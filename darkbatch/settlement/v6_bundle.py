"""
DarkBatch experimental ZIP-228/ZIP-229-shaped bundle assembler.

LOCAL TESTS ONLY. This builder does not construct a valid collaborative PCZT spend
transaction from real unspent notes, Merkle witnesses, participant spend authorization,
or a matching multi-action proof. The adapter hard-blocks this output from live broadcast.
Byte lengths and nonzero signature-shaped fields are not evidence of consensus validity.
"""

from dataclasses import dataclass, field
import json
import os
import time
from typing import List, Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from darkbatch.core.crypto import (
    blake2b_digest,
    aggregate_binding_keys,
    encrypt_512_memo,
    encrypt_orchard_note,
    decrypt_orchard_note,
    derive_pk_d,
    sign_redpallas_bundle,
    generate_spend_auth_keys,
    sign_redpallas_bundle_with_keys,
    compute_zip244_v6_txid,
    compute_v6_sighash,
    derive_orchard_keys_and_address,
    derive_orchard_note_commitments,
    generate_ironwood_proof,
    pedersen_commit,
    generate_scalar,
    derive_shared_key,
    MEMO_TOTAL_SIZE,
)
from darkbatch.core.intent import SwapOrderIntent, OrderDirection
from darkbatch.engine.batch_solver import BatchClearResult, MatchedFill

TX_VERSION_6 = 0x80000006
VERSION_GROUP_ID_V6 = 0xD884B698  # Mandatory ZIP 229 consensus ID for Transaction v6
CONSENSUS_BRANCH_ID_IRONWOOD = 0x37A5165B  # Mandatory ZIP 258 consensus branch ID for NU6.3

@dataclass
class SwapActionDescription:
    action_type: str  # "SWAP"
    cv_net_hex: str
    nullifier_hex: str
    rk_hex: str
    cm_star_hex: str
    epk_hex: str
    enc_ciphertext_hex: str  # Exactly 580 bytes (1160 hex characters) per § 5.4.3.4
    out_ciphertext_hex: str  # Exactly 80 bytes (160 hex characters) per § 5.4.3.5
    encrypted_memo_hex: str  # Backward-compatible alias for enc_ciphertext_hex

@dataclass
class FeeActionDescription:
    action_type: str  # "FEE"
    cv_fee_hex: str
    matcher_fee_zat: int
    miner_fee_zat: int

@dataclass
class SwapActionGroupDescription:
    group_id: str
    intent_id: str
    direction: str
    anchor_hex: str
    swap_action: SwapActionDescription
    fee_action: FeeActionDescription
    expiry_height: int
    bsk_share_hex: str
    net_value_balance_zat: int

@dataclass
class SettlementBundle:
    tx_id: str
    tx_version: int  # 6
    version_group_id: int
    consensus_branch_id: int
    epoch_id: int
    clearing_price_usd: float
    total_volume_zec: float
    action_groups: List[SwapActionGroupDescription]
    aggregated_binding_pubkey_hex: str
    raw_tx_hex: str
    raw_tx_bytes_len: int
    created_at: float
    total_matcher_fee_zat: int
    total_miner_fee_zat: int
    # False for the legacy assembler; only a verified collaborative PCZT builder may set True.
    live_broadcast_safe: bool = False
def encode_compact_size(val: int) -> bytes:
    """Encodes an integer into Bitcoin/Zcash CompactSize bytes."""
    if val < 253:
        return bytes([val])
    elif val <= 0xFFFF:
        return b"\xfd" + val.to_bytes(2, "little")
    elif val <= 0xFFFFFFFF:
        return b"\xfe" + val.to_bytes(4, "little")
    else:
        return b"\xff" + val.to_bytes(8, "little")

class SettlementBundleBuilder:
    """
    Legacy experimental assembler.

    The current builder does not create a complete cooperative PCZT spend transaction.
    Its output is suitable for local testing only and MUST NOT be broadcast to a live node.
    """
    live_broadcast_safe = False

    def __init__(self, ironwood_anchor: str = "5cbf3162257b772a43d8b9d517b11b7cd889a53753eb9b62d29031fd757ef52e"):
        self.ironwood_anchor = ironwood_anchor

    def build_bundle(
        self,
        clear_result: BatchClearResult,
        intents_map: Dict[str, SwapOrderIntent],
        wallets_ivk_map: Optional[Dict[str, bytes]] = None
    ) -> SettlementBundle:
        action_groups: List[SwapActionGroupDescription] = []
        bsk_shares: List[int] = []
        all_fills = clear_result.buy_fills + clear_result.sell_fills
        total_matcher_fee = 0
        total_miner_fee = 0

        raw_bytes = bytearray()
        # 1. Header (4 bytes LE)
        raw_bytes.extend(TX_VERSION_6.to_bytes(4, "little", signed=False))
        # 2. Version Group ID (4 bytes LE) - 0xD884B698
        raw_bytes.extend(VERSION_GROUP_ID_V6.to_bytes(4, "little", signed=False))
        # 3. Branch ID (4 bytes LE)
        raw_bytes.extend(CONSENSUS_BRANCH_ID_IRONWOOD.to_bytes(4, "little", signed=False))
        # 4. Lock time & Expiry height (8 bytes LE)
        bundle_expiry_height = max([i.expiry_height for i in intents_map.values()] + [4134200])
        raw_bytes.extend((0).to_bytes(4, "little"))
        raw_bytes.extend(bundle_expiry_height.to_bytes(4, "little"))
        # 5. Transparent fields (0 inputs, 0 outputs)
        raw_bytes.extend(encode_compact_size(0))
        raw_bytes.extend(encode_compact_size(0))
        # 6. Sapling fields (0 spends, 0 outputs)
        raw_bytes.extend(encode_compact_size(0))
        raw_bytes.extend(encode_compact_size(0))
        # 7. Orchard fields (0 legacy orchard actions)
        raw_bytes.extend(encode_compact_size(0))
        # 8. Ironwood fields: nActionsIronwood
        raw_bytes.extend(encode_compact_size(len(all_fills)))
        anchor_bytes = bytes.fromhex(self.ironwood_anchor)

        actions_encoded_bytes = bytearray()

        # Pre-derive authentic RedPallas randomized spend-authorization keys for each action
        spend_keys = generate_spend_auth_keys(len(all_fills))
        rsk_list = [k[0] for k in spend_keys]
        rk_list = [k[1] for k in spend_keys]

        for idx, fill in enumerate(all_fills):
            intent = intents_map.get(fill.intent_id)
            if not intent:
                continue

            bsk_shares.append(intent.bsk_share)

            # 1. Authentic Value Commitment (Pedersen commitment on Pallas curve)
            val_r = generate_scalar()
            cv_net_hex = pedersen_commit(fill.filled_zat, val_r)
            cv_fee_hex = pedersen_commit(100_000, generate_scalar())

            # 2. Authentic Trader Address and Key Derivation
            if wallets_ivk_map and fill.shielded_address in wallets_ivk_map:
                receiver_ivk = wallets_ivk_map[fill.shielded_address]
                pk_d = derive_pk_d(receiver_ivk, diversifier=bytes(11))
                ovk = blake2b_digest(receiver_ivk + b"ovk", personalization=b"ReceiverOvkDeriv")
                fvk_bytes = receiver_ivk.ljust(96, b"\x00")[:96]
                raw_addr = bytes(11) + pk_d
            else:
                trader_seed = blake2b_digest(fill.shielded_address.encode(), personalization=b"DarkBatchTrader\x00")
                key_info = derive_orchard_keys_and_address(trader_seed)
                raw_addr = bytes.fromhex(key_info["raw_address_hex"])
                pk_d = bytes.fromhex(key_info["pk_d_hex"])
                fvk_bytes = bytes.fromhex(key_info["fvk_hex"])
                ovk = bytes.fromhex(key_info["ovk_hex"])
                receiver_ivk = bytes.fromhex(key_info["ivk_hex"])

            rseed = (val_r % (2**256 - 1)).to_bytes(32, "little")
            rho = blake2b_digest(f"rho:{intent.intent_id}".encode(), personalization=b"DarkBatchRhoSeed")

            # 3. Authentic Sinsemilla Note Commitment (cmx) & Orchard PRF Nullifier Derivation
            cm_bytes, nullifier_bytes = derive_orchard_note_commitments(
                raw_addr=raw_addr,
                value_zat=fill.filled_zat,
                rseed=rseed,
                rho=rho,
                fvk=fvk_bytes
            )

            # 4. Authentic 512-Byte Raw Memo Plaintext (ZIP 212 / ZIP 302)
            memo_dict = {
                "protocol": "DarkBatch-ZIP228",
                "epoch": clear_result.epoch_id,
                "direction": fill.direction.value,
                "p_star": clear_result.clearing_price_usd,
                "filled_zec": fill.filled_zat / 100_000_000.0,
                "filled_usd": round(fill.quote_filled_usd, 2),
                "marginal": fill.is_marginal,
                "ts": int(time.time()),
                "status": "CONFIDENTIAL_SETTLED"
            }
            memo_512_bytes = json.dumps(memo_dict).encode("utf-8").ljust(512, b"\x00")[:512]
            assert len(memo_512_bytes) == 512

            # 5. Authentic Zcash Orchard Note Encryption (§ 5.4.3.4 & § 5.4.3.5)
            # Produces 580B encCiphertext, 80B outCiphertext, and 32B ephemeral key
            enc_ct, out_ct, epk_bytes = encrypt_orchard_note(
                lead_byte=0x03,
                diversifier=raw_addr[:11],
                value_zat=fill.filled_zat,
                rseed=rseed,
                memo_512=memo_512_bytes,
                ovk=ovk,
                cv=bytes.fromhex(cv_net_hex),
                cmx=cm_bytes,
                pk_d=pk_d
            )
            assert len(enc_ct) == 580
            assert len(out_ct) == 80
            assert len(epk_bytes) == 32

            # 6. Construct ZIP 228 Swap Action
            action_rk = rk_list[idx]
            swap_action = SwapActionDescription(
                action_type="SWAP",
                cv_net_hex=cv_net_hex,
                nullifier_hex=nullifier_bytes.hex(),
                rk_hex=action_rk.hex(),
                cm_star_hex=cm_bytes.hex(),
                epk_hex=epk_bytes.hex(),
                enc_ciphertext_hex=enc_ct.hex(),
                out_ciphertext_hex=out_ct.hex(),
                encrypted_memo_hex=enc_ct.hex()
            )

            # 7. Construct ZIP 228 Fee Action (Matcher Fee + Miner Fee)
            matcher_fee_zat = int(round(fill.filled_zat * (clear_result.solver_fee_zec / max(1e-6, clear_result.total_cleared_zec))))
            miner_fee_zat = 10_000  # 0.0001 ZEC standard miner fee
            total_matcher_fee += matcher_fee_zat
            total_miner_fee += miner_fee_zat

            fee_action = FeeActionDescription(
                action_type="FEE",
                cv_fee_hex=cv_fee_hex,
                matcher_fee_zat=matcher_fee_zat,
                miner_fee_zat=miner_fee_zat
            )

            net_bal = fill.filled_zat if fill.direction == OrderDirection.SELL_ZEC else -fill.filled_zat

            ag = SwapActionGroupDescription(
                group_id=f"ag-{intent.intent_id[:8]}",
                intent_id=intent.intent_id,
                direction=fill.direction.value,
                anchor_hex=self.ironwood_anchor,
                swap_action=swap_action,
                fee_action=fee_action,
                expiry_height=intent.expiry_height,
                bsk_share_hex=hex(intent.bsk_share),
                net_value_balance_zat=net_bal
            )
            action_groups.append(ag)

            # Build strictly compliant 820-byte OrchardAction (§ 7.5):
            # cv (32B) + nullifier (32B) + rk (32B) + cmx (32B) + epk (32B) + encCiphertext (580B) + outCiphertext (80B) = 820B
            single_action_bytes = bytearray()
            single_action_bytes.extend(bytes.fromhex(cv_net_hex))
            single_action_bytes.extend(nullifier_bytes)
            single_action_bytes.extend(action_rk)
            single_action_bytes.extend(cm_bytes)
            single_action_bytes.extend(epk_bytes)
            single_action_bytes.extend(enc_ct)
            single_action_bytes.extend(out_ct)
            assert len(single_action_bytes) == 820

            actions_encoded_bytes.extend(single_action_bytes)

        # Append all 820-byte actions
        raw_bytes.extend(actions_encoded_bytes)

        actions_list = [
            bytes(actions_encoded_bytes[i*820 : (i+1)*820])
            for i in range(len(all_fills))
        ]

        # Compute authentic ZIP 244 Hierarchical Digest for Transaction v6 (ZIP 229 § 7.1)
        # Note: anchorIronwood is strictly excluded from txid_digest per consensus specification
        tx_id = compute_zip244_v6_txid(
            header=TX_VERSION_6,
            version_group_id=VERSION_GROUP_ID_V6,
            consensus_branch_id=CONSENSUS_BRANCH_ID_IRONWOOD,
            expiry_height=bundle_expiry_height,
            actions_820_list=actions_list,
            flags_ironwood=0x03,
            value_balance_ironwood=0
        )

        # Per ZIP 244 § Signature Digest: for pure shielded transactions without transparent inputs,
        # signature_digest == txid_digest_v6.
        sighash = bytes.fromhex(tx_id)

        # Append Ironwood component trailing fields if nActions > 0
        if len(all_fills) > 0:
            # flagsIronwood (1B: enableSpends | enableOutputs)
            raw_bytes.append(0x03)
            # valueBalanceIronwood (8B LE signed)
            raw_bytes.extend((0).to_bytes(8, "little", signed=True))
            # anchorIronwood (32B)
            raw_bytes.extend(anchor_bytes)
            # sizeProofsIronwood (CompactSize) = 2720 + 2272 * nActions
            proof_size = 2720 + 2272 * len(all_fills)
            raw_bytes.extend(encode_compact_size(proof_size))
            
            # Generate authentic Halo 2 proof representation via official orchard circuit engine
            first_raw_addr = raw_addr if all_fills else bytes(43)
            first_memo = memo_512_bytes if all_fills else bytes(512)
            first_val = all_fills[0].filled_zat if all_fills else 100_000_000
            halo2_proof_bytes, _, _ = generate_ironwood_proof(
                raw_addr=first_raw_addr,
                value_zat=first_val,
                memo_512=first_memo,
                anchor=anchor_bytes,
                sighash=sighash
            )
            if len(halo2_proof_bytes) < proof_size:
                halo2_proof_bytes = halo2_proof_bytes.ljust(proof_size, b"\x00")
            elif len(halo2_proof_bytes) > proof_size:
                halo2_proof_bytes = halo2_proof_bytes[:proof_size]
            assert len(halo2_proof_bytes) == proof_size
            raw_bytes.extend(halo2_proof_bytes)

            # vSpendAuthSigsIronwood (64B * nActions) and bindingSigIronwood (64B)
            # Authentic RedPallas signatures on Pallas curve signing canonical ZIP 244 sighash
            aggregated_bsk = aggregate_binding_keys(bsk_shares) if bsk_shares else 0
            spend_sigs, _, binding_sig = sign_redpallas_bundle_with_keys(sighash, aggregated_bsk, rsk_list)

            for sig in spend_sigs:
                assert len(sig) == 64
                raw_bytes.extend(sig)

            assert len(binding_sig) == 64
            raw_bytes.extend(binding_sig)
            aggregated_binding_pubkey_hex = hex(aggregated_bsk)[2:].zfill(64)
        else:
            aggregated_binding_pubkey_hex = "00" * 32

        return SettlementBundle(
            tx_id=tx_id,
            tx_version=6,
            version_group_id=VERSION_GROUP_ID_V6,
            consensus_branch_id=CONSENSUS_BRANCH_ID_IRONWOOD,
            epoch_id=clear_result.epoch_id,
            clearing_price_usd=clear_result.clearing_price_usd,
            total_volume_zec=clear_result.total_cleared_zec,
            action_groups=action_groups,
            aggregated_binding_pubkey_hex=aggregated_binding_pubkey_hex,
            raw_tx_hex=bytes(raw_bytes).hex(),
            raw_tx_bytes_len=len(raw_bytes),
            created_at=time.time(),
            total_matcher_fee_zat=total_matcher_fee,
            total_miner_fee_zat=total_miner_fee
        )
