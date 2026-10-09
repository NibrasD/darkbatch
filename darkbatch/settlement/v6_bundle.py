"""
DarkBatch settlement simulation record builder.

This module currently does not build or serialize a consensus-ready Ironwood transaction.
It emits deterministic FBA simulation metadata until wallet-authorized Ironwood spends,
valid witnesses, proofs, signatures, and canonical serialization are integrated.
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
    # tx_id is None until a transaction is built and serialized by the authoritative
    # Ironwood transaction pipeline. The current application only emits simulation_id.
    tx_id: Optional[str]
    simulation_id: str
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
    consensus_ready: bool = False
    construction_mode: str = "LOCAL_SIMULATION_ONLY"
    validation_blockers: List[str] = field(default_factory=lambda: [
        "Trade intents do not contain wallet-authorized Ironwood spend notes.",
        "No live Ironwood note-tree Merkle witnesses are supplied.",
        "The official Ironwood bundle/proof/signature output is not the serialized action set.",
        "The current app wallet and settlement node are simulations, not a Zebra wallet/node.",
    ])

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
    Constructs genuine ZIP 228 Swap Bundles & ZIP 229 Transaction v6 payloads.
    """
    def __init__(self, ironwood_anchor: str = "5cbf3162257b772a43d8b9d517b11b7cd889a53753eb9b62d29031fd757ef52e"):
        self.ironwood_anchor = ironwood_anchor

    def build_bundle(
        self,
        clear_result: BatchClearResult,
        intents_map: Dict[str, SwapOrderIntent],
        wallets_ivk_map: Optional[Dict[str, bytes]] = None
    ) -> SettlementBundle:
        """
        Produce a deterministic *simulation record*, never a raw Ironwood transaction.

        An order intent and a recipient viewing key do not provide spend authority,
        spendable notes, or note-tree witnesses. The official Ironwood builder must
        receive real authorized spends and outputs and serialize the exact bundle it
        proved. Until that integration exists, this method fails closed at the
        consensus boundary instead of emitting fabricated proofs/signatures/txids.
        """
        all_fills = clear_result.buy_fills + clear_result.sell_fills
        total_matcher_fee = sum(
            int(round(fill.filled_zat * self._fee_fraction(clear_result)))
            for fill in all_fills
        )
        total_miner_fee = 10_000 * len(all_fills)
        transcript = {
            "epoch_id": clear_result.epoch_id,
            "clearing_price_usd": clear_result.clearing_price_usd,
            "total_volume_zec": clear_result.total_cleared_zec,
            "anchor": self.ironwood_anchor,
            "fills": [
                {
                    "intent_id": fill.intent_id,
                    "direction": fill.direction.value,
                    "filled_zat": fill.filled_zat,
                    "recipient": fill.shielded_address,
                }
                for fill in all_fills
            ],
        }
        simulation_id = "sim_" + blake2b_digest(
            json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode(),
            personalization=b"DarkBatchSimID"
        ).hex()
        return SettlementBundle(
            tx_id=None,
            simulation_id=simulation_id,
            tx_version=6,
            version_group_id=VERSION_GROUP_ID_V6,
            consensus_branch_id=CONSENSUS_BRANCH_ID_IRONWOOD,
            epoch_id=clear_result.epoch_id,
            clearing_price_usd=clear_result.clearing_price_usd,
            total_volume_zec=clear_result.total_cleared_zec,
            action_groups=[],
            aggregated_binding_pubkey_hex="",
            raw_tx_hex="",
            raw_tx_bytes_len=0,
            created_at=time.time(),
            total_matcher_fee_zat=total_matcher_fee,
            total_miner_fee_zat=total_miner_fee,
            consensus_ready=False,
            construction_mode="LOCAL_SIMULATION_ONLY",
        )

    @staticmethod
    def _fee_fraction(clear_result: BatchClearResult) -> float:
        if clear_result.total_cleared_zec <= 0:
            return 0.0
        return clear_result.solver_fee_zec / clear_result.total_cleared_zec
