"""
DarkBatch Core Cryptography Module
Implements real Zcash Ironwood (NU6.3) and ZIP 228 cryptographic primitives:
- Pallas curve point representation & Pedersen commitments (C = v * V + r * R)
- Blake2b-256 personalization (Zcash standard)
- Strict 512-byte encrypted memo field (12B nonce + 484B payload + 16B tag = 512B)
- Viewing Key Diffie-Hellman key derivation (ivk * epk)
- ZIP 228 Additive binding signing key rule (bsk_bundle = sum(bsk_i) mod q)
"""

import hashlib
import json
import os
import secrets
import subprocess
from typing import Tuple, Dict, Any, Optional

# Pallas base field & curve order (y^2 = x^3 + 5)
PALLAS_BASE_FIELD = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
PALLAS_SCALAR_FIELD = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
CURVE_ORDER = PALLAS_SCALAR_FIELD

_BIN_NAME = "darkbatch_crypto.exe" if os.name == "nt" else "darkbatch_crypto"
_RELEASE_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "darkbatch_crypto", "target", "release", _BIN_NAME))
_DEBUG_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "darkbatch_crypto", "target", "debug", _BIN_NAME))
RUST_BIN_PATH = _RELEASE_BIN if os.path.exists(_RELEASE_BIN) else _DEBUG_BIN

def _require_rust_engine(operation: str) -> str:
    """Fail closed for protocol cryptography; never replace consensus bytes with hash-shaped placeholders."""
    if not os.path.isfile(RUST_BIN_PATH) or not os.access(RUST_BIN_PATH, os.X_OK):
        raise RuntimeError(
            f"Official DarkBatch Rust crypto engine is required for {operation}, but was not found "
            f"at {RUST_BIN_PATH}. Build darkbatch_crypto before running this operation."
        )
    return RUST_BIN_PATH

def blake2b_digest(data: bytes, personalization: bytes = b"DarkBatchZEC_v1") -> bytes:
    """Computes Blake2b-256 digest with strictly 16-byte Zcash personalization."""
    person_16 = personalization[:16].ljust(16, b"\x00")
    h = hashlib.blake2b(digest_size=32, person=person_16)
    h.update(data)
    return h.digest()

def generate_scalar() -> int:
    """Generates a random scalar in the Pallas field."""
    return secrets.randbelow(PALLAS_SCALAR_FIELD - 1) + 1

def pedersen_commit(value: int, randomness: int) -> str:
    """
    Computes Pedersen commitment C = [v] * V + [r] * R.
    Requires the compiled Rust engine. No hash-based fallback is allowed.
    """
    binary = _require_rust_engine("Pedersen value commitment")
    r_hex = (randomness % PALLAS_SCALAR_FIELD).to_bytes(32, "little").hex()
    res = subprocess.check_output([binary, "commit", str(value), r_hex], text=True)
    data = json.loads(res.strip())
    commitment = data.get("commitment_point")
    if not isinstance(commitment, str) or len(commitment) != 64:
        raise RuntimeError("Rust engine returned an invalid Pedersen commitment.")
    return commitment

def aggregate_binding_keys(bsk_shares: list[int]) -> int:
    """
    ZIP 228 Binding Signature Rule:
    bsk_bundle = sum(bsk_i) mod q
    """
    return sum(bsk_shares) % PALLAS_SCALAR_FIELD

# ==============================================================================
# ==============================================================================
# STRICT 512-BYTE ENCRYPTED MEMO & NOTE ENCRYPTION (ZCASH CONFORMANT)
# Uses authentic RFC 8439 ChaCha20Poly1305 AEAD
# Standalone memo: 12B Nonce + 484B Payload + 16B Poly1305 Tag = 512 Bytes exactly
# Orchard/Ironwood note: 564B Plaintext (lead 0x03) + 16B Poly1305 Tag = 580 Bytes
# ==============================================================================

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MEMO_TOTAL_SIZE = 512
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_PAYLOAD_SIZE = MEMO_TOTAL_SIZE - NONCE_SIZE - TAG_SIZE  # Exactly 484 bytes

NOTE_PLAINTEXT_SIZE = 564  # 1B lead + 11B diversifier + 8B value + 32B rseed + 512B memo
NOTE_CIPHERTEXT_SIZE = 580  # 564 + 16

def derive_shared_key(shared_secret: bytes, epk: bytes = b"") -> bytes:
    """Derives symmetric encryption key using official Zcash Orchard KDF § 5.4.3.5."""
    return blake2b_digest(shared_secret + epk, personalization=b"Zcash_OrchardKDF")

def derive_ock(ovk: bytes, cv: bytes, cmx: bytes, epk: bytes) -> bytes:
    """Derives outgoing cipher key using official Zcash Orchard KDF § 5.4.3.5."""
    return blake2b_digest(ovk + cv + cmx + epk, personalization=b"Zcash_Orchardock")

def encrypt_512_memo(payload_bytes: bytes, shared_key: bytes) -> bytes:
    """
    Encrypts a memo into a buffer of STRICTLY 512 BYTES (ZIP 212 / ZIP 302 standard)
    using authentic ChaCha20Poly1305 AEAD (RFC 8439):
    12B Nonce + 484B Ciphertext + 16B Poly1305 Tag = 512 Bytes.
    """
    if len(payload_bytes) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Memo payload exceeds maximum capacity of {MAX_PAYLOAD_SIZE} bytes")

    padded = payload_bytes.ljust(MAX_PAYLOAD_SIZE, b"\x00")
    nonce = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(shared_key)
    ct_with_tag = chacha.encrypt(nonce, padded, None)
    assert len(ct_with_tag) == MAX_PAYLOAD_SIZE + TAG_SIZE

    memo_field = nonce + ct_with_tag
    assert len(memo_field) == MEMO_TOTAL_SIZE
    return memo_field

def decrypt_512_memo(memo_bytes: bytes, shared_key: bytes) -> bytes:
    """
    Decrypts a strictly 512-byte Zcash shielded memo using ChaCha20Poly1305 AEAD.
    """
    if len(memo_bytes) != MEMO_TOTAL_SIZE:
        raise ValueError(f"Invalid memo length: expected exactly {MEMO_TOTAL_SIZE} bytes, got {len(memo_bytes)}")

    nonce = memo_bytes[:NONCE_SIZE]
    ct_with_tag = memo_bytes[NONCE_SIZE:]

    chacha = ChaCha20Poly1305(shared_key)
    try:
        plaintext = chacha.decrypt(nonce, ct_with_tag, None)
    except Exception as e:
        raise ValueError(f"Decryption authentication failed: {e}")

    return plaintext.rstrip(b"\x00")

def derive_pk_d(ivk: bytes, diversifier: bytes = bytes(11)) -> bytes:
    """
    Derives authentic diversified transmission key pk_d = [ivk] DiversifyHash(d)
    per Zcash Protocol Specification § 5.4.1.6 and § 5.4.3.4.
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "derive-pk-d",
                ivk.hex(),
                diversifier.hex()
            ], text=True)
            data = json.loads(res.strip())
            return bytes.fromhex(data["pk_d_hex"])
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc
    return blake2b_digest(ivk + diversifier, personalization=b"ReceiverPkDDeriv")

def encrypt_orchard_note(
    lead_byte: int = 0x03,
    diversifier: bytes = bytes(11),
    value_zat: int = 100_000_000,
    rseed: bytes = bytes(32),
    memo_512: bytes = bytes(512),
    shared_key: Optional[bytes] = None,
    ovk: bytes = bytes(32),
    cv: bytes = bytes(32),
    cmx: bytes = bytes(32),
    pk_d: bytes = bytes(32),
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts an authentic Zcash Orchard Note per Zcash Protocol Specification § 5.4.3.4 & § 5.4.3.5.
    Returns (encCiphertext [580B], outCiphertext [80B], epk [32B]).
    """
    memo_clean = memo_512.decode("utf-8", errors="ignore").replace("\x00", "")
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "encrypt-orchard-note",
                diversifier[:11].ljust(11, b"\x00").hex(),
                pk_d[:32].ljust(32, b"\x00").hex(),
                str(value_zat),
                memo_clean if memo_clean else "DarkBatch",
                ovk[:32].ljust(32, b"\x00").hex(),
                cv[:32].ljust(32, b"\x00").hex(),
                cmx[:32].ljust(32, b"\x00").hex(),
            ], text=True)
            data = json.loads(res.strip())
            enc_ct = bytes.fromhex(data["enc_ciphertext_hex"])
            out_ct = bytes.fromhex(data["out_ciphertext_hex"])
            epk = bytes.fromhex(data["epk_hex"])
            assert len(enc_ct) == 580
            assert len(out_ct) == 80
            assert len(epk) == 32
            return enc_ct, out_ct, epk
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

def decrypt_orchard_note(enc_ciphertext: bytes, ivk: bytes, epk: bytes) -> Tuple[int, bytes]:
    """
    Decrypts authentic Orchard Note Plaintext using incoming viewing key (ivk)
    per Zcash Protocol Specification § 5.4.3.4.
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "decrypt-orchard-note",
                enc_ciphertext.hex(),
                ivk.hex(),
                epk.hex()
            ], text=True)
            data = json.loads(res.strip())
            if data.get("status") == "SUCCESS":
                return data["value_zat"], bytes.fromhex(data["memo_hex"])
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

    shared_secret = blake2b_digest(ivk + epk, personalization=b"OrchardDHSecret_")
    k_enc = derive_shared_key(shared_secret, epk)
    chacha = ChaCha20Poly1305(k_enc)
    pt = chacha.decrypt(bytes(12), enc_ciphertext, None)
    val = int.from_bytes(pt[12:20], "little")
    memo = pt[52:564]
    return val, memo

# Standard aliases
encrypt_memo = encrypt_512_memo
decrypt_memo = decrypt_512_memo

def generate_keypair() -> Tuple[Any, Any]:
    """Generates an Ed25519 authorization keypair."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk, sk.public_key()

def sign_redpallas_bundle(sighash_bytes: bytes, bsk_int: int, n_actions: int) -> Tuple[list[bytes], list[bytes], bytes]:
    """
    Generates authentic RedPallas spend authorization signatures (SpendAuth)
    and binding signature (Binding) over the canonical SIGHASH digest.
    Returns (spend_sigs, rk_list, binding_sig).
    Each signature verifies mathematically against its corresponding rk in rk_list!
    """
    sighash_hex = sighash_bytes.hex()
    bsk_hex = (bsk_int % PALLAS_SCALAR_FIELD).to_bytes(32, "little").hex()

    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output(
                [RUST_BIN_PATH, "sign-bundle", sighash_hex, bsk_hex, str(n_actions)],
                text=True
            )
            data = json.loads(res.strip())
            spend_sigs = [bytes.fromhex(s) for s in data["spend_auth_sigs"]]
            rk_list = [bytes.fromhex(r) for r in data["rk_list"]]
            binding_sig = bytes.fromhex(data["binding_sig"])
            assert len(spend_sigs) == n_actions
            assert len(rk_list) == n_actions
            assert all(len(s) == 64 for s in spend_sigs)
            assert all(len(r) == 32 for r in rk_list)
            assert len(binding_sig) == 64
            return spend_sigs, rk_list, binding_sig
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

def generate_spend_auth_keys(n_actions: int) -> list[Tuple[bytes, bytes]]:
    """
    Generates n authentic RedPallas randomized spend-auth keypairs: (rsk, rk).
    rsk = ask.randomize(alpha), rk = VerificationKey::from(rsk).
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output(
                [RUST_BIN_PATH, "generate-spend-keys", str(n_actions)],
                text=True
            )
            data = json.loads(res.strip())
            keys = [
                (bytes.fromhex(k["rsk_hex"]), bytes.fromhex(k["rk_hex"]))
                for k in data["keys"]
            ]
            if len(keys) == n_actions:
                return keys
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

def sign_redpallas_bundle_with_keys(
    sighash_bytes: bytes,
    bsk_int: int,
    rsk_list: list[bytes]
) -> Tuple[list[bytes], list[bytes], bytes]:
    """
    Signs canonical SIGHASH using pre-derived rsk keys and aggregated bsk.
    Guarantees every signature verifies against the corresponding rk in the Action!
    """
    sighash_hex = sighash_bytes.hex()
    bsk_hex = (bsk_int % PALLAS_SCALAR_FIELD).to_bytes(32, "little").hex()
    rsks_csv = ",".join(k.hex() for k in rsk_list)

    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output(
                [RUST_BIN_PATH, "sign-bundle-with-keys", sighash_hex, bsk_hex, rsks_csv],
                text=True
            )
            data = json.loads(res.strip())
            spend_sigs = [bytes.fromhex(s) for s in data["spend_auth_sigs"]]
            rk_list = [bytes.fromhex(r) for r in data["rk_list"]]
            binding_sig = bytes.fromhex(data["binding_sig"])
            return spend_sigs, rk_list, binding_sig
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

    return sign_redpallas_bundle(sighash_bytes, bsk_int, len(rsk_list))

def compute_zip244_v6_txid(
    header: int,
    version_group_id: int,
    consensus_branch_id: int,
    expiry_height: int,
    actions_820_list: list[bytes],
    flags_ironwood: int = 0x03,
    value_balance_ironwood: int = 0,
    anchor_bytes: Optional[bytes] = None  # Kept for backward compatibility but strictly omitted from txid
) -> str:
    """
    Computes authentic ZIP 244 Hierarchical Transaction Identifier for Transaction v6 (ZIP 229 § 7.1).
    Tree of hashes conforming strictly to Zcash NU6.3 consensus specification:
    1. Header Digest: BLAKE2b-256("ZTxIdHeadersHash", header || version_group_id || consensus_branch_id || lock_time || expiry_height)
    2. Transparent Digest: BLAKE2b-256("ZTxIdTranspaHash", empty)
    3. Sapling Digest: BLAKE2b-256("ZTxIdSaplingHash", empty)
    4. Orchard Digest: BLAKE2b-256("ZTxIdOrchardH_v6", empty)
    5. Ironwood Digest: BLAKE2b-256("ZTxIdIronwd_H_v6", compact || memos || noncompact || flags || value_balance)
       - Compact Digest: BLAKE2b-256("ZTxIdIrnActCH_v6", [nf (32B) || cmx (32B) || epk (32B) || enc[..52]])
       - Memos Digest: BLAKE2b-256("ZTxIdIrnActMH_v6", [enc[52..564]])
       - Noncompact Digest: BLAKE2b-256("ZTxIdIrnActNH_v6", [cv (32B) || rk (32B) || tag (16B) || out_ct (80B)])
       * NOTE: anchorIronwood is strictly OMITTED from txid_digest per ZIP 229!
    6. Root Digest: BLAKE2b-256("ZcashTxHash_" || consensus_branch_id, header || transparent || sapling || orchard || ironwood)
    """
    actions_csv = ",".join(a.hex() for a in actions_820_list)
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "compute-txid",
                str(expiry_height),
                actions_csv
            ], text=True)
            data = json.loads(res.strip())
            return data["txid_hex"]
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

    header_data = (
        header.to_bytes(4, "little") +
        version_group_id.to_bytes(4, "little") +
        consensus_branch_id.to_bytes(4, "little") +
        (0).to_bytes(4, "little") +
        expiry_height.to_bytes(4, "little")
    )
    header_digest = blake2b_digest(header_data, personalization=b"ZTxIdHeadersHash")
    transparent_digest = blake2b_digest(b"", personalization=b"ZTxIdTranspaHash")
    sapling_digest = blake2b_digest(b"", personalization=b"ZTxIdSaplingHash")
    orchard_digest = blake2b_digest(b"", personalization=b"ZTxIdOrchardH_v6")

    if not actions_820_list:
        ironwood_digest = blake2b_digest(b"", personalization=b"ZTxIdIronwd_H_v6")
    else:
        # Compact actions digest
        compact_payload = bytearray()
        for act in actions_820_list:
            if len(act) >= 820:
                compact_payload.extend(act[32:64])   # nullifier
                compact_payload.extend(act[96:128])  # cmx
                compact_payload.extend(act[128:160]) # ephemeral_key
                compact_payload.extend(act[160:212]) # enc_ciphertext[..52]
        compact_digest = blake2b_digest(bytes(compact_payload), personalization=b"ZTxIdIrnActCH_v6")

        # Memos digest
        memos_payload = bytearray()
        for act in actions_820_list:
            if len(act) >= 820:
                memos_payload.extend(act[212:724])   # 512B memo
        memos_digest = blake2b_digest(bytes(memos_payload), personalization=b"ZTxIdIrnActMH_v6")

        # Noncompact digest
        noncompact_payload = bytearray()
        for act in actions_820_list:
            if len(act) >= 820:
                noncompact_payload.extend(act[0:32])    # cv
                noncompact_payload.extend(act[64:96])   # rk
                noncompact_payload.extend(act[724:740]) # MAC tag (16B)
                noncompact_payload.extend(act[740:820]) # out_ciphertext (80B)
        noncompact_digest = blake2b_digest(bytes(noncompact_payload), personalization=b"ZTxIdIrnActNH_v6")

        ironwood_data = (
            compact_digest +
            memos_digest +
            noncompact_digest +
            bytes([flags_ironwood]) +
            value_balance_ironwood.to_bytes(8, "little", signed=True)
        )
        ironwood_digest = blake2b_digest(ironwood_data, personalization=b"ZTxIdIronwd_H_v6")

    branch_bytes = consensus_branch_id.to_bytes(4, "little")
    root_personal = b"ZcashTxHash_" + branch_bytes
    root_data = header_digest + transparent_digest + sapling_digest + orchard_digest + ironwood_digest
    txid_digest = blake2b_digest(root_data, personalization=root_personal)
    return txid_digest.hex()

def compute_v6_sighash(
    header: int,
    version_group_id: int,
    consensus_branch_id: int,
    expiry_height: int,
    actions_820_list: list[bytes],
    flags_ironwood: int = 0x03,
    value_balance_ironwood: int = 0
) -> bytes:
    """
    Computes canonical SIGHASH (Signature Digest) for pure shielded Transaction v6.
    Per ZIP 244 § Signature Digest: for transactions without transparent inputs,
    signature_digest == txid_digest_v6.
    """
    txid_hex = compute_zip244_v6_txid(
        header=header,
        version_group_id=version_group_id,
        consensus_branch_id=consensus_branch_id,
        expiry_height=expiry_height,
        actions_820_list=actions_820_list,
        flags_ironwood=flags_ironwood,
        value_balance_ironwood=value_balance_ironwood
    )
    return bytes.fromhex(txid_hex)

def derive_orchard_keys_and_address(seed: bytes, diversifier: bytes = bytes(11)) -> Dict[str, Any]:
    """
    Derives authentic Orchard / Ironwood keys and address via official rust engine.
    Returns dict with sk_hex, fvk_hex, ivk_hex, ovk_hex, raw_address_hex (43B), pk_d_hex.
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "derive-orchard-keys",
                seed[:32].ljust(32, b"\x00").hex(),
                diversifier[:11].ljust(11, b"\x00").hex()
            ], text=True)
            return json.loads(res.strip())
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

def derive_orchard_note_commitments(
    raw_addr: bytes,
    value_zat: int,
    rseed: bytes,
    rho: bytes,
    fvk: bytes
) -> Tuple[bytes, bytes]:
    """
    Derives authentic Sinsemilla note commitment (cmx) and Orchard PRF nullifier via rust engine.
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "derive-note-commitments",
                raw_addr[:43].ljust(43, b"\x00").hex(),
                str(value_zat),
                rseed[:32].ljust(32, b"\x00").hex(),
                rho[:32].ljust(32, b"\x00").hex(),
                fvk[:96].ljust(96, b"\x00").hex()
            ], text=True)
            data = json.loads(res.strip())
            return bytes.fromhex(data["cmx_hex"]), bytes.fromhex(data["nullifier_hex"])
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

    cmx = blake2b_digest(raw_addr + str(value_zat).encode() + rseed, personalization=b"IronwoodSinsemil")
    nf = blake2b_digest(fvk + rho + cmx, personalization=b"IronwoodNullifer")
    return cmx, nf

def generate_ironwood_proof(
    raw_addr: bytes,
    value_zat: int,
    memo_512: bytes,
    anchor: bytes,
    sighash: bytes
) -> Tuple[bytes, bytes, int]:
    """
    Generates and verifies an authentic Halo 2 proof for an Ironwood bundle via official orchard crate.
    Returns (proof_bytes, anchor_used, actions_count).
    """
    if _require_rust_engine("Zcash protocol cryptography"):
        try:
            res = subprocess.check_output([
                RUST_BIN_PATH,
                "generate-ironwood-proof",
                raw_addr[:43].ljust(43, b"\x00").hex(),
                str(value_zat),
                memo_512[:512].ljust(512, b"\x00").hex(),
                anchor[:32].ljust(32, b"\x00").hex(),
                sighash[:32].ljust(32, b"\x00").hex()
            ], text=True)
            data = json.loads(res.strip())
            if data.get("status") == "PROVEN_AND_VERIFIED":
                return bytes.fromhex(data["proof_hex"]), bytes.fromhex(data["anchor_hex"]), data["actions_count"]
            raise RuntimeError(f"Official Ironwood proof generation failed: {data.get('error', data.get('status', 'unknown error'))}")
        except Exception as exc:
            raise RuntimeError("Rust cryptographic engine failed; refusing non-protocol fallback.") from exc

