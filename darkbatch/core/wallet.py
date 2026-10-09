"""
DarkBatch simulated wallet for the off-chain FBA prototype.
Keys, receiver strings, and balances are local demo data, not a Zcash ZIP-316/Ironwood wallet.
- Spending Key (sk)
- Full Viewing Key (fvk)
- Incoming Viewing Key (ivk)
- Outgoing Viewing Key (ovk)
- Unified Address (u1...) with Ironwood receiver component
"""

import hashlib
import os
import secrets
from typing import Dict, Any, Tuple
from darkbatch.core.crypto import blake2b_digest, encrypt_512_memo, decrypt_512_memo

class ShieldedWallet:
    """
    Local demo wallet only; it cannot receive or spend real Zcash notes.
    """
    def __init__(self, alias: str, seed: bytes = None):
        self.alias = alias
        self.seed = seed or os.urandom(32)
        
        # 1. Derive Spending Key (sk)
        self.sk = blake2b_digest(self.seed, personalization=b"IronwoodSpendKey")
        
        # 2. Derive Full Viewing Key components (fvk = (ak, nk, rivk))
        self.ak = blake2b_digest(self.sk + b"\x01", personalization=b"IronwoodAuthKey_")
        self.nk = blake2b_digest(self.sk + b"\x02", personalization=b"IronwoodNullfKey")
        self.rivk = blake2b_digest(self.sk + b"\x03", personalization=b"IronwoodRInVKey_")
        
        # 3. Derive Incoming Viewing Key (ivk) and Outgoing Viewing Key (ovk)
        self.ivk = blake2b_digest(self.rivk, personalization=b"IronwoodIncomVK_")
        self.ovk = blake2b_digest(self.sk + b"\x04", personalization=b"IronwoodOutgoVK_")
        
        # 4. Derive Diversified Transmission Key & Receiver (pk_d)
        diversifier = blake2b_digest(self.ivk[:11], personalization=b"IronwoodDiversif")[:11]
        self.pk_d = blake2b_digest(diversifier + self.ivk, personalization=b"IronwoodPkD____")
        
        # 5. Construct Unified Address string (ZIP 316 format: u1...)
        raw_receiver = diversifier + self.pk_d
        checksum = hashlib.sha256(hashlib.sha256(raw_receiver).digest()).digest()[:4]
        self.unified_address = f"u1zcash_{alias.lower()}_{raw_receiver.hex()[:24]}"
        
        # Balance tracking
        self.shielded_balance_zat: int = 0
        self.quote_balance_cents: int = 0  # e.g. USDC in cents
        self.unspent_notes: list[Dict[str, Any]] = []

    @property
    def shielded_balance_zec(self) -> float:
        return self.shielded_balance_zat / 100_000_000.0

    @property
    def quote_balance_usd(self) -> float:
        return self.quote_balance_cents / 100.0

    def fund(self, zec: float = 0.0, usd: float = 0.0):
        """Funds the wallet with initial balances for trading simulation."""
        self.shielded_balance_zat += int(round(zec * 100_000_000))
        self.quote_balance_cents += int(round(usd * 100))

    def decrypt_incoming_memo(self, encrypted_memo: bytes) -> str:
        """
        Decrypts a local-demo 512-byte receipt encrypted directly with the demo IVK bytes.
        This is not Zcash Ironwood note decryption or an actual viewing-key derivation.
        """
        try:
            return decrypt_512_memo(encrypted_memo, self.ivk).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alias": self.alias,
            "unified_address": self.unified_address,
            "fvk_hex": (self.ak + self.nk).hex()[:32] + "...",
            "ivk_hex": self.ivk.hex()[:32] + "...",
            "shielded_balance_zec": self.shielded_balance_zec,
            "quote_balance_usd": self.quote_balance_usd,
            "unspent_notes_count": len(self.unspent_notes)
        }
