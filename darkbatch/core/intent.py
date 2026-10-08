"""
DarkBatch Swap Order Intent Specification
Implements off-chain Swap Order (SO) models inspired by ZIP 228 and Archer Exchange.
"""

from enum import Enum
import json
import time
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import ed25519
from darkbatch.core.crypto import (
    blake2b_digest,
    generate_scalar,
    pedersen_commit,
    generate_keypair,
)

class OrderDirection(str, Enum):
    BUY_ZEC = "BUY_ZEC"    # Buyer offers quote asset (e.g. USDC) to receive Shielded ZEC
    SELL_ZEC = "SELL_ZEC"  # Seller offers Shielded ZEC to receive quote asset

class SwapOrderIntent(BaseModel):
    """
    Cryptographically sealed off-chain swap order (intent).
    Conforms to ZIP 228 off-chain Action Group specifications.
    """
    intent_id: str
    direction: OrderDirection
    base_amount_zat: int = Field(gt=0, description="Amount in Zatoshis (1 ZEC = 100,000,000 zat)")
    limit_price_cents: int = Field(gt=0, description="Limit price in cents (e.g. 4250 = $42.50 / ZEC)")
    shielded_address: str = Field(description="Zcash Unified Address with Ironwood receiver")
    expiry_height: int = Field(description="Block height deadline")
    created_at_timestamp: float = Field(default_factory=time.time)
    
    # Cryptographic commitments & ZIP 228 keys
    blinding_scalar: int
    value_commitment: str
    bsk_share: int  # Binding signing key share for ZIP 228 bundle accumulation
    auth_pubkey_hex: str
    signature_hex: str
    
    @property
    def base_amount_zec(self) -> float:
        return self.base_amount_zat / 100_000_000.0

    @property
    def limit_price_usd(self) -> float:
        return self.limit_price_cents / 100.0

    @property
    def quote_amount_usd(self) -> float:
        return self.base_amount_zec * self.limit_price_usd

    def get_digest(self) -> bytes:
        """Computes deterministic Blake2b digest of intent terms for signing."""
        payload = f"{self.direction.value}:{self.base_amount_zat}:{self.limit_price_cents}:{self.shielded_address}:{self.expiry_height}:{self.value_commitment}".encode()
        return blake2b_digest(payload, personalization=b"DarkBatchIntent")

    def verify_signature(self) -> bool:
        """Verifies that the intent signature is valid."""
        try:
            pubkey_bytes = bytes.fromhex(self.auth_pubkey_hex)
            sig_bytes = bytes.fromhex(self.signature_hex)
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            pubkey.verify(sig_bytes, self.get_digest())
            return True
        except Exception:
            return False

def create_intent(
    direction: OrderDirection,
    zec_amount: float,
    limit_price_usd: float,
    shielded_address: str,
    current_height: int = 4134010,
    validity_blocks: int = 120,
    private_key: Optional[ed25519.Ed25519PrivateKey] = None
) -> SwapOrderIntent:
    """Helper factory to instantiate and cryptographically sign a SwapOrderIntent."""
    base_amount_zat = int(round(zec_amount * 100_000_000))
    limit_price_cents = int(round(limit_price_usd * 100))
    expiry_height = current_height + validity_blocks
    
    # Generate cryptographic blinding factor and Pedersen value commitment
    blinding_scalar = generate_scalar()
    value_commitment = pedersen_commit(base_amount_zat, blinding_scalar)
    
    # Generate ZIP 228 binding signature key share
    bsk_share = generate_scalar()
    
    if private_key is None:
        private_key, pubkey = generate_keypair()
    else:
        pubkey = private_key.public_key()
        
    auth_pubkey_hex = pubkey.public_bytes_raw().hex()
    
    # Temporary intent to compute digest
    temp_intent = SwapOrderIntent(
        intent_id="temp",
        direction=direction,
        base_amount_zat=base_amount_zat,
        limit_price_cents=limit_price_cents,
        shielded_address=shielded_address,
        expiry_height=expiry_height,
        blinding_scalar=blinding_scalar,
        value_commitment=value_commitment,
        bsk_share=bsk_share,
        auth_pubkey_hex=auth_pubkey_hex,
        signature_hex=""
    )
    
    digest = temp_intent.get_digest()
    sig = private_key.sign(digest)
    intent_id = blake2b_digest(sig).hex()[:32]
    
    return SwapOrderIntent(
        intent_id=intent_id,
        direction=direction,
        base_amount_zat=base_amount_zat,
        limit_price_cents=limit_price_cents,
        shielded_address=shielded_address,
        expiry_height=expiry_height,
        blinding_scalar=blinding_scalar,
        value_commitment=value_commitment,
        bsk_share=bsk_share,
        auth_pubkey_hex=auth_pubkey_hex,
        signature_hex=sig.hex()
    )
