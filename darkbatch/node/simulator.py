"""
DarkBatch Zcash Ironwood Node Simulator
Simulates consensus rules, block mining, nullifier double-spend prevention,
and the Incremental Note Commitment Tree for the Ironwood shielded pool.
"""

from dataclasses import dataclass, field
import hashlib
import time
from typing import Dict, List, Set, Optional, Any, Tuple
from darkbatch.core.merkle import IncrementalNoteTree
from darkbatch.core.crypto import blake2b_digest

@dataclass
class SimulatedBlock:
    height: int
    hash: str
    prev_hash: str
    timestamp: float
    anchor_root: str
    tx_count: int
    transactions: List[Dict[str, Any]] = field(default_factory=list)

class ZcashNodeSimulator:
    """
    Simulates a consensus-verifying Zcash Ironwood node (Zebra equivalent).
    """
    def __init__(self, initial_height: int = 3450000):
        self.height = initial_height
        self.tree = IncrementalNoteTree()
        self.nullifier_set: Set[str] = set()
        self.blocks: List[SimulatedBlock] = []
        self.mempool: List[Dict[str, Any]] = []
        
        # Initialize Genesis / Initial Block Anchor
        genesis_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        genesis_block = SimulatedBlock(
            height=self.height,
            hash=blake2b_digest(f"Genesis:{self.height}".encode(), personalization=b"ZcashBlockHeader").hex(),
            prev_hash=genesis_prev,
            timestamp=time.time(),
            anchor_root=self.tree.root_hex(),
            tx_count=0
        )
        self.blocks.append(genesis_block)

    def current_anchor(self) -> str:
        """Returns the current Merkle root (anchor) of the note commitment tree."""
        return self.tree.root_hex()

    def submit_settlement_bundle(self, bundle_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates consensus rules for a ZIP 228 / Transaction v6 bundle:
        1. Checks nullifiers against double-spending.
        2. Appends new note commitments to the Ironwood Incremental Tree.
        3. Mines a new block containing the settlement.
        """
        tx_id = bundle_dict.get("tx_id", "")
        action_groups = bundle_dict.get("action_groups", [])

        # 1. Consensus Rule: Verify Nullifiers (Double-Spend Check)
        incoming_nullifiers = []
        for ag in action_groups:
            for act in ag.get("actions", []):
                nf = act.get("nullifier") or act.get("nullifier_hex")
                if nf:
                    if nf in self.nullifier_set:
                        return False, f"Consensus Error: Nullifier {nf[:16]}... already spent!"
                    incoming_nullifiers.append(nf)

        # 2. Append new Note Commitments to the tree
        for ag in action_groups:
            for act in ag.get("actions", []):
                cm = act.get("cm_point") or act.get("cm_point_hex")
                if cm:
                    self.tree.append(bytes.fromhex(cm))

        # Commit nullifiers to spent set
        for nf in incoming_nullifiers:
            self.nullifier_set.add(nf)

        # 3. Mine Block containing the settlement transaction
        self.height += 1
        prev_hash = self.blocks[-1].hash
        block_hash = blake2b_digest(
            f"Block:{self.height}:{prev_hash}:{tx_id}".encode(),
            personalization=b"ZcashBlockHeader"
        ).hex()

        new_block = SimulatedBlock(
            height=self.height,
            hash=block_hash,
            prev_hash=prev_hash,
            timestamp=time.time(),
            anchor_root=self.tree.root_hex(),
            tx_count=1,
            transactions=[bundle_dict]
        )
        self.blocks.append(new_block)

        return True, block_hash

    def get_blockchain_info(self) -> Dict[str, Any]:
        """Returns standard Zcash RPC getblockchaininfo response."""
        return {
            "chain": "main",
            "blocks": self.height,
            "headers": self.height,
            "bestblockhash": self.blocks[-1].hash,
            "difficulty": 1.0,
            "verificationprogress": 1.0,
            "consensus": {
                "chaintip": self.blocks[-1].hash,
                "nextblock": "Ironwood",
                "branch_id": "0x2f8b66c3"
            },
            "pools": {
                "sprout": {"status": "disabled"},
                "sapling": {"status": "active"},
                "orchard": {"status": "withdrawal_only (NU6.3)"},
                "ironwood": {
                    "status": "active",
                    "anchor": self.current_anchor(),
                    "spent_nullifiers_count": len(self.nullifier_set),
                    "commitments_count": len(self.tree.commitments)
                }
            }
        }

    def get_block(self, height: int) -> Optional[Dict[str, Any]]:
        for b in self.blocks:
            if b.height == height:
                return {
                    "height": b.height,
                    "hash": b.hash,
                    "prev_hash": b.prev_hash,
                    "timestamp": b.timestamp,
                    "anchor_root": b.anchor_root,
                    "tx_count": b.tx_count,
                    "transactions": b.transactions
                }
        return None
