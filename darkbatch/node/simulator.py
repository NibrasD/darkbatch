"""
DarkBatch local state simulator.

This is not Zebra and does not implement Zcash consensus. It must never mine or
accept a purported settlement transaction as evidence of network confirmation.
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
    Exposes local UI/demo state only. Heights and roots are synthetic; no consensus
    validation or transaction acceptance is performed.
    """
    def __init__(self, initial_height: int = 4134010):
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
        Refuse transaction submission. A local simulator cannot verify Ironwood proofs,
        signatures, balances, note witnesses, or consensus, and must not create fake blocks.
        """
        vg_id = bundle_dict.get("version_group_id")
        if vg_id is not None and vg_id != 0xD884B698:
            return False, f"Target metadata has invalid v6 version-group ID: {hex(vg_id)}"
        branch_id = bundle_dict.get("consensus_branch_id")
        if branch_id is not None and branch_id != 0x37A5165B:
            return False, f"Target metadata has invalid Ironwood branch ID: {hex(branch_id)} (expected 0x37A5165B for NU6.3)"
        return False, "Local simulator is not a consensus validator and refuses transaction submission; use a compatible Zebra node."

    def get_blockchain_info(self) -> Dict[str, Any]:
        """Returns synthetic UI metadata; this is deliberately not a Zcash RPC response."""
        return {
            "chain": "local-simulation",
            "subversion": "/DarkBatch-Local-Simulator/ (not Zebra)",
            "validator": "DarkBatch local simulator (NOT a consensus validator)",
            "blocks": self.height,
            "headers": self.height,
            "bestblockhash": self.blocks[-1].hash,
            "difficulty": 1.0,
            "verificationprogress": 0.0,
            "consensus": {
                "chaintip": self.blocks[-1].hash,
                "nextblock": "Ironwood target metadata only",
                "branch_id": "0x37a5165b",
                "activation_height": 4134000
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
