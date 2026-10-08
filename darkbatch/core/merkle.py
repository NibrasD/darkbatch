"""
DarkBatch Incremental Note Commitment Tree
Implements a 32-level Merkle tree matching Zcash Shielded Note Commitment Tree specifications
(Sapling / Orchard / Ironwood consensus trees).
"""

import hashlib
from typing import List, Optional, Tuple

TREE_DEPTH = 32

def hash_combine(left: bytes, right: bytes, level: int) -> bytes:
    """Combines two Merkle nodes using Zcash-style Blake2b tree hashing."""
    h = hashlib.blake2b(digest_size=32, person=f"ZcashTreeLvl{level:02d}".encode())
    h.update(left)
    h.update(right)
    return h.digest()

# Precompute empty roots for each level
EMPTY_LEAVES: List[bytes] = [hashlib.blake2b(b"IronwoodEmptyLeaf", digest_size=32).digest()]
for lvl in range(TREE_DEPTH):
    EMPTY_LEAVES.append(hash_combine(EMPTY_LEAVES[lvl], EMPTY_LEAVES[lvl], lvl))

class IncrementalNoteTree:
    """
    Incremental Merkle tree maintaining note commitments and computing anchors.
    """
    def __init__(self, depth: int = TREE_DEPTH):
        self.depth = depth
        self.commitments: List[bytes] = []
        self._root_cache: Optional[bytes] = None

    def append(self, commitment: bytes) -> int:
        """Appends a new note commitment to the tree, returning its position."""
        if len(commitment) != 32:
            raise ValueError("Commitment must be 32 bytes")
        pos = len(self.commitments)
        self.commitments.append(commitment)
        self._root_cache = None
        return pos

    def root(self) -> bytes:
        """Computes the current Merkle root (anchor) of the tree."""
        if self._root_cache is not None:
            return self._root_cache

        if not self.commitments:
            self._root_cache = EMPTY_LEAVES[self.depth]
            return self._root_cache

        current_level = list(self.commitments)
        for lvl in range(self.depth):
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = EMPTY_LEAVES[lvl]
                next_level.append(hash_combine(left, right, lvl))
            current_level = next_level

        self._root_cache = current_level[0]
        return self._root_cache

    def root_hex(self) -> str:
        return self.root().hex()

    def get_witness(self, position: int) -> List[Tuple[bytes, bool]]:
        """
        Generates an authentication path (witness) for note at `position`.
        Returns list of (sibling_hash, is_right_sibling).
        """
        if position < 0 or position >= len(self.commitments):
            raise IndexError("Position out of range")

        auth_path = []
        idx = position
        current_level = list(self.commitments)

        for lvl in range(self.depth):
            sibling_idx = idx ^ 1
            if sibling_idx < len(current_level):
                sibling_hash = current_level[sibling_idx]
            else:
                sibling_hash = EMPTY_LEAVES[lvl]
            is_right = (idx % 2 == 0)
            auth_path.append((sibling_hash, is_right))

            # Move up
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else EMPTY_LEAVES[lvl]
                next_level.append(hash_combine(left, right, lvl))
            current_level = next_level
            idx //= 2

        return auth_path
