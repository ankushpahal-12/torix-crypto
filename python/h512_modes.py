"""
Project H-512: Extended Cryptographic Modes & Constructions (Phase 13)
======================================================================
Architectural Modules:
1. Domain-Separated Hasher (Tags 0x00..0x05)
2. Parallel Binary Merkle Tree Hashing (H-512-Tree) & Merkle Proof System
3. RFC 5869 HMAC-Based Key Derivation Function (HKDF-H512)
4. Extendable-Output Function (H-512-XOF / Variable Length Output)
"""

import os
import sys

# Ensure package directory is in sys.path for standalone imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


import math
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple, Union

import h512
from h512 import H512Hasher, hmac_h512

# Domain Separation Constants
TAG_STANDARD_512 = 0x00
TAG_TRUNCATED_256 = 0x01
TAG_TREE_LEAF = 0x02
TAG_TREE_INTERNAL = 0x03
TAG_TREE_ROOT = 0x04
TAG_XOF_STREAM = 0x05


def h512_custom_tag(data: Union[bytes, bytearray, str], domain_tag: int) -> bytes:
    """Computes H-512 with an explicit HAIFA domain separation tag."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return H512Hasher(domain_tag=domain_tag).update(data).digest()


# ==============================================================================
# MODULE 1: PARALLEL BINARY MERKLE TREE HASHING (H-512-Tree)
# ==============================================================================
class H512TreeHasher:
    """
    BLAKE3-style parallel tree hasher for Project H-512.
    Divides data into 1024-byte chunks, hashes leaves in parallel with TAG_TREE_LEAF (0x02),
    reduces a binary Merkle tree with TAG_TREE_INTERNAL (0x03), and finalizes root with TAG_TREE_ROOT (0x04).
    """

    def __init__(self, chunk_size: int = 1024, num_workers: int = 4):
        self.chunk_size = chunk_size
        self.num_workers = num_workers

    def hash(self, data: bytes) -> bytes:
        """One-shot parallel tree hashing."""
        n = len(data)
        # Base case: if data fits in a single chunk, return standard H-512 hash
        if n <= self.chunk_size:
            return h512_custom_tag(data, TAG_STANDARD_512)

        # 1. Partition data into chunks
        chunks = [data[i : i + self.chunk_size] for i in range(0, n, self.chunk_size)]

        # 2. Leaf stage: hash all chunks using TAG_TREE_LEAF
        if self.num_workers > 1 and len(chunks) > 4:
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                leaf_hashes = list(
                    executor.map(lambda c: h512_custom_tag(c, TAG_TREE_LEAF), chunks)
                )
        else:
            leaf_hashes = [h512_custom_tag(c, TAG_TREE_LEAF) for c in chunks]

        # 3. Binary tree reduction
        nodes = leaf_hashes
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Combine left and right sibling nodes (64 + 64 = 128 bytes)
                    parent = h512_custom_tag(nodes[i] + nodes[i + 1], TAG_TREE_INTERNAL)
                    next_level.append(parent)
                else:
                    # Promote lone odd node to next level
                    next_level.append(nodes[i])
            nodes = next_level

        # 4. Finalize root
        return h512_custom_tag(nodes[0], TAG_TREE_ROOT)


def h512_tree_hash(data: bytes, chunk_size: int = 1024, num_workers: int = 4) -> bytes:
    """Convenience functional interface for parallel tree hashing."""
    return H512TreeHasher(chunk_size=chunk_size, num_workers=num_workers).hash(data)


# ==============================================================================
# MODULE 2: MERKLE AUTHENTICATION PROOF SYSTEM (O(log N) Verifiable Streaming)
# ==============================================================================
class MerkleTreeBuilder:
    """Constructs the full tree structure to generate inclusion proofs."""

    def __init__(self, data: bytes, chunk_size: int = 1024):
        self.chunk_size = chunk_size
        self.data = data
        n = len(data)
        if n <= chunk_size:
            self.chunks = [data]
            self.levels = [[h512_custom_tag(data, TAG_STANDARD_512)]]
            self.root = self.levels[0][0]
            return

        self.chunks = [data[i : i + chunk_size] for i in range(0, n, chunk_size)]
        self.levels: List[List[bytes]] = []

        # Level 0: leaves
        current = [h512_custom_tag(c, TAG_TREE_LEAF) for c in self.chunks]
        self.levels.append(current)

        # Intermediate levels
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    parent = h512_custom_tag(current[i] + current[i + 1], TAG_TREE_INTERNAL)
                    next_level.append(parent)
                else:
                    next_level.append(current[i])
            self.levels.append(next_level)
            current = next_level

        # Root level
        self.root = h512_custom_tag(current[0], TAG_TREE_ROOT)

    def get_proof(self, chunk_index: int) -> List[Tuple[str, bytes]]:
        """
        Generates an authentication path for chunk_index.
        Each entry is ('left'|'right', sibling_hash).
        """
        if len(self.chunks) == 1:
            return []

        proof: List[Tuple[str, bytes]] = []
        idx = chunk_index
        for lvl in range(len(self.levels) - 1):
            nodes = self.levels[lvl]
            if idx % 2 == 0:
                # Sibling is to the right
                if idx + 1 < len(nodes):
                    proof.append(("right", nodes[idx + 1]))
            else:
                # Sibling is to the left
                proof.append(("left", nodes[idx - 1]))
            idx = idx // 2
        return proof


def verify_merkle_proof(chunk: bytes, chunk_index: int, proof: List[Tuple[str, bytes]], root: bytes) -> bool:
    """Verifies that chunk is member of tree with root."""
    if not proof:
        # Single chunk case
        return h512_custom_tag(chunk, TAG_STANDARD_512) == root

    current = h512_custom_tag(chunk, TAG_TREE_LEAF)
    for direction, sibling in proof:
        if direction == "right":
            current = h512_custom_tag(current + sibling, TAG_TREE_INTERNAL)
        else:
            current = h512_custom_tag(sibling + current, TAG_TREE_INTERNAL)

    calculated_root = h512_custom_tag(current, TAG_TREE_ROOT)
    return calculated_root == root


# ==============================================================================
# MODULE 3: RFC 5869 HMAC-BASED KEY DERIVATION FUNCTION (HKDF-H512)
# ==============================================================================
def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """
    HKDF-Extract: Extracts pseudorandom key (PRK) from Input Keying Material (IKM).
    PRK = HMAC-H512(salt, IKM) -> 64 bytes (512 bits).
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * 64
    return hmac_h512(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand: Expands PRK to arbitrary output length L (up to 255 * 64 bytes).
    """
    assert len(prk) == 64, f"PRK must be exactly 64 bytes for H-512, got {len(prk)}"
    assert length <= 255 * 64, f"Requested length {length} exceeds HKDF max bound (16,320 bytes)"

    n_blocks = math.ceil(length / 64.0)
    okm = bytearray()
    t_prev = b""

    for i in range(1, n_blocks + 1):
        step_payload = t_prev + info + bytes([i])
        t_prev = hmac_h512(prk, step_payload)
        okm.extend(t_prev)

    return bytes(okm[:length])


def hkdf_h512(salt: Optional[bytes], ikm: bytes, info: bytes, length: int) -> bytes:
    """One-step full HKDF (Extract and Expand) using H-512."""
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ==============================================================================
# MODULE 4: EXTENDABLE-OUTPUT FUNCTION (H-512-XOF)
# ==============================================================================
def h512_xof(message: bytes, length: int) -> bytes:
    """
    Arbitrary-length Extendable-Output Function (XOF / SHAKE-style) for Project H-512.
    Produces length pseudorandom bytes deterministically from message under TAG_XOF_STREAM (0x05).
    """
    n_blocks = math.ceil(length / 64.0)
    stream = bytearray()

    for c in range(n_blocks):
        # Format counter payload: Message || uint64_be(counter) || uint64_be(requested_length)
        counter_header = struct.pack(">QQ", c, length)
        payload = message + counter_header
        block_digest = h512_custom_tag(payload, TAG_XOF_STREAM)
        stream.extend(block_digest)

    return bytes(stream[:length])
