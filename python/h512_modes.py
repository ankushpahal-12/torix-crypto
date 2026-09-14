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
TAG_TURBO_512 = 0x06


def h512_custom_tag(data: Union[bytes, bytearray, str], domain_tag: int, num_rounds: int = 16) -> bytes:
    """Computes H-512 with an explicit HAIFA domain separation tag."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    rounds = 10 if domain_tag == TAG_TURBO_512 else num_rounds
    return H512Hasher(domain_tag=domain_tag, num_rounds=rounds).update(data).digest()


# ==============================================================================
# MODULE 1: PARALLEL BINARY MERKLE TREE HASHING (H-512-Tree)
# ==============================================================================
class H512TreeHasher:
    """
    BLAKE3-style parallel tree hasher for Project H-512.
    Divides data into 1024-byte chunks, hashes leaves in parallel with TAG_TREE_LEAF (0x02),
    reduces a binary Merkle tree with TAG_TREE_INTERNAL (0x03), and finalizes root with TAG_TREE_ROOT (0x04).
    """

    def __init__(self, chunk_size: int = 1024, num_workers: int = 4, num_rounds: int = 16):
        self.chunk_size = chunk_size
        self.num_workers = num_workers
        self.num_rounds = num_rounds

    def hash(self, data: bytes) -> bytes:
        """One-shot parallel tree hashing."""
        n = len(data)
        # Base case: if data fits in a single chunk, return standard hash
        if n <= self.chunk_size:
            if self.num_rounds == 10:
                return h512_custom_tag(data, TAG_TURBO_512, num_rounds=10)
            return h512_custom_tag(data, TAG_STANDARD_512, num_rounds=16)

        # 1. Partition data into chunks
        chunks = [data[i : i + self.chunk_size] for i in range(0, n, self.chunk_size)]

        # 2. Leaf stage: hash all chunks using TAG_TREE_LEAF
        if self.num_workers > 1 and len(chunks) > 4:
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                leaf_hashes = list(
                    executor.map(lambda c: h512_custom_tag(c, TAG_TREE_LEAF, num_rounds=self.num_rounds), chunks)
                )
        else:
            leaf_hashes = [h512_custom_tag(c, TAG_TREE_LEAF, num_rounds=self.num_rounds) for c in chunks]

        # 3. Binary tree reduction
        nodes = leaf_hashes
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Combine left and right sibling nodes (64 + 64 = 128 bytes)
                    parent = h512_custom_tag(nodes[i] + nodes[i + 1], TAG_TREE_INTERNAL, num_rounds=self.num_rounds)
                    next_level.append(parent)
                else:
                    # Promote lone odd node to next level
                    next_level.append(nodes[i])
            nodes = next_level

        # 4. Finalize root
        return h512_custom_tag(nodes[0], TAG_TREE_ROOT, num_rounds=self.num_rounds)


def h512_tree_hash(data: bytes, chunk_size: int = 1024, num_workers: int = 4) -> bytes:
    """Convenience functional interface for parallel tree hashing."""
    return H512TreeHasher(chunk_size=chunk_size, num_workers=num_workers, num_rounds=16).hash(data)


def h512_turbo_tree_hash(data: bytes, chunk_size: int = 1024, num_workers: int = 4) -> bytes:
    """Convenience functional interface for parallel tree hashing with Turbo-10 profile."""
    return H512TreeHasher(chunk_size=chunk_size, num_workers=num_workers, num_rounds=10).hash(data)


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


# ==============================================================================
# MODULE 5: SEEKABLE STREAMING CONTAINER (.t512 / Bao-style)
# ==============================================================================
T512_MAGIC = b"T512BAO\x01"
T512_HEADER_SIZE = 32
T512_FLAG_STANDARD = 0x00
T512_FLAG_TURBO = 0x01


def t512_container_size(content_length: int, chunk_size: int = 1024) -> int:
    """Calculates exact container size in bytes for given payload length and chunk size."""
    if chunk_size == 0:
        chunk_size = 1024
    num_chunks = (content_length + chunk_size - 1) // chunk_size if content_length > 0 else 0
    if num_chunks <= 1:
        return T512_HEADER_SIZE + content_length
    total_nodes = 0
    cur = num_chunks
    while True:
        total_nodes += cur
        if cur <= 1:
            break
        cur = (cur + 1) // 2
    return T512_HEADER_SIZE + total_nodes * 64 + content_length


def encode_t512(data: bytes, chunk_size: int = 1024, is_turbo: bool = False) -> bytes:
    """
    Encodes raw data bytes into a self-contained, seekable .t512 streaming container.
    Container layout: [32-byte Header] [Precomputed Merkle Tree Index] [Raw Payload]
    """
    if chunk_size == 0:
        chunk_size = 1024
    content_len = len(data)
    num_rounds = 10 if is_turbo else 16
    flags = T512_FLAG_TURBO if is_turbo else T512_FLAG_STANDARD

    # 1. Header: 32 bytes
    header = bytearray(32)
    header[0:8] = T512_MAGIC
    header[8:16] = struct.pack("<Q", content_len)
    header[16:20] = struct.pack("<I", chunk_size)
    header[20:24] = struct.pack("<I", flags)
    header[24:32] = b"\x00" * 8

    num_chunks = (content_len + chunk_size - 1) // chunk_size if content_len > 0 else 0
    if num_chunks <= 1:
        return bytes(header) + data

    # 2. Build tree levels
    chunks = [data[i : i + chunk_size] for i in range(0, content_len, chunk_size)]
    level0 = [h512_custom_tag(c, TAG_TREE_LEAF, num_rounds=num_rounds) for c in chunks]

    tree_bytes = bytearray()
    for leaf in level0:
        tree_bytes.extend(leaf)

    prev_level = level0
    while len(prev_level) > 1:
        next_level = []
        for i in range(0, len(prev_level), 2):
            if i + 1 < len(prev_level):
                parent = h512_custom_tag(prev_level[i] + prev_level[i + 1], TAG_TREE_INTERNAL, num_rounds=num_rounds)
                next_level.append(parent)
            else:
                next_level.append(prev_level[i])
        for node in next_level:
            tree_bytes.extend(node)
        prev_level = next_level

    return bytes(header) + bytes(tree_bytes) + data


def encode_t512_file(input_path: str, output_path: str, chunk_size: int = 1024, is_turbo: bool = False) -> None:
    """Encodes a file into a .t512 container file."""
    with open(input_path, "rb") as f:
        data = f.read()
    container = encode_t512(data, chunk_size=chunk_size, is_turbo=is_turbo)
    with open(output_path, "wb") as f:
        f.write(container)


def verify_t512_slice(container: bytes, offset: int, length: int, expected_root: bytes) -> bytes:
    """
    Extracts and cryptographically verifies a slice [offset, offset + length) from a .t512 container.
    Verifies leaf chunk digests and the O(log N) Merkle authentication path to expected_root.
    Raises ValueError on any tampering or mismatch.
    """
    if len(container) < T512_HEADER_SIZE:
        raise ValueError("Container truncated: missing header")
    if container[:8] != T512_MAGIC:
        raise ValueError("Invalid magic bytes: not a .t512 container")

    content_len = struct.unpack("<Q", container[8:16])[0]
    chunk_size = struct.unpack("<I", container[16:20])[0]
    flags = struct.unpack("<I", container[20:24])[0]
    if chunk_size == 0:
        chunk_size = 1024

    is_turbo = (flags & T512_FLAG_TURBO) != 0
    num_rounds = 10 if is_turbo else 16

    expected_size = t512_container_size(content_len, chunk_size)
    if len(container) < expected_size:
        raise ValueError("Container truncated: smaller than expected size")

    if offset + length > content_len:
        raise ValueError(f"Slice range [{offset}, {offset + length}) exceeds content length {content_len}")
    if length == 0:
        return b""

    num_chunks = (content_len + chunk_size - 1) // chunk_size if content_len > 0 else 0

    if num_chunks <= 1:
        payload = container[T512_HEADER_SIZE : T512_HEADER_SIZE + content_len]
        computed_root = h512.h512_turbo_hash(payload) if is_turbo else h512.h512_hash(payload)
        if not h512.constant_time_compare(computed_root, expected_root):
            raise ValueError("Root hash mismatch: single chunk container corrupted or tampered")
        return payload[offset : offset + length]

    # Multi-chunk verification
    level_counts = []
    level_offsets = []
    cur_count = num_chunks
    cur_offset = T512_HEADER_SIZE
    total_nodes = 0

    while True:
        level_counts.append(cur_count)
        level_offsets.append(cur_offset)
        total_nodes += cur_count
        cur_offset += cur_count * 64
        if cur_count <= 1:
            break
        cur_count = (cur_count + 1) // 2

    num_levels = len(level_counts)
    payload_base = T512_HEADER_SIZE + total_nodes * 64

    # Verify top node against expected_root
    top_node = container[level_offsets[-1] : level_offsets[-1] + 64]
    computed_root = h512_custom_tag(top_node, TAG_TREE_ROOT, num_rounds=num_rounds)
    if not h512.constant_time_compare(computed_root, expected_root):
        raise ValueError("Root hash mismatch: Merkle root rejected")

    # Verify chunks covering [offset, offset + length)
    first_chunk = offset // chunk_size
    last_chunk = (offset + length - 1) // chunk_size

    for c in range(first_chunk, last_chunk + 1):
        c_ptr = payload_base + c * chunk_size
        c_len = (content_len - c * chunk_size) if (c == num_chunks - 1) else chunk_size
        chunk_data = container[c_ptr : c_ptr + c_len]
        leaf_hash = h512_custom_tag(chunk_data, TAG_TREE_LEAF, num_rounds=num_rounds)

        expected_leaf = container[level_offsets[0] + c * 64 : level_offsets[0] + (c + 1) * 64]
        if not h512.constant_time_compare(leaf_hash, expected_leaf):
            raise ValueError(f"Leaf chunk {c} hash mismatch: payload corrupted or tampered")

        # Verify path to top node
        idx = c
        for lvl in range(num_levels - 1):
            left_child = idx if (idx % 2 == 0) else (idx - 1)
            right_child = left_child + 1
            parent_idx = idx // 2
            parent_node = container[level_offsets[lvl + 1] + parent_idx * 64 : level_offsets[lvl + 1] + (parent_idx + 1) * 64]

            if right_child < level_counts[lvl]:
                left_hash = container[level_offsets[lvl] + left_child * 64 : level_offsets[lvl] + (left_child + 1) * 64]
                right_hash = container[level_offsets[lvl] + right_child * 64 : level_offsets[lvl] + (right_child + 1) * 64]
                computed_parent = h512_custom_tag(left_hash + right_hash, TAG_TREE_INTERNAL, num_rounds=num_rounds)
                if not h512.constant_time_compare(computed_parent, parent_node):
                    raise ValueError(f"Internal Merkle node mismatch at level {lvl}")
            else:
                promoted_hash = container[level_offsets[lvl] + left_child * 64 : level_offsets[lvl] + (left_child + 1) * 64]
                if not h512.constant_time_compare(promoted_hash, parent_node):
                    raise ValueError(f"Promoted node mismatch at level {lvl}")
            idx = parent_idx

    payload = container[payload_base : payload_base + content_len]
    return payload[offset : offset + length]


def verify_t512_file_slice(t512_path: str, offset: int, length: int, expected_root: bytes) -> bytes:
    """Extracts and verifies a slice from a .t512 container file on disk."""
    with open(t512_path, "rb") as f:
        container = f.read()
    return verify_t512_slice(container, offset, length, expected_root)
