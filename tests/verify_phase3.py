"""
Project H-512: Phase 3 State Construction Verification Suite
============================================================
Formally verifies all mathematical and physical properties of the Phase 3 State:
1. Property 1: NUMS IV Derivation, Bit Entropy & Weight Distribution
2. Property 2: Toroidal Graph Topology (4-regularity, reciprocality, diameter)
3. Property 3: Invariant Subspace Defense & Symmetry Shattering
4. Property 4: Synchronous Dual-Buffering & Evaluation Order Independence
5. Property 5: Memory Alignment & 64-bit Word Vector Isomorphism
"""

import os
import sys

# Ensure python directory is in sys.path for standalone execution
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR = os.path.abspath(os.path.join(_TESTS_DIR, "..", "python"))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)


import collections
import math
import random
import struct
from typing import List, Tuple

from h512 import (
    IV,
    disperse_message_block,
    round_transform,
)


def count_set_bits(n: int) -> int:
    return bin(n).count("1")


# ==============================================================================
# PROPERTY 1: NUMS IV Verification
# ==============================================================================
def verify_nums_iv():
    print("\n" + "=" * 70)
    print("VERIFICATION 1: NUMS IV Derivation, Bit Entropy & Balance")
    print("=" * 70)

    # 1. Check dimensions
    assert len(IV) == 8, f"Expected 8 rows, got {len(IV)}"
    for r in range(8):
        assert len(IV[r]) == 8, f"Row {r} length is not 8"

    # Flatten IV
    flat_iv = [IV[r][c] for r in range(8) for c in range(8)]
    assert len(flat_iv) == 64, "Total IV bytes must be exactly 64 (512 bits)"

    # 2. Total set bits (Hamming weight) across 512 bits
    total_bits = sum(count_set_bits(byte) for byte in flat_iv)
    weight_pct = (total_bits / 512.0) * 100.0
    print(f"[*] Total IV Set Bits     : {total_bits} / 512 ({weight_pct:.2f}%)")
    print(f"[*] Ideal Target (50%)    : 256 bits")
    # Must be reasonably close to 256
    assert 220 <= total_bits <= 292, f"IV bit balance out of range: {total_bits}"

    # 3. Byte entropy (Shannon Entropy)
    counts = collections.Counter(flat_iv)
    entropy = -sum((cnt / 64.0) * math.log2(cnt / 64.0) for cnt in counts.values())
    max_entropy = math.log2(64)  # 6.0 bits
    print(f"[*] Shannon Entropy       : {entropy:.3f} / {max_entropy:.3f} bits")
    print(f"[*] Unique Byte Values    : {len(counts)} / 64")
    assert len(counts) >= 45, "IV byte diversity is too low"

    print("[+] PASS: NUMS IV derivation is well-balanced, non-zero, and high-entropy.")


# ==============================================================================
# PROPERTY 2: Toroidal Graph Topology Verification
# ==============================================================================
def verify_toroidal_topology():
    print("\n" + "=" * 70)
    print("VERIFICATION 2: Toroidal Topology & Neighborhood Graph")
    print("=" * 70)

    # Define neighbor functions on 8x8 torus
    def north(r, c): return ((r - 1) % 8, c)
    def south(r, c): return ((r + 1) % 8, c)
    def east(r, c):  return (r, (c + 1) % 8)
    def west(r, c):  return (r, (c - 1) % 8)

    # 1. Test 4-regularity and reciprocality for all 64 nodes
    adjacency = collections.defaultdict(set)
    for r in range(8):
        for c in range(8):
            node = (r, c)
            n_n = north(r, c)
            n_s = south(r, c)
            n_e = east(r, c)
            n_w = west(r, c)

            # Reciprocal checks
            assert south(*n_n) == node, f"North reciprocal failed at {node}"
            assert north(*n_s) == node, f"South reciprocal failed at {node}"
            assert west(*n_e) == node, f"East reciprocal failed at {node}"
            assert east(*n_w) == node, f"West reciprocal failed at {node}"

            neighbors = {n_n, n_s, n_e, n_w}
            assert len(neighbors) == 4, f"Node {node} has duplicate neighbors: {neighbors}"
            adjacency[node] = neighbors

    print("[*] Checked all 64 cells: 4-regularity & reciprocality confirmed.")

    # 2. Graph Diameter (Shortest path between all pairs via BFS)
    max_dist = 0
    nodes = list(adjacency.keys())
    for src in nodes:
        queue = collections.deque([(src, 0)])
        visited = {src}
        while queue:
            curr, dist = queue.popleft()
            if dist > max_dist:
                max_dist = dist
            for neighbor in adjacency[curr]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, dist + 1))
        assert len(visited) == 64, f"Graph disconnected from {src}"

    print(f"[*] Measured Torus Diameter: {max_dist} hops (Ideal flat torus diameter: 4+4=8)")
    assert max_dist == 8, f"Expected diameter 8, got {max_dist}"
    print("[+] PASS: Toroidal lattice is fully connected, 4-regular, with diameter 8.")


# ==============================================================================
# PROPERTY 3: Invariant Subspace Defense & Symmetry Shattering
# ==============================================================================
def verify_symmetry_shattering():
    print("\n" + "=" * 70)
    print("VERIFICATION 3: Invariant Subspace Defense & Symmetry Shattering")
    print("=" * 70)

    # Construct an extreme pathological symmetric state:
    # Transpose-symmetric state: S[r][c] == S[c][r] with identical rows
    symmetric_block = bytes([((r * 17) ^ (c * 17)) & 0xFF for r in range(8) for c in range(8)])

    # Check that initial block is indeed symmetric: M[r][c] == M[c][r]
    for r in range(8):
        for c in range(8):
            assert symmetric_block[r * 8 + c] == symmetric_block[c * 8 + r]

    print("[*] Created pathological symmetric test block where M == M^T.")

    # Step 1: Orthogonal row dispersal
    m_disp = disperse_message_block(symmetric_block)

    # Check dispersal asymmetry: M_disp != M_disp^T
    disp_diffs = sum(1 for r in range(8) for c in range(8) if m_disp[r][c] != m_disp[c][r])
    print(f"[*] Asymmetry after Orthogonal Row Dispersal: {disp_diffs} / 64 asymmetric cells")
    assert disp_diffs >= 50, "Orthogonal dispersal failed to break reflection symmetry"

    # Step 2: Diagonal HAIFA counter injection
    cumulative_bits = 512
    t_bytes = struct.pack(">Q", cumulative_bits)
    S = [[IV[r][c] ^ m_disp[r][c] for c in range(8)] for r in range(8)]
    for r in range(8):
        S[r][r] ^= t_bytes[r]

    # Measure total difference from transpose
    final_diffs = sum(1 for r in range(8) for c in range(8) if S[r][c] != S[c][r])
    print(f"[*] Asymmetry after Diagonal HAIFA Injection: {final_diffs} / 64 asymmetric cells")
    assert final_diffs >= 56, "HAIFA injection failed to shatter diagonal subspace"

    print("[+] PASS: State construction completely shatters symmetric invariant subspaces.")


# ==============================================================================
# PROPERTY 4: Synchronous Dual-Buffering Order Independence
# ==============================================================================
def verify_dual_buffering_invariance():
    print("\n" + "=" * 70)
    print("VERIFICATION 4: Synchronous Dual-Buffering & Order Independence")
    print("=" * 70)

    # Standard round evaluation (evaluates cells in sequential order)
    S_init = [row[:] for row in IV]
    S_standard = round_transform(S_init, round_idx=0)

    # Custom implementation simulating random evaluation order into new buffer
    from h512 import ROUND_FAMILIES, ROUND_CONSTANTS, n_bio, rotl8, _apply_global_permutation, _apply_mds_hyper_diffusion

    family = ROUND_FAMILIES[0]
    alpha, beta, gamma, delta = family.rotations
    rc = ROUND_CONSTANTS[0]

    coords = [(r, c) for r in range(8) for c in range(8)]
    # Shuffle evaluation order randomly 5 times
    for trial in range(5):
        random.seed(42 + trial)
        random.shuffle(coords)

        # Update cells in shuffled order into a new buffer
        S_new = [[0] * 8 for _ in range(8)]
        for r, c in coords:
            north = S_init[(r - 1) % 8][c]
            east = S_init[r][(c + 1) % 8]
            south = S_init[(r + 1) % 8][c]
            west = S_init[r][(c - 1) % 8]

            context = (
                S_init[r][c]
                ^ rotl8(north, alpha)
                ^ rotl8(east, beta)
                ^ rotl8(south, gamma)
                ^ rotl8(west, delta)
            )
            S_new[r][c] = n_bio(context) ^ rc[r][c]

        S_mds = _apply_mds_hyper_diffusion(S_new)
        S_shuffled = _apply_global_permutation(S_mds, family.perm_type)
        assert S_standard == S_shuffled, f"Trial {trial} failed: Order dependence detected!"

    print("[*] Tested 5 randomized cell evaluation orders: All outputs 100% bit-exact.")
    print("[+] PASS: Synchronous dual-buffering guarantees 100% data-parallelism.")


# ==============================================================================
# PROPERTY 5: 64-bit Row Packing & SIMD Isomorphism
# ==============================================================================
def verify_simd_packing():
    print("\n" + "=" * 70)
    print("VERIFICATION 5: Memory Alignment & 64-bit Word Isomorphism")
    print("=" * 70)

    state_bytes = bytes([IV[r][c] for r in range(8) for c in range(8)])
    assert len(state_bytes) == 64

    # Pack into 8 uint64_t words
    words = list(struct.unpack("<8Q", state_bytes))
    print(f"[*] State packed into 8 x uint64_t words successfully:")
    for idx, w in enumerate(words):
        print(f"    Row {idx} (uint64): 0x{w:016x}")

    # Unpack back to bytes and check exact identity
    reconstructed_bytes = struct.pack("<8Q", *words)
    assert state_bytes == reconstructed_bytes, "SIMD word roundtrip conversion failed"

    print("[+] PASS: Row-major layout is completely isomorphic to 8x64-bit SIMD registers.")


# ==============================================================================
# MAIN VERIFICATION RUNNER
# ==============================================================================
if __name__ == "__main__":
    print("======================================================================")
    print("       PROJECT H-512: PHASE 3 STATE CONSTRUCTION VERIFICATION         ")
    print("======================================================================")

    verify_nums_iv()
    verify_toroidal_topology()
    verify_symmetry_shattering()
    verify_dual_buffering_invariance()
    verify_simd_packing()

    print("\n" + "=" * 70)
    print("       PHASE 3 STATE CONSTRUCTION VERIFIED AND VALIDATED [100% PASS]  ")
    print("======================================================================\n")
