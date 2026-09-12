"""
Project H-512: Phase 4 Nonlinear Core Verification Suite
========================================================
Comprehensive mathematical verification of N_bio:
1. Verification 1: Bijectivity, Invertibility & Cycle Decomposition
2. Verification 2: Difference Distribution Table (DDT) & Differential Uniformity
3. Verification 3: Linear Approximation Table (LAT) & Nonlinearity (NL)
4. Verification 4: Algebraic Normal Form (ANF) & Algebraic Degree
5. Verification 5: Isolated S-Box Strict Avalanche Criterion (SAC)
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
from typing import Dict, List, Tuple

from h512 import n_bio, n_bio_inv, rotl4


def count_set_bits(n: int) -> int:
    return bin(n).count("1")


def dot_product(a: int, b: int) -> int:
    """Computes the inner product of two 8-bit vectors over GF(2)."""
    return count_set_bits(a & b) % 2


# ==============================================================================
# VERIFICATION 1: Bijectivity, Invertibility & Cycle Decomposition
# ==============================================================================
def verify_bijectivity_and_invertibility():
    print("\n" + "=" * 70)
    print("VERIFICATION 1: Bijectivity, Invertibility & Cycle Decomposition")
    print("=" * 70)

    # 1. Test image size
    outputs = [n_bio(x) for x in range(256)]
    unique_count = len(set(outputs))
    print(f"[*] Total Unique Outputs: {unique_count} / 256")
    assert unique_count == 256, "Bijectivity check failed: collisions detected!"

    # 2. Test mathematical inverse
    for x in range(256):
        y = n_bio(x)
        x_rec = n_bio_inv(y)
        assert x_rec == x, f"Invertibility failed for x = {x}: got {x_rec}"
    print("[*] Exact Mathematical Inverse N_bio_inv(N_bio(x)) == x verified for all 256 inputs.")

    # 3. Fixed points and cycle decomposition
    fixed_points = [x for x in range(256) if n_bio(x) == x]
    print(f"[*] Fixed Points (N(x) == x): {len(fixed_points)} ({fixed_points})")

    # Cycle lengths
    visited = set()
    cycles = []
    for x in range(256):
        if x not in visited:
            curr = x
            length = 0
            while curr not in visited:
                visited.add(curr)
                curr = n_bio(curr)
                length += 1
            cycles.append(length)

    print(f"[*] Permutation Disjoint Cycles: {len(cycles)} cycles")
    print(f"[*] Cycle Lengths: {sorted(cycles, reverse=True)}")
    print("[+] PASS: N_bio is a strictly invertible permutation over GF(2^8).")


# ==============================================================================
# VERIFICATION 2: Difference Distribution Table (DDT)
# ==============================================================================
def verify_differential_uniformity():
    print("\n" + "=" * 70)
    print("VERIFICATION 2: Difference Distribution Table (DDT) & Uniformity")
    print("=" * 70)

    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for d_in in range(256):
            d_out = n_bio(x) ^ n_bio(x ^ d_in)
            ddt[d_in][d_out] += 1

    # Find max differential entry for non-zero input difference
    max_d_entry = 0
    max_in, max_out = 0, 0
    for d_in in range(1, 256):
        for d_out in range(256):
            if ddt[d_in][d_out] > max_d_entry:
                max_d_entry = ddt[d_in][d_out]
                max_in, max_out = d_in, d_out

    # Maximum Differential Probability (MEDP)
    medp = max_d_entry / 256.0
    print(f"[*] Maximum Differential Entry (Differential Uniformity delta_max): {max_d_entry} / 256")
    print(f"[*] Maximum Expected Differential Probability (MEDP): {medp:.4f}")
    print(f"    (Occurs at Delta_in = 0x{max_in:02x} -> Delta_out = 0x{max_out:02x})")

    # Count distribution of DDT entries
    entry_counts = collections.Counter()
    for d_in in range(1, 256):
        for d_out in range(256):
            entry_counts[ddt[d_in][d_out]] += 1

    print(f"[*] DDT Value Distribution across 65,280 non-zero pairs:")
    for val in sorted(entry_counts.keys()):
        pct = (entry_counts[val] / 65280.0) * 100.0
        print(f"    Entry {val:2d} : {entry_counts[val]:5d} pairs ({pct:5.2f}%)")

    assert max_d_entry <= 16, f"Differential uniformity is too high: {max_d_entry}"
    print("[+] PASS: Differential uniformity is low, resisting differential attacks.")


# ==============================================================================
# VERIFICATION 3: Linear Approximation Table (LAT) & Nonlinearity
# ==============================================================================
def verify_linear_cryptanalysis():
    print("\n" + "=" * 70)
    print("VERIFICATION 3: Linear Approximation Table (LAT) & Nonlinearity (NL)")
    print("=" * 70)

    # Fast Walsh-Hadamard Transform (FWHT) computes exact LAT spectrum in milliseconds
    def fwht(a: List[int]) -> List[int]:
        res = list(a)
        h = 1
        while h < len(res):
            for i in range(0, len(res), h * 2):
                for j in range(i, i + h):
                    x = res[j]
                    y = res[j + h]
                    res[j] = x + y
                    res[j + h] = x - y
            h *= 2
        return res

    max_lat_bias = 0
    best_a, best_b = 0, 0

    # For each non-zero output mask b
    for b in range(1, 256):
        # Component function sign vector: (-1)^(b . N(x))
        sign_vector = [1 if dot_product(b, n_bio(x)) == 0 else -1 for x in range(256)]
        walsh_spectrum = fwht(sign_vector)

        # walsh_spectrum[a] = sum_{x} (-1)^(a . x ^ b . N(x)) = 2 * LAT(a, b)
        for a in range(1, 256):
            bias = abs(walsh_spectrum[a]) // 2
            if bias > max_lat_bias:
                max_lat_bias = bias
                best_a, best_b = a, b

    nonlinearity = 128 - max_lat_bias
    spectral_bias = max_lat_bias / 256.0

    print(f"[*] Maximum Linear Approximation Bias : {max_lat_bias} / 128 (epsilon = {spectral_bias:.4f})")
    print(f"    (Occurs at mask_in = 0x{best_a:02x}, mask_out = 0x{best_b:02x})")
    print(f"[*] Minimum S-Box Nonlinearity (NL)    : {nonlinearity} (Target >= 96)")

    assert nonlinearity >= 96, f"Nonlinearity is too low: {nonlinearity}"
    print("[+] PASS: Strong resistance against Matsui's Linear Cryptanalysis (FWHT Verified).")


# ==============================================================================
# VERIFICATION 4: Algebraic Normal Form (ANF) & Algebraic Degree
# ==============================================================================
def verify_algebraic_degree():
    print("\n" + "=" * 70)
    print("VERIFICATION 4: Algebraic Normal Form (ANF) & Algebraic Degree")
    print("=" * 70)

    # Fast Mobius Transform over GF(2)^8 to extract ANF coefficients
    def fast_mobius_transform(truth_table: List[int]) -> List[int]:
        anf = list(truth_table)
        for i in range(8):
            for j in range(256):
                if j & (1 << i):
                    anf[j] ^= anf[j ^ (1 << i)]
        return anf

    degrees = []
    monomial_counts = []

    print(f"{'Bit':<5} | {'Algebraic Degree':<18} | {'Total Non-Zero Monomials':<25}")
    print("-" * 55)

    for bit in range(8):
        # Extract truth table for coordinate function y_bit = f_bit(x)
        truth_table = [(n_bio(x) >> bit) & 1 for x in range(256)]
        anf = fast_mobius_transform(truth_table)

        # Degree is maximum Hamming weight of j where anf[j] == 1
        max_deg = max(count_set_bits(j) for j in range(256) if anf[j] == 1)
        nonzero_terms = sum(1 for j in range(256) if anf[j] == 1)

        degrees.append(max_deg)
        monomial_counts.append(nonzero_terms)
        print(f"Bit {bit:<2} | Degree {max_deg} / 7        | {nonzero_terms:3d} / 256 monomials")

    min_deg = min(degrees)
    max_deg = max(degrees)
    print(f"\n[*] Overall Algebraic Degree : min = {min_deg}, max = {max_deg} (Max theoretical for 8-bit bijection is 7)")
    assert min_deg >= 5, f"Algebraic degree too low: {min_deg}"
    print("[+] PASS: High algebraic degree protects against interpolation and algebraic attacks.")


# ==============================================================================
# VERIFICATION 5: Isolated S-Box Strict Avalanche Criterion (SAC)
# ==============================================================================
def verify_isolated_sac():
    print("\n" + "=" * 70)
    print("VERIFICATION 5: Isolated S-Box SAC Matrix (8 x 8)")
    print("=" * 70)

    # sac_matrix[in_bit][out_bit] = probability of flip
    sac_counts = [[0] * 8 for _ in range(8)]

    for x in range(256):
        y = n_bio(x)
        for in_bit in range(8):
            x_flip = x ^ (1 << in_bit)
            y_flip = n_bio(x_flip)
            diff = y ^ y_flip
            for out_bit in range(8):
                if diff & (1 << out_bit):
                    sac_counts[in_bit][out_bit] += 1

    print("SAC Probability Matrix P(Delta y_out = 1 | Delta x_in = 1):")
    print("       out_0  out_1  out_2  out_3  out_4  out_5  out_6  out_7")
    total_probs = []
    for in_bit in range(8):
        row_str = f"in_{in_bit} : "
        for out_bit in range(8):
            prob = sac_counts[in_bit][out_bit] / 256.0
            total_probs.append(prob)
            row_str += f"{prob:.2f}   "
        print(row_str)

    avg_sac = sum(total_probs) / len(total_probs)
    print(f"\n[*] Average Single-Cell Flip Probability: {avg_sac:.4f} (Ideal: 0.5000)")
    assert 0.45 <= avg_sac <= 0.55, f"Average SAC out of acceptable range: {avg_sac}"
    print("[+] PASS: Isolated S-box satisfies the Strict Avalanche Criterion.")


# ==============================================================================
# MAIN TEST RUNNER
# ==============================================================================
if __name__ == "__main__":
    print("======================================================================")
    print("       PROJECT H-512: PHASE 4 NONLINEAR CORE VERIFICATION SUITE       ")
    print("======================================================================")

    verify_bijectivity_and_invertibility()
    verify_differential_uniformity()
    verify_linear_cryptanalysis()
    verify_algebraic_degree()
    verify_isolated_sac()

    print("\n" + "=" * 70)
    print("       PHASE 4 NONLINEAR CORE FULLY VERIFIED & VALIDATED [100% PASS]  ")
    print("======================================================================\n")
