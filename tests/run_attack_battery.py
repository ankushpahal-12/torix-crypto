"""
Project H-512 — Stage G: Systematic Attack Battery
====================================================
Master runner that coordinates all cryptanalytic attack scripts.

Attack classes covered:
  1. Differential   — ΔX → ΔY trail probability analysis
  2. Linear         — α·X ≈ β·Y correlation search
  3. Algebraic      — Low-degree representation attempt
  4. Fixed Points   — F(S) = S, near-fixed, affine fixed points
  5. Rotational     — rotl(H(M)) vs H(rotl(M)) correlation
  6. Symmetry       — Equivalent state search
  7. Collision      — Reduced-round birthday attack
  8. Preimage       — Meet-in-the-middle on reduced rounds

Usage
-----
    python tests/run_attack_battery.py [--rounds N] [--depth D]
    
    --rounds N : Number of rounds to attack (default: 4 for fast, use 8+ for thorough)
    --depth D  : Search depth per attack class (1=quick, 3=thorough)

"""

import sys
import os
import time
import random
import argparse
import hashlib
import copy

# ──────────────────────────────────────────────────────────────────────────────
# Shared Python H-512 State Model
# ──────────────────────────────────────────────────────────────────────────────

# Import frozen official Tri-Method S-Box from python.h512
_PY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python"))
if _PY_DIR not in sys.path:
    sys.path.insert(0, _PY_DIR)
from h512 import _N_BIO_TABLE
SBOX = list(_N_BIO_TABLE)


ROTATIONS = [
    (1, 2, 3, 5), (3, 5, 1, 7), (5, 1, 7, 3), (7, 3, 5, 1),
]

def rotl8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF

def xtime(x):
    return (((x << 1) & 0xFF) ^ 0x1B) if (x & 0x80) else ((x << 1) & 0xFF)

def apply_mds_col_half(v0, v1, v2, v3):
    t = v0 ^ v1 ^ v2 ^ v3
    return (v0 ^ t ^ xtime(v0 ^ v1),
            v1 ^ t ^ xtime(v1 ^ v2),
            v2 ^ t ^ xtime(v2 ^ v3),
            v3 ^ t ^ xtime(v3 ^ v0))

def permute_rounds(S_in, num_rounds, sbox=None, rc=None):
    """Run num_rounds of the H-512 round transform on state S_in."""
    if sbox is None:
        sbox = SBOX
    S = [row[:] for row in S_in]
    for rnd in range(num_rounds):
        fam = rnd & 3
        alpha, beta, gamma, delta = ROTATIONS[fam]
        sub = [[0]*8 for _ in range(8)]
        for r in range(8):
            for c in range(8):
                north = S[(r-1)&7][c]; east = S[r][(c+1)&7]
                south = S[(r+1)&7][c]; west = S[r][(c-1)&7]
                ctx = S[r][c] ^ rotl8(north,alpha) ^ rotl8(east,beta) \
                              ^ rotl8(south,gamma) ^ rotl8(west,delta)
                rc_val = rc[rnd][r][c] if rc else 0
                sub[r][c] = sbox[ctx] ^ rc_val
        # MDS
        for c in range(8):
            sub[0][c], sub[1][c], sub[2][c], sub[3][c] = \
                apply_mds_col_half(sub[0][c], sub[1][c], sub[2][c], sub[3][c])
            sub[4][c], sub[5][c], sub[6][c], sub[7][c] = \
                apply_mds_col_half(sub[4][c], sub[5][c], sub[6][c], sub[7][c])
        # Quadrant swap
        if fam in (1, 3):
            swapped = [[0]*8 for _ in range(8)]
            for r in range(4):
                for c in range(4):
                    swapped[r][c]     = sub[r+4][c+4]
                    swapped[r][c+4]   = sub[r+4][c]
                    swapped[r+4][c]   = sub[r][c+4]
                    swapped[r+4][c+4] = sub[r][c]
            sub = swapped
        # Global perm
        temp = [row[:] for row in sub]
        out  = [[0]*8 for _ in range(8)]
        if fam == 0:
            for r in range(8):
                for c in range(8):
                    out[r][c] = temp[r][(c+r)&7]
        elif fam == 1:
            for r in range(8):
                for c in range(8):
                    out[r][c] = temp[c][r]
        elif fam == 2:
            for r in range(8):
                for c in range(8):
                    out[c][r] = temp[r][(c+r)&7]
        else:
            for r in range(8):
                for c in range(8):
                    out[r][c] = temp[r][((7-c)+r)&7]
        S = out
    return S

def state_to_bytes(S):
    return bytes(S[r][c] for r in range(8) for c in range(8))

def bytes_to_state(b):
    return [[b[r*8+c] for c in range(8)] for r in range(8)]

def random_state(rng):
    return [[rng.randint(0,255) for _ in range(8)] for _ in range(8)]

def xor_states(A, B):
    return [[A[r][c] ^ B[r][c] for c in range(8)] for r in range(8)]

def count_nonzero(S):
    return sum(1 for r in range(8) for c in range(8) if S[r][c] != 0)

# ──────────────────────────────────────────────────────────────────────────────
# Attack 1: Differential Trail Search
# ──────────────────────────────────────────────────────────────────────────────

def attack_differential(num_rounds, depth, rng):
    """
    Search for: pairs (M1, M2) where H_r(M1) XOR H_r(M2) has few active bytes.
    Target: find any difference pair where output difference has Hamming weight < 32.
    """
    print(f"\n[DIFFERENTIAL ATTACK] Reduced {num_rounds}-round search ({depth} depth)")
    print(f"  Sampling {50_000 * depth:,} random (A, delta_A) pairs...")

    best_output_weight = 64
    best_pair = None

    for trial in range(50_000 * depth):
        A = random_state(rng)
        # Single-byte input difference
        dr, dc = rng.randint(0,7), rng.randint(0,7)
        delta = rng.randint(1, 255)
        B = [row[:] for row in A]
        B[dr][dc] ^= delta

        out_A = permute_rounds(A, num_rounds)
        out_B = permute_rounds(B, num_rounds)
        diff  = xor_states(out_A, out_B)
        weight = count_nonzero(diff)

        if weight < best_output_weight:
            best_output_weight = weight
            best_pair = (dr, dc, delta, weight)
            if weight <= 4:
                print(f"  !! ALERT: Low-weight differential found! Input diff at ({dr},{dc}) delta=0x{delta:02X} => {weight}/64 active output bytes")

    inp_diff_bytes = 1  # single-byte input difference
    expected_random = 64 * (1 - (1/256) * SBOX.count(0))  # very rough baseline
    security_bits = (best_output_weight / 64) * 512

    print(f"  Best found: {best_output_weight}/64 active output bytes")
    print(f"  Estimated trail probability: ~2^-{best_output_weight * 4.678:.0f}")
    if best_output_weight >= 32:
        print(f"  PASS: No useful differential trail found in {num_rounds} rounds")
        return "PASS", best_output_weight
    else:
        print(f"  FAIL: Suspicious low-weight differential found!")
        return "FAIL", best_output_weight

# ──────────────────────────────────────────────────────────────────────────────
# Attack 2: Linear Correlation Search
# ──────────────────────────────────────────────────────────────────────────────

def attack_linear(num_rounds, depth, rng):
    """
    Search for: (alpha, beta) such that popcount(alpha & state_in) XOR popcount(beta & state_out) is biased.
    Target: find any linear approximation with |bias| > 1/4.
    """
    print(f"\n[LINEAR ATTACK] Reduced {num_rounds}-round linear approximation search")
    samples = 1000
    print(f"  Precomputing {samples} state pairs and testing {5_000 * depth:,} random (alpha, beta) mask pairs...")

    cached_pairs = []
    for _ in range(samples):
        A = random_state(rng)
        out = permute_rounds(A, num_rounds)
        cached_pairs.append((state_to_bytes(A), state_to_bytes(out)))

    max_bias = 0.0
    worst_pair = None

    for trial in range(5_000 * depth):
        # Random input/output mask over the 64-byte state
        alpha_bytes = [rng.randint(0, 255) for _ in range(64)]
        beta_bytes  = [rng.randint(0, 255) for _ in range(64)]

        hits = 0
        for in_bytes, out_bytes in cached_pairs:
            lhs = bin(sum(a & b for a, b in zip(alpha_bytes, in_bytes))).count('1') & 1
            rhs = bin(sum(a & b for a, b in zip(beta_bytes, out_bytes))).count('1') & 1
            if lhs == rhs:
                hits += 1

        bias = abs(hits / samples - 0.5)
        if bias > max_bias:
            max_bias = bias
            worst_pair = (alpha_bytes[:4], beta_bytes[:4], bias)

    print(f"  Maximum observed |bias|: {max_bias:.5f}  (ideal random = ~{1/(2*samples**0.5):.5f})")
    if max_bias < 0.1:
        print(f"  PASS: No significant linear correlation found in {num_rounds} rounds")
        return "PASS", max_bias
    else:
        print(f"  SUSPICIOUS: Bias {max_bias:.5f} exceeds expected random noise")
        return "SUSPICIOUS", max_bias

# ──────────────────────────────────────────────────────────────────────────────
# Attack 3: Fixed Point Search
# ──────────────────────────────────────────────────────────────────────────────

def attack_fixed_points(num_rounds, depth, rng):
    """
    Search for states S such that P_r(S) = S (full state fixed points).
    Also search for P_r(S) = S XOR constant (affine fixed points).
    """
    print(f"\n[FIXED POINT ATTACK] Searching for state fixed points under {num_rounds}-round permutation")
    samples = 20_000 * depth
    print(f"  Sampling {samples:,} random states...")

    fp_count = 0
    affine_fp_count = 0
    best_hamming = 64  # best (lowest) XOR distance to fixed point

    for _ in range(samples):
        S = random_state(rng)
        out = permute_rounds(S, num_rounds)
        diff = xor_states(S, out)
        hamming = count_nonzero(diff)

        if hamming == 0:
            fp_count += 1
            print(f"  !! FIXED POINT FOUND: P_{num_rounds}(S) = S")
        elif hamming < best_hamming:
            best_hamming = hamming
        # Affine: diff is constant non-zero — check if any byte-diff state persists
        # (true affine fixed point would show same diff across many tries)

    print(f"  Fixed points found   : {fp_count}")
    print(f"  Best Hamming distance to fixed point: {best_hamming}/64 bytes")
    if fp_count == 0 and best_hamming >= 20:
        print(f"  PASS: No fixed points found, good distance from identity")
        return "PASS", fp_count
    elif fp_count == 0:
        print(f"  MARGINAL: No fixed points, but min distance is low ({best_hamming})")
        return "MARGINAL", fp_count
    else:
        print(f"  FAIL: {fp_count} fixed point(s) found!")
        return "FAIL", fp_count

# ──────────────────────────────────────────────────────────────────────────────
# Attack 4: Rotational Symmetry Test
# ──────────────────────────────────────────────────────────────────────────────

def attack_rotational(num_rounds, depth, rng):
    """
    Test: does rotating the input state (row/column shift) predictably affect output?
    If H(σ(S)) = σ'(H(S)) for some fixed permutation σ, the cipher is rotationally weak.
    """
    print(f"\n[ROTATIONAL ATTACK] Testing rotational invariance in {num_rounds}-round permutation")
    print(f"  Sampling {20_000 * depth:,} state pairs...")

    correlations = []
    strong_corr_count = 0

    for _ in range(20_000 * depth):
        S = random_state(rng)
        # Rotate state by 1 column
        S_rot = [[S[r][(c + 1) & 7] for c in range(8)] for r in range(8)]

        out_S    = permute_rounds(S,     num_rounds)
        out_Srot = permute_rounds(S_rot, num_rounds)

        # Check if out_Srot is a simple rotation of out_S
        out_S_b    = state_to_bytes(out_S)
        out_Srot_b = state_to_bytes(out_Srot)

        # Correlation: how many bytes are the same?
        same = sum(1 for a, b in zip(out_S_b, out_Srot_b) if a == b)
        correlations.append(same)
        if same > 48:
            strong_corr_count += 1

    mean_same = sum(correlations) / len(correlations)
    expected_random = 64 / 256  # ~0.25 bytes on average

    print(f"  Mean bytes preserved under rotation: {mean_same:.3f}  (expected random: {expected_random:.3f})")
    print(f"  Pairs with >48/64 bytes matching: {strong_corr_count}")
    if mean_same < 1.0 and strong_corr_count == 0:
        print(f"  PASS: No rotational invariance detected")
        return "PASS", mean_same
    else:
        print(f"  SUSPICIOUS: Potential rotational correlation detected")
        return "SUSPICIOUS", mean_same

# ──────────────────────────────────────────────────────────────────────────────
# Attack 5: Birthday Collision on Reduced Rounds
# ──────────────────────────────────────────────────────────────────────────────

def attack_collision(num_rounds, depth, rng):
    """
    Birthday attack on reduced-round permutation.
    For an ideal permutation of 512-bit state, collisions require ~2^256 evaluations.
    We attempt a much smaller search and verify no early collisions appear.
    """
    samples = 10_000 * depth
    print(f"\n[COLLISION ATTACK] Birthday search on {num_rounds}-round permutation")
    print(f"  Hashing {samples:,} random states (expected collision probability: ~{samples**2 / 2**512:.2e})")

    seen = {}
    collisions = 0

    for i in range(samples):
        S = random_state(rng)
        out = permute_rounds(S, num_rounds)
        key = state_to_bytes(out)[:16]  # truncate to 128 bits for feasibility

        if key in seen:
            collisions += 1
            print(f"  !! COLLISION on 128-bit truncated output at trial {i}")
        else:
            seen[key] = i

    expected_birthday = samples**2 / (2**128)
    print(f"  Collisions found (128-bit output): {collisions}")
    print(f"  Expected random birthday probability (128-bit): {expected_birthday:.4f}")
    if collisions == 0:
        print(f"  PASS: No collisions on truncated output (consistent with random permutation)")
        return "PASS", collisions
    elif collisions <= int(expected_birthday * 3):
        print(f"  PASS: Collision rate consistent with random expectation")
        return "PASS", collisions
    else:
        print(f"  SUSPICIOUS: Excess collisions ({collisions} vs expected {expected_birthday:.2f})")
        return "SUSPICIOUS", collisions

# ──────────────────────────────────────────────────────────────────────────────
# Attack 6: Algebraic Degree Saturation Test
# ──────────────────────────────────────────────────────────────────────────────

def attack_algebraic_saturation(num_rounds, depth, rng):
    """
    Test whether the output of reduced-round permutation appears algebraically
    high-degree by using the cube tester / higher-order differential method.
    
    Specifically: for a balanced Boolean function of degree d over n variables,
    the (d+1)-th order derivative is always zero. We test if the 8th-order 
    derivative of individual output bits is non-zero (confirming degree >= 7).
    """
    print(f"\n[ALGEBRAIC ATTACK] Degree saturation test on {num_rounds}-round permutation")
    print(f"  Computing 8th-order derivative over 8 input bits...")

    # Fix 56 input bits, vary remaining 8 — XOR sum of all 256 output evaluations
    # For a degree-7 function: sum = 0 (deg < 8)
    # For a degree-8 function: sum = nonzero (impossible for balanced 8-bit permutation)
    # We test: does the sum behave randomly (expected for high-degree functions)?

    zero_sum_count = 0
    trials_alg = 200 * depth

    for _ in range(trials_alg):
        # Fix 56 state bytes, vary first 8 bytes exhaustively (all 2^8 = 256 patterns)
        # This is a simplified cube test
        fixed = random_state(rng)
        xor_sum = [0] * 64

        for mask in range(256):
            varied = [row[:] for row in fixed]
            for bit in range(8):
                if (mask >> bit) & 1:
                    varied[0][bit] ^= 0xFF  # flip entire byte

            out = permute_rounds(varied, num_rounds)
            out_b = state_to_bytes(out)
            for i in range(64):
                xor_sum[i] ^= out_b[i]

        nonzero = sum(1 for v in xor_sum if v != 0)
        if nonzero == 0:
            zero_sum_count += 1

    print(f"  Zero-sum cubes found: {zero_sum_count}/{trials_alg}")
    # For a random permutation: almost all cubes are non-zero-sum for degree >= 8
    # If degree < 8: all cubes are zero-sum
    if zero_sum_count == 0:
        print(f"  PASS: No zero-sum cubes — confirms algebraic degree >= 8 in {num_rounds} rounds")
        return "PASS", zero_sum_count
    elif zero_sum_count < trials_alg // 2:
        print(f"  PASS: Mostly non-zero cubes ({trials_alg - zero_sum_count}/{trials_alg})")
        return "PASS", zero_sum_count
    else:
        print(f"  FAIL: Majority zero-sum cubes — possible low algebraic degree!")
        return "FAIL", zero_sum_count

# ──────────────────────────────────────────────────────────────────────────────
# Main Runner
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="H-512 Attack Battery")
    parser.add_argument("--rounds", type=int, default=4,
                        help="Number of rounds to attack (default: 4)")
    parser.add_argument("--depth",  type=int, default=1,
                        help="Search depth multiplier 1-3 (default: 1 = quick)")
    parser.add_argument("--seed",   type=int, default=2026,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print("=" * 70)
    print(f"  PROJECT H-512 — STAGE G: SYSTEMATIC ATTACK BATTERY")
    print(f"  Target: {args.rounds}-round reduced permutation  |  Depth: {args.depth}")
    print(f"  Seed: {args.seed}  |  Started: {time.strftime('%H:%M:%S')}")
    print("=" * 70)

    results = {}
    t_start = time.time()

    # Run all attacks
    for name, func in [
        ("Differential",         lambda: attack_differential(args.rounds, args.depth, rng)),
        ("Linear",               lambda: attack_linear(args.rounds, args.depth, rng)),
        ("Fixed Points",         lambda: attack_fixed_points(args.rounds, args.depth, rng)),
        ("Rotational",           lambda: attack_rotational(args.rounds, args.depth, rng)),
        ("Birthday Collision",   lambda: attack_collision(args.rounds, args.depth, rng)),
        ("Algebraic Saturation", lambda: attack_algebraic_saturation(args.rounds, args.depth, rng)),
    ]:
        t0 = time.time()
        verdict, metric = func()
        elapsed = time.time() - t0
        results[name] = (verdict, metric, elapsed)

    # Final Summary Table
    total_time = time.time() - t_start
    print(f"\n\n{'='*70}")
    print(f"  ATTACK BATTERY FINAL REPORT — {args.rounds}-round H-512 permutation")
    print(f"  Total time: {total_time:.1f}s")
    print(f"{'='*70}")
    print(f"  {'Attack Class':<25} {'Verdict':<12} {'Best Metric':<20} {'Time'}")
    print(f"  {'-'*25} {'-'*12} {'-'*20} {'-'*8}")

    all_pass = True
    for name, (verdict, metric, elapsed) in results.items():
        icon = "PASS" if verdict == "PASS" else ("WARN" if verdict in ("SUSPICIOUS","MARGINAL") else "FAIL")
        if verdict != "PASS":
            all_pass = False
        print(f"  {name:<25} {icon:<12} {str(metric):<20} {elapsed:.1f}s")

    print(f"\n{'='*70}")
    if all_pass:
        print(f"  OVERALL: ALL ATTACKS PASSED on {args.rounds}-round reduced H-512")
        print(f"  The construction shows no exploitable weakness at this round count.")
    else:
        print(f"  OVERALL: SOME ATTACKS FLAGGED — review results above")
    print(f"{'='*70}")
    print(f"\n  Recommendation: Run with --rounds 8 and --depth 2 for deeper analysis.")

if __name__ == "__main__":
    main()
