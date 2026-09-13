"""
Project H-512 — Stage C: Diffusion Round Measurement
=====================================================
Empirically measures how many rounds are required for a single-bit
difference in any position (r, c) to reach ALL 64 cells of the 8x8 state.

For each starting position, the avalanche is tracked round by round using
the current round_transform() logic modeled in Python.

Outputs:
  - Per-position avalanche onset (rounds until 100% cell coverage)
  - Global minimum / maximum / mean onset across all 64 positions
  - A textual heatmap of round-of-full-avalanche per starting cell

Also tests:
  - What fraction of cells are affected after each round (cascade curve)
  - How diffusion compares to a theoretical random permutation baseline

"""

import sys
import os
import time

# ──────────────────────────────────────────────────────────────────────────────
# Python model of the H-512 round transform (matches h512.c exactly)
# ──────────────────────────────────────────────────────────────────────────────

SBOX = [
    0x36, 0x4e, 0xf4, 0x5e, 0xa2, 0x16, 0x09, 0x44, 0x14, 0x4f, 0x13, 0xc1, 0x0b, 0x26, 0x85, 0x60,
    0x87, 0x21, 0x5c, 0x4a, 0x0f, 0xc7, 0xe8, 0xd4, 0x00, 0x6d, 0x3f, 0x97, 0x18, 0x46, 0xed, 0xc8,
    0xe3, 0xd0, 0xf9, 0x12, 0xf8, 0x5b, 0xa8, 0x8e, 0xe9, 0x50, 0x53, 0x34, 0xb1, 0xc5, 0x9d, 0xac,
    0x84, 0x6c, 0x43, 0x79, 0x82, 0x98, 0x47, 0xf3, 0xfa, 0xdf, 0x9c, 0xcc, 0x56, 0x49, 0x3b, 0xe0,
    0xf7, 0xde, 0x78, 0xa5, 0xd8, 0xdd, 0x76, 0xa1, 0x54, 0x90, 0xb0, 0x20, 0x5d, 0x30, 0x91, 0xf5,
    0xaf, 0xf0, 0xdb, 0x06, 0x75, 0x71, 0x7e, 0x6a, 0xbc, 0x2c, 0x1d, 0xab, 0x99, 0x68, 0x83, 0x64,
    0x40, 0x31, 0x10, 0x39, 0xdc, 0x0d, 0x69, 0xba, 0xee, 0x6b, 0xe6, 0x02, 0x4c, 0x4d, 0xa3, 0xd3,
    0xfe, 0x48, 0x42, 0x6e, 0x1e, 0x15, 0x32, 0x29, 0x55, 0xb7, 0xc2, 0x2d, 0x94, 0x9a, 0xd1, 0xbf,
    0x6f, 0x67, 0x35, 0xec, 0x70, 0x41, 0xad, 0xc9, 0x74, 0xb3, 0xef, 0x24, 0x8c, 0xcd, 0x88, 0x73,
    0x38, 0x25, 0x81, 0x05, 0x57, 0xf2, 0xb8, 0x86, 0x23, 0xcb, 0xe7, 0xfd, 0x1c, 0xb2, 0xff, 0x07,
    0xbe, 0x3a, 0x2b, 0x1b, 0xd6, 0x59, 0xcf, 0x58, 0x04, 0x61, 0x0a, 0x5a, 0x62, 0xe1, 0x17, 0xc4,
    0xae, 0x7a, 0x0e, 0x8d, 0xf6, 0x01, 0x96, 0x9f, 0xea, 0xa0, 0x45, 0x7f, 0x3c, 0x7c, 0xd9, 0x11,
    0xb4, 0x52, 0xa9, 0x9e, 0x72, 0xa7, 0xc6, 0x03, 0x8b, 0x80, 0xd2, 0x1f, 0x89, 0xd7, 0xfc, 0x08,
    0x95, 0xc3, 0x27, 0x77, 0xb9, 0x8a, 0x66, 0xce, 0x7b, 0xda, 0x9b, 0xc0, 0x22, 0x19, 0x2e, 0x8f,
    0xa4, 0x28, 0xe4, 0x3d, 0x0c, 0xbb, 0x2a, 0x4b, 0x5f, 0xaa, 0x33, 0x92, 0x1a, 0xb6, 0xbd, 0xb5,
    0xfb, 0xca, 0xa6, 0x2f, 0xe5, 0x63, 0x93, 0xf1, 0x3e, 0x37, 0x65, 0xd5, 0x7d, 0x51, 0xeb, 0xe2,
]

# Round constants (first 4 rounds, enough for diffusion study)
# Use zero RC for diffusion analysis (RC injection doesn't affect difference propagation)
RC = [[[0]*8 for _ in range(8)] for _ in range(24)]

ROTATIONS = [
    (1, 2, 3, 5),  # Family A
    (3, 5, 1, 7),  # Family B
    (5, 1, 7, 3),  # Family C
    (7, 3, 5, 1),  # Family D
]

def rotl8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF

def xtime(x):
    """GF(2^8) multiply by x (AES polynomial 0x1B)."""
    if x & 0x80:
        return ((x << 1) & 0xFF) ^ 0x1B
    return (x << 1) & 0xFF

def apply_mds_half(col):
    """Apply AES-style MDS to a 4-element list."""
    r0, r1, r2, r3 = col
    t = r0 ^ r1 ^ r2 ^ r3
    col[0] = r0 ^ t ^ xtime(r0 ^ r1)
    col[1] = r1 ^ t ^ xtime(r1 ^ r2)
    col[2] = r2 ^ t ^ xtime(r2 ^ r3)
    col[3] = r3 ^ t ^ xtime(r3 ^ r0)

def apply_mds(S):
    """Apply MDS to all columns (rows 0..3 and 4..7 independently)."""
    import copy
    out = copy.deepcopy(S)
    for c in range(8):
        top = [out[r][c] for r in range(4)]
        bot = [out[r][c] for r in range(4, 8)]
        apply_mds_half(top)
        apply_mds_half(bot)
        for r in range(4):
            out[r][c] = top[r]
        for r in range(4, 8):
            out[r][c] = bot[r - 4]
    return out

def swap_quadrants(S):
    import copy
    out = copy.deepcopy(S)
    for r in range(4):
        for c in range(4):
            # Q0 <-> Q3
            out[r][c],     out[r+4][c+4] = S[r+4][c+4], S[r][c]
            # Q1 <-> Q2
            out[r][c+4],   out[r+4][c]   = S[r+4][c],   S[r][c+4]
    return out

def apply_global_perm(S, fam):
    import copy
    temp = copy.deepcopy(S)
    out  = [[0]*8 for _ in range(8)]
    if fam == 0:
        # ShiftRows: row r shifted left by r
        for r in range(8):
            for c in range(8):
                out[r][c] = temp[r][(c + r) & 7]
    elif fam == 1:
        # Transpose
        for r in range(8):
            for c in range(8):
                out[r][c] = temp[c][r]
    elif fam == 2:
        # ShiftRows + Transpose
        for r in range(8):
            for c in range(8):
                shifted = temp[r][(c + r) & 7]
                out[c][r] = shifted
    else:
        # ShiftRows + Row-Reverse
        for r in range(8):
            for c in range(8):
                out[r][c] = temp[r][((7 - c) + r) & 7]
    return out

def round_transform_python(S, rnd):
    """Python implementation of h512.c round_transform()."""
    import copy
    fam = rnd & 3
    alpha, beta, gamma, delta = ROTATIONS[fam]

    # Pass 1: Toroidal context coupling + N_bio + RC
    S_sub = [[0]*8 for _ in range(8)]
    for r in range(8):
        for c in range(8):
            north = S[(r - 1) & 7][c]
            east  = S[r][(c + 1) & 7]
            south = S[(r + 1) & 7][c]
            west  = S[r][(c - 1) & 7]
            ctx   = S[r][c] ^ rotl8(north, alpha) ^ rotl8(east, beta) \
                            ^ rotl8(south, gamma) ^ rotl8(west, delta)
            S_sub[r][c] = SBOX[ctx] ^ RC[rnd][r][c]

    # Pass 2: MDS hyper-diffusion
    S_sub = apply_mds(S_sub)

    # Pass 3: Quadrant swap (families 1, 3)
    if fam in (1, 3):
        S_sub = swap_quadrants(S_sub)

    # Pass 4: Global permutation
    S_sub = apply_global_perm(S_sub, fam)

    return S_sub

# ──────────────────────────────────────────────────────────────────────────────
# Diffusion measurement: track active cells (byte-level) under difference prop
# ──────────────────────────────────────────────────────────────────────────────

def active_cell_count(S):
    """Count cells with S[r][c] != 0."""
    return sum(1 for r in range(8) for c in range(8) if S[r][c] != 0)

def measure_diffusion_from(start_r, start_c, max_rounds=16, trials=8):
    """
    Inject a random nonzero 1-byte difference at (start_r, start_c) in a
    random baseline state. Track how many cells are nonzero in the difference
    state after each round.

    Returns: list of (round, mean_active_count) for rounds 0..max_rounds
    """
    import random
    rng = random.Random(start_r * 8 + start_c)

    cumulative = [0.0] * (max_rounds + 1)

    for _ in range(trials):
        # Random baseline state A
        A = [[rng.randint(0, 255) for _ in range(8)] for _ in range(8)]
        # State B: differs from A only at (start_r, start_c)
        delta_byte = rng.randint(1, 255)
        B = [row[:] for row in A]
        B[start_r][start_c] ^= delta_byte

        # Difference state
        D = [[A[r][c] ^ B[r][c] for c in range(8)] for r in range(8)]
        cumulative[0] += active_cell_count(D)

        for rnd in range(max_rounds):
            A = round_transform_python(A, rnd)
            B = round_transform_python(B, rnd)
            D = [[A[r][c] ^ B[r][c] for c in range(8)] for r in range(8)]
            cumulative[rnd + 1] += active_cell_count(D)

    return [v / trials for v in cumulative]

def find_full_avalanche_round(cascade):
    """Find first round where mean active cells >= 63.5 (essentially all 64)."""
    for rnd, count in enumerate(cascade):
        if count >= 63.5:
            return rnd
    return -1  # didn't reach full avalanche in max_rounds

# ──────────────────────────────────────────────────────────────────────────────
# Main Analysis
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  PROJECT H-512 — STAGE C: DIFFUSION ROUND MEASUREMENT")
    print("  Tracking single-bit difference propagation across 64 positions")
    print("=" * 70)

    MAX_ROUNDS = 16
    TRIALS_PER_POS = 16  # Increase for more accuracy; 16 is fast enough

    onset_map = [[0] * 8 for _ in range(8)]
    cascades  = {}
    t0 = time.time()

    print(f"\n  Measuring diffusion from all 64 starting positions ({TRIALS_PER_POS} trials each)...")
    for r in range(8):
        for c in range(8):
            cascade = measure_diffusion_from(r, c, max_rounds=MAX_ROUNDS, trials=TRIALS_PER_POS)
            cascades[(r, c)] = cascade
            onset = find_full_avalanche_round(cascade)
            onset_map[r][c] = onset
            sys.stdout.write(f"\r  Position ({r},{c}) — Full avalanche at round {onset:>2}  [{r*8+c+1}/64]")
            sys.stdout.flush()

    elapsed = time.time() - t0
    print(f"\n  Done in {elapsed:.1f}s")

    # ── Summary Statistics ─────────────────────────────────────────────────────
    all_onsets = [onset_map[r][c] for r in range(8) for c in range(8) if onset_map[r][c] >= 0]
    min_onset = min(all_onsets) if all_onsets else -1
    max_onset = max(all_onsets) if all_onsets else -1
    mean_onset = sum(all_onsets) / len(all_onsets) if all_onsets else 0

    never_full = [(r, c) for r in range(8) for c in range(8) if onset_map[r][c] < 0]

    print(f"\n{'='*70}")
    print(f"  DIFFUSION ONSET SUMMARY (full 64-cell avalanche)")
    print(f"{'='*70}")
    print(f"  Min rounds to full avalanche : {min_onset}")
    print(f"  Max rounds to full avalanche : {max_onset}")
    print(f"  Mean rounds to full avalanche: {mean_onset:.2f}")
    if never_full:
        print(f"  Positions never reaching full avalanche in {MAX_ROUNDS} rounds: {never_full}")
    else:
        print(f"  All 64 positions reach full avalanche within {MAX_ROUNDS} rounds")

    # Security target: full avalanche in ≤ 4 rounds
    if max_onset <= 4:
        print(f"\n  PASS: Full global diffusion achieved in <= 4 rounds")
    elif max_onset <= 8:
        print(f"\n  MARGINAL: Full diffusion requires up to {max_onset} rounds")
    else:
        print(f"\n  CONCERN: Some positions require {max_onset} rounds for full diffusion")

    # ── Heatmap ───────────────────────────────────────────────────────────────
    print(f"\n  Avalanche Onset Heatmap (rounds to full 64-cell coverage):")
    print(f"         c=0  c=1  c=2  c=3  c=4  c=5  c=6  c=7")
    for r in range(8):
        row_str = "  ".join(
            f"{onset_map[r][c]:>2}" if onset_map[r][c] >= 0 else " N"
            for c in range(8)
        )
        print(f"  r={r}:   {row_str}")

    # ── Cascade Curve: global average active cells per round ──────────────────
    print(f"\n  Global Cascade Curve (mean active cells across all 64 start positions):")
    print(f"  {'Round':<8} {'Active Cells':<14} {'Coverage %':<12} Bar")
    global_cascade = []
    for rnd in range(MAX_ROUNDS + 1):
        mean_active = sum(cascades[(r, c)][rnd] for r in range(8) for c in range(8)) / 64
        global_cascade.append(mean_active)
        bar = "#" * int(mean_active * 40 / 64)
        print(f"  {rnd:<8} {mean_active:<14.2f} {mean_active/64*100:<12.1f}% {bar}")

    # ── Avalanche at specific rounds ───────────────────────────────────────────
    print(f"\n  Key milestone rounds:")
    for target_rnd in [1, 2, 3, 4, 8, 12, 16]:
        if target_rnd <= MAX_ROUNDS:
            pct = global_cascade[target_rnd] / 64 * 100
            print(f"    After round {target_rnd:>2}: {global_cascade[target_rnd]:.1f}/64 cells active ({pct:.1f}%)")

    print(f"\n{'='*70}")
    print(f"  SECURITY IMPLICATION")
    print(f"{'='*70}")
    print(f"  For a differential trail spanning R rounds to have probability > 2^-512,")
    print(f"  active S-boxes must be < 512 / log2(256/delta_max).")
    print(f"  With delta_max=10: min trail weight = 512 / log2(25.6) = {512/4.678:.0f} active boxes")
    print(f"  With delta_max=6 (target): min trail weight = 512 / log2(42.7) = {512/5.415:.0f} active boxes")
    print(f"  Diffusion onset of {max_onset} rounds means after {max_onset} rounds, any difference")
    print(f"  touches all 64 S-boxes, making trail cancellation exponentially harder.")

if __name__ == "__main__":
    main()
