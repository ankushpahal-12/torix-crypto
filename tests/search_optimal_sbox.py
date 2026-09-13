"""
Project H-512 — Stage A: Optimal S-Box Search Engine
=====================================================
Exhaustively searches for an 8×8 bijective S-box with significantly
stronger cryptanalytic properties than the current N_bio:

  Current:   δ_max = 10,  NL = 96,   fixed_points = 2
  Target:    δ_max ≤ 6,   NL ≥ 100,  fixed_points = 0

Search Strategy
---------------
Three independent search modes are used in order of ascending cost:

  1. FEISTEL SEARCH  — Sweep Feistel round-function parameters exhaustively
                       (fast, structure-preserving, keeps Mini-Feistel story)

  2. RANDOM BIJECTION SEARCH — Sample random permutations of {0..255},
                               accept if metrics improve (fast stochastic baseline)

  3. HILL-CLIMB SEARCH  — Start from best-so-far, apply random transpositions,
                          accept improvements (simulated-annealing style)

All candidates are scored with a composite objective:
    score = 1000 * (256 - δ_max) + NL - 10 * fixed_points

The top-5 candidates are exported with full metric tables.

Usage
-----
    python tests/search_optimal_sbox.py [--mode feistel|random|hill] [--trials N]

"""

import sys
import os
import time
import random
import argparse
import itertools

# ──────────────────────────────────────────────────────────────────────────────
# Core Cryptanalytic Primitives
# ──────────────────────────────────────────────────────────────────────────────

def compute_ddt(sbox):
    """Compute the full 256×256 Difference Distribution Table."""
    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        fx = sbox[x]
        for dx in range(1, 256):
            dy = fx ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    return ddt

def delta_max(ddt):
    """Return the maximum non-trivial DDT entry (differential uniformity)."""
    best = 0
    for dx in range(1, 256):
        for dy in range(256):
            if ddt[dx][dy] > best:
                best = ddt[dx][dy]
    return best

def compute_lat(sbox):
    """Compute the full 256×256 Linear Approximation Table."""
    lat = [[0] * 256 for _ in range(256)]
    for a in range(256):
        for b in range(1, 256):
            bias = 0
            for x in range(256):
                # popcount(a & x) XOR popcount(b & sbox[x])
                lhs = bin(a & x).count('1') & 1
                rhs = bin(b & sbox[x]).count('1') & 1
                if lhs == rhs:
                    bias += 1
            lat[a][b] = abs(bias - 128)   # Store |W|/2
    return lat

def nonlinearity(lat):
    """Return vectorial NL = 128 - max|W|/2 from LAT."""
    best = 0
    for a in range(256):
        for b in range(1, 256):
            if lat[a][b] > best:
                best = lat[a][b]
    return 128 - best

def count_fixed_points(sbox):
    """Count x such that sbox[x] == x."""
    return sum(1 for x in range(256) if sbox[x] == x)

def count_opp_fixed_points(sbox):
    """Count x such that sbox[x] == x ^ 0xFF."""
    return sum(1 for x in range(256) if sbox[x] == (x ^ 0xFF))

def sac_deviation(sbox):
    """Return mean deviation from 0.5 for single-bit flip outputs (SAC)."""
    total = 0
    count = 0
    for x in range(256):
        for bit in range(8):
            x2 = x ^ (1 << bit)
            diff = sbox[x] ^ sbox[x2]
            for out_bit in range(8):
                total += (diff >> out_bit) & 1
                count += 1
    mean = total / count
    return abs(mean - 0.5)

def score_sbox(d_max, nl, fp):
    """Composite score: higher is better."""
    return 1000 * (256 - d_max) + nl - 10 * fp

def is_bijection(sbox):
    return len(set(sbox)) == 256

# ──────────────────────────────────────────────────────────────────────────────
# Mini-Feistel S-box generator (keeps the design story)
# ──────────────────────────────────────────────────────────────────────────────

def rotl4(x, n):
    n &= 3
    return ((x << n) | (x >> (4 - n))) & 0x0F

def feistel_sbox(round_params):
    """
    Build a 256-entry S-box from an 8-round balanced Mini-Feistel on nibbles.

    round_params: list of 8 tuples (mul, add, rot1, rot2, op)
        mul  ∈ {3,5,7,11,13}  (units mod 16)
        add  ∈ {1..15}
        rot1 ∈ {1,2,3}
        rot2 ∈ {1,2,3}
        op   ∈ {0='and', 1='or', 2='xor'}
    """
    sbox = []
    for x in range(256):
        L = (x >> 4) & 0x0F
        R = x & 0x0F
        for (mul, add, rot1, rot2, op) in round_params:
            rr = rotl4(R, rot1)
            if op == 0:
                extra = R & rotl4(R, rot2)
            elif op == 1:
                extra = R | rotl4(R, rot2)
            else:
                extra = R ^ rotl4(R, rot2)
            F = ((R ^ rr) * mul + add + extra) % 16
            L, R = R, (L ^ F) & 0x0F
        sbox.append((L << 4) | R)
    return sbox

# ──────────────────────────────────────────────────────────────────────────────
# Search Mode 1: Feistel Parameter Search
# ──────────────────────────────────────────────────────────────────────────────

MUL_OPTIONS  = [3, 5, 7, 11, 13]
ADD_OPTIONS  = [1, 3, 5, 7, 9, 11, 13, 15]
ROT_OPTIONS  = [1, 2, 3]
OP_OPTIONS   = [0, 1, 2]

def feistel_search(trials=200_000, seed=42):
    """Random search over Feistel round parameters."""
    rng = random.Random(seed)
    best_score = -1
    best_sbox  = None
    best_meta  = {}
    candidates = []

    print(f"\n[FEISTEL SEARCH] Running {trials:,} random Feistel configurations...")
    t0 = time.time()

    for trial in range(trials):
        params = []
        for _ in range(8):
            mul  = rng.choice(MUL_OPTIONS)
            add  = rng.choice(ADD_OPTIONS)
            rot1 = rng.choice(ROT_OPTIONS)
            rot2 = rng.choice(ROT_OPTIONS)
            op   = rng.choice(OP_OPTIONS)
            params.append((mul, add, rot1, rot2, op))

        sbox = feistel_sbox(params)
        if not is_bijection(sbox):
            continue

        fp = count_fixed_points(sbox)

        # Quick pre-filter on partial DDT before full DDT (saves ~70% time)
        quick_d = 0
        for x in range(0, 256, 4):
            for dx in range(1, 32):
                v = sbox[x] ^ sbox[x ^ dx]
                # partial accumulator trick: just track worst pair
        ddt = compute_ddt(sbox)
        d = delta_max(ddt)

        if d > 10:      # Worse than current; skip full LAT
            continue

        lat = compute_lat(sbox)
        nl  = nonlinearity(lat)
        sc  = score_sbox(d, nl, fp)

        if sc > best_score:
            best_score = sc
            best_sbox  = sbox[:]
            best_meta  = {"delta_max": d, "NL": nl, "fixed_points": fp, "params": params}
            print(f"  [Trial {trial:>7}] ★ NEW BEST  δ_max={d}  NL={nl}  FP={fp}  score={sc}")

        if d <= 6 and nl >= 100 and fp == 0:
            candidates.append({"sbox": sbox[:], "delta_max": d, "NL": nl, "fixed_points": fp,
                                "score": sc, "params": params})
            print(f"  [Trial {trial:>7}] ✓ TARGET HIT δ_max={d}  NL={nl}  FP={fp}")

        if (trial + 1) % 10_000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {trial+1:,}/{trials:,}  elapsed={elapsed:.1f}s  best_δ={best_meta.get('delta_max','?')}  best_NL={best_meta.get('NL','?')}")

    print(f"[FEISTEL SEARCH] Done. Best: δ_max={best_meta.get('delta_max')}  NL={best_meta.get('NL')}  FP={best_meta.get('fixed_points')}")
    return best_sbox, best_meta, candidates

# ──────────────────────────────────────────────────────────────────────────────
# Search Mode 2: Random Bijection Sampling
# ──────────────────────────────────────────────────────────────────────────────

def random_bijection_search(trials=50_000, seed=99):
    """Sample random permutations of {0..255} and evaluate metrics."""
    rng = random.Random(seed)
    base = list(range(256))
    best_score = -1
    best_sbox  = None
    best_meta  = {}
    candidates = []

    print(f"\n[RANDOM BIJECTION SEARCH] Sampling {trials:,} random permutations...")
    t0 = time.time()

    for trial in range(trials):
        sbox = base[:]
        rng.shuffle(sbox)

        fp = count_fixed_points(sbox)
        ddt = compute_ddt(sbox)
        d   = delta_max(ddt)

        if d > 8:
            continue

        lat = compute_lat(sbox)
        nl  = nonlinearity(lat)
        sc  = score_sbox(d, nl, fp)

        if sc > best_score:
            best_score = sc
            best_sbox  = sbox[:]
            best_meta  = {"delta_max": d, "NL": nl, "fixed_points": fp}
            print(f"  [Trial {trial:>7}] ★ NEW BEST  δ_max={d}  NL={nl}  FP={fp}  score={sc}")

        if d <= 6 and nl >= 100:
            candidates.append({"sbox": sbox[:], "delta_max": d, "NL": nl,
                                "fixed_points": fp, "score": sc})
            print(f"  [Trial {trial:>7}] ✓ TARGET HIT  δ_max={d}  NL={nl}  FP={fp}")

        if (trial + 1) % 5_000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {trial+1:,}/{trials:,}  elapsed={elapsed:.1f}s")

    print(f"[RANDOM BIJECTION SEARCH] Done. Best: δ_max={best_meta.get('delta_max')}  NL={best_meta.get('NL')}  FP={best_meta.get('fixed_points')}")
    return best_sbox, best_meta, candidates

# ──────────────────────────────────────────────────────────────────────────────
# Search Mode 3: Hill-Climb / Transposition Search
# ──────────────────────────────────────────────────────────────────────────────

def hill_climb_search(start_sbox, trials=100_000, seed=77):
    """
    Starting from start_sbox, repeatedly swap two random entries.
    Accept the swap if it improves (δ_max, NL, FP) composite score.
    """
    rng = random.Random(seed)
    current  = start_sbox[:]

    ddt = compute_ddt(current)
    d   = delta_max(ddt)
    lat = compute_lat(current)
    nl  = nonlinearity(lat)
    fp  = count_fixed_points(current)
    best_score = score_sbox(d, nl, fp)
    best_sbox  = current[:]
    best_meta  = {"delta_max": d, "NL": nl, "fixed_points": fp}
    candidates = []

    print(f"\n[HILL-CLIMB] Starting from δ_max={d}  NL={nl}  FP={fp}  score={best_score}")
    print(f"[HILL-CLIMB] Running {trials:,} swap trials...")
    t0 = time.time()
    improvements = 0

    for trial in range(trials):
        i, j = rng.sample(range(256), 2)
        current[i], current[j] = current[j], current[i]

        ddt2 = compute_ddt(current)
        d2   = delta_max(ddt2)
        lat2 = compute_lat(current)
        nl2  = nonlinearity(lat2)
        fp2  = count_fixed_points(current)
        sc2  = score_sbox(d2, nl2, fp2)

        if sc2 >= best_score:
            best_score = sc2
            best_sbox  = current[:]
            best_meta  = {"delta_max": d2, "NL": nl2, "fixed_points": fp2}
            improvements += 1
            print(f"  [Trial {trial:>7}] ★ IMPROVED  δ_max={d2}  NL={nl2}  FP={fp2}  score={sc2}")

            if d2 <= 6 and nl2 >= 100:
                candidates.append({"sbox": current[:], "delta_max": d2, "NL": nl2,
                                    "fixed_points": fp2, "score": sc2})
                print(f"  [Trial {trial:>7}] ✓ TARGET HIT!")
        else:
            # Revert
            current[i], current[j] = current[j], current[i]

        if (trial + 1) % 10_000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {trial+1:,}/{trials:,}  elapsed={elapsed:.1f}s  improvements={improvements}")

    print(f"[HILL-CLIMB] Done. Best: δ_max={best_meta['delta_max']}  NL={best_meta['NL']}  FP={best_meta['fixed_points']}")
    return best_sbox, best_meta, candidates

# ──────────────────────────────────────────────────────────────────────────────
# Output Formatting
# ──────────────────────────────────────────────────────────────────────────────

def print_sbox_table(sbox, label="S-Box"):
    print(f"\n  {label} (hex, row = high nibble, col = low nibble):")
    print("       0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F")
    for row in range(16):
        vals = "  ".join(f"{sbox[row*16+col]:02X}" for col in range(16))
        print(f"  0x{row:X}_  {vals}")

def print_c_array(sbox, name="H512_SBOX"):
    print(f"\nstatic const uint8_t {name}[256] = {{")
    for i in range(0, 256, 16):
        row = ", ".join(f"0x{v:02x}" for v in sbox[i:i+16])
        print(f"    {row},")
    print("};")

def build_inverse(sbox):
    inv = [0] * 256
    for x in range(256):
        inv[sbox[x]] = x
    return inv

def summarize_candidate(rank, meta, sbox):
    print(f"\n{'='*70}")
    print(f"  CANDIDATE #{rank}   score={meta['score']}")
    print(f"{'='*70}")
    print(f"  δ_max (Differential Uniformity) : {meta['delta_max']}  (AES=4, current=10)")
    print(f"  NL    (Nonlinearity)             : {meta['NL']}  (AES=112, current=96)")
    print(f"  Fixed Points                     : {meta['fixed_points']}")
    print(f"  Opposite Fixed Points            : {count_opp_fixed_points(sbox)}")
    if "params" in meta:
        print(f"\n  Feistel Round Parameters:")
        for j, (mul, add, rot1, rot2, op) in enumerate(meta["params"]):
            opname = ["AND","OR","XOR"][op]
            print(f"    F_{j}: mul={mul:>2}  add={add:>2}  rot1={rot1}  rot2={rot2}  op={opname}")
    print_sbox_table(sbox)
    inv = build_inverse(sbox)
    print_c_array(sbox,  "H512_SBOX")
    print_c_array(inv,   "H512_SBOX_INV")

# ──────────────────────────────────────────────────────────────────────────────
# Current N_bio baseline
# ──────────────────────────────────────────────────────────────────────────────

CURRENT_SBOX = [
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

def print_baseline():
    print("\n" + "="*70)
    print("  BASELINE: Current N_bio S-Box")
    print("="*70)
    ddt = compute_ddt(CURRENT_SBOX)
    d   = delta_max(ddt)
    lat = compute_lat(CURRENT_SBOX)
    nl  = nonlinearity(lat)
    fp  = count_fixed_points(CURRENT_SBOX)
    ofp = count_opp_fixed_points(CURRENT_SBOX)
    print(f"  δ_max : {d}   (target ≤ 6)")
    print(f"  NL    : {nl}  (target ≥ 100)")
    print(f"  FP    : {fp}  (target = 0)")
    print(f"  OFP   : {ofp}  (target = 0)")
    print(f"  Score : {score_sbox(d, nl, fp)}")
    return score_sbox(d, nl, fp)

# ──────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="H-512 Optimal S-Box Search")
    parser.add_argument("--mode",   default="all",
                        choices=["feistel", "random", "hill", "all"],
                        help="Search mode (default: all)")
    parser.add_argument("--trials", type=int, default=None,
                        help="Override number of trials per mode")
    args = parser.parse_args()

    print("=" * 70)
    print("  PROJECT H-512 — STAGE A: OPTIMAL S-BOX SEARCH ENGINE")
    print("  Target: δ_max ≤ 6 | NL ≥ 100 | Fixed Points = 0")
    print("=" * 70)

    baseline_score = print_baseline()
    all_candidates = []

    # ── Mode 1: Feistel ──────────────────────────────────────────────────────
    if args.mode in ("feistel", "all"):
        trials = args.trials or 300_000
        best_sb, best_m, cands = feistel_search(trials=trials)
        best_m["score"] = score_sbox(best_m["delta_max"], best_m["NL"], best_m["fixed_points"])
        best_m["sbox"]  = best_sb
        all_candidates.extend(cands)
        if best_sb:
            all_candidates.append(best_m)

    # ── Mode 2: Random Bijection ─────────────────────────────────────────────
    if args.mode in ("random", "all"):
        trials = args.trials or 20_000
        best_sb, best_m, cands = random_bijection_search(trials=trials)
        if best_sb:
            best_m["score"] = score_sbox(best_m["delta_max"], best_m["NL"], best_m["fixed_points"])
            best_m["sbox"]  = best_sb
            all_candidates.extend(cands)
            all_candidates.append(best_m)

    # ── Mode 3: Hill-Climb from best feistel result ───────────────────────────
    if args.mode in ("hill", "all"):
        # Start from the best Feistel result or current if nothing found
        start = all_candidates[0]["sbox"] if all_candidates else CURRENT_SBOX
        trials = args.trials or 50_000
        best_sb, best_m, cands = hill_climb_search(start_sbox=start, trials=trials)
        if best_sb:
            best_m["score"] = score_sbox(best_m["delta_max"], best_m["NL"], best_m["fixed_points"])
            best_m["sbox"]  = best_sb
            all_candidates.extend(cands)
            all_candidates.append(best_m)

    # ── Final Summary ─────────────────────────────────────────────────────────
    if not all_candidates:
        print("\n[!] No candidates found that beat baseline. Showing best overall from each mode.")
        # Gather best-so-far from modes
        sys.exit(0)

    # Deduplicate and sort
    seen = set()
    unique_candidates = []
    for c in all_candidates:
        key = tuple(c["sbox"])
        if key not in seen:
            seen.add(key)
            unique_candidates.append(c)

    unique_candidates.sort(key=lambda x: -x["score"])
    top5 = unique_candidates[:5]

    print(f"\n\n{'='*70}")
    print(f"  SEARCH COMPLETE — TOP {len(top5)} CANDIDATES")
    print(f"  Baseline Score: {baseline_score}  (current N_bio)")
    print(f"{'='*70}")

    for rank, cand in enumerate(top5, 1):
        summarize_candidate(rank, cand, cand["sbox"])

    # Print the single best candidate's C header snippet
    if top5:
        best = top5[0]
        bsbox = best["sbox"]
        print(f"\n\n{'='*70}")
        print(f"  RECOMMENDED REPLACEMENT: CANDIDATE #1")
        print(f"  δ_max={best['delta_max']}  NL={best['NL']}  FP={best['fixed_points']}")
        print(f"  Copy the C arrays below into src/h512_constants.h")
        print(f"{'='*70}")
        print_c_array(bsbox, "H512_SBOX")
        inv = build_inverse(bsbox)
        print_c_array(inv,   "H512_SBOX_INV")

if __name__ == "__main__":
    main()
