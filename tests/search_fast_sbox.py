"""
Project H-512 — Stage A: Fast S-Box Search (NumPy-Accelerated)
===============================================================
Replaces the pure-Python search with numpy-vectorized DDT and LAT,
achieving ~100x speedup.

Strategy:
  - Phase 1 (fast pre-filter):  Compute only δ_max via vectorized DDT.
                                 Reject if δ_max > threshold.
  - Phase 2 (full check):       Compute NL via WHT only for survivors.
  - Phase 3 (hill-climb):       Start from best found, apply transpositions.

Target: δ_max ≤ 6, NL ≥ 100, zero fixed points.

Usage:
    python tests/search_fast_sbox.py [--mode feistel|random|hill|all] [--trials N]
"""

import numpy as np
import random
import time
import argparse
import sys

# ──────────────────────────────────────────────────────────────────────────────
# NumPy-accelerated DDT and NL
# ──────────────────────────────────────────────────────────────────────────────

def compute_delta_max_np(sbox):
    """
    Compute differential uniformity δ_max using numpy broadcasting.
    DDT[dx][dy] = #{x : sbox[x] ^ sbox[x^dx] = dy}
    Returns δ_max (scalar).
    """
    s = np.array(sbox, dtype=np.uint8)
    x  = np.arange(256, dtype=np.uint8)
    dx = np.arange(1, 256, dtype=np.uint8)

    # s_x:  [256]  →  broadcast over dx
    # s_xd: [255, 256] where s_xd[i,j] = sbox[j ^ dx[i]]
    x_xd = x[np.newaxis, :] ^ dx[:, np.newaxis]       # [255, 256]
    s_xd = s[x_xd]                                     # [255, 256]
    dy   = s[np.newaxis, :] ^ s_xd                     # [255, 256]  output differences

    # Count occurrences per (dx_idx, dy_val)
    # Flatten and use bincount
    dx_idx = np.repeat(np.arange(255), 256)            # [255*256]
    dy_flat = dy.ravel()                               # [255*256]
    linear  = dx_idx * 256 + dy_flat.astype(np.int32)
    counts  = np.bincount(linear, minlength=255*256)
    return int(counts.max())

def compute_nl_np(sbox):
    """
    Compute vectorial nonlinearity NL using Walsh-Hadamard Transform.
    Uses numpy for the WHT butterfly.
    NL = 128 - max_{alpha, beta!=0} |W_beta(alpha)| / 2
    where W is computed over {+1,-1} inputs.
    Returns NL (scalar).
    """
    s = np.array(sbox, dtype=np.int32)
    x = np.arange(256, dtype=np.int32)

    global_max_w = 0

    for b in range(1, 256):
        # Boolean function: f(x) = popcount(b & sbox[x]) mod 2
        bv = int(b)
        f_bits = np.bitwise_and(s, bv)
        # popcount mod 2 via lookup: popcount(x) & 1
        # Fast: use np.unpackbits trick
        f01 = np.array([bin(int(v)).count('1') & 1 for v in f_bits], dtype=np.int32)
        # Map {0,1} -> {+1,-1}
        f_pm = 1 - 2 * f01

        # In-place WHT
        wht = f_pm.copy()
        step = 1
        while step < 256:
            a = wht[0::step*2].copy()  # placeholder — do proper butterfly
            # Reshape for butterfly
            w = wht.reshape(-1, step * 2)
            lo = w[:, :step].copy()
            hi = w[:, step:].copy()
            w[:, :step] = lo + hi
            w[:, step:] = lo - hi
            wht = w.ravel()
            step *= 2

        # Exclude alpha=0 from NL computation
        local_max = int(np.max(np.abs(wht[1:])))
        if local_max > global_max_w:
            global_max_w = local_max

    return 128 - global_max_w // 2

def compute_nl_fast_np(sbox):
    """
    Faster NL via full vectorized WHT over all 255 beta values at once.
    Memory: 255 x 256 integers.
    """
    s = np.array(sbox, dtype=np.uint8)

    # Build truth table matrix: T[b, x] = popcount(b & sbox[x]) mod 2
    # b in [1..255], x in [0..255]
    betas = np.arange(1, 256, dtype=np.uint8)          # [255]
    s_rep = s[np.newaxis, :]                            # [1, 256]
    b_rep = betas[:, np.newaxis]                        # [255, 1]

    # Efficient popcount mod 2: use XOR fold
    # popcount(v) mod 2 = v ^ (v>>1) ^ (v>>2) ^ ... ^ (v>>7), last bit
    bsv = (s_rep & b_rep).astype(np.uint8)             # [255, 256]
    # Fold XOR to get parity
    bsv = bsv ^ (bsv >> 4)
    bsv = bsv ^ (bsv >> 2)
    bsv = bsv ^ (bsv >> 1)
    parity = (bsv & 1).astype(np.int32)                # [255, 256]

    # Map {0,1} -> {+1,-1}
    f_pm = 1 - 2 * parity                              # [255, 256]

    # WHT along axis=1 (256-point transform for each of 255 rows)
    wht = f_pm.astype(np.float32)
    step = 1
    while step < 256:
        w = wht.reshape(255, -1, step * 2)
        lo = w[:, :, :step].copy()
        hi = w[:, :, step:].copy()
        w[:, :, :step] = lo + hi
        w[:, :, step:] = lo - hi
        wht = w.reshape(255, 256)
        step *= 2

    # Exclude alpha=0 column from NL (column 0 = WHT[b, alpha=0] = sum of f_pm)
    max_abs = np.max(np.abs(wht[:, 1:]))
    return int(128 - max_abs // 2)

def count_fixed_points(sbox):
    s = np.array(sbox, dtype=np.uint8)
    return int(np.sum(s == np.arange(256, dtype=np.uint8)))

def count_opp_fixed_points(sbox):
    s = np.array(sbox, dtype=np.uint8)
    return int(np.sum(s == (np.arange(256, dtype=np.uint8) ^ 0xFF)))

def is_bijection(sbox):
    return len(set(sbox)) == 256

def score(d, nl, fp, ofp=0):
    return 1000 * (256 - d) + nl - 50 * fp - 50 * ofp

# ──────────────────────────────────────────────────────────────────────────────
# Mini-Feistel Generator
# ──────────────────────────────────────────────────────────────────────────────

def rotl4(x, n):
    n &= 3
    return ((x << n) | (x >> (4 - n))) & 0x0F

def feistel_sbox(params):
    sbox = []
    for x in range(256):
        L = (x >> 4) & 0x0F
        R = x & 0x0F
        for (mul, add, rot1, rot2, op) in params:
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

MUL_OPTIONS = [3, 5, 7, 11, 13]
ADD_OPTIONS = [1, 3, 5, 7, 9, 11, 13, 15]
ROT_OPTIONS = [1, 2, 3]
OP_OPTIONS  = [0, 1, 2]

# ──────────────────────────────────────────────────────────────────────────────
# Current S-Box baseline
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

# ──────────────────────────────────────────────────────────────────────────────
# Search Modes
# ──────────────────────────────────────────────────────────────────────────────

def feistel_search(trials, rng, d_threshold=8, nl_threshold=98):
    print(f"\n[FEISTEL SEARCH] {trials:,} trials  |  pre-filter δ≤{d_threshold}, NL≥{nl_threshold}")
    best_sc = score(compute_delta_max_np(CURRENT_SBOX), 96, 2, 3)
    best_sbox = CURRENT_SBOX[:]
    best_meta = {"delta_max": 10, "NL": 96, "FP": 2, "OFP": 3}
    survivors = []
    t0 = time.time()

    for trial in range(trials):
        params = [(rng.choice(MUL_OPTIONS), rng.choice(ADD_OPTIONS),
                   rng.choice(ROT_OPTIONS), rng.choice(ROT_OPTIONS),
                   rng.choice(OP_OPTIONS)) for _ in range(8)]
        sbox = feistel_sbox(params)
        if not is_bijection(sbox):
            continue

        # Fast DDT pre-filter
        d = compute_delta_max_np(sbox)
        if d > d_threshold:
            continue

        # Full NL check for survivors
        nl = compute_nl_fast_np(sbox)
        fp = count_fixed_points(sbox)
        ofp = count_opp_fixed_points(sbox)
        sc = score(d, nl, fp, ofp)

        survivors.append((d, nl, fp, ofp, sc, sbox[:], params))

        if sc > best_sc:
            best_sc = sc
            best_sbox = sbox[:]
            best_meta = {"delta_max": d, "NL": nl, "FP": fp, "OFP": ofp, "params": params}
            print(f"  [Trial {trial:>7}] ★ NEW BEST  δ_max={d}  NL={nl}  FP={fp}  OFP={ofp}  score={sc}")

        if d <= 6 and nl >= 100 and fp == 0 and ofp == 0:
            print(f"  [Trial {trial:>7}] TARGET HIT! δ_max={d}  NL={nl}  FP={fp}  OFP={ofp}")

        if (trial + 1) % 5000 == 0:
            t = time.time() - t0
            rate = (trial + 1) / t
            print(f"  ... {trial+1:,}/{trials:,}  survivors={len(survivors)}  "
                  f"best_δ={best_meta['delta_max']}  NL={best_meta['NL']}  "
                  f"rate={rate:.0f}/s  eta={int((trials-trial-1)/rate)}s")

    print(f"\n[FEISTEL SEARCH] Done. {len(survivors)} survivors out of {trials} trials.")
    print(f"  Best: δ_max={best_meta['delta_max']}  NL={best_meta['NL']}  FP={best_meta['FP']}  OFP={best_meta['OFP']}")
    return best_sbox, best_meta, survivors

def random_bijection_search(trials, rng, d_threshold=8, nl_threshold=98):
    print(f"\n[RANDOM BIJECTION] {trials:,} trials  |  pre-filter δ≤{d_threshold}")
    base = list(range(256))
    best_sc = score(10, 96, 2, 3)
    best_sbox = None
    best_meta = {}
    survivors = []
    t0 = time.time()

    for trial in range(trials):
        sbox = base[:]
        rng.shuffle(sbox)

        d = compute_delta_max_np(sbox)
        if d > d_threshold:
            continue

        nl = compute_nl_fast_np(sbox)
        fp = count_fixed_points(sbox)
        ofp = count_opp_fixed_points(sbox)
        sc = score(d, nl, fp, ofp)
        survivors.append((d, nl, fp, ofp, sc, sbox[:]))

        if sc > best_sc:
            best_sc = sc
            best_sbox = sbox[:]
            best_meta = {"delta_max": d, "NL": nl, "FP": fp, "OFP": ofp}
            print(f"  [Trial {trial:>7}] ★ NEW BEST  δ_max={d}  NL={nl}  FP={fp}  OFP={ofp}  score={sc}")

        if d <= 6 and nl >= 100 and fp == 0 and ofp == 0:
            print(f"  [Trial {trial:>7}] TARGET HIT! δ_max={d}  NL={nl}  FP={fp}  OFP={ofp}")

        if (trial + 1) % 2000 == 0:
            t = time.time() - t0
            rate = (trial + 1) / t
            print(f"  ... {trial+1:,}/{trials:,}  survivors={len(survivors)}  "
                  f"rate={rate:.0f}/s  eta={int((trials-trial-1)/rate)}s")

    print(f"\n[RANDOM BIJECTION] Done. {len(survivors)} survivors.")
    if best_meta:
        print(f"  Best: δ_max={best_meta['delta_max']}  NL={best_meta['NL']}  FP={best_meta['FP']}  OFP={best_meta['OFP']}")
    return best_sbox, best_meta, survivors

def hill_climb(start_sbox, trials, rng):
    print(f"\n[HILL-CLIMB] {trials:,} swap trials from starting point...")
    current = start_sbox[:]
    d = compute_delta_max_np(current)
    nl = compute_nl_fast_np(current)
    fp = count_fixed_points(current)
    ofp = count_opp_fixed_points(current)
    best_sc = score(d, nl, fp, ofp)
    best_sbox = current[:]
    best_meta = {"delta_max": d, "NL": nl, "FP": fp, "OFP": ofp}
    improvements = 0
    t0 = time.time()

    print(f"  Start: δ_max={d}  NL={nl}  FP={fp}  OFP={ofp}  score={best_sc}")

    for trial in range(trials):
        i, j = rng.sample(range(256), 2)
        current[i], current[j] = current[j], current[i]

        d2 = compute_delta_max_np(current)
        if d2 > best_meta["delta_max"] + 1:
            current[i], current[j] = current[j], current[i]
            continue

        nl2 = compute_nl_fast_np(current)
        fp2 = count_fixed_points(current)
        ofp2 = count_opp_fixed_points(current)
        sc2 = score(d2, nl2, fp2, ofp2)

        if sc2 >= best_sc:
            best_sc = sc2
            best_sbox = current[:]
            best_meta = {"delta_max": d2, "NL": nl2, "FP": fp2, "OFP": ofp2}
            improvements += 1
            print(f"  [Trial {trial:>7}] ★ IMPROVED  δ_max={d2}  NL={nl2}  FP={fp2}  OFP={ofp2}  score={sc2}")
            if d2 <= 6 and nl2 >= 100 and fp2 == 0 and ofp2 == 0:
                print(f"  TARGET HIT! δ_max={d2}  NL={nl2}  FP={fp2}  OFP={ofp2}")
        else:
            current[i], current[j] = current[j], current[i]

        if (trial + 1) % 5000 == 0:
            t = time.time() - t0
            print(f"  ... {trial+1:,}/{trials:,}  improvements={improvements}  elapsed={t:.0f}s")

    print(f"\n[HILL-CLIMB] Done. Best: δ_max={best_meta['delta_max']}  NL={best_meta['NL']}  FP={best_meta['FP']}  OFP={best_meta['OFP']}")
    return best_sbox, best_meta

# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def print_c_array(sbox, name):
    print(f"\nstatic const uint8_t {name}[256] = {{")
    for i in range(0, 256, 16):
        row = ", ".join(f"0x{v:02x}" for v in sbox[i:i+16])
        print(f"    {row},")
    print("};")

def build_inverse(sbox):
    inv = [0]*256
    for x in range(256):
        inv[sbox[x]] = x
    return inv

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="H-512 Fast S-Box Search (NumPy)")
    parser.add_argument("--mode",   default="all", choices=["feistel","random","hill","all"])
    parser.add_argument("--trials", type=int, default=None)
    parser.add_argument("--seed",   type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    np.random.seed(args.seed)

    print("="*70)
    print("  H-512 STAGE A — FAST S-BOX SEARCH (NumPy-Accelerated)")
    print(f"  Target: δ_max ≤ 6 | NL ≥ 100 | FP = 0")
    print("="*70)

    # Baseline
    d_base = compute_delta_max_np(CURRENT_SBOX)
    nl_base = compute_nl_fast_np(CURRENT_SBOX)
    fp_base = count_fixed_points(CURRENT_SBOX)
    ofp_base = count_opp_fixed_points(CURRENT_SBOX)
    print(f"\n  Baseline N_bio: δ_max={d_base}  NL={nl_base}  FP={fp_base}  OFP={ofp_base}  score={score(d_base,nl_base,fp_base,ofp_base)}")

    all_survivors = []
    best_sbox = CURRENT_SBOX[:]
    best_meta = {"delta_max": d_base, "NL": nl_base, "FP": fp_base, "OFP": ofp_base}

    if args.mode in ("feistel", "all"):
        trials = args.trials or 500_000
        bs, bm, surv = feistel_search(trials, rng)
        all_survivors.extend(surv)
        if bm and score(bm["delta_max"], bm["NL"], bm["FP"], bm["OFP"]) > score(best_meta["delta_max"], best_meta["NL"], best_meta["FP"], best_meta["OFP"]):
            best_sbox, best_meta = bs, bm

    if args.mode in ("random", "all"):
        trials = args.trials or 100_000
        bs, bm, surv = random_bijection_search(trials, rng)
        all_survivors.extend(surv)
        if bs and bm and score(bm["delta_max"], bm["NL"], bm["FP"], bm["OFP"]) > score(best_meta["delta_max"], best_meta["NL"], best_meta["FP"], best_meta["OFP"]):
            best_sbox, best_meta = bs, bm

    if args.mode in ("hill", "all"):
        trials = args.trials or 100_000
        bs, bm = hill_climb(best_sbox, trials, rng)
        if score(bm["delta_max"], bm["NL"], bm["FP"], bm["OFP"]) > score(best_meta["delta_max"], best_meta["NL"], best_meta["FP"], best_meta["OFP"]):
            best_sbox, best_meta = bs, bm

    # Final report
    print(f"\n{'='*70}")
    print(f"  SEARCH COMPLETE")
    print(f"  Best result: δ_max={best_meta['delta_max']}  NL={best_meta['NL']}  FP={best_meta['FP']}  OFP={best_meta['OFP']}")
    print(f"  Baseline:    δ_max={d_base}            NL={nl_base}    FP={fp_base}    OFP={ofp_base}")

    if best_meta["delta_max"] < d_base or best_meta["NL"] > nl_base:
        print(f"\n  IMPROVEMENT FOUND — copy arrays below into src/h512_constants.h")
        print_c_array(best_sbox, "H512_SBOX")
        inv = build_inverse(best_sbox)
        print_c_array(inv, "H512_SBOX_INV")
    else:
        print(f"\n  No improvement over baseline found in this run.")
        print(f"  Consider increasing --trials or running overnight.")

    if all_survivors:
        # Sort and print top 5
        all_survivors.sort(key=lambda x: -x[3])
        print(f"\n  Top 5 survivors by score:")
        for i, entry in enumerate(all_survivors[:5], 1):
            d, nl, fp, sc, sb = entry[:5]
            print(f"    #{i}: δ_max={d}  NL={nl}  FP={fp}  score={sc}")

if __name__ == "__main__":
    main()
