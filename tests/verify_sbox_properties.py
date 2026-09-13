"""
Project H-512 — Stage A: Complete S-Box Cryptanalytic Verifier
==============================================================
Given any 256-entry S-box, computes and reports every relevant
cryptanalytic metric exhaustively:

  1. Bijectivity (permutation check)
  2. Differential Uniformity δ_max  — full 256×256 DDT
  3. Nonlinearity NL                — full 256×256 LAT (Walsh-Hadamard)
  4. Algebraic Degree deg(y_k)      — for all 8 coordinate functions via ANF
  5. Strict Avalanche Criterion     — 512×512 bit-flip response tensor
  6. Bit Independence Criterion     — pairwise output bit correlation
  7. Fixed Points & Opposite Fixed Points
  8. Cycle Decomposition            — orbit lengths in S_256
  9. Inverse S-Box                  — verified round-trip identity

Usage
-----
    python tests/verify_sbox_properties.py [--sbox current|<hex_file>]

"""

import sys
import os
import time
import argparse

_stdout_reconf = getattr(sys.stdout, "reconfigure", None)
if _stdout_reconf is not None:
    try:
        _stdout_reconf(encoding="utf-8")
    except Exception:
        pass

_stderr_reconf = getattr(sys.stderr, "reconfigure", None)
if _stderr_reconf is not None:
    try:
        _stderr_reconf(encoding="utf-8")
    except Exception:
        pass

# Import reference S-box from python package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
try:
    from h512 import _N_BIO_TABLE as CURRENT_SBOX
except ImportError:
    CURRENT_SBOX = [
        0x57, 0xe9, 0xfe, 0xd7, 0x66, 0xf6, 0x67, 0xeb, 0xa6, 0x7a, 0x54, 0xd5, 0x8b, 0x07, 0x46, 0x41,
        0x82, 0x8c, 0x16, 0x9a, 0x8a, 0x1b, 0x3a, 0xd8, 0xc1, 0x4e, 0x52, 0xd2, 0xc6, 0xa5, 0x9b, 0x08,
        0x03, 0x8d, 0x30, 0x18, 0x49, 0xef, 0x95, 0x58, 0xf7, 0xbc, 0xb8, 0x23, 0x71, 0x59, 0x02, 0x10,
        0x24, 0x7d, 0x05, 0x4d, 0x6e, 0x26, 0xac, 0x84, 0xcc, 0xf0, 0x9f, 0x39, 0xbd, 0x1c, 0x96, 0x63,
        0x47, 0xb0, 0x97, 0x61, 0x14, 0xc0, 0x7e, 0x3e, 0x3d, 0x86, 0x04, 0x56, 0x2a, 0xea, 0x22, 0xd4,
        0xc3, 0x69, 0x3f, 0xe1, 0xec, 0x43, 0xb6, 0xda, 0xab, 0x91, 0x0d, 0xbf, 0x8e, 0xe3, 0x78, 0x75,
        0xa1, 0x87, 0x2f, 0x4c, 0x6a, 0x1d, 0xf3, 0x28, 0xe4, 0x70, 0xfd, 0xd6, 0xce, 0xd3, 0xa9, 0xe2,
        0xe8, 0xa2, 0x79, 0x60, 0x77, 0xf8, 0x09, 0x6d, 0xc4, 0x5a, 0xe7, 0xb3, 0xa3, 0xf5, 0x62, 0x32,
        0x94, 0xde, 0xb9, 0x35, 0x40, 0x90, 0x0b, 0x45, 0xe5, 0x0f, 0x15, 0xff, 0xdf, 0xe6, 0xb1, 0x5b,
        0x27, 0x42, 0x4a, 0x20, 0x50, 0x2c, 0xf9, 0xd0, 0x3c, 0x89, 0xe0, 0xbe, 0xb2, 0xae, 0xf2, 0x76,
        0x9d, 0xdc, 0x6f, 0x80, 0x0e, 0x81, 0x7b, 0xad, 0xc7, 0x36, 0x6b, 0xb5, 0x38, 0x85, 0x21, 0x5f,
        0x73, 0x65, 0x0c, 0xcb, 0xee, 0x55, 0x99, 0xd9, 0x00, 0x2e, 0x29, 0x34, 0x6c, 0x01, 0x83, 0x12,
        0xc8, 0xa7, 0x33, 0x53, 0xc9, 0xba, 0xcd, 0x25, 0xd1, 0x17, 0xf4, 0xfa, 0x06, 0x31, 0xb7, 0x11,
        0x7c, 0x13, 0x5c, 0x3b, 0x51, 0x2b, 0x9e, 0xb4, 0x0a, 0x72, 0xfc, 0x37, 0x68, 0x4f, 0x1a, 0xa8,
        0xa4, 0xaa, 0x98, 0xcf, 0x48, 0x5d, 0x2d, 0x9c, 0x93, 0xaf, 0xfb, 0x5e, 0xbb, 0xf1, 0xc5, 0x88,
        0xdb, 0x92, 0x7f, 0x8f, 0x19, 0xca, 0x1e, 0x1f, 0xdd, 0x64, 0x44, 0x4b, 0xed, 0xa0, 0xc2, 0x74
    ]

# ──────────────────────────────────────────────────────────────────────────────
# 1. Bijectivity
# ──────────────────────────────────────────────────────────────────────────────

def verify_bijectivity(sbox):
    img = set(sbox)
    n = len(sbox)
    ok = (n == 256 and len(img) == 256 and min(img) == 0 and max(img) == 255)
    return ok, n, len(img)

# ──────────────────────────────────────────────────────────────────────────────
# 2. Difference Distribution Table
# ──────────────────────────────────────────────────────────────────────────────

def compute_ddt(sbox):
    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for dx in range(1, 256):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    return ddt

def analyze_ddt(ddt):
    d_max = 0
    d_max_pairs = []
    histogram = {}
    for dx in range(1, 256):
        for dy in range(256):
            v = ddt[dx][dy]
            histogram[v] = histogram.get(v, 0) + 1
            if v > d_max:
                d_max = v
                d_max_pairs = [(dx, dy)]
            elif v == d_max:
                d_max_pairs.append((dx, dy))
    return d_max, d_max_pairs, histogram

# ──────────────────────────────────────────────────────────────────────────────
# 3. Linear Approximation Table + Nonlinearity
# ──────────────────────────────────────────────────────────────────────────────

def compute_lat_and_nl(sbox):
    """
    Compute vectorial NL via Walsh-Hadamard Transform.
    W_beta(alpha) = sum_{x in F_2^8} (-1)^{ popcount(beta & sbox[x]) XOR popcount(alpha & x) }
    NL = 128 - max_{alpha, beta != 0} |W_beta(alpha)| / 2
    
    The in-place WHT requires truth-table in {-1,+1} form:
    f_pm(x) = 1 - 2*f(x)  where f(x) = popcount(beta & sbox[x]) mod 2
    Then the unnormalized WHT gives W values in [-256, 256].
    NL = 128 - max|W| / 2.
    """
    max_w = 0
    max_a, max_b = 0, 0
    coord_nl = []

    for b in range(1, 256):
        # Map {0,1} truth table to {+1,-1}: 0->1, 1->-1
        f_pm = [1 - 2 * (bin(b & sbox[x]).count('1') & 1) for x in range(256)]

        # In-place Walsh-Hadamard butterfly over {+1,-1} values
        wht = f_pm[:]
        step = 1
        while step < 256:
            for i in range(0, 256, step * 2):
                for j in range(step):
                    u = wht[i + j]
                    v = wht[i + j + step]
                    wht[i + j]        = u + v
                    wht[i + j + step] = u - v
            step *= 2

        # WHT[0] = sum of all f_pm = 256 - 2*popcount(f); others are Walsh coefficients
        # We exclude alpha=0 from the NL computation (it equals sum_x f_pm = const)
        local_max = max(abs(wht[a]) for a in range(1, 256))
        coord_nl.append(128 - local_max // 2)

        # Also check alpha=0 for global max (for reporting, not for NL)
        full_max = max(abs(w) for w in wht)
        if full_max > max_w:
            max_w = full_max
            # find which alpha gives this
            for ai, w in enumerate(wht):
                if abs(w) == full_max:
                    max_a = ai
                    break
            max_b = b

    nl = min(coord_nl)
    return nl, max_w, max_a, max_b, coord_nl

# ──────────────────────────────────────────────────────────────────────────────
# 4. Algebraic Degree via ANF (Möbius / Algebraic Normal Form)
# ──────────────────────────────────────────────────────────────────────────────

def truth_table_to_anf(tt):
    """
    Converts a truth table (list of 256 bits) to its ANF coefficients
    via the Möbius transform. Returns list of 256 ANF coefficients.
    """
    anf = tt[:]
    for i in range(8):
        for x in range(256):
            if (x >> i) & 1:
                anf[x] ^= anf[x ^ (1 << i)]
    return anf

def anf_degree(anf):
    """Return max Hamming weight of support index with nonzero ANF coefficient."""
    deg = 0
    for u in range(256):
        if anf[u]:
            w = bin(u).count('1')
            if w > deg:
                deg = w
    return deg

def compute_algebraic_degrees(sbox):
    """Compute algebraic degree for each of the 8 output coordinate functions."""
    degrees = []
    for bit in range(8):
        tt = [(sbox[x] >> bit) & 1 for x in range(256)]
        anf = truth_table_to_anf(tt)
        degrees.append(anf_degree(anf))
    return degrees

# ──────────────────────────────────────────────────────────────────────────────
# 5. Strict Avalanche Criterion (SAC)
# ──────────────────────────────────────────────────────────────────────────────

def compute_sac(sbox):
    """
    SAC: for each input bit flip, on average half the output bits should flip.
    Returns (mean_flip_prob, std_dev, 8x8 matrix of per-(in_bit, out_bit) probs).
    """
    # flip_counts[in_bit][out_bit] = number of x where flipping in_bit changes out_bit
    flip_counts = [[0] * 8 for _ in range(8)]
    for x in range(256):
        for in_bit in range(8):
            x2 = x ^ (1 << in_bit)
            diff = sbox[x] ^ sbox[x2]
            for out_bit in range(8):
                if (diff >> out_bit) & 1:
                    flip_counts[in_bit][out_bit] += 1

    probs = [[c / 256.0 for c in row] for row in flip_counts]
    all_probs = [p for row in probs for p in row]
    mean = sum(all_probs) / len(all_probs)
    variance = sum((p - mean) ** 2 for p in all_probs) / len(all_probs)
    std = variance ** 0.5
    return mean, std, probs

# ──────────────────────────────────────────────────────────────────────────────
# 6. Bit Independence Criterion (BIC)
# ──────────────────────────────────────────────────────────────────────────────

def compute_bic(sbox):
    """
    BIC: for each input bit flip, pairs of output bits should be uncorrelated.
    Returns mean absolute Pearson correlation across all (in_bit, out_bit_i, out_bit_j) triples.
    """
    correlations = []
    for in_bit in range(8):
        # Compute the 256-bit response vector per output bit
        responses = []
        for out_bit in range(8):
            rv = []
            for x in range(256):
                x2 = x ^ (1 << in_bit)
                diff = sbox[x] ^ sbox[x2]
                rv.append((diff >> out_bit) & 1)
            responses.append(rv)
        # Correlate each pair of output bits
        for i in range(8):
            for j in range(i + 1, 8):
                ri = responses[i]
                rj = responses[j]
                n = 256
                sum_ij = sum(ri[k] * rj[k] for k in range(n))
                sum_i  = sum(ri)
                sum_j  = sum(rj)
                # Pearson
                num = n * sum_ij - sum_i * sum_j
                denom_i = (n * sum(ri[k]**2 for k in range(n)) - sum_i**2) ** 0.5
                denom_j = (n * sum(rj[k]**2 for k in range(n)) - sum_j**2) ** 0.5
                if denom_i > 0 and denom_j > 0:
                    r = abs(num / (denom_i * denom_j))
                else:
                    r = 0.0
                correlations.append(r)

    mean_corr = sum(correlations) / len(correlations) if correlations else 0
    return mean_corr

# ──────────────────────────────────────────────────────────────────────────────
# 7. Fixed Points
# ──────────────────────────────────────────────────────────────────────────────

def find_fixed_points(sbox):
    return [x for x in range(256) if sbox[x] == x]

def find_opp_fixed_points(sbox):
    return [x for x in range(256) if sbox[x] == (x ^ 0xFF)]

# ──────────────────────────────────────────────────────────────────────────────
# 8. Cycle Decomposition
# ──────────────────────────────────────────────────────────────────────────────

def cycle_decomposition(sbox):
    visited = [False] * 256
    cycles = []
    for start in range(256):
        if visited[start]:
            continue
        cycle = []
        x = start
        while not visited[x]:
            visited[x] = True
            cycle.append(x)
            x = sbox[x]
        cycles.append(len(cycle))
    cycles.sort(reverse=True)
    return cycles

# ──────────────────────────────────────────────────────────────────────────────
# 9. Inverse S-Box
# ──────────────────────────────────────────────────────────────────────────────

def build_inverse(sbox):
    inv = [0] * 256
    for x in range(256):
        inv[sbox[x]] = x
    return inv

def verify_inverse(sbox, inv):
    return all(inv[sbox[x]] == x and sbox[inv[x]] == x for x in range(256))

# ──────────────────────────────────────────────────────────────────────────────
# Report Formatting
# ──────────────────────────────────────────────────────────────────────────────

def grade(val, low_good, high_good, current, target, lower_is_better=True):
    """Return emoji grade based on comparison to target."""
    if lower_is_better:
        if val <= target:
            return "✅ EXCEEDS TARGET"
        elif val <= current:
            return "✔  BETTER THAN CURRENT"
        else:
            return "❌ WORSE THAN CURRENT"
    else:
        if val >= target:
            return "✅ EXCEEDS TARGET"
        elif val >= current:
            return "✔  BETTER THAN CURRENT"
        else:
            return "❌ WORSE THAN CURRENT"

def print_sbox_table(sbox):
    print("\n  S-Box (hex, row=high nibble, col=low nibble):")
    print("       0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F")
    for r in range(16):
        row_str = "  ".join(f"{sbox[r*16+c]:02X}" for c in range(16))
        print(f"  0x{r:X}_  {row_str}")

def run_full_analysis(sbox, label="S-Box"):
    print("\n" + "=" * 72)
    print(f"  PROJECT H-512 — FULL CRYPTANALYTIC VERIFICATION")
    print(f"  Subject: {label}")
    print("=" * 72)

    # ── Bijectivity ───────────────────────────────────────────────────────────
    print("\n[1] BIJECTIVITY")
    ok, n, img_size = verify_bijectivity(sbox)
    print(f"    Table size    : {n}")
    print(f"    Distinct vals : {img_size}")
    if ok:
        print(f"    ✅ BIJECTION CONFIRMED — all 256 values appear exactly once")
    else:
        print(f"    ❌ NOT A BIJECTION — {256 - img_size} collisions detected")
        return

    # ── DDT ───────────────────────────────────────────────────────────────────
    print("\n[2] DIFFERENTIAL UNIFORMITY (DDT)")
    print("    Computing full 256×256 DDT...", end="", flush=True)
    t0 = time.time()
    ddt = compute_ddt(sbox)
    t1 = time.time()
    d_max, d_pairs, hist = analyze_ddt(ddt)
    print(f" done ({t1-t0:.2f}s)")

    p_max = d_max / 256
    print(f"    δ_max                   : {d_max}  (p_diff = {d_max}/256 ≈ 2^{{{-1/p_max:.3f}}})")
    print(f"    DDT histogram (top vals): ", end="")
    for v in sorted(hist.keys(), reverse=True)[:6]:
        print(f"{v}→{hist[v]}  ", end="")
    print()
    print(f"    Worst-case (ΔX,ΔY) pairs: {len(d_pairs)} pairs achieving δ={d_max}")
    if d_pairs[:3]:
        for dx, dy in d_pairs[:3]:
            print(f"      ΔX=0x{dx:02X}  ΔY=0x{dy:02X}")
    print(f"    {grade(d_max, 4, 6, 10, 6, lower_is_better=True)}")
    print(f"    Reference: AES=4, current N_bio=10, target≤6")

    # ── LAT + NL ──────────────────────────────────────────────────────────────
    print("\n[3] NONLINEARITY (Walsh-Hadamard / LAT)")
    print("    Computing full Walsh-Hadamard Transform (255×256)...", end="", flush=True)
    t0 = time.time()
    nl, max_w, max_a, max_b, coord_nls = compute_lat_and_nl(sbox)
    t1 = time.time()
    print(f" done ({t1-t0:.2f}s)")

    epsilon = max_w / (2 * 256)
    print(f"    Vectorial NL (min over β) : {nl}  (ε_max = {epsilon:.6f} ≈ 2^{{{-1/epsilon:.3f} if epsilon > 0 else '∞'}})")
    print(f"    Max |Walsh| : {max_w}  at (α=0x{max_a:02X}, β=0x{max_b:02X})")
    print(f"    Coordinate NL per output bit (single-bit beta masks):")
    # coord_nls is indexed by output bit 0..7 (beta = 1<<bit), length 8
    # We compute coord NL only for the 8 single-bit masks for the readable summary;
    # the vectorial minimum is computed over all 255 beta values above.
    for bit in range(8):
        b_mask = 1 << bit
        # Recompute single-bit WHT for clean display
        f = [bin(b_mask & sbox[x]).count('1') & 1 for x in range(256)]
        wht = f[:]
        step = 1
        while step < 256:
            for ii in range(0, 256, step * 2):
                for jj in range(step):
                    u = wht[ii + jj]; v = wht[ii + jj + step]
                    wht[ii + jj] = u + v; wht[ii + jj + step] = u - v
            step *= 2
        lm = max(abs(w) for w in wht)
        cnl = 128 - lm // 2
        print(f"      y_{bit} (beta=0x{b_mask:02X}) : NL={cnl}  max|W|={lm}")
    print(f"    Vectorial NL (min over all 255 beta) = {nl}")
    print(f"    {grade(nl, 100, 112, 96, 100, lower_is_better=False)}")
    print(f"    Reference: AES=112, target>=100")

    # ── Algebraic Degree ──────────────────────────────────────────────────────
    print("\n[4] ALGEBRAIC DEGREE (via Möbius/ANF Transform)")
    print("    Computing ANF for all 8 coordinate functions...", end="", flush=True)
    t0 = time.time()
    degrees = compute_algebraic_degrees(sbox)
    t1 = time.time()
    print(f" done ({t1-t0:.2f}s)")

    min_deg = min(degrees)
    for k, d in enumerate(degrees):
        mark = "✅" if d == 7 else "⚠️"
        print(f"    {mark} y_{k} : deg = {d}")
    if min_deg == 7:
        print(f"    ✅ ALL 8 COORDINATE FUNCTIONS ACHIEVE MAXIMUM DEGREE 7")
    else:
        print(f"    ⚠️  Minimum coordinate degree = {min_deg}  (target = 7)")

    # ── SAC ───────────────────────────────────────────────────────────────────
    print("\n[5] STRICT AVALANCHE CRITERION (SAC)")
    mean_sac, std_sac, probs = compute_sac(sbox)
    dev = abs(mean_sac - 0.5)
    print(f"    Mean bit-flip probability : {mean_sac:.6f}  (ideal = 0.5000)")
    print(f"    Deviation from 0.5        : {dev:.6f}  (current N_bio ≈ 0.0005)")
    print(f"    Std deviation             : {std_sac:.6f}")
    print(f"    SAC Matrix (in_bit rows, out_bit cols):")
    print("      " + "  ".join(f"y{j}" for j in range(8)))
    for i in range(8):
        row_str = "  ".join(f"{probs[i][j]:.3f}" for j in range(8))
        mark = "✅" if all(abs(probs[i][j] - 0.5) < 0.05 for j in range(8)) else "⚠️"
        print(f"    x{i}: {row_str}  {mark}")

    # ── BIC ───────────────────────────────────────────────────────────────────
    print("\n[6] BIT INDEPENDENCE CRITERION (BIC)")
    print("    Computing pairwise output bit correlations...", end="", flush=True)
    t0 = time.time()
    mean_bic = compute_bic(sbox)
    t1 = time.time()
    print(f" done ({t1-t0:.2f}s)")
    print(f"    Mean |Pearson ρ| : {mean_bic:.5f}  (current N_bio ≈ 0.035, theoretical noise ≈ 0.035)")
    if mean_bic < 0.05:
        print(f"    ✅ BIC SATISFIED")
    else:
        print(f"    ⚠️  BIC may be weak — correlation > 0.05")

    # ── Fixed Points ──────────────────────────────────────────────────────────
    print("\n[7] FIXED POINTS & OPPOSITE FIXED POINTS")
    fps  = find_fixed_points(sbox)
    ofps = find_opp_fixed_points(sbox)
    print(f"    Fixed Points (S(x)=x)        : {len(fps)}  {fps}")
    print(f"    Opp. Fixed Points (S(x)=x^FF): {len(ofps)}  {ofps}")
    if len(fps) == 0 and len(ofps) == 0:
        print(f"    ✅ ZERO FIXED & OPPOSITE FIXED POINTS")
    elif len(fps) <= 2:
        print(f"    ⚠️  {len(fps)} isolated fixed points (broken by round constants in practice)")
    else:
        print(f"    ❌ {len(fps)} fixed points — structurally significant")

    # ── Cycles ────────────────────────────────────────────────────────────────
    print("\n[8] CYCLE DECOMPOSITION")
    cycles = cycle_decomposition(sbox)
    print(f"    Number of cycles : {len(cycles)}")
    print(f"    Cycle lengths    : {cycles}")
    max_cycle = max(cycles)
    print(f"    Dominant cycle   : {max_cycle}  (current N_bio = 109)")
    if max_cycle >= 100:
        print(f"    ✅ High orbit complexity")
    else:
        print(f"    ⚠️  Dominant cycle < 100 — may indicate structure")

    # ── Inverse ───────────────────────────────────────────────────────────────
    print("\n[9] INVERSE S-BOX VERIFICATION")
    inv = build_inverse(sbox)
    ok_inv = verify_inverse(sbox, inv)
    if ok_inv:
        print(f"    ✅ N_bio^(-1)(N_bio(x)) = x  for all 256 values")
    else:
        print(f"    ❌ Inverse verification FAILED")

    # ── Print S-Box ───────────────────────────────────────────────────────────
    print_sbox_table(sbox)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("  CRYPTANALYTIC VERDICT SUMMARY")
    print("=" * 72)
    verdict_rows = [
        ("Bijectivity",          "PASS" if ok else "FAIL", "Required"),
        ("δ_max",                str(d_max),                f"Target ≤8, AES=4"),
        ("NL",                   str(nl),                   f"Target ≥100, AES=112"),
        ("Algebraic Degree",     str(min_deg),              f"Target=7 (all bits)"),
        ("Fixed Points",         str(len(fps)),             f"Target=0"),
        ("Opp. Fixed Points",    str(len(ofps)),            f"Target=0"),
        ("SAC Deviation",        f"{dev:.5f}",              f"Target<0.002"),
        ("BIC Mean |ρ|",         f"{mean_bic:.5f}",         f"Target<0.05"),
    ]
    print(f"  {'Metric':<22} {'Value':<12} {'Context'}")
    print(f"  {'-'*22} {'-'*12} {'-'*30}")
    for m, v, ctx in verdict_rows:
        print(f"  {m:<22} {v:<12} {ctx}")

    # Overall verdict
    passed = (ok and d_max <= 8 and nl >= 100 and min_deg == 7 and len(fps) == 0 and len(ofps) == 0)
    print()
    if passed:
        print("  ✅✅✅  ALL TARGETS MET — CANDIDATE APPROVED FOR H-512 INTEGRATION")
    else:
        issues = []
        if not ok:              issues.append("not bijective")
        if d_max > 8:           issues.append(f"δ_max={d_max} > 8")
        if nl < 100:            issues.append(f"NL={nl} < 100")
        if min_deg < 7:         issues.append(f"min degree={min_deg} < 7")
        if len(fps) > 0:        issues.append(f"{len(fps)} fixed points")
        if len(ofps) > 0:       issues.append(f"{len(ofps)} opposite fixed points")
        print(f"  ⚠️   TARGETS NOT FULLY MET: {', '.join(issues)}")
        print(f"      Continuing search is recommended.")

    return {
        "bijective": ok,
        "delta_max": d_max,
        "NL": nl,
        "min_degree": min_deg,
        "fixed_points": len(fps),
        "opp_fixed_points": len(ofps),
        "SAC_deviation": dev,
        "BIC_mean_corr": mean_bic,
        "cycles": cycles,
        "approved": passed,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main Entry
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="H-512 S-Box Full Cryptanalytic Verifier")
    parser.add_argument("--sbox", default="current",
                        help="'current' to verify existing N_bio, or path to hex file")
    args = parser.parse_args()

    if args.sbox == "current":
        sbox = CURRENT_SBOX
        label = "Current N_bio (Mini-Feistel 8-Round)"
    else:
        # Load from hex file: space/newline separated hex bytes
        with open(args.sbox) as f:
            raw = f.read().split()
        sbox = [int(v, 16) for v in raw]
        label = f"Candidate from {args.sbox}"

    run_full_analysis(sbox, label=label)

if __name__ == "__main__":
    main()
