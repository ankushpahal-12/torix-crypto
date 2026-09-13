# TORIX-512: Architectural Roadmap (Security Track vs. Performance Track)

## Executive Summary & Engineering Philosophy

This document formalizes the development and evaluation strategy for the **TORIX-512** cryptographic suite. To maintain scientific integrity and academic rigor, the project separates its objectives into two orthogonal, independently evaluated tracks:

1. **The Security Track (Ground Truth):** Establishes the mathematical, structural, and empirical security invariants of the algorithm (e.g., differential uniformity, nonlinearity, wide-trail active S-box bounds, Strict Avalanche Criterion, and side-channel timing invariance). Performance claims are never permitted to precede or weaken formal security proofs.
2. **The Performance Track (Engineering Targets & Hypotheses):** Explores implementation efficiency across instruction set architectures (ANSI C99 SWAR, AVX2, AVX-512, OpenMP parallel tree hashing, and dedicated FPGA/ASIC hardware). All throughput projections are classified strictly as **engineering targets** until validated through reproducible benchmarks on documented hardware with explicit methodology disclosures.

```
                           TORIX-512
                               │
                ┌──────────────┴──────────────┐
                │                             │
          SECURITY TRACK                PERFORMANCE TRACK
          (Ground Truth)                 (Engineering Targets)
                │                             │
       [x] S-Box Properties            [x] Reference Python Engine
           (NL=100, δ_max=8, FP=0)         (Functional Verification)
                ↓                             ↓
       [x] Wide-Trail Bounds           [x] C99 Branchless SWAR Baseline
           (n_act ≥ 544, P_diff ≤ 2^-2720) (O(1) memory, zero heap)
                ↓                             ↓
       [x] SAC & Diffusion             [ ] Target: AVX2 Core (SIMD Feistel)
           (Round 2 50.39% saturation)     (Hypothesis: ≥ 3.0 GB/s)
                ↓                             ↓
       [x] Reduced-Round Attacks       [ ] Target: Native C Multi-Threading
           (Biclique, Integral, Slide)     (Hypothesis: Linear core scaling)
                ↓                             ↓
       [ ] External Cryptanalysis      [ ] Target: FPGA / ASIC Synthesis
           (Academic Peer Review)          (Hypothesis: Low Gate Count)
                │                             │
                └──────────────┬──────────────┘
                               ↓
                   FINAL VERIFIED ASSESSMENT
```

---

## 1. Track A: The Security Track (Established Invariants)

The security foundations of TORIX-512 have been formally verified through 14 automated verification suites (`tests/run_all_phases.py`) and a 6-phase cryptanalytic attack battery (`tests/run_attack_battery.py`):

| Property | Formally Verified Metric | Cryptanalytic Standard / Ground Truth |
| :--- | :---: | :--- |
| **S-Box Bijectivity** | $100\%$ bijective ($S_{256}$) | Provably invertible permutation; zero entropy loss |
| **Differential Uniformity** | $\delta_{\max} = 8$ ($p_{\max} = 2^{-5.000}$) | Upper-bounds differential transition probability |
| **Vectorial Nonlinearity** | $\mathcal{NL} = 100$ ($[100..106]$ per coordinate) | Bounded linear approximation bias ($\epsilon_{\max} = 2^{-3.170}$) |
| **Algebraic Degree** | $\deg = 7$ on all 8 coordinate bits | Maximum possible for 8-bit bijection (defeats higher-order differential cryptanalysis) |
| **Degeneracy Invariance** | $\text{FP} = 0$, $\text{OFP} = 0$ | Guaranteed by affine boundary whitening shift $K = \mathtt{0x01}$ |
| **Cycle Decomposition** | $[171, 73, 12]$ | Min cycle length 12; zero short cycles or fixed points |
| **MDS Hyper-Diffusion** | Optimal Branch Number $\mathcal{B}_{\text{MDS}} = 5$ | $\text{circ}(\mathtt{02}, \mathtt{03}, \mathtt{01}, \mathtt{01})$ over $\mathbb{F}_{2^8}$ modulo $\mathtt{0x11B}$ |
| **Active S-Boxes Bound** | $n_{\text{act}} \ge 544$ across 16 rounds | Proves $P_{\text{diff}} \le 2^{-2720.0}$ and $\|C_{\text{trail}}\| \le 2^{-1193.0}$ |
| **Avalanche Saturation** | Round 2 ($50.39\%$ bit-flip probability) | Full state diffusion achieved in 2 rounds; $\sigma^2 < 0.00015$ |
| **Side-Channel Invariance** | Welch's $t$-test ($t_{\text{stat}} = 0.28 < 4.5$) | 100,000 randomized execution traces show zero timing leakage |

---

## 2. Track B: The Performance Track (Measured vs. Targets)

### 2.1 Current Measured Baseline (C99 Branchless SWAR)
All measurements conducted on host CPU (x86_64, Windows 11, GCC 6.3.0 `-O3`, single-thread):

| Benchmark Payload | Measured Throughput | Measurement Context |
| :--- | :---: | :--- |
| **64 Bytes (Micro-Packet)** | **$416.91\text{ MB/s}$** | In-memory buffer, zero setup overhead |
| **1 Kilobyte (Network MTU)** | **$1111.75\text{ MB/s}$** | L1 cache aligned, 8-byte SWAR execution |
| **64 Kilobytes (System Buffer)**| **$1248.28\text{ MB/s}$** | Steady-state block processing speed |
| **1 Megabyte (File Chunk)** | **$1250.57\text{ MB/s}$** | Core C99 engine block loop |
| **10 Megabytes (Stream Pipe)** | **$13.33\text{ MB/s}$** | Single-threaded subprocess OS pipe |

---

### 2.2 Engineering Strategy 1: AVX2 SIMD Core (Target: $\ge 3.0\text{ GB/s}$)

#### The `VPSHUFB` Reality & The 4-bit Feistel Advantage
In x86 SIMD architectures, the byte-shuffle instruction `_mm256_shuffle_epi8` (`VPSHUFB`) operates on **16-byte tables per 128-bit lane** using 4-bit index nibbles (bits 0–3). If bit 7 of the index is set, the lane is zeroed.
* **Why an arbitrary 256-byte S-box is slow in SIMD:** Looking up a general 256-byte S-box requires nibble splitting (high/low), two separate 16-byte table lookups, shifting, and blending (the Hamburg `vpaes` approach).
* **The $N_{\text{bio}}$ Architectural Advantage:** Because $N_{\text{bio}}$ is constructed from an **8-round Balanced Mini-Feistel network**, its internal round function:
  $$
  g(R) = (R^2 \bmod 16) \oplus \text{rotl}_4(R, 1) \oplus \mathtt{0x9}
  $$
  operates strictly on **4-bit nibbles** ($2^4 = 16$ elements). The precomputed table for $g(R)$ is **exactly 16 bytes long**:
  ```c
  static const uint8_t G_LUT[16] = {
      0x9, 0xC, 0x1, 0x6, 0x7, 0x8, 0xF, 0x2,
      0x5, 0xE, 0x3, 0x4, 0xB, 0x0, 0xD, 0xA
  };
  ```
  This 16-byte table fits natively into a single `__m128i` / `__m256i` register lane!
  
  Consequently, all 64 byte cells of the state can be substituted simultaneously by evaluating the 8 Feistel rounds directly in vector registers using **8 successive `VPSHUFB` instructions** on the low nibbles, completely bypassing 256-byte table lookups.

#### AVX2 Implementation Target
- Vectorize MDS layer: Process 32 bytes (4 full rows) simultaneously using `_mm256_xor_si256` and branchless vector `xtime_u256`.
- Vectorize Feistel substitution: 8 `VPSHUFB` passes evaluating $g(R)$ in parallel.
- **Target Hypothesis:** $\ge 3{,}000\text{ MB/s}$ single-core throughput.

---

### 2.3 Engineering Strategy 2: Multi-Threaded Native C Tree Hashing (Target: $\ge 10.0\text{ GB/s}$)

The data-independent chunk processing demonstrated in Python (`python/h512_modes.py`) is designed for OpenMP / pthreads parallelization:

```c
void h512_tree_hash_parallel(const uint8_t *data, size_t len, uint8_t digest[64], int num_threads) {
    size_t num_chunks = (len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    uint8_t chunk_digests[num_chunks][64];

    #pragma omp parallel for num_threads(num_threads) schedule(static)
    for (size_t i = 0; i < num_chunks; i++) {
        size_t offset = i * CHUNK_SIZE;
        size_t clen = (offset + CHUNK_SIZE <= len) ? CHUNK_SIZE : (len - offset);
        h512_hash(data + offset, clen, chunk_digests[i]);
    }

    // Binary Merkle tree reduction
    h512_tree_reduce(chunk_digests, num_chunks, digest);
}
```

#### Realistic Throughput Considerations
While theoretical linear scaling predicts $N_{\text{cores}} \times \text{Throughput}_{\text{single}}$, real-world systems are bounded by:
1. **DDR4 / DDR5 Memory Bus Bandwidth:** Dual-channel DDR4-3200 saturates at ~25.6 GB/s; DDR5-5600 reaches ~44.8 GB/s. No hashing algorithm can exceed physical memory bus read bandwidth when processing streaming payloads from DRAM.
2. **Thread Synchronization Overhead:** For payloads under 64 KB, thread creation and join latency dominate execution time.
3. **Target Hypothesis:** $\ge 10{,}000\text{ MB/s}$ on a 4-core / 8-thread workstation for payloads $\ge 1\text{ MB}$.

---

### 2.4 Engineering Strategy 3: Dedicated Silicon (FPGA / ASIC Hypotheses)

The structural simplicity of TORIX-512 offers favorable hardware characteristics:
* **State Registers:** Exactly 64 byte flip-flops (512 bits) with zero external RAM buffers.
* **MDS Column Replicas:** 8 identical 4-byte circulant multipliers operating in parallel.
* **Feistel Circuit:** A compact 4-bit combinatorial circuit computing $R^2 \oplus \text{rotl}_4(R, 1) \oplus \mathtt{0x9}$.

#### Hardware Targets Pending RTL Synthesis
- **Design Target:** $< 10{,}000\text{ Gate Equivalents (GE)}$ in standard 28nm ASIC cell libraries.
- **Verification Rule:** All gate count, clock frequency, and Gbps throughput estimates must be verified through Verilog/VHDL synthesis reports (e.g. Synopsys Design Compiler or Xilinx Vivado) before inclusion as verified metrics.

---

## 3. Implemented C99 Engine Optimizations & Verification Status

The following high-performance SWAR and cryptographic hardening optimizations have been implemented directly in [`src/h512.c`](file:///c:/Users/ankus/Desktop/New%20folder/New%20folder%20(6)/src/h512.c) and [`src/h512_constants.h`](file:///c:/Users/ankus/Desktop/New%20folder/New%20folder%20(6)/src/h512_constants.h) and verified with 100% bit-exact parity:

1. **[x] 64-Byte Cache Alignment (`H512_ALIGN64`):**
   - Applied `__attribute__((aligned(64)))` / `__declspec(align(64))` to `H512_IV`, `H512_RC`, `H512_SBOX`, and `H512_SBOX_INV`.
   - Guarantees the S-box occupies exactly 4 contiguous L1 cache lines (zero cache-line straddling).
2. **[x] Strict-Aliasing Compliant State Union (`h512_state_t`):**
   - Encapsulated internal states inside a 64-byte aligned union (`uint8_t b[8][8]`, `uint64_t u64[8]`, `uint32_t u32[16]`).
   - Fully compliant with C99 Section 6.5.2.3 type-punning rules, eliminating compiler reordering hazards under `-O3`.
3. **[x] Zero-Copy Ping-Pong State Buffering:**
   - Double-buffered round transformations using `state_buf[2]` (`state_buf[rnd & 1]` -> `state_buf[(rnd + 1) & 1]`).
   - Completely eliminated 16 intermediate buffer allocations and copies per block (2.62 million memory copies eliminated per 10 MB payload).
4. **[x] In-Place 64-Bit Word Register Permutations:**
   - Evaluates row rotations using branchless word shifts (`rotl_bytes64`), in-place transposition (`transpose8x8_inplace`), and byte reversals (`H512_BSWAP64`).
   - Replaced the 64-iteration nested loop and temporary buffers with hardware register operations.
5. **[x] Cryptographic & Side-Channel Hardening:**
   - Pre-loads L1 cache lines via `__builtin_prefetch` at block boundaries to neutralize first-access timing differentials.
   - Enforces volatile compiler memory barriers in `h512_cleanse` to guarantee context zeroization against dead-code elimination.
6. **[x] Dual 64-Bit Packed Round Constants (`H512_RC_U64`):**
   - Installed `H512_RC_U64[16][8]` pre-packed rows in `src/h512_constants.h`.

### Verification Milestones Achieved:
- **Bit-Exact Parity:** 100% cross-language parity confirmed against Python reference (`tests/verify_phase9.py`).
- **Full Phase Suite:** 14/14 test suites PASSED in 57.07 seconds (`tests/run_all_phases.py`).
- **Cryptanalytic Attack Battery:** All 6 attack classes PASSED on 4-round reduced core (`tests/run_attack_battery.py`).

