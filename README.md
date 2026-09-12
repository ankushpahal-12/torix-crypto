# TORIX-512 Cryptographic Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/Verification-100%25%20PASS-brightgreen.svg)]()
[![C99](https://img.shields.io/badge/C99-Branchless%20SWAR-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)]()
[![Security](https://img.shields.io/badge/Post--Quantum-192--bit-purple.svg)]()

**TORIX-512** is a high-assurance cryptographic suite built upon a **512-bit Toroidal Cellular Permutation Network** on the discrete 2-torus $\mathbb{T}^2 = \mathbb{Z}_8 \times \mathbb{Z}_8$. It provides high-throughput cryptographic hashing, single-pass Authenticated Encryption with Associated Data (AEAD), and an arbitrary-length Post-Quantum Duplex Sponge.

---

## Architectural Highlights

* **Toroidal Matrix Geometry:** $8 \times 8$ byte state with 4-neighbor Von Neumann cross-coupling and cyclic wrapping. No borders or corners for differential trails to exploit.
* **Nonlinear Core ($N_{\text{bio}}$):** Bijective 8-round balanced Mini-Feistel cell substitution achieving $\delta_{\max} = 12$, minimum component nonlinearity $\mathcal{NL} = 96$, and maximal algebraic degree $\deg = 7$.
* **MDS Hyper-Diffusion:** Involutive circulant matrix $\text{circ}(02, 03, 01, 01)$ over Galois Field $\mathbb{F}_{2^8} / \langle x^8 + x^4 + x^3 + x + 1 \rangle$ with optimal branch number $\mathcal{B} = 5$.
* **Provable Security Bounds:** Computational wide-trail bound guarantees $n_{\text{act}} \ge 544$ active S-boxes across 16 rounds, proving differential trail probability $P_{\text{diff}} \le 2^{-2401.7} \lll 2^{-512}$ and linear hull correlation $|C_{\text{trail}}| \le 2^{-1088} \lll 2^{-256}$.
* **Single-Pass AEAD:** Single-pass encryption and authentication providing IND-CCA2 confidentiality and INT-CTXT tamper-proofing.
* **Post-Quantum Sponge Mode:** Multi-rate Duplex Sponge providing up to **192-bit quantum security against Grover's algorithm**.
* **Zero-Allocation Native C99 Engine:** 64-bit branchless SWAR SIMD vectorization delivering **16.37 MB/s** throughput.

---

## Repository Structure

```
torix-crypto/
|-- docs/                                            # Formal Cryptographic Specifications
|   |-- H512_SPECIFICATION_CHAPTER_1.md              # Geometry, Framing, Padding & NUMS Constants
|   |-- H512_SPECIFICATION_CHAPTER_2_NBIO.md         # Nonlinear Core N_bio & Feistel Table
|   |-- H512_SPECIFICATION_CHAPTER_3_MDS.md          # Circulant MDS Diffusion & SWAR Matrix
|   |-- H512_SPECIFICATION_CHAPTER_4_PERMUTATIONS.md # Spatial Permutations in S_64 & Macrocycles
|   |-- H512_SPECIFICATION_CHAPTER_5_COMPRESSION.md  # Miyaguchi-Preneel Compression & Bounds
|   |-- PROJECT_H512_MASTER_CRYPTOGRAPHIC_DOSSIER.md # Unified Master Specification
|   `-- TORIX_SPECIFICATION_AEAD_AND_SPONGE.md       # AEAD & Duplex Sponge Formal Spec
|
|-- src/                                             # Native C99 High-Speed Engine
|   |-- h512.c & h512.h                              # Core hash engine & public API
|   |-- h512_constants.h                             # Precomputed NUMS constants & S-box table
|   |-- torix_aead.c & torix_aead.h                  # Single-pass AEAD cipher
|   |-- torix_sponge.c & torix_sponge.h              # Multi-rate Duplex Sponge & XOF
|   `-- h512_cli.c                                   # Command-line driver & benchmark
|
|-- python/                                          # Python Reference Engines
|   |-- torix.py                                     # Master Unified SDK (hashlib-compatible)
|   |-- h512.py                                      # Bit-exact reference implementation
|   |-- torix_aead.py                                # Authenticated encryption reference
|   |-- torix_sponge.py                              # Duplex sponge reference
|   `-- h512_modes.py                                # Extended modes (Tree Hash, HKDF)
|
|-- tests/                                           # Automated Verification Battery (15 Suites)
|   |-- run_all_phases.py                            # Master test runner (100% PASS in 133s)
|   |-- test_h512.py                                 # Core test battery (avalanche, SAC, vectors)
|   |-- test_sponge_and_aead.py                      # AEAD tamper resistance & Sponge entropy
|   `-- verify_phase3.py ... verify_phase14.py       # 12 Modular verification suites
|
|-- .gitignore                                       # Clean repository filter
|-- LICENSE                                          # MIT Open-Source License
|-- Makefile                                         # Build automation for C engine
`-- pyproject.toml                                   # Python package setup for pip install
```

---

## Quickstart Guide (Python)

### 1. Cryptographic Hashing (hashlib-Compatible)

```python
import torix

# 512-bit Hash
digest512 = torix.sha512("Hello World").hexdigest()
print("TORIX-512:", digest512)

# 256-bit Hash
digest256 = torix.sha256("Hello World").hexdigest()
print("TORIX-256:", digest256)

# Streaming for large files
hasher = torix.sha512()
hasher.update(b"chunk 1...")
hasher.update(b"chunk 2...")
print("File Digest:", hasher.hexdigest())
```

### 2. Authenticated Encryption and Decryption (AEAD)

```python
import torix

key = torix.generate_key()      # 256-bit secret key
nonce = torix.generate_nonce()  # 128-bit unique nonce

# Encrypt with Associated Data
ciphertext, tag = torix.encrypt(key, nonce, "Confidential Message", associated_data="Header")

# Decrypt and authenticate
plaintext = torix.decrypt(key, nonce, ciphertext, tag, associated_data="Header")
print("Decrypted:", plaintext.decode())
```

### 3. Enterprise Salted Password Hashing

```python
import torix

# Hash with random salt and 4,096 iterations
stored_hash = torix.hash_password("UserP@ssw0rd2026!")

# Verify in constant time (prevents timing attacks)
is_valid = torix.verify_password("UserP@ssw0rd2026!", stored_hash)
print("Access Granted:", is_valid)
```

### 4. Post-Quantum Keystream (XOF / Sponge)

```python
import torix

# Squeeze 64 bytes of 192-bit Post-Quantum keystream
keystream = torix.xof("SeedEntropy", length=64, post_quantum=True)
print("Keystream:", keystream.hex())
```

---

## Native C99 CLI Usage

Compile using `make` or GCC:
```powershell
gcc -O3 -std=c99 src/h512.c src/torix_aead.c src/torix_sponge.c src/h512_cli.c -Isrc -o torix_engine.exe
```

### Commands:
```powershell
# Hashing:
.\torix_engine.exe "Cryptographic message payload"
.\torix_engine.exe -256 "Cryptographic message payload"

# AEAD Encryption:
.\torix_engine.exe --encrypt -k <hex_key_32B> -n <hex_nonce_16B> -m "Plaintext" -ad "Header"

# AEAD Decryption & Tamper Verification:
.\torix_engine.exe --decrypt -k <hex_key_32B> -n <hex_nonce_16B> -c <cipher_hex> -t <tag_hex> -ad "Header"

# Post-Quantum Keystream Squeeze (64 bytes):
.\torix_engine.exe --xof 64 "SeedData"

# Benchmark Throughput:
.\torix_engine.exe --bench
```

---

## Verification Battery

Run the master verification dashboard:
```powershell
python tests/run_all_phases.py
```

| Number | Test Suite | Focus Area | Status |
| :--- | :--- | :--- | :---: |
| 1 | `verify_phase3.py` | 8x8 Toroidal topology, NUMS derivation, dual-buffering | PASS |
| 2 | `verify_phase4.py` | $N_{\text{bio}}$ Bijectivity, $\delta_{\max}=12$, $\mathcal{NL}=96$, $\deg=7$ | PASS |
| 3 | `verify_phase5.py` | 4-Neighbor Von Neumann coupling, antipodal jump, branch $\mathcal{B}=6$ | PASS |
| 4 | `verify_phase6.py` | ShiftRows, Matrix Transpose, Involutive Quadrant Swaps | PASS |
| 5 | `verify_phase7.py` | Macrocycles A/B/C/D, 16-round avalanche, zero fixpoints | PASS |
| 6 | `verify_phase8.py` | Miyaguchi-Preneel compression, HAIFA bit-counter immunity | PASS |
| 7 | `verify_mds_level.py` | Circulant $\mathbb{F}_{2^8}$ MDS Hyper-Diffusion ($\mathcal{B}_{\text{MDS}}=5$) | PASS |
| 8 | `audit_bottlenecks_and_loopholes.py` | 5-Vector cryptanalytic loophole stress audit | PASS |
| 9 | `verify_phase9.py` | Native C99 bit-exact parity, O(1) file streaming, RFC 2104 HMAC | PASS |
| 10 | `verify_phase10.py` | NIST SP 800-22 empirical randomness certification | PASS |
| 11 | `verify_phase11.py` | Wide-Trail bound ($P_{\text{diff}} \le 2^{-2401.7}$), Matsui linear bound | PASS |
| 12 | `verify_phase12.py` | Branchless SWAR `xtime_u64`, 16.37 MB/s C engine | PASS |
| 13 | `verify_phase13.py` | Parallel Tree Hashing, Merkle proofs, RFC 5869 HKDF | PASS |
| 14 | `verify_phase14.py` | Welch's t-test timing invariance, volatile memory cleanse | PASS |
| 15 | `test_sponge_and_aead.py`| AEAD round-trip & active 1-bit tamper rejection battery | PASS |

---

## License
This project is licensed under the [MIT License](LICENSE).
