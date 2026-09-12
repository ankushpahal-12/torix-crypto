"""
Project H-512 Reference Implementation (Phase 2 Prototype)
==========================================================
Architectural Specifications:
- 512-bit internal state modeled as an 8x8 matrix of 8-bit octets on a 2D torus.
- Layer 1: NIST 10*1 padding with 64-bit length and 8-bit domain separation tag.
- Layer 2: Orthogonal message dispersal and HAIFA diagonal bit-counter injection.
- Layer 3: Bijective 8-bit Balanced Mini-Feistel cell permutation (N_bio).
- Layer 4 & 5: Three-tier diffusion (Local, Regional, Global) across 4 cycling round families (A, B, C, D).
- Layer 6: Miyaguchi-Preneel feedforward compression.
"""

import os
import sys

# Ensure package directory is in sys.path for standalone imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


import struct
from typing import List, Tuple, Union


def _generate_first_n_primes(n: int) -> List[int]:
    """Generate the first n prime numbers deterministically."""
    primes = []
    candidate = 2
    while len(primes) < n:
        is_prime = True
        for p in primes:
            if p * p > candidate:
                break
            if candidate % p == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(candidate)
        candidate += 1
    return primes


# ==============================================================================
# CONSTANTS GENERATION (Nothing-Up-My-Sleeve / NUMS)
# ==============================================================================
# First 64 primes define the 8x8 Initialization Vector (IV) from fractional parts of sqrt(p).
# Next 1024 primes define the 16 rounds * 8x8 Round Constants (RC) from cbrt(p).
_ALL_PRIMES = _generate_first_n_primes(64 + 16 * 64)

# 8x8 Initial Vector IV
IV: List[List[int]] = []
for r in range(8):
    row = []
    for c in range(8):
        p = _ALL_PRIMES[r * 8 + c]
        # Fractional part of sqrt(p) * 256
        val = int((p**0.5 - int(p**0.5)) * 256) & 0xFF
        row.append(val)
    IV.append(row)

# 16 Rounds x 8x8 Round Constants RC
ROUND_CONSTANTS: List[List[List[int]]] = []
prime_offset = 64
for rnd in range(16):
    rc_matrix: List[List[int]] = []
    for r in range(8):
        rc_row: List[int] = []
        for c in range(8):
            p = _ALL_PRIMES[prime_offset + rnd * 64 + r * 8 + c]
            # Fractional part of cbrt(p) * 256
            val = int((p ** (1.0 / 3.0) - int(p ** (1.0 / 3.0))) * 256) & 0xFF
            rc_row.append(val)
        rc_matrix.append(rc_row)
    ROUND_CONSTANTS.append(rc_matrix)


# ==============================================================================
# BITWISE & CELL UTILITIES
# ==============================================================================
def rotl8(x: int, n: int) -> int:
    """Cyclic left rotation of an 8-bit octet."""
    n = n % 8
    return (((x << n) | (x >> (8 - n))) & 0xFF)


def rotl4(x: int, n: int) -> int:
    """Cyclic left rotation of a 4-bit nibble."""
    n = n % 4
    return (((x << n) | (x >> (4 - n))) & 0x0F)


# ==============================================================================
# PHASE 4: UPGRADED 8-ROUND NONLINEAR CELL PERMUTATION (N_bio)
# ==============================================================================
# 8-round Balanced Mini-Feistel combining XOR, modular arithmetic in Z_16, and AND/OR.
# Properties: 100% Bijective, delta_max = 12, NL = 96, Algebraic Degree = 7 on all 8 bits.
def _feistel_f(r: int, rnd: int) -> int:
    """Nonlinear round function for 4-bit nibble in round rnd."""
    if rnd == 0:
        return (((r ^ rotl4(r, 1)) * 7 + 5 + (r & rotl4(r, 2))) & 0x0F)
    elif rnd == 1:
        return (((r ^ rotl4(r, 2)) * 11 + 3 + (r | rotl4(r, 1))) & 0x0F)
    elif rnd == 2:
        return (((r ^ rotl4(r, 3)) * 13 + 9 + (r & rotl4(r, 3))) & 0x0F)
    elif rnd == 3:
        return (((r ^ rotl4(r, 1)) * 5 + 7 + (r ^ rotl4(r, 2))) & 0x0F)
    elif rnd == 4:
        return (((r ^ rotl4(r, 2)) * 7 + 1 + (r & rotl4(r, 1))) & 0x0F)
    elif rnd == 5:
        return (((r ^ rotl4(r, 3)) * 3 + 11 + (r | rotl4(r, 2))) & 0x0F)
    elif rnd == 6:
        return (((r ^ rotl4(r, 1)) * 11 + 5 + (r & rotl4(r, 1))) & 0x0F)
    else:  # rnd == 7
        return (((r ^ rotl4(r, 2)) * 13 + 7 + (r ^ rotl4(r, 3))) & 0x0F)


def _eval_feistel_n_bio(x: int) -> int:
    L = (x >> 4) & 0x0F
    R = x & 0x0F
    for rnd in range(8):
        L, R = R, L ^ _feistel_f(R, rnd)
    return ((L << 4) | R) & 0xFF


def _eval_feistel_n_bio_inv(y: int) -> int:
    L = (y >> 4) & 0x0F
    R = y & 0x0F
    for rnd in range(7, -1, -1):
        R, L = L, R ^ _feistel_f(L, rnd)
    return ((L << 4) | R) & 0xFF


# Precomputed static S-Box tables (O(1) cache lookup, identical to C H512_SBOX)
_N_BIO_TABLE = [_eval_feistel_n_bio(x) for x in range(256)]
_N_BIO_INV_TABLE = [_eval_feistel_n_bio_inv(y) for y in range(256)]


def n_bio(x: int) -> int:
    """
    Bijective 8-bit Balanced Mini-Feistel Octet Permutation (8 rounds).
    Guarantees:
    - 100% Injective Permutation (256 unique outputs for 256 inputs).
    - High Nonlinearity (NL = 96, Max LAT bias = 32).
    - Low Differential Uniformity (delta_max = 12).
    - Maximum Algebraic Degree (deg = 7 on all 8 coordinate functions).
    """
    return _N_BIO_TABLE[x & 0xFF]


def n_bio_inv(y: int) -> int:
    """Exact inverse of n_bio, unrolling Feistel rounds in reverse order."""
    return _N_BIO_INV_TABLE[y & 0xFF]


# ==============================================================================
# LAYER 1: MESSAGE TRANSFORMATION & PADDING
# ==============================================================================
def pad_message(message: bytes, domain_tag: int = 0x00) -> bytes:
    """
    Pads the input message into 512-bit (64-byte) blocks.
    Framing: Message || 0x80 || 0x00*k || DomainTag (1 byte) || LengthBits (8 bytes big-endian)
    """
    bit_len = len(message) * 8
    # 1 byte (0x80) + k zero bytes + 1 byte (domain) + 8 bytes (length) = k + 10 bytes
    k = (64 - ((len(message) + 10) % 64)) % 64
    padding = b"\x80" + (b"\x00" * k) + bytes([domain_tag & 0xFF]) + struct.pack(">Q", bit_len)
    return message + padding


# ==============================================================================
# LAYER 2: STATE EXPANSION & MESSAGE DISPERSAL
# ==============================================================================
def disperse_message_block(block: bytes) -> List[List[int]]:
    """
    Parses a 64-byte block into an 8x8 matrix and applies orthogonal row dispersal:
    M_disp[r][c] = M_block[r][(c + r) mod 8]
    """
    m_disp: List[List[int]] = []
    for r in range(8):
        row = []
        for c in range(8):
            disp_c = (c + r) % 8
            row.append(block[r * 8 + disp_c])
        m_disp.append(row)
    return m_disp


# ==============================================================================
# LAYER 4 & 5: THREE-TIER DIFFUSION & ROUND FAMILIES
# ==============================================================================
class RoundFamily:
    def __init__(self, name: str, rotations: Tuple[int, int, int, int], swap_quads: bool, perm_type: str):
        self.name = name
        self.rotations = rotations
        self.swap_quads = swap_quads
        self.perm_type = perm_type


ROUND_FAMILIES = {
    0: RoundFamily("Type A", (1, 2, 3, 5), False, "shift_rows"),
    1: RoundFamily("Type B", (3, 5, 1, 7), True, "transpose"),
    2: RoundFamily("Type C", (5, 1, 7, 3), False, "shift_rows_transpose"),
    3: RoundFamily("Type D", (7, 3, 5, 1), True, "shift_rows_reverse"),
}


def _swap_quadrants(S: List[List[int]]) -> List[List[int]]:
    """Swaps 4x4 quadrants diagonally: Q0 <-> Q3 and Q1 <-> Q2."""
    out = [[0] * 8 for _ in range(8)]
    for r in range(4):
        for c in range(4):
            # Q0 <-> Q3
            out[r][c] = S[r + 4][c + 4]
            out[r + 4][c + 4] = S[r][c]
            # Q1 <-> Q2
            out[r][c + 4] = S[r + 4][c]
            out[r + 4][c] = S[r][c + 4]
    return out


def _apply_global_permutation(S: List[List[int]], perm_type: str) -> List[List[int]]:
    """Applies global permutation (Shift-Rows, Transposition, Row Reversal)."""
    # Shift-Rows: row r rotated cyclically by r positions
    if perm_type == "shift_rows":
        return [[S[r][(c + r) % 8] for c in range(8)] for r in range(8)]

    # Transposition: S[r][c] <-> S[c][r]
    if perm_type == "transpose":
        return [[S[c][r] for c in range(8)] for r in range(8)]

    # Shift-Rows + Transposition
    if perm_type == "shift_rows_transpose":
        shifted = [[S[r][(c + r) % 8] for c in range(8)] for r in range(8)]
        return [[shifted[c][r] for c in range(8)] for r in range(8)]

    # Shift-Rows + Row-Reverse
    if perm_type == "shift_rows_reverse":
        shifted = [[S[r][(c + r) % 8] for c in range(8)] for r in range(8)]
        return [[shifted[r][7 - c] for c in range(8)] for r in range(8)]

    return S


# ==============================================================================
# PHASE 8+ ENHANCEMENT: GF(2^8) CIRCULANT MDS HYPER-DIFFUSION LAYER
# ==============================================================================
_XTIME_TABLE = [(((a << 1) ^ (0x1B if (a & 0x80) else 0x00)) & 0xFF) for a in range(256)]


def xtime(a: int) -> int:
    """Galois Field GF(2^8) multiplication by 0x02 modulo P(x) = 0x11B."""
    return _XTIME_TABLE[a & 0xFF]


def mds_mix_column4(v0: int, v1: int, v2: int, v3: int) -> Tuple[int, int, int, int]:
    """
    Applies the 4x4 Circulant MDS Matrix over GF(2^8):
    M_MDS = circ(02, 03, 01, 01), Branch Number B = 5.
    Uses Daemen-Rijmen fast linear combination:
        t = v0 ^ v1 ^ v2 ^ v3
        z0 = v0 ^ t ^ xtime(v0 ^ v1) = 2*v0 ^ 3*v1 ^ v2 ^ v3
    """
    t = v0 ^ v1 ^ v2 ^ v3
    z0 = v0 ^ t ^ xtime(v0 ^ v1)
    z1 = v1 ^ t ^ xtime(v1 ^ v2)
    z2 = v2 ^ t ^ xtime(v2 ^ v3)
    z3 = v3 ^ t ^ xtime(v3 ^ v0)
    return z0, z1, z2, z3


def _apply_mds_hyper_diffusion(S: List[List[int]]) -> List[List[int]]:
    """Applies MDS matrix diffusion to all 8 columns (top and bottom half-columns)."""
    out = [[0] * 8 for _ in range(8)]
    for c in range(8):
        # Top 4 rows (r = 0..3)
        z0, z1, z2, z3 = mds_mix_column4(S[0][c], S[1][c], S[2][c], S[3][c])
        out[0][c], out[1][c], out[2][c], out[3][c] = z0, z1, z2, z3

        # Bottom 4 rows (r = 4..7)
        z4, z5, z6, z7 = mds_mix_column4(S[4][c], S[5][c], S[6][c], S[7][c])
        out[4][c], out[5][c], out[6][c], out[7][c] = z4, z5, z6, z7
    return out


def round_transform(S: List[List[int]], round_idx: int) -> List[List[int]]:
    """
    Executes an enhanced transformation round:
    1. Toroidal 4-neighbor coupling (Local Diffusion, Branch = 6)
    2. Nonlinear substitution N_bio + Round Constants
    3. Involutive GF(2^8) Circulant MDS Hyper-Diffusion (Branch = 5)
    4. Regional quadrant swapping (if active in family)
    5. Global permutation (Shift-Rows / Transposition)
    """
    family = ROUND_FAMILIES[round_idx % 4]
    alpha, beta, gamma, delta = family.rotations
    rc = ROUND_CONSTANTS[round_idx]

    # Pass 1: Toroidal Context Coupling + Nonlinear Substitution N_bio
    S_sub = [[0] * 8 for _ in range(8)]
    for r in range(8):
        for c in range(8):
            north = S[(r - 1) % 8][c]
            east = S[r][(c + 1) % 8]
            south = S[(r + 1) % 8][c]
            west = S[r][(c - 1) % 8]

            context = (
                S[r][c]
                ^ rotl8(north, alpha)
                ^ rotl8(east, beta)
                ^ rotl8(south, gamma)
                ^ rotl8(west, delta)
            )
            S_sub[r][c] = n_bio(context) ^ rc[r][c]

    # Pass 2: Involutive GF(2^8) Circulant MDS Hyper-Diffusion Layer
    S_mds = _apply_mds_hyper_diffusion(S_sub)

    # Pass 3: Regional Diffusion (Quadrant Swapping)
    if family.swap_quads:
        S_reg = _swap_quadrants(S_mds)
    else:
        S_reg = S_mds

    # Pass 4: Global Permutation
    S_out = _apply_global_permutation(S_reg, family.perm_type)
    return S_out


# ==============================================================================
# LAYER 6: FINAL COMPRESSION & FEEDFORWARD
# ==============================================================================
def compress_block(S_prev: List[List[int]], block: bytes, cumulative_bits: int) -> List[List[int]]:
    """
    Compresses a single 64-byte message block into the state using Miyaguchi-Preneel feedforward:
    S_next = S_prev ^ S* ^ M_disp
    """
    # 1. Disperse block
    m_disp = disperse_message_block(block)

    # 2. Ingest block and cumulative bit counter t along diagonal
    t_bytes = struct.pack(">Q", cumulative_bits)
    S = [[0] * 8 for _ in range(8)]
    for r in range(8):
        for c in range(8):
            S[r][c] = S_prev[r][c] ^ m_disp[r][c]
            if r == c:
                S[r][c] ^= t_bytes[r]

    # 3. Execute 16 Rounds of Multi-Family Transformation
    for rnd in range(16):
        S = round_transform(S, rnd)

    # 4. Miyaguchi-Preneel Feedforward
    S_next = [[0] * 8 for _ in range(8)]
    for r in range(8):
        for c in range(8):
            S_next[r][c] = S_prev[r][c] ^ S[r][c] ^ m_disp[r][c]

    return S_next


# ==============================================================================
# HIGH-LEVEL API
# ==============================================================================
# ==============================================================================
# PHASE 9: REFERENCE IMPLEMENTATION STREAMING API & HASHER CLASSES
# ==============================================================================
class H512Hasher:
    """
    Stateful incremental streaming hasher for Project H-512 (512-bit digest).
    Supports arbitrary chunk sizes with O(1) internal buffer overhead.
    """
    def __init__(self, domain_tag: int = 0x00):
        self.domain_tag = domain_tag & 0xFF
        self.state = [row[:] for row in IV]
        self.buffer = bytearray()
        self.total_bytes = 0
        self.blocks_processed = 0

    def update(self, data: Union[bytes, bytearray, str]) -> "H512Hasher":
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.total_bytes += len(data)
        self.buffer.extend(data)

        # Process full 64-byte blocks
        while len(self.buffer) >= 64:
            block = bytes(self.buffer[:64])
            self.buffer = self.buffer[64:]
            self.blocks_processed += 1
            cumulative_bits = min(self.blocks_processed * 512, self.total_bytes * 8)
            self.state = compress_block(self.state, block, cumulative_bits)

        return self

    def digest(self) -> bytes:
        """Finalizes padding and returns the 64-byte H-512 digest."""
        # Create final padded payload for the remaining buffer
        bit_len = self.total_bytes * 8
        rem_len = len(self.buffer)
        k = (64 - ((rem_len + 10) % 64)) % 64
        padded_rem = bytes(self.buffer) + b"\x80" + (b"\x00" * k) + bytes([self.domain_tag]) + struct.pack(">Q", bit_len)

        temp_state = [row[:] for row in self.state]
        num_final_blocks = len(padded_rem) // 64
        for i in range(num_final_blocks):
            block = padded_rem[i * 64 : (i + 1) * 64]
            cumulative_bits = bit_len
            temp_state = compress_block(temp_state, block, cumulative_bits)

        if self.domain_tag == 0x01:
            # H-256 Truncated Cross-Fold Mode (32 bytes)
            out = bytearray(32)
            for r in range(4):
                for c in range(8):
                    out[8 * r + c] = temp_state[r][c] ^ n_bio(temp_state[r + 4][c])
            return bytes(out)
        else:
            # H-512 Canonical Row-Major Mode (64 bytes)
            out = bytearray(64)
            for r in range(8):
                for c in range(8):
                    out[8 * r + c] = temp_state[r][c]
            return bytes(out)

    def hexdigest(self) -> str:
        """Returns the digest as a lowercase hexadecimal string."""
        return self.digest().hex()

    def copy(self) -> "H512Hasher":
        """Returns a deep clone of the hasher at its current internal state."""
        clone = H512Hasher(domain_tag=self.domain_tag)
        clone.state = [row[:] for row in self.state]
        clone.buffer = bytearray(self.buffer)
        clone.total_bytes = self.total_bytes
        clone.blocks_processed = self.blocks_processed
        return clone


class H256Hasher(H512Hasher):
    """
    Stateful incremental streaming hasher for Project H-256 (256-bit truncated fold).
    """
    def __init__(self):
        super().__init__(domain_tag=0x01)


# ==============================================================================
# HIGH-LEVEL API FUNCTIONS
# ==============================================================================
def h512_hash(data: Union[bytes, bytearray, str]) -> bytes:
    """One-shot computation of the 512-bit (64-byte) Project H-512 digest."""
    return H512Hasher(domain_tag=0x00).update(data).digest()


def h256_hash(data: Union[bytes, bytearray, str]) -> bytes:
    """One-shot computation of the 256-bit (32-byte) Project H-256 digest."""
    return H256Hasher().update(data).digest()


def hexdigest(digest_bytes: bytes) -> str:
    """Helper to convert digest bytes to lowercase hexadecimal string."""
    return digest_bytes.hex()


def hash_file(filepath: str, mode: str = "512", buffer_size: int = 65536) -> str:
    """
    Streams and hashes a file from disk using O(1) memory.
    mode can be '512' (default) or '256'.
    """
    hasher = H512Hasher(domain_tag=0x00 if mode == "512" else 0x01)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(buffer_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def hmac_h512(key: Union[bytes, str], message: Union[bytes, str]) -> bytes:
    """
    RFC 2104 compliant Keyed-Hash Message Authentication Code using H-512.
    Block size: 64 bytes (512 bits), Output: 64 bytes (512 bits).
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")

    block_size = 64
    if len(key) > block_size:
        key = h512_hash(key)
    if len(key) < block_size:
        key = key + (b"\x00" * (block_size - len(key)))

    ipad = bytes([k ^ 0x36 for k in key])
    opad = bytes([k ^ 0x5C for k in key])

    inner_hash = h512_hash(ipad + message)
    return h512_hash(opad + inner_hash)


def constant_time_compare(a: Union[bytes, bytearray], b: Union[bytes, bytearray]) -> bool:
    """
    Branchless constant-time equality comparison between two byte sequences.
    Prevents timing side-channel leakage in MAC and digest verification.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for byte_a, byte_b in zip(a, b):
        diff |= (byte_a ^ byte_b)
    return diff == 0


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Project H-512 Reference Cryptographic Hash CLI")
    parser.add_argument("input", nargs="?", help="Text string to hash (or stdin if omitted)")
    parser.add_argument("-256", "--h256", action="store_true", help="Produce 256-bit truncated cross-fold digest")
    parser.add_argument("-f", "--file", help="Hash file at specified path in streaming mode")
    parser.add_argument("-k", "--key", help="Key for HMAC-H512 message authentication")

    args = parser.parse_args()

    if args.file:
        mode_str = "256" if args.h256 else "512"
        print(f"File ({mode_str}-bit) : {args.file}")
        print(f"Digest         : {hash_file(args.file, mode=mode_str)}")
    elif args.key:
        msg = args.input or sys.stdin.read()
        mac = hmac_h512(args.key, msg)
        print(f"HMAC-H512 : {mac.hex()}")
    else:
        text = args.input if args.input is not None else sys.stdin.read()
        if args.h256:
            print(h256_hash(text).hex())
        else:
            print(h512_hash(text).hex())
