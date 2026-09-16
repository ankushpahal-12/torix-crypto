"""
TORIX-512 Frontier 3: Self-Healing Cryptographic Sponge with Reed-Solomon FEC in One Pass
========================================================================================
Implements single-pass erasure-tolerant streaming where Cauchy-MDS Reed-Solomon Forward
Error Correction (FEC) is integrated natively with the TORIX 512-bit duplex sponge.

Key Properties:
- Systematic (k, m) MDS Code over GF(2^8) (optimal singleton bound n = k + m).
- Any e <= m packet erasures (drops) in a frame are reconstructed instantly in memory.
- Cryptographic Authentication Tag: Sponge capacity continuously authenticates stream;
  verifies healed packets and catches adversarial tamper/corruption.
- Zero-Retransmission overhead for satellite links, UDP streaming, and lossy channels.
"""

from __future__ import annotations
import os
import sys
import time
from typing import List, Tuple, Dict, Any, Optional

# Ensure package directory is in sys.path
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

from torix_sponge import TorixSponge


# ==============================================================================
# 1. FINITE FIELD GF(2^8) ARITHMETIC PRIMITIVES (p(x) = x^8 + x^4 + x^3 + x + 1)
# ==============================================================================

class GF256:
    """
    Galois Field GF(2^8) with irreducible polynomial 0x11B (AES / TORIX compatible).
    Precomputes log and exp tables for fast O(1) multiplication, division, and inversion.
    """
    _EXP = [0] * 512
    _LOG = [0] * 256
    _INITIALIZED = False

    @classmethod
    def _init_tables(cls):
        if cls._INITIALIZED:
            return
        x = 1
        for i in range(255):
            cls._EXP[i] = x
            cls._LOG[x] = i
            # Multiply by generator 0x03
            # x * 3 = x ^ (x * 2)
            hi = x & 0x80
            x2 = ((x << 1) ^ (0x1B if hi else 0x00)) & 0xFF
            x = x2 ^ x
        for i in range(255, 512):
            cls._EXP[i] = cls._EXP[i - 255]
        cls._INITIALIZED = True

    @classmethod
    def add(cls, a: int, b: int) -> int:
        """Addition in GF(2^8) is bitwise XOR."""
        return (a ^ b) & 0xFF

    @classmethod
    def sub(cls, a: int, b: int) -> int:
        """Subtraction in GF(2^8) is identical to addition (characteristic 2)."""
        return (a ^ b) & 0xFF

    @classmethod
    def mul(cls, a: int, b: int) -> int:
        """Multiplication in GF(2^8) via log/exp lookup."""
        if not cls._INITIALIZED:
            cls._init_tables()
        if a == 0 or b == 0:
            return 0
        return cls._EXP[cls._LOG[a] + cls._LOG[b]]

    @classmethod
    def inv(cls, a: int) -> int:
        """Multiplicative inverse in GF(2^8). inv(a) * a = 1."""
        if not cls._INITIALIZED:
            cls._init_tables()
        if a == 0:
            raise ZeroDivisionError("Cannot invert 0 in GF(2^8)")
        return cls._EXP[255 - cls._LOG[a]]

    @classmethod
    def div(cls, a: int, b: int) -> int:
        """Division in GF(2^8): a / b = a * inv(b)."""
        if b == 0:
            raise ZeroDivisionError("Division by zero in GF(2^8)")
        if a == 0:
            return 0
        if not cls._INITIALIZED:
            cls._init_tables()
        log_res = cls._LOG[a] - cls._LOG[b]
        if log_res < 0:
            log_res += 255
        return cls._EXP[log_res]


GF256._init_tables()


# ==============================================================================
# 2. LINEAR ALGEBRA OVER GF(2^8) (GAUSSIAN ELIMINATION & CAUCHY MDS GENERATOR)
# ==============================================================================

def gf_matrix_invert(A: List[List[int]]) -> List[List[int]]:
    """
    Computes inverse of an n x n square matrix over GF(2^8) using Gauss-Jordan elimination.
    Raises ValueError if matrix is singular.
    """
    n = len(A)
    if any(len(row) != n for row in A):
        raise ValueError("Matrix must be square")

    # Augment A with identity matrix: [A | I]
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(A)]

    for col in range(n):
        # Find pivot in current column
        pivot_row = None
        for r in range(col, n):
            if aug[r][col] != 0:
                pivot_row = r
                break
        if pivot_row is None:
            raise ValueError("Matrix is singular over GF(2^8) - cannot invert")

        # Swap pivot row into place
        if pivot_row != col:
            aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

        # Scale pivot row so pivot element is 1
        pivot_val = aug[col][col]
        inv_pivot = GF256.inv(pivot_val)
        for c in range(2 * n):
            aug[col][c] = GF256.mul(aug[col][c], inv_pivot)

        # Eliminate other rows
        for r in range(n):
            if r != col and aug[r][col] != 0:
                factor = aug[r][col]
                for c in range(2 * n):
                    elim = GF256.mul(factor, aug[col][c])
                    aug[r][c] = GF256.sub(aug[r][c], elim)

    # Extract right half [I | A^-1]
    return [[aug[r][c + n] for c in range(n)] for r in range(n)]


def make_cauchy_generator_matrix(k: int, m: int) -> List[List[int]]:
    """
    Builds an (k + m) x k systematic Cauchy MDS Generator Matrix over GF(2^8).
    - Top k x k rows: Identity Matrix I_k (systematic data)
    - Bottom m x k rows: Cauchy Matrix C where C[j][i] = 1 / (X[j] ^ Y[i])
      Every submatrix of a Cauchy matrix is non-singular, guaranteeing optimal MDS erasure bounds!
    """
    if k + m > 256:
        raise ValueError(f"k + m ({k + m}) exceeds field size 256")

    # Choose disjoint evaluation sets: X = [0..m-1], Y = [m..m+k-1]
    X = [j for j in range(m)]
    Y = [m + i for i in range(k)]

    G: List[List[int]] = []
    # Systematic identity for data packets
    for i in range(k):
        row = [1 if j == i else 0 for j in range(k)]
        G.append(row)

    # Cauchy rows for parity packets
    for j in range(m):
        row = []
        for i in range(k):
            denom = GF256.add(X[j], Y[i])
            row.append(GF256.inv(denom))
        G.append(row)

    return G


# ==============================================================================
# 3. SELF-HEALING CRYPTOGRAPHIC SPONGE (ONE-PASS ENCODING & DECODING)
# ==============================================================================

class FECFrame:
    """
    Represents an encoded stream frame with k data packets, m parity packets,
    and a cryptographic TORIX-512 authentication tag.
    """
    def __init__(
        self,
        frame_id: int,
        k: int,
        m: int,
        packet_size: int,
        data_packets: List[bytes],
        parity_packets: List[bytes],
        auth_tag: bytes,
    ):
        self.frame_id = frame_id
        self.k = k
        self.m = m
        self.packet_size = packet_size
        self.data_packets = data_packets
        self.parity_packets = parity_packets
        self.auth_tag = auth_tag

    @property
    def total_packets(self) -> int:
        return self.k + self.m

    def get_packet(self, index: int) -> bytes:
        if index < self.k:
            return self.data_packets[index]
        elif index < self.total_packets:
            return self.parity_packets[index - self.k]
        else:
            raise IndexError(f"Packet index {index} out of bounds (n={self.total_packets})")


class FECRecoveryReport:
    """Structured report returned after decoding and repairing a packet stream."""
    def __init__(
        self,
        frame_id: int,
        status: str,
        lost_indices: List[int],
        recovered_indices: List[int],
        data_bytes: bytes,
        auth_verified: bool,
        elapsed_us: float,
        message: str,
    ):
        self.frame_id = frame_id
        self.status = status  # 'INTACT', 'HEALED_AND_VERIFIED', 'UNRECOVERABLE', 'CORRUPTED'
        self.lost_indices = lost_indices
        self.recovered_indices = recovered_indices
        self.data_bytes = data_bytes
        self.auth_verified = auth_verified
        self.elapsed_us = elapsed_us
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "status": self.status,
            "lost_indices": self.lost_indices,
            "recovered_indices": self.recovered_indices,
            "data_len": len(self.data_bytes),
            "auth_verified": self.auth_verified,
            "elapsed_us": round(self.elapsed_us, 2),
            "message": self.message,
        }


class TorixFEC:
    """
    Frontier 3 Engine: Single-Pass Self-Healing MDS Duplex Sponge.
    """

    def __init__(self, k: int = 4, m: int = 2, packet_size: int = 32):
        if k < 1 or m < 1:
            raise ValueError("k and m must be at least 1")
        if k + m > 256:
            raise ValueError("k + m must not exceed 256")
        self.k = k
        self.m = m
        self.packet_size = packet_size
        self.generator = make_cauchy_generator_matrix(k, m)

    def encode(self, data: bytes, frame_id: int = 0) -> FECFrame:
        """
        Single-Pass Dual Absorption:
        1. Slices data into k chunks of packet_size (padded with 0x00 if needed).
        2. Absorbs data chunks into TorixSponge state to form cryptographic hash.
        3. Generates m Cauchy-MDS parity packets across the k data packets.
        4. Squeezes 64-byte TORIX-512 authentication tag.
        """
        expected_len = self.k * self.packet_size
        padded_data = data.ljust(expected_len, b"\x00")[:expected_len]

        # Extract k data packets
        data_packets = [
            padded_data[i * self.packet_size : (i + 1) * self.packet_size]
            for i in range(self.k)
        ]

        # Squeeze cryptographic sponge tag over original data
        sponge = TorixSponge(rate_bytes=32, capacity_bytes=32, domain_tag=0x33)
        sponge.absorb(padded_data)
        auth_tag = sponge.squeeze(64)

        # Compute m parity packets via Cauchy generator rows
        parity_packets: List[bytes] = []
        for j in range(self.m):
            cauchy_row = self.generator[self.k + j]
            parity_buf = bytearray(self.packet_size)
            for byte_idx in range(self.packet_size):
                val = 0
                for i in range(self.k):
                    c_ji = cauchy_row[i]
                    d_ib = data_packets[i][byte_idx]
                    val = GF256.add(val, GF256.mul(c_ji, d_ib))
                parity_buf[byte_idx] = val
            parity_packets.append(bytes(parity_buf))

        return FECFrame(
            frame_id=frame_id,
            k=self.k,
            m=self.m,
            packet_size=self.packet_size,
            data_packets=data_packets,
            parity_packets=parity_packets,
            auth_tag=auth_tag,
        )

    def decode_and_heal(
        self,
        received_packets: Dict[int, bytes],
        auth_tag: bytes,
        frame_id: int = 0,
    ) -> FECRecoveryReport:
        """
        Receives dictionary of {packet_index: packet_bytes}.
        Packet indices: 0..(k-1) are data packets, k..(k+m-1) are parity packets.
        If up to m packets are missing, mathematically reconstructs them via
        Gaussian elimination over GF(2^8) without retransmission, then verifies
        the cryptographic sponge authentication tag.
        """
        t0 = time.perf_counter()
        total_n = self.k + self.m
        present_indices = sorted([idx for idx in received_packets if 0 <= idx < total_n])
        lost_indices = [idx for idx in range(total_n) if idx not in received_packets]

        # Check if too many packets lost
        if len(present_indices) < self.k:
            elapsed = (time.perf_counter() - t0) * 1e6
            return FECRecoveryReport(
                frame_id=frame_id,
                status="UNRECOVERABLE",
                lost_indices=lost_indices,
                recovered_indices=[],
                data_bytes=b"",
                auth_verified=False,
                elapsed_us=elapsed,
                message=f"Received {len(present_indices)} packets, but need at least k={self.k} to decode",
            )

        # Validate packet buffer lengths
        for idx in present_indices:
            if len(received_packets[idx]) != self.packet_size:
                elapsed = (time.perf_counter() - t0) * 1e6
                return FECRecoveryReport(
                    frame_id=frame_id,
                    status="CORRUPTED",
                    lost_indices=lost_indices,
                    recovered_indices=[],
                    data_bytes=b"",
                    auth_verified=False,
                    elapsed_us=elapsed,
                    message=f"Packet {idx} has invalid length {len(received_packets[idx])} (expected {self.packet_size})",
                )

        # Check if all data packets are already present (no repair needed)
        missing_data_indices = [i for i in range(self.k) if i not in received_packets]
        if not missing_data_indices:
            # Data intact! Concatenate and check auth
            data_bytes = b"".join(received_packets[i] for i in range(self.k))
            sponge = TorixSponge(rate_bytes=32, capacity_bytes=32, domain_tag=0x33)
            sponge.absorb(data_bytes)
            test_tag = sponge.squeeze(64)
            auth_ok = (test_tag == auth_tag)
            elapsed = (time.perf_counter() - t0) * 1e6
            return FECRecoveryReport(
                frame_id=frame_id,
                status="INTACT" if auth_ok else "CORRUPTED",
                lost_indices=lost_indices,
                recovered_indices=[],
                data_bytes=data_bytes,
                auth_verified=auth_ok,
                elapsed_us=elapsed,
                message="All systematic data packets present without erasures",
            )

        # REPAIR PATH: Select any k surviving packets to invert generator submatrix
        selected_indices = present_indices[: self.k]
        submatrix = [self.generator[idx][:] for idx in selected_indices]

        try:
            inv_submatrix = gf_matrix_invert(submatrix)
        except ValueError as exc:
            elapsed = (time.perf_counter() - t0) * 1e6
            return FECRecoveryReport(
                frame_id=frame_id,
                status="ERROR",
                lost_indices=lost_indices,
                recovered_indices=[],
                data_bytes=b"",
                auth_verified=False,
                elapsed_us=elapsed,
                message=f"Failed to invert surviving submatrix: {exc}",
            )

        # Reconstruct original k data packets: D = InvSubmatrix * Y
        # For each data packet d in 0..k-1:
        # D_d[byte] = sum_{r=0..k-1} inv[d][r] * selected_packet[r][byte]
        reconstructed_data_packets: List[bytearray] = [
            bytearray(self.packet_size) for _ in range(self.k)
        ]

        for byte_idx in range(self.packet_size):
            for d in range(self.k):
                val = 0
                for r, sel_idx in enumerate(selected_indices):
                    coef = inv_submatrix[d][r]
                    y_val = received_packets[sel_idx][byte_idx]
                    val = GF256.add(val, GF256.mul(coef, y_val))
                reconstructed_data_packets[d][byte_idx] = val

        recovered_bytes = b"".join(bytes(p) for p in reconstructed_data_packets)

        # Verify cryptographic sponge tag on healed data
        sponge = TorixSponge(rate_bytes=32, capacity_bytes=32, domain_tag=0x33)
        sponge.absorb(recovered_bytes)
        test_tag = sponge.squeeze(64)
        auth_verified = (test_tag == auth_tag)

        elapsed = (time.perf_counter() - t0) * 1e6
        status = "HEALED_AND_VERIFIED" if auth_verified else "CORRUPTED"

        return FECRecoveryReport(
            frame_id=frame_id,
            status=status,
            lost_indices=lost_indices,
            recovered_indices=missing_data_indices,
            data_bytes=recovered_bytes,
            auth_verified=auth_verified,
            elapsed_us=elapsed,
            message=(
                f"Successfully healed {len(missing_data_indices)} erased data packet(s) "
                f"via GF(2^8) Cauchy MDS inversion. Sponge authentication: {'VERIFIED' if auth_verified else 'FAILED'}."
            ),
        )
