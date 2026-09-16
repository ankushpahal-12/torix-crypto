"""
TORIX-Sponge: Full Post-Quantum Multi-Rate Duplex Sponge Engine
===============================================================
Implements the multi-rate cryptographic sponge and duplex construction
built on top of the TORIX 512-bit toroidal permutation network.

Security Profiles:
- Fast XOF: Rate = 32B (256b), Capacity = 32B (256b) -> 128-bit Post-Quantum
- PQ-Standard: Rate = 16B (128b), Capacity = 48B (384b) -> 192-bit Post-Quantum
"""

import os
import sys

# Ensure package directory is in sys.path for standalone imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


from typing import List, Optional
from h512 import IV, round_transform


def state_to_bytes(S: List[List[int]]) -> bytes:
    """Converts an 8x8 matrix of octets to a 64-byte string."""
    return bytes(S[r][c] for r in range(8) for c in range(8))


def bytes_to_state(b: bytes) -> List[List[int]]:
    """Converts a 64-byte string to an 8x8 matrix of octets."""
    if len(b) != 64:
        raise ValueError(f"State requires 64 bytes, got {len(b)}")
    return [[b[r * 8 + c] for c in range(8)] for r in range(8)]


def permute_p16(S: List[List[int]]) -> List[List[int]]:
    """Executes the full 16-round permutation P_16."""
    state = [row[:] for row in S]
    for rnd in range(16):
        state = round_transform(state, rnd)
    return state


def permute_p8(S: List[List[int]]) -> List[List[int]]:
    """Executes the reduced 8-round permutation P_8."""
    state = [row[:] for row in S]
    for rnd in range(8):
        state = round_transform(state, rnd)
    return state


class TorixSponge:
    """
    Stateful Duplex Sponge Engine over the 512-bit discrete Torus.
    """

    def __init__(self, rate_bytes: int = 32, capacity_bytes: int = 32, domain_tag: int = 0x53):
        if rate_bytes + capacity_bytes != 64:
            raise ValueError("Rate + Capacity must equal exactly 64 bytes (512 bits)")
        self.rate = rate_bytes
        self.capacity = capacity_bytes
        self.domain_tag = domain_tag & 0xFF
        
        # Initialize internal state from NUMS IV + parameter domain injection
        init_state = [row[:] for row in IV]
        init_state[0][0] ^= self.rate
        init_state[0][1] ^= self.capacity
        init_state[7][7] ^= self.domain_tag
        self.state = permute_p16(init_state)

    def copy(self) -> "TorixSponge":
        """Returns an independent defensive clone of the sponge engine."""
        clone = TorixSponge(rate_bytes=self.rate, capacity_bytes=self.capacity, domain_tag=self.domain_tag)
        clone.state = [row[:] for row in self.state]
        return clone

    def absorb(self, data: bytes):
        """
        Absorbs arbitrary-length data into the sponge with multi-rate NIST 10*1 padding.
        """
        # NIST 10*1 padding: data || 0x01 || 0x00*k || 0x80
        pad_len = self.rate - (len(data) % self.rate)
        if pad_len == 1:
            padded = data + b"\x81"
        else:
            padded = data + b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"

        # Absorb block-by-block
        for offset in range(0, len(padded), self.rate):
            block = padded[offset : offset + self.rate]
            raw_state = bytearray(state_to_bytes(self.state))
            for i in range(self.rate):
                raw_state[i] ^= block[i]
            self.state = permute_p16(bytes_to_state(bytes(raw_state)))

    def squeeze(self, num_bytes: int) -> bytes:
        """
        Squeezes arbitrary number of bytes from the sponge.
        """
        output = bytearray()
        while len(output) < num_bytes:
            raw_state = state_to_bytes(self.state)
            take = min(num_bytes - len(output), self.rate)
            output.extend(raw_state[:take])
            if len(output) < num_bytes:
                self.state = permute_p16(self.state)
        return bytes(output)

    def duplex(self, data_in: bytes, squeeze_len: int) -> bytes:
        """
        Interactive duplex step: absorbs an input chunk (<= rate) and squeezes squeeze_len bytes.
        Maintains continuous session history without resetting the state.
        """
        if len(data_in) > self.rate:
            raise ValueError(f"Duplex input cannot exceed rate ({self.rate} bytes)")

        raw_state = bytearray(state_to_bytes(self.state))
        for i in range(len(data_in)):
            raw_state[i] ^= data_in[i]
        
        # Domain separation for duplex transition
        raw_state[63] ^= 0x01
        self.state = permute_p16(bytes_to_state(bytes(raw_state)))

        # Squeeze output bytes
        return self.squeeze(squeeze_len)


def torix_xof(data: bytes, output_len: int, post_quantum: bool = False) -> bytes:
    """
    One-shot Extendable-Output Function (XOF).
    - If post_quantum=True: uses PQ-Standard (Rate=16B, Capacity=48B, 192-bit quantum security)
    - If post_quantum=False: uses Fast-XOF (Rate=32B, Capacity=32B, 128-bit quantum security)
    """
    rate = 16 if post_quantum else 32
    capacity = 48 if post_quantum else 32
    sponge = TorixSponge(rate_bytes=rate, capacity_bytes=capacity)
    sponge.absorb(data)
    return sponge.squeeze(output_len)


def torix_prng(seed: bytes, output_len: int) -> bytes:
    """
    Cryptographically secure pseudorandom generator (PRNG).
    """
    return torix_xof(b"TORIX_PRNG_INIT::" + seed, output_len, post_quantum=True)
