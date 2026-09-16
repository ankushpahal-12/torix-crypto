"""
TORIX-AEAD: Authenticated Encryption with Associated Data
=========================================================
Implements high-speed single-pass authenticated encryption providing:
- IND-CCA2 confidentiality (privacy against chosen-ciphertext attacks)
- INT-CTXT ciphertext & metadata integrity (tamper-proofing)

Parameters:
- Key: 256 bits (32 bytes)
- Nonce: 128 bits (16 bytes)
- Tag: 256 bits (32 bytes)
- Rate: 256 bits (32 bytes)
- Capacity: 256 bits (32 bytes)
- Permutations: P_16 (Init/Finalize), P_8 (Streaming)
"""

import os
import sys

# Ensure package directory is in sys.path for standalone imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


import secrets
from typing import Optional, Tuple
from torix_sponge import bytes_to_state, permute_p16, permute_p8, state_to_bytes


# Domain separation constants
TAU_INIT = 0x41  # ASCII 'A'
TAU_AD   = 0x01
TAU_ENC  = 0x02


def _init_aead_state(key: bytes, nonce: bytes) -> bytearray:
    """
    Initializes the 512-bit AEAD state with Key and Nonce:
    S_rate = Key (32 bytes)
    S_capacity = Nonce (16B) || 0^15 || TAU_INIT (1B)
    """
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes (256 bits), got {len(key)}")
    if len(nonce) != 16:
        raise ValueError(f"Nonce must be exactly 16 bytes (128 bits), got {len(nonce)}")

    raw_state = bytearray(64)
    # Rate: Rows 0..3 (32 bytes) = Key
    raw_state[0:32] = key
    # Capacity: Rows 4..7 (32 bytes) = Nonce || Zero Padding || TAU_INIT
    raw_state[32:48] = nonce
    raw_state[48:63] = b"\x00" * 15
    raw_state[63] = TAU_INIT

    # P_16 initialization permutation
    S = permute_p16(bytes_to_state(bytes(raw_state)))
    state_bytes = bytearray(state_to_bytes(S))

    # Key injection into capacity
    for i in range(32):
        state_bytes[32 + i] ^= key[i]

    return state_bytes


def _process_associated_data(state_bytes: bytearray, associated_data: bytes) -> bytearray:
    """
    Absorbs associated data in 32-byte chunks using reduced P_8 permutations.
    """
    if len(associated_data) > 0:
        # Pad AD to multiple of 32 bytes
        pad_len = 32 - (len(associated_data) % 32)
        if pad_len == 1:
            ad_padded = associated_data + b"\x81"
        else:
            ad_padded = associated_data + b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"

        for offset in range(0, len(ad_padded), 32):
            chunk = ad_padded[offset : offset + 32]
            for i in range(32):
                state_bytes[i] ^= chunk[i]
            S = permute_p8(bytes_to_state(bytes(state_bytes)))
            state_bytes = bytearray(state_to_bytes(S))

    # Domain separator for AD
    state_bytes[63] ^= TAU_AD
    return state_bytes


def torix_aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext and generates a 256-bit authentication tag.
    Returns: (ciphertext, tag)
    """
    # 1. Initialize state
    state_bytes = _init_aead_state(key, nonce)

    # 2. Absorb Associated Data
    state_bytes = _process_associated_data(state_bytes, associated_data)

    # 3. Encrypt Plaintext
    ciphertext = bytearray()
    if len(plaintext) > 0:
        offset = 0
        while offset < len(plaintext):
            chunk_len = min(32, len(plaintext) - offset)
            chunk = plaintext[offset : offset + chunk_len]

            # Ciphertext is Plaintext XOR Rate
            c_chunk = bytearray(chunk_len)
            for i in range(chunk_len):
                c_chunk[i] = chunk[i] ^ state_bytes[i]
                state_bytes[i] = c_chunk[i]  # Feedback ciphertext into Rate

            ciphertext.extend(c_chunk)

            # Domain padding if last block is partial (< 32 bytes)
            if chunk_len < 32:
                state_bytes[chunk_len] ^= 0x01

            # Permute with P_8
            S = permute_p8(bytes_to_state(bytes(state_bytes)))
            state_bytes = bytearray(state_to_bytes(S))
            offset += chunk_len

    # Domain tag for encryption phase completion
    state_bytes[63] ^= TAU_ENC

    # 4. Finalization
    for i in range(32):
        state_bytes[32 + i] ^= key[i]

    S = permute_p16(bytes_to_state(bytes(state_bytes)))
    final_state = state_to_bytes(S)

    # Tag is the Rate (top 32 bytes)
    tag = final_state[:32]
    return bytes(ciphertext), tag


def torix_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b"") -> Optional[bytes]:
    """
    Decrypts ciphertext and verifies the 256-bit authentication tag in constant time.
    Returns: plaintext if tag is valid; None if tag verification fails.
    """
    # 1. Initialize state
    state_bytes = _init_aead_state(key, nonce)

    # 2. Absorb Associated Data
    state_bytes = _process_associated_data(state_bytes, associated_data)

    # 3. Decrypt Ciphertext
    plaintext = bytearray()
    if len(ciphertext) > 0:
        offset = 0
        while offset < len(ciphertext):
            chunk_len = min(32, len(ciphertext) - offset)
            chunk = ciphertext[offset : offset + chunk_len]

            p_chunk = bytearray(chunk_len)
            for i in range(chunk_len):
                p_chunk[i] = chunk[i] ^ state_bytes[i]
                state_bytes[i] = chunk[i]  # Feedback ciphertext into Rate

            plaintext.extend(p_chunk)

            if chunk_len < 32:
                state_bytes[chunk_len] ^= 0x01

            S = permute_p8(bytes_to_state(bytes(state_bytes)))
            state_bytes = bytearray(state_to_bytes(S))
            offset += chunk_len

    # Domain tag for encryption phase completion
    state_bytes[63] ^= TAU_ENC

    # 4. Finalization
    for i in range(32):
        state_bytes[32 + i] ^= key[i]

    S = permute_p16(bytes_to_state(bytes(state_bytes)))
    final_state = state_to_bytes(S)
    computed_tag = final_state[:32]

    # Constant-time tag comparison
    tag_valid = (len(tag) == 32) and secrets.compare_digest(computed_tag, tag)
    if tag_valid:
        return bytes(plaintext)
    else:
        # Wipe plaintext buffer to prevent any unauthenticated data release
        for i in range(len(plaintext)):
            plaintext[i] = 0
        return None
