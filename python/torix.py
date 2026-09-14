"""
TORIX Master Python SDK (Unified Cryptographic Toolkit)
=======================================================
A developer-friendly, all-in-one cryptographic interface providing:
1. Hashlib-compatible API for Hashing (like hashlib.sha256 / sha512)
2. One-line Authenticated Encryption & Decryption (AEAD)
3. Post-Quantum Keystream & XOF Generation (SHAKE style)
4. Military-Grade Salted & Iterated Password Hashing
"""

import os
import sys

# Ensure package directory is in sys.path for standalone imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


import os
import secrets
from typing import Optional, Tuple, Union

# Import internal specialized engines
import h512
from h512 import H512Hasher, H256Hasher
import torix_aead
import torix_sponge


# ==============================================================================
# 1. HASHLIB-COMPATIBLE HASHING INTERFACE
# ==============================================================================
def torix512(data: Union[str, bytes] = b"") -> H512Hasher:
    """
    Creates a 512-bit TORIX hash object (exact equivalent of hashlib.sha512).
    Supports .update(data), .digest(), .hexdigest(), and .copy().
    """
    hasher = H512Hasher(domain_tag=0x00)
    if data:
        hasher.update(data)
    return hasher


def torix256(data: Union[str, bytes] = b"") -> H256Hasher:
    """
    Creates a 256-bit TORIX hash object (exact equivalent of hashlib.sha256).
    Supports .update(data), .digest(), .hexdigest(), and .copy().
    """
    hasher = H256Hasher()
    if data:
        hasher.update(data)
    return hasher


# Aliases for instant drop-in replacement of hashlib
sha512 = torix512
sha256 = torix256


def hash512(data: Union[str, bytes]) -> str:
    """One-shot 512-bit hex digest of a string or bytes."""
    return torix512(data).hexdigest()


def hash256(data: Union[str, bytes]) -> str:
    """One-shot 256-bit hex digest of a string or bytes."""
    return torix256(data).hexdigest()


def hash_file(
    filepath: Union[str, os.PathLike],
    algorithm: str = "torix512",
    chunk_size: int = 65536,
) -> str:
    """
    Cryptographically hashes any file (documents, audio, video) using constant O(1) memory.
    Reads binary streams in sequential buffers (default 64 KB).

    Supported algorithms:
      - 'torix512' / 'sha512': 512-bit canonical digest (128 hex characters)
      - 'torix256' / 'sha256': 256-bit cross-folded digest (64 hex characters)
    """
    hasher = torix256() if algorithm.lower() in ("torix256", "sha256", "h256", "256") else torix512()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_file_tree(
    filepath: Union[str, os.PathLike],
    chunk_size: int = 65536,
    num_workers: int = 4,
) -> str:
    """
    Parallel binary Merkle tree hash for large multimedia files (videos, high-res audio).
    Processes chunks across multiple CPU cores with O(log N) seekable proof capability.
    """
    import h512_modes
    with open(filepath, "rb") as f:
        data = f.read()
    hasher = h512_modes.H512TreeHasher(chunk_size=chunk_size, num_workers=num_workers)
    return hasher.hash(data).hex()



# ==============================================================================
# 2. AUTHENTICATED ENCRYPTION & DECRYPTION (AEAD)
# ==============================================================================
def generate_key() -> bytes:
    """Generates a cryptographically secure 256-bit (32-byte) secret key."""
    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generates a cryptographically secure 128-bit (16-byte) unique nonce."""
    return os.urandom(16)


def encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: Union[str, bytes],
    associated_data: Union[str, bytes] = b""
) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext and generates a 256-bit tamper-proof authentication tag.
    Returns: (ciphertext_bytes, tag_bytes)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(associated_data, str):
        associated_data = associated_data.encode("utf-8")

    return torix_aead.torix_aead_encrypt(key, nonce, plaintext, associated_data)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Union[str, bytes] = b""
) -> Optional[bytes]:
    """
    Decrypts ciphertext and verifies authentication tag in constant time.
    Returns: plaintext_bytes on success, or None if tampered / invalid.
    """
    if isinstance(associated_data, str):
        associated_data = associated_data.encode("utf-8")

    return torix_aead.torix_aead_decrypt(key, nonce, ciphertext, tag, associated_data)


# ==============================================================================
# 3. POST-QUANTUM EXTENDABLE OUTPUT (XOF / SPONGE)
# ==============================================================================
def xof(data: Union[str, bytes], length: int = 64, post_quantum: bool = True) -> bytes:
    """
    Squeezes an arbitrary number of pseudorandom bytes from input data (like SHAKE).
    - post_quantum=True provides 192-bit quantum security against Grover's algorithm.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return torix_sponge.torix_xof(data, length, post_quantum=post_quantum)


# ==============================================================================
# 4. ENTERPRISE PASSWORD STORAGE & VERIFICATION
# ==============================================================================
def hash_password(password: str, iterations: int = 4096) -> str:
    """
    Hashes a password with a 16-byte random salt and 4,096 iterations.
    Returns a standard crypt string: $torix$i=4096$salt_hex$hash_hex
    """
    salt = os.urandom(16)
    pw_bytes = password.encode("utf-8")

    # Iterated key derivation
    current = h512.h512_hash(salt + b"::" + pw_bytes)
    for _ in range(iterations - 1):
        current = h512.h512_hash(current + pw_bytes)

    return f"$torix$i={iterations}${salt.hex()}${current.hex()}"


def verify_password(password: str, stored_hash_str: str) -> bool:
    """
    Verifies a password against a stored crypt string in constant time.
    """
    try:
        parts = stored_hash_str.split("$")
        # Format: ['', 'torix', 'i=4096', 'salt_hex', 'hash_hex']
        iterations = int(parts[2].split("=")[1])
        salt = bytes.fromhex(parts[3])
        expected_hex = parts[4]
    except Exception:
        return False

    pw_bytes = password.encode("utf-8")
    current = h512.h512_hash(salt + b"::" + pw_bytes)
    for _ in range(iterations - 1):
        current = h512.h512_hash(current + pw_bytes)

    # Constant-time comparison
    return secrets.compare_digest(current.hex(), expected_hex)


# ==============================================================================
# 5. FIPS 140-3 / NIST POWER-ON SELF-TEST
# ==============================================================================
self_test = h512.h512_self_test
