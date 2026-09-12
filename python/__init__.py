"""
TORIX-512 Cryptographic Package
===============================
"""

import os
import sys

# Ensure package directory is in sys.path
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

from torix import (
    torix512,
    torix256,
    sha512,
    sha256,
    hash512,
    hash256,
    generate_key,
    generate_nonce,
    encrypt,
    decrypt,
    xof,
    hash_password,
    verify_password,
)

__version__ = "1.0.0"
__all__ = [
    "torix512",
    "torix256",
    "sha512",
    "sha256",
    "hash512",
    "hash256",
    "generate_key",
    "generate_nonce",
    "encrypt",
    "decrypt",
    "xof",
    "hash_password",
    "verify_password",
]
