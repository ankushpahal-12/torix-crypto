"""
TORIX-512 Cryptographic Suite
=============================
Official Python Implementation of the TORIX-512 Cryptographic Permutation,
Hashing Modes, and the 5 Frontier Breakthrough Primitives:
- Frontier 4: 2D Spatial Forensic Tamper Heatmap & Inversion
- Frontier 1: ZK-STARK Dual-Field Arithmetization (<300 constraints/block)
- Frontier 3: Self-Healing MDS Duplex Sponge with Cauchy Reed-Solomon FEC
- Frontier 2: In-Storage DMA & Zero-Copy eBPF Ring Hashing (TORIX-Direct)
- Frontier 5: Blind Toroidal Vector Commitments & Proof-of-Reserves
"""

import os
import sys

# Ensure package directory is in sys.path
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

from torix import (
    # Core Hashing
    torix512,
    torix256,
    sha512,
    sha256,
    hash512,
    hash256,
    # AEAD & Key Management
    generate_key,
    generate_nonce,
    encrypt,
    decrypt,
    xof,
    # Password Protection (Salt + Pepper)
    hash_password,
    verify_password,
    # FIPS 140-3
    self_test,
    # Seekable Container (.t512)
    encode_t512,
    encode_t512_file,
    verify_t512_slice,
    verify_t512_file_slice,
    # Frontier 4: 2D Spatial Forensics
    forensic_audit,
    forensic_audit_files,
    # Frontier 1: ZK-STARK Arithmetization
    zk_trace,
    zk_verify,
    zk_metrics,
    # Frontier 3: Self-Healing FEC Duplex Sponge
    fec_encode,
    fec_decode,
    # Frontier 2: In-Storage DMA & Zero-Copy eBPF
    direct_mmap_hash,
    direct_stream_hash,
    pack_frame,
    unpack_frame,
    TorixFrameGuard,
    AntiReplayWindow,
    compute_rfc1071_checksum,
    # Frontier 5: Blind Toroidal Vector Commitments & PoR
    vector_commit,
    vector_open,
    vector_verify,
    vector_open_batch,
    vector_verify_batch,
    proof_of_reserves,
    verify_proof_of_reserves,
)

__version__ = "2.1.0"
__all__ = [
    "__version__",
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
    "self_test",
    "encode_t512",
    "encode_t512_file",
    "verify_t512_slice",
    "verify_t512_file_slice",
    "forensic_audit",
    "forensic_audit_files",
    "zk_trace",
    "zk_verify",
    "zk_metrics",
    "fec_encode",
    "fec_decode",
    "direct_mmap_hash",
    "direct_stream_hash",
    "pack_frame",
    "unpack_frame",
    "TorixFrameGuard",
    "AntiReplayWindow",
    "compute_rfc1071_checksum",
    "vector_commit",
    "vector_open",
    "vector_verify",
    "vector_open_batch",
    "vector_verify_batch",
    "proof_of_reserves",
    "verify_proof_of_reserves",
]
