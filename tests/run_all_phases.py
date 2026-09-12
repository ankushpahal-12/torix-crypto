"""
Project H-512: Master Automated Verification Dashboard (Phase 15 Capstone)
==========================================================================
Executes the complete end-to-end verification battery across all 14 test suites:
- Phase 3: State Construction & Torus Topology
- Phase 4: Nonlinear Core & S-Box Bijectivity
- Phase 5: Three-Tier Diffusion Engine
- Phase 6: Permutation Network & Invariants
- Phase 7: Round Structure & Safety Margin
- Phase 8: Finalization & Miyaguchi-Preneel
- Extra Level: Involutive GF(2^8) Circulant MDS Layer
- Audit: Loophole & Bottleneck Attack Suite (5 Attacks)
- Phase 9: Reference Implementation & C Parity
- Phase 10: NIST SP 800-22 Statistical Testing Suite
- Phase 11: Formal Cryptanalysis & Security Bounds
- Phase 12: SIMD Vectorization & Multi-Lane Optimization
- Phase 13: Extended Modes (Tree Hashing, HKDF, XOF)
- Phase 14: Production Hardening & Side-Channel Verification
"""

import os
import sys

# Ensure python directory is in sys.path for standalone execution
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR = os.path.abspath(os.path.join(_TESTS_DIR, "..", "python"))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)


import os
import subprocess
import sys
import time

TEST_SUITES = [
    ("Phase 3: State Construction & Topology", "verify_phase3.py"),
    ("Phase 4: Nonlinear Core & Mini-Feistel", "verify_phase4.py"),
    ("Phase 5: Multi-Tier Diffusion Engine", "verify_phase5.py"),
    ("Phase 6: Permutation Network & Bijections", "verify_phase6.py"),
    ("Phase 7: Round Structure & Safety Margin", "verify_phase7.py"),
    ("Phase 8: Finalization & Miyaguchi-Preneel", "verify_phase8.py"),
    ("Extra Level: GF(2^8) Circulant MDS Layer", "verify_mds_level.py"),
    ("Audit: 5 Attack Vectors & Defenses", "audit_bottlenecks_and_loopholes.py"),
    ("Phase 9: Reference Impl & C99 Parity", "verify_phase9.py"),
    ("Phase 10: NIST SP 800-22 Randomness Suite", "verify_phase10.py"),
    ("Phase 11: Formal Cryptanalysis & Bounds", "verify_phase11.py"),
    ("Phase 12: High-Speed SIMD Vectorization", "verify_phase12.py"),
    ("Phase 13: Extended Cryptographic Modes", "verify_phase13.py"),
    ("Phase 14: Hardening & Side-Channel Defense", "verify_phase14.py"),
]


def run_master_suite():
    print("=" * 80)
    print("        PROJECT H-512: MASTER VERIFICATION DASHBOARD (ALL 14 PHASES)   ")
    print("=" * 80)
    print(f"Directory : {os.getcwd()}")
    print(f"Python    : {sys.version.split()[0]}")
    print("=" * 80 + "\n")

    results = []
    total_start = time.perf_counter()

    for idx, (title, filename) in enumerate(TEST_SUITES, 1):
        script_path = os.path.join(os.path.dirname(__file__), filename)
        assert os.path.exists(script_path), f"Test suite {filename} not found!"

        print(f"[{idx:2d}/14] Running {title} ({filename})...", flush=True)
        test_env = os.environ.copy()
        python_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python"))
        test_env["PYTHONPATH"] = python_dir + os.pathsep + test_env.get("PYTHONPATH", "")

        t0 = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=test_env,
        )
        elapsed = time.perf_counter() - t0

        if proc.returncode == 0:
            print(f"       -> [PASS] Completed in {elapsed:6.2f}s\n")
            results.append((title, filename, "PASS", elapsed, ""))
        else:
            print(f"       -> [FAIL] Exit code {proc.returncode} in {elapsed:6.2f}s")
            print("STDERR:\n" + proc.stderr[:500] + "\n")
            results.append((title, filename, "FAIL", elapsed, proc.stderr))

    total_elapsed = time.perf_counter() - total_start

    # Print Summary Dashboard
    print("\n" + "=" * 80)
    print("                    MASTER VERIFICATION SUMMARY DASHBOARD                      ")
    print("=" * 80)
    print(f"{'#':<3} | {'Phase / Test Suite Title':<44} | {'Status':<6} | {'Time':<8}")
    print("-" * 80)

    all_passed = True
    for idx, (title, filename, status, elapsed, err) in enumerate(results, 1):
        status_str = f"\033[92m{status}\033[0m" if status == "PASS" else f"\033[91m{status}\033[0m"
        # Plain text status for windows console
        plain_status = f"[{status}]"
        print(f"{idx:<3} | {title:<44} | {plain_status:<6} | {elapsed:6.2f}s")
        if status != "PASS":
            all_passed = False

    print("=" * 80)
    passed_count = sum(1 for r in results if r[2] == "PASS")
    print(f"Total Suites : 14")
    print(f"Passed       : {passed_count} / 14 ({passed_count / 14 * 100:.1f}%)")
    print(f"Total Time   : {total_elapsed:.2f} seconds")

    if all_passed:
        print("\n" + "*" * 80)
        print("   *** 100% GLOBAL VERIFICATION ACHIEVED: PROJECT H-512 IS ROCK-SOLID! ***    ")
        print("*" * 80 + "\n")
    else:
        print("\n[!] CRITICAL: Some test suites failed! Review errors above.\n")
        sys.exit(1)


if __name__ == "__main__":
    run_master_suite()
