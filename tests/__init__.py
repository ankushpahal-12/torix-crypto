"""
TORIX-512 Verification & Cryptanalysis Test Package
===================================================
Automatically configures sys.path so test suites resolve python/ modules seamlessly.
"""

import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR = os.path.abspath(os.path.join(_TESTS_DIR, "..", "python"))

if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)
