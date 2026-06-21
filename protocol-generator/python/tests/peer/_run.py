"""Zero-dependency test runner for the S3 peer suites.

The peer tests are written as pytest functions but use only plain ``assert``,
so they run under stdlib alone (the profile's named fallback: "stdlib unittest
is the zero-dep fallback if pytest is ever disallowed").  The S2 codec suite
runs under pytest where available; this runner keeps the S3 gate runnable in the
offline core image (which ships no pytest, only the one runtime dep).

Usage: ``PYTHONPATH=src python tests/peer/_run.py``
"""

from __future__ import annotations

import importlib
import sys
import traceback

MODULES = [
    "tests.peer.test_type_registry",
    "tests.peer.test_multisig",
    "tests.peer.test_loopback",
]


def main() -> int:
    sys.path.insert(0, ".")  # repo root for `tests.*`
    sys.path.insert(0, "src")  # the package
    passed = 0
    failed = 0
    for modname in MODULES:
        mod = importlib.import_module(modname)
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"[PASS] {modname}::{name}")
            except Exception:  # noqa: BLE001
                failed += 1
                print(f"[FAIL] {modname}::{name}")
                traceback.print_exc()
    print(f"\n=== {passed} passed, {failed} failed ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
