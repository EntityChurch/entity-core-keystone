#!/usr/bin/env python3
"""Re-render a pytest JUnit XML report as libtest result lines.

``tools/peer-contract/report.py`` reads local test evidence in libtest's format
(``test <name> ... ok|FAILED|ignored``), which is cargo's.  pytest does not print that, so
run-contract.sh asks pytest for ``--junitxml`` and this script renders one line per test
case — every case, not only the contract ones, so the evidence is the whole run.

A case with a ``<failure>`` or ``<error>`` child is ``FAILED``; ``<skipped>`` is ``ignored``;
otherwise ``ok``.  The name is the test function name (with any parametrization id), which
for the contract tests carries the requirement prefix report.py matches.  A missing or
unparseable report prints nothing and exits 1: no lines means ``unknown``, never ``pass``.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


def main(path: str) -> int:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"junit_to_libtest: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    n = 0
    for case in root.iter("testcase"):
        name = case.get("name", "")
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "FAILED"
        elif case.find("skipped") is not None:
            outcome = "ignored"
        else:
            outcome = "ok"
        print(f"test {name} ... {outcome}")
        n += 1
    print(f"junit_to_libtest: {n} test case(s) rendered", file=sys.stderr)
    return 0 if n else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
