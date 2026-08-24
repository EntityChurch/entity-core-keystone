#!/usr/bin/env python3
"""check-set-gate.py — refuse to compare peer scores that were not measured on the same checks.

WHY THIS EXISTS
---------------
A conformance number is only meaningful against a known check set. `validate-peer` is
deterministic and does run the identical set on every peer -- measured 2026-08-17, 42 of 45
peers produced a byte-identical 740-check set under `--profile core`. But there is one way the
executed set can silently shrink: the **global `-timeout`** expiring mid-suite. When it does,
the oracle stops emitting the remaining categories' checks and emits one synthetic
`<category>/skipped` entry instead, at severity **SKIP** -- the *same severity it uses for a
legitimate `--profile core` extension carve-out*. So in the machine-readable report:

    "we deliberately do not run this"   -> severity SKIP
    "we never got to this"              -> severity SKIP

and `summary` cannot tell them apart. A run that never measured the core `resource_bounds`
category reports `{"failed": 1, "skipped": 111}` and reads like a near-clean run. That is
exactly how three peers (asm-x86_64 / asm-arm64 / riscv64) carried 3 core FAILs each while the
matrix recorded 1, for four consecutive census runs.

This gate closes that hole on our side. It does NOT patch or second-guess the oracle (forbidden
-- AGENTS.md "Boundaries"); it validates the oracle's own output before we are allowed to
publish a comparison. The oracle-side reporting defect is escalated separately in
`research/stewardship/HANDOFF-TO-ARCH-2026-08-17-budget-exhaustion-reporting.md`.

WHAT IT ENFORCES
----------------
1. Every report executed the *same set of check names* as the pinned reference.
2. No report contains a `budget_exhausted` category.

Either failure makes that peer's P/W/F/S an INCOMPLETE MEASUREMENT, not a result. The gate exits
non-zero and names the peer; a census that trips it must not be published as a cohort comparison.

USAGE
-----
    tools/check-set-gate.py                       # gate the standard census dir
    tools/check-set-gate.py path/to/reports/      # gate a directory of report JSONs
    tools/check-set-gate.py a.json b.json         # gate specific reports
    tools/check-set-gate.py --update-pin          # recompute + print the pin line after a re-pin

The expected digest is read from `tools/oracle-pin.env` (`core_executed_check_set_digest`). It is
a property of the ORACLE PIN, so it legitimately changes when the pin changes -- and when it
does, every peer must be re-measured anyway. If the key is absent the gate falls back to
"all reports must agree with each other" and says so.
"""
from __future__ import annotations
import sys, json, hashlib, pathlib, collections

REPO = pathlib.Path(__file__).resolve().parent.parent
PIN = REPO / "tools" / "oracle-pin.env"
DEFAULT_DIRS = [REPO / "output" / "scratch" / "census"]
# Reports that intentionally supersede an earlier one for the same peer.
OVERLAY_DIRS = [REPO / "output" / "scratch" / "reverify"]


def check_set(doc):
    return sorted(f'{c["category"]}/{c["name"]}' for c in doc.get("checks", []))


def digest(names):
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def starved(doc):
    return sorted({c["category"] for c in doc.get("checks", [])
                   if "budget_exhausted" in (c.get("message") or "")})


def pinned_digest():
    if not PIN.exists():
        return None
    for line in PIN.read_text().splitlines():
        if line.strip().startswith("core_executed_check_set_digest"):
            return line.split("=", 1)[1].strip().split()[0]
    return None


def collect(args):
    reports = {}
    if args:
        paths = []
        for a in args:
            p = pathlib.Path(a)
            paths.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
        for p in paths:
            reports[p.stem] = (p, json.loads(p.read_text()))
    else:
        for d in DEFAULT_DIRS:
            for p in sorted(d.glob("*.json")):
                reports[p.stem] = (p, json.loads(p.read_text()))
        for d in OVERLAY_DIRS:                       # post-rebuild re-verifications win
            for p in sorted(d.glob("*.json")):
                reports[p.stem] = (p, json.loads(p.read_text()))
    return reports


def main(argv):
    if "--update-pin" in argv:
        argv = [a for a in argv if a != "--update-pin"]
        reports = collect(argv)
        counts = collections.Counter(digest(check_set(d)) for _, d in reports.values())
        h, n = counts.most_common(1)[0]
        size = len(check_set(next(d for _, d in reports.values() if digest(check_set(d)) == h)))
        print(f"core_executed_check_set_digest = {h}  # {size} checks, agreed by {n} peers")
        return 0

    reports = collect(argv)
    if not reports:
        print("check-set-gate: no reports found — nothing to gate", file=sys.stderr)
        return 2

    expected = pinned_digest()
    by_digest = collections.defaultdict(list)
    for peer, (_, doc) in reports.items():
        by_digest[digest(check_set(doc))].append(peer)

    if expected is None:
        expected = max(by_digest, key=lambda h: len(by_digest[h]))
        src = f"majority of {len(reports)} reports (no pin in tools/oracle-pin.env)"
    else:
        src = "tools/oracle-pin.env"

    ref_peer = by_digest.get(expected, [None])[0]
    ref_set = set(check_set(reports[ref_peer][1])) if ref_peer else None

    bad = []
    for peer in sorted(reports):
        _, doc = reports[peer]
        names = check_set(doc)
        h = digest(names)
        st = starved(doc)
        if h != expected or st:
            bad.append((peer, h, len(names), set(names), st))

    print(f"check-set gate — {len(reports)} reports, reference from {src}")
    print(f"  expected digest : {expected}")
    print(f"  expected size   : {len(ref_set) if ref_set else '?'} checks")
    print(f"  conforming      : {len(reports) - len(bad)} / {len(reports)}")

    if not bad:
        print("\nPASS — every peer was scored on the identical check set; scores are comparable.")
        return 0

    print(f"\nFAIL — {len(bad)} peer(s) were NOT scored on the reference check set.")
    print("Their P/W/F/S is an INCOMPLETE MEASUREMENT, not a result. Do not publish these")
    print("alongside the others as if they were comparable.\n")
    for peer, h, n, names, st in bad:
        print(f"  {peer}")
        print(f"    digest {h[:16]}…  ({n} checks, expected {len(ref_set) if ref_set else '?'})")
        if ref_set is not None:
            missing = sorted(ref_set - names)
            extra = sorted(names - ref_set)
            if missing:
                cats = collections.Counter(m.split("/")[0] for m in missing)
                print(f"    NEVER RAN {len(missing)} checks across {len(cats)} categories: "
                      + ", ".join(f"{c}({k})" for c, k in sorted(cats.items())))
            if extra:
                print(f"    extra {len(extra)}: {', '.join(extra[:6])}"
                      + (" …" if len(extra) > 6 else ""))
        if st:
            print(f"    budget_exhausted in: {', '.join(st)}")
            core = [c for c in st if c in {"connectivity", "encoding", "type_system",
                                           "origination", "resource_bounds", "concurrency"}]
            if core:
                print(f"    !! {len(core)} of these are CORE GATE categories: {', '.join(core)}")
        print()
    print("Fix the peer (or re-measure the starved categories with")
    print("`research/diagnostics/starved-categories-probe.sh <peer>`) before comparing scores.")
    print("Raising -timeout to make the report green is forbidden — see AGENTS.md.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
