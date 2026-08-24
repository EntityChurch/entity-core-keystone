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
    tools/check-set-gate.py --tracked             # gate the TRACKED per-peer status reports
    tools/check-set-gate.py --update-pin          # recompute + print the pin line after a re-pin

The expected digest is read from `tools/oracle-pin.env` (`core_executed_check_set_digest`). It is
a property of the ORACLE PIN, so it legitimately changes when the pin changes -- and when it
does, every peer must be re-measured anyway. If the key is absent the gate falls back to
"all reports must agree with each other" and says so.

--tracked: THE COMMITTED REPORTS, NOT THE SCRATCH ONES
------------------------------------------------------
The default mode gates `output/scratch/census/` -- which is GITIGNORED. That is fine for
answering "is this census internally comparable", but it says nothing about what a person who
CLONES this repo actually reads. Measured 2026-08-22: every tracked
`protocol-generator/<peer>/status/CONFORMANCE-REPORT.json` had drifted a full oracle pin behind
the published matrix -- 38 peers at the retired de8f807 740-check set, 4 at 682, NONE at the
current 755 -- while CONFORMANCE-MATRIX.md §1 published fresh census numbers. Nothing was wrong
with §1; the defect was that a clone showed each peer's own committed report contradicting its
published row, and no gate looked at those files at all.

`--tracked` closes that. It reads the committed reports and requires them to be at the pinned
check set. It gates a DELIBERATELY NARROW set: the peers this repo currently claims are
publishable (0-FAIL at the current pin, per the census). Peers still owing the CAP fix are
known-behind, tracked in CONFORMANCE-MATRIX.md §3, and are REPORTED but do not fail the gate --
a gate that is permanently red because of tracked, disclosed debt gets ignored, and an ignored
gate is worse than none. As each peer is fixed and refreshed it joins the gated set
automatically, so the gate can only ratchet tighter.

Refresh a tracked report with `tools/run-cohort-census.sh --to-status <peer>`. It is a
MEASUREMENT -- never hand-copy a census JSON onto a tracked report.
"""
from __future__ import annotations
import sys, json, hashlib, pathlib, collections

REPO = pathlib.Path(__file__).resolve().parent.parent
PIN = REPO / "tools" / "oracle-pin.env"
DEFAULT_DIRS = [REPO / "output" / "scratch" / "census"]
# Reports that intentionally supersede an earlier one for the same peer.
OVERLAY_DIRS = [REPO / "output" / "scratch" / "reverify"]


TRACKED_GLOB = "protocol-generator/*/status/CONFORMANCE-REPORT.json"


def peer_key(path: pathlib.Path) -> str:
    """Peer name for a report path.

    The census names files <peer>.json, so the stem is the peer. Tracked reports are all
    named CONFORMANCE-REPORT.json and live under protocol-generator/<peer>/status/, so the
    stem collides for every peer -- keying 45 reports by stem silently collapses them to ONE
    entry and the gate then "passes" having looked at a single file. Key those by the peer
    directory instead.
    """
    if path.stem == "CONFORMANCE-REPORT":
        return path.parent.parent.name
    return path.stem


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
            reports[peer_key(p)] = (p, json.loads(p.read_text()))
    else:
        for d in DEFAULT_DIRS:
            for p in sorted(d.glob("*.json")):
                reports[p.stem] = (p, json.loads(p.read_text()))
        # Post-rebuild re-verifications supersede the census -- but ONLY if they are
        # actually NEWER than the census report they would replace. The overlay dir is
        # not scoped to a run or to an oracle pin, so a re-verify left behind by an
        # EARLIER pin sits there indefinitely and silently wins over a fresh census.
        # Measured 2026-08-22: reverify/ still held node-red + rust-wasm{,-wasmtime}
        # reports from 2026-08-17 at the retired de8f807 pin (740 checks). They
        # outranked the 2026-08-21 c1b0708 census (755 checks), so the gate reported
        # 7 non-comparable peers instead of the true 4 -- three of them condemned on
        # four-day-old evidence measured against a different check set. Same class as
        # the stale-build-artifact rule in AGENTS.md: an input that predates what it
        # supersedes is not an override, it is drift.
        for d in OVERLAY_DIRS:
            for p in sorted(d.glob("*.json")):
                prev = reports.get(p.stem)
                if prev and prev[0].stat().st_mtime > p.stat().st_mtime:
                    print(f"check-set-gate: ignoring STALE overlay {p} "
                          f"(older than {prev[0]})", file=sys.stderr)
                    continue
                reports[p.stem] = (p, json.loads(p.read_text()))
    return reports


def publishable_peers(expected):
    """Peers this repo currently CLAIMS are publishable: 0-FAIL on the pinned check set.

    Read from the census, which is where the published matrix numbers come from. Returns None
    if no census is present -- the claim set is then unknowable and --tracked reports without
    gating rather than inventing a verdict. (tools/tier-status.py reads the census the same
    way; both are gitignored-scratch-dependent by design.)
    """
    census = REPO / "output" / "scratch" / "census"
    if not census.is_dir():
        return None
    out = set()
    found = False
    for p in sorted(census.glob("*.json")):
        found = True
        try:
            doc = json.loads(p.read_text())
        except Exception:
            continue
        if doc.get("summary", {}).get("failed") == 0 and digest(check_set(doc)) == expected:
            out.add(p.stem)
    return out if found else None


def tracked_gate(expected, quiet=False):
    paths = sorted(REPO.glob(TRACKED_GLOB))
    if not paths:
        print("check-set-gate --tracked: no tracked reports found", file=sys.stderr)
        return 2
    if expected is None:
        print("check-set-gate --tracked: no core_executed_check_set_digest in "
              "tools/oracle-pin.env — cannot gate tracked reports", file=sys.stderr)
        return 2

    claims = publishable_peers(expected)
    rows = []
    for p in paths:
        peer = peer_key(p)
        try:
            doc = json.loads(p.read_text())
        except Exception as e:
            rows.append((peer, None, 0, f"UNREADABLE ({type(e).__name__})", None))
            continue
        names = check_set(doc)
        s = doc.get("summary", {})
        rows.append((peer, digest(names), len(names), None, s))

    current = [r for r in rows if r[1] == expected]
    behind = [r for r in rows if r[1] != expected]

    print(f"check-set gate (--tracked) — {len(rows)} committed per-peer reports")
    print(f"  expected digest : {expected}")
    print(f"  at pinned set   : {len(current)} / {len(rows)}")

    if claims is None:
        print("\n  NOTE: no census present, so the publishable-claim set is unknown.")
        print("  Reporting only — run tools/run-cohort-census.sh to enable gating.")

    expected_size = current[0][2] if current else None
    if behind and not quiet:
        want = expected_size if expected_size is not None else "?"
        print(f"\n  {len(behind)} report(s) NOT at the pinned check set:")
        for peer, h, n, err, _s in sorted(behind, key=lambda r: r[0]):
            if err:
                print(f"    {peer:24s} {err}")
            else:
                print(f"    {peer:24s} {n} checks (expected {want})  digest {h[:12]}…")
    elif behind:
        print(f"  behind the pin  : {len(behind)} (disclosed debt — matrix §3; "
              f"re-run with --tracked for the list)")

    # Gate only the peers we CLAIM are publishable. Disclosed, tracked debt (peers still
    # owing the CAP fix) is reported above but must not hold the gate red forever.
    if not claims:
        print("\nPASS (reporting only — nothing gated).")
        return 0

    stale_claims = sorted(r[0] for r in behind if r[0] in claims)
    print(f"\n  publishable peers (0-FAIL at pin) : {len(claims)}")
    print(f"  of those, stale committed report  : {len(stale_claims)}")

    if not stale_claims:
        print("\nPASS — every peer claimed publishable has a committed report at the pinned")
        print("check set. A clone reads the same numbers the matrix publishes.")
        return 0

    print(f"\nFAIL — {len(stale_claims)} peer(s) are published as 0-FAIL at the current pin while")
    print("their COMMITTED status/CONFORMANCE-REPORT.json is from an older check set.")
    print("A clone of this repo shows those peers contradicting CONFORMANCE-MATRIX.md §1.\n")
    for peer in stale_claims:
        print(f"  {peer}")
    print("\nRefresh with:  tools/run-cohort-census.sh --to-status " + " ".join(stale_claims))
    print("It is a MEASUREMENT — never hand-copy a census JSON onto a tracked report.")
    return 1


def main(argv):
    if "--tracked" in argv:
        return tracked_gate(pinned_digest(), quiet="--quiet" in argv)

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
