#!/usr/bin/env python3
"""Per-peer verification for a cohort sweep: did this change move any verdict?

The standing verification standard for a sweep is not "the summary looks right".
It is: run BOTH check sets, diff PER CHECK, assert the denominator is non-zero,
and refuse a starved run.  This tool is the per-peer half of that.

    tools/sweep-verify.py --pinned <peer> [...]        # vs the peer's TRACKED report
    tools/sweep-verify.py --candidate <json> <peer>    # a candidate-oracle report

WHY THIS EXISTS RATHER THAN output/scratch/sevdiff.py
  That script's starvation guard reads `report["categories"]`, and these reports
  carry no such key -- it is `checks`, flat, with the category on each check.  So
  the guard could never fire: it examined zero things and printed the same word as
  one that examined 778.  It is the class AGENTS.md records against gates, sitting
  in the instrument used to certify that a gate did not move.  Three assertions
  here answer the three ways a comparison can be vacuous:

    * DENOMINATOR non-zero -- a diff over an empty check map reports "0 moved",
      which is the same string a clean run prints.
    * BUDGET not exhausted -- a starved run files whole categories under `skipped`
      and its P/W/F/S is a floor, not a result.  Scanned over the RAW TEXT, because
      the marker's location in the schema is exactly what the old guard got wrong.
    * NAME COVERAGE -- if the two reports share almost no check names the diff is
      measuring a schema change, not a verdict change, and "everything moved" and
      "nothing moved" are both meaningless.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def sevmap(report):
    """Severity per check, keyed by (CATEGORY, NAME) and disambiguated by ordinal.

    NOT by `name` alone.  Measured on the first peer this tool was pointed at: a
    778-check report collapses to 740 distinct names, so 38 checks share a name
    with another and a dict keyed on `name` silently drops all but the last -- a
    moved severity on any of them is invisible, and the tool prints "moved 0 of
    740" beside a summary saying 778.  Only printing the denominator showed it.
    That is the `Path.stem` collision AGENTS.md already records against
    check-set-gate, in the instrument written to certify that nothing moved.

    The ordinal suffix is what makes the key TOTAL: two checks can share a name
    WITHIN one category (the oracle runs some parametrized checks more than once),
    and (category, name) alone still collapses those.  Run order is stable across
    runs of the same check set, which is the property that makes the ordinal a
    valid key rather than noise.
    """
    out, seen = {}, {}
    for c in report.get("checks", []):
        key = (c.get("category", ""), c.get("name", ""))
        n = seen.get(key, 0)
        seen[key] = n + 1
        out[key + (n,)] = c["severity"]
    return out


def fmt(s):
    return (f"{s['total']} · {s['passed']}P/{s['warned']}W/"
            f"{s['failed']}F/{s['skipped']}S")


def load(path):
    raw = path.read_text()
    return json.loads(raw), raw


def compare(label, fresh_path, base_path):
    """Returns (ok, lines).  ok is False for any vacuity or any moved severity."""
    lines = []
    if not fresh_path.exists():
        return False, [f"{label:24} NO REPORT at {fresh_path}"]
    if not base_path.exists():
        return False, [f"{label:24} NO BASELINE at {base_path}"]
    fresh, fresh_raw = load(fresh_path)
    base, _ = load(base_path)
    a, b = sevmap(fresh), sevmap(base)

    ok = True
    # (1) denominator
    if not b or not a:
        lines.append(f"{label:24} !! EMPTY CHECK MAP (fresh {len(a)}, base {len(b)}) "
                     "-- the diff below would be vacuous")
        return False, lines
    # (2) starvation, over the raw text
    if "budget_exhausted" in fresh_raw:
        lines.append(f"{label:24} !! BUDGET EXHAUSTED -- incomplete measurement, "
                     "P/W/F/S is a floor")
        ok = False
    # (3) name coverage
    shared = set(a) & set(b)
    if len(shared) < 0.9 * min(len(a), len(b)):
        lines.append(f"{label:24} !! ONLY {len(shared)} shared check names of "
                     f"{len(a)}/{len(b)} -- comparing different check sets")
        ok = False

    moved = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    lines.append(f"{label:24} fresh {fmt(fresh['summary'])} | base {fmt(base['summary'])} "
                 f"| moved {len(moved)} of {len(b)}")
    for k in moved:
        lines.append(f"    {k[0]}/{k[1]}: {b.get(k)} -> {a.get(k)}")
    if moved:
        ok = False
    if fresh["summary"]["failed"]:
        lines.append(f"    !! {fresh['summary']['failed']} FAIL(s) in the fresh report")
        ok = False
    return ok, lines


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    rc = 0
    if mode == "--pinned":
        for peer in argv[2:]:
            ok, lines = compare(
                peer,
                ROOT / "output/scratch/census" / f"{peer}.json",
                ROOT / "protocol-generator" / peer / "status/CONFORMANCE-REPORT.json",
            )
            print("\n".join(lines))
            rc |= 0 if ok else 1
    elif mode == "--candidate":
        # A candidate-oracle report has no tracked baseline to diff against -- the
        # check set is different by construction.  What it must show is 0 FAIL and
        # a non-starved, non-empty run, so it is compared against ITSELF for the
        # vacuity assertions and reported on its summary.
        for path in argv[2:]:
            p = pathlib.Path(path)
            if not p.exists():
                print(f"{p.name:24} NO REPORT")
                rc |= 1
                continue
            d, raw = load(p)
            checks = sevmap(d)
            bad = []
            if not checks:
                bad.append("EMPTY CHECK MAP")
            if "budget_exhausted" in raw:
                bad.append("BUDGET EXHAUSTED")
            if d["summary"]["failed"]:
                bad.append(f"{d['summary']['failed']} FAIL")
            print(f"{p.stem:24} {fmt(d['summary'])} over {len(checks)} checks"
                  + ("   !! " + " / ".join(bad) if bad else "   OK"))
            for c in d.get("checks", []):
                if c["severity"] == "FAIL":
                    print(f"    FAIL {c['category']}/{c['name']}: {c['message'][:140]}")
            rc |= 1 if bad else 0
    else:
        print(__doc__)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
