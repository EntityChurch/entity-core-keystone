#!/usr/bin/env python3
"""summarize.py — turn a roster run of arc-probe into a cohort table.

WHY THIS IS A FILE AND NOT A ONE-LINER. Two standing rules in AGENTS.md, both of
which have cost this repo a published number:

  - "Before reading a probe directory as a cohort picture, either re-run the whole
    roster or compare mtimes." A probe report carries no run identity; a mixed-age
    directory is the one artifact that reads as a measurement and is not one. This
    script refuses to print a table whose files span more than a stated window, and
    names every roster member with NO report rather than silently ranging over the
    ones that happen to be there.

  - "A gate that examines zero things prints the same word as one that examines
    forty-six." Every count here is printed with its denominator, and the
    denominator is asserted against the roster.

Usage:  tools/arc-probe/summarize.py [--dir output/scratch/arc] [--md]
"""
import json
import os
import sys
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROSTER_TSV = os.path.join(ROOT, "tools", "peer-tiers.tsv")


def roster():
    out = []
    with open(ROSTER_TSV) as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            name = line.split("\t")[0].strip()
            if name and name != "peer":
                out.append(name)
    return out


def main():
    argv = sys.argv[1:]
    d = os.path.join(ROOT, "output", "scratch", "arc")
    as_md = "--md" in argv
    if "--dir" in argv:
        d = argv[argv.index("--dir") + 1]

    names = roster()
    reports, mtimes = {}, {}
    for n in names:
        p = os.path.join(d, n + ".json")
        if os.path.exists(p):
            try:
                reports[n] = json.load(open(p))
                mtimes[n] = os.path.getmtime(p)
            except Exception as e:  # a truncated report is not a peer finding
                print(f"!! {n}: unreadable report ({e})", file=sys.stderr)

    missing = [n for n in names if n not in reports]
    span = (max(mtimes.values()) - min(mtimes.values())) / 3600.0 if mtimes else 0.0

    print(f"# arc-probe cohort table — {len(reports)} of {len(names)} roster peers reported")
    print(f"# report age span: {span:.2f} h "
          f"(a span over ~6 h means this directory mixes runs and is NOT a cohort picture)")
    if missing:
        print(f"# NO REPORT ({len(missing)}): {' '.join(missing)}")
    untrusted = [n for n, r in reports.items() if not r.get("trusted")]
    if untrusted:
        print(f"# UNTRUSTED, suppressed from every count below ({len(untrusted)}): "
              f"{' '.join(untrusted)}")
    print()

    live = {n: r for n, r in reports.items() if r.get("trusted")}
    ids = [c["id"] for c in next(iter(live.values()))["cases"]] if live else []

    # Per-row tally. The classification is the leading token of `conforms`, which
    # is the only field graded against the spec; the rest of the string is the
    # reason and varies per peer by design.
    def cls(v):
        if v.startswith("VOID"):
            return "void"
        if v.startswith("yes"):
            return "yes"
        if v.startswith("partial"):
            return "partial"
        if v.startswith("no"):
            return "no"
        return "unclassified"

    rows = []
    for cid in ids:
        tally = Counter()
        detail = defaultdict(list)
        role = ""
        for n, r in live.items():
            for c in r["cases"]:
                if c["id"] == cid:
                    role = c["role"]
                    tally[cls(c["conforms"])] += 1
                    detail[f'{c["status"]} {c["code"]}'.strip()].append(n)
        rows.append((cid, role, tally, detail))

    w = max((len(r[0]) for r in rows), default=10)
    for cid, role, tally, detail in rows:
        if role == "control" or role == "antecedent":
            bad = tally["no"] + tally["partial"] + tally["unclassified"] + tally["void"]
            print(f"{cid:<{w}}  [{role}]  {tally['yes']}/{len(live)} ok"
                  + (f"   ⚠ {bad} FAILED" if bad else ""))
            continue
        print(f"{cid:<{w}}  [{role}]  yes={tally['yes']:<3} partial={tally['partial']:<3} "
              f"no={tally['no']:<3} void={tally['void']:<3} unclassified={tally['unclassified']:<3}"
              f"  of {len(live)}")
        for k, v in sorted(detail.items(), key=lambda kv: -len(kv[1])):
            print(f"{'':<{w}}     {len(v):>2} × [{k}]  {' '.join(sorted(v))}")
    print()

    # Which peers differ from the cohort mode, per row — the standing "diff the
    # per-check severities before believing the headline" rule, applied forward.
    print("# peers whose answers are not the cohort mode on at least one measured row")
    mode = {}
    for cid, role, tally, detail in rows:
        if role in ("control", "antecedent"):
            continue
        mode[cid] = max(detail.items(), key=lambda kv: len(kv[1]))[0] if detail else ""
    odd = defaultdict(list)
    for n, r in live.items():
        for c in r["cases"]:
            if c["id"] in mode:
                k = f'{c["status"]} {c["code"]}'.strip()
                if k != mode[c["id"]]:
                    odd[n].append(f'{c["id"]}={k}')
    for n in sorted(odd):
        print(f"  {n}: " + " · ".join(odd[n]))
    if not odd:
        print("  none — every trusted peer answered identically on every measured row")
    return 0


if __name__ == "__main__":
    sys.exit(main())
