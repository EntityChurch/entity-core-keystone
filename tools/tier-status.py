#!/usr/bin/env python3
"""tier-status.py — where every peer stands, per maintenance tier.

The tier policy (CONFORMANCE-MATRIX.md §4) says M1 re-runs on every oracle re-pin and the
lower tiers catch up as capacity allows. That is only workable if "which tiers are caught up"
is a question with a cheap, exact answer. This is that answer.

    tools/tier-status.py              # per-tier summary + anything not current
    tools/tier-status.py --full       # every peer, one line each
    tools/tier-status.py --tier M1    # one tier
    tools/tier-status.py --gate       # exit non-zero unless M1 is current AND 0-FAIL

Sources, each with one canonical home:
    tools/peer-tiers.tsv    tier assignment + last_measured_pin   (the roster)
    tools/oracle-pin.env    the current pin (`ref`)
    output/scratch/census/  the verdicts from the last census     (gitignored)
    output/scratch/reverify/ post-rebuild re-verifications, which win ONLY IF NEWER

A peer whose last_measured_pin != the current ref is STALE. Stale is a tracked state, not a
failure — it means "this peer's recorded verdict was true at an older oracle and has not been
re-measured", which is exactly what a tier policy is for.
"""
from __future__ import annotations
import sys, json, pathlib, collections

REPO = pathlib.Path(__file__).resolve().parent.parent
ROSTER = REPO / "tools" / "peer-tiers.tsv"
PIN = REPO / "tools" / "oracle-pin.env"
CENSUS = REPO / "output" / "scratch" / "census"
REVERIFY = REPO / "output" / "scratch" / "reverify"

TIER_ORDER = ["M1", "M2", "M3", "probe", "exploratory"]
TIER_DESC = {
    "M1": "lockstep — re-run on EVERY re-pin; gates the re-pin",
    "M2": "priority catch-up — after M1 converges",
    "M3": "on-demand — spare capacity / pre-release / adopter ask",
    "probe": "paradigm probe — when its axis is touched, or pre-release",
    "exploratory": "not a deployable peer — never gates",
}


def read_roster():
    rows = []
    for line in ROSTER.read_text().splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("peer\t"):
            continue
        f = line.split("\t")
        rows.append({"peer": f[0], "tier": f[1], "pin": f[2],
                     "note": f[3] if len(f) > 3 else ""})
    return rows


def current_ref():
    for line in PIN.read_text().splitlines():
        if line.strip().startswith("ref ") or line.strip().startswith("ref="):
            return line.split("=", 1)[1].strip().split()[0]
    return "?"


def verdicts():
    """Census verdicts, with the reverify overlay applied ONLY WHERE IT IS NEWER.

    The overlay exists so a post-rebuild re-verification supersedes a stale census row
    (an isolated-worktree fix whose build cache the census reused). That is right in
    intent, and it was applied UNCONDITIONALLY -- which is wrong the moment the overlay
    is the older file. `output/scratch/reverify/` is scoped to neither a run nor an
    oracle pin, so a report left there survives every later census indefinitely.

    Measured 2026-08-28: three reports written on 2026-08-17 at the retired de8f807
    740-check pin were still overriding the 2026-08-21 c1b0708 census, so `node-red`,
    `rust-wasm` and `rust-wasm-wasmtime` displayed as current-and-0-FAIL on 11-day-old
    evidence measured against a DIFFERENT check set. The fresh census says 3F for all
    three. Nothing published moved -- `check-set-gate.py --tracked` reads the committed
    reports and correctly counted those three as behind the pin -- but `--gate` and the
    tier counts here were reading the past over the present.

    THIS IS THE IDENTICAL DEFECT check-set-gate.py CARRIED, FIXED THERE ON 2026-08-22,
    AND NOT CHECKED FOR HERE. AGENTS.md states the rule that would have caught it in the
    same breath as the first fix -- "when you harden one anchor, check its siblings for
    the same defect the same day" -- and the sibling is the file next to it that reads
    the same directory. An input that PREDATES what it supersedes is not an override, it
    is drift.

    THIRD SOURCE, added 2026-09-01, and it is the same class ONE SOURCE OVER: the
    docstring above fixed the overlay's recency and never asked whether the set of
    sources was complete. It was not. `run-cohort-census.sh` has TWO destinations --
    `output/scratch/census/` by default and the peers' TRACKED
    `status/CONFORMANCE-REPORT.json` under `--to-status` -- and this function only ever
    knew about the first. So a `--to-status` run, which is the documented way to refresh
    the committed record, leaves `output/scratch/census/` untouched and this tool reports
    the PREVIOUS census's verdicts indefinitely.

    Measured 2026-09-01: the PD-1 fix took `pd` `asm-x86_64` `asm-arm64` `riscv64`
    `wasm-wat` to 756 / 0F, the tracked reports said so, and `tier-status` printed
    FAIL(1) for all five off pre-fix scratch files. The benign direction is the one we
    hit; THE DANGEROUS DIRECTION IS THE INVERSE -- a peer that REGRESSED and was then
    refreshed with `--to-status` would keep displaying its old GREEN verdict here, and
    `--gate` would pass on it.

    A tracked report is a MEASUREMENT (`--to-status` re-runs the peer; hand-copying a
    census JSON onto it is forbidden precisely so this holds), so it ranks by recency
    beside the other two rather than being a special case.

    Keyed by the peer DIRECTORY, never by `Path.stem`: every tracked report is named
    `CONFORMANCE-REPORT.json`, so `stem` collapses all 46 into one entry -- the exact
    collision check-set-gate.py shipped and had to be fixed for.
    """
    def load(p):
        try:
            doc = json.loads(p.read_text())
        except Exception:
            return None
        s = doc.get("summary", {})
        starved = sorted({c["category"] for c in doc.get("checks", [])
                          if "budget_exhausted" in (c.get("message") or "")})
        return {"F": s.get("failed"), "total": s.get("total"),
                "P": s.get("passed"), "W": s.get("warned"),
                "S": s.get("skipped"), "starved": starved}

    out, seen_mtime = {}, {}
    if CENSUS.is_dir():
        for p in sorted(CENSUS.glob("*.json")):
            v = load(p)
            if v is not None:
                out[p.stem], seen_mtime[p.stem] = v, p.stat().st_mtime
    if REVERIFY.is_dir():
        for p in sorted(REVERIFY.glob("*.json")):
            prev = seen_mtime.get(p.stem)
            if prev is not None and p.stat().st_mtime <= prev:
                print(f"tier-status: ignoring stale reverify overlay for {p.stem} "
                      f"(older than the census report it would replace)", file=sys.stderr)
                continue
            v = load(p)
            if v is not None:
                out[p.stem], seen_mtime[p.stem] = v, p.stat().st_mtime
    # Tracked reports (`run-cohort-census.sh --to-status`), same newer-wins rule. Keyed
    # by the peer directory -- p.stem is "CONFORMANCE-REPORT" for all 46.
    for p in sorted((REPO / "protocol-generator").glob("*/status/CONFORMANCE-REPORT.json")):
        peer = p.parent.parent.name
        prev = seen_mtime.get(peer)
        if prev is not None and p.stat().st_mtime <= prev:
            continue
        v = load(p)
        if v is not None:
            out[peer], seen_mtime[peer] = v, p.stat().st_mtime
    return out


def state(row, ref, v):
    if row["pin"] == "none":
        return "UNMEASURED"
    if row["pin"] != ref:
        return f"STALE@{row['pin']}"
    if v is None:
        return "NO-REPORT"
    if v["starved"]:
        return "INVALID"
    return "0-FAIL" if v["F"] == 0 else f"FAIL({v['F']})"


def main(argv):
    full = "--full" in argv
    gate = "--gate" in argv
    only = None
    if "--tier" in argv:
        only = argv[argv.index("--tier") + 1]

    rows, ref, V = read_roster(), current_ref(), verdicts()
    print(f"maintenance-tier status — current oracle pin: {ref}")
    print("(maintenance tiers govern RE-MEASUREMENT CADENCE only; they are not")
    print(" research/LANDSCAPE.md's selection tiers, and they never gate publication)\n")

    by = collections.defaultdict(list)
    for r in rows:
        by[r["tier"]].append(r)

    rc = 0
    for tier in TIER_ORDER:
        if only and tier != only:
            continue
        group = by.get(tier, [])
        if not group:
            continue
        st = {r["peer"]: state(r, ref, V.get(r["peer"])) for r in group}
        cur = [p for p, s in st.items() if s == "0-FAIL"]
        prob = {p: s for p, s in st.items() if s != "0-FAIL"}
        flag = "" if not prob else "   <-- catch-up owed" if tier in ("M1", "M2") else "   <-- backlog"
        print(f"  {tier:12s} {len(cur):2d}/{len(group):2d} current & 0-FAIL   "
              f"[{TIER_DESC[tier]}]{flag}")
        for p in sorted(prob):
            note = next(r["note"] for r in group if r["peer"] == p)
            print(f"      {p:22s} {prob[p]:16s} {note[:72]}")
        if full:
            for p in sorted(cur):
                v = V.get(p, {})
                print(f"      {p:22s} {st[p]:16s} "
                      f"{v.get('total')}·{v.get('F')}F — "
                      f"{v.get('P')}P/{v.get('W')}W/{v.get('F')}F/{v.get('S')}S")
        print()

    m1 = by.get("M1", [])
    m1bad = [r["peer"] for r in m1 if state(r, ref, V.get(r["peer"])) != "0-FAIL"]
    if m1bad:
        print(f"M1 IS NOT CURRENT: {', '.join(m1bad)}")
        print("Per §4, an oracle re-pin is not landed until M1 is current and 0-FAIL.")
        rc = 1
    else:
        print(f"M1 is current and 0-FAIL at {ref} — the re-pin is landed; lower tiers may lag.")

    if gate:
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
