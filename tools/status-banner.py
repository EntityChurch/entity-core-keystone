#!/usr/bin/env python3
"""status-banner.py — front a peer's prose conformance report with its CURRENT measurement.

WHY THIS EXISTS
---------------
`tools/check-set-gate.py --tracked` gates the machine-readable
`protocol-generator/<peer>/status/CONFORMANCE-REPORT.json`. Nothing gates the `.md`
beside it, and the `.md` is what a human opens first. Measured 2026-08-22: several
led with `cc1970f`/`b30a589`-era banners quoting `552`/`576` totals while §1 published
fresh numbers -- the peer's own directory contradicting its published row.

That was fixed by hand for the 13 peers publishable at the time. Doing it by hand a
second time, for the ~25 peers the CAP propagation moves to 0-FAIL, is how the two
copies drift apart again -- and AGENTS.md already records what a hand pass over
prose reports costs: the 2026-08-22 one asserted history that did not exist for
`lean`, which had never had a `.md` at all.

So the banner is GENERATED, from the peer's own tracked JSON, and it asserts nothing
it cannot read out of that file.

WHAT IT REFUSES TO DO
---------------------
- It will not write a banner from a report that is not at the pinned check set. A
  banner is a publication of a number; publishing one off a stale or starved
  measurement is the exact defect this file exists to prevent.
- It will not claim "everything below predates this measurement" when there is
  nothing below. A new `.md` gets the banner and no such sentence.
- It does not measure anything. Refreshing the JSON is
  `tools/run-cohort-census.sh --to-status <peer>` (or the peer's own `run-s4.sh`),
  and that is a MEASUREMENT, never a file copy.

USAGE
-----
    tools/status-banner.py <peer> [<peer>...]     # write/refresh the banner
    tools/status-banner.py --check <peer>...      # report drift, write nothing
"""
import hashlib
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PIN = REPO / "tools" / "oracle-pin.env"
MARKER = "<!-- current-pin-banner:"


def pin_values():
    out = {}
    for line in PIN.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def check_set_digest(doc):
    names = sorted(f'{c["category"]}/{c["name"]}' for c in doc.get("checks", []))
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def banner(peer, doc, pin, has_history):
    """The banner cites the check-set DIGEST, never the oracle's commit.

    [ADR-0012] Amendment 1: published commits are authored fresh at the release
    boundary ([ADR-0027]), so a `dev` SHA resolves for no reader outside this repo
    and never will -- `oracle-pin.env` says so in as many words ("THE PIN IS THE
    THREE CONTENT DIGESTS; `ref` and `commit` are an internal convenience and are
    NOT part of any published claim"). These reports publish. The 2026-08-22 hand
    pass wrote `oracle entity-core-go @ c1b0708` into all thirteen; generating the
    banner is what stops that spreading to the rest of the cohort.
    """
    s = doc["summary"]
    date = doc["timestamp"][:10]
    executed = check_set_digest(doc)
    verdict = "PASS, 0 FAIL" if s["failed"] == 0 else f'FAIL, {s["failed"]} FAIL'
    lines = [
        f"{MARKER}{executed[:12]} -->",
        f'> **CURRENT ({date}) — spec snapshot `{pin["spec_snapshot"].split()[0]}`, '
        f"executed check set `{executed[:12]}…`.**",
        f'> `validate-peer --profile core` → **{verdict}** · '
        f'**{s["total"]} total · {s["passed"]} pass · {s["warned"]} warn · '
        f'{s["failed"]} FAIL · {s["skipped"]} skip** (elapsed {s["elapsed_ms"]} ms).',
        ">",
        "> That digest is the pinned `core_executed_check_set_digest`, so this number is",
        "> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT",
        "> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).",
        "> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative",
        "> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated",
        "> from it by `tools/status-banner.py` rather than typed.",
    ]
    if has_history:
        lines += [
            ">",
            "> **Everything below this line predates this measurement and is retained as build",
            "> history.** Where it disagrees with the figures above, the figures above win;",
            "> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.",
        ]
    return "\n".join(lines) + "\n\n---\n\n"


def strip_existing(text):
    """Remove a previously generated banner, leaving the authored history untouched."""
    if not text.startswith(MARKER):
        return text
    parts = re.split(r"\n---\n\n?", text, maxsplit=1)
    return parts[1] if len(parts) == 2 else ""


def main(argv):
    check_only = "--check" in argv
    peers = [a for a in argv if not a.startswith("-")]
    if not peers:
        print(__doc__.strip().splitlines()[-3], file=sys.stderr)
        return 2
    pin = pin_values()
    expected = pin.get("core_executed_check_set_digest")
    rc = 0
    for peer in peers:
        sdir = REPO / "protocol-generator" / peer / "status"
        jpath, mpath = sdir / "CONFORMANCE-REPORT.json", sdir / "CONFORMANCE-REPORT.md"
        if not jpath.exists():
            print(f"{peer}: no tracked CONFORMANCE-REPORT.json", file=sys.stderr)
            rc = 1
            continue
        doc = json.loads(jpath.read_text())
        got = check_set_digest(doc)
        if expected and got != expected:
            print(f"{peer}: REFUSED — report is at check set {got[:12]}…, "
                  f"pin expects {expected[:12]}… (re-measure, do not hand-edit)", file=sys.stderr)
            rc = 1
            continue
        history = strip_existing(mpath.read_text() if mpath.exists() else "")
        new = banner(peer, doc, pin, has_history=bool(history.strip())) + history
        if check_only:
            state = "current" if mpath.exists() and mpath.read_text() == new else "DRIFTED"
            print(f"{peer}: {state}")
            rc = rc or (state == "DRIFTED")
            continue
        mpath.write_text(new)
        s = doc["summary"]
        print(f'{peer}: banner written — {s["total"]} · {s["failed"]}F'
              f' ({s["passed"]}P/{s["warned"]}W/{s["failed"]}F/{s["skipped"]}S)')
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
