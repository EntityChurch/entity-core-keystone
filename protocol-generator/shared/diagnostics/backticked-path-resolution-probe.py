#!/usr/bin/env python3
"""Resolve every BACKTICKED inline path in tracked markdown, and report the ones that do not.

WHY THIS IS A PROBE AND NOT A GATE — the measurement is the point, and it is what
disqualified the gate. `tools/link-gate.py` check 1 resolves markdown `[](...)` links;
check 2 catches a published file naming a path the release STRIPS. Neither can see a
backticked inline path that resolves to nothing, which is how a citation to a file that
NEVER EXISTED sat in a published file for months (`HANDOFF-FROM-ARCH-v1.md`, cited from
`shared/lifecycle/PROMPT-CONSTANTS.md`, named as a known defect in [ADR-0021]'s follow-up
list, `git log --all` empty).

The obvious gate does not survive contact with the tree. Measured 2026-09-09:

    every backticked *.md path      863 candidates -> 318 unresolved
    scoped to repo-rooted paths     418 candidates ->  38 unresolved

The 318 are overwhelmingly ROOT-RELATIVE SHORTHAND — `status/PHASE-S2.md` means "this
peer's", `arch/PROFILE-RATIONALE.md` likewise — which is correct prose and unresolvable
by construction. Even the scoped 38 carry an irreducible ambiguity: `docs/` is a top-level
directory HERE and in every sibling repo, so `docs/spec/SPEC-KEYSTONE-PEER.md` (the
generator's) is indistinguishable from one of ours by path alone.

A check that cannot separate its signal from its noise is not a weak check, it is a broken
one -- scope it or drop it, and say which. This one is scoped to a probe and said so.

WHAT THE 38 ACTUALLY ARE, so a future reader does not re-triage them:
  * ~15  `research/RELEASE-READINESS.md` -- the peer-selection "slate" cited by cpp/dart/
         kotlin/php phase records. NEVER existed in this repo's history; it was a planning
         artifact elsewhere. NOT rewritten: these are dated phase records, and a dated
         snapshot that gets back-edited stops being evidence of anything.
  * ~10  sibling-repo paths (`docs/spec/…`, `docs/status/WORK-STATUS.md`, `docs/validation/…`)
  *   3  `docs/status/STATUS.md` -- correct at the time; [ADR-0031] moved it to `docs/STATUS.md`.
         Two of the three are inside the finding that DOCUMENTS that move.
  *   1  a retired `spec-data/v7.56/` snapshot, cited historically by the findings register.

THE ONE DISTINCTION THAT DECIDES WHETHER TO FIX A HIT, and it is not "does it resolve":
a LIVE INSTRUCTION ("escalate per `X`") that names a dead path is a defect, because a
reader is being sent somewhere on purpose. A PROVENANCE CITATION in a dated record is
evidence of what was true then, and rewriting it is the damage. Fix the first, leave the
second, and never sweep the two together.

Usage:  python3 protocol-generator/shared/diagnostics/backticked-path-resolution-probe.py [--all]
        --all   drop the repo-rooted scoping (shows the full 863/318 noise floor)
"""

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]

# Immutable-snapshot tiers plus the injected ecosystem ADRs: deliberately left pointing at
# old names, and not ours to edit. `FINDINGS-MOVED.md` is the old->new map itself, so every
# left-hand path in it is dead ON PURPOSE.
SKIP_PREFIXES = ("docs/adr/ecosystem/", "docs/status/", "docs/archive/")
SKIP_FILES = {
    "research/stewardship/FINDINGS-MOVED.md",
    "protocol-generator/shared/diagnostics/backticked-path-resolution-probe.py",
}

# A backticked path ending .md. Requires a leading alnum so `../x.md` and glob forms fall out.
PATH = re.compile(r"`([A-Za-z0-9._][A-Za-z0-9._/-]*\.md)`")


def repo_roots():
    return tuple(
        sorted(p.name + "/" for p in REPO.iterdir() if p.is_dir() and not p.name.startswith("."))
    )


def tracked_markdown():
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    for rel in out.split("\0"):
        if rel and not rel.startswith(SKIP_PREFIXES) and rel not in SKIP_FILES:
            yield rel


def main() -> int:
    scoped = "--all" not in sys.argv
    roots = repo_roots()
    examined = 0
    unresolved = []

    for rel in tracked_markdown():
        try:
            text = (REPO / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in PATH.finditer(text):
            target = m.group(1)
            if any(c in target for c in "*<>$"):  # globs and <lang> placeholders
                continue
            if scoped:
                if not target.startswith(roots):
                    continue
            elif "/" not in target:
                continue
            examined += 1
            here = REPO / rel
            if (REPO / target).exists() or (here.parent / target).exists():
                continue
            unresolved.append((rel, text.count("\n", 0, m.start()) + 1, target))

    mode = "repo-rooted" if scoped else "all backticked"
    print(f"backticked-path probe — {mode} .md citations")
    print(f"  examined   : {examined}")
    print(f"  unresolved : {len(unresolved)}")
    for rel, line, target in sorted(set(unresolved)):
        print(f"    {rel}:{line}  ->  {target}")
    if unresolved:
        print(
            "\nA hit is a DEFECT only if it is a live instruction pointing a reader somewhere.\n"
            "A provenance citation in a dated record is evidence — leave it. See this file's\n"
            "docstring for the standing triage of the current set."
        )
    return 0  # a probe measures; it never gates


if __name__ == "__main__":
    raise SystemExit(main())
