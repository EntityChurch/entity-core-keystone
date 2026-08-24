#!/usr/bin/env python3
"""link-gate — every relative markdown link in the tree must resolve on disk.

WHY THIS EXISTS. The release pipeline runs six gates and this repo runs three more, and
between the nine of them **not one asks whether a published document points at something a
reader can open.** leak-audit asks whether it is safe to publish; conform-audit whether it
conforms; public-regress whether anything vanished; check-set-gate whether the numbers are
comparable; pin-gate whether the anchors resolve. All nine would pass a tree in which every
internal link is broken.

Measured 2026-08-23, the release sweep: `protocol-generator/fortran/status/` had been citing
two spec findings at `research/stewardship/HANDOFF-TO-ARCH-*.md` paths that had not existed
since those findings were archived weeks earlier — dangling out of a PUBLISHED file, past
every gate, for weeks. Nobody found it by reading. This finds it in a second.

WHAT IT DOES NOT CATCH, and the limit is the point rather than an apology:

  * a path in backticks rather than a markdown link — most of this repo's cross-references
    are inline code, deliberately, because they are paths and not navigation;
  * a truncated path split across a wrapped line (the class that already burned us once:
    a backtick span that WRAPS is invisible to a per-line scan, so README's headline number
    sat anchored to a dead identifier with the gate reporting clean);
  * a path a TOOL prints at runtime — `check-set-gate.py` names a diagnostic as the reader's
    next step, and that diagnostic was being deleted at release;
  * a link that resolves but points at the wrong thing.

So this is the cheap floor, not the coverage story. **The hand-walk of the published tree
stays mandatory** (AGENTS.md, "no gate asks whether the published tree is internally
coherent"). A gate that made people feel the walk was covered would be worse than no gate.

Exit 0 clean, 1 on any broken link.
"""

import os
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# `[text](target)` — target up to the first '#', ')' or whitespace.
LINK = re.compile(r"\[[^\]]*\]\(\s*([^)\s#]+)(?:#[^)]*)?\s*\)")

# Skipped wholesale: the ecosystem ADRs are byte-identical copies of files authored in
# another repo, where their relative links resolve. They are undeclared, they strip at
# release by standing ruling, and editing them here is forbidden — so their links are
# neither ours to fix nor a public reader's to follow. (Hand-synced; there is no automated
# transport, and that is deliberate rather than pending.)
SKIP_PREFIXES = ("docs/adr/ecosystem/",)


def tracked_markdown():
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    for rel in out.split("\0"):
        if rel and not rel.startswith(SKIP_PREFIXES):
            yield rel


def main() -> int:
    quiet = "--quiet" in sys.argv
    broken = []
    n_files = n_links = 0

    for rel in tracked_markdown():
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        n_files += 1
        for m in LINK.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "//")):
                continue
            n_links += 1
            if not (path.parent / target).exists():
                line = text.count("\n", 0, m.start()) + 1
                broken.append((rel, line, target))

    if broken:
        print(f"link-gate: {len(broken)} BROKEN relative link(s):", file=sys.stderr)
        for rel, line, target in broken:
            print(f"  {rel}:{line}  ->  {target}", file=sys.stderr)
        print(
            "\nA link is broken when the referrer moved, not only when the target did — "
            "check both sides before fixing.",
            file=sys.stderr,
        )
        return 1

    if not quiet:
        print(f"link-gate: OK — {n_links} relative links across {n_files} files all resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
