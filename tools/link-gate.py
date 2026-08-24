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

CHECK 2 — no published file may NAME a path the release strips.

A link that resolves on disk can still be dead for a reader, because `canon-filter` deletes
undeclared prose under a doc root on the way out. Check 1 cannot see this: the target exists
here. This check replays the filter's rule (prose-only, doc-root prefixes — read from
`internal/canon/canon.go`, and re-read it, because that rule was silently corrected once) and
scans every file that survives it for a path that does not.

It reads the JOINED text, not lines, so a path wrapped across a line break with a comment
prefix on the continuation still matches. That is not hypothetical: two of the three
citations this check was built for were exactly that shape, in a `.c` and an `.s`, and a
`.md`-only per-line grep found neither.

**Severity is split, deliberately, on the same principle as `check-set-gate`'s disclosed
debt.** Non-prose citations — source, scripts, configs — FAIL: they are shipped engineering
provenance and the set is small and actionable. Prose-to-prose citations are REPORTED and do
not fail: ~25 of those are dated internal snapshots cited from published docs, measured and
parked by operator ruling. Hard-failing them would leave the gate permanently red, which
teaches people to skip it — the failure mode this repo has already written down twice.

WHAT NEITHER CHECK CATCHES, and the limit is the point rather than an apology:

  * a path a TOOL prints at runtime — `check-set-gate.py` names a diagnostic as the reader's
    next step, and that diagnostic was once being deleted at release;
  * a link that resolves but points at the wrong thing;
  * a claim in prose that has gone stale without any path being wrong at all.

So this is the cheap floor, not the coverage story. **The hand-walk of the published tree
stays mandatory** (AGENTS.md, "no gate asks whether the published tree is internally
coherent"). A gate that made people feel the walk was covered would be worse than no gate.

Exit 0 clean, 1 on a broken link or a non-prose citation of a stripped path.
"""

import os
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# `[text](target)` — target up to the first '#', ')' or whitespace.
LINK = re.compile(r"\[[^\]]*\]\(\s*([^)\s#]+)(?:#[^)]*)?\s*\)")

# --- canon-filter's rule, replayed. Read from entity-core-devops
# `tools/release-builder/internal/canon/canon.go`. CORRECTED UPSTREAM 2026-08-23 to
# prose-only; it previously dropped ANY extension under a doc root, which shipped a
# sibling mirror that failed its own test suite on stripped .cbor vectors. If this
# ever disagrees with a supplied strip list, re-read canon.go before trusting either.
PROSE_EXT = (".md", ".markdown", ".rst", ".txt", ".adoc", ".patch", ".diff")
DOC_ROOTS = (
    "docs/", "doc/", "reviews/", "review/", "research/", "explorations/", "exploration/",
    "proposals/", "proposal/", "validation/", "stewardship/", "status/", "reports/",
    "report/", "notes/", "handoffs/", "handoff/", "audits/", "audit/", "planning/",
    "design/", "designs/",
)
MANIFEST = "CANONICAL-DOCS.toml"

# A path continuing on the next line may carry a comment marker. Covers //, #, ;, *,
# --, !, % and a bare continuation — i.e. every comment syntax in this cohort.
_WRAP = "/(?:\\x00[ \\t]*(?://|#|;|\\*|--|!|%)?[ \\t]*)?"


def _declared():
    """Paths declared canonical. Deliberately a regex, not a TOML parse: this must run
    with no third-party dependency, and the manifest's `path = "..."` lines are the only
    thing it needs."""
    text = (REPO / MANIFEST).read_text(encoding="utf-8")
    keep = set(re.findall(r'^path\s*=\s*"([^"]+)"', text, re.M))
    keep.update({"README.md", MANIFEST})
    return keep


def _strips(rel, declared):
    if rel in declared:
        return False
    if not rel.lower().endswith(PROSE_EXT):
        return False
    return rel.startswith(DOC_ROOTS) or "/" not in rel


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

    # --- check 2: published files naming a path the release strips
    declared = _declared()
    all_tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    all_tracked = [p for p in all_tracked if p]
    strip_set = {p for p in all_tracked if _strips(p, declared)}
    published = [p for p in all_tracked if p not in strip_set]

    # Compile each stripped path ONCE. Naively this is |published| x |strip_set| regex
    # compiles — 300k of them, which took `make lint` from 0.18 s to 2 s and would have
    # handed the per-commit release oracle a 10x regression for no added coverage.
    patterns = [
        (target, re.compile(re.escape(target).replace(r"/", _WRAP)))
        for target in sorted(strip_set)
    ]
    # Cheap prefilter: a file that never mentions any doc-root prefix cannot cite a
    # stripped path, and that is the overwhelming majority of a 2,700-file tree.
    roots = tuple(r.rstrip("/") for r in DOC_ROOTS)

    dead_code, dead_prose = [], []
    for rel in published:
        if rel.startswith(SKIP_PREFIXES) or rel == "tools/link-gate.py":
            continue
        try:
            text = (REPO / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(r in text for r in roots):
            continue
        joined = text.replace("\n", "\x00")
        bucket = dead_prose if rel.lower().endswith(PROSE_EXT) else dead_code
        for target, pat in patterns:
            for m in pat.finditer(joined):
                bucket.append((rel, joined.count("\x00", 0, m.start()) + 1, target))

    if dead_code:
        print(
            f"link-gate: {len(dead_code)} NON-PROSE file(s) name a path the release strips:",
            file=sys.stderr,
        )
        for rel, line, target in sorted(dead_code):
            print(f"  {rel}:{line}  ->  {target}", file=sys.stderr)
        print(
            "\nThis is shipped engineering provenance pointing at a file the reader will not "
            "receive.\nReword to describe the source rather than name its path, or move the "
            "target out of a doc root.",
            file=sys.stderr,
        )
        return 1

    if not quiet:
        print(f"link-gate: OK — {n_links} relative links across {n_files} files all resolve")
        print(
            f"link-gate: OK — 0 of {len(published)} published files name a stripped path "
            f"from code ({len(dead_prose)} prose citations reported, not gated — "
            "dated snapshots, parked by ruling)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
