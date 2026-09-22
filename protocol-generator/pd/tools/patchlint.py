#!/usr/bin/env python3
"""patchlint.py — PROSE IN A COMMENT IS CODE IN THIS FILE FORMAT.

A Pd record ends at an unescaped `,` or `;`, and that is true INSIDE a `#X text`
comment too. Ordinary English punctuation therefore breaks out of the comment and
Pd dispatches the remainder as messages at patch-load time.

Measured 2026-09-02 on the RT-6 comment in src/main.pd. Four unescaped separators
produced three load-time errors:

    error: canvas: no method for 'not'      <- "must be REJECTED, not re-processed"
    error: established_ok: no such object   <- "auth_decode; established_ok 0 -> 401"
    error: established_ok: no such object   <- "...sig/bind; established_ok 1 -> ..."

Those were harmless ONLY because the words following the separators happened to
name nothing. The identical defect one word over sends a real message to a real
receiver at load — `; net_listen`, `; buf_reset` — and nothing would report it.
That is why this is a build gate rather than a style note.

It survived for months because pd logs to stderr and run-s4.sh directed that to a
path inside a `--rm` container, so the evidence was destroyed on every run. The
harness captures it now; this keeps it from returning.

Run from the peer root:  python3 tools/patchlint.py
Exit 0 clean, 1 on any finding.
"""
import glob
import re
import sys

# A separator is live unless preceded by a backslash. The record's own trailing
# `;` terminator is stripped before the scan -- it is the one that SHOULD be bare.
LIVE_SEPARATOR = re.compile(r"(?<!\\)[,;]")


def findings(root="src"):
    for path in sorted(glob.glob(f"{root}/**/*.pd", recursive=True)):
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")
                if not line.startswith("#X text"):
                    continue
                body = line[:-1] if line.endswith(";") else line
                hits = [m.start() for m in LIVE_SEPARATOR.finditer(body)]
                if hits:
                    yield path, lineno, body, hits


def main():
    found = list(findings())
    for path, lineno, body, hits in found:
        print(
            f"PATCHLINT FAIL: {path}:{lineno} — {len(hits)} unescaped , or ; in a "
            f"#X text comment. Pd ends the record there and executes the rest as "
            f"messages. Escape them as \\, and \\;",
            file=sys.stderr,
        )
        for pos in hits[:4]:
            print(f"    {body[pos]!r} -> {body[pos + 1:pos + 48].strip()}", file=sys.stderr)
    if found:
        return 1
    print("PATCHLINT OK: no #X text comment can break out into a message")
    return 0


if __name__ == "__main__":
    sys.exit(main())
