#!/usr/bin/env python3
"""st-compile-string-check — find a Smalltalk `compile: '…'` literal that ends EARLY.

WHY THIS EXISTS. A chunk-format `.st` embeds every method body in an OUTER string literal, so
one lone apostrophe anywhere inside — including in an ordinary English comment, "the caller's
own exclude" — terminates the method mid-sentence. The compiler's diagnostic points at the
NEXT construct, and `make image` pipes the Pharo load through `grep -vi 'undeclared|warning'`,
so the build still says `built`. AGENTS.md records the class; this is the instrument.

WHY THE OBVIOUS CHECK IS USELESS HERE. A per-line quote-parity scan reports every `compile: '`
opener as odd, because it legitimately is: two files in `smalltalk` produce 86 and 124 "suspect"
lines, and the four real defects are invisible inside that. Signal-to-noise IS the failure mode
— AGENTS.md: "a check that cannot separate its signal from its noise is not a weak check, it is
a broken one."

WHAT WORKS. Walk each `compile: '` literal forward under the ''-escape rule and assert the
character after its close is `.` — which is what a well-formed chunk always has. A literal that
closes anywhere else closes early.

    python3 st-compile-string-check.py <file.st> [...]

Prints the number of `compile:` SITES EXAMINED per file and asserts it non-zero: a scanner that
matched no sites reports exactly the same word as one that matched a hundred. Exits 1 on any
suspect site.

Measured when it was written (2026-09-15, the 0.8.2.25 sweep): 44 sites in EcPeerHandlers2.st
and 57 in EcCapAuthz.st, 4 suspect, all four introduced by that session's own comments, 0 after.
"""
import re
import sys


def check(path):
    s = open(path, encoding="utf-8").read()
    suspect, n = [], 0
    for m in re.finditer(r"compile: '", s):
        n += 1
        i = m.end()
        while i < len(s):
            if s[i] == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    i += 2
                    continue
                break
            i += 1
        after = s[i + 1 : i + 2]
        if after != ".":
            suspect.append(
                (
                    s.count("\n", 0, m.start()) + 1,
                    s[m.end() : m.end() + 60].split("\n")[0],
                    s.count("\n", 0, i) + 1,
                    after,
                )
            )
    return n, suspect


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    bad, total = 0, 0
    for path in argv:
        n, suspect = check(path)
        total += n
        note = "" if n else "   (no methods defined here — script or class-definition file)"
        print("%-64s %3d compile: site(s) examined, %d suspect%s" % (path, n, len(suspect), note))
        for line, head, endline, after in suspect:
            bad += 1
            print("  line %-5d %-50s closes at line %d, next char %r" % (line, head, endline, after))
    # The examined-zero-things assert belongs to the RUN, not to each file: a chunk-format tree
    # legitimately contains scripts and class-definition files with no `compile:` at all, and
    # failing on those makes the check permanently red against a glob — which is how a gate gets
    # switched off. Zero across the WHOLE invocation is the case that means the idiom moved.
    print("%-64s %3d compile: site(s) examined in total" % ("ALL", total))
    if total == 0:
        print("  ERROR: examined ZERO sites — wrong files, or the idiom moved.")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
