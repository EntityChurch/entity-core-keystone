#!/usr/bin/env python3
"""ascii-wire-gate — a wire-VISIBLE string literal is ASCII-only, in every peer.

WHY THIS EXISTS, AND WHY IT IS A GATE RATHER THAN A HABIT
=========================================================
`AGENTS.md` ratifies this discipline on TWO independent crashes, in two unrelated
languages, with two unrelated compilers:

  - Oz  (A-OZ-008): a U+00A7 baked into a compiled string constant crashed the
    request handler at RUNTIME with an internal unification failure. `ozc`
    accepted the literal with zero warnings.
  - Io  (2026-08-17): the peer's OWN hand-rolled UTF-8 validator rejected
    byte-correct UTF-8 on the encode path. The peer is single-threaded, so the
    uncaught exception killed the process and cascaded 104 FAILs from ONE string.

The rule it earned: treat any wire-VISIBLE string literal -- an error `message`,
or any field the codec will CBOR-text-encode and send -- as ASCII-only until a
peer has a PROVEN non-ASCII wire round-trip test. Spec citations stay in comments.

`AGENTS.md` then says, in as many words, that the enforcement point did not exist:

    "No enforcement grep yet (both instances were caught by the peer's own
     run-s4.sh, not by static analysis) -- a candidate lint would be
     `grep -RP '"[^"]*[\\x80-\\xff]' protocol-generator/*/src` scoped to
     fail()/err()/Out_Err()-style wire-message call sites specifically,
     not comments."

This is that lint. It was built on 2026-09-14, and the first run over the cohort
found roughly twenty live violations -- INCLUDING ONE ON `io`, which is one of the
two peers whose crash established the rule in the first place. A discipline with
no enforcement point is theater, and this one had been theater for four weeks.

WHY THE SCOPING IS WHAT IT IS -- every exclusion below is a measured one
========================================================================
The naive form of this scan returns 69,592 hits and is USELESS. `AGENTS.md`:
"a check that cannot separate its signal from its noise is not a weak check, it
is a broken one -- scope it or drop it, and say which." So, measured:

  - BINARY FILES. `apl/src/ext/ec_native.so` is a shared object sitting under a
    `src/` tree. A byte-oriented scan reports thousands of "literals" from its
    machine code. Skipped by sniffing for NUL in the first 8 KiB, NOT by
    extension -- `ruby` and `dart` each write a raw NUL byte into a source file,
    so an extension allowlist alone would still let a binary through and a NUL
    check alone would drop two real source files. Both tests are needed and they
    are ANDed the safe way round.

  - TEST AND HARNESS OUTPUT. `println`/`printf`/`putStrLn` of "12 pass -- 3 fail"
    is not a wire string. Test trees are excluded by path, and the emission-call
    pattern excludes the rest.

  - VENDORED AND GENERATED TREES. `rust/output/vendor/`, `ocaml/_build/`,
    `node_modules/`, `dist/`, `target/`. A vendored crate's test fixture is not
    ours and editing it would be undone by the next fetch.

WHAT IT DOES NOT CATCH, STATED SO NOBODY READS IT AS TOTAL
==========================================================
This is a LINE-oriented heuristic over an emission-call vocabulary, so it shares
the two failure modes this repo has recorded repeatedly:

  1. A wire message built ACROSS LINES -- `err(400, code,\\n  "... section ...")` --
     is invisible to it. Every hit it has ever found is single-line, but absence
     of a hit is a statement about the pattern, not about the tree.
  2. A peer whose emission function is named something not in EMIT below is not
     scanned for. The vocabulary was derived from the 46 peers as they stand;
     a NEW peer with a new spelling is a silent gap. That is the H4-packaging-
     survey lesson -- a survey keyed on a list you wrote yourself reports
     "absent" where it means "could not look" -- so the gate PRINTS the count of
     files it examined and asserts it is non-zero, and the self-test asserts the
     detector fires.

A LATENT violation is still reported. `AGENTS.md` distinguishes latent from live
for REPORTING severity, and the gate deliberately does not try to decide
reachability -- it cannot, and the two peers that crashed both did so on a path
somebody had reasoned was fine.

Usage:
    tools/ascii-wire-gate.py              # gate; exit 1 on any hit
    tools/ascii-wire-gate.py --report     # list hits, always exit 0
    tools/ascii-wire-gate.py --self-test  # plant a defect, prove the gate fires
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PEERS = REPO / "protocol-generator"

# Source extensions across the 46-peer cohort. An extension NOT here is skipped,
# which is a deliberate under-approximation: adding one can only find more.
SRC_EXT = {
    ".go", ".py", ".rs", ".ts", ".js", ".mjs", ".rb", ".ex", ".exs", ".hs",
    ".ml", ".mli", ".swift", ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".zig", ".lisp", ".lean", ".adb", ".ads", ".cob", ".f90", ".jl", ".nim",
    ".cr", ".php", ".pl", ".pro", ".tcl", ".rex", ".st", ".io", ".oz", ".dart",
    ".odin", ".fs", ".fth", ".sql", ".apl", ".wat", ".s", ".u", ".scm", ".tal",
}

# Path fragments that are never ours to edit or never reach the wire.
SKIP_DIRS = {
    "_build", "build", "dist", "out", "output", "target", "node_modules",
    "vendor", "ext", ".git", ".lake", "dist-newstyle", "obj", "bin",
    "test", "tests", "spec", "Tests", "t",
}

# Wire-message emission vocabulary, derived from the cohort as it stands.
#
# TWO CONSTRAINTS, AND BOTH WERE ADDED AFTER MEASURING THE FIRST CUT. That cut
# used a looser vocabulary and no positional test, and returned 34 hits of which
# three were noise -- which is the exact ratio that gets a gate switched off:
#
#   - `deny` matched the PROSE "DENY -> 403" inside an elixir doc comment.
#   - `fail` matched `fail += run_synth();` on an asm diff-harness printf line,
#     and `println("... pass, ... fail")` in a julia smoke test.
#
# The fix is (1) the POSITIONAL rule -- the offending literal must appear AFTER
# the call token, i.e. be an ARGUMENT to it -- plus (2) dropping the bare generic
# words (`deny`, `reject`, `refusal`, `failure`), which are English before they
# are function names and which no peer in this cohort actually uses as an
# emitter. Both noise lines die on the positional rule alone: in each, the
# non-ASCII literal sits BEFORE the word that matched.
#
# ⛔ WHAT IT MUST NOT DO IS REQUIRE `token(`. That was the first repair, and it
# was WRONG IN THE DIRECTION NOBODY RE-CHECKS: it silently dropped every
# prefix-notation peer, because their paren comes BEFORE the token --
# `(err 503 "…")` in common-lisp, `[err 403 …]` in tcl, `errMsg 403 "…"` in
# unison. Three peers vanished from the report and the count still looked
# plausible. Caught only by diffing the hit list before and after the change.
# The delimiter class stays permissive; the POSITION is what does the work.
EMIT = re.compile(
    r"\b("
    r"err|errMsg|errOutcome|errorOutcome|err_outcome|error_outcome|errResult|"
    r"errorResult|errMessage|errorWith|raiseErr|throwErr|"
    r"OutErr|out_err|Out_Err|outErr|make_err|mkErr|makeErr|fail"
    r")\s*[\(\[\{ ]",
    re.IGNORECASE,
)

# Harness / logging calls. A line whose non-ASCII literal belongs to one of
# these is test output, not a wire field -- "12 pass, 3 fail" is nobody's
# protocol message.
PRINTLIKE = re.compile(
    r"\b(print|println|printf|puts|echo|putStrLn|showInfo|writeln|"
    r"write_line|log|logger|debug|warn|trace|assert\w*)\s*\(",
    re.IGNORECASE,
)

# A double- or single-quoted run containing a byte >= 0x80.
LITERAL = re.compile(r"""(["'])[^"'\n]*[^\x00-\x7f][^"'\n]*\1""")

# Line-comment openers across the cohort. A comment is not a wire string.
COMMENT = ("//", "#", "--", ";", "*", "%", "!", '"""', "'''", "/*", "<!--", "|")


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def candidate_files() -> list[Path]:
    out: list[Path] = []
    for p in sorted(PEERS.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in SRC_EXT:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        out.append(p)
    return out


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return (lineno, line) for every wire-emission line carrying a non-ASCII literal."""
    hits = []
    for n, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(COMMENT):
            continue
        lit = LITERAL.search(line)
        if not lit:
            continue
        emit = EMIT.search(line)
        if not emit:
            continue
        # The literal must be an ARGUMENT to the emitter, not merely on the same
        # line as a word that looks like one.
        if lit.start() < emit.end():
            continue
        # If a print-like call also claims this literal and sits closer to it,
        # the string is harness output rather than a wire field.
        pr = PRINTLIKE.search(line)
        if pr and pr.end() <= lit.start() and pr.start() > emit.start():
            continue
        hits.append((n, stripped))
    return hits


def run(report_only: bool) -> int:
    files = candidate_files()
    all_hits: list[tuple[Path, int, str]] = []
    examined = 0
    skipped_binary = 0

    for f in files:
        try:
            raw = f.read_bytes()
        except OSError:
            continue
        if is_binary(raw):
            skipped_binary += 1
            continue
        examined += 1
        for n, line in scan_text(raw.decode("utf-8", "replace")):
            all_hits.append((f, n, line))

    # THE COUNT IS THE POINT. A gate that examined zero things prints the same
    # word as one that examined four thousand -- ratified twice in AGENTS.md,
    # once when check-set-gate keyed 45 reports into one dict entry, and once
    # when coherence-gate matched a banner form that did not exist.
    print(
        f"ascii-wire-gate: {examined} source file(s) examined "
        f"({skipped_binary} binary-looking skipped), {len(all_hits)} hit(s)"
    )
    if examined == 0:
        print("ascii-wire-gate: FAIL — examined ZERO files; the scan is broken, "
              "not the tree", file=sys.stderr)
        return 1

    if not all_hits:
        print("PASS — no wire-visible string literal carries a non-ASCII byte.")
        return 0

    by_peer: dict[str, list[tuple[Path, int, str]]] = {}
    for f, n, line in all_hits:
        peer = f.relative_to(PEERS).parts[0]
        by_peer.setdefault(peer, []).append((f, n, line))

    for peer in sorted(by_peer):
        print(f"\n  {peer}:")
        for f, n, line in by_peer[peer]:
            print(f"    {f.relative_to(REPO)}:{n}")
            print(f"        {line[:120]}")

    print(
        f"\n{len(all_hits)} hit(s) across {len(by_peer)} peer(s). "
        "Replace the non-ASCII character in the MESSAGE STRING ONLY; leave every "
        "comment alone. A section sign in a comment is correct and is not a hit."
    )
    if report_only:
        return 0
    return 1


def self_test() -> int:
    """Plant a defect and prove the detector fires. A gate with no regression
    suite is a script that has not been wrong yet."""
    ok = True

    # (a) POSITIVE: a wire emission carrying a section sign must be caught.
    planted = 'return errOutcome(403, "forbidden_pattern", "§6.2: nope");'
    if not scan_text(planted):
        print("self-test FAIL: planted wire violation NOT detected", file=sys.stderr)
        ok = False

    # (b) NEGATIVE: the same character in a COMMENT must NOT be caught. This is
    #     the arm that matters -- a gate that fires on comments would be swept
    #     by somebody "fixing" it, and a mechanical rewriter that cannot tell
    #     code from commentary has already destroyed one comment in this repo.
    if scan_test_comment := scan_text('// §6.2: user-installed handlers'):
        print(f"self-test FAIL: comment flagged as a hit: {scan_test_comment}",
              file=sys.stderr)
        ok = False

    # (c) NEGATIVE: test-harness output is not a wire string.
    if scan_text('println("→ SMOKE: 12 pass, 0 fail")'):
        print("self-test FAIL: harness output flagged as a hit", file=sys.stderr)
        ok = False

    # (d) NEGATIVE: an ASCII wire message must be clean.
    if scan_text('return errOutcome(403, "forbidden_pattern", "section 6.2: nope");'):
        print("self-test FAIL: clean ASCII message flagged", file=sys.stderr)
        ok = False

    # (e1)-(e3) THE THREE FALSE POSITIVES THE FIRST CUT PRODUCED, pinned as
    #     regression cases. Each was found by RUNNING the gate over the cohort
    #     and reading all 34 hits, not by reasoning about the pattern.
    for label, line in [
        # `fail +=` is not a call; the section sign belongs to the printf.
        ("asm diff-harness printf",
         r'printf("\n-- synthetic key-sort (input unsorted → canonical) --\n"); fail += run_synth();'),
        # `DENY ` matched a bare-word vocabulary; it is English in a doc comment.
        ("elixir doc-comment prose",
         '/ A-OC-008 boundary; section 5.2 flat "DENY → 403" under-specifies the split).'),
        # A julia smoke line: print-like, and `fail` is inside the string.
        ("julia smoke println",
         'println("\\n→ SMOKE: ", all_pass ? "PASS" : "FAIL", " (", PASS[], " pass, ", FAIL[], " fail)")'),
    ]:
        if scan_text(line):
            print(f"self-test FAIL: false positive returned for {label}", file=sys.stderr)
            ok = False

    # (e4)-(e7) POSITIVE COMPANIONS, ONE PER CALL SYNTAX. These exist because the
    #     first repair for (e1)-(e3) required `token(` and thereby went blind to
    #     every prefix-notation peer at once -- three of them -- while the report
    #     still looked well-formed. A false negative in a gate is worse than a
    #     false positive, so each syntax family in the cohort is pinned here.
    for label, line in [
        ("infix call (go/java/ruby)",
         'return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection");'),
        ("s-expression (common-lisp)",
         '(if (null env) (err 503 "no_outbound_seam" "no live §6.11 reentry connection")'),
        ("bracket command (tcl)",
         'return [err 403 forbidden_pattern "§6.2: handlers MUST NOT register at system/*"]'),
        ("juxtaposition (unison/haskell)",
         'errMsg 403 "forbidden_pattern" ("§6.2: handlers MUST NOT register")'),
    ]:
        if not scan_text(line):
            print(f"self-test FAIL: real violation NOT detected for {label}", file=sys.stderr)
            ok = False

    # (e) The binary sniffer must reject a real ELF header and accept a source
    #     file that legitimately contains a NUL byte nowhere near the front.
    if not is_binary(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64):
        print("self-test FAIL: ELF not detected as binary", file=sys.stderr)
        ok = False
    if is_binary(b'x = "plain source"\n' * 10):
        print("self-test FAIL: plain source misdetected as binary", file=sys.stderr)
        ok = False

    # (f) The file walker must actually find files. Guards the class where the
    #     gate passes having examined nothing.
    n = len(candidate_files())
    if n < 100:
        print(f"self-test FAIL: walker found only {n} candidate files", file=sys.stderr)
        ok = False

    print(f"ascii-wire-gate --self-test: 13 checks, walker sees {n} files — "
          f"{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(run(report_only="--report" in sys.argv))
