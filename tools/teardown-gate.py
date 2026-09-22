#!/usr/bin/env python3
"""teardown-gate — a peer harness must WAIT for its peer to be gone, not just signal it.

WHY THIS EXISTS. Every `protocol-generator/*/run-s4.sh` launches its peer in the
background and tears it down from an EXIT trap. Until 2026-09-02, 45 of the 46 wrote
that trap as

    trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

which is fire-and-forget: kill(1) DELIVERS a signal and returns. The trap then returns,
the script exits, and the peer is still holding the listening socket. Whether that is
harmless or fatal is decided by the peer runtime, not by the harness, so it is invisible
on whichever peer you happen to test. Measured — how long the port kept ACCEPTING
CONNECTIONS after the harness had already exited:

    elixir   >400ms   and the next invocation in the same container exited 1
    rexx      forever the ecnet daemon was never reaped at all (see below)
    julia      ~88ms
    smalltalk   ~4ms
    zig, go        0ms

`go` and `zig` are the two peers anyone reaches for first, and both are clean. That is
the whole argument for a gate rather than a fix: the defect is real, it is cohort-wide,
and the cheapest peers to check are the ones that do not show it.

WHAT IT CHECKS, for all 46 harnesses:

  1. Exactly one non-comment `trap` line, and it names a FUNCTION (a bare word), never
     an inline command. An inline `trap 'kill ...'` is the defect by construction.
  2. That function is defined in the same file.
  3. Its body contains a `wait` on a pid. `wait` is the only thing in POSIX sh that
     answers "is it gone", and it is exactly what the old form omitted.

WHAT IT DELIBERATELY DOES NOT CHECK. Not the signal (`python`/`ruby`/`prolog` chose -9
deliberately and SIGKILL + wait is correct), not the poll bound, not the wording. Those
are per-peer judgement; the invariant is that teardown does not return early.

AND IT PRINTS THE COUNT. A gate whose success message contains no number cannot
distinguish "all 46 green" from "examined nothing" — this repo has shipped that bug
twice (`check-set-gate`'s Path.stem collision, `coherence-gate`'s banner pattern), so
the peer count is asserted against the roster, not merely reported.

Exit 0 clean, 1 on any failure.  `--self-test` runs the regression suite.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PG = ROOT / "protocol-generator"

TRAP = re.compile(r"^\s*trap\s+(.*?)\s+(EXIT|INT|TERM|HUP)\b")
BAREWORD = re.compile(r"^[A-Za-z_]\w*$")
WAIT = re.compile(r"^\s*wait\s+[\"']?\$")


def harnesses(pg):
    return sorted(pg.glob("*/run-s4.sh"))


def func_body(lines, name):
    """Lines of `name() { ... }`, matched on the closing brace at the opening indent."""
    open_re = re.compile(r"^(\s*)" + re.escape(name) + r"\(\)\s*\{\s*$")
    for i, l in enumerate(lines):
        m = open_re.match(l)
        if not m:
            continue
        close = m.group(1) + "}"
        for j in range(i + 1, len(lines)):
            if lines[j].rstrip() == close:
                return lines[i + 1:j]
    return None


def check(path):
    """Return a list of failure strings for one harness (empty == clean)."""
    lines = path.read_text().splitlines()
    code = [l for l in lines if not l.lstrip().startswith("#")]
    traps = [l for l in code if TRAP.match(l)]
    if len(traps) != 1:
        return [f"expected exactly 1 trap, found {len(traps)}"]
    handler = TRAP.match(traps[0]).group(1)
    # `trap 'reap_host' EXIT` and `trap reap_host EXIT` are the same call; crystal
    # writes the first. Strip a matched outer quote before the bareword test -- an
    # inline command still fails it, because it contains a space.
    if len(handler) >= 2 and handler[0] == handler[-1] and handler[0] in "\"'":
        handler = handler[1:-1]
    if not BAREWORD.match(handler):
        return [f"trap runs an inline command, not a function: {handler}"]
    body = func_body(lines, handler)
    if body is None:
        return [f"trap names {handler}() but no such function is defined here"]
    if not any(WAIT.match(l) for l in body):
        return [f"{handler}() signals the peer but never waits for it to be gone"]
    return []


def run(quiet=False, pg=PG):
    peers = harnesses(pg)
    roster = [d for d in pg.iterdir() if d.is_dir() and d.name != "shared"]
    bad = {}
    for p in peers:
        fails = check(p)
        if fails:
            bad[p.parent.name] = fails

    # A gate that examined nothing prints the same word as one that examined 46.
    if len(peers) != len(roster):
        print(f"teardown-gate: ERROR examined {len(peers)} harnesses but the roster has "
              f"{len(roster)} peer directories — a peer with no run-s4.sh is unmeasured, "
              f"not compliant", file=sys.stderr)
        return 1
    if not peers:
        print("teardown-gate: ERROR examined 0 harnesses", file=sys.stderr)
        return 1

    for peer in sorted(bad):
        for f in bad[peer]:
            print(f"teardown-gate: FAIL {peer}/run-s4.sh — {f}", file=sys.stderr)
    if bad:
        print(f"teardown-gate: {len(bad)} of {len(peers)} harnesses tear down without "
              f"waiting", file=sys.stderr)
        return 1
    if not quiet:
        print(f"teardown-gate: OK — all {len(peers)} peer harnesses wait for the peer "
              f"to exit before returning")
    return 0


def self_test():
    """Plant each defect this gate exists to catch. A gate with no regression suite is
    a script that has not been wrong yet — both gates this repo shipped broken were
    caught by planting, not by reading."""
    victim = "go"
    src = (PG / victim / "run-s4.sh").read_text()
    ok = True

    def attempt(label, mutate, expect_fail=True):
        nonlocal ok
        with tempfile.TemporaryDirectory() as td:
            shadow = pathlib.Path(td) / "protocol-generator"
            shutil.copytree(PG, shadow, symlinks=True)
            f = shadow / victim / "run-s4.sh"
            new = mutate(src)
            if new == src:
                print(f"  self-test BUG: plant {label!r} changed nothing")
                ok = False
                return
            f.write_text(new)
            rc = run(quiet=True, pg=shadow)
        good = (rc != 0) if expect_fail else (rc == 0)
        print(f"  {'PASS' if good else 'FAIL'} plant: {label} (exit {rc})")
        ok = ok and good

    attempt("revert to a fire-and-forget inline kill-trap",
            lambda s: re.sub(r"(?m)^trap reap_host (EXIT.*)$",
                             r"""trap 'kill "$HOST_PID" 2>/dev/null || true' \1""", s))
    attempt("drop the wait from the reap function",
            lambda s: s.replace('  wait "$HOST_PID" 2>/dev/null || true\n', ""))
    attempt("trap names a function that does not exist",
            lambda s: re.sub(r"(?m)^trap reap_host (EXIT.*)$", r"trap tidy_up \1", s))
    attempt("unmodified tree is accepted", lambda s: s + "\n# touched\n",
            expect_fail=False)

    # Vacuity: the gate must refuse a roster it cannot fully examine.
    with tempfile.TemporaryDirectory() as td:
        shadow = pathlib.Path(td) / "protocol-generator"
        shutil.copytree(PG, shadow, symlinks=True)
        (shadow / victim / "run-s4.sh").unlink()
        rc = run(quiet=True, pg=shadow)
    print(f"  {'PASS' if rc != 0 else 'FAIL'} plant: a peer with no run-s4.sh at all "
          f"(exit {rc})")
    ok = ok and rc != 0

    print("teardown-gate self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(run(quiet="--quiet" in sys.argv))
