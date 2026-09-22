#!/usr/bin/env python3
"""harness-gate — three structural invariants of every `protocol-generator/*/run-s4.sh`.

A. TEARDOWN MUST WAIT, not merely signal.
B. THE CALLER ARGS MUST REACH THE ORACLE.
C. A BARE RUN MUST NOT DEFAULT ITS REPORT ONTO THE TRACKED ONE.

Both were cohort-wide defects found on 2026-09-02, both were invisible to every other
gate in the repo, and both fail in the direction where the harness still reports success.

────────────────────────────────────────────────────────────────────────────────────
A. TEARDOWN MUST WAIT

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

────────────────────────────────────────────────────────────────────────────────────
B. THE CALLER ARGS MUST REACH THE ORACLE

`run-s4.sh [validate-peer-args...]` is the documented interface, and 38 of 46 honoured
it. Three did not: `python`, `ruby` and `prolog` hardcoded their whole argument list, so
`run-s4.sh -category connectivity` silently ran the full 756-check suite AND rewrote the
tracked, signed-off `CONFORMANCE-REPORT.json` — a diagnostic run overwriting the record
it is meant to be diagnosed against. Measured: `python` answered 756 where the caller
asked for 25.

Five more (`ada` `c` `common-lisp` `java` `kotlin`) spliced `'"$*"'` into their
container block. **That one does work** — the outer shell consumes the quotes and the
inner shell word-splits what is left, verified at 25 checks — so it is a latent hazard
rather than a break: it flattens argv into one string and hands it to a shell to
re-parse, so a value containing a space, a glob or a `;` is mangled or executed. All
eight now use the `bash -c SCRIPT bash "$@"` form the other four re-exec peers already
had, which crosses the podman boundary as real argv.

WHAT IT CHECKS:

  4. The oracle invocation forwards `"$@"`.
  5. If that invocation lives inside a re-exec block, the block is terminated with
     argv forwarding (`' bash "$@"`). Without it `$@` is empty inside the block and the
     harness quietly falls back to its default — which is the ignore-class defect with
     a different mechanism and the same silent symptom.

────────────────────────────────────────────────────────────────────────────────────

AND IT PRINTS THE COUNT. A gate whose success message contains no number cannot
distinguish "all 46 green" from "examined nothing" — this repo has shipped that bug
twice (`check-set-gate`'s Path.stem collision, `coherence-gate`'s banner pattern), so
the peer count is asserted against the roster, not merely reported.

Exit 0 clean, 1 on any failure.  `--self-test` runs the regression suite.

────────────────────────────────────────────────────────────────────────────────────
C. A BARE RUN MUST NOT DEFAULT ITS REPORT ONTO THE TRACKED ONE

`run-s4.sh` with no arguments used to default `-json-out` to this peer's TRACKED
`status/CONFORMANCE-REPORT.json` — the signed-off record `CONFORMANCE-MATRIX.md`
publishes and `check-set-gate --tracked` gates. So a human diagnostic run silently
republished a number nobody had reviewed, and it fired on exactly the invocation where
overwriting is most wrong: the census always passes an explicit destination, so it is
only the by-hand run that was affected. Found 2026-09-04 when a `t1_1_concurrent_demux`
flake was banked over a committed PASS; closed cohort-wide 2026-09-08 (44 harnesses).

This is invariant B in a second shape. There the harness IGNORED the caller's args;
here it DEFAULTED to the published path — same consequence, opposite mechanism.

WHAT IT CHECKS: no harness may name `status/CONFORMANCE-REPORT.json` anywhere in its
CODE (comments are free, and several explain the rule). Writing the tracked report is
deliberate: `tools/run-cohort-census.sh --to-status <peer>`, or an explicit `JSON_OUT=`.
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
# The oracle invocation. Every harness spells it `"$ORACLE" -addr <host:port> ...`.
ORACLE_CALL = re.compile(r'"\$ORACLE"\s+-addr\b')
# `sh -c '` / `bash -lc '` opening a container block, and the `' bash "$@"` that closes
# one while forwarding argv. The interpreter word is argv[0] and may be sh or bash.
REEXEC_OPEN = re.compile(r"(?:^|\s)(?:ba)?sh\s+-[a-z]*c\s+'\s*$")
REEXEC_ARGV = re.compile(r"""^\s*'\s+\S+\s+"\$@"\s*$""")


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


def check(path, seen=None):
    """Failure strings for one harness (empty == clean).

    `seen` is a tally of which ANCHORS each check actually found. Without it a
    regex that matches nothing reports the same clean result as one that matched
    everything, which is the vacuity bug this repo has now shipped twice."""
    if seen is None:
        seen = {}
    lines = path.read_text().splitlines()
    code = [l for l in lines if not l.lstrip().startswith("#")]
    traps = [l for l in code if TRAP.match(l)]
    if len(traps) != 1:
        return [f"expected exactly 1 trap, found {len(traps)}"]
    seen["trap"] = seen.get("trap", 0) + 1
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
    seen["wait"] = seen.get("wait", 0) + 1

    # B. the caller args must reach the oracle.
    calls = [l for l in code if ORACLE_CALL.search(l)]
    if not calls:
        return ["no `\"$ORACLE\" -addr` invocation found — cannot tell what it runs"]
    seen["oracle_call"] = seen.get("oracle_call", 0) + 1
    if not any('"$@"' in l for l in calls):
        return ["the oracle invocation does not forward \"$@\" — caller args are dropped"]
    seen["forwards"] = seen.get("forwards", 0) + 1
    # A harness that re-execs into podman must ALSO hand argv across that boundary, or
    # "$@" inside the block is empty and it silently falls back to its own default.
    if any(REEXEC_OPEN.search(l) for l in code):
        seen["reexec"] = seen.get("reexec", 0) + 1
        if not any(REEXEC_ARGV.match(l) for l in code):
            return ["re-execs into a container but the block is not terminated with "
                    "argv forwarding (`' bash \"$@\"`) — \"$@\" is empty inside it"]
        seen["reexec_argv"] = seen.get("reexec_argv", 0) + 1

    # C. a bare run must not default onto the tracked report.
    tracked = [l for l in code if "status/CONFORMANCE-REPORT.json" in l]
    if tracked:
        return ["names the TRACKED status/CONFORMANCE-REPORT.json in code — a bare run "
                "would republish a signed-off number; default to scratch and let "
                "`--to-status` or an explicit JSON_OUT= write it: " + tracked[0].strip()[:90]]
    seen["scratch_default"] = seen.get("scratch_default", 0) + 1
    return []


def run(quiet=False, pg=PG):
    peers = harnesses(pg)
    roster = [d for d in pg.iterdir() if d.is_dir() and d.name != "shared"]
    bad = {}
    seen = {}
    for p in peers:
        fails = check(p, seen)
        if fails:
            bad[p.parent.name] = fails

    # A gate that examined nothing prints the same word as one that examined 46.
    if len(peers) != len(roster):
        print(f"harness-gate: ERROR examined {len(peers)} harnesses but the roster has "
              f"{len(roster)} peer directories — a peer with no run-s4.sh is unmeasured, "
              f"not compliant", file=sys.stderr)
        return 1
    if not peers:
        print("harness-gate: ERROR examined 0 harnesses", file=sys.stderr)
        return 1

    for peer in sorted(bad):
        for f in bad[peer]:
            print(f"harness-gate: FAIL {peer}/run-s4.sh — {f}", file=sys.stderr)
    if bad:
        print(f"harness-gate: {len(bad)} of {len(peers)} harnesses violate a run-s4.sh "
              f"invariant", file=sys.stderr)
        return 1
    # Every anchor a check depends on is counted, and the counts are asserted. A regex
    # that silently matched nothing would otherwise print this same OK line.
    if (seen.get("wait") != len(peers) or seen.get("forwards") != len(peers)
            or seen.get("scratch_default") != len(peers)):
        print(f"harness-gate: ERROR anchors not found on every harness — "
              f"waited={seen.get('wait', 0)} forwarded={seen.get('forwards', 0)} "
              f"scratch_default={seen.get('scratch_default', 0)} of "
              f"{len(peers)}", file=sys.stderr)
        return 1
    if not seen.get("reexec"):
        print("harness-gate: ERROR detected no re-exec harnesses; 11 are known to "
              "exist, so the container-block check matched nothing", file=sys.stderr)
        return 1
    if not quiet:
        print(f"harness-gate: OK — {seen['wait']} harnesses wait for the peer to exit, "
              f"{seen['forwards']} forward caller args to the oracle, "
              f"{seen['reexec_argv']} of those hand argv across a container boundary, "
              f"{seen['scratch_default']} default their report to scratch not to the "
              f"tracked one")
    return 0


def self_test():
    """Plant each defect this gate exists to catch. A gate with no regression suite is
    a script that has not been wrong yet — both gates this repo shipped broken were
    caught by planting, not by reading."""
    ok = True

    def attempt(label, victim, mutate, expect_fail=True):
        nonlocal ok
        src = (PG / victim / "run-s4.sh").read_text()
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
        print(f"  {'PASS' if good else 'FAIL'} plant [{victim}]: {label} (exit {rc})")
        ok = ok and good

    # A. teardown
    attempt("revert to a fire-and-forget inline kill-trap", "go",
            lambda s: re.sub(r"(?m)^trap reap_host (EXIT.*)$",
                             r"""trap 'kill "$HOST_PID" 2>/dev/null || true' \1""", s))
    attempt("drop the wait from the reap function", "go",
            lambda s: s.replace('  wait "$HOST_PID" 2>/dev/null || true\n', ""))
    attempt("trap names a function that does not exist", "go",
            lambda s: re.sub(r"(?m)^trap reap_host (EXIT.*)$", r"trap tidy_up \1", s))

    # B. caller args. `go` is a plain harness, `java` re-execs into podman, and the
    # two fail through different mechanisms — plant on both, not on whichever is handy.
    # The literal here must track the harness. It did NOT: `-reference-peer` was folded
    # into every harness on 2026-09-03, which put `$REFPEER_FLAG` between the address and
    # `"$@"`, and this plant silently stopped matching -- so from that day the self-test
    # reported `plant changed nothing` and FAILED, and nothing noticed because `make lint`
    # ran the gate and not its regression suite. Both halves fixed 2026-09-08: the plant
    # is anchored on the part that cannot drift, and `--self-test` is now in `make lint`.
    attempt("hardcode the oracle args instead of forwarding \"$@\"", "go",
            lambda s: s.replace('$REFPEER_FLAG "$@"', '$REFPEER_FLAG -profile core'))
    attempt("re-exec block stops forwarding argv across the boundary", "java",
            lambda s: s.replace('  \' bash "$@"\n', "  '\n"))

    # C. the tracked-report default. Two victims for the two forms the default takes:
    # `go` sets it inline in the `set --` line, `ada` via a JSON_OUT= assignment.
    attempt("default -json-out back onto the TRACKED report (inline form)", "go",
            lambda s: s.replace('-json-out "${JSON_OUT:-/tmp/ec-s4-go.json}"',
                                '-json-out "$PROJ/status/CONFORMANCE-REPORT.json"'))
    attempt("default -json-out back onto the TRACKED report (JSON_OUT= form)", "ada",
            lambda s: s.replace('JSON_OUT="${JSON_OUT:-/tmp/ec-s4-ada.json}"',
                                'JSON_OUT="/work/protocol-generator/ada/status/CONFORMANCE-REPORT.json"'))

    attempt("unmodified tree is accepted", "go", lambda s: s + "\n# touched\n",
            expect_fail=False)

    # Vacuity: the gate must refuse a roster it cannot fully examine.
    with tempfile.TemporaryDirectory() as td:
        shadow = pathlib.Path(td) / "protocol-generator"
        shutil.copytree(PG, shadow, symlinks=True)
        (shadow / "go" / "run-s4.sh").unlink()
        rc = run(quiet=True, pg=shadow)
    print(f"  {'PASS' if rc != 0 else 'FAIL'} plant: a peer with no run-s4.sh at all "
          f"(exit {rc})")
    ok = ok and rc != 0

    print("harness-gate self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(run(quiet="--quiet" in sys.argv))
