#!/usr/bin/env python3
"""fold-reference-peer.py — wire the B-role reference peer into every run-s4.sh.

WHY A SCRIPT AND NOT 46 HAND EDITS
  `validate-peer --profile core` executes 756 checks; with `-reference-peer <addr>`
  it executes 758. The census never passed the flag, which is the only reason a
  separate `run-origination-core.sh` existed on 31 peers and was ABSENT on 15.

  46 hand edits to process-lifetime code is exactly how the fire-and-forget teardown
  defect reached 45 of 46 harnesses. So: one shared helper
  (`protocol-generator/shared/tools/refpeer.sh`), three anchors, and a sweep that
  REPORTS what it could not patch instead of half-applying it.

WHAT IT ASSERTS, AND WHY THE POSTCONDITION IS THE CHECK
  The standing rule from the de-versioning sweep: verify that the new thing
  RESOLVES, never that the old token is absent -- absence is a property of your
  pattern, existence is a property of the tree. So after patching, every harness is
  re-parsed and must exhibit all four properties, and the COUNT is printed and
  asserted against the roster. A sweep that patched zero files prints the same word
  as one that patched 46 unless it says how many.

  --check  verify only, exit 1 if any harness is unpatched (used by harness-gate)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "protocol-generator"
SOURCE_LINE = ". /work/protocol-generator/shared/tools/refpeer.sh"

# The trap handler names the harness may use; harness-gate already guarantees the
# trap names a function, so we find it rather than assuming `reap_host`.
TRAP = re.compile(r"^\s*trap\s+['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?\s+(?:EXIT|INT|TERM|HUP)\b", re.M)
# The oracle invocation: `"$ORACLE" -addr "127.0.0.1:$PORT" ... "$@"`. Deliberately
# anchored on the ORACLE variable rather than on a literal binary name -- three peers
# swap ORACLE for a one-off measurement binary.
# A PREFIX BEFORE THE BINARY IS THE COMMON CASE, NOT THE EXCEPTION. Five harnesses
# (io pd python ruby sql) write `rc=0; "$ORACLE" -addr ... || rc=$?` because their
# oracle call has no `|| true` under `set -e` and the exit code has to be held. A
# line-start anchor silently misses all five -- and five is exactly the size of
# miss that reads as "a few odd peers" rather than as a broken pattern.
# `-addr` is what makes this the invocation rather than a preflight test.
ORACLE_CALL = re.compile(
    r'^(?P<indent>[ \t]*)(?!\s*#)(?P<lead>[^\n#]*?)'
    r'(?P<pre>["\']?\$\{?ORACLE\}?["\']?\s+-addr\s+\S+)(?P<rest>.*)$', re.M)


def peers():
    out = []
    for d in sorted(GEN.iterdir()):
        if d.name == "shared" or not d.is_dir():
            continue
        if (d / "run-s4.sh").is_file():
            out.append(d.name)
    return out


def properties(text):
    """The four postconditions, independent of how they got there."""
    handler = TRAP.search(text)
    reaped = False
    if handler:
        name = handler.group(1)
        body = re.search(rf"^[ \t]*{re.escape(name)}\s*\(\)\s*\{{(.*?)^[ \t]*\}}", text, re.M | re.S)
        reaped = bool(body and "refpeer_reap" in body.group(1))
    return {
        "sourced": SOURCE_LINE in text,
        "up": re.search(r"^\s*refpeer_up\s*$", text, re.M) is not None,
        "flag": "$REFPEER_FLAG" in text,
        "reaped": reaped,
    }


def patch(text):
    """Apply the three anchors. Returns (text, [unmet anchor names])."""
    # 1+2 — source the helper and bring the reference up, BOTH immediately before
    #        the oracle invocation, at its indentation.
    #
    # THE SOURCE LINE MUST SHARE A SHELL WITH THE CALL, AND THAT IS NOT WHERE IT
    # LOOKS LIKE IT BELONGS. The obvious anchor is the harness's own ORACLE= default
    # near the top -- and for the 19 peers that re-exec into their container that
    # line runs on the HOST, while the oracle call runs INSIDE. Measured on `c`: the
    # first cut sourced /work/... host-side (where the path does not exist) and left
    # `refpeer_up` undefined in the container. Anchoring both to the call site makes
    # the scope question unaskable.
    # $REFPEER_FLAG goes into the argument list BEFORE "$@" so an explicit caller
    # value still wins (Go's flag package takes the last occurrence).
    def add_flag(m):
        rest = m.group("rest")
        if "$REFPEER_FLAG" in rest:
            return m.group(0)
        return f'{m.group("indent")}{m.group("lead")}{m.group("pre")} $REFPEER_FLAG{rest}'

    new = ORACLE_CALL.sub(add_flag, text, count=1)
    if new != text or "$REFPEER_FLAG" in text:
        text = new
        m = ORACLE_CALL.search(text)
        if m and not re.search(r"^\s*refpeer_up\s*$", text, re.M):
            line_start = text.rfind("\n", 0, m.start()) + 1
            ind = m.group("indent")
            text = (text[:line_start] + ind + SOURCE_LINE + "\n"
                    + ind + "refpeer_up\n" + text[line_start:])

    # 3 — refpeer_reap as the first statement of the existing teardown function.
    h = TRAP.search(text)
    if h:
        name = h.group(1)
        fn = re.search(rf"^([ \t]*{re.escape(name)}\s*\(\)\s*\{{\n)", text, re.M)
        if fn and "refpeer_reap" not in text:
            # GUARDED, because the trap is installed BEFORE the helper is sourced: a
            # peer that dies before LISTENING fires this teardown with refpeer_reap
            # undefined. An `&&` form would return non-zero and, under `set -e`,
            # abort the teardown before the TARGET is reaped -- turning a helper
            # detail into a leaked peer process.
            ind = re.match(r"\s*", fn.group(1)).group(0).replace("\n", "")
            text = (text[: fn.end(1)]
                    + ind + "  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi\n"
                    + text[fn.end(1):])

    return text


def main():
    check_only = "--check" in sys.argv
    names = peers()
    unpatched, changed = [], []

    for name in names:
        f = GEN / name / "run-s4.sh"
        original = f.read_text()
        text = original if check_only else patch(original)
        if not check_only and text != original:
            f.write_text(text)
            changed.append(name)
        props = properties(text)
        missing = [k for k, v in props.items() if not v]
        if missing:
            unpatched.append((name, missing))

    # THE COUNT IS THE POINT. A gate that examined zero things prints the same word
    # as one that examined 46 (AGENTS.md, ratified twice).
    ok = len(names) - len(unpatched)
    if not check_only:
        print(f"fold-reference-peer: modified {len(changed)} harness(es)")
    print(f"fold-reference-peer: {ok} of {len(names)} harnesses carry the reference peer")
    if unpatched:
        print("\nUNPATCHED — hand work required (anchor not found):")
        for name, missing in unpatched:
            print(f"  {name:<22} missing: {', '.join(missing)}")
        return 1
    if len(names) != 46:
        print(f"  WARNING roster is {len(names)}, expected 46", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
