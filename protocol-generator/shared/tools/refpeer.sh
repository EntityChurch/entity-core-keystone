# refpeer.sh — the B-role reference peer, one copy, sourced by every run-s4.sh.
#
# WHY THIS EXISTS
#   `validate-peer --profile core` executes 756 checks. With `-reference-peer <addr>`
#   it executes 758: `origination/dispatch_outbound_reentry`, `reference_connect` and
#   `reference_ready` run instead of collapsing into one `origination: skipped`
#   placeholder. Measured 2026-09-03 against the reference peer, one flag at a time.
#
#   The census had NEVER passed that flag. That is the only reason a separate
#   `run-origination-core.sh` existed on 31 peers and was ABSENT on 15 — a whole axis
#   that was a workaround for a flag nobody passed, and 15 peers with no coverage of
#   it at all. Folding it in here retires the axis and covers those 15.
#
# WHY A SOURCED HELPER AND NOT 46 COPIES
#   The standing one-copy rule (AGENTS.md, the superseded-corpus entry): a second copy
#   of a thing is a second authority. 46 hand-edited copies of a process-lifetime
#   dance is how the fire-and-forget teardown defect reached 45 of 46 harnesses.
#
# CONTRACT FOR THE CALLER — THREE anchor points, deliberately few, because this is
# rolled out across 46 heterogeneous harnesses and every extra anchor is another way
# for a mechanical sweep to half-apply:
#   1. `. /work/protocol-generator/shared/tools/refpeer.sh`   (after PORT is set)
#   2. `refpeer_up`                                           (immediately before the
#      oracle invocation — starts the reference AND waits for it to be ready)
#   3. `refpeer_reap` as the FIRST line of the harness's existing teardown function.
#   Then pass `$REFPEER_FLAG` to the oracle, BEFORE "$@", so an explicit caller value
#   still wins (Go's flag package takes the last occurrence).
#
# NO APOSTROPHES ANYWHERE IN THIS FILE'S CALL SITES. 19 harnesses re-exec into their
#   container with the inner script as a single-quoted argument, so one apostrophe in
#   inserted text closes the quote and the failure is reported in text that never
#   existed. This file is SOURCED rather than inlined precisely so its body is exempt
#   from that constraint -- but the three call-site lines above are not.
#
# ENV: RPORT (default PORT+1), REFPEER (default the pinned entity-peer).

RPORT="${RPORT:-$((${PORT:-7777} + 1))}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
REFPEER_FLAG=""
REFPEER_LOG="${REFPEER_LOG:-/tmp/ref.err}"

# Loopback is private to this container (--network=none), so PORT+1 cannot collide
# with any other peer's run. Under --profile core the reference is connected and
# otherwise unused -- the §6.11 reentry probe uses the VALIDATOR as B over the same
# inbound connection, not a fresh dial -- but it must still be a real entity-peer,
# because reference_connect and reference_ready assert against it.
refpeer_start() {
  # A MISSING REFERENCE MUST BE FATAL, NOT SILENT. Without this the three checks
  # quietly become skips again, and a skip counts as a failure ([ADR-0012]) -- the
  # exact silent coverage loss this fold exists to end.
  if [ ! -x "$REFPEER" ]; then
    echo "refpeer: ERROR reference peer not found at $REFPEER" >&2
    echo "  Built from the sibling entity-core-go at the pinned oracle digest;" >&2
    echo "  run tools/oracle-bootstrap.sh." >&2
    exit 3
  fi
  "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>"$REFPEER_LOG" &
  REF_PID=$!
}

# The reference logs readiness to STDERR, not stdout. Poll for it rather than
# sleeping: a fixed sleep is either too slow 46 times over or too short on a loaded
# host, and a reference that is not up yet fails reference_connect in a way that
# reads as a defect in the peer under test.
# The single call site: start the reference and block until it is serving. Starting
# it here rather than alongside the target costs ~200 ms and buys one anchor instead
# of two -- worth it at 46 harnesses.
refpeer_up() {
  refpeer_start
  refpeer_wait
}

refpeer_wait() {
  [ -n "${REF_PID:-}" ] || return 0
  r=0
  while [ "$r" -lt 100 ]; do
    if grep -q "Ready to accept connections" "$REFPEER_LOG" 2>/dev/null; then
      REFPEER_FLAG="-reference-peer 127.0.0.1:$RPORT"
      return 0
    fi
    if ! kill -0 "$REF_PID" 2>/dev/null; then
      echo "refpeer: ERROR reference exited before ready" >&2
      cat "$REFPEER_LOG" >&2
      exit 1
    fi
    r=$((r + 1))
    sleep 0.1
  done
  echo "refpeer: ERROR reference never became ready on :$RPORT" >&2
  cat "$REFPEER_LOG" >&2
  exit 1
}

# Called FIRST from the harness teardown, above any early-out that returns when the
# target is already gone -- otherwise the reference and its listening socket leak
# into the next invocation in this container. TERM, bounded poll, then KILL, so the
# `wait` cannot block on a process that ignores TERM.
refpeer_reap() {
  [ -n "${REF_PID:-}" ] || return 0
  kill -0 "$REF_PID" 2>/dev/null || return 0
  kill -TERM "$REF_PID" 2>/dev/null || true
  k=0
  while [ "$k" -lt 50 ]; do
    kill -0 "$REF_PID" 2>/dev/null || break
    k=$((k + 1))
    sleep 0.1
  done
  kill -KILL "$REF_PID" 2>/dev/null || true
  wait "$REF_PID" 2>/dev/null || true
}
