#!/usr/bin/env bash
# S4 conformance harness — drive the REAL Go `validate-peer` oracle against the SQL
# (authority-as-query) peer over loopback TCP, fully offline (--network=none; loopback
# is up in the isolated netns). The oracle is a static CGO_ENABLED=0 fedora:43 ELF, so
# it runs INSIDE the sqlite-toolchain image alongside the peer — one loopback, sealed.
#
# The gate is `validate-peer --profile core` → `Result: PASS` with 0 fail. `--profile core`
# IS the gate (it scopes the core categories, applies the §9.5 53-type floor, and auto-
# allowlists the §9.0 extension carve-out skips). Do NOT hand-maintain a category list;
# repeated -category flags do NOT accumulate (Go's flag parser: last wins).
#
#   ./run-s4.sh                        # full core gate → the JSON report (scratch by default; see JSON_OUT below)
#   ./run-s4.sh -category authz -verbose
#   ./run-s4.sh -profile core -verbose
#
# The peer runs with `--debug-open-grants --validate --name conformance`:
#   --debug-open-grants  the degenerate default→* seed (grant-gated categories need it)
#   --validate           enables the §7a system/validate/{echo,dispatch-outbound} handlers
#   --name conformance   loads the persistent Ed25519 identity from
#                        ~/.entity/peers/conformance/keypair (provisioned below with the
#                        cohort's deterministic 0x11×32 seed) so the validator's multisig
#                        accept-path probe can co-sign AS the peer.
#
# Oracle pinned at cc1970f (tools/oracle-pin.env; gitignored binary in output/s4-oracles/,
# (re)built via tools/oracle-bootstrap.sh). Cohort constant: 682·0F @ cc1970f.
#
# JSON_OUT — WHERE A BARE RUN WRITES ITS REPORT (changed 2026-09-08)
# A bare `./run-s4.sh` used to default `-json-out` to this peer's TRACKED
# status/CONFORMANCE-REPORT.json — the signed-off record the matrix publishes — so a
# human diagnostic run silently republished a number nobody had reviewed. The default is
# now a scratch path. To refresh the tracked report, MEASURE it deliberately:
#     tools/run-cohort-census.sh --to-status <peer>       (preferred)
#     JSON_OUT=<path> ./run-s4.sh                          (explicit)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/sqlite-toolchain:latest"
WORKDIR="/work/protocol-generator/sql"
PORT="${ECPORT:-15250}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness -- but that also swallows a MISSING
# binary, and the script would exit 0 having validated nothing.
# $ORACLE is a CONTAINER path -- the repo root is mounted at /work -- so the existence
# test has to be made against the HOST path, or it can never pass. Measured 2026-08-27:
# in this form the guard rejected all 33 peers carrying it. It had never been executed.
ORACLE_HOST="$ORACLE"
case "$ORACLE_HOST" in
  /work/*) ORACLE_HOST="$(cd "$(dirname "$0")/../.." && pwd)/${ORACLE_HOST#/work/}" ;;
esac
[ -x "$ORACLE_HOST" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE_HOST" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
EC_NAME="${EC_NAME:-conformance}"

# Default: the full core-profile gate with the JSON report.
if [ "$#" -eq 0 ]; then set -- -profile core -json-out "${JSON_OUT:-/tmp/ec-s4-sql.json}"; fi

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e ORACLE="$ORACLE" -e PORT="$PORT" -e EC_NAME="$EC_NAME" \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -e
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    # persistent identity: the cohort deterministic 0x11×32 seed (entity-core PEM = base64 of the 32-byte seed)
    KPDIR="${HOME:-/root}/.entity/peers/$EC_NAME"; mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    make peer >/tmp/build-s4.log 2>&1 || { echo "peer build failed:"; cat /tmp/build-s4.log; exit 1; }
    /tmp/ec-sql-build/ec-sql-peer --name "$EC_NAME" --debug-open-grants --validate --port "$PORT" >/tmp/peer-s4.log 2>/tmp/peer-s4.err &
    PP=$!
    # Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
    # trap returns while the peer still owns the listening socket and a second invocation
    # in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
    # accepting connections AFTER the harness had exited: elixir >400ms (and the next run
    # did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
    # property of the peer runtime, not of the harness, which is why every peer carries
    # this and not only the ones that were seen to fail.
    reap_host() {
      if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
      [ -n "${PP:-}" ] || return 0
      kill -0 "$PP" 2>/dev/null || return 0
      kill -TERM "$PP" 2>/dev/null || true
      # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
      # killed, instead of hanging the run forever.
      j=0
      while [ "$j" -lt 50 ]; do
        kill -0 "$PP" 2>/dev/null || return 0
        j=$((j + 1))
        sleep 0.1
      done
      kill -KILL "$PP" 2>/dev/null || true
      wait "$PP" 2>/dev/null || true
    }
    trap reap_host EXIT
    sleep 1
    kill -0 $PP 2>/dev/null || { echo "peer failed to start:"; cat /tmp/peer-s4.log /tmp/peer-s4.err; exit 1; }
    . /work/protocol-generator/shared/tools/refpeer.sh
    refpeer_up
    rc=0; "$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || rc=$?

    # SURFACE THE STDERR OF THE PEER ITSELF. /tmp/peer-s4.err is a path INSIDE a --rm
    # container, so without this the dying words of the peer are discarded with the
    # container and a mid-run abort leaves a log reading only "connection refused".
    # That is not hypothetical: the zig intermittent survived four investigations
    # reported as "no crash, empty stderr" until this line existed on that harness,
    # and then produced a stack trace on the first reproduction. Emitted on stderr so
    # it cannot be mistaken for oracle output, and only when non-empty so a clean run
    # stays quiet.
    if [ -s /tmp/peer-s4.err ]; then
      echo "--- peer stderr (/tmp/peer-s4.err) ---" >&2
      cat /tmp/peer-s4.err >&2
    fi
    exit "$rc"
  ' bash "$@"
