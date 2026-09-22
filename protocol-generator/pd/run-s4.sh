#!/usr/bin/env bash
# S4 conformance harness — drive the REAL `validate-peer` oracle against the real
# `pd` peer over loopback TCP, fully offline (--network=none; loopback is up in the
# isolated netns). This is the higher-bar live-peer oracle (vs. the hand-rolled
# Python clients of the S3 gates): a real entity-core initiator does the §4.1
# handshake against our peer, so it catches wire shapes a cohort-of-one client can't
# (it is exactly how the §3.1 envelope-wrapper bug was found — the Python clients and
# [ecodec] shared a non-conformant envelope shape and passed against each other).
#
# The oracle (output/s4-oracles/validate-peer) is a static CGO_ENABLED=0 Go binary,
# so it runs in the puredata-toolchain image alongside pd. It is gitignored + NOT
# auto-rebuilt — provenance is tools/oracle-pin.env; (re)build via
# tools/oracle-bootstrap.sh.
#
#   ./run-s4.sh                      # -profile core (the full core gate; matches
#                                     # every other peer's default — a bare invocation
#                                     # must give the real gate verdict, not a single
#                                     # category dressed up as one)
#   ./run-s4.sh -category connectivity -verbose
#   PATCH=src/handshake-test.pd ./run-s4.sh   # override the served patch
#   ./run-s4.sh -category authz               # the §5.2 verify_request DENY paths
#
# STATUS: src/main.pd (the composed peer) passes connectivity 22/22 clean. The
# §5.2 authz ladder passes the DENY paths reachable by a core peer (deny_default,
# grantee→401, no_catchall, expired); delegate_grant/scope_exceeds/revoked need
# handler machinery (system/role, system/capability:request) — see status/.
#
# HISTORY: this defaulted to `-category connectivity` (24 checks) until 2026-07-27.
# That default let a bare invocation print a `Result:` line that reads exactly like
# a gate verdict while never running the gate — corrected to match every sibling
# harness's convention of defaulting to the real `-profile core` run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/puredata-toolchain:latest"
WORKDIR="/work/protocol-generator/pd"
PATCH="${PATCH:-src/main.pd}"
PORT="${ECPORT:-15104}"
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
# Cohort gate convention (mirrors the Go/C peers' `--debug-open-grants --validate`):
# grant-gated categories need the degenerate default→* seed; the §7a
# system/validate/* handlers are conformance scaffolding, OFF outside this harness.
# Pd patches have no argv, so the modes ride as env vars read by [ecodec].
# EC_NAME loads the persistent identity from ~/.entity/peers/$EC_NAME/keypair
# (provisioned below with the cohort's deterministic 0x11×32 seed) so the
# validator's multisig accept-path probe can co-sign AS the peer.
EC_OPEN_GRANTS="${EC_OPEN_GRANTS:-1}"
EC_VALIDATE="${EC_VALIDATE:-1}"
EC_NAME="${EC_NAME:-conformance}"

# Default oracle args: the full core gate, same convention as every sibling harness.
JSON_OUT="${JSON_OUT:-$WORKDIR/status/CONFORMANCE-REPORT.json}"
if [ "$#" -eq 0 ]; then set -- -profile core -json-out "$JSON_OUT"; fi

# Oracle args ("$@") are forwarded as positional parameters into the container
# shell (bash -lc '…' bash "$@") — no string interpolation, so args stay intact.
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e ORACLE="$ORACLE" -e PATCH="$PATCH" -e PORT="$PORT" \
  -e EC_OPEN_GRANTS="$EC_OPEN_GRANTS" -e EC_VALIDATE="$EC_VALIDATE" -e EC_NAME="$EC_NAME" \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -e
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    if [ -n "$EC_NAME" ]; then
      KPDIR="${HOME:-/root}/.entity/peers/$EC_NAME"
      mkdir -p "$KPDIR"
      printf "%s\n%s\n%s\n" \
        "-----BEGIN ENTITY PRIVATE KEY-----" \
        "ERERERERERERERERERERERERERERERERERERERERERE=" \
        "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    fi
    # Quiet on success, but SAY WHY on failure. This used to be
    # `make external >/dev/null 2>&1`: set -e still aborted the run, so a build
    # break was loud, but the REASON was discarded -- and `external` now depends
    # on the patchlint gate, whose whole value is the message naming the file and
    # line. A build that fails without saying why is the Pharo `grep -vi warning`
    # shape one step removed.
    make external >build/s4-make.log 2>&1 \
      || { echo "make external FAILED:" >&2; cat build/s4-make.log >&2; exit 1; }
    pd -nogui -noaudio -stderr -path build -open "$PATCH" >build/s4-pd.log 2>build/s4-pd.err &
    PDPID=$!
    trap "kill $PDPID 2>/dev/null || true" EXIT
    sleep 2
    kill -0 $PDPID 2>/dev/null || { echo "pd failed to start:"; cat build/s4-pd.log build/s4-pd.err; exit 1; }
    rc=0; "$ORACLE" -addr "127.0.0.1:$PORT" "$@" || rc=$?

    # SURFACE THE STDERR OF THE PEER ITSELF. build/s4-pd.err is a path INSIDE a --rm
    # container, so without this the dying words of the peer are discarded with the
    # container and a mid-run abort leaves a log reading only "connection refused".
    # That is not hypothetical: the zig intermittent survived four investigations
    # reported as "no crash, empty stderr" until this line existed on that harness,
    # and then produced a stack trace on the first reproduction. Emitted on stderr so
    # it cannot be mistaken for oracle output, and only when non-empty so a clean run
    # stays quiet.
    if [ -s build/s4-pd.err ]; then
      echo "--- peer stderr (build/s4-pd.err) ---" >&2
      cat build/s4-pd.err >&2
    fi
    exit "$rc"
  ' bash "$@"
