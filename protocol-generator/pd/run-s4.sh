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
#   ./run-s4.sh                      # -category connectivity (the handshake leg)
#   ./run-s4.sh -category connectivity -verbose
#   ./run-s4.sh -profile core        # the full core gate (once the peer is further along)
#   PATCH=src/handshake-test.pd ./run-s4.sh   # override the served patch
#   ./run-s4.sh -category authz               # the §5.2 verify_request DENY paths
#
# STATUS: src/main.pd (the composed peer) passes connectivity 22/22 clean. The
# §5.2 authz ladder passes the DENY paths reachable by a core peer (deny_default,
# grantee→401, no_catchall, expired); delegate_grant/scope_exceeds/revoked need
# handler machinery (system/role, system/capability:request) — see status/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/puredata-toolchain:latest"
WORKDIR="/work/protocol-generator/pd"
PATCH="${PATCH:-src/main.pd}"
PORT="${ECPORT:-15104}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
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

# Default oracle args: the connectivity category (exercises the §4.1 handshake).
if [ "$#" -eq 0 ]; then set -- -category connectivity; fi

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
    make external >/dev/null 2>&1
    pd -nogui -noaudio -stderr -path build -open "$PATCH" >build/s4-pd.log 2>&1 &
    PDPID=$!
    trap "kill $PDPID 2>/dev/null || true" EXIT
    sleep 2
    kill -0 $PDPID 2>/dev/null || { echo "pd failed to start:"; cat build/s4-pd.log; exit 1; }
    "$ORACLE" -addr "127.0.0.1:$PORT" "$@"
  ' bash "$@"
