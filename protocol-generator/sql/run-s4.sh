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
#   ./run-s4.sh                        # full core gate → status/CONFORMANCE-REPORT.json
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
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/sqlite-toolchain:latest"
WORKDIR="/work/protocol-generator/sql"
PORT="${ECPORT:-15250}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
EC_NAME="${EC_NAME:-conformance}"

# Default: the full core-profile gate with the JSON report.
if [ "$#" -eq 0 ]; then set -- -profile core -json-out "$WORKDIR/status/CONFORMANCE-REPORT.json"; fi

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
    /tmp/ec-sql-build/ec-sql-peer --name "$EC_NAME" --debug-open-grants --validate --port "$PORT" >/tmp/peer-s4.log 2>&1 &
    PP=$!
    trap "kill $PP 2>/dev/null || true" EXIT
    sleep 1
    kill -0 $PP 2>/dev/null || { echo "peer failed to start:"; cat /tmp/peer-s4.log; exit 1; }
    "$ORACLE" -addr "127.0.0.1:$PORT" "$@"
  ' bash "$@"
