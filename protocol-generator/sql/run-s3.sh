#!/usr/bin/env bash
# S3 gate runner — container-bound, sealed-offline (--network=none; loopback is up in the
# isolated netns), capped. Builds the C host peer + the authored SQL interior and runs the two
# S3 gates:
#
#   1. THE AUTHORITY GATE (make authority-check) — the authority-as-query harness: the VERBATIM
#      src/sql/*.sql (verify_ladder / resolve / k_of_n) run over real Ed25519-signed facts,
#      asserting the §5.2a verdict trichotomy + §4.10 depth-400 pre-check + §6.6 longest-prefix +
#      the mandatory 2-of-3 multisig ACCEPT (A-SQL-004). This is the probe's headline deliverable.
#
#   2. THE SMOKE GATE (ec-sql-peer --selftest) — a real loopback TCP §4.1 handshake both ways
#      (EXECUTE hello → EXECUTE_RESPONSE hello; EXECUTE authenticate with real Ed25519 PoP →
#      EXECUTE_RESPONSE capability grant), a post-auth EXECUTE to an unregistered path → 404
#      (via the authored resolve.sql running in the LIVE host), and request_id demux. Green =
#      the peer talks at the wire level.
#
#   3. (optional) THE LIVE-ORACLE LEG — if output/s4-oracles/validate-peer is present, drive the
#      REAL Go oracle's `connectivity` category against the peer. This is the higher-bar S4
#      preview (final confirmation caveat); reported informationally, NOT the S3 gate.
#
#   ./run-s3.sh            # authority gate + smoke gate (the S3 gates)
#   ./run-s3.sh oracle     # additionally attempt the live validate-peer connectivity leg
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/sqlite-toolchain:latest"
WORKDIR="/work/protocol-generator/sql"
PORT="${ECPORT:-15250}"
EC_NAME="${EC_NAME:-conformance}"
MODE="${1:-gates}"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e EC_NAME="$EC_NAME" -e PORT="$PORT" -e MODE="$MODE" \
    -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" bash -lc "$1"
}

run '
  set -e
  echo "== S3 gate 1: authority-as-query (verbatim src/sql/*.sql over real Ed25519 facts) =="
  make clean >/dev/null 2>&1 || true
  make authority-check

  echo
  echo "== S3 gate 2: peer wire smoke (--selftest: §4.1 handshake both ways + §6.6 404 + §6.11 demux) =="
  make peer >/dev/null
  /tmp/ec-sql-build/ec-sql-peer --selftest --port '"$PORT"'

  if [ "$MODE" = "oracle" ]; then
    echo
    echo "== S3 optional leg: live validate-peer connectivity (S4 preview; informational) =="
    ORACLE=/work/output/s4-oracles/validate-peer
    if [ ! -x "$ORACLE" ]; then echo "oracle not present — skipping (rebuild from go HEAD for S4)"; exit 0; fi
    # persistent identity for the peer (the cohort deterministic 0x11x32 seed)
    KPDIR="${HOME:-/root}/.entity/peers/'"$EC_NAME"'"; mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    EC_NAME='"$EC_NAME"' /tmp/ec-sql-build/ec-sql-peer --name '"$EC_NAME"' --validate --port '"$PORT"' >/tmp/peer.log 2>&1 &
    PP=$!; trap "kill $PP 2>/dev/null || true" EXIT; sleep 1
    "$ORACLE" -addr 127.0.0.1:'"$PORT"' -category connectivity || echo "(connectivity leg not yet green — see status/PHASE-S3.md S4 handoff)"
  fi
'
