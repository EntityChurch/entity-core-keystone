#!/usr/bin/env bash
# S3 peer machinery — the two-direction loopback smoke gate, container-bound and
# sealed-offline (--network=none, loopback only). Mirrors the Java/Zig S3
# precedent: boots the GO REFERENCE PEER (`entity-peer`) + the Ada peer over real
# loopback TCP inside ONE fedora:43 container (the ada-toolchain image), so the
# reference + the peer share one loopback and the run stays offline.
#
#   Scenario A (Ada dials Go):   the Ada initiator peer dials the Go entity-peer,
#                                drives the §4.1 handshake (hello+authenticate),
#                                EXECUTE→unregistered path→404, request_id demux.
#   Scenario B (Go dials Ada):   the Go `probe-peer` client dials the Ada Host,
#                                completing the handshake from the OTHER side +
#                                a tree get + a 404 — proves the Ada RESPONDER is
#                                wire-compatible with the Go client.
#
# The Go binaries are VENDORED from the Go oracle (entity-core-go, read-only) by
# a host `go build` (CGO_ENABLED=0 → a static fedora:43-runnable ELF, the cohort
# pattern). The Ada peer is built by gprbuild inside the container (offline).
#
#   ./run-s3.sh            # build (if needed) + the two-direction smoke gate
#   ./run-s3.sh build      # gprbuild the Ada peer only
#   NOBUILD_GO=1 ./run-s3.sh   # skip the go vendor build (reuse .s3-oracle/)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ada-toolchain:latest"
WORKDIR="/work/protocol-generator/ada"
ADA_DIR="$REPO_ROOT/protocol-generator/ada"
GO_ORACLE="${GO_ORACLE:-$HOME/projects/entity-systems/entity-core-go}"
ORACLE_DIR="$ADA_DIR/.s3-oracle"          # gitignored; vendored go ELFs land here

# ── 1. Vendor the Go reference binaries (host build from the Go oracle) ──────────
if [ "${NOBUILD_GO:-0}" != "1" ]; then
  mkdir -p "$ORACLE_DIR"
  echo "vendoring go reference peer from $GO_ORACLE (HEAD $(git -C "$GO_ORACLE" rev-parse --short HEAD))"
  if [ -n "$(git -C "$GO_ORACLE" status -s)" ]; then
    echo "WARNING: go oracle working tree is not clean" >&2
  fi
  ( cd "$GO_ORACLE/cmd" \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$ORACLE_DIR/entity-peer" ./entity-peer \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$ORACLE_DIR/probe-peer"  ./probe-peer )
fi

# ── 2. Build the Ada peer (offline, in-container) ───────────────────────────────
build() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    gprbuild -P entity_core_protocol.gpr -p
}

if [ "${1:-all}" = "build" ]; then
  build
  exit 0
fi

build

# ── 3. The two-direction smoke, inside the container over loopback ──────────────
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -u
    ORACLE="'"$WORKDIR"'/.s3-oracle"
    PASS=0; FAIL=0

    # ── Scenario A: Ada dials the Go reference peer ──────────────────────────────
    "$ORACLE/entity-peer" -addr 127.0.0.1:0 -ready-file /tmp/go.json >/tmp/go.out 2>/tmp/go.err &
    GO_PID=$!
    for i in $(seq 1 50); do [ -f /tmp/go.json ] && break; sleep 0.1; done
    if ! [ -f /tmp/go.json ]; then echo "go entity-peer never became ready"; cat /tmp/go.err; exit 1; fi
    GO_ADDR=$(sed -n "s/.*\"addr\":\"\([^\"]*\)\".*/\1/p" /tmp/go.json)
    echo "go entity-peer ready at $GO_ADDR (peer $(sed -n "s/.*\"peer_id\":\"\([^\"]*\)\".*/\1/p" /tmp/go.json))"
    ./bin/smoke_s3 "$GO_ADDR"; A_RC=$?
    kill $GO_PID 2>/dev/null || true
    if [ "$A_RC" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

    echo
    echo "Scenario B — Go probe-peer dials the Ada Host:"

    # ── Scenario B: Go probe-peer dials the Ada responder ────────────────────────
    ./bin/host --port 0 >/tmp/ada.out 2>/tmp/ada.err &
    ADA_PID=$!
    for i in $(seq 1 50); do grep -q "^LISTENING" /tmp/ada.out 2>/dev/null && break; sleep 0.1; done
    if ! grep -q "^LISTENING" /tmp/ada.out 2>/dev/null; then
      echo "  [FAIL] Ada host never printed LISTENING"; cat /tmp/ada.err; FAIL=$((FAIL+1));
    else
      ADA_PORT=$(sed -n "s/^LISTENING *//p" /tmp/ada.out | tr -d " ")
      echo "  ada host listening on 127.0.0.1:$ADA_PORT ($(sed -n "s/^PEER //p" /tmp/ada.out))"
      # B.1 handshake + a granted tree get (system/handler/ is in the discovery floor).
      if "$ORACLE/probe-peer" -addr "127.0.0.1:$ADA_PORT" "system/handler/" >/tmp/probe1.out 2>&1 \
           && grep -q "Connected to" /tmp/probe1.out \
           && grep -q "Remote PeerID:" /tmp/probe1.out; then
        echo "  [PASS] Go client completed §4.1 handshake against the Ada responder"; PASS=$((PASS+1))
      else
        echo "  [FAIL] Go client handshake against the Ada responder"; sed "s/^/    /" /tmp/probe1.out | head -20; FAIL=$((FAIL+1))
      fi
      # B.2 unregistered path → 404 (floor-allowed read of an unbound leaf).
      "$ORACLE/probe-peer" -addr "127.0.0.1:$ADA_PORT" "system/handler/go-probe-unregistered" >/tmp/probe2.out 2>&1 || true
      if grep -q "status 404" /tmp/probe2.out; then
        echo "  [PASS] Go client: unregistered path on the Ada responder → 404"; PASS=$((PASS+1))
      else
        echo "  [FAIL] Go client: expected 404 from the Ada responder"; sed "s/^/    /" /tmp/probe2.out | tail -10; FAIL=$((FAIL+1))
      fi
    fi
    kill $ADA_PID 2>/dev/null || true

    echo
    echo "============================================================"
    echo "S3 SMOKE: $PASS check-group(s) PASS, $FAIL FAIL"
    if [ "$FAIL" -eq 0 ]; then echo "S3 SMOKE: GREEN"; exit 0; else echo "S3 SMOKE: RED"; exit 1; fi
  '
