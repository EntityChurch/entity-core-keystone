#!/usr/bin/env bash
# §10.2 origination-core probe — Haskell target (A-role) against the Go entity-peer
# reference (B-role). Both run inside ghc-toolchain (the Go ELFs run there too);
# shared loopback, sealed-offline (--network=none).
#
# Post-§7a resolution (2026-06-13): runOriginationCore IS the
# dispatch_outbound_reentry probe — the validator mints a reentry capability,
# EXECUTEs system/validate/dispatch-outbound on the target, and the target
# originates an outbound EXECUTE back to the validator-as-B over the SAME inbound
# connection (§6.11 reentry; NOT a fresh dial to the reference). The Go reference
# is connected only to keep the gate's input shape (`-reference-peer required`)
# consistent with --profile full; otherwise unused under core. The target MUST run
# with --validate (system/validate/dispatch-outbound live); absent it the probe
# honest-SKIPs — which is why the single-peer run-s4.sh honest-SKIPs origination.
#
# Haskell note: the §6.11 outbound/reentry seam is the native forkIO + STM build
# (Transport.hs reader-demux + request_id↔reply correlation in a TVar pending map +
# Peer.outboundDispatch). This gate is the cross-impl wire proof of it. GHC's
# -threaded RTS multiplexes the blocking inbound read with the outbound await on
# the same connection (N6), so the reentry leg does not stall the reader.
#
# Invoke from the repo root:
#   ./protocol-generator/haskell/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ghc-toolchain:latest"
WORKDIR="/work/protocol-generator/haskell"
TPORT="${TPORT:-7777}"   # target (Haskell)
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e CABAL_DIR=/work/protocol-generator/haskell/.cabal-home \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    TPORT="'"$TPORT"'"; RPORT="'"$RPORT"'"; ORACLE="'"$ORACLE"'"; REFPEER="'"$REFPEER"'"
    if [ "${NOBUILD:-0}" != "1" ]; then cabal build exe:host --offline >/dev/null 2>&1; fi
    HOST_BIN="$(find dist-newstyle -name host -type f -path "*/build/host/host" | head -1)"
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Haskell host (A-role) — --validate makes system/validate/dispatch-outbound live.
    "$HOST_BIN" --port "$TPORT" --debug-open-grants --validate +RTS -N -RTS \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 200 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Haskell host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give Go reference a moment to bind
    echo "target(Haskell)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
