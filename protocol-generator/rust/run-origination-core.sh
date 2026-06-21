#!/bin/sh
# §10.2 origination-core probe — Rust target (A-role) against the Go entity-peer
# reference (B-role). Both run inside the rust-toolchain container (the Go ELFs run
# there too); shared loopback, sealed-offline with --network=none.
#
# Post-§7a resolution (2026-06-13): runOriginationCore is the dispatch_outbound_reentry
# probe — the validator mints a reentry capability, EXECUTEs system/validate/dispatch-
# outbound on the target, and the target originates an outbound EXECUTE back to the
# validator-as-B over the SAME inbound connection (§6.11 reentry; NOT a fresh dial to
# the reference). The Go reference entity-peer is connected only to keep the gate's
# input shape (`-reference-peer required`) consistent with --profile full; it is
# otherwise unused under core. The target MUST run with --validate (system/validate/
# dispatch-outbound live); absent it the probe honest-SKIPs — which is why the
# single-peer run-s4.sh honest-SKIPs origination.
#
# Rust transport note: the §6.11 outbound/reentry seam is the transport.rs reader-demux
# (request_id → condvar slot) + the §6.13(b) OutboundFn seam; each inbound EXECUTE is
# served on its own std::thread (N6) so the reentry leg does not stall the reader.
#
# Rust uses loopback port 7777 (target); the Go reference entity-peer binds 7778.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none --security-opt label=disable \
#     -v "$PWD":/work:Z \
#     entity-core-keystone/rust-toolchain:latest \
#     sh /work/protocol-generator/rust/run-origination-core.sh
set -eu
TPORT="${TPORT:-7777}"   # target (Rust)
RPORT="${RPORT:-7778}"   # reference (Go entity-peer)
PROJ=/work/protocol-generator/rust
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
cd "$PROJ"

# Offline cargo: replace crates-io with the vendored mirror.
export CARGO_HOME=/tmp/cargo-home
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "$PROJ/output/vendor"
EOF

[ "${NOBUILD:-0}" = "1" ] || cargo build --release --offline --bin entity-peer-host >/dev/null 2>/tmp/build.err || {
  echo "peer build failed:" >&2; cat /tmp/build.err >&2; exit 1; }
HOST_BIN="$PROJ/target/release/entity-peer-host"

# Reference Go entity-peer (B-role), open-access (degenerate seed policy at 33f35fd).
"$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target Rust host (A-role) — --validate makes system/validate/dispatch-outbound live.
"$HOST_BIN" --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 200 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Rust host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give the Go reference a moment to bind
echo "target(Rust)=$(head -1 /tmp/host.out)  reference(Go entity-peer) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
