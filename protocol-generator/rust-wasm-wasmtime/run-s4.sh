#!/bin/sh
# S4 conformance harness — entity-core-protocol-rust-wasm-wasmtime (the Rust peer compiled
# to wasm32-wasip1, precompiled to native code and run under WASMTIME/AOT). Direct analog
# of ../rust-wasm/run-s4.sh; the differences are (1) the runtime is wasmtime not WasmEdge,
# (2) the peer runs as AOT-native `.cwasm` not JIT, (3) the listener is HOST-preopened via
# `-S tcplisten` (the guest accepts on it) rather than self-bound. Same interior, same
# oracle, same loopback — so this isolates runtime + execution-mode for the AOT column.
#
# Runs inside the rust-wasm-wasmtime-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, sharing one loopback; --network=none keeps it
# sealed). Mount a cargo cache at /cargo so the one-time crate fetch is reused.
#
# Invoke from the repo root:
#   podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z \
#     localhost/entity-core-keystone/rust-wasm-wasmtime-toolchain:latest \
#     sh /work/protocol-generator/rust-wasm-wasmtime/run-s4.sh [validate-peer-args...]
#
# MODE=aot (default) runs out/peer.cwasm (--allow-precompiled). MODE=wasm runs out/peer.wasm
# directly (wasmtime JIT-compiles it) — for the AOT-vs-JIT-warmup datapoint on ONE runtime.
#
# JSON_OUT — WHERE A BARE RUN WRITES ITS REPORT (changed 2026-09-08)
# A bare `./run-s4.sh` used to default `-json-out` to this peer's TRACKED
# status/CONFORMANCE-REPORT.json — the signed-off record the matrix publishes — so a
# human diagnostic run silently republished a number nobody had reviewed. The default is
# now a scratch path. To refresh the tracked report, MEASURE it deliberately:
#     tools/run-cohort-census.sh --to-status <peer>       (preferred)
#     JSON_OUT=<path> ./run-s4.sh                          (explicit)
set -eu
PORT="${PORT:-7777}"
MODE="${MODE:-aot}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
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
PROJ=/work/protocol-generator/rust-wasm-wasmtime
# --debug-open-grants: the degenerate default→* seed policy so grant-gated categories RUN.
# --validate: arm the §7a conformance scaffold (reentrant-dispatch checks). Both OFF in
# production default. These go to the GUEST (after the module path), not to wasmtime.
PEERFLAGS="${PEERFLAGS:---debug-open-grants --validate}"
cd "$PROJ"

# The peer's identity is compiled in (the cohort seed 0x11 x 32), but the VALIDATOR
# needs the same key ON DISK at the peer-manager location to co-sign AS the peer for
# the M6 root-at-local multisig accept path. Without it those three checks SKIP:
#   "accept-path requires the peer's on-disk key (M6 root-at-local): peer keypair not found"
# That is not a --profile core carve-out, it is an unconfigured surface -- and a skip
# counts as a FAIL ([ADR-0012]). These two peers were the ONLY 2 of 46 harnesses with no
# keypair provisioning, which is why they alone reported 109 skips against the cohort's
# 106 while publishing 0-FAIL. Found 2026-09-03 by asking, of every tracked report,
# which skips are NOT explained by a declared carve-out.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

if [ "$MODE" = "aot" ]; then
  [ "${NOBUILD:-0}" = "1" ] || make aot >/dev/null
  MODULE="out/peer.cwasm"
  PRECOMPILED="--allow-precompiled"
else
  [ "${NOBUILD:-0}" = "1" ] || make peer >/dev/null
  MODULE="out/peer.wasm"
  PRECOMPILED=""
fi

# `-S preview2=n` selects wasmtime's legacy wasip1 implementation — the one that supports
# `-S tcplisten` (the host-preopened Berkeley listener the guest accepts on). `-S tcplisten`
# grants the listen socket bound to 127.0.0.1:$PORT; the guest receives it as a preopened fd.
# No `--run-mode` flag — AOT means the .cwasm is already native (this is the WasmEdge
# `--enable-jit` analog made unnecessary: Cranelift compiled per-request Ed25519 verify to
# native code ahead of time, so §6.11 t2_1/t2_2 sustain full verification with no JIT warmup).
wasmtime run \
  -S preview2=n \
  -S tcplisten="127.0.0.1:$PORT" \
  $PRECOMPILED \
  "$MODULE" $PEERFLAGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
reap_host() {
  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
  [ -n "${HOST_PID:-}" ] || return 0
  kill -0 "$HOST_PID" 2>/dev/null || return 0
  kill -TERM "$HOST_PID" 2>/dev/null || true
  # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
  # killed, instead of hanging the run forever.
  j=0
  while [ "$j" -lt 50 ]; do
    kill -0 "$HOST_PID" 2>/dev/null || return 0
    j=$((j + 1))
    sleep 0.1
  done
  kill -KILL "$HOST_PID" 2>/dev/null || true
  wait "$HOST_PID" 2>/dev/null || true
}
trap reap_host EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "peer exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1
  fi
  i=$((i + 1)); sleep 0.1
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "${JSON_OUT:-/tmp/ec-s4-rust-wasm-wasmtime.json}"
fi
. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || true

# SURFACE THE STDERR OF THE PEER ITSELF. /tmp/host.err is a path INSIDE a --rm
# container, so without this the dying words of the peer are discarded with the
# container and a mid-run abort leaves a log reading only "connection refused".
# That is not hypothetical: the zig intermittent survived four investigations
# reported as "no crash, empty stderr" until this line existed on that harness,
# and then produced a stack trace on the first reproduction. Emitted on stderr so
# it cannot be mistaken for oracle output, and only when non-empty so a clean run
# stays quiet.
if [ -s /tmp/host.err ]; then
  echo "--- peer stderr (/tmp/host.err) ---" >&2
  cat /tmp/host.err >&2
fi
