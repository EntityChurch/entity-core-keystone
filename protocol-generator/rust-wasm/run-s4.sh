#!/bin/sh
# S4 conformance harness — entity-core-protocol-rust-wasm (the Rust peer compiled to
# wasm32-wasip1, run under WasmEdge). Direct analog of ../wasm-wat/run-s4.sh; the ONLY
# difference is the peer is Rust→LLVM→wasm instead of hand-authored WAT — same runtime,
# same oracle, same loopback, so the head-to-head isolates codegen.
#
# Runs inside the rust-wasm-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, sharing one loopback; --network=none keeps it
# sealed). Mount a cargo cache at /cargo so the one-time crate fetch is reused.
#
# Invoke from the repo root:
#   podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z \
#     localhost/entity-core-keystone/rust-wasm-toolchain:latest \
#     sh /work/protocol-generator/rust-wasm/run-s4.sh [validate-peer-args...]
#
# Identity is the hardcoded cohort conformance seed (0x11×32 → the same peer_id --name
# conformance yields), so extra launch args (--name) are tolerated/ignored. --port 7777.
set -eu
PORT="${PORT:-7777}"
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
PROJ=/work/protocol-generator/rust-wasm
# --debug-open-grants: the degenerate default→* seed policy so grant-gated categories
# actually RUN. --validate: arm the §7a conformance scaffold so the reentrant-dispatch
# checks (validate_echo_dispatch, t1_2_concurrent_reentry) RUN via the same-connection
# reentrant outbound pump (src/main.rs pump_outbound). Both OFF in production default.
PEERFLAGS="${PEERFLAGS:---debug-open-grants --validate}"
cd "$PROJ"

[ "${NOBUILD:-0}" = "1" ] || make peer >/dev/null

# --enable-jit is load-bearing (the wasm-wat finding): WasmEdge's interpreter runs one
# Ed25519 verify at ~ms, so §5.2's two per-request verifies cannot sustain the §6.11
# t2_1/t2_2 10k-request probes. JIT (~µs/verify) makes full per-request verification fast
# enough — no auth-caching shortcut (which tampered_signature proves is non-conformant).
wasmedge --run-mode=jit out/peer.wasm $PEERFLAGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

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
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true

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
