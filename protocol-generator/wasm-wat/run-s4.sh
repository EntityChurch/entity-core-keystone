#!/bin/sh
# S4 conformance harness — entity-core-protocol-wasm-wat (hand-authored WAT peer).
#
# Runs inside the wasm-wat-toolchain container (the Go validate-peer oracle is a fedora:43
# ELF that runs there too, sharing one loopback; --network=none keeps it sealed). Builds the
# merged peer.wasm (make peer), launches it under WasmEdge, waits for LISTENING, points
# validate-peer at it, tears it down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z entity-core-keystone/wasm-wat-toolchain:latest \
#     sh /work/protocol-generator/wasm-wat/run-s4.sh [validate-peer-args...]
#
# Identity is the hardcoded cohort conformance seed (0x11×32 → the same peer_id --name
# conformance yields), so extra launch args (--name) are tolerated/ignored. --port is 7777.
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
PROJ=/work/protocol-generator/wasm-wat
# --debug-open-grants is the cohort gate: the degenerate default→* seed policy so the grant-gated
# categories (capability, handlers, tree, authz, concurrency, universal_address_space) actually
# RUN instead of honest-SKIPping under the discovery-only floor identity.
# --validate arms the §7a conformance scaffold (system/validate/{echo,dispatch-outbound}) so the
# reentrant-dispatch checks (validate_echo_dispatch, t1_2_concurrent_reentry) RUN and PASS — the
# dialer is a real same-connection §6.11 reentrant outbound seam (dispatch.wat serve_dispatch_
# outbound + serve_resume). The scaffold stays OFF in the peer's production default (opt-in).
PEERFLAGS="${PEERFLAGS:---debug-open-grants --validate}"

# Provision the peer keypair at ~/.entity/peers/conformance/keypair (seed 0x11x32, base64
# "ERER...") so the validator can co-sign AS this peer. host.wat hardcodes that same seed
# ($seed, src/host.wat), so the file is a second copy of an identity the peer already has —
# what it adds is the ORACLE's ability to author entities the peer will accept as granter-
# signed. Without it four checks cannot construct their fixtures and SKIP: the three §3.6
# multisig probes (M4 below-threshold pair + the M6 accept path) and CAP-6a
# ingest_rejects_unrepresentable_expiry, whose control is a round-tripped token that must
# carry a valid granter signature before temporal validation is ever reached.
# Every other peer in the cohort has provisioned this since the multisig accept path landed;
# wasm-wat never did, so its skips read as substrate limits rather than a missing setup file.
KPDIR="${HOME:-/root}/.entity/peers/conformance"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cd "$PROJ"

[ "${NOBUILD:-0}" = "1" ] || make peer >/dev/null

# --enable-jit is load-bearing: WasmEdge's default interpreter runs the codec's Ed25519 verify at
# ~9 ms/op, so §5.2's two per-request signature verifies (~18 ms) cannot sustain the §6.11
# 10k-request t2_1/t2_2 robustness probes within the window. JIT drops verify to ~84 µs (~107×),
# making full per-request verification fast enough — no auth-caching shortcut needed (which
# tampered_signature proves would be non-conformant). See status/PHASE-S3.md.
wasmedge --enable-jit out/peer.wasm $PEERFLAGS >/tmp/host.out 2>/tmp/host.err &
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

# The peer IS launched with --validate (see PEERFLAGS), so the §7a conformance-handler scaffold
# is present and the two reentrant-dispatch checks (validate_echo_dispatch, t1_2_concurrent_
# reentry) RUN and PASS — no allow-skip needed. This is true cohort parity: the dialer is a real
# same-connection §6.11 reentrant outbound seam, not a declined opt-in. (See status/PHASE-S3.md.)
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
