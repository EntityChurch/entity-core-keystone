#!/bin/sh
# S4 conformance harness — entity-core-protocol-asm-arm64 (hand-written aarch64 asm peer,
# run under qemu-user). Mirrors asm-x86_64/run-s4.sh; the one difference is the peer is an
# aarch64 ELF launched via `qemu-aarch64-static` while the Go validate-peer oracle is a native
# x86-64 fedora:43 ELF running directly — they share one loopback, sealed with --network=none.
#
# Runs entirely inside the asm-arm64-toolchain container. Cross-builds the codec .so + the peer
# (make host, which depends on `codec`), provisions the persistent identity, launches the host
# under qemu, waits for its LISTENING line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=4096 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z entity-core-keystone/asm-arm64-toolchain:latest \
#     sh /work/protocol-generator/asm-arm64/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the extension-free gating profile). ORACLE/PORT/NOBUILD/
# CONFORMANCE/PEERNAME env overrides. The codec .so is reached via LD_LIBRARY_PATH; the guest
# loader/libc via QEMU_LD_PREFIX.

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
PROJ=/work/protocol-generator/asm-arm64
CODEC_DIR="${CODEC_DIR:-/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build-aarch64}"
SYSROOT="${SYSROOT:-/usr/aarch64-redhat-linux/sys-root/fc43}"
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  make host >/dev/null           # depends on `codec` → cross-builds the aarch64 .so if absent
fi

# Provision the peer's persistent identity at ~/.entity/peers/NAME/keypair — the entity-core
# PEM = the base64 of a 32-byte seed. Fixed seed 0x11 x 32 (base64 "ERER…") ⇒ deterministic
# peer_id 2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg, matching what the Go oracle derives.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

HOST_ARGS="--port $PORT --name $NAME --debug-open-grants"
if [ "${CONFORMANCE:-1}" = "1" ]; then
  HOST_ARGS="$HOST_ARGS --validate"
fi

# shellcheck disable=SC2086
QEMU_LD_PREFIX="$SYSROOT" LD_LIBRARY_PATH="$CODEC_DIR" \
  qemu-aarch64-static ./bin/host $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
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
