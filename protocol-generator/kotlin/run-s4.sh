#!/usr/bin/env bash
# S4 conformance harness — entity-core-protocol-kotlin (REACH peer; JVM/Kotlin axis).
#
# Runs entirely inside the kotlin-toolchain container (the Go validate-peer oracle is a
# fedora:43 static ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none). Builds the peer's standalone Host launcher via
# Gradle `installDist` (fully offline — kotlin-stdlib / kotlinx-coroutines / kotlin-test
# are pre-fetched into the image's gradle caches at container BUILD time), provisions the
# persistent `conformance` identity on disk (so the validator's multisig accept-path probe
# can co-sign AS the peer), launches the Host with --name conformance --debug-open-grants
# (grant-gated categories need the degenerate seed) + --validate (§7a system/validate/*
# conformance handlers live), waits for its LISTENING readiness line, points validate-peer
# at it, tears the host down.
#
# Invoke from the repo root:
#   ./protocol-generator/kotlin/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the V7 §9.0 core-profile gate) + JSON out.
# Env overrides: ORACLE, PORT, NOBUILD (1=skip gradle), VALIDATE (1=on, 0=exercise SKIP path).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/kotlin-toolchain:latest"
WORKDIR="/work/protocol-generator/kotlin"
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
VALIDATE="${VALIDATE:-1}"
NOBUILD="${NOBUILD:-0}"
JSON_OUT="$WORKDIR/status/CONFORMANCE-REPORT.json"
LAUNCHER="build/install/entity-core-protocol-kotlin/bin/entity-core-protocol-kotlin"

VALIDATE_FLAG=""
[ "$VALIDATE" = "1" ] && VALIDATE_FLAG="--validate"

# Oracle args (default = the core-profile gate). Pass-through if caller supplies any.
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$JSON_OUT"
fi

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; VFLAG="'"$VALIDATE_FLAG"'"; NOBUILD="'"$NOBUILD"'"
    LAUNCHER="'"$LAUNCHER"'"
    # 1. Build the standalone Host launcher (offline installDist).
    if [ "$NOBUILD" != "1" ]; then
      gradle --offline --no-daemon -q installDist >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    # 1b. Provision the peer'"'"'s persistent identity at the standard on-disk location so the
    # validator'"'"'s multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the
    # peer'"'"'s keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising
    # genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches
    # the Host default identity, so peer_id is unchanged (2KHoAk…). NAME follows the Go
    # entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair ($HOME=/root).
    NAME="conformance"
    KPDIR="${HOME:-/root}/.entity/peers/$NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    # 2. Boot the Host (peer). It prints "LISTENING <port>" then parks on the accept loop.
    # shellcheck disable=SC2086
    "$LAUNCHER" --port "$PORT" --name "$NAME" --debug-open-grants $VFLAG \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID 2>/dev/null || true" EXIT INT TERM
    # 3. Wait for the LISTENING readiness line.
    i=0
    while [ "$i" -lt 600 ]; do
      if grep -q "^LISTENING" /tmp/host.out 2>/dev/null; then break; fi
      if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
      i=$((i + 1)); sleep 0.1
    done
    head -2 /tmp/host.out
    # 4. Point the oracle at it — the profile IS the gate.
    "$ORACLE" -addr "127.0.0.1:$PORT" '"$*"' || true

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
  '
