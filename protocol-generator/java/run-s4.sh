#!/usr/bin/env bash
# S4 conformance harness — entity-core-protocol-java (peer #6 / 8th byte-compat impl).
#
# Runs entirely inside the java-toolchain container (the Go validate-peer oracle is a
# fedora:43 static ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none). Builds the peer (mvn -o, fully offline — JUnit /
# opt-in BouncyCastle are pre-fetched into the image ~/.m2 at container BUILD time),
# launches the standalone Host with --debug-open-grants (grant-gated categories need the
# degenerate seed) + --validate (§7a system/validate/* conformance handlers live), waits
# for its LISTENING readiness line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   ./protocol-generator/java/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the V7 v7.72 §9.0 core-profile gate) + JSON out.
# Env overrides: ORACLE, PORT, NOBUILD (1=skip mvn), VALIDATE (1=on, 0=exercise SKIP path).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/java-toolchain:latest"
WORKDIR="/work/protocol-generator/java"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
VALIDATE="${VALIDATE:-1}"
NOBUILD="${NOBUILD:-0}"
JSON_OUT="$WORKDIR/status/CONFORMANCE-REPORT.json"

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
    # 1. Build the peer (offline). The standalone Host main is org.entitycore.protocol.peer.Host.
    if [ "$NOBUILD" != "1" ]; then
      mvn -o -B -q -DskipTests package >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    CP="target/classes"
    # 1b. Provision the peer'"'"'s persistent identity at the standard on-disk location so the
    # validator'"'"'s multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the
    # peer'"'"'s keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising
    # genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches
    # the Host default, so peer_id is unchanged. NAME follows the Go entity-peer /
    # peer-manager convention: ~/.entity/peers/NAME/keypair ($HOME = /root in-container).
    NAME="conformance"
    KPDIR="${HOME:-/root}/.entity/peers/$NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    # 2. Boot the Host (peer). It prints "LISTENING <port>" then parks on the accept loop.
    # shellcheck disable=SC2086
    java -cp "$CP" org.entitycore.protocol.peer.Host --port "$PORT" --name "$NAME" --debug-open-grants $VFLAG \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID 2>/dev/null || true" EXIT INT TERM
    # 3. Wait for the LISTENING readiness line.
    i=0
    while [ "$i" -lt 300 ]; do
      if grep -q "^LISTENING" /tmp/host.out 2>/dev/null; then break; fi
      if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
      i=$((i + 1)); sleep 0.1
    done
    head -2 /tmp/host.out
    # 4. Point the oracle at it — the profile IS the gate.
    "$ORACLE" -addr "127.0.0.1:$PORT" '"$*"' || true
  '
