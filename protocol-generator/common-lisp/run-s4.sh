#!/usr/bin/env bash
# S4 conformance harness — entity-core-protocol-common-lisp.
#
# Runs entirely inside the common-lisp-toolchain container (the Go validate-peer
# oracle is a fedora:43 ELF that runs there too, so oracle + peer share one
# loopback; stays sealed-offline with --network=none). Builds+loads the peer,
# launches the SBCL host with --debug-open-grants (grant-gated categories need the
# degenerate seed) + --validate (§7a conformance handlers), waits for its LISTENING
# readiness line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   ./protocol-generator/common-lisp/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the v7.72 §9.0 core-profile gate) + JSON out.
# Env overrides: ORACLE, PORT, VALIDATE (1=on, 0=exercise the SKIP path).
#
# NOTE: `(require :asdf)` / `(require :sb-bsd-sockets)` MUST each be their own
# --eval before any form that *names* those packages — SBCL resolves package-
# qualified symbols at read time (the run-s2/run-s3 lesson).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/common-lisp-toolchain:latest"
WORKDIR="/work/protocol-generator/common-lisp"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
VALIDATE="${VALIDATE:-1}"
JSON_OUT="$WORKDIR/status/CONFORMANCE-REPORT.json"

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch probe runs live instead of
# honest-SKIP. Off in production; on here.
VALIDATE_FLAG=""
[ "$VALIDATE" = "1" ] && VALIDATE_FLAG="--validate"

# Oracle args (default = the core-profile gate). Pass-through if caller supplies any.
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$JSON_OUT"
fi

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; VFLAG="'"$VALIDATE_FLAG"'"
    # 0. Provision the peer'"'"'s persistent identity at the standard on-disk location so
    #    the validator'"'"'s multisig accept-path probe (valid_2of3_peer_signed_accepted)
    #    can find the peer'"'"'s keypair (crypto.LookupKeypairByPeerID) and co-sign AS the
    #    peer — exercising genuine K-of-N instead of env-skipping. The seed (0x11 × 32,
    #    base64 "ERER…") matches the host default (#x11), so peer_id is unchanged. NAME
    #    follows the Go entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
    NAME="conformance"
    KPDIR="${HOME:-/root}/.entity/peers/$NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    # 1. Boot the SBCL host (peer): load the system + host.lisp, run the host.
    #    It prints "LISTENING ..." on stdout then blocks on the accept thread.
    sbcl --non-interactive \
      --eval "(require :asdf)" \
      --eval "(require :sb-bsd-sockets)" \
      --eval "(load #p\"/opt/quicklisp/setup.lisp\")" \
      --eval "(push (truename \".\") asdf:*central-registry*)" \
      --eval "(handler-bind ((warning (function muffle-warning))) (asdf:load-system :entity-core/peer))" \
      --eval "(load \"host.lisp\")" \
      --eval "(entity-core/host:main)" \
      -- --port "$PORT" --name "$NAME" --debug-open-grants $VFLAG >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID 2>/dev/null || true" EXIT INT TERM
    # 2. Wait for the LISTENING readiness line.
    i=0
    while [ "$i" -lt 200 ]; do
      if grep -q "^LISTENING" /tmp/host.out 2>/dev/null; then break; fi
      if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
      i=$((i + 1)); sleep 0.1
    done
    head -1 /tmp/host.out
    # 3. Point the oracle at it — the profile IS the gate.
    "$ORACLE" -addr "127.0.0.1:$PORT" '"$*"' || true
  '
