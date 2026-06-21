#!/bin/sh
# S4 conformance harness — entity-core-protocol-rust (CLEAN-ROOM peer).
#
# Runs entirely inside the rust-toolchain container (the Go validate-peer oracle is
# a fedora:43 ELF that runs there too, so oracle + peer share one loopback and the
# run stays sealed-offline with --network=none). Builds the peer host (offline,
# against the gitignored output/vendor crate mirror), provisions the persistent
# conformance keypair, launches the host with --name conformance --validate
# --debug-open-grants, waits for its LISTENING line, points validate-peer at it,
# tears the host down.
#
# CLEAN-ROOM NOTE: the Rust peer is built from the spec; the oracle binaries under
# output/s4-oracles/ are the conformance TOOL (built from entity-core-go 33f35fd in
# an isolated temp dir OUTSIDE entity-core-go, NOT read as source while building
# the peer). The peer is byte-VALIDATED against the oracle here, not derived from it.
# output/vendor is a plain `cargo vendor` mirror of the S2/S3 crate closure
# (ed25519-dalek + sha2 + transitive deps) — no new deps, just offline material.
#
# Rust uses loopback port 7777 (its own port; each S4 run is --network=none so it
# cannot collide with a concurrent peer — distinct ports are belt-and-suspenders).
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none --security-opt label=disable \
#     -v "$PWD":/work:Z \
#     entity-core-keystone/rust-toolchain:latest \
#     sh /work/protocol-generator/rust/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the 16 core-profile categories at oracle 33f35fd;
# the oracle auto-allowlists the §9.0 extension-carve-out skips). The PASS/FAIL
# gate is hardened with -allow-skip "" semantics implied by --profile core (every
# residual skip under core is an oracle-owned auto-allowlist). ORACLE/PORT/NOBUILD/
# VALIDATE/PEERNAME env overrides.

set -eu
PORT="${PORT:-7777}"
PROJ=/work/protocol-generator/rust
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
cd "$PROJ"

# Offline cargo: replace crates-io with the vendored mirror so the --network=none
# build resolves without touching the network.
export CARGO_HOME=/tmp/cargo-home
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "$PROJ/output/vendor"
EOF

if [ "${NOBUILD:-0}" != "1" ]; then
  cargo build --release --offline --bin entity-peer-host >/dev/null 2>/tmp/build.err || {
    echo "peer build failed:" >&2; cat /tmp/build.err >&2; exit 1; }
fi
HOST_BIN="$PROJ/target/release/entity-peer-host"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair and co-sign AS the peer — exercising genuine K-of-N instead of
# env-skipping. The cohort seed is a fixed 0x11 × 32 (base64 "ERER…"), so the
# peer_id is deterministic and matches what the Go validator derives (2KHoAk…).
# NAME follows the Go entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validator's validate_echo_dispatch probe runs live
# instead of honest-SKIP. ON by default (cohort convention); VALIDATE=0 exercises
# the SKIP path. --debug-open-grants is the degenerate seed policy the grant-gated
# categories need.
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# shellcheck disable=SC2086
"$HOST_BIN" --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 200 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
  i=$((i + 1)); sleep 0.1
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
