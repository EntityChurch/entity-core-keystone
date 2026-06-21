#!/usr/bin/env bash
# oracle-diff.sh — independent wire-conformance cross-check for the Kotlin peer.
#
# Builds the Go `wire-conformance` oracle from entity-core-go HEAD into a TEMP DIR
# OUTSIDE the go repo (the runbook's hard-learned rule: NEVER build with the go repo
# as cwd or output dir — a prior run leaked binaries into the sacred oracle tree),
# produces Go's emit-go.cbor over the vendored corpus, produces THIS peer's
# emit-kotlin.cbor (via the EmitCanonical main, inside the kotlin-toolchain container),
# and byte-compares the two emission files.
#
# Byte-identity == the Kotlin codec converges with the Go reference on every vector.
#
# This is the "run your codec against the oracle" S2 step; the in-build ConformanceTest
# is the primary gate (byte-identity to the cross-blessed fixture), and this script is
# the independent second confirmation against a freshly built Go reference.
#
# Usage: tools/oracle-diff.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"          # protocol-generator/kotlin
WORKTREE="$(cd "$HERE/../.." && pwd)"                             # repo root (worktree)
. "$WORKTREE/tools/podman-caps.sh"
VEC="$WORKTREE/protocol-generator/shared/test-vectors/v0.8.0"
GO_REPO="${GO_REPO:-$HOME/projects/[internal]/[internal]/entity-core-go}"
GO_IMAGE="${GO_IMAGE:-localhost/entity-core-keystone/go:latest}"
KT_IMAGE="${KT_IMAGE:-entity-core-keystone/kotlin-toolchain:latest}"

COMMIT="$(git -C "$GO_REPO" rev-parse HEAD)"
TMP="$(mktemp -d /tmp/wire-oracle.XXXXXX)"
OUT="$(mktemp -d /tmp/oracle-out.XXXXXX)"
trap 'rm -rf "$TMP" "$OUT"' EXIT

echo "go repo:   $GO_REPO @ $COMMIT"
echo "temp build (outside go repo): $TMP"

# 1. Archive the full HEAD tree (cmd module needs ../core, ../ext via local replace).
git -C "$GO_REPO" archive "$COMMIT" | tar -x -C "$TMP"

# 2. Build the oracle in the go container; OUTPUT stays inside the temp dir.
podman run $PODMAN_RUN_CAPS --rm \
  -v "$TMP":/src:Z \
  -v "$HOME/go/pkg/mod":/root/go/pkg/mod:Z \
  -e GOWORK=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
  --security-opt label=disable \
  "$GO_IMAGE" \
  bash -c 'cd /src/cmd && go build -o /src/wire-conformance ./internal/wire-conformance'

# 3. Go emission over the vendored corpus.
podman run $PODMAN_RUN_CAPS --rm \
  -v "$TMP":/src:Z -v "$VEC":/vec:ro \
  --security-opt label=disable "$GO_IMAGE" \
  /src/wire-conformance emit-canonical --input /vec/conformance-vectors-v1.cbor \
    --out /src/emit-go.cbor --impl-version go-oracle
cp "$TMP/emit-go.cbor" "$OUT/emit-go.cbor"

# 4. Kotlin emission over the same corpus (EmitCanonical main, inside the kt container).
#    Produced under the Go oracle's IDENTITY (core-go / go-oracle) so the emission is
#    byte-IDENTICAL when the codec payload converges — the impl/impl_version fields are
#    metadata, NOT codec output, and would otherwise be the only (spurious) difference.
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$WORKTREE":/work:Z --security-opt label=disable \
  -w /work/protocol-generator/kotlin \
  -e EMIT_IMPL=core-go -e EMIT_IMPL_VERSION=go-oracle "$KT_IMAGE" \
  bash -c 'gradle --offline --no-daemon -q classes >/dev/null 2>&1; \
    kotlin -classpath build/classes/kotlin/main \
      org.entitycore.protocol.conformance.EmitCanonical \
      /work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor \
      /work/protocol-generator/kotlin/build/emit-kotlin.cbor'
cp "$WORKTREE/protocol-generator/kotlin/build/emit-kotlin.cbor" "$OUT/emit-kotlin.cbor"

# 5. Byte-compare.
echo
echo "=== emission byte-diff ==="
ls -l "$OUT/emit-go.cbor" "$OUT/emit-kotlin.cbor"
if cmp -s "$OUT/emit-go.cbor" "$OUT/emit-kotlin.cbor"; then
  echo "PASS: emit-kotlin.cbor is BYTE-IDENTICAL to emit-go.cbor"
  exit 0
else
  echo "FAIL: emissions differ"
  cmp "$OUT/emit-go.cbor" "$OUT/emit-kotlin.cbor" || true
  exit 1
fi
