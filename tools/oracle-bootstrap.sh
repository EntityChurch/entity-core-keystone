#!/bin/sh
# oracle-bootstrap.sh — produce the conformance oracle from the sibling entity-core-go.
#
# The keystone's behavioral gate (validate-peer) and the §10.2 reference peer
# (entity-peer) are Go binaries built from entity-core-go. They are gitignored
# (local tools, not committed source — clean-room boundary), so a fresh clone has
# none. This script is the one-shot way to make them, and it is MIRROR-STABLE:
#
#   * Normally it builds the pinned ref recorded in output/s4-oracles/PROVENANCE.txt.
#   * If that ref does NOT resolve (public-mirror cutover rewrote history, tag/commit
#     gone), it FALLS BACK to building the sibling repo's working-tree HEAD and warns.
#     The commit hash may be meaningless post-cutover; the core-gate fingerprint
#     (sha256 of profile.go — the category set that defines `--profile core`) is the
#     anchor that tells you whether this oracle's core surface matches what the peers
#     converged against, regardless of the commit hash.
#
# Prereqs: podman + the entity-core-keystone/go:latest image (containers/go), and the
# sibling entity-core-go checked out next to this repo. Network is needed ONCE (go mod
# download); the conformance RUN itself is always --network=none.
#
# Usage (from anywhere):
#   tools/oracle-bootstrap.sh                 # build the pinned ref (or fall back to HEAD)
#   ORACLE_REF=v7.77 tools/oracle-bootstrap.sh   # build a specific tag/commit
#   GO_REPO=/path/to/entity-core-go tools/oracle-bootstrap.sh
#   FORCE=1 tools/oracle-bootstrap.sh         # rebuild even if binaries already match
set -eu

KEYSTONE_ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$KEYSTONE_ROOT/tools/podman-caps.sh"
GO_REPO="${GO_REPO:-$KEYSTONE_ROOT/../entity-core-go}"
OUT="$KEYSTONE_ROOT/output/s4-oracles"
PIN_FILE="$KEYSTONE_ROOT/tools/oracle-pin.env"   # COMMITTED anchor (output/ is gitignored)
PROV_FILE="$OUT/PROVENANCE.txt"                  # local runtime provenance (alongside binaries)
GO_IMAGE="${GO_IMAGE:-entity-core-keystone/go:latest}"
ORACLE_REF="${ORACLE_REF:-}"   # tag/commit; empty => PROVENANCE.txt's ref, else sibling HEAD
CORE_GATE=cmd/internal/validate/profile.go   # the mirror-stable core anchor

die(){ echo "oracle-bootstrap: ERROR $*" >&2; exit 1; }

[ -d "$GO_REPO/.git" ] || die "sibling go repo not found at $GO_REPO (set GO_REPO=...)"

# 1. Resolve which ref to build.
if [ -z "$ORACLE_REF" ] && [ -f "$PIN_FILE" ]; then
  ORACLE_REF=$(awk -F'= *' '/^ref/{print $2; exit}' "$PIN_FILE")
fi
if [ -n "$ORACLE_REF" ] && git -C "$GO_REPO" rev-parse --verify -q "$ORACLE_REF^{commit}" >/dev/null 2>&1; then
  COMMIT=$(git -C "$GO_REPO" rev-parse "$ORACLE_REF^{commit}")
  ARCHIVE_REF="$COMMIT"; SRC="pinned ref '$ORACLE_REF' ($COMMIT)"
else
  # R1 fallback: pin gone (mirror cutover). Build the sibling's current working tree.
  [ -n "$ORACLE_REF" ] && echo "oracle-bootstrap: WARN pinned ref '$ORACLE_REF' not found in $GO_REPO — falling back to working-tree HEAD" >&2
  COMMIT=$(git -C "$GO_REPO" rev-parse HEAD)
  ARCHIVE_REF="HEAD"; SRC="sibling working-tree HEAD ($COMMIT)  [fallback]"
fi
SHORT=$(printf '%s' "$COMMIT" | cut -c1-7)

# 2. Mirror-stable core anchor: sha256 of profile.go at the resolved ref.
CORE_SHA=$(git -C "$GO_REPO" show "$ARCHIVE_REF:$CORE_GATE" | sha256sum | cut -d' ' -f1)
EXPECT=""
[ -f "$PIN_FILE" ] && EXPECT=$(awk -F'= *' '/^core_gate_sha256/{print $2; exit}' "$PIN_FILE" | awk '{print $1}')
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$CORE_SHA" ]; then
  echo "oracle-bootstrap: NOTE core anchor differs from committed pin" >&2
  echo "  committed (tools/oracle-pin.env): $EXPECT" >&2
  echo "  building now:                     $CORE_SHA" >&2
  echo "  => the core gate moved; expect a peer re-converge (policy §4). Update oracle-pin.env if intended." >&2
fi
if [ "${FORCE:-0}" != "1" ] && [ -x "$OUT/validate-peer" ] && [ -f "$PROV_FILE" ]; then
  HAVE=$(awk -F'= *' '/^core_gate_sha256/{print $2; exit}' "$PROV_FILE" | awk '{print $1}')
  if [ "$HAVE" = "$CORE_SHA" ]; then
    echo "oracle-bootstrap: installed oracle already matches core anchor $CORE_SHA — nothing to do (FORCE=1 to rebuild)."
    exit 0
  fi
fi

echo "oracle-bootstrap: building from $SRC"
echo "oracle-bootstrap: core-gate anchor (profile.go) = $CORE_SHA"

# 3. Archive the ref OUTSIDE the live go tree (clean-room) and build in the container.
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
( cd "$GO_REPO" && git archive "$ARCHIVE_REF" ) | tar -x -C "$TMP"
rm -f "$TMP/mise.toml"
podman run $PODMAN_RUN_CAPS --rm --security-opt label=disable -v "$TMP":/src:Z -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS= "$GO_IMAGE" sh -c '
    export GOWORK=off
    for m in core ext cmd; do (cd /src/$m && go mod tidy); done
    unset GOWORK; cd /src/cmd
    go build -o /src/_out/validate-peer ./validate-peer
    go build -o /src/_out/entity-peer  ./entity-peer' || die "go build failed"

# 4. Install into repo-root, backing up the prior binaries for bisection.
mkdir -p "$OUT"
for b in validate-peer entity-peer; do
  [ -f "$OUT/$b" ] && cp "$OUT/$b" "$OUT/$b.$SHORT.bak"
  cp "$TMP/_out/$b" "$OUT/$b"; chmod +x "$OUT/$b"
done

# 5. Record local runtime provenance (what is actually installed right now).
{
  echo "# Local oracle provenance — what is installed in this output/ tree right now."
  echo "# Authoritative committed anchor lives in tools/oracle-pin.env. Regenerate via"
  echo "# tools/oracle-bootstrap.sh. core_gate_sha256 matching the pin => core surface intact."
  echo "ref              = ${ORACLE_REF:-HEAD}"
  echo "commit           = $COMMIT"
  echo "built_from       = $SRC"
  echo "core_gate_sha256 = $CORE_SHA   # sha256(cmd/internal/validate/profile.go)"
  echo "built_at         = $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$PROV_FILE"

echo "oracle-bootstrap: installed validate-peer + entity-peer @ $SHORT into $OUT"
