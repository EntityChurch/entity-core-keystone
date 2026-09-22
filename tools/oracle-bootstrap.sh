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
#     The commit hash may be meaningless post-cutover; the core-gate FINGERPRINT
#     (the normalized category set + type floor from profile.go — the semantic content
#     that defines `--profile core`, NOT the raw file bytes) is the anchor that tells
#     you whether this oracle's core surface matches what the peers converged against,
#     regardless of the commit hash. A comment reword / reformat of profile.go leaves
#     the fingerprint unchanged (this is exactly what false-alarmed the e8524ed->cc1970f
#     cutover); only a genuine add/remove/rename of a core category or floor type moves it.
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

# check_set_digest — the SECOND anchor, and the one core_gate_fingerprint is blind
# to. Reads the NON-TEST sources of cmd/internal/validate on stdin (see
# validate_sources below) and hashes the sorted set of DECLARED CHECK NAMES.
#
# Why it exists (2026-07-27, measured): cc1970f -> af8a582 added four hard-FAIL
# vectors INSIDE existing core categories (handshake_nonce_single_use,
# f40_id_scope_exclude_literal, f40_id_scope_include_no_overgrant,
# t1_4_frame_write_atomicity) and flipped most of the cohort from PASS to FAIL —
# while core_gate_fingerprint stayed byte-identical (8261a033…), because the
# category set and type floor did not move. The fingerprint answers "which
# categories run"; it CANNOT answer "what do they assert". Reasoning
# "same fingerprint => verdicts carry forward" from it is unsound, and that
# reasoning was committed policy until this run disproved it.
#
# So: fingerprint unchanged + digest unchanged => a carry-forward is defensible.
# Fingerprint unchanged + digest MOVED => the gate moved; re-run the cohort.
#
# 2026-08-16: extended \.Declare\( to \.Declare(Self)?\( — arch added a
# .DeclareSelf( method (offline/client-free checks) that the original regex was
# blind to (35 sites at go de8f807), which would have under-counted the check set
# on any re-pin done before this fix. (Recorded as W1 in an internal session note,
# 2026-08-13 — not published.)
#
# 2026-09-01: extended again, and this is the THIRD time this extraction has been
# blind to a registration form (after .DeclareSelf( above and _test.go inclusion in
# validate_sources below). A check whose name is a CONST is invisible to a literal-
# only regex:
#
#     const name = "connect_prehello_authenticate"
#     ...
#     checks = append(checks, probePreHelloAuthenticate(ctx, addr))
#
# Measured at go HEAD: 10 declared names sat in that form, and FOUR are in
# catConnectivity, a CORE category — connect_prehello_authenticate (the FM-1 check,
# landing in this very re-pin), handshake_nonce_single_use, handshake_probe_baseline,
# handshake_replay_cross_connection. The other six are catRelay* (extension).
#
# handshake_nonce_single_use is the sharp one: THIS FILE's own justification block
# names it as one of the four af8a582 hard-FAIL vectors that proved
# core_gate_fingerprint could not answer "what do these categories assert" — the
# exact defect check_set_digest was built to catch. It was never visible to
# check_set_digest either. The anchor was blind to its own motivating example.
#
# RESIDUAL BLIND SPOT, stated rather than papered over: a name COMPUTED at runtime
# cannot be recovered by any static extraction — handlers.go:94 does
# `name := "handler_" + expected.name + suffix`, so the whole handler_* family is
# unreachable here, and the trailing-`+` exclusion below deliberately drops the
# "handler_" fragment rather than recording a prefix as if it were a check name.
# `core_executed_check_set_digest` (what a RUN emitted) is the anchor that covers
# them, and it always did. Two anchors, different blind spots, on purpose.
#
# (Pattern (a) has always harvested the bare fragment `handler_` from handlers.go's
# eight `.Declare("handler_" + …)` sites — a degenerate stand-in for eight computed
# names. It is PRE-EXISTING, present in every digest ever recorded, and identical on
# both sides of every comparison, so it moves no verdict. Left as-is deliberately:
# removing it would be a second, benefit-free method change in the same commit and
# would make this pin's delta harder to attribute.)
#
# CONSEQUENCE FOR COMPARISON: values from this method are NOT comparable to any
# recorded before 2026-09-01. See the re-pin block in tools/oracle-pin.env for the
# previous pin recomputed under this method.
check_set_digest() {
  cs_tmp=$(mktemp)
  cat > "$cs_tmp"
  {
    # (a) literal: .Declare("x" / .DeclareSelf("x"
    grep -oE '\.Declare(Self)?\("[a-z0-9_]+"' "$cs_tmp" | sed 's/.*("//; s/"//'
    # (b) const/var: `const name… = "x"` / `name… := "x"`, where the literal is the
    #     WHOLE right-hand side. The end-anchor is what excludes a concatenation
    #     fragment such as `name := "handler_" + expected.name + suffix`.
    grep -oE '(const|var)?[[:space:]]*name[A-Za-z0-9_]*[[:space:]]*:?=[[:space:]]*"[a-z0-9_]+"[[:space:]]*$' "$cs_tmp" \
      | sed 's/.*"\([a-z0-9_]*\)"[[:space:]]*$/\1/'
  } | sort -u | sha256sum | cut -d' ' -f1
  rm -f "$cs_tmp"
}

# validate_sources — the digest's INPUT, and the whole reason it is a function.
#
# 2026-08-21, found by arch (ROUTING-2026-08-21-m §3), measured before fixing: this
# used to be `git archive "$ref" cmd/internal/validate | tar -xO`, and `git archive`
# of a DIRECTORY includes `_test.go`. So check_set_digest hashed go's test fixtures
# alongside its real checks — and oracle-pin.env makes that digest THE authoritative
# anchor for carry-forward ("Both must match, or the cohort re-runs"). A digest move
# is a 45-peer census. A test fixture could order one.
#
# Measured at d697b9a -> c1b0708: directory-including-tests moved
# ca0c988f… -> 3e749f37…, while the non-test declared set was IDENTICAL at 1137
# names both sides. The entire move was three fixture strings in runner_test.go
# (before_gate, behavioral_body_ran, behavioral_root), added with the
# CheckRunner.Gate primitive. None exists in the built binary; no peer is ever
# scored on them.
#
# This is the same class core_gate_fingerprint (one function down) already normalizes
# against — hash the SEMANTIC content, not the raw bytes of whatever happens to sit in
# the directory. That normalization simply never reached this anchor. Enumerating
# non-test `.go` paths explicitly is that normalization for this input: a file the
# built oracle cannot contain must not be able to move the pin.
#
# Works for a resolved commit and for the literal "HEAD" of the R1 fallback path.
validate_sources() {
  git -C "$GO_REPO" ls-tree -r --name-only "$1" cmd/internal/validate \
    | grep '\.go$' | grep -v '_test\.go$' | sort \
    | while IFS= read -r f; do git -C "$GO_REPO" show "$1:$f"; done
}

# core_gate_fingerprint — the AUTHORITATIVE, mirror-stable identity of the core
# gate. Reads profile.go on stdin and hashes the *normalized semantic content* of
# its two gate maps (coreProfileCategories = the category set + coreTypeFloor = the
# 53-type floor that together define `--profile core`), stripping comments and
# whitespace and sorting. Only a genuine add/remove/rename of a core category or a
# floor type moves it — a comment reword / reformat does not (contrast the raw
# sha256 of the file bytes, which flips on any edit and false-alarmed the mirror
# cutover). Emits a 64-hex digest.
core_gate_fingerprint() {
  awk '
    /coreProfileCategories = map\[string\]bool\{/ {m="cat";  next}
    /coreTypeFloor = map\[string\]bool\{/          {m="type"; next}
    m != "" && /^\}/ {m=""; next}
    m != "" {
      s=$0; sub(/\/\/.*/, "", s); gsub(/[ \t\r]/, "", s)   # strip comment + whitespace
      if (s ~ /:true,?$/) { sub(/:true,?$/, "", s); print m "|" s }
    }' | sort -u | sha256sum | cut -d' ' -f1
}

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

# 2. Mirror-stable core anchor. Two fingerprints of profile.go at the resolved ref:
#    * CORE_FP  (core_gate_fingerprint) — AUTHORITATIVE: normalized category set +
#      type floor, comment/format-invariant. This is what the pin compares against.
#    * CORE_SHA (core_gate_sha256)      — INFORMATIONAL: raw file bytes, moves on any
#      edit (incl. a comment reword); kept only for traceability.
CORE_FP=$(git -C "$GO_REPO" show "$ARCHIVE_REF:$CORE_GATE" | core_gate_fingerprint)
CORE_SHA=$(git -C "$GO_REPO" show "$ARCHIVE_REF:$CORE_GATE" | sha256sum | cut -d' ' -f1)
CHECK_SET=$(validate_sources "$ARCHIVE_REF" | check_set_digest)
EXPECT_CS=""
[ -f "$PIN_FILE" ] && EXPECT_CS=$(awk -F'= *' '/^check_set_digest/{print $2; exit}' "$PIN_FILE" | awk '{print $1}')
if [ -n "$EXPECT_CS" ] && [ "$EXPECT_CS" != "$CHECK_SET" ]; then
  # THIS IS A HARD STOP, and it used to be a NOTE that exited 0. Measured 2026-08-23
  # against a genuine fresh clone (keystone worktree + `git clone --no-local
  # --single-branch --branch master` of go, 2 commits, pinned ref absent):
  #
  #   * `ref = c1b0708` did not resolve, so R1 fell back to HEAD = cc1970f.
  #   * core_gate_fingerprint MATCHED BYTE-FOR-BYTE (8261a033…) — it has been
  #     identical across all five pins, so it raises nothing.
  #   * check_set_digest differed, printed a NOTE, and the script BUILT AND
  #     INSTALLED ANYWAY, exit 0.
  #   * The installed oracle is missing request_mint_temporal_ceiling,
  #     ingest_rejects_unrepresentable_expiry and configure_empty_grants_withdrawal
  #     — verified with `strings`. Those three ARE the release's entire finding.
  #
  # So an adopter following the documented path got a clean build, a green run, and
  # 32 peers passing that CONFORMANCE-MATRIX.md says fail. A falsely-GREEN result
  # from a successful build is the worst outcome this repo can produce, and every
  # honesty discipline here exists to prevent exactly it. A warning on stderr in the
  # middle of a wall of `go: downloading` lines is not a control.
  echo "oracle-bootstrap: ERROR the built oracle is NOT the pinned oracle." >&2
  echo "  committed check_set_digest (tools/oracle-pin.env): $EXPECT_CS" >&2
  echo "  built from $SRC:  $CHECK_SET" >&2
  echo >&2
  echo "  The CHECK SET differs — different vectors, so no verdict in" >&2
  echo "  CONFORMANCE-MATRIX.md carries over to a run against this build, even though" >&2
  echo "  core_gate_fingerprint may match (it tracks WHICH CATEGORIES RUN, never WHAT" >&2
  echo "  THEY ASSERT, and it has been byte-identical across all five pins)." >&2
  echo >&2
  if [ "$ARCHIVE_REF" = "HEAD" ]; then
    echo "  CAUSE: the pinned ref '$ORACLE_REF' does not exist in $GO_REPO, so this fell" >&2
    echo "  back to its HEAD. If that repo is a clone of public 'master', the pinned" >&2
    echo "  oracle is genuinely not there: published commits are authored fresh at the" >&2
    echo "  release boundary ([ADR-0027]), and as of 2026-08-23 entity-core-go's public" >&2
    echo "  master is 514 commits behind the oracle this cohort was measured on." >&2
    echo "  FIX: build against a tree whose content matches the pin. The digests above" >&2
    echo "  are how you confirm you have one — the commit hash does not matter." >&2
  else
    echo "  CAUSE: ref '$ORACLE_REF' resolved, but its check set is not the pinned one." >&2
  fi
  echo >&2
  echo "  If you are DELIBERATELY re-pinning: REPIN=1 tools/oracle-bootstrap.sh, then" >&2
  echo "  re-measure the cohort and update tools/oracle-pin.env. Never publish a number" >&2
  echo "  measured on a build this check rejected." >&2
  [ "${REPIN:-0}" = "1" ] || exit 3
  echo "oracle-bootstrap: REPIN=1 — proceeding anyway. RE-RUN THE COHORT." >&2
fi
EXPECT=""
[ -f "$PIN_FILE" ] && EXPECT=$(awk -F'= *' '/^core_gate_fingerprint/{print $2; exit}' "$PIN_FILE" | awk '{print $1}')
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$CORE_FP" ]; then
  echo "oracle-bootstrap: NOTE core-gate fingerprint differs from committed pin" >&2
  echo "  committed (tools/oracle-pin.env): $EXPECT" >&2
  echo "  building now:                     $CORE_FP" >&2
  echo "  => the core category set / type floor genuinely moved; expect a peer re-converge" >&2
  echo "     (policy §4). Update oracle-pin.env if intended. (A comment reword alone can no" >&2
  echo "     longer trigger this — the raw sha256 is informational: $CORE_SHA)" >&2
fi
# "Nothing to do" requires BOTH anchors to match. Matching the fingerprint alone is
# NOT sufficient and used to be: at the cc1970f -> af8a582 bucket-B cutover the
# fingerprint was byte-identical while the check set gained four hard-FAIL core
# vectors, so this short-circuit would have declared a stale oracle current and
# silently run the OLD check set over the whole cohort — the exact failure mode
# AGENTS.md warns about, mechanized.
#
# AND IT MUST COMPARE AGAINST THE COMMITTED PIN, NOT AGAINST ITSELF. Found the same
# way, 2026-08-23: HAVE/HAVE_CS come from PROVENANCE.txt (what is installed) and
# CORE_FP/CHECK_SET from the ref being built. On a second run in the fresh clone both
# describe the same wrong cc1970f oracle, so they agreed trivially and the script
# printed, three lines apart:
#
#   NOTE check-set digest differs from committed pin
#   installed oracle matches BOTH … — nothing to do
#
# A self-consistency check reads exactly like a correctness check and is not one.
# The comparison below is now against EXPECT_CS/EXPECT — the committed pin — with the
# installed-vs-built check kept as the second condition, so "nothing to do" means
# "installed == built == pinned" and nothing weaker.
if [ "${FORCE:-0}" != "1" ] && [ -x "$OUT/validate-peer" ] && [ -f "$PROV_FILE" ]; then
  HAVE=$(awk -F'= *' '/^core_gate_fingerprint/{print $2; exit}' "$PROV_FILE" | awk '{print $1}')
  HAVE_CS=$(awk -F'= *' '/^check_set_digest/{print $2; exit}' "$PROV_FILE" | awk '{print $1}')
  if [ -n "$EXPECT_CS" ] && [ "$HAVE_CS" != "$EXPECT_CS" ]; then
    echo "oracle-bootstrap: installed oracle does not match the COMMITTED pin — rebuilding." >&2
    echo "  installed (output/s4-oracles/PROVENANCE.txt): $HAVE_CS" >&2
    echo "  committed (tools/oracle-pin.env):             $EXPECT_CS" >&2
  elif [ "$HAVE" = "$CORE_FP" ] && [ "$HAVE_CS" = "$CHECK_SET" ]; then
    echo "oracle-bootstrap: installed oracle matches BOTH the core-gate fingerprint ($CORE_FP)"
    echo "                  and the check-set digest ($CHECK_SET) — nothing to do (FORCE=1 to rebuild)."
    exit 0
  fi
  [ "$HAVE" = "$CORE_FP" ] && [ "$HAVE_CS" != "$CHECK_SET" ] && \
    echo "oracle-bootstrap: fingerprint matches but the CHECK SET moved — rebuilding (this is the stale-oracle trap)." >&2
fi

echo "oracle-bootstrap: building from $SRC"
echo "oracle-bootstrap: core-gate fingerprint = $CORE_FP  (raw sha256 $CORE_SHA)"

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
  echo "# tools/oracle-bootstrap.sh. core_gate_fingerprint matching the pin => core surface intact."
  # Record what was BUILT, not what was asked for. This said `ref = c1b0708` beside
  # `commit = cc1970f…` in the fresh-clone test — the pin's name attached to a
  # different oracle, which is the confusion this whole class is made of.
  echo "ref                   = ${ARCHIVE_REF}"
  echo "requested_ref         = ${ORACLE_REF:-HEAD}"
  echo "commit                = $COMMIT"
  echo "built_from            = $SRC"
  echo "core_gate_fingerprint = $CORE_FP   # normalized category set + type floor (AUTHORITATIVE)"
  echo "core_gate_sha256      = $CORE_SHA   # raw sha256(cmd/internal/validate/profile.go) (informational)"
  echo "check_set_digest      = $CHECK_SET   # sorted set of declared check names (AUTHORITATIVE for carry-forward)"
  echo "built_at              = $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$PROV_FILE"

echo "oracle-bootstrap: installed validate-peer + entity-peer @ $SHORT into $OUT"
