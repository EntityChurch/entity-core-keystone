#!/usr/bin/env bash
# run-mint-floor.sh — drive `arc-probe` against a peer through its OWN UNMODIFIED
# harness, i.e. WITH `--debug-open-grants`, for the sake of the MINTED-CAPABILITY
# families only: E, F and G.
#
# WHY A SECOND SETUP EXISTS, AND WHY IT IS NOT THE DEFAULT
# --------------------------------------------------------
# `run.sh` removes `--debug-open-grants` because the A and B families measure
# AUTHORIZATION: under the degenerate `default -> *` seed policy nothing is outside
# the caller's grant, so those families would report every guard holding for a
# reason that has nothing to do with the guard. That reasoning is about the CALLER's
# grant, and it does not transfer to family E.
#
# Family E's subject is a capability the probe MINTS during the run, and the value
# under test is that minted capability's OWN `resources.exclude`. The seed policy
# decides only whether `system/capability:request` is permitted at all. So:
#
#   * widening the caller's floor cannot make a narrowed cap's exclude look
#     enforced when it is not — the exclude belongs to the minted token, not to the
#     floor; and
#   * the E0 control (the same mint, same use, MINUS the one value under test)
#     rides along and proves the arm is live on this peer.
#
# It exists because SEVEN peers refuse `system/capability:request` under the §6.9a
# discovery floor — `sql`, `wasm-wat`, `asm-x86_64`, `asm-arm64`, `riscv64` answer
# 403 to the request itself, and `forth`/`smalltalk` mint but then deny the minted
# cap on use — so `run.sh` can only report their E family VOID. Five of the seven
# become measurable here; `forth` and `smalltalk` stay VOID for a reason that is
# about the peer rather than about the floor, and that is worth saying separately.
#
# FAMILIES F AND G READ OUT OF THIS RUN TOO, BY THE SAME ARGUMENT AND WITH ONE
# DIFFERENCE WORTH STATING. Both mint their own capability and both grade that
# minted token's own scope, so the caller's floor decides only whether the mint is
# permitted:
#
#   * family F's subject is the minted cap's `peers` dimension. F1 excludes THIS
#     peer from a grant it then presents here; no floor can make that grant cover
#     this peer. The F0 control (explicit local `peers`, same grant otherwise)
#     proves the arm is live.
#   * family G's subject is a minted capability covering qA and NOT qB. The G1
#     antecedent — qB refused under that capability — is what proves the narrowing
#     survived the wider floor, and it is checked on every row before G2 is read.
#
#   ⚠ ONE ROW CHANGES MEANING HERE AND IT IS GRADED, NOT HIDDEN. Family F's
#   `F2_peers_foreign_only` is refused at MINT under the discovery floor (§6.2's
#   subset check: a foreign `peers` include is not a subset of the floor's). Under
#   `default -> *` the same grant MINTS, so the refusal — if it comes — comes from
#   `check_permission` on use instead. Both are conformant and the verdict string
#   says which gate answered, so an F2 row from this runner is a reading about L1
#   where the same row from `run.sh` is a reading about L4. They are not the same
#   measurement and must not be pooled into one count.
#
# READ ONLY THE E, F AND G FAMILIES OUT OF THIS RUN. The A and B rows in the
# output are measured under open grants and are NOT comparable with `run.sh`'s;
# they are left in the report rather than suppressed, because a report that
# silently omits rows is worse than one that says which rows it is for.
#
#   tools/arc-probe/run-mint-floor.sh python           # one peer
#   tools/arc-probe/run-mint-floor.sh --roster         # every peer in peer-tiers.tsv
#
# Reports land in output/scratch/arc-mint-floor/<peer>.json (gitignored).
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="$REPO/output/scratch/arc-mint-floor"
mkdir -p "$OUT"

[ -x "$REPO/output/s4-oracles/arc-probe" ] || {
  echo "run-mint-floor.sh: build it first — tools/build-probes.sh arc-probe" >&2; exit 2; }

peers=("$@")
if [ "${1:-}" = "--roster" ]; then
  # Skip comments AND the column header — the header line is `peer\ttier\t...`, which
  # is not a comment and which an unguarded filter happily hands back as a peer name.
  mapfile -t peers < <(awk '$1 !~ /^#/ && $1 != "peer" && NF > 1 {print $1}' "$REPO/tools/peer-tiers.tsv")
fi

failed=""
for peer in "${peers[@]}"; do
  src="$REPO/protocol-generator/$peer/run-s4.sh"
  [ -f "$src" ] || { echo "run-mint-floor.sh: no harness for '$peer' — SKIPPED" >&2; failed="$failed $peer"; continue; }

  echo "=== $peer ==="
  # Same host/container discrimination as run.sh: discriminate on whether the script
  # EXECUTES podman, not on whether the word appears in a header comment.
  if grep -vE '^[[:space:]]*#' "$src" | grep -q 'podman run'; then
    ORACLE=/work/output/s4-oracles/arc-probe ${NOBUILD:+NOBUILD="$NOBUILD"} \
      bash "$src" -json-out "/work/output/scratch/arc-mint-floor/$peer.json" -peer "$peer" || true
  else
    # The image-name pattern carries `_`: asm-x86_64-toolchain is the one image whose
    # name contains an underscore, and a class of [a-z0-9.-] misses it. Captured with
    # `|| true` so the explicit guard below is what reports, rather than pipefail
    # killing the loop before it can.
    img="$(grep -oE 'entity-core-keystone/[A-Za-z0-9._-]+:latest' "$src" | head -1 || true)"
    if [ -z "$img" ]; then
      echo "run-mint-floor.sh: $peer is container-only and names no image — SKIPPED" >&2
      failed="$failed $peer"
      continue
    fi
    # shellcheck source=../podman-caps.sh
    . "$REPO/tools/podman-caps.sh"
    podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
      -v "$REPO":/work:Z -w /work \
      -e ORACLE=/work/output/s4-oracles/arc-probe ${NOBUILD:+-e NOBUILD="$NOBUILD"} \
      "$img" bash "/work/protocol-generator/$peer/run-s4.sh" \
      -json-out "/work/output/scratch/arc-mint-floor/$peer.json" -peer "$peer" || true
  fi
done

# A roster run that stops partway and reports nothing is worse than one that records
# a failure, so the loop continues and the skips are NAMED here.
if [ -n "$failed" ]; then
  echo "run-mint-floor.sh: NOT MEASURED —$failed" >&2
fi
