#!/bin/sh
# inner-container-script-check.sh — syntax-check the script a run-s4.sh sends INTO its
# container, which `sh -n` on the harness itself structurally cannot see.
#
# Eleven of the 46 peer harnesses re-exec into podman and carry their whole peer
# lifecycle inside a single-quoted `sh -c '...'` / `bash -lc '...'` argument. To the
# outer shell that argument is one string: `sh -n run-s4.sh` parses it as a literal and
# returns 0 no matter what is inside. Any sweep that edits those blocks — the 2026-09-02
# teardown sweep did — needs this or it is checking 35 files and reporting 46.
#
# HOW IT GETS THE TEXT, and why the obvious way is wrong. Reconstructing the block with a
# regex fails, and fails quietly: the blocks contain lines like
#
#     PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"
#
# where the outer shell CLOSES the single-quoted string, splices a value, and reopens it.
# A scanner that treats the first unescaped quote as the end captures a fragment, and
# `sh -n` then reports a syntax error in text that never existed. So: shim podman, let
# the real shell do the quoting, and check exactly what podman would have been handed.
#
# The shim reads the argument after the LAST `-*c` flag, not after a literal `-c`: four
# peers use `bash -lc`, and matching only `-c` captured nothing for them while reporting
# them as "no inner script" — a false clean, which is the same defect class the sweep
# this was written for is about.
#
#   sh protocol-generator/shared/diagnostics/inner-container-script-check.sh
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SHIMDIR="$(mktemp -d)"
trap 'rm -rf "$SHIMDIR"' EXIT INT TERM

cat > "$SHIMDIR/podman" <<'SHIM'
#!/bin/sh
last=""; prev=""
for a in "$@"; do
  case "$prev" in -*c) last="$a" ;; esac
  prev="$a"
done
printf '%s' "$last" > "${SHIM_DUMP:?SHIM_DUMP unset}"
exit 0
SHIM
chmod +x "$SHIMDIR/podman"

checked=0; failed=0; noinner=0
for f in "$ROOT"/protocol-generator/*/run-s4.sh; do
  peer="$(basename "$(dirname "$f")")"
  dump="$SHIMDIR/inner-$peer.sh"
  : > "$dump"
  SHIM_DUMP="$dump" PATH="$SHIMDIR:$PATH" sh "$f" -profile core >/dev/null 2>&1
  if [ ! -s "$dump" ]; then
    noinner=$((noinner + 1))
    continue
  fi
  checked=$((checked + 1))
  if ! sh -n "$dump" 2>"$SHIMDIR/err"; then
    echo "SYNTAX FAIL $peer: $(cat "$SHIMDIR/err")"
    failed=$((failed + 1))
  fi
done

# Print the counts and assert on them: a run that captured nothing would otherwise
# print the same success line as one that captured every block.
echo "inner container scripts: checked=$checked failures=$failed (no inner block: $noinner)"
[ "$checked" -gt 0 ] || { echo "ERROR captured no inner blocks at all" >&2; exit 1; }
[ "$failed" -eq 0 ]
