#!/bin/sh
# p47-run.sh — run the pre-hello-authenticate probe across peers, safely.
#
# WHY A WRAPPER AND NOT JUST `ORACLE=...`. Eight of the 46 run-s4.sh scripts
# re-exec into their own container and forward only a couple of env vars, so an
# `ORACLE` set on the host is SILENTLY DROPPED at the container boundary and the
# inner run falls back to the real validator. That failure is invisible in the
# worst way: the run succeeds, exits 0, and writes a perfectly good CONFORMANCE
# report where a probe report was expected. Measured: 8 peers did exactly that.
#
# Trying to special-case them means replicating eight peers' podman invocations —
# a second copy of the dispatch table, which is the thing this repo's tooling
# explicitly refuses to grow. So instead: every peer defaults ORACLE to the same
# path (`/work/output/s4-oracles/validate-peer`), so the probe is installed THERE
# for the duration of the run. No per-peer knowledge, nothing to keep in sync.
#
# THE OBVIOUS DANGER IS HANDLED EXPLICITLY. Leaving the probe installed as
# `validate-peer` would mean the next conformance run silently measures nothing
# and reports success — the exact class of defect this repo keeps finding. So:
#   * the real binary is copied aside BEFORE anything else, and its SHA-256 recorded;
#   * an EXIT/INT/TERM trap restores it;
#   * the restore is VERIFIED by hash, and a mismatch is a loud non-zero exit;
#   * if a previous run left a backup behind, this refuses to start.
#
# Usage:  tools/p47-run.sh [peer ...]      (no args = all peers in the roster)
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ORACLE_BIN="output/s4-oracles/validate-peer"
PROBE_BIN="output/s4-oracles/p47-probe"
BACKUP="output/s4-oracles/validate-peer.p47-backup"

[ -x "$PROBE_BIN" ] || { echo "p47-run: ERROR probe not built at $PROBE_BIN" >&2; exit 2; }
[ -x "$ORACLE_BIN" ] || { echo "p47-run: ERROR no validator at $ORACLE_BIN" >&2; exit 2; }

if [ -e "$BACKUP" ]; then
  echo "p47-run: ERROR $BACKUP already exists — a previous run did not restore." >&2
  echo "  Do NOT run a conformance census until this is resolved. Compare:" >&2
  echo "    sha256sum $BACKUP $ORACLE_BIN" >&2
  echo "  and move the real validator back into place by hand." >&2
  exit 2
fi

REAL_SUM="$(sha256sum "$ORACLE_BIN" | cut -d' ' -f1)"
cp -p "$ORACLE_BIN" "$BACKUP" || exit 2

restore() {
  if [ -e "$BACKUP" ]; then
    cp -p "$BACKUP" "$ORACLE_BIN" && rm -f "$BACKUP"
  fi
  now="$(sha256sum "$ORACLE_BIN" 2>/dev/null | cut -d' ' -f1)"
  if [ "$now" != "$REAL_SUM" ]; then
    echo >&2
    echo "p47-run: !! THE VALIDATOR WAS NOT RESTORED CORRECTLY." >&2
    echo "  expected sha256 $REAL_SUM" >&2
    echo "  found    sha256 ${now:-<missing>}" >&2
    echo "  Restore from $BACKUP or re-run tools/oracle-bootstrap.sh BEFORE any" >&2
    echo "  conformance run — otherwise the next census measures the wrong binary." >&2
    exit 9
  fi
  echo "p47-run: validator restored and hash-verified ($REAL_SUM)"
}
trap restore EXIT INT TERM

cp -p "$PROBE_BIN" "$ORACLE_BIN" || exit 2
echo "p47-run: probe installed as $ORACLE_BIN (real validator backed up)"
echo

tools/run-cohort-census.sh --probe "$@"
rc=$?
exit $rc
