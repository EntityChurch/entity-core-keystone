#!/bin/sh
# starved-categories-probe.sh — surface the categories a budget-exhausted run never measured.
#
# WHY: `-timeout` is a GLOBAL budget. One hung or very slow check can consume it, after which
# whole categories report `budget_exhausted`. The oracle's HUMAN output flags that loudly
# ("!! WHOLE CATEGORIES NEVER RAN … this is coverage loss, not a slow peer"); its JSON does
# NOT — starved categories land under `skipped`, so a summary-only reader sees a small `failed`
# count and a slightly high skip count, and the hidden categories may contain real FAILs.
# (asm-x86_64, 2026-08-17: 7 categories starved, `resource_bounds` among them, hiding 2 core
# FAILs. See CONFORMANCE-MATRIX.md §1a.)
#
# Driving one category at a time is better than raising -timeout: it runs in seconds instead
# of re-running the whole suite behind the hang, and it keeps the published gate verdict at
# the default budget where it belongs.
#
# Find the starved categories first:
#   python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); \
#     print(sorted({c["category"] for c in d["checks"] if "budget_exhausted" in c.get("message","")}))' \
#     output/scratch/census/<peer>.json
#
# Then run this INSIDE the peer's toolchain container, from the repo root:
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     localhost/entity-core-keystone/<peer>-toolchain:latest \
#     sh /work/protocol-generator/shared/diagnostics/starved-categories-probe.sh <peer> [category...]
#
# Results land in output/scratch/starved/<peer>/<category>.json (gitignored).
set -u
PEER="${1:?usage: starved-categories-probe.sh <peer> [category...]}"
shift
if [ "$#" -eq 0 ]; then
  # the seven starved on the asm/ISA trio — override by passing your own list
  set -- resource_bounds authz crypto_agility format_agility negotiation \
         peer_canonicalization universal_address_space
fi
OUT=/work/output/scratch/starved/"$PEER"
mkdir -p "$OUT"
for cat in "$@"; do
  echo "=== $PEER / $cat ==="
  # Only the trailing block matters: the interleaved "FAIL <cat>.<check> <n>s" progress lines
  # include retries and extension checks that the category itself does not count. The
  # authoritative per-category verdict is the JSON written to $OUT.
  NOBUILD=1 sh /work/protocol-generator/"$PEER"/run-s4.sh \
    -profile core -category "$cat" -timeout 120s \
    -json-out "$OUT/$cat.json" 2>&1 | grep -E '^Result:' | tail -1
done
echo
echo "=== per-category JSON written to output/scratch/starved/$PEER/ ==="
echo "Summarise on the HOST (this container may have no python3):"
echo
cat <<'HINT'
  python3 - output/scratch/starved/<peer>/*.json <<'PY'
  import json,sys,os
  for f in sys.argv[1:]:
      d=json.load(open(f)); s=d["summary"]
      print(f'{os.path.basename(f)[:-5]:26s} P={s["passed"]:3d} W={s["warned"]:3d} '
            f'F={s["failed"]:3d} S={s["skipped"]:3d}')
      for c in d["checks"]:
          if c["severity"]=="FAIL":
              print(f'    FAIL {c["name"]}: {c["message"][:150]}')
  PY
HINT
