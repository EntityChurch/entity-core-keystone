#!/usr/bin/env bash
# Run the keystone peer contract suite against one peer and write its report.
#
#   tools/peer-contract/run.sh <peer>              # report to output/scratch/peer-contract/<peer>/
#   tools/peer-contract/run.sh <peer> --to-status  # report to protocol-generator/<peer>/status/
#
# Steps, each one visible: build the shared driver (Go, pinned image) → the peer's own
# run-contract.sh (its container; builds its bare host and contract host, runs the driver and its
# local tests) → report.py. A bare run never writes the tracked report; publishing one is a
# deliberate --to-status (AGENTS.md: a gate must not rewrite a committed artifact).
#
# A peer is brought up to the contract by giving it: protocol-generator/<peer>/run-contract.sh,
# a contract host (FIXTURE-HOST.md), and the local tests the registry names. Nothing here changes.
set -euo pipefail
cd "$(dirname "$0")/../.."
. tools/podman-caps.sh

PEER="${1:?usage: run.sh <peer> [--to-status]}"
TO_STATUS=0; [ "${2:-}" = "--to-status" ] && TO_STATUS=1
SCRIPT="protocol-generator/$PEER/run-contract.sh"
[ -x "$SCRIPT" ] || { echo "peer-contract: $PEER has no $SCRIPT — not brought up to the contract yet" >&2; exit 2; }

GO_IMAGE="${GO_IMAGE:-entity-core-keystone/go:latest}"
mkdir -p output/peer-contract
echo "peer-contract: building the driver"
podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$PWD":/work:Z -w /work/tools/peer-contract/driver \
  -e CGO_ENABLED=0 -e GOFLAGS= -e GOWORK=off -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
  "$GO_IMAGE" go build -o /work/output/peer-contract/kpc-driver .

OUT="output/scratch/peer-contract/$PEER"
rm -rf "$OUT" && mkdir -p "$OUT"
echo "peer-contract: $SCRIPT"
OUT="$OUT" "$SCRIPT"

DEST="$OUT/KEYSTONE-PEER-REPORT.json"
[ "$TO_STATUS" = 1 ] && DEST="protocol-generator/$PEER/status/KEYSTONE-PEER-REPORT.json"
PLANTS=()
[ -f "protocol-generator/$PEER/status/KEYSTONE-PEER-PLANTS.json" ] && PLANTS=(--plants "protocol-generator/$PEER/status/KEYSTONE-PEER-PLANTS.json")
# shellcheck disable=SC1090
. "protocol-generator/$PEER/contract/artifacts.env"
ARTS=()
for a in $KPC_ARTIFACTS; do ARTS+=(--artifact "$a"); done
python3 tools/peer-contract/report.py --peer "$PEER" --cases "$OUT/cases.json" --local "$OUT/local.txt" \
  --image "$KPC_IMAGE" "${ARTS[@]}" "${PLANTS[@]}" --out "$DEST"
