#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-julia. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# Delegates to the peer's existing run-conformance.sh, which already carries the
# offline-correct invocation (direct `julia --project=. test/<file>.jl`, NOT
# Pkg.test — that reaches for the General registry even for a stdlib-only package
# and dies under --network=none, A-JULIA-009). This exists so the S2 axis has the
# entry point the sweep looks for; it is a name, not a second implementation.
set -euo pipefail
exec "$(dirname "$0")/run-conformance.sh" --tests
