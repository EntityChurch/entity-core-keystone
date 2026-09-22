#!/usr/bin/env julia
# ECF wire-conformance harness — the S2 gate runner (profile [testing].conformance_probe).
# Thin CLI over test/harness.jl: run the corpus, print the tally, exit nonzero on any FAIL.
#
# Run:  julia --project=. test/conformance.jl [path/to/conformance-vectors.cbor]

include("harness.jl")

const DEFAULT_FIXTURE = joinpath(@__DIR__, "..", "..", "shared", "test-vectors", "ecf-conformance",
                                 "conformance-vectors.cbor")

path = length(ARGS) >= 1 ? ARGS[1] : DEFAULT_FIXTURE
pass, fail, _, _ = run_conformance(path; verbose = true)
exit(fail == 0 ? 0 : 1)
