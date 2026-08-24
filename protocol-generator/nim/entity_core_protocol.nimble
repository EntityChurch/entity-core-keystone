# entity-core-protocol-nim — nimble manifest (profile [layout], [build]).
# The ONLY runtime dependency is system libsodium (crypto floor); the codec,
# base58, varint, and test harness are hand-rolled in-repo, and unittest /
# tables / options / asyncdispatch ship with the compiler. No third-party nimble
# packages for the core floor.

# version is the PACKAGE version (0.1.0-pre, pre-release; nimble-registry publish
# deferred cohort-wide, git-URL install works pre-registration). NOT the spec version
# — the tracked spec is ENTITY-CORE-PROTOCOL v0.8.0 (V8), recorded in CHANGELOG.md.
version       = "0.1.0-pre"
author        = "Entity Core Protocol contributors"
description   = "entity-core core protocol peer (Nim) — hand-rolled canonical ECF codec + libsodium crypto floor + asyncdispatch peer machinery"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["host"]   # the standalone peer host (S4 conformance target)

# Nim toolchain pinned in containers/nim-toolchain/Containerfile (2.2.2).
requires "nim >= 2.0.0"

# S2 gate: byte-identity vs the v0.8.0 corpus + the [2^63,2^64-1] self-test.
task conformance, "Run the ECF wire-conformance harness (S2 gate)":
  exec "nim c -r --mm:orc --overflowChecks:on -d:release --hints:off " &
       "-o:tests/tconformance_bin tests/tconformance.nim " &
       "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"

# S3 gate: the smoke scenario (handshake both directions, unknown-handler status,
# request_id demux) over real loopback TCP between two Nim peers.
task smoke, "Run the S3 peer-machinery smoke gate":
  exec "nim c -r --mm:orc --overflowChecks:on -d:release --hints:off " &
       "-o:/tmp/smoke_bin src/smoke.nim"
