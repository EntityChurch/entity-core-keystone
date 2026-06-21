// entity-core-protocol-go — clean-room Go core protocol peer (V7).
//
// Version line: 0.1.0-pre (Go modules carry the version via a git SemVer TAG —
// `v0.1.0-pre` at a reviewed commit — NOT a field in go.mod; see status/PHASE-S5.md
// §Version-pin for the module-path / tag nuance). Tracks V7 spec-data v7.75; codec
// corpus v0.8.0. Conformance: validate-peer --profile core PASS, 653/0F/94skip @ oracle
// entity-core-go 75c532e.
//
// Stdlib-only — ZERO third-party modules; go.sum stays empty (the single S11 pin is the
// Go toolchain, 1.25.10, from containers/go/Containerfile). crypto/ed25519 + crypto/sha256
// + crypto/sha512 + net + testing cover everything; CBOR/base58/varint are hand-rolled.
//
// CLEAN-ROOM: built from the V7 spec, NOT from entity-core-go (the oracle's own source).
module github.com/entity-core/entity-core-protocol-go

go 1.25
