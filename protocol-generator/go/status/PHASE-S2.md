# Phase S2 — Go peer — Codec build

**Phase:** S2 (codec — in-container build + wire-conformance)
**Peer:** Go (`protocol-generator/go/`) — **clean-room** (Go is the oracle's
language; no entity-core-go source read while building — only the opaque
conformance corpus).
**Spec read:** `spec-data/v7.75` (ENTITY-CBOR-ENCODING v1.5, V7 §§3–9, §6.3,
§1.2/§1.5/§7.3, §4.7).
**Status:** ✅ COMPLETE — **69/69 byte-identical, 0 FAIL.**

## Result

`go test -run TestConformance` → **69/69 PASS** (64 encode_equal + 5
decode_reject), `go vet` clean, `gofmt -l` empty, build `--network=none`
(stdlib-only, `go.sum` empty). Full breakdown + invariant coverage in
`status/CONFORMANCE-REPORT.md`.

## Module layout (per profile `[layout]`)

```
protocol-generator/go/src/
  go.mod                       module github.com/entity-core/entity-core-protocol-go (go 1.25, zero deps)
  hash.go                      package entitycore — Entity, EncodeECF, ContentHash, VerifyContentHash
  peerid.go                    PeerID Format/Parse (Base58 + varint prefix)
  sign.go                      Ed25519 Sign/Verify over ECF(entity), PublicKeyFromSeed
  conformance_test.go          §E.3 harness: loads the .cbor, dispatches per category
  internal/
    cbor/  value.go            Value model (Kind discriminator: uint/nint/float/…; data = arbitrary ECF value)
           encode.go           canonical encoder (Rule 1/2/3/4/4a/5), shortest-float, map-key sort
           decode.go           recursive decoder; tag reject (§6.3/N2), non-minimal/indefinite/dup reject
           cbor_test.go        beyond-corpus regression (A-GO-003 int bands, N3, float boundary)
    base58/ base58.go          Bitcoin-alphabet encode/decode
    varint/ varint.go          LEB128 (N1); minimal-encoding rejection on decode
```

Public API at module root (`package entitycore`); codec internals under
`internal/` (compiler-enforced encapsulation). Strategy = **native**, as the
profile bet; no FFI fallback was needed.

## Key implementation decisions

- **Shortest-float (Rule 4 / 4a):** hand-rolled `encodeFloat` tries
  float16 → float32 → float64, taking the shortest form that round-trips to the
  exact `float64`. `float64ToHalf` checks exact representability for both normal
  (exp ∈ [-14,15], low-13-mantissa-bits zero) and subnormal (exp ∈ [-24,-15],
  exact right-shift) half ranges. Specials are emitted as the exact Rule-4a
  bytes BEFORE the shortest-form search: NaN→`F9 7E00` (all payloads collapse to
  the canonical quiet NaN), +Inf→`F9 7C00`, -Inf→`F9 FC00`, -0.0→`F9 8000` (via
  `math.Signbit`), +0.0→`F9 0000`. The corpus' 65503 (f32) vs 65504 (max-normal
  f16) boundary is the discriminating case and passes.
- **Map-key ordering (Rule 2):** each pair's key+value is fully pre-encoded,
  then keys are sorted by **encoded-length-then-byte-wise-lexicographic**
  (`canonicalLess`). This handles text/byte/mixed keys uniformly (the encoded
  key bytes carry the major-type, so `h'6b6579'` vs `"text_key"` sort exactly as
  the corpus pins). Duplicate keys (now adjacent) are rejected (Rule 5) on both
  encode and decode.
- **Value model:** an explicit `Kind`-tagged `Value` preserves the
  distinctions Go's native types erase — uint vs nint vs float, and the full
  `nint` band `[-2⁶⁴,-1]` carried as a `uint64` magnitude (A-GO-003). Entity
  `data` is an arbitrary ECF `Value`, NOT necessarily a map (A-JAVA-010).
- **Decoder:** recursive structural decode; rejects major-type-6 tags at any
  depth (§6.3/N2), non-minimal integer arguments, indefinite lengths (Rule 3),
  duplicate keys (Rule 5), invalid UTF-8, trailing bytes. This is what makes the
  5 `tag_reject` vectors pass — the tag is hit while walking the
  envelope/entity/included structure and the decode aborts.
- **content_hash §4.7 asymmetry:** construction (`ContentHash`) serialises
  whatever `format_code` the caller supplies (forward-compat; corpus
  `content_hash.4` synthetic code 128 → `80 01` varint prefix + SHA-256 digest);
  verification (`VerifyContentHash`) gates on the registry and returns
  `ErrUnsupportedHashFormat` for unknown codes. Both halves implemented.
- **Crypto:** stdlib `crypto/ed25519` (deterministic RFC-8032 signing — the 3
  signature vectors reproduce exactly from fixed seeds), `crypto/sha256` (floor),
  `crypto/sha512` (SHA-384/512 agility hashing). Zero third-party crypto.

## Vectors that fought back

**None failed.** The work that needed care (anticipated, not surprising):
1. **content_hash.4 / peer_id.3 (synthetic ≥0x80 codes):** required the real
   LEB128 varint (N1), not a fixed byte — `128` → `80 01`. Wiring all
   format/key/hash framing through `internal/varint` made these pass first try.
2. **Class B dispatch:** the corpus' Class B `input` is *semantic*
   (`{seed, entity}` for signature, `{key_type,hash_type,digest}` for peer_id),
   and `canonical` is a *derived* value (signature/peer-id/hash), NOT a
   re-encoding of `input`. The harness dispatches by category so it applies the
   right construction; Class A categories (incl. `nested`/`envelope`) are a plain
   canonical re-encode of the decoded `input`.
3. **float16 subnormal exactness:** the encoder's half-precision exactness test
   needed both the normal and subnormal branches correct; verified by an added
   smallest-subnormal-f16 regression (`F9 0001`).

## Container build

Image `entity-core-keystone/go:latest` (reused `containers/go/Containerfile`,
fedora:43 + golang-1.25.10) was already present (7 days old); verified
`go version go1.25.10`. Build + full conformance run execute `--network=none`
(zero module fetches — stdlib-only core peer). File ownership after in-container
writes fixed via `podman unshare chown` per the rootless-subuid workflow.

## Spec ambiguities logged

- **A-GO-005 (new):** corpus version skew — profile pins `v7.75` but no
  `test-vectors/v7.7x` dir exists past `v7.71`; the ECF codec corpus is
  byte-identical (SHA `41d68d2d…`) across v7.56→v7.71 per the MANIFEST, so v7.71
  IS the v7.75 ECF corpus. Ran against v7.71; recommended keystone vendor a
  v7.75 re-stamp so the reproducibility coordinate resolves to a literal dir.
  Informational, NOT a blocker — 69/69 is exact against the canonical file.

A-GO-001 (hand-roll vs fxamacker — confirmed: native hand-roll reached 69/69, the
A-005 pattern holds for Go), A-GO-002 (Ed448 deferred — not exercised by the core
floor corpus), A-GO-003 (nint uint64-carrier — validated by the beyond-corpus
regression) all carry forward unchanged. **No blocking items.**

## Phase exit criteria — met

- [x] All 69 conformance vectors PASS (encode + decode-reject + hash/sig/peer-id)
- [x] Conformance report green (`status/CONFORMANCE-REPORT.md`)
- [x] Ambiguity log: no blocking items (A-GO-005 informational)
- [x] Codec compiles clean under the profile's compiler/linter floor
      (`go build` / `go vet` clean, `gofmt -l` empty)
- [x] N1–N4 each covered by a corpus vector and/or regression test
- [x] Native strategy held — no FFI fallback needed

## Next phase (S3 — NOT in scope here)

Peer machinery: goroutine-per-conn, `sync.RWMutex` content store (§4.8 / §7b —
non-negotiable from day one per the Zig/CL store-race lesson), `request_id`→
channel demux (§6.11), TCP_NODELAY, dispatcher boundary. The codec surface here
is the foundation; S3 builds the transport/dispatch on top.
