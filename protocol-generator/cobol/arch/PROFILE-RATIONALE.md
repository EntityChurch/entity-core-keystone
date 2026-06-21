# entity-core-protocol-cobol — Profile Rationale

Why each profile choice was made. Audit trail for future operators. Grounded in
the S1 feasibility spike (`spike/SPIKE-FINDINGS.md`, GO) and the V7 spec.

## Codec strategy — FFI-hybrid, not "FFI-everything"

The slate (RELEASE-READINESS §2) framed COBOL as "FFI everything (no COBOL
CBOR/crypto)." The spike refined this. **The C-ABI is entity-envelope-grained,
not value-grained** (A-CBL-002): `ec_encode_ecf` / `ec_content_hash` take the
entity `data` field as *already-canonical CBOR* — the rust impl is explicit
(*"`data` is the opaque, already-canonical CBOR of the data field"*). The library
frames the 2-key `{data, type}` entity map, hashes it, signs it, and runs the N2
tag-scanner on decode — but the *contents* of `data` (the params maps, capability
token fields, signature triples, etc.) are the caller's to produce canonically.

So COBOL still hand-rolls a **canonical CBOR value codec** — exactly the layer
every native peer owns (A-005: no platform CBOR lib gives ECF's guarantees), just
here over FFI for everything *around* it. This is genuinely less work than a
native peer (crypto, SHA-2, base58/peer-id, entity framing, envelope verify, and
the subtle N2 recursive tag-reject all come from the C-ABI byte-exact), but it is
**not a thin shim**. The honest label is FFI-hybrid. No COBOL crypto exists, so
the crypto FFI is non-negotiable regardless.

Float (f16/f32/f64 shortest-form, the ECF "float ladder" every peer re-derived)
is the one place this pays off twice: floats appear only in the **S2 ECF
conformance corpus**, never in the peer's own data payloads (protocol values are
uint/text/bytes/map/array/bool/null). Rather than re-derive the float ladder in
COBOL, the corpus float vectors are validated through the FFI bare-value
round-trip (`ec_encode_bare_value`, identity on canonical input). The COBOL value
encoder therefore omits float entirely — a deliberate, documented scope cut.

## Numeric model — the discovery payoff (spike P3 / A-CBL-001)

COBOL is decimal-first. `PIC 9(n)` is a *decimal-digit* width. uint64 max
(`18446744073709551615`) is 20 digits; the comfortable `PIC 9(18)` is one
digit-class short and silently truncates, and GnuCOBOL refuses to *declare* a
>18-digit binary. The carrier is an **8-byte `PIC 9(18) COMP-5`** (full 2^64
storage) built with `-fno-binary-truncate`; native byte order aligns with the C
`uint64_t` over the FFI boundary. This is the integer-head-form trap's 5th
distinct flavor and the sharpest argument for the queued u64-range vectors (F7).

## Error model — status codes, not exceptions

COBOL has no exception or `Result`/`Either` machinery. The native idiom is an
integer `RETURN-CODE` + a status field tested at the call site. This maps
*directly* onto two things the protocol already speaks in integers: the C-ABI's
`int32_t EC_*` codes, and the wire status codes (200/403/404/413/400/…). So the
whole peer threads a `PIC S9(9) COMP-5` status with `88`-level condition names —
no impedance mismatch, the most COBOL-faithful choice.

## Async / concurrency — OS threads + single-writer store lock

COBOL has no language async. §4.8 (inbound concurrent with outbound dispatch) and
§6.11 (reentrancy) are met with OS threads (pthread via a tiny C shim, the same
FFI seam): an accept loop dispatches each connection; the chain-walk and decoder
are `RECURSIVE`+`LOCAL-STORAGE` (spike P1 — `WORKING-STORAGE` is static and would
corrupt under recursion). Store data-race safety (§4.8, the v7.75 `concurrency`
gate) is a **single-writer lock** — the raw-thread idiom (Zig/CL class), enforced
by hand, since COBOL has neither actors (Swift/Elixir) nor STM (Haskell). Per §7b,
blocking `read`/`accept` run on dedicated OS threads, not a bounded pool.

## Naming — canonical COBOL

UPPER-KEBAB-CASE data names + paragraphs (the canonical COBOL style); lower-kebab
program-ids/copybooks to match the repo and GnuCOBOL's module-name resolution.
Free source format (`-free`) over fixed columns — modern GnuCOBOL idiom, and the
1960s column rules add nothing.

## Build / packaging — source distribution

No COBOL package registry exists. The artifact is a source distribution built by
`cobc` in `containers/cobol-toolchain/` via a `Makefile`, linking
`libentitycore_codec`. License Apache-2.0 (S9 default; COBOL has no MIT-preference
ecosystem norm).

## Pins (S11)

`gnucobol-3.2-8.fc43` (~11 months), `gcc-15.2.1-7.fc43`,
`libsodium-1.0.22-1.fc43` — all ≥30 days old, mirrored in the Containerfile.
The codec C-ABI is pinned at v1.1 with rust+c interchangeable impls (provenance
via `ec_impl_info()`, not filename).
