# entity-core-protocol-cobol — Phase S1 summary

**Status:** COMPLETE. **Spike:** GO (see `spike/SPIKE-FINDINGS.md`).

## What S1 produced

- `containers/cobol-toolchain/Containerfile` — GnuCOBOL 3.2 + gcc + libsodium,
  S11-pinned. Built + verified (`cobc 3.2.0`).
- `profile.toml` — complete, no TBD on any load-bearing field.
- `arch/PROFILE-RATIONALE.md` — why each choice.
- `spike/` — four go/no-go probes (recursion, var-length, uint64, FFI), all PASS.
- Ambiguity log: `A-CBL-001` (uint64 discovery, strengthens F7), `A-CBL-002`
  (FFI is entity-grained → COBOL still owns the canonical value codec).

## Decisions locked

| Axis | Choice | Why |
|---|---|---|
| Codec strategy | **FFI-hybrid** | C-ABI does crypto/hash/entity-framing/peer-id/envelope byte-exact; COBOL hand-rolls the canonical CBOR *value* codec (C-ABI is entity-grained, A-CBL-002) |
| uint64 carrier | 8-byte `PIC 9(18) COMP-5`, `-fno-binary-truncate` | decimal-first model; `9(18)` truncates, >18-digit binary undeclarable (A-CBL-001) |
| Error model | status-code (`PIC S9(9) COMP-5` + 88-levels) | maps onto C-ABI `EC_*` + wire status codes; no COBOL exceptions |
| Concurrency | OS threads + single-writer store lock | no COBOL async; raw-thread §4.8 idiom; RECURSIVE+LOCAL-STORAGE for chain-walk |
| Float | omitted from COBOL encoder; corpus floats via FFI round-trip | floats only in S2 corpus, never peer payloads |
| Naming | UPPER-KEBAB data/paragraphs, lower-kebab program-ids, free format | canonical COBOL |
| Packaging | source dist + Makefile, Apache-2.0 | no COBOL registry |

## Module plan (S2→S3)

`cbor` (value codec) · `ffi` (C-ABI bindings) · `model` · `peer-id` · `identity`
· `store` · `wire` · `capability` (chain-walk) · `transport` · `peer` · `bin/host`.

## Exit criteria — met

Profile fully populated; rationale written; container built + verified; ambiguity
log has no blocking items (A-CBL-001/002 are findings/refinements, not blockers).
Next: **S2 codec** — FFI bindings + canonical CBOR value codec + self-test
byte-identical against the v7.71 conformance corpus.
