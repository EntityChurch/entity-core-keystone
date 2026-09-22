# Six wire-visible disposition codes that no normative document defines

**Date:** 2026-09-09 · **From:** `entity-core-keystone`
**Corpus searched, by name** (the F51 rule — a claim of absence records what it read):
`protocol-generator/shared/spec-data/v0.8.2.11/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`
plus the **entire** `entity-system-architecture/specs/` tree — all `EXTENSION-*.md`, `SDK-*.md`,
`DOMAIN-*.md` and `GUIDE-*.md`.

---

## The finding

**Six disposition codes are emitted by 24–36 of our 46 peers each and appear in no spec.**

| code | peers emitting | observed on the wire? |
|---|---:|---|
| `no_outbound_seam` | 36 | traced in source |
| `invalid_resource` | 34 | traced in source |
| `no_handler_body` | 32 | **yes — measured**, 8 peers, `tools/host-seam-probe` |
| `invalid_peer_pattern` | 31 | traced in source |
| `expression_not_found` | 24 | traced in source |
| `unsupported_expression` | 24 | traced in source |

The distinction in the last column is deliberate: only `no_handler_body` has been *observed* leaving a
peer. The other five are traced as arguments to the same `errOutcome`/`err_out` constructors that
produce a response entity, so they are wire-reachable by construction — but that is an inference, and
it is labelled as one.

**Why it matters rather than being cosmetic.** §4.7 makes the error surface a **MUST-emit contract**,
and §3.3 pins codes per status row precisely so a caller can switch on them. A code no document
defines is one no independent client can be written against — and these are not one peer's local
habit: they are the *generated cohort's* shared vocabulary, which is exactly the shape that reads as
a convention and has no authority behind it.

## Attribution — the oracle is NOT the source, and that was the hypothesis

Stated plainly because the opposite was suspected and checking it was cheap:

**The oracle enforces no code absent from the spec.** All 31 codes `entity-core-go`'s validator
compares against were extracted and classified. Every one is either spec-defined or tolerated rather
than required. The single candidate — `unknown_handler` — sits in `registry_issuer.go` (**REGISTRY**,
not a core category) inside an **OR of accepted alternatives**:

```go
return status == 404 || code == "handler_not_found" || code == "not_found" || code == "unknown_handler"
```

That is permissive, not an assertion, and no peer is gated on it. **`entity-core-go` is not
legislating through the oracle**, and the ten other oracle-asserted codes that are absent from *our
vendored snapshot* — `cast_out_of_range`, `index_out_of_range`, `type_mismatch`, `invalid_expression`,
`scope_unreachable` (EXTENSION-COMPUTE), `type_not_found` (EXTENSION-TYPE),
`delegator_must_be_local_peer` (EXTENSION-ROLE), `embedded_cap_unauthorized`,
`unknown_transform_op`, `path_traversal_rejected` (DOMAIN-LOCAL-FILES) — are all properly defined in
extension specs we deliberately do not vendor. That is the vendoring boundary working, not a defect.

**So the six are keystone's own.** They originate in this repo's `go` peer and propagated with the
generation lineage. Owning that is the point of writing it down.

## The underlying gap: §6.13(a)'s failure surface has no pinned vocabulary

The codes cluster on one surface — **what a peer answers when a registered handler cannot produce a
body** — and that surface has no code in any spec. Measured on the wire across all 46 peers
(`shared/findings/host-seam-dispatch-wire-census.md`), the cohort spells that one failure **four
ways**:

| spelling | peers |
|---|---:|
| `no_handler_body` | 8 |
| `handler_not_found` | 7 |
| `unsupported_operation` | 4 |
| `not_implemented` | 1 (`pd`) |

All four are answers to the identical request. A client cannot distinguish "registered but no body"
from "no handler here" on 7 of these peers, because they answer the same code for both.

## Asks for architecture

1. **Pin a disposition for "registered handler, no body."** §3.3's 501 row names
   `unsupported_operation` for *an operation absent from the manifest*; this is a different failure —
   the operation IS in the manifest and the body is missing — and §6.13(a) does not name a code for
   it. If `unsupported_operation` is the intended answer, saying so retires `no_handler_body` on 8
   peers and settles the other three spellings.
2. **Rule on `pd`'s `501 not_implemented`.** §3.3 (0.8.2.7) lists `not_implemented` as one of four
   non-conformant spellings of the 501 row. Whether that blacklist reaches *this* failure is unclear:
   0.8.2.8 carves out *"a domain code defined for a different failure that also answers 501"*, and
   "no body bound" is arguably a different failure. **We have not treated this as a defect** pending
   the ruling.
3. **Say whether an implementation may mint a code at all.** The other five
   (`no_outbound_seam`, `invalid_resource`, `invalid_peer_pattern`, `expression_not_found`,
   `unsupported_expression`) each name a real, distinct failure with no spec code. Either they want
   registry entries, or the spec should say a peer MUST fall back to a pinned code — the current
   state, where 36 peers emit a code nothing defines, is the one answer that helps nobody.

**Nothing here is a conformance failure at the current check set**, and no peer's number moves. This
is a vocabulary gap that the 778-check set structurally cannot see, because no vector drives the
surface.
