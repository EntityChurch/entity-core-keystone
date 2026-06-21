# entity-core-protocol-rust — Spec Ambiguity Log

Every guess made while authoring the Rust peer goes here (S3 / PROMPT-CONSTANTS
"no silent guesses"). Items escalate to architecture as proposal candidates via
`research/stewardship/`. Format per `shared/lifecycle/PROMPT-CONSTANTS.md`.

These S1 entries are **profile/library decisions**, not spec-semantic guesses — the
spec-data v7.75 surface is tight and well-trodden by 9 prior peers, so S1 surfaced no
*protocol-semantic* ambiguity (consistent with the dry-discovery-well finding; the Rust
peer is a same-language-as-the-sibling cross-check, not a discovery peer). Entries are
recorded for the audit trail per S6 ("profile decides; if a decision isn't authorized,
log it") and S11 (library pins). Genuine spec-semantic ambiguities (if any) get logged
at S2–S4 as `A-RUST-00N` continuing this sequence.

---

## A-RUST-001: CBOR library — hand-roll vs `ciborium`/`minicbor`/`cbor4ii`

**V7 section:** ENTITY-CBOR-ENCODING Rules 2/3/4/4a/5 + §6.3 (ECF canonical layer)
**Profile field:** `[codec].cbor_library`
**Your guess:** Hand-roll a canonical CBOR encoder/decoder (private `cbor` module); do
NOT use `ciborium` (or `minicbor`/`cbor4ii`) for the core codec. `serde_cbor` is excluded
outright (deprecated/unmaintained — supply-chain non-starter).
**Rationale:** No surveyed Rust CBOR lib gives ECF's guarantees for free — `ciborium`'s
"canonical" mode targets RFC-8949 §4.2 bytewise map ordering, NOT ECF Rule-2
length-then-lex; none enforce decode-side shortest-float minimality (Rule 4), recursive
§6.3 major-type-6 tag rejection returning the specific `400 non_canonical_ecf`, or
raw-byte `data` fidelity. All would have to be hand-written on top, at which point the lib
buys little while adding a registry pin. Same A-005 pattern all 9 prior native peers hit
(A-GO-001 is the go-peer twin). Byte-exactness for a content-addressing substrate is
owned + proven vector-by-vector, not delegated.
**Escalation:** operator — local profile decision (not a spec issue). Re-evaluable bar
for a future maintainer: a lib that reproduces `map_keys.*`/`float.*`/`tag_reject.*`
byte-for-byte AND enforces decode-side rejection.

---

## A-RUST-002: Ed448 native support — DEFERRED (native-full-agility NOT cleanly reachable)

**V7 section:** §1.5 / §7.3 (key_type 0x02 = Ed448) + §9.1 floor (Ed25519+SHA-256 only) + crypto-agility seam
**Profile field:** `[codec].ed448_library`
**Your guess:** DEFER native Ed448. Ship Ed25519 + SHA-256 (+ native SHA-384 via `sha2`)
as the conformance floor; when crypto-agility is in scope, source Ed448 via HYBRID FFI
(consume `libentitycore_codec`'s `ec_ed448_*` over the C-ABI v1.1, the OCaml route), NOT
a native Rust crate.
**Rationale (the headline crypto finding):** Native-full-agility incl. Ed448 is NOT
cleanly reachable for Rust the way it was for Haskell (crypton). RustCrypto
`ed448-goldilocks` has Ed448 *signing* ONLY in its `0.14.0-pre` PRERELEASE series
(`0.14.0-pre.13`, etc.), which fails S11 two ways — pre-release (no
pinned-stable) AND RustCrypto's own "NOT been audited — USE AT YOUR OWN RISK" caveat; the
latest *stable* `ed448-goldilocks` is `0.9.0` (2023), no signing API. The third-party
`ed448-goldilocks-plus` `0.16.0` IS stable with signing but is a
single-maintainer unaudited fork (same risk class as an unaudited hand-roll). So Rust is
in the cohort's **gap → hybrid-FFI** band with Go (A-GO-002) / Zig (A-ZIG-002) / OCaml
(A-OC-002) / Swift — Haskell's native-full-agility was the exception, not the rule. Does
NOT affect the §9.1 floor (Ed25519+SHA-256; Ed448 is validated, not required). SHA-384
agility hashing IS native (`sha2::Sha384`) — only the Ed448 *signature* family is the FFI
gap.
**Escalation:** operator — local profile decision (matches the cohort gap; no spec issue).
Revisit trigger: `ed448-goldilocks` graduating `0.14.0` out of `-pre` WITH an audit would
flip this to native-full-agility (like Haskell).

---

## A-RUST-003: Async runtime — std::thread (NOT tokio) for the core peer

**V7 section:** §6.11 (inbound-concurrent-with-outbound) + §4.8/§4.9 + §7b concurrency gate
**Profile field:** `[concurrency].style`, `[idiom].async_runtime`
**Your guess:** Use `std::thread` + `std::sync` (blocking `std::net`, thread-per-conn) for
the core peer; do NOT pull `tokio`/`async-std`. Async is a future opt-in.
**Rationale:** Rust offers both threaded and async concurrency; the §6.11/§7b surface (one
reader thread demuxing EXECUTE_RESPONSE by request_id, data-race-safe store, no-crash
under load) is fully met by threads + `mpsc` channels. `tokio` is a large transitive
closure (dozens of crates) against the repo's supply-chain stance — not worth pulling for
a surface threads cover. Store-safety (§4.8) is enforced by the type system regardless
(an unsynchronized shared-mutable store is a compile error), so the Zig/CL store-race is
structurally unrepresentable. NOT a spec ambiguity — the spec is async-agnostic; this is a
profile idiom choice with a dep-minimization rationale.
**Escalation:** operator — local profile decision (dep-minimization). Re-evaluable if a
phase genuinely needs async (then pin the runtime >=30 days old per S11).

---

## A-RUST-004: sha2 0.10.x stable line vs the new 0.11.0 major

**V7 section:** ENTITY-CBOR-ENCODING (content_hash floor) + agility hashing (SHA-384)
**Profile field:** `[codec].sha256_source`, `[deps].sha2`
**Your guess:** Pin `sha2 = "0.10.9"`, NOT the newer `0.11.0`.
**Rationale:** Both clear the S11 ≥30-day floor (0.11.0 is ~3 months old). But 0.11.0 is a
fresh major-version API break on a fresh release; the 0.10.x line is the settled,
widely-depended-on series and is exactly compatible with the `digest 0.10.x` traits the
RustCrypto stack expects. Conservative choice for a content-addressing floor. NOT a spec
issue.
**Escalation:** operator — local pin decision; re-pin to 0.11 deliberately if a future
phase wants the new API (re-applying the S11 rule).

---

## A-RUST-005: map-key canonical ordering — Rule-2 (length-then-lex) vs bytewise-on-encoded-key (S2)

**V7 section:** ENTITY-CBOR-ENCODING Rule 2 / §4.2.1 (deterministic map-key ordering)
**Profile field:** `[codec].cbor_library` (the hand-rolled canonical layer)
**Your guess:** Sort map keys by **bytewise comparison of the full canonical
encoded-key bytes** (head byte + payload), which is what the go oracle's
`encodeMapCanonical` does, rather than implementing "length-then-lex" as a separate
two-stage comparator. For the ECF key space (text strings, byte strings, small
integers, bools) these are **provably equivalent**: the CBOR head byte already encodes
the major type + length class in its high bits, so a shorter key always has a
numerically smaller leading byte than a longer key of the same major type, and
same-length keys fall through to bytewise on the payload — i.e. bytewise-on-encoded =
length-then-lex for this surface. Verified byte-for-byte against `map_keys.1`–`.6`
(incl. the mixed bstr/text `map_keys.5` and the len-23-vs-24 boundary `map_keys.4`).
**Rationale:** The profile's `[codec]` comment frames Rule 2 as "length-then-lex" and
explicitly flags the RFC-8949 §4.2 plain-bytewise variant as "a real trap." The
resolution here is that the trap is about bytewise on the *decoded* key value (where a
2-char string could sort before a 1-char one); bytewise on the *encoded* key form
(which is what both the go oracle and this impl do) is identical to length-then-lex.
The decoder enforces the same predicate strictly-ascending on encoded key bytes, so it
also rejects unsorted maps (Rule 2) and duplicate keys (Rule 5) in one pass. No
divergence from the corpus; the oracle emission matched byte-for-byte (64/64 encode).
**Escalation:** operator — implementation note, not a spec ambiguity (the spec rule and
the oracle agree; this records *why* the simpler comparator is correct so a future
maintainer doesn't "fix" it into a decoded-value comparator and break `map_keys.2`).

---

## A-RUST-006: peer-layer signature target = the 33-byte content_hash (S3)

**V7 section:** §3.5 (system/signature) + §4.6 / §5.5 (proof-of-possession + chain sig)
**Profile field:** absent (peer-machinery decision, not a `[codec]` field)
**Your guess:** At the **peer layer** a `system/signature` entity signs the target
entity's **33-byte content_hash** (`0x00 ‖ SHA-256(ECF({type,data}))`), via a dedicated
`Identity::sign_entity` that signs the raw hash bytes. This is DISTINCT from the S2 codec
primitive `signature::sign_entity`, which signs the entity's **canonical-ECF encoding**
(what the `signature.*` corpus vectors pin). The peer's `system/signature {target =
content_hash, signer, algorithm, signature}` shape carries the content_hash as `target`
and verification re-signs/re-verifies over that hash.
**Rationale:** The cohort blueprint (Zig `identity.signEntity` / OCaml `sign.ml`) signs the
33-byte content_hash for `system/signature`, and the handshake/chain proof-of-possession is
over the entity hash, not a re-encoding — this is what an oracle verifying a `system/peer`
signature or a capability-chain link expects. The S2 codec's ECF-bytes signing remains the
right primitive for the `signature.*` *codec* vectors (a different surface). Recording the
split so the two are never conflated (the codec primitive is NOT the peer's chain signer).
**Escalation:** operator — peer-machinery convention grounded in §3.5 + the cohort; the
live `validate-peer` at S4 is the byte/behaviour confirmation. Not a spec ambiguity.

---

## A-RUST-007: handshake nonce + host keypair decode without a new crate (S3)

**V7 section:** §4.6 (authenticate nonce — SHOULD ≥32-byte CSPRNG)
**Profile field:** `[deps]` (dep-minimization stance), `[idiom].async_runtime` rationale
**Your guess:** Generate the §4.6 handshake nonce by reading 32 bytes from `/dev/urandom`
directly (with a non-crypto SHA-256(time ‖ counter ‖ stack-addr) fallback on the unexpected
read failure), and hand-roll the host's `--name` PEM **base64 decode**, rather than pulling
a `rand` / `getrandom` / `base64` registry crate.
**Rationale:** The S1/S2 closure is exactly `ed25519-dalek + sha2 + transitive` (2 direct
deps). `ed25519-dalek` with `default-features = false` does NOT re-export an OS RNG, so a
nonce needs OS entropy from somewhere; `/dev/urandom` is the live path on every supported
host (fedora:43 container + Linux dev boxes) and adds zero deps — consistent with the
hand-rolled base58/varint/CBOR stance (A-RUST-001 et al.). The fallback is uniqueness-only
(a single handshake), never production crypto, and is unreachable in practice. The nonce is
NOT a signing seed (signing keys still come from the 32-byte identity seed via dalek).
**Escalation:** operator — dep-minimization local decision; re-evaluable if a phase wants
a portable `getrandom` (then pin ≥30 days per S11). Not a spec issue.

---

## A-RUST-008: S4 offline crate material via gitignored `cargo vendor` mirror (S4)

**V7 section:** absent (build-mechanism, not protocol semantics)
**Profile field:** `[deps]` (dep-minimization / sealed-offline stance), S4 `--network=none` rule
**Your guess:** Satisfy the sealed-offline (`--network=none`) S4 build by checking out a
plain `cargo vendor --locked` mirror of the **unchanged** S2/S3 crate closure
(`ed25519-dalek + sha2 + transitive`) into the **gitignored** `output/vendor/`, and inject a
`[source.crates-io] replace-with = "vendored-sources"` config at run time from `run-s4.sh`
(via a throwaway `$CARGO_HOME`), rather than committing a `.cargo/config.toml` or a vendor
tree into the repo. The Go `validate-peer` + `entity-peer` oracles are likewise built from
the pinned `e8524ed` snapshot into the gitignored `output/s4-oracles/` and never committed.
**Rationale:** The crate closure is identical to S2/S3 (no new dep — `cargo vendor` just
materializes the already-pinned `Cargo.lock` so the netns-isolated container resolves without
a network round-trip). Keeping the mirror and the oracle binaries under `output/` (already
`**/output/` in `.gitignore`) holds the "local tools, never committed" rule for both the
oracle and its offline build material, and keeps the committed tree to source + scripts +
status only. A committed `.cargo/config.toml` would have leaked a host-specific path and
pinned a vendor tree into git review.
**Escalation:** operator — S4 build-mechanism local decision; re-derivable from `Cargo.lock`
on any box (`cargo vendor --locked output/vendor`). Not a spec issue.
