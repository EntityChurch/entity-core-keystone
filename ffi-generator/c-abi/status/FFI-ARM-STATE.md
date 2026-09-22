# ffi-generator / c-abi — state of the arm

**Measured 2026-09-04, §3 added 2026-09-07.** Run `ffi-generator/c-abi/run-ffi-gate.sh` for
current numbers; this file records what the numbers mean and what they do not cover.

## Where it stands

| | `entity-core-codec-ffi-c` | `entity-core-codec-ffi-rust` |
|---|---|---|
| Spec-declared symbols exported | **27 / 27** | **26 / 27** — `ec_entity_original_bytes` absent, which spec §4.1 declares OPTIONAL |
| Graded against architecture's ECF corpus | **71 / 71** | **no in-tree harness** |
| Encoder regression suite | **12 / 12** | — |
| Cross-impl differential (real `dlopen` boundary) | **101 / 101 probes**, over 19 of 27 symbols | same run |
| Leak on the per-request path (ASan/LSan, exported ABI only, valid + malformed input) | **0 records** | **0 bytes/pass** over 18 000 passes |
| Builds offline | **yes** | **no** — no vendored crate closure |

## The leak, and how it was verified

`libentitycore_codec` leaked an entire `ec_value` tree on every `ec_encode_ecf` and
`cc_content_hash` — both per-request — plus one tree per included entity in
`ec_envelope_find_signature_for` and the decoder's partial tree on **every malformed input**,
that last one reachable with bad bytes alone. Fixed in `f51cbb4`.

**Both instruments were validated against a control before their result was believed**, because
a leak detector that reports clean on a tree known to leak has measured nothing:

| instrument | pre-fix tree (control) | HEAD |
|---|---|---|
| ASan/LSan, exported ABI only | **141 leak records** | **0** |
| RSS growth, 20 000 passes | **5 552 bytes/pass** | **0.00 bytes/pass** |

`conformance/leak-probe-with-control.sh` reproduces both columns; it takes a source tree as an
argument so it can be pointed at the pre-fix tree. The gate itself runs only the HEAD column —
the control needs a tree the gate does not have — and the gate was separately proved to have
teeth by planting the removal of one `ev_free`, which produced **10 records** naming the exact
function and line.

**Do not read the shipped test binaries' ASan output as this measurement.** `regression_test`
and `conformance_harness` build `ec_value` trees directly and hold the corpus for the life of
the process, so they report leak records at HEAD that are the *harness's* and not the
library's. A peer never does that — it only ever crosses the exported `ec_*` surface, which is
what `conformance/abi_leak_probe.c` drives and nothing else.

## Three gaps, open

**1. The Rust impl has no independent corpus harness.** Its only verification is the
cross-impl differential, which is a **mutual** check: a defect both impls shared would pass it.
The C impl alone is graded against architecture's fixture. Its README documented
`./target/release/conformance_harness` and a **69/69** result; that binary has never existed in
this repository (`git log` finds no commit adding or removing it, the crate declares no
`[[bin]]`), so the number was unreproducible from a clone and has been withdrawn rather than
restated.

*Owed fix:* drive the corpus **through the ABI**, so one harness grades either impl against the
fixture instead of against its sibling. That also retires the asymmetry where one impl's grade
is architecture-authored and the other's is ours.

**2. The Rust impl has no vendored crate closure.** `cargo build --offline` cannot resolve; the
`kc-cargo` volume the README names is host-local and empty on a fresh machine. `Cargo.lock` is
committed and `--locked` is honored, so a **networked** build is reproducible — an air-gapped
one is not possible. This is the ratified class from `AGENTS.md` (dart, csharp, typescript,
ghc, python): *any image that vendors a dependency closure must derive it from the tree's own
lockfile*. Here nothing vendors it at all.

*Owed fix:* seed the closure into `containers/cargo` at image-build time from this crate's own
`Cargo.lock`, then re-resolve `--offline` inside the image build to prove the closure is
complete — an unsatisfiable lockfile should fail the IMAGE build, which is the right place.

**3. The two impls disagree about their FAILURE SET, and the spec declares none.**
Measured 2026-09-07, and this one is a live divergence rather than an absence.** The
differential's 101 probes drive **valid** input, so they are structurally silent about what
each impl does with input it refuses. Asked directly — `conformance/abi_failset_probe.c`,
both libraries `dlopen`ed side by side with the compare-a-lib-to-itself case asserted:

| `type` bytes | C | Rust | |
|---|---|---|---|
| `primitive/bytes` (ascii) | `EC_OK` | `EC_OK` | agree |
| empty | `EC_OK` | `EC_OK` | agree |
| `ff fe` (invalid UTF-8) | `EC_OK` | `EC_INVALID_ARGUMENT` | **diverge** |
| `80` (lone continuation) | `EC_OK` | `EC_INVALID_ARGUMENT` | **diverge** |
| `c3` (truncated 2-byte) | `EC_OK` | `EC_INVALID_ARGUMENT` | **diverge** |
| `c0 80` (overlong) | `EC_OK` | `EC_INVALID_ARGUMENT` | **diverge** |
| `ed a0 80` (UTF-16 surrogate) | `EC_OK` | `EC_INVALID_ARGUMENT` | **diverge** |
| `a\0b` (embedded NUL) | `EC_OK` | `EC_OK` | agree |

**5 of 8.** Rust's `ec_content_hash` runs `str::from_utf8` on `type` and refuses; C hashes the
bytes as-is. Rust additionally maps a caught panic to `EC_INTERNAL_ERROR`, which C has no
analogue for. **Spec §4.1's table declares a behaviour for `ec_content_hash` and no failure
set at all**, so neither impl is violating anything written down — which is the finding.

**Why it matters more than an ordinary divergence: `type` is attacker-controlled wire bytes.**
On §6.3's `put` admission path a submitted entity's `type` is a CBOR major-3 head, and CBOR does
not enforce that a text string's bytes are valid UTF-8. So the same submission is hashed by one
impl and refused by the other, and a consumer that does not check the return code compares an
**unwritten** output buffer and answers `400 hash_mismatch` — a codec refusal stated as an
accusation about the submitter's bytes. Found because `asm-x86_64`'s native codec had exactly
that unchecked-return shape; the three ISA peers now check it, but **the audit of the other
codec consumers has not been done.**

**Not resolved here, deliberately.** Picking a winner is a behaviour change for 34 linking
peers and it is a genuine design question, not a bug to patch: RFC 8949 requires major-3 to be
UTF-8, so Rust's refusal is arguably the more correct of the two, and the C impl silently
produces a content hash over a byte sequence that is not valid canonical CBOR. Whichever way it
goes, §4.1 must **declare the failure set** so the next impl is not a third opinion.

*Owed:* (a) settle and specify `ec_content_hash`'s failure set in `spec/ENTITY-CODEC-C-ABI-V1.md`
§4.1; (b) extend the differential to drive **refusal** inputs, not only valid ones, so a
failure-set divergence cannot pass a green run again; (c) audit the remaining codec consumers
for the unchecked-return-code shape.

## One thing that is NOT a defect, recorded so it is not "fixed" twice

`ec_entity_original_bytes` is exported by C and absent from Rust. **Spec §4.1 says MAY /
OPTIONAL, so Rust is conformant.** It is still a footgun — the two ship the same soname and
artifact name and are advertised as drop-in interchangeable, so a consumer that links one and
swaps the other gets an unresolved symbol — and no peer in the tree calls it. The differential
now **reports** the asymmetry instead of being silent about it, and does not fail on it.

Note also that the two disagree on what the function *means*: C validates a tag-free canonical
**value**, Rust's sibling `ec_decode_entity` requires the `{type,data}` **entity** shape, and
the header calls this function "sugar" for `ec_decode_entity`. If it is ever made mandatory,
settle the semantics first — implementing it in Rust against the header's wording would create
a live divergence on non-entity input where today there is only an absence.

## Why this arm now has a runner

`tools/run-axis-sweep.sh` sweeps the per-peer verification axes across `protocol-generator/*`.
This arm is not peer-scoped, so it was in **no sweep and no `make lint` gate** — while 34 peers
link the artifact it builds. The leak survived months on the per-request path of every consumer
and was found by accident, while measuring an unrelated peer's capacity work. That is the
standing rule — *an axis with a per-peer harness and no cohort runner is one nobody is
measuring* — applied to a whole arm. `run-ffi-gate.sh` is the fix, and the arm is listed in
`run-axis-sweep.sh --list` so the inventory is complete even though the runner is separate.

## Propagation: a fix in this arm did not reach its consumers

Nine peers declared the codec `.so` as a **bare make file target** — no prerequisites — so the
recipe ran only when the file was *absent*. Three of the nine were measurably linking a
pre-fix codec: `asm-arm64` and `riscv64` against cross-builds dated 2026-07-15 (confirmed by
symbol, `nm`: no `ev_free`, not by mtime alone) and `io` against a peer-local copy dated
2026-07-27. Three of the nine even said `if absent` in the comment above the rule.

Fixed by giving the target its real prerequisites, **derived with `find`** rather than
hand-listed — a literal file list is a second copy of the dependency graph, and a second copy
drifts. cmake still does the incremental work; make's job is only to decide whether to call it.
Both directions were exercised: touch a codec source → all nine rebuild; leave it current →
all nine report `Nothing to be done`. All three stale peers were rebuilt and **re-measured**,
and each reproduced its committed row at the pinned check set — `asm-arm64` and `riscv64` with
**0 of 758 severities different**, `io` with **1 of 758**, that one being the
`concurrency/t1_1_concurrent_demux` timing flake already documented in `CONFORMANCE-MATRIX.md`.
It moved in the favourable direction (WARN → PASS) and the tracked report was therefore **left
alone**: a single sample is not a rate, and banking a number that went the right way is exactly
when that rule matters.
