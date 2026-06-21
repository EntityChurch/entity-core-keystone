# entity-core-protocol-c — Conformance Report

**Peer #10** (C / C11 / POSIX, procedural / manual-memory /
return-code idiom) · **Phases S2 (codec) + S4 (conformance)** · **Status: 🟢 GREEN —
`validate-peer --profile core` PASS, 0 FAIL @ the TRUE v7.75 cohort baseline `b30a589`
(576 · 0F · 89S, `resource_bounds` 2P+1W active); also 0 FAIL @ `62044c5` subset (574 · 0F ·
90S) and `7e5ab04` superset (631 · 0F · 92S).**

---

## S4 — `validate-peer --profile core` → **PASS** (576 · 0 FAIL) @ TRUE cohort baseline `b30a589`

```
576 total · 291 passed · 196 warned · 0 FAILED · 89 skipped → Result: PASS
```

**HEADLINE certification — cohort-comparable, resource_bounds active.** Machine-verified:
`CONFORMANCE-REPORT.json` → `summary.failed == 0`. Peer ID
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (byte-identical to the cohort; unchanged
across all three oracle runs — this was an **oracle swap only**, the peer was NOT rebuilt or
modified).

**Provenance correction (⚑ surface to mainline/arch).** The 9-peer cohort scorecard records
its v7.75 oracle as **`62044c5`** (576·0F·89S, resource_bounds PASS), but that is
**off-by-one-commit**: `62044c5`'s `cmd/internal/validate/profile.go`
`coreProfileCategories` has `catConcurrency: true` but **NOT** `catResourceBounds`, so
`resource_bounds` SKIPs under `--profile core` there (→ 574, exactly what this peer scored).
The next commit **`b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds
enumerated") adds `catResourceBounds: true` → `resource_bounds` becomes ACTIVE in core →
**576·0F·89S**, the actual recorded cohort number. So `b30a589` is the true v7.75 oracle and
yields the recorded figure; the scorecard's "62044c5" is a label off-by-one. See A-C-008 /
SPEC-AMBIGUITY-LOG.

**Live count is 576 · 0 FAIL · 89 skip** — matching the recorded cohort figure exactly
(machine-verified, NOT assumed). The decisive difference vs `62044c5`: `resource_bounds` is
now an **ACTIVE** category (0 in-category skip), scoring **r1 `413 payload_too_large` PASS ·
r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN** (§4.10(c) external-admission
SHOULD carve-out). The C peer's own surface is identical across all three oracles (108
`type_system` PASS, 5 `concurrency` PASS, §1.4 universal_address_space register 8/8,
**0 FAIL** everywhere).

**Command:** `./run-s4.sh` → `validate-peer -addr 127.0.0.1:7777 -profile core -json-out
status/CONFORMANCE-REPORT.json`, run sealed-offline (`--network=none`) in
`entity-core-keystone/c-toolchain:latest`; the Go ELF + the C host share one loopback.

**Oracle provenance.** `output/s4-oracles/{validate-peer,entity-peer}` (the certification
oracle) built `CGO_ENABLED=0 / GOWORK=off` from a **read-only `git archive` extract** of the
READ-ONLY `entity-core-go` source at the TRUE cohort baseline
**`b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds enumerated").
The oracle tree was never checked-out/stashed/cleaned (`git archive | tar -x` is read-only).
Verified at the binary's **live behavior** that `resource_bounds` is now ACTIVE under
`--profile core` (2 PASS + 1 WARN, 0 SKIP — the `catResourceBounds: true` fold) rather than
a SKIP. The earlier oracle binaries are retained alongside as
`output/s4-oracles/{validate-peer,entity-peer}.62044c5` (574 subset) and `*.7e5ab04` (631
superset).

**Additional evidence — `62044c5` subset (574 · 0 FAIL · 90 skip) and `7e5ab04` superset
(631 · 0 FAIL · 92 skip).** The same unchanged peer is PASS at both the `62044c5` subset
(`resource_bounds` not-yet-in-core, single SKIP placeholder → 574) and the later
`7e5ab0428a63eb78b981a2000a90e5d4c85e7c79` superset (631). `b30a589` sits check-wise between
them (it adds exactly the resource_bounds 2P+1W rows on top of 574-style inventory).
**0 FAIL at the 574 subset, the 576 cohort baseline, AND the 631 superset →
conformance-safe** (the Java-peer precedent: 0-FAIL at subset and superset means no
conformance category is dodged by the smaller inventory).

### Core-profile scoreboard (live @ `b30a589`)

| Category | P | W | F | S | Note |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | **0** | 0 | §4.1 handshake (incl. F12 cross-conn replay — CSPRNG nonce) |
| encoding | 6 | 0 | **0** | 0 | ECF wire |
| type_system | 108 | 194 | **0** | 0 | **53/53 §9.5 floor byte-identical**; 194 WARN = non-floor (matched-if-present); 52 fewer non-floor WARN rows than `7e5ab04` |
| handlers | 35 | 0 | **0** | 32 | core get/put/connect/capability/type + operations-match; ext handlers auto-skip; **§10.1 register gate 10/10** (`core_register_*`) |
| capability | 12 | 0 | **0** | 0 | §6.2 mint/delegate(501 remote)/revoke |
| tree_operations | 24 | 1 | **0** | 31 | core get/put + §1.4 R1 path validation; EXTENSION-TREE §9 ops auto-skip |
| security | 28 | 0 | **0** | 1 | §5 capability/signature chain |
| multisig | 10 | 0 | **0** | 0 | §PR-8 multi-granter |
| authz | 6 | 0 | **0** | 2 | §A4-AUTHZ codes; ROLE-ext skips carved out |
| **concurrency** | **5** | 0 | **0** | 0 | **§7b — all 5 PASS** (atomic refcount, A-C-009); gates core at this oracle |
| **resource_bounds** | **2** | **1** | **0** | 0 | **ACTIVE at `b30a589`** (`catResourceBounds: true`): r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (§4.10(c) SHOULD); was a single SKIP at `62044c5` |
| universal_address_space | 8 | 0 | **0** | 0 | §1.4 peer-relative ≡ absolute round-trip |
| peer_canonicalization | 7 | 0 | **0** | 0 | §1.5 v7.65 |
| negotiation | 4 | 0 | **0** | 0 | §4.5 disjoint hash_format/key_type reject |
| crypto_agility / format_agility | 4 / 10 | 0 | **0** | 0 | §4.7 surfaces (Ed25519/SHA-256 floor) |
| (extension categories) | 0 | 0 | 0 | ~rest | auto-allowlisted §9.0 carve-outs |
| **Total** | **291** | **196** | **0** | **89** | **Result: PASS** |

No FAIL is disguised as a SKIP; the 89 skips are §9.0 extension carve-outs the oracle
auto-allowlists, the 196 warns are non-§9.5-floor type vocabulary + the resource_bounds r3
SHOULD. (At the `62044c5` subset the totals read 289P/195W/0F/90S = 574 — resource_bounds a
single SKIP; at the `7e5ab04` superset 291P/248W/0F/92S = 631 — same 0-FAIL surface, larger
check-set.)

### origination-core 3/3 (`run-origination-core.sh`)

```
[origination]  PASS reference_connect · PASS reference_ready · PASS dispatch_outbound_reentry
Result: PASS (3 total, 3 passed, 0 failed)
```

The §6.11 reentry seam wire-proven over real two-peer TCP against the **`b30a589`** Go
`entity-peer -open-access` reference: the C target originates an outbound EXECUTE back to the
validator-as-B over the SAME inbound connection. dispatch-outbound is a **generic relay**
(forwards `{value: X}` verbatim, returns the downstream result entity verbatim). (Re-run at
the cohort baseline; identical 3/3 to the earlier `62044c5`/`7e5ab04`-reference runs.)

### §9.5 53-type floor — 53/53 byte-identical

Rendered from `src/core_typedefs.c` (generated by `tools/gen-typedefs.py` from the shared
cross-impl `type-registry-shapes.json`); each content_hash computed by THIS peer's own
S2-green codec. Diffed **53/53 byte-identical** against `type-registry-vectors-v1` by
`make typereg` (peer-side dual of the S2 corpus) AND independently confirmed by the live
oracle's `type_system` checks (108 PASS / 0 FAIL).

### The grind: 31 → 0 FAIL (3 oracle runs)

1. **Run 1** 31 FAIL → **22 were one crash cascade**: a `heap-use-after-free in
   ec_entity_ref` under the `concurrency` C×K load (plain-int refcount raced across the
   per-EXECUTE dispatch threads). Fix: `refcount → atomic_int` (A-C-009) — the C peer's
   net-new §4.8 datapoint.
2. **Run 2** 9 FAIL (cascade gone) → fixed: clock-nonce replay (F12, CSPRNG; A-C-010),
   empty handler operations-maps, §1.4 path validation (`//` + embedded-NUL), delegate-501
   ordering, §4.5 disjoint negotiation reject (A-C-011).
3. **Run 3** **631 · 291P/248W/0F/92S → PASS** (vs the `7e5ab04` superset oracle). The
   unchanged peer was then re-run against the `62044c5` subset oracle (**574 ·
   289P/195W/0F/90S → PASS**, resource_bounds a single SKIP) and, finally, against the
   **TRUE cohort baseline `b30a589`** (resource_bounds folded into core via
   `catResourceBounds: true`): **576 · 291P/196W/0F/89S → PASS** — the headline
   cohort-comparable certification, resource_bounds 2P+1W active.

All fixes were derived spec-first from V7 + the cohort — the oracle, vectors, and harness
were never doctored. Regression: S3 smoke 11/11 + S2 corpus 82/82 + typereg 53/53, all
ASan/LSan/UBSan-clean, `-Werror` clean.

### Reproduce

```sh
# 1. build the oracle ELFs from a READ-ONLY archive of the TRUE cohort baseline commit
#    (b30a589 = the commit that folds catResourceBounds:true into coreProfileCategories):
git -C $REPO/entity-core-go archive b30a589 | tar -x -C $BUILD
podman run --rm -v $BUILD:/go-src:Z -v $WT/output/s4-oracles:/out:Z \
  -e GOWORK=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
  localhost/entity-core-keystone/go:latest \
  bash -c 'cd /go-src/cmd && go build -o /out/validate-peer ./validate-peer && go build -o /out/entity-peer ./entity-peer'

# 2. drive the peer (sealed offline, oracle ELF in the c container):
./protocol-generator/c/run-s4.sh                  # the --profile core gate
./protocol-generator/c/run-origination-core.sh    # the §6.11 reentry 3/3
```

Raw JSON: `status/CONFORMANCE-REPORT.json` (`summary.failed == 0`). Full phase narrative:
`status/PHASE-S4.md`.

---

# entity-core-protocol-c — Conformance Report (S2 codec)

**Phase S2 (codec)** · **Status: 🟢 GREEN — 69/69 wire-conformance, byte-identical,
ASan/LSan/UBSan-clean.**

---

## S2 — codec layer · `wire-conformance` corpus

| Corpus | Vendored version | Result |
|---|---|---|
| **ECF codec** (`conformance-vectors-v1.cbor`) | v7.71 (byte-identical to v7.56/v7.70); sha256 `41d68d2d…6a052` (verified against MANIFEST) | **69/69 PASS, byte-identical, 0 fixes after the base58 bug was fixed** |
| **Self-tests** (uncovered-range + KAT) | — | **13/13 PASS** (uint64 range, float ladder, N1/N2, base58 round-trip, peer_id §1.5, Ed25519 RFC-8032 TEST-1 pubkey + sign/verify/tamper) |

```
== ECF conformance: 69/69 PASS, 0 FAIL ==
== TOTAL: 82 pass, 0 fail ==
```

Run in-container, sealed-offline (`--network=none`) via `./run-s2.sh`
(`make clean && make test`) — builds + runs the hand-rolled C harness
(`test/conformance.c`) under **AddressSanitizer + LeakSanitizer + UBSan** (an
un-freed alloc, use-after-free, overflow, or UB is a TEST FAILURE — the C peer's
manual-memory conformance bonus). Image
`entity-core-keystone/c-toolchain:latest` (rebuilt this phase: gcc-15.2.1-7.fc43,
make-4.4.1, libsodium-1.0.22-1.fc43 static+devel, **+libasan-15.2.1-7.fc43 /
libubsan-15.2.1-7.fc43** added at S2 — see PHASE-S2 "Container").

## Oracle / fixture provenance (what `wire-conformance` is here)

`wire-conformance` is a fixture **producer + cross-blesser**, NOT a runtime
checker — its `build-fixture` / `emit-canonical` subcommands (Go
`cmd/internal/wire-conformance/`) emit the `conformance-vectors-v1.cbor` file,
whose every `encode_equal` `canonical` field is the 3-way **Go × Rust × Python
byte-equality lock** (71/71 PASS; arch `specs/test-vectors/
ecf-conformance/` commit **`23db2546`**, recorded in the v7.71 MANIFEST). The C
harness **decodes that fixture with THIS peer's OWN decoder** (a decoder bug is
itself a conformance failure per ENTITY-CBOR-ENCODING.md §E.3), runs every vector
through the codec, and byte-compares against the embedded `canonical`.
Byte-identity to the fixture == oracle PASS. (Same self-contained mechanism the
C# / TS / OCaml / Elixir / Zig / Common-Lisp / Java peers used.)

**Go oracle state (recorded per the S2 vendoring mandate):** the read-only Go
oracle `~/projects/entity-systems/entity-core-go` is **clean** (0 uncommitted) at
HEAD **`7e5ab0428a63eb78b981a2000a90e5d4c85e7c79`** (`7e5ab04`, "RELAY cohort
handoff"). The handoff prompt cited HEAD `0d48de6` as clean — that commit is now
the **direct parent** of `7e5ab04`; the newer commit is an EXTENSION-RELAY
handoff that does **not** touch the `core/ecf` or `wire-conformance` codec path
(the codec corpus is byte-stable across the whole v7.56→v7.71→v7.75 window). The
fixture's producer lineage is the arch byte-lock `23db2546` above, not the live
Go HEAD; both are recorded for traceability. We did **not** rebuild the Go binary
— the vendored fixture IS the oracle output (self-contained harness), so no
on-the-fly Go build was needed.

**Free cross-check (independent of the fixture):** the Go `wire-conformance`
`canonical.go` sorts map keys by `bytes.Compare` on the **encoded** key bytes
(pure bytewise on the encoded octets). For ECF text/byte keys this is
**equivalent** to the length-first-then-lexicographic (CTAP2) rule this peer
implements, because the CBOR head byte already encodes the key length (so `"z"`
encoded `617a` sorts before `"aa"` encoded `626161` under both rules). The C
encoder reproduces every map-ordering vector (map_keys.1–6, incl. the mixed
text/byte map_keys.5) byte-for-byte, confirming the equivalence.

## ECF corpus — 69/69 (the 10th independent native ECF codec)

**Tenth** independent native ECF codec to reach 69/69 byte-identical (after C# /
TS / OCaml / Elixir / Zig / Common-Lisp / Swift / Haskell / Java — S8/S9
convergence holds; the procedural / manual-memory / return-code idiom converges
with the GC'd and functional ones). Hand-rolled canonical encoder (grow-on-demand
byte buffer) + index-walk decoder (`src/ecf.c`, encode+decode in one translation
unit), plus LEB128 varint (`src/varint.c`), base58 (`src/base58.c`), content-hash
(`src/content_hash.c`), peer-id (`src/peer_id.c`), and Ed25519 + SHA-256 via
libsodium (`src/crypto.c`).

| Category | n | Notes |
|---|---|---|
| `float` | 14 | shortest-float ladder (f16/f32/f64) + Rule-4a specials. Exact IEEE bits via `memcpy(&u, &f, …)` (no strict-aliasing UB); f16 via pure-integer mantissa/exponent test (low-42-bits-zero for normals; integer-scaled-in-[1,1023] for subnormals); -0.0 → `f98000`. |
| `int` | 14 | major-0/1 minimization. **Full uint64 / -2^64 head-form via NATIVE `uint64_t`** — C's native unsigned (the cleanest int story alongside Zig; no `ulong`/int63 special-casing). nint carried as (negative flag, argument). |
| `map_keys` | 6 | length-first then byte-lexicographic on encoded key bytes (ECF Rule 2 / §3.5); mixed text/byte keys. `qsort` with a length-then-`memcmp` comparator (guarded for n≤1 and 0-length keys — UBSan-clean). |
| `length` | 8 | definite-length only; **N3** empty-map = `0xA0` (falls out of the generic map encoder, not special-cased). |
| `primitive` | 6 | bool/null/empty containers (distinct EC_BOOL / EC_NULL / EC_FLOAT_* nodes keep absent ≠ null ≠ false). |
| `nested` | 4 | entity + envelope carrier shapes. |
| `tag_reject` | 5 | **N2** — recursive major-type-6 rejection at any depth, incl. nested in `included` entity data and the bare tag-55799 wire frame; the decoder returns `EC_ERR_TAG_REJECTED` from the major-type dispatch (no library default trusted — there is no library). |
| `content_hash` | 4 | `varint(format_code) ‖ SHA-256(ECF({type,data}))`; **N1** multi-byte varint prefix (synthetic 0x80 → `80 01`, content_hash.4). |
| `peer_id` | 3 | `CBOR-text(Base58(varint(kt) ‖ varint(ht) ‖ digest))`; N1 multi-byte key_type (128). |
| `signature` | 3 | deterministic Ed25519 over canonical ECF, libsodium `crypto_sign_detached`. |
| `envelope` | 2 | full `{root, included}` ECF under the map-key rules. |

(64 `encode_equal` + 5 `decode_reject` = 69 testable; the 2 meta entries carry no
`kind` and are skipped, not counted — same accounting as the cohort's 69/69.)

## Conformance invariants (N1–N4) — enforced + covered

| Invariant | How (file) | Covering vectors |
|---|---|---|
| **N1** LEB128 varints | `src/varint.c` — every format-code / key-type / hash-type prefix routed through `ec_varint_encode`/`ec_varint_decode` (with non-minimal-trailing-zero rejection on decode) | `content_hash.4` (fc 128 → `80 01`), `peer_id.3` (kt 128), selftest `varint128` |
| **N2** tag rejection | `src/ecf.c` `dec_value` major-6 → `EC_ERR_TAG_REJECTED` at any depth | `tag_reject.1–5` (incl. nested-in-included + bare 55799), selftest `bare_tag` |
| **N3** empty-map `0xA0` | generic map encoder with 0 entries (`enc_head(b,5,0)` → `0xA0`) | `length.2` (`{}` → `a0`), `content_hash.1` (empty-data boundary, full-entity hash `005f3139…0ca396b`) |
| **N4** entity fidelity | the decoder is structural and copies byte/text payloads into owned nodes; major-2 (bytes) ≠ major-3 (text) are distinct kinds; the content_hash/signature paths re-encode `{type,data}` canonically from the SAME node tree the corpus supplied (no lossy round-trip). The peer-layer zero-copy borrow (forward original bytes) is an S3 refinement; at S2 the decode→encode round-trip is identity for canonical input (selftest `mixed_map` / `neg_zero`). | round-trip selftests |

## Crypto — libsodium (Ed25519 + SHA-256), the one runtime dep

- **Ed25519** RFC-8032 deterministic detached sign/verify via
  `crypto_sign_seed_keypair` / `crypto_sign_detached` / `crypto_sign_verify_detached`;
  the **all-zero-seed → RFC-8032 TEST-1 public key** KAT passes
  (`3b6a27bc…59da29`), and sign→verify→tamper-reject passes. The 3 `signature.*`
  corpus vectors (deterministic seeds over canonical-ECF-encoded entities) are
  byte-identical.
- **SHA-256** via `crypto_hash_sha256` — the content_hash digest; content_hash.1–4
  byte-identical.
- **Ed448 / SHA-384** agility is **DEFERRED** (A-C-001) — libsodium has no Ed448.
  The §9.1 floor (Ed25519 + SHA-256) is fully native and is the only path the S2
  corpus exercises. The `agility-vectors-v1.cbor` set is gated on A-C-001 and is
  NOT run here.

## Memory correctness (the manual-memory conformance bonus)

The harness is built `-fsanitize=address,undefined` and run with
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`. The full run
(fixture decode of ~10 KB → 69 vectors → 13 self-tests, all allocating + freeing
node trees, encode buffers, base58 buffers, and digests) reports **0 ASan
errors, 0 LSan leaks, 0 UBSan findings**. Two real defects were caught by the
sanitizer/byte gate during bring-up (both fixed — see PHASE-S2 "The grind"):

1. **UBSan** flagged `qsort(NULL, 0, …)` (and a latent 0-length-key `memcmp`) —
   fixed by guarding `qsort` for n≤1 and the comparator for 0-length keys.
2. The **byte gate** caught a base58 long-division bug (wrong `high`/break
   tracking truncated the digit stream) — peer_id.1–3 were wrong; fixed by the
   standard backward-walk multiply/divide with an explicit running `length`.

## Exit criteria

69/69 corpus byte-identical · 13/13 self-tests (incl. Ed25519 RFC-8032 KAT) ·
`make` compiles clean under `-std=c11 -pedantic -Wall -Wextra -Werror` (no
warnings) · ASan/LSan/UBSan clean · `.a` + `.so` + harness build · only `ec_*`
symbols exported (`-fvisibility=hidden`, nm-verified) · ambiguity log has no
blocking codec items · container reproducible + offline. **S2 PASS.**
