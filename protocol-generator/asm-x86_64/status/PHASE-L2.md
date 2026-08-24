# PHASE-L2 — native canonical codec (asm-x86_64, Level 2)

**Level 2** (ISA-MAP Axis B / matrix point 2): hand-roll the canonical **entity ECF codec**
in x86-64 asm, keeping only Ed25519 + SHA-256 behind the FFI. The *discovery bet* of the asm
family — "can the canonical-CBOR N1–N4 invariants be expressed in asm and stay byte-exact?"
(L1 answered the easier "control-flow on bare metal"). Cross-checked **differentially**
against the 3-way-locked (Go×Rust×Python) conformance corpus, not just self-consistency.

## Milestone 1 — canonical transcoder — GREEN (61/61)

`src/codec.s` implements the C-ABI F6 hook `ec_encode_bare_value` (the "Class-A encoder
core" reachable across the ABI for exactly this differential) as a recursive-descent
**transcoder**: read one CBOR value, re-derive its canonical form from the decoded value, and
re-emit. Covers:

- **Integer / length minimization** (RFC 8949 Rule 1): shortest `0x18/19/1a/1b` head.
- **Shortest-float ladder** (Rule 4 / 4a): f16→f32→f64 by round-trip-exactness, with
  NaN→`f97e00`, ±Inf→`f97c00`/`f9fc00`, ±0→`f9(80)00`, and the f16/f32 boundary
  (65504→f16 `f97bff`, 65503→f32 `fa477fdf00`). Hand-rolled f16↔f64 (no F16C dependency).
- **Definite-length only** (Rule 3) — indefinite heads (ai 31) rejected at decode.
- **Recursive major-type-6 tag REJECT** (N2): any tag at any nesting depth →
  `EC_DECODE_ERROR`. The transcoder's own recursion *is* the recursive scanner.
- Primitives (false/true/null/undefined), arrays, maps, byte/text strings, nesting.

**Result:** `make diff` → **61 PASS / 0 FAIL** vs the pinned corpus golden bytes
(`tools/diff-harness.c` + host-generated `tools/corpus_vectors.h` from the `.diag`).
Categories: float 14, int 14, map_keys 6, length 8, primitive 6, nested 6, envelope 2,
tag_reject 5. The 10 Class-B crypto vectors (content_hash 4, peer_id 3, signature 3) are the
M2 surface (below). The shortest-float ladder — the hardest canonical primitive — assembled
green on the first build.

**Reproduce:** `make diff` in `containers/asm-x86_64-toolchain` (offline). `codec.s` is a
standalone native codec (no libc, no FFI) linked directly into the C harness; it is **not**
in `HOST_OBJS`, so the shipped L1 peer (`make host`) is untouched and still builds green.

## Milestone 2 — full ECF corpus + key-sort — GREEN (71/71 corpus + 4 synthetic)

The native codec now covers the **entire** ECF conformance corpus, crypto-only FFI:

- **Key-sort** — genuine length-then-lex map key ordering (selection sort over scanned
  pair/key spans in `.tc_map`). Proven by 4 synthetic **unsorted→canonical** vectors (the
  corpus can't, being pre-sorted) AND by content_hash.3 / signature.2 (unsorted data whose
  golden depends on the sorted encoding). Closes the A-ASM-015 vacuous-green gap.
- **content_hash** (4) — `ec_content_hash{,_with_format}` = native canonical ECF (`build_ecf`,
  sorted) + FFI `ec_sha256`; the multi-byte LEB128 format prefix (content_hash.4, fmt=128).
- **peer_id** (3) — `ec_peerid_format` = native base58 (Bitcoin alphabet, byte-carry) +
  LEB128 varint; multi-byte varint key_type (peer_id.3, kt=128).
- **signature** (3) — native `ec_encode_ecf` (sorted) + FFI `ec_ed25519_sign`. **Finding
  (A-ASM-018):** the corpus signs the entity's **ECF bytes**, not its content_hash (≠ §7.3).

**Result:** `make diff` → **71 corpus + 4 synthetic, 0 FAIL**. **Symbol-verified non-vacuous**
(A-ASM-017): `nm bin/diff` shows `ec_content_hash`/`ec_encode_ecf`/`ec_peerid_format`/
`ec_encode_bare_value` as **T** (our .o), only `ec_sha256`/`ec_ed25519_sign` as **U** (FFI).

## Milestone 3 — peer integration — GREEN (682·0F, live-oracle)

The native codec is now **linked into the live peer** and the peer re-passes the conformance
oracle with the canonical codec provided by asm (only crypto still FFI). This is the point L2
becomes a *shipped peer*, not a codec-differential milestone — it earns the CONFORMANCE-MATRIX
row.

- **Integration surface was small** (the handoff's finding held): the peer's only FFI codec
  calls are `ec_content_hash` (×27), `ec_peerid_format` (×2), `ec_peerid_parse` (×1) — all now
  native — plus the three `ec_ed25519_*` (stay FFI). The peer hand-rolls its envelope/data-map
  CBOR via `cbor.s`, so it never calls `ec_encode_ecf`/`ec_decode_entity`; no arena/N4 decode
  work was needed for M3.
- **`ec_peerid_parse`** — the one function written this milestone (`codec.s`): base58 **decode**
  (byte-carry bignum, invalid-char reject) + LEB128 decode of the two leading varints; remainder
  is the digest. Mirrors the C-ABI reference (`base58.c`/`codec.c`) incl. return codes
  (`0`/`-1`/`-8`). Used by the §4.4/§7.1 hello key-type agility check in `dispatch.s`.
- **Link mechanic:** `$(OBJ)/codec.o` prepended to `HOST_OBJS`, ahead of `-lentitycore_codec`,
  so our native symbols win; the `.so` still supplies `ec_sha256` + `ec_ed25519_*` (which our
  `ec_content_hash` calls internally). Same override mechanic verified in `make diff`.

**Result:** `run-s4.sh --profile core` → **682 total · 583 P · 3 W · 0 F · 96 S** (Result: PASS)
@ oracle `cc1970f` — identical pass count to L1 (same canonical bytes; only the *provider*
changed from FFI to native asm). **Symbol-verified** (`nm bin/host`): `ec_content_hash` /
`ec_peerid_format` / `ec_peerid_parse` / `ec_encode_bare_value` / `ec_encode_ecf` = **T** (ours);
`ec_sha256` / `ec_ed25519_{sign,verify,seed_to_pubkey}` = **U** (FFI). The L2 boundary is exactly
"canonical codec native, crypto FFI".

- **Parse accept-path unit (`make parse-test`, `tools/peerid-parse-test.c`):** the corpus has no
  peer-id *parse* vector (peer_id.N are `encode_equal` only), so the decode accept-path would be
  oracle-invisible. Drives it 3 ways — format→parse round-trip (6, incl. multi-byte varints,
  empty/short digest), known peer_id.N string→(kt,ht,digest) (3), reject paths (bad char / NULL)
  (2) → **11 P / 0 F**. Closes the "conformance-green can be vacuous" gap on the parse direction.

## Honesty (ADR-0012) — what M1 does and does NOT prove

- **Proves:** shortest-float ladder, integer/length minimization, definite-length,
  recursive tag-reject — byte-exact in asm, against an independent 3-way-locked corpus.
  This is **corroboration** (a fourth transcode of the same canonical rules), and a genuine
  substrate result: the canonical layer L1 hid behind the FFI is asm-expressible.
- **Does NOT prove (A-ASM-015):** length-then-lex **map key sorting**. The F6 differential is
  identity-on-canonical-input; the corpus `map_keys` inputs are pre-sorted, so M1 emits map
  entries in input order and passes them **vacuously**. M1 makes no canonical-sort claim.
  The sort is load-bearing in the real ECF encoder and is proven at `content_hash.3`
  (unsorted data map, hash over canonical form) — that is M2, not a bolt-on to the test hook.
- **Gap (A-ASM-016):** f16 subnormal *input* decode rejects rather than normalizes (no corpus
  vector; fail-safe). M1b + synthetic vector.

## Next

- **M1 / M2 / M3 — DONE** (see above). L2 is a live, oracle-gated peer with a native canonical
  codec and only Ed25519 + SHA-256 behind the FFI; CONFORMANCE-MATRIX carries the L2 row.
  **The asm probe's discovery arc is complete** — L2 answered the real bet ("can asm express
  canonical CBOR byte-exact?" → yes); everything past here is corroboration, not new findings.
- **L3 — DEFERRED indefinitely (2026-07-15 decision).** Hand-writing SHA-256 + Ed25519 in asm is
  (a) **per-ISA** so it does *not* enable ports (the "L3 unblocks riscv" claim was backwards),
  (b) the **KAT-owned crypto boundary the methodology deliberately doesn't hand-author**
  (Ed25519 field arithmetic = carry/constant-time blast radius), (c) **~zero discovery value**.
  Crypto stays **linked-compiled** (FFI / a self-contained ref lib for foreign arches). Full
  rationale in `arch/OPTIONS-AND-ISA-MAP.md` matrix point 5. Revisit only as a deliberate
  bare-metal exercise, never on the critical path.
- **RISC-V L1 — the one remaining optional item** (portfolio "third ISA", not new signal). The
  earlier "blocked" call was a Fedora-secondary-arch packaging gap, not a riscv problem: a
  first-class riscv64 distro (Debian/Ubuntu) under `qemu-riscv64-static` ships libsodium and
  builds natively — no cross-sysroot, **no crypto, no L3**. See ISA-MAP point 4. Next session.
- **Deferred codec polish (not peer-gated, no live-frame exercises them):** f16-subnormal
  *input* decode (A-ASM-016), the >32-key map-sort cap, and `ec_decode_entity` with the
  arena/N4 original-byte contract (the peer hand-rolls its CBOR via `cbor.s`, so it never
  needs the ABI decode entry — pick it up only if a future consumer does).
