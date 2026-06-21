# COBOL feasibility spike — findings & GO/NO-GO

**Decision D2** (`research/RELEASE-READINESS.md §5`): before committing to a COBOL
peer build, run a throwaway spike answering four go/no-go questions. A "no" on any
is itself a finding. This is that spike.

**Verdict: GO.** All four feasibility questions clear. GnuCOBOL 3.2 can carry a
core protocol peer over an FFI-everything strategy. The one genuine *discovery*
question (the decimal-first numeric model vs the uint64 integer head-form) is
answered with a concrete, navigable carrier pattern — and it sharpens an existing
spec candidate (see Finding D below).

**Toolchain:** `containers/cobol-toolchain/` (GnuCOBOL `cobc 3.2.0`, fedora:43,
S11-pinned `gnucobol-3.2-8.fc43`). Spike sources +
`run-spike.sh` in this dir. Reproduce: `./run-spike.sh`.

---

## The four probes (all PASS)

| Probe | Question | Result |
|:-:|---|---|
| **P1** | Can GnuCOBOL recurse with correct per-frame state? (§5.5 chain-walk, §6.3 recursive tag-reject) | **PASS** |
| **P2** | Can it carry variable-length CBOR byte streams vs PIC fixed-width? | **PASS** |
| **P3** | Does the COMP-3/decimal/PIC numeric model fight the uint64 integer head-form? | **PASS** (trap real but carried) |
| **P4** | C-ABI FFI ergonomics — a real codec symbol, byte-exact? | **PASS** (`ec_sha256("abc")` byte-identical) |

---

## Finding A — recursion: YES, but it MUST use LOCAL-STORAGE

GnuCOBOL supports recursion via `PROGRAM-ID. name RECURSIVE` and self-`CALL` by
literal name. **The trap:** `WORKING-STORAGE` is *static* — shared across every
recursive invocation — so a naive recursive program corrupts its own frame state.
Genuine recursion requires `LOCAL-STORAGE SECTION` for any per-frame value. P1
proves it: `factorial(10) = 3628800` with the frame's `n` snapshot surviving the
recursive call intact.

**Implication for the peer:** the capability chain-walk and the recursive
tag/nesting reject both live in `RECURSIVE` programs with `LOCAL-STORAGE` for the
working set. Cheap and idiomatic; no blocker. (Note `-x` makes the *first*
program the entry point, which may not take `USING` — declare the driver first,
the recursive subprogram after.)

## Finding B — variable-length buffers: YES, via buffer + used-length counter

CBOR is a variable-length byte stream; COBOL records are fixed PIC width. The
idiom that works: a max-size `PIC X(N)` buffer + an explicit `used-length`
counter, with **reference modification** `BUF(offset:len)` for append/slice.
Reading a byte's *numeric* value (to split a CBOR initial byte into major-type
and additional-info — no native bit ops, so `/ 32` and `MOD 32`) needs a
**`REDEFINES` over `PIC X` with `PIC 9(2) COMP-X`** (unsigned binary, 1 byte).

**Sizing trap caught here:** `COMP-X` sizes to the digit count — `9(2)`→1 byte,
`9(3)`→2 bytes. A single byte MUST be `9(2) COMP-X`; `9(3)` silently reads two
bytes and corrupts every downstream offset. P2 built `0x8301182a63616263` and
parsed `0x83 → major=4, addl=3` once the cell width was right.

## Finding C — FFI: YES, byte-exact, with two required cobc flags

The FFI-everything strategy is fully viable. P4 called the real
`int32_t ec_sha256(const uint8_t*, size_t, uint8_t*)` in `libentitycore_codec.so`
and got `ba7816bf…20015ad` — byte-identical to the SHA256("abc") oracle. The
C-ABI calling convention maps cleanly:

- `BY REFERENCE` for `const uint8_t*` / `uint8_t*` (pointer to a COBOL buffer),
- `BY VALUE` for `size_t` (an 8-byte `PIC 9(18) COMP-5` → 64-bit C arg),
- `RETURNING` into a 4-byte signed `COMP-5` for the `int32` status.

**Two required flags:** `-fstatic-call` so `CALL "ec_sha256"` binds to the linked
symbol instead of GnuCOBOL trying to `dlopen` a *module* named `ec_sha256`; and
link with `-L… -lentitycore_codec` (+ `LD_LIBRARY_PATH` at runtime). With those,
the entire codec + crypto surface (incl. Ed448, `ec_ed25519_seed_to_pubkey`) is
reachable. This collapses S2 to a binding shim — no native COBOL CBOR/crypto.

## Finding D — the decimal-first numeric model: the discovery payoff ⚑

COBOL is **decimal-first**: `PIC 9(n)` is a *decimal-digit* width, not a bit
width. The uint64 integer head-form is the carrier every prior peer tripped on
(OCaml int63, C# ulong, TS bigint, Zig overflow-trap). COBOL's flavor is distinct
and sharp:

- `2^64 − 1 = 18446744073709551615` is **20 decimal digits**. The comfortable
  COBOL'85 ceiling is `PIC 9(18)` — **one digit-class short of uint64**. A peer
  reaching for the "obvious" 18-digit field **silently truncates** (P3:
  `…→ 446744073709551615`, top two digits gone).
- You **cannot even declare** a >18-digit `USAGE COMP-5`/binary field — cobc:
  *"binary field cannot be larger than 18 digits."* So uint64 cannot be a wide
  *decimal-binary*; it must ride an **8-byte `PIC 9(18) COMP-5`** whose *physical*
  storage holds the full 2^64 range. The digit count is a display/MOVE-truncation
  cap, not a storage cap — a `REDEFINES` view over 8 raw bytes reads the full
  `18446744073709551615` even with `binary-truncate` ON (P3, both 3a/3b).
- `COMP-5` is **native byte order**, which matches a C `uint64_t` handed back over
  the FFI boundary (the codec does CBOR's big-endian on the C side). So the carrier
  is FFI-aligned for free; only manual COBOL byte-twiddling (which FFI lets us
  avoid) would need an endian flip.

**The carrier pattern for the peer:** uint64 values ride an 8-byte `PIC 9(18)
COMP-5` built with `-fno-binary-truncate`; a `PIC 9(20+)` DISPLAY decimal is used
only where a >18-digit value must be shown or decimal-compared (decimal arithmetic
goes to 38 digits; only *binary* usage is capped at 18).

### Why this is more than a peer-impl note → spec candidate

This **strengthens the existing F7 / A-OC-001 candidate (u64-range test vectors).**
A COBOL peer written with the natural `PIC 9(18)` field would **pass the current
conformance vectors** (which don't exercise integers above 10^18) **while silently
truncating real uint64 values on the wire.** That is a concrete demonstration that
the test surface does not currently catch the integer-head-form truncation class —
exactly the argument for adding u64-range vectors. Logged as `A-CBL-001`. This is
corroboration-with-teeth, not a brand-new defect: the 5th distinct native-int trap
class, and the one that best motivates closing F7.

---

## Recommendation

**Proceed to a full COBOL peer build.** Strategy confirmed:
`codec_strategy = "ffi"` (everything over the C-ABI), recursion via
`RECURSIVE`+`LOCAL-STORAGE`, variable-length via buffer+counter+reference-mod,
uint64 via the 8-byte `COMP-5` carrier above. Next: S1 profile
(`/entity-rosetta --profile-only cobol`) folding these four findings into
`profile.toml` + `PROFILE-RATIONALE.md`, then S2 binding shim.
