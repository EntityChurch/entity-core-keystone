# Changelog — entity-core-protocol-forth

All notable changes to this peer. Spec-version tracked literally per the keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note:** Forth has no package registry and no version grammar to satisfy — the
> `0.1.0-pre` marker lives here + in README.md only; there is nothing analogous to a
> `Cargo.toml`/`pack.pl` version field to carry it. `make dist` stamps the tarball name from
> `VERSION` (default `0.1.0-pre`).

## [0.1.0-pre]

**Tracks Entity Core v0.8.0 (V8)** spec-data (`protocol-generator/shared/spec-data/v0.8.0/`);
**codec corpus v0.8.0**. The core wire contract is byte-unchanged across the V7→V8 cutover.
Oracle pin: **`entity-core-go @cc1970f`**.

First release line. **Peer #25 — the cohort's stack-machine / typeless probe** (gforth 0.7.3:
two-stack RPN, no native records, typeless cells). Derived spec-first as an **FFI-hybrid**:
**pure-Forth canonical CBOR** (the peer owns the whole ECF byte-layer), crypto + SHA over the
codec C-ABI (`libentitycore_codec`) via gforth's **in-process** `libcc` `c-function`. Not yet
published — parked at `-pre` pending architecture v0.1 sign-off + a first external gforth
consumer (the S5 promotion gate).

The probe's payoff is **generator robustness down to a typeless stack machine** (A-FT-000:
corroboration — the recursive canonical-CBOR encoder/decoder and the §5 capability chain-walk
read as native Forth, not translated), plus the **seven S4 code-bug findings** the alien
substrate flushed out (below). Exact `--profile core` parity with the Rexx peer (#24).

### Conformance
- `validate-peer --profile core`: **Result: PASS** — **682 total · 291P / 295W / 0F / 96S**
  (all 96 skips are §9.0 auto-allowlisted extension carve-outs; 0 fail-counting), oracle
  `entity-core-go @cc1970f` (core-gate fingerprint `8261a033…`, vectors confirmed compiled).
  **Exact parity with Rexx (#24, `682·0F`).**
- Codec (S2): **69/69** byte-identical to `conformance-vectors-v1` — pure-Forth ECF; content_hash
  + signature legs cross the C-ABI for SHA/Ed25519. uint64 `[2^63, 2^64-1]` boundary self-test.
  `content_hash.4` (synthetic `format_code = 128`, 2-byte LEB128 prefix) PASSES (COBOL skipped it).
- §9.5 53-type floor: **53/53** byte-identical (render-from-model, asserted equal to the Go
  reference — not ingested).
- S3: foundation self-test **20/20** + two-peer loopback smoke **6/6** (in-process sockets +
  crypto; no co-process daemon).
- origination-core §10.2: **3/3** over a real two-peer connection (`dispatch_outbound_reentry` —
  the §6.11 reentry seam cross-impl wire-proven against the Go reference).
- multisig: genuine 2-of-3 M3+M4+M6 with a positive accept-path (`valid_2of3_peer_signed_accepted`).

### Added
- **Pure-Forth canonical CBOR / ECF byte-layer** (`src/cbor.fs`, `varint.fs`, `base58.fs`,
  `peer-id.fs`): shortest-float ladder (f16/f32/f64 — f32/f64 assembled from NATIVE IEEE bits via
  `SF!`/`DF!`; only the f16 leg + the shortest-form ladder are hand-rolled bit arithmetic),
  recursive major-type-6 tag reject at every node (N2), length-then-lex key sort, minimal-head
  re-validation, full-consume, N4 entity byte-fidelity (forward original wire, never re-encode).
- **In-process `libcc` C-ABI crypto binding** (`src/ffi/crypto.fs`): Ed25519 sign/verify/
  seed→pubkey, SHA-256/384 over `libentitycore_codec` (C-ABI v1.1, libsodium 1.0.22) via
  gforth's `c-function` — a genuine libffi call, **no subprocess / FIFO / co-process** (the
  cleanest binding in the FFI-hybrid family). Provenance via `ec_impl_info()`.
- **Native BSD sockets + single-thread select-pump peer** (`src/net.fs`, `peer.fs`): §6.5/§6.6
  dispatch, §5 capability chain-walk + authz trichotomy, §4.10(a)/(b) floor, §6.11 request_id
  reentry demux — all in-process (A-FT-008/015, the COBOL/Tcl native shape).
- §7a conformance handlers (`--validate`): `system/validate/echo`,
  `system/validate/dispatch-outbound`.
- **`handlers:register`/`unregister` full protocol** (A-FT-024) + handler dispatch entities.
- `bin/peer.fs` host driver: `--port`, `--name` (Ed25519 identity from
  `~/.entity/peers/NAME/keypair`), `--seed HH` (keypair-free test convenience), `--validate`,
  `--debug-open-grants`. Prints `LISTENING <port>` on stdout.
- **`make dist`** source-tarball packaging (the profile `package_command`) + `LOAD.md` load stub.

### Fixed (S4 — code bugs in the generated peer, not relaxed vectors)
- **A-FT-025 (the concurrency payoff):** a latent `pend-new` missing-return that only concurrent
  §6.11(b) reentry exposed — cross-talk in the request_id demux; + codec depth-cap, enlarged
  stacks, and an 8-MiB arena robustness set under the sustained-load categories.
- **A-FT-023:** a leaf-revocation false-positive was a `created_at:0` token-hash collision — the
  disabled `cap-revoked?` check the prior agent left was **re-enabled and root-caused**, not left off.
- **A-FT-026:** §5.2 resource-scope + §5.7 delegation caveats + mint-attenuation were unenforced.
- **A-FT-027:** §1.4 path-flex — NUL byte + leading-slash-non-peer-id rejection.
- **A-FT-028:** §4.10(c) connection-admission — conn table sized for the r3 flood (r3 → WARN,
  Rexx parity).
- **A-FT-017/018/020/021:** S2/S3 codec + URI-normalization + §5.6 direction-sensitive expiry.

### Known limitations / honest notes
- **Ed448 / SHA-384 agility deferred** (cohort-wide): the Ed25519 + SHA-256/384 floor is
  byte-proven; Ed448 is available over the same C-ABI (`ec_ed448_*`) but not yet wired — a
  documented non-v0.1 item, not a gap.
- **The crypto floor is a C-ABI FFI call, by design** — no different from the C peer; Forth owns
  the *codec* byte-layer (pure-Forth ECF), the C-ABI owns the *crypto* primitives.
- The C-ABI oracle ELFs (`output/s4-oracles/`) and the built `.so` / `libcc` wrapper are
  gitignored (byte-built floor), not committed — sources + run scripts are.
- No package registry / no version-grammar field (see the version note).

### Spec items surfaced (logged in status/SPEC-AMBIGUITY-LOG.md)
All 29 items **A-FT-000..028** are RESOLVED at their stage or research-owned
(generator-robustness); **none are open spec findings**. On the current saturated wire surface
the stack-machine probe surfaced no fresh spec-precision issue — clean corroboration end to end,
which is the answer the profile was built to get. Durable cross-Forth lessons banked:
A-FT-010/011 (the `>r`/`?do`/`r@` return-stack collision; the `1 0 ?do` empty-container wrap),
A-FT-012/013/014 (gforth locals stack-order; bump-heap `store-dup` aliasing; append-word
double-write). **Owner: operator/research** (no arch escalation outstanding).
