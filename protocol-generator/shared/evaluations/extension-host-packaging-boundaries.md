# The extension-host packaging boundary, across 46 substrates

**What this is.** The survey behind the keystone host contract's **H4** — *"a keystone peer
MUST be usable as a library, constructed in-process by a host application, and not only as a
standalone binary"* — asked of every peer in the tree.

**Why it exists.** H4 is the requirement this ecosystem has been wrong about most often, and
the errors have all been in one direction: a reviewer reads a peer's source, finds a
registration call and a container, and records a capability. Four nominations, four different
packaging boundaries, **three wrong** — class scope in `cpp`, assembly scope in `csharp`, a
container nothing reads in `julia`, and a dispatch-path fallback in a fourth. Two of them were
ours.

**What this document does and does not claim.** It records **facts about substrates and
manifests**, which are measurable by reading the tree. It records **no capability claim about
any peer's seam** — those read `unknown` until a harness executes, which is the standing rule
and the reason the four nominations above were withdrawn.

---

## 1. The correction that prompted it

The planning survey in circulation splits the cohort **26 with a packaging unit / 20 that
structurally decline H4**. Re-derived from each peer's own `profile.toml [publishing]` block —
the tree's declared answer, authored at S5, rather than a list of manifest filenames — the
split is different and **eleven of the forty-six rows disagree**:

| | prior | measured |
|---|---|---|
| Publishes to a real registry | 26 | **25** |
| Source-vendored — a genuine consumption mode, no registry exists for the substrate | — | **13** |
| No `[publishing]` declaration at all | 20 | **8** |

**Five peers that publish to a registry were filed as declining**: `fortran` (fpm),
`lean` (Reservoir, via Lake), `prolog` (SWI-Prolog pack), `smalltalk` (Metacello baseline),
`unison` (unison-share). **Six that do not publish were counted as having a unit**:
`crystal` `datalog` `node-red` `rust-wasm` `rust-wasm-wasmtime` `turbowarp`.

**The mechanism is the one this repo already has written down twice, and it failed silently
toward the flattering direction of "nothing owed here."** A survey keyed on a list of manifest
filenames cannot see a language whose packaging system was not on the list. Reproduced twice
while writing this: a scan for `package.json Cargo.toml pyproject.toml …` missed `ada`'s
`alire.toml`, then `lean`'s `lakefile.lean`, then `prolog`'s `pack.pl` — and `prolog`'s sources
are in `prolog/prolog/`, not `src/`, so a source grep scoped to `src/` returns nothing for it
as well. **Every miss produced a confident "no packaging unit", never an error.**

**`lean` is the one to notice**, because it is not an exotic corner: it is an **M1** peer, one
of the five that gate every oracle re-pin, and it declares `package «entity-core-protocol-lean»`
with `lean_lib EntityCore` as a default target.

**Enforcement:** derive a packaging survey from `[publishing]` in each peer's own profile, never
from a filename list. A peer that has no such block is a peer that has not declared one, which is
a reviewable gap; a filename list produces the same output for "declines" and for "the surveyor
had not heard of this package manager."

## 2. The measured split

**Registry-published (25).** A third party can name a version and depend on it.

> `ada` (Alire) · `common-lisp` (Quicklisp) · `cpp` (CMake package + vcpkg + conan) ·
> `csharp` (NuGet) · `dart` (pub.dev) · `elixir` (hex) · `fortran` (fpm) ·
> `go` (go modules, git-tag) · `haskell` (Hackage) · `java` (Maven Central) ·
> `julia` (General registry) · `kotlin` (Maven Central) · `lean` (Reservoir via Lake) ·
> `nim` (nimble) · `ocaml` (opam) · `php` (packagist) · `prolog` (SWI-Prolog pack) ·
> `python` (PyPI) · `ruby` (RubyGems) · `rust` (crates.io) · `smalltalk` (Metacello) ·
> `swift` (SwiftPM, git) · `typescript` (npm) · `unison` (unison-share) · `zig` (build.zig.zon)

**Source-vendored (13).** No registry exists for the substrate, and vendoring the source *is*
the consumption mode there. **This is not a failure and must not be recorded as one.**

> `apl` · `asm-x86_64` · `c` · `cobol` · `crystal` · `datalog` · `forth` · `io` · `odin` ·
> `oz` · `rexx` · `tcl` · `wasm-wat`

**No publishing declaration (8).**

> `asm-arm64` · `node-red` · `pd` · `riscv64` · `rust-wasm` · `rust-wasm-wasmtime` · `sql` ·
> `turbowarp`

**The limit on all three columns, stated rather than implied:** `[publishing].registry` is a
*declared distribution target* authored at S5. It is evidence that the peer intends a unit and
names which; it is **not** evidence that a package is published, nor that a consumer can reach
the peer's types across that boundary. The second question is H4's and needs a harness.

## 3. The design finding: H4 conflates two independent axes

H4 reads *"usable as a library … and not only as a standalone binary."* The cohort shows those
are **two questions, and a peer can answer them opposite ways**:

| | **Library consumption mode** — can a host program construct a peer in-process? | **Distribution unit** — is there something to depend on by name and version? |
|---|---|---|
| `c` | **yes, and it is the most library-shaped artifact in the tree** — `make` emits `libentity_core_protocol.a` *and* `.so`, and `make install` places the header and a `.pc` under `PREFIX` | **no registry** — its declared target is `source-tarball + pkg-config`, because pkg-config *is* C's distribution convention |
| `node-red` · `turbowarp` | it is an **application**, not a library | has a `package.json` |
| `smalltalk` | the deliverable is a **live image**; you file code in, you do not link against a package | Metacello baseline |
| `datalog` | the peer's language is Datalog; the thing a consumer links is a **Rust crate** | deferred |

**So a single `status = host | declined` field cannot express the cohort**, and a survey that
asks only "is there a manifest" gets `c` and `node-red` both wrong, in opposite directions.

**Consequence for the profile schema (H5):** the `[extension_host]` block needs the two axes
separately — `library_entry_point` (the in-process construction surface, which is what the
generator actually needs) and `packaging_unit` / `packaging_boundary` (what a consumer depends
on). `typescript`'s block already carries both; the remaining 45 should be authored that way
rather than with one conflated verdict.

## 4. Where the contract's *vocabulary* does not fit, independent of the answer

These are substrates where H1–H7's wording — "a runtime-mutable container", "the public
registration surface", "a separate compilation unit depending only on the published package" —
does not have an obvious referent. Each needs the requirement **restated for the substrate**, not
a yes/no.

- **Live-image (`smalltalk`).** `make` loads `src/*.st` doits into a fresh base image and
  snapshots a peer `.image`; **there is no AOT binary.** "A separate compilation unit depending
  only on the published package" has no analogue. The nearest honest observable is: file the
  extension into a *fresh* image built from the published baseline, and reach it.
- **Language-hosting-a-seam (`datalog`, and every hybrid-FFI peer).** The peer's authored
  language is not the language a consumer links. This is exactly why the profile block is
  `[extension_host]` and not `[host]` — `datalog/profile.toml` already uses `[host]` for
  *the language hosting the seam* (`language = "rust"`).
- **Content-addressed code (`unison`).** There is no file-based package; the unit is a namespace
  in a codebase, managed through UCM. "Depends only on the published package" needs restating as
  a namespace dependency.
- **Visual / patch substrates (`pd`, `turbowarp`, `node-red`).** A third-party "body" is a patch
  or block graph, not a callable. Whether that is installable at all is a real question and is
  not answered by any packaging fact.
- **Hand-authored, no packaging concept (`asm-x86_64` `asm-arm64` `riscv64` `wasm-wat` `forth`
  `cobol`).** These legitimately decline, and declining is a **profile value**, not a defect.

## 5. What is measured today

**One peer.** `typescript` — H1, H2 (including invocation **order**, which no `validate-peer`
category tests and which nothing anywhere had measured before 2026-09-04), H6 and H7, all by
execution, through the module specifier `package.json`'s `exports["."]` map publishes, with
planted-defect controls on every check. See
`protocol-generator/shared/diagnostics/host-seam-probe-typescript.mjs` and the peer's own
`test/host-seam.test.ts`.

**Forty-five peers read `unknown`, and that is the correct value.** Nothing in this document
changes one of them: a packaging fact is not a capability.
