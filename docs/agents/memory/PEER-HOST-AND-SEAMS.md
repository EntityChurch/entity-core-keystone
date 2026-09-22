# Peer host and seams — keystone memory

The keystone peer contract and the extension-host surface — what a third party can install, reach, and read in a constructed peer.

**Arrive here when:** an installed handler cannot be reached, an in-process surface differs from the wire, or an extension can see something it should not.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A NEW SEAM MUST BE ORDERED BEHIND THE BEHAVIOUR A CHECK ALREADY DRIVES, OR IT CAN MOVE A CONFORMANCE NUMBER
- A PEER CAN OFFER TWO SURFACES FOR ONE OPERATION, AND THE ORACLE DRIVES EXACTLY ONE OF THEM — the other is the one an extension host is told to use
- The extensibility boundary is research, not a one-off
- AN IDEMPOTENT GENERATOR MUST RECORD WHAT IT OWNS, NEVER INFER IT FROM THE STATE IT JUST CREATED — the second run is where that bites, and the first run looks perfect
- RATIFIED — A TOML KEY WRITTEN AFTER AN ARRAY-OF-TABLES BELONGS TO THE LAST TABLE
- A PUBLIC FIELD ON A TYPE HANDED TO THIRD-PARTY CODE IS A CAPABILITY, AND THE PEER'S PRIVATE KEY WAS ONE
- RUN THE CONSUMER'S OWN SUITE, OLD PEER AGAINST NEW, BEFORE SHIPPING A SURFACE CHANGE — and read the test that flips before deciding which side is wrong
- AN EXPORTED SYMBOL IS NOT A REACHABLE SEAM — reachability is decided at the PACKAGING BOUNDARY, and that boundary is a different construct in every language

---

- **A NEW SEAM MUST BE ORDERED BEHIND THE BEHAVIOUR A CHECK ALREADY DRIVES, OR IT CAN MOVE A
  CONFORMANCE NUMBER.** Candidate (first occurrence, `typescript` H7, 2026-09-04; the enforcement
  point is exact). Adding an installable evaluator to the §6.13(a) entity-native path is only safe
  because the built-in `compute/literal` branch answers **first** and is unaffected by anything
  installed — that branch is what `core_register_body_binding` drives on all 46 peers. Consulted
  *before* it, an installed evaluator silently owns a check the peer is measured on; consulted
  *after*, a peer with no evaluator is byte-identical to the peer before the seam existed.
  **Measured both ways**: unmutated → `758 · 317P/336W/0F/105S`, exactly 1 of 758 severities
  different from the committed report and that one the documented `t1_1_concurrent_demux` flake, so
  zero checks moved; the plant that preempts the literal path reddens exactly the fast-path test.
  **Rule: when adding a seam to a path a conformance check already exercises, the built-in floor
  goes first and the seam gets the fallback arm — and assert that with its own test, because the
  ordering is invisible in any run where the seam is uninstalled.**

- **A PEER CAN OFFER TWO SURFACES FOR ONE OPERATION, AND THE ORACLE DRIVES EXACTLY ONE OF THEM —
  the other is the one an extension host is told to use.** RATIFIED 2026-09-06: two shapes in one
  session, both on `typescript`, both routed by `entity-system-generator` out of building `CONTENT`,
  and both **structurally invisible to `--profile core`**.
  - **Registration.** The wire `system/handler:register` op forwards a full §3.7 manifest verbatim
    (`handlers-handler.ts:53,82`), so an `operations` map carrying `input_type`/`output_type`
    reaches the interface entity. The IN-PROCESS `registerHandler` declared
    `operations: readonly string[]` and rendered each op as an **empty** `operation-spec` — so a
    handler installed the way a host installs one could publish operation NAMES and nothing else,
    and the extension had to re-write its own interface entity afterwards. §3.7 calls those types
    the thing *"tooling and code generators rely on to derive op shapes without per-extension
    knowledge"*. **`python`'s bootstrap already carried `(op, input_type, output_type)` triples in
    `_CORE_SPECS`** — so this was a cohort outlier and a sibling had the answer, which is the
    standing *"when a scope question has 45 existing answers in the tree, ask them"* rule again.
  - **The response view.** `ExecuteResponse` was built from `envelope.root` **alone** at all three
    client sites, discarding the envelope's `included` map (§3.1) — which is how CONTENT returns a
    blob and its chunks. A caller using the peer's own client surface received the reference and
    could never obtain the referent. The server side was correct throughout.
  **Why neither could be measured, and it is not an oracle gap:** the oracle is a WIRE client. It
  builds its own envelopes and reads ours directly; it never constructs the peer's `Handler` type
  and never goes through the peer's `ExecuteResponse`. So a defect in either surface sits outside
  every conformance category by construction — confirmed rather than assumed: both fixes moved
  **0 of 721** severities, and the only difference against the tracked report was the documented
  `t1_1_concurrent_demux` flake (WARN in 3 of 3 runs, so the tracked PASS is the outlier and the
  report was left alone).
  **Enforcement: for any operation a peer exposes BOTH over the wire and in-process, diff what the
  two ACCEPT and what each PUBLISHES.** A narrower in-process surface is the defect, every time,
  because the wire one is the one under test. Generalize past registration: any type that wraps a
  wire message for a caller (`ExecuteResponse`, a session, a client) must be checked against the
  ENVELOPE it was built from, not against the root entity — a field the oracle reads directly is a
  field a wrapper can silently drop.
  *(Sub-lesson, and it is the standing control rule pointed at my own prediction: **name which ARM
  a plant reddens, then RUN it.** The `python` H6 controls were written predicting checks 1 and 3;
  measured, the ACCESSOR plant reddens 1 and 4 and only the ENFORCER plant reddens 3. Two plants on
  **disjoint** checks is what proves the accessor arm and the enforcer arm are independently
  measured rather than one carrying the other — with a single plant, *"the number a body reads is
  the number in force"* would have rested on one observation. The prediction was recorded in the
  test's own docstring and corrected there.)*

- **The extensibility boundary is research, not a one-off.** "Does a core peer already
  support installing a handler + outbound dispatch?" surfaced three buildable gaps
  (handler-register stubbed / handler outbound dispatch / a retroactive hand-maintained
  `--profile core` map) — design the core ↔ extension ↔ SDK boundary, don't bolt on a spike.
  Compute is an entity-native handler dispatching through the *same* §6.6 path (dispatch
  uniformity).

- **AN IDEMPOTENT GENERATOR MUST RECORD WHAT IT OWNS, NEVER INFER IT FROM THE STATE IT JUST
  CREATED — the second run is where that bites, and the first run looks perfect.** Candidate (first
  occurrence, 2026-09-09, `tools/author-extension-host.py`; enforcement exact). The script decided
  whether a peer's `[extension_host]` block was hand-authored by asking *"does an `[extension_host]`
  section exist"*. On run 1 that was correct. **On run 2 the section existed because run 1 had made
  it**, so all 44 generated blocks were reclassified as hand-authored and regeneration **stripped
  `dispatch_read_site` from every one of them** — the load-bearing field, the entire reason H5 has
  that field. Fix: two markers (`FULL` = the script owns the whole block, `MEASURED` = a hand-authored
  block owns the prose and only the measured fields are injected), read from the file rather than
  inferred. **Enforcement: run any generator TWICE in its own test and require the second run to
  report zero writes.** A single run cannot detect this class at all.
  **AND THE CHECK PASSED THE STRIPPED TREE — SECOND OCCURRENCE IN ONE SESSION OF A CONTROL ASSERTING
  THE WRONG PROPOSITION.** `--check` verified the H1 keys were present and said *"46 examined, 0
  problems"* over 44 blocks whose `dispatch_read_site` had just been deleted. It printed the count,
  which this file already requires — **the count was right and the predicate was wrong**, so the
  examined-zero-things rule is necessary and not sufficient. **A gate must assert the field the
  artifact EXISTS FOR**, and for a generated block that is whichever field a human traced by hand.
  *(Two cheaper sub-lessons from the same tool, both caught by its own postcondition rather than by
  reading: **a fragment of `key = value` lines appended to a TOML file lands in whatever table the
  file ENDS in** — `[spec]` on all 46 — which is valid TOML and silently wrong, so emit the section
  header and then PARSE the result; and **interpolating traced source text into a TOML string needs a
  real escaper**, because the values quote code containing quotes and seven profiles stopped parsing.
  Both are the postcondition rule: verify the property, never that the edit was written.)*
  **CURRENT STATE 2026-09-12 — THE HEADLINE BELOW WAS MISLABELLED, AND THE LABEL HID A REAL GAP FOR A
  WEEK. The 2026-09-09 census measured §6.13(a), NOT H1.** `tools/host-seam-probe` registers a body
  over the WIRE and asserts a `compute/literal` evaluates; H1's Observation installs a LANGUAGE-NATIVE
  body through the public surface and names that literal path as the one that cannot satisfy it. The
  verdict was written into `h1_status`, so 26 profiles read `host` on H1 — **17 of them declaring no
  in-process install path in the adjacent field**, `rust` among them — and the generator's rust
  measurement closed on 2026-09-06 with nothing moving *because the gate said rust was already a
  host*. Routed back as their K-10. **What makes it worth a numbered entry is that `docs/STATUS.md`
  said so in the same paragraph** (*"read `host` precisely: the entity-native path works, not that a
  language-native callable can be installed"*) and every reader trusted the field over the caveat.
  **RATIFIED — A CAVEAT IN PROSE DOES NOT RENAME A FIELD**, the same class as the Makefiles that said
  `if absent` over a staleness bug and the deferral comments that said `until X exists`: the
  qualification was written down beside the defect, and the defect is the thing tools read.
  **Enforcement: `tools/author-extension-host.py --check` refuses any `h1_status` other than `unknown`
  whose `h1_verified_by` rests on the wire probe**; the probe verdict lives on as `entity_native_*`
  (26/19/1, unchanged), and `h1_status` is `host` only with an executed H1 harness named — `rust`
  (`tests/host_contract.rs`, landed the same day with plants), `typescript` (keystone's host-seam
  test); `python` `not-yet` (dict reachable, H3 excludes a raw container); 43 `unknown`.
  **Two gate defects fell out, both the standing classes:** (a) that `--check` **exited 1 on any
  checkout without the gitignored probe reports** — `make lint` was red on this host and would be red
  on every clean clone, fourth occurrence of *"a gate that only reads gitignored scratch"*; it now
  validates the committed properties without them and says staleness was not compared. (b) the new
  discriminator **first ran only after a write**, so the plant reported merely STALE — a control
  exercised in the wrong mode. Planted in both modes before landing.
  *(Sub-lesson from the rust plants the same day, the inert-control class again: the first H6 plant
  cut the connection's budget and the test stayed green, because `frame_budget()` falls back to the
  peer's value and the two were equal. **When a number has two sources, a plant must cut both** — or
  choose a test input where they differ.)*
  *(And a near-miss on the same surface, the harden-one-anchor rule pointed at a NEW surface rather
  than a sibling: the first cut of `rust`'s in-process `register_handler` refused `system/*`, copied
  from the wire op beside it — **a rule withdrawn at 0.8.2.13, in a copy `SDK-OPERATIONS` v1.12 names
  as the thing that makes standard-extension installation impossible**, and which our own F61 finding
  quotes. It passed every test, because no test installed at `system/compute`. Caught re-reading F61
  while writing the reply. **When a new surface mirrors an old one, diff what each REFUSES against the
  current text, not against each other** — the old one may be held on purpose for a reason that does
  not transfer.)*
  *(And for anyone extending a published Rust struct: a new `pub` field on an all-`pub` struct breaks
  every downstream struct literal, and a private one breaks `..Default::default()` too. `CreateOptions`
  was left untouched and the new knobs went into `PeerConfig` + `Peer::create_with`, verified by
  building the downstream workspace against the branch before merging — 105 of their tests, 0 red.)*
  **CURRENT STATE 2026-09-09 (headline SUPERSEDED above — read "H1" as "the entity-native path") — H1
  IS MEASURED COHORT-WIDE: 26 of 46 peers can dispatch a
  third-party-installed body; 20 cannot, and nothing in the 778-check set says so.** Verified rather
  than assumed: `core_register_body_binding` asserts only that the §11.6.1 entities were BOUND,
  `unsupported_operation_on_registered_handler`'s `registeredURI` is **`system/tree`** (a BOOTSTRAP
  handler — "registered" means present), and `validate_echo_dispatch` drives the built-in
  `system/validate/echo`, the oracle's own declaration recording that the dispatch half was
  deliberately *"moved off compute/literal"*. **So a peer binds all four writes, scores `778 · 0F`,
  and has nowhere for a body to run.** None of it is a conformance failure — §6.13(a) is an extension
  surface — but two of the three failure shapes report SUCCESS for a registration that can never be
  dispatched, which is a promise the peer cannot keep. Two spec questions fell out and are recorded as
  questions, not assertions: **`no_handler_body` appears nowhere in `v0.8.2.11`** (it is `go`'s
  spelling, copied by 8 peers, and the cohort spells that failure four ways), and `pd` answers
  `501 not_implemented`, one of the four spellings §3.3 retired at 0.8.2.7 — though 0.8.2.8's
  carve-out for *"a domain code defined for a different failure"* may reach it.
  **CURRENT STATE 2026-09-07 — §6.3's `0.8.2.11` PUT ADMISSION LADDER is CLOSED at 46 of 46, 6 of 6
  on `tools/put-probe`, and it moved NO conformance check.** This is the first ACCEPT-side rule of
  the whole `0.8.2.x` arc and it was new implementation on every peer, not a re-vendor: measured
  first at **0 of 46 conformant**, with 36 peers accepting-and-storing a two-key `{type, data}`
  submission. The pinned oracle (`f313028`, executed set `d30c3dd0…`) carries no vector on this
  surface — its own `put` inputs all carry a well-formed `content_hash` — so **the ladder is
  additive at this check set, verified per-check against every committed report rather than by
  summary.** The oracle re-pin that WILL gate it is still deliberately open (`go` is 54+ commits
  past the pin and was landing `fix(tree)` work on this surface); the vendor and the re-pin stay
  decoupled. Detail: `shared/findings/put-admission-wire-census.md`.
  **CURRENT STATE 2026-09-01 — the `0.8.2.3` sweep is CLOSED at 46 of 46, `756 · 0F`, cohort-standard
  row `314P/336W/0F/106S`. The `755 · 0F` cohort row below is HISTORY.** Both anchors moved together
  (oracle `c1b0708 → f313028`, spec `v0.8.2 → v0.8.2.3`, executed set `95edd774… → d30c3dd0…`), two
  new core checks landed (`connect_prehello_authenticate` FM-1,
  `dispatch_inbound_foreign_namespace_refused` PD-1) and one was **deleted rather than re-pointed**
  (`authz_peers_target_from_uri`, whose PASS branch required the escalation — see the F51 withdrawal
  entry above). The last five peers (`pd` `wasm-wat` `asm-x86_64` `asm-arm64` `riscv64`) took the
  §1.4 address gate; all 46 tracked reports and prose banners were **re-measured**, not copied, and
  the matrix's own pin prose was a pin behind independently of the peers (`pin-gate` was red on
  `check_set_digest` and the spec-snapshot hashes — the re-pin updated `oracle-pin.env` and the code,
  and left the document that tells a reader what the pin IS).
  **Two verification-tool defects fell out of the refresh, and their correct answers are OPPOSITE —
  worth holding together, because "check the sibling for the same defect" argues for making them
  match and that would be wrong.** Both read `output/scratch/census/`, which a `--to-status` run does
  not write. `tier-status.py` is a status DISPLAY, so freshest-wins is right: it gained the tracked
  reports as a third recency-ranked source (keyed by peer DIRECTORY — every tracked report is named
  `CONFORMANCE-REPORT.json`, the `Path.stem` collision `check-set-gate` already shipped once).
  `check-set-gate.py --tracked` is a GATE ON those reports, and its census read is exactly what keeps
  the claim set independent of what it checks — deriving it from the tracked reports makes the gate
  *"every tracked report at the pinned digest is at the pinned digest"*, the `oracle-bootstrap`
  HAVE/WANT shape — so it REPORTS the drift instead. **A stale input is not always an override to
  fix; sometimes it is the independence you were relying on. Ask what question the tool answers
  before porting a sibling's fix into it.**
  *(And a third, cheap: `coherence-gate --self-test` died on `assert bad != matrix_text` because its
  planted defects named `755`-era literals. **That loud death is the design working** — a plant that
  silently matched nothing would make those checks vacuous — but a regression suite needing a hand
  edit on every re-pin is one nobody runs. **Derive plants from the file under test, never hardcode
  the figures.**)*
  **CLOSED 2026-08-30 — every peer in the cohort is at `755 · 0F`. 46 of 46, no exclusions.** The
  last five landed in one pass: `asm-x86_64`, `asm-arm64`, `riscv64` (INVALID → 0F), `cobol`
  (30F → 0F) and `apl` (excluded → 0F).
  **This paragraph said "45 of 45" and "`apl` remains unmeasurable and upstream-blocked — that is a
  toolchain fact, not a conformance one" for several hours, and every clause of that was false.**
  The toolchain had been fixed three days earlier, the upstream tarball was never deleted, and the
  exclusion was enforced by the census itself. See the exclusion entry above; it is the more
  important lesson of the two, because the wrong number was *published* and no gate could see it.
  **Say what this is and what it is not.** It is 46 peers passing one author's vectors at one pinned
  check set: **cohort-consistent, not independent convergence**, and the ISA trio is one lineage
  ported twice on top of that. It is not a claim that the peers are correct — three of the four
  defects closed here had been PASSING checks for months for reasons unrelated to what those checks
  test.
  **Three things the last four peers taught, all of them about how a defect DISGUISES itself:**
  - **The connection-pressure family never existed.** Three peers were quarantined for a "shared
    connection-pressure defect" and the actual cause was a §4.9(c) silent drop on a length-colliding
    op name — a correctness bug billed entirely to the caller's timeout, so it read as slowness.
    §1a's accumulation theory is retracted; the 2026-08-29 measurement that disproved it was correct
    and pointed nowhere, because it was answering "is the peer unhealthy" and the peer was fine.
  - **`cobol`'s 30 FAILs were 24 cascade + 5 real + 1.** One unchecked `MOVE` of wire data into a
    fixed field killed the process; every check after it reported connection-refused. **Count the
    cascade before budgeting the work** — the standing "first FAIL in RUN ORDER, last check before
    the first transport error" diagnostic gives the real number in one read of the census JSON.
  - **Two of the four peers had defects that were holding each other up.** `cobol`'s id-scope
    over-canonicalization and its absolute-handler-value were individually invisible; fixing either
    alone makes the peer worse. When a fix moves a number the WRONG way, the second defect is the
    finding — this is the standing "a fix that raises the FAIL count is a finding" rule with the two
    halves inside one dimension.
  **Owed, and named rather than quietly carried:** ~~the ISA trio still over-publishes extension type
  vocabularies~~ — **closed 2026-08-30**, the grep returns nothing and the three now read
  `313P/336W` / `312P/337W` / `312P/337W` against the cohort-standard `312P/337W` (the fix lowered
  the pass count by 282; see the type-registry entry above).
  ~~`asm-arm64`/`riscv64` never received b6371d7's four `host.s` hardenings~~ — **ported 2026-08-30;
  `r3_connection_flood` WARN→PASS on both, all three ISA rows now `313P/336W`, and the cohort finding
  moves 44/2 → 42/4.** `cobol` skips two concurrency checks its 65535-byte
  frame cap and 8192-byte entity ceiling make unreachable.

- **RATIFIED — A TOML KEY WRITTEN AFTER AN ARRAY-OF-TABLES BELONGS TO THE LAST TABLE.** Second
  occurrence, different shape: the first was `author-extension-host.py` appending `key = value` lines to
  profiles that ended in `[spec]`; this one was hand-authored. `requirements.toml`'s `controls = [...]`
  sat at the end of the file after the last `[[requirement]]`, so it parsed as a field of
  `authority.path_permission` and the top-level list was empty — valid TOML, silently wrong. It was
  caught only because the verdict rule **fails closed**: with no controls every driver requirement read
  "no control held", and `--check` refused all 20. **Enforcement: put top-level keys before the first
  `[[table]]`, and have the reader assert the key exists at the top level** (`--check`'s "lists no
  control" does). A reader that defaults a missing list to empty is the defect that lets this pass.

- **A PUBLIC FIELD ON A TYPE HANDED TO THIRD-PARTY CODE IS A CAPABILITY, AND THE PEER'S PRIVATE KEY WAS
  ONE.** RATIFIED 2026-09-13 — second occurrence the same day, and a different shape: that one
  let a secret be READ, the second let an address be WRITTEN. `Entity.hash` is `pub`, and
  `Store::put_entity`/`bind_with_context` trusted it. Extension code could therefore file an entity
  under another entity's content hash, and the authority path resolves grantees from that store by
  hash: 0.8.2.23's `K1` forgery, moved in-process. Wire decode had always recomputed the hash, so
  every wire-side check passed. Only a fixture that DELIBERATELY constructs the forgery could see it
  (`embed.data/forged-hash-not-filed`, plant `data-hash-trusted`). **When a field can't go private
  because consumers read it (326 reads downstream), the check moves to where it is TRUSTED**: the
  store verifies `content_hash_holds()` at write and returns `bool`. **Enforcement: for each `pub`
  field on a type an extension receives, name the site that relies on it. A reliance with no check
  there is the defect.** First occurrence (2026-09-13, `rust`; found by the gap audit, not by any test). `Identity.seed` was
  `pub`, and `HandlerContext::peer()` hands every installed handler body the `Peer` — so any extension
  could read the Ed25519 private seed, and `#[derive(Debug)]` would print it. Nothing measured it:
  conformance cannot see an in-process field, and H1–H9 never asked what a body can *read*. Made
  private with a redacting `Debug`; signing stays on `Identity::sign_entity`. **Enforcement: for every
  type reachable from a handler context, list its `pub` fields and ask which are secrets** — and repeat
  it for each language as it is brought up to the contract (python's `DispatchCtx` is a public
  dataclass). An extension-host surface is an authority boundary, and a field is on it.

- **RUN THE CONSUMER'S OWN SUITE, OLD PEER AGAINST NEW, BEFORE SHIPPING A SURFACE CHANGE — and read the test
  that flips before deciding which side is wrong.** Candidate (2026-09-13, S3). Bringing typescript and
  python up to the contract changed public return types, the readiness line and a CLI flag on peers that
  `entity-system-generator` stages by copy. Their suites were run read-only against a scratch copy of their
  staged build with our peer swapped in, **with an old-peer arm in the same run**. The first attempt showed
  both arms red, which is what separated a broken reconstruction (stale `__pycache__`, node 24's non-TAP
  reporter printing no counts) from a real break. The one real flip was a test they wrote to fire on exactly
  this change. The tempting "fix", a read-back getter, would have turned their gate green over an evaluator
  whose signature 500s at dispatch. **Enforcement: every arm prints a pass COUNT, and an old-peer arm exists
  in the same run.** *(Sub-lesson: `shutil.copytree` follows symlinks by default, so `plant.py` turned
  `node_modules/.bin/tsc` into a file whose relative require failed; plant copies keep links as links now.)*

- **AN EXPORTED SYMBOL IS NOT A REACHABLE SEAM — reachability is decided at the PACKAGING BOUNDARY,
  and that boundary is a different construct in every language.** RATIFIED 2026-09-03 (the
  source-grep class again, in a new surface, and **two of the wrong calls were ours**). Answering
  `entity-system-generator`'s peer host contract — *can a third party install a handler into a
  constructed peer* — four peers were nominated as satisfying it from source reads, by three
  different seats, and **three of the four were wrong, each at a different boundary**:
  - `cpp` — **class scope.** We cited `include/entity_core/peer.hpp:91`; `private:` is at line 75, so
    `register_handler`, `lookup_handler`, `handlers_` **and the `Handler` typedef itself** are
    private. An external caller cannot even name the body type. Verified.
  - `csharp` — **assembly scope.** We cited a `public RegisterHandler` at `Peer.cs:177`. It is a
    public member of `internal sealed class Peer` (`:23`), and every type in the assembly is
    `internal` bar ten exception classes and `PeerId`. Verified: the public type list is exceptions.
  - `julia` — **a live public entry point onto a container nothing reads.** `register_handler!` is
    exported and writes a `Dict{String,Function}` commented *"extension seam"*; the dict is
    **declared once, written once, never read** — dispatch resolves through the store instead. This
    is the dangerous shape, because it reads as satisfied from every artifact a reviewer would open:
    an exported symbol, a typed container, and a doc comment naming it the seam.
    **FIXED 2026-09-08 — `julia` IS a live host now and this bullet is kept for the LESSON, not as a
    current fact about the peer.** `peer.jl` reads the dict at `_dispatch` (`get(p.handlers, stripped,
    nothing)`), the §11.6.1 entities are bound, and the H7 ordering — built-ins answer FIRST, the
    installed map takes the fallback arm — is asserted in the source at the read site. Measured
    independently on the wire 2026-09-09: `julia` verdicts `EVALUATES`. **The reason to leave the
    text standing is that the dead-map shape is what H5's `dispatch_read_site` field exists to catch,
    and it is the only recorded instance — deleting the example would delete the argument for the
    field.** Say which peer it was and that it was repaired; do not cite it as a live defect.
  **Two rules, and the second is the general one.** (a) **The entry point is not the seam; the seam
  is the line that READS the container.** A census that reads the registration site and stops cannot
  distinguish a working host from a dead map. (b) **"Is the member public" is the wrong question —
  ask whether it is reachable across the packaging boundary**, which is the class in C++, the
  **assembly** in C#, the module in Go, and the `exports` map in npm. Four nominations, four
  boundaries, three misses.
  **Enforcement, and it is the standing `unknown`-until-executed rule earning itself in advance: a
  capability claim about a peer reads `unknown` until a harness executes it.** The check that settles
  it installs through the public surface only, drives an EXECUTE from a second peer, and asserts a
  witness value derived from a request field **and** registration-time state — no `compute/literal`
  entity-native body can produce that, so a peer with no live index cannot pass on the fallback path.
  Both controls required (mutated harness → RED, unmutated → GREEN). One peer of 46 is measured.
