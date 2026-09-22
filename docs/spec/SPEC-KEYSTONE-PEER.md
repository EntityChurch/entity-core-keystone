# SPEC-KEYSTONE-PEER — the host contract

**Version 1.0** · normative body digest recorded in `tools/keystone-spec-pin.env` ·
citable form **`H1…H9 @ <digest>`**

The additional obligations a **keystone peer** carries beyond core-protocol conformance, so that
an extension can be installed into one.

**A plain core-protocol peer owes none of this.** A peer can be fully conformant on the wire —
every check in `--profile core`, zero failures — and satisfy none of the requirements below. That
is the test for whether a requirement belongs in this document at all: *could a peer be fully
core-protocol conformant and still fail it?* If yes, it is ours. If a third-party peer would have
to honour it for interop, it is a proposal to architecture and does not belong here.

| | Binds | Owner |
|---|---|---|
| Core protocol | every peer that speaks the wire | `entity-core-protocol` / architecture. **Never us** |
| SDK / conformance guidance | every SDK and every implementation | architecture |
| **This document** | **the peers in this tree, and anything generated from them** | **`entity-core-keystone`** |

## How to cite this document

**Cite the digest, never a commit.** Published commits are authored fresh at the release boundary,
so an internal SHA resolves to nothing for a reader outside this ecosystem, and this repo has
already been burned by exactly that. The digest of this document's normative body is recorded in
`tools/keystone-spec-pin.env` and verified by `tools/keystone-spec-gate.py` in `make lint`.

**H-numbers are append-only, and a requirement is never edited in place once a peer has been
measured against it.** A withdrawn requirement is marked withdrawn and keeps its number. An
amendment moves the version and the digest; it does not rewrite history. H1 has already been
restated once — from *"there is a public call and a container"* to *"an EXECUTE reaches the
installed body"* — and a consumer had built a probe against the first wording. That is why the
pin exists: **cite at a digest, and re-read when the digest moves.**

## The standing evidence rule

**A capability claim about a peer reads `unknown` until a harness executes it.** This is not
caution, it is method: four peers were nominated as satisfying H1 from source reads, by three
different seats, and three of the four were wrong — each at a different packaging boundary
(`cpp` class scope, `csharp` assembly scope, `julia` a live entry point onto a container nothing
read). A source read cannot distinguish a working host from a dead map.

Every requirement below therefore names **what would be observed** if it held. A requirement whose
observation cannot be executed is not satisfied; it is unmeasured, and those are different words.

---

## H1 — Handler installation after construction

**Normative.** A keystone peer MUST resolve a dispatch pattern to a handler body through a
**runtime-mutable container**, not through a compiled-in branch on the pattern literal. A third
party holding a constructed peer MUST be able to install a handler at a pattern the peer was not
compiled with, **through the peer's public surface**.

**Observation.** Install a language-native body through the public surface only; drive an EXECUTE
over the wire from a second peer; assert a response value derived from **a request field combined
with registration-time captured state**. No `compute/literal` entity-native body can produce such
a value, so a peer with no live index cannot pass on the fallback path. Both controls required:
the mutated harness must go red, the unmutated one green.

**Why the container is not enough.** An exported symbol is not a reachable seam, and reachability
is decided at the **packaging boundary** — which is a different construct in every language: the
class in C++, the **assembly** in C#, the module in Go, the `exports` map in npm. "Is the member
public" is the wrong question. A registration site that writes a container nothing reads satisfies
every artifact a reviewer would open and fails this requirement.

**Installation binds the dispatch entities, not only the callable.** §6.6 resolution walks the
store for a `system/handler` entity; a pattern with no entity bound answers `404` and dispatch
never reaches the container at all. An in-process install MUST do the same work the wire
`system/handler:register` op does, so that the two produce the same peer.

## H2 — Consumer registration after construction

**Normative.** A keystone peer MUST expose a way to register an **emit-pathway consumer** — a
function invoked on tree-change and/or content-store events — and MUST invoke consumers in
registration order.

**Note on cost.** This is much cheaper than H1 and was already built nearly everywhere, because
the emit pathway is a reachable MUST with zero consumers, so every peer built it. **Nothing said a
third party could add a handler, so that did not get built.** Written down → built; not written
down → absent at random. That asymmetry is this document's entire thesis, and it was arrived at
independently by the seat being asked to implement against it.

## H3 — The composition surface is the only public mutation path

**Normative.** The dispatch index MUST NOT be public. Installation goes through the peer's
registration surface, which owns the collision refusal and the handle lifecycle.

**Exposing the raw container instead of a registration call does not satisfy H1** — it satisfies
the mechanism and defeats the invariant. Reaching the index by reflection or by a language escape
hatch is what this requirement forbids.

## H4 — Both consumption modes reachable

**Normative.** A keystone peer MUST be usable **as a library** — constructed in-process by a host
application — and not only as a standalone binary.

**Observation.** *A host application in a separate compilation unit, depending only on the
published package, constructs a peer and reaches it.* Not "a manifest exists."

**Package metadata is not H4, and it is not even evidence of H4.** A peer may declare a package id,
a licence, a description and pinned dependencies — every artifact a reviewer would open — while its
entire externally-accessible API is a handful of exception types. Conversely a peer with no registry
at all can be the most library-shaped artifact in the tree.

**H4 conflates two independent axes and they must be answered separately**, because peers answer
them opposite ways:

| | Question |
|---|---|
| **(a) construction surface** | is there an in-process way to build and reach a peer? |
| **(b) distribution unit** | is there a unit a consumer can depend on? |

A single `host \| declined` field gets both wrong in opposite directions. Declare them separately.

## H5 — The platform bindings are declared

**Normative.** `profile.toml` carries an **`[extension_host]`** block naming, for that language:
the handler registration call, the consumer registration call, the body/callable shape, the
handle/cleanup idiom, the module unit an extension ships as, which consumption modes are available,
**the dispatch read site** (the file and symbol where the container is consulted), and **the
frame-budget accessor** (H6, or `absent`).

**The dispatch read site is required and is not the entry point.** A profile naming only the
registration call cannot distinguish a peer whose container is read from one whose container is
dead — which is the exact defect H1's observation exists to catch.

**A peer that cannot satisfy a requirement DECLARES that.** `declined` is a value; silence is not.
Several substrates legitimately decline, and that is a fact about the substrate which belongs in
the profile exactly as `codec_strategy` does. **A survey keyed on a list of names the surveyor
wrote down cannot see what they did not think of, and it reports "absent" rather than "could not
look"** — so the block is the authority, never an inventory of filenames.

*The block is `[extension_host]` and not `[host]` because `[host]` is already taken, for an
unrelated subject — the language hosting an FFI seam — and every hybrid peer will want it.*

## H6 — The connection's frame budget is reachable from a handler body

**Normative.** A keystone peer MUST make the frame budget in force for the request's connection
readable by the handler body at response-construction time.

**Why it exists.** An extension that returns a large result has no other way to decide whether to
chunk. Without it the handler either guesses a constant or discovers the limit by being refused.

## H7 — The entity-native evaluation path is delegable

**Normative.** A keystone peer MUST allow a host to install an evaluator for the entity-native
dispatch path, and **the built-in floor MUST be consulted FIRST**, with the installed evaluator
taking the fallback arm.

**The ordering is the requirement, not a detail.** Consulted *before* the built-in, an installed
evaluator silently owns a conformance check the peer is measured on. Consulted *after*, a peer with
no evaluator installed is byte-identical to the peer before the seam existed. **Assert the ordering
with its own test**, because it is invisible in any run where the seam is uninstalled.

**Discriminate on the expression path, never on a status code.** Falling through on `501` swallows
a real `501` from a handler that does have a body.

**Install once, at composition time, before the peer begins listening.**

## H8 — A tree-change event carries its execution context

**Normative.** An event emitted on the emit pathway MUST carry the execution context of the request
that caused it, where one exists.

**Why it is not cosmetic.** An event with no context is **indistinguishable from an autonomous
write**, because the autonomous case is defined exactly — so a recorder's fallback is correct in
form and wrong about the world. A peer scores full marks on the presence checks while its audit
trail attributes every remote caller's write to itself.

**Observation.** The test MUST be driven from a **second peer**. On a single-peer harness the
caller and the local peer are the same identity, so the fabricated value and the correct value are
the same bytes and every assertion passes. Assert both `author == initiator` **and**
`author != responder`.

## H9 — A public path-permission predicate

**Normative.** A keystone peer MUST expose a public predicate answering whether a given
`(operation, path, token, handler_pattern, local_peer)` is permitted.

**Scope, and this is load-bearing.** Resources match against the **local peer, with no granter
frame.** This repo has recorded the granter-frame over-scoping defect three times in three
different peers, and every instance was somebody adding a frame to a surface that does not take
one. The chain-attenuation surface is a **different function**.

**Its absence is not necessarily an authorization gap** — a dispatcher that refuses a request with
no resource target already covers the ordinary path. The need is real for an extension whose target
lives in the request params.

**Observation.** At least one **accept** assertion, plus one **deny** per scope dimension. The
accept case is the one that validates the fixture: a test built only from deny cases is
indistinguishable from one asserting `False == False`, and a broken fixture makes all of them pass.

---

## Enforcement

A requirement with no enforcement point is theater. Each row names where the claim is settled.

| | Enforcement point | Kind |
|---|---|---|
| **H1** | per-peer host-seam harness — install via public surface, EXECUTE from a second peer, witness combines a request field with registration-time state | executed, both controls |
| **H2** | host-seam harness — consumer invoked, in registration order | executed |
| **H3** | the harness installs through the registration call only; reaching the index another way is the defect | executed |
| **H4** | a host program in a **separate compilation unit** depending only on the published package | executed |
| **H5** | `[extension_host]` present in `profile.toml`, every field a declared value or `declined` | declared, gateable |
| **H6** | harness asserts the budget read from a handler body matches the connection's | executed |
| **H7** | two tests — the built-in floor still wins uninstalled; the seam takes the fallback when installed | executed, both arms |
| **H8** | two-peer harness asserting author is the initiator and not the responder | executed, second peer required |
| **H9** | one accept plus one deny per scope dimension | executed |

**Conformance to this document is reported separately from `--profile core` and never mixed into
it.** A keystone-peer number and a core-protocol number answer different questions, and combining
them would overstate both.

## Relationship to the core protocol

Nothing here is wire-observable to a third-party peer, and nothing here may contradict the
protocol. Where this document and the protocol appear to disagree, **the protocol wins and the
disagreement is a defect in this document** — route it, do not reconcile it locally.

**This document may not be used to justify a peer behaviour that a core-protocol vector measures.**
H7's ordering rule is the model: the seam is required to sit *behind* the conformance-measured
path, precisely so that satisfying this document cannot move a protocol number.
