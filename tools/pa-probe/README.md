# `pa-probe` — the §4.11 pre-admission-refusal wire census · **Kind A (probe)**

## Status: ACTIVE

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does not judge, it
does not gate, it never appears in a published conformance number, and it always exits 0.

## The surface

`0.8.2.25` landed **§4.11**:

> *"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the wire
> `[MUST]` — correlated by request_id where the id is available, and otherwise as a best-effort
> coded frame carrying no correlation."* … *"The frame obligation belongs to the class; the CODE
> belongs to the cause `[MUST]`."*

**§4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"* and therefore
reaches none of these inputs** — which is why §4.11 exists at all. The pinned check set
(778 @ `7aa6f3de…`) has no vector on this surface either; that was verified by driving the causes
against the reference peer, not assumed.

## Why it is a separate probe and not an eighth `arc-probe` family

**`arc-probe` speaks well-formed frames.** Every one of its families opens a session, sends a
structurally valid envelope, and grades the answer. Four of the arms here — `D1`, `D2`, `D3`, `D7`
— are events at the **framing layer or below the request abstraction**, and nothing else in this
tree reaches them. A peer can be `0 of 15` on `arc-probe` and still close on an oversize length
prefix with no frame at all.

**And the alternative does not scale to what is left.** Both `0.8.2.25` vanguards verified §4.11
with a language-native socket test, which works for `go`, `python`, `rust` and `typescript`. It
does not work for three assembly ports, hand-authored WAT, Forth, COBOL, Oz, Pd, Smalltalk and two
wasm transport seams, where a per-peer socket-level unit test costs more than the fix it verifies
and on several is not available at all. A peer whose §4.11 arms are checked by READING is the
standing rule verbatim: **a guard that was never executed is not a guard.**

## The arms — six measurements, two controls

| id | input | cause is assigned |
|---|---|---|
| `P0_positive_control` | a well-formed EXECUTE | **must be ANSWERED** (any status) |
| `D1_oversize_length_prefix` | a 4-byte prefix declaring 4 GiB−1, no body | `413 payload_too_large` |
| `D2_truncated_frame` | prefix declares 64, 8 bytes delivered, then FIN | `400 invalid_request` |
| `D3_clean_close_control` | FIN at a frame boundary | **must emit NOTHING** |
| `D4_miskeyed_included_entry` | a valid entity filed under a key that is not its `content_hash` | `400 hash_mismatch` |
| `D5_cbor_tag_in_a_data_field` | a CBOR tag in a data-field position | `400 non_canonical_ecf` |
| `D6_undecodable_complete_frame` | a complete frame that never becomes an Envelope | `400 invalid_request` |
| `D7_non_execute_root` | a well-formed envelope whose root is neither EXECUTE nor EXECUTE_RESPONSE | `400 invalid_request` |

`D5` keeps its own code deliberately: §4.11 rules `non_canonical_ecf` non-conformant *"on the
framing arm"* and gives its reason in the same sentence — `ENTITY-CBOR-ENCODING` defines that code
for **CBOR tag-policy violations specifically**, which §6.3 still MUSTs at decode time. The rows
are disjoint by CAUSE, not in conflict.

## The controls — and why the negative one is the load-bearing half

**`P0` (positive, per peer).** A well-formed EXECUTE must be answered on this connection. Without
it, *"the peer emitted nothing"* is equally explained by a hung peer, and every row would be a
reading about our own dial. `trusted: false` **suppresses every measurement row** — it does not sit
beside them.

It asserts only that the frame is **ANSWERED**, never that it is **ALLOWED**. That is what lets one
control serve both launch configurations, and it is why an unauthorized `403` is a passing control.

**`D3` (negative).** A clean close at a frame boundary must emit nothing. **This is the control
`D2` cannot do without, and it is the one a naive fix breaks:** the cheapest way to pass `D2` is to
answer every read error, which turns an ordinary hangup into a refusal of nothing. `D2` and `D3`
differ by exactly one input byte — whether a length prefix was begun — so **a peer that passes
`D2` and fails `D3` has not implemented the distinction, it has deleted it.**

## Grading — three ways to fail, because §4.11 names two of them separately

```
yes                  the coded frame arrived with the code its cause is assigned
no — WRONG CODE      a frame arrived; the code belongs to a different cause
no — DROPPED         nothing arrived, connection still open   (the weaker failure,
                     "precisely because nothing surfaces it")
no — CLOSED          the connection went away with no coded frame  (indistinguishable
                     from a network fault, §4.6)
```

Collapsing those loses the diagnosis: a `WRONG CODE` peer has a mapping to fix, a `DROPPED` peer
has a branch that falls off the end, and a `CLOSED` peer has a `break` where a write belongs. They
are three different repairs.

**`D4` grades a §1.8 mechanism-(b) peer `yes`.** Such a peer discards the wire key and addresses
entities by a validated `content_hash`, so it never detects the mis-key at all: the lookup
**misses**, and §5.2a assigns that miss the row of the step that missed. Requiring the
decode-boundary code of it would make a conformant mechanism non-conformant to satisfy a code the
*other* mechanism's detection point selects — the objection this seat filed against a
one-disposition-for-two-mechanisms ruling, which it would be indefensible to then commit in an
instrument.

## The launch configuration — and why it differs from `arc-probe`'s

`tools/arc-probe/run.sh` removes `--debug-open-grants` from the peer's harness, because under the
degenerate `default → *` seed policy an authorization probe has nothing to bypass.

**§4.11 is not an authorization surface.** Every arm here is refused before any authority is
consulted — at the length prefix, at the decoder, or at the root-type test — so the seed policy
cannot change any answer, and removing the flag would measure the peers in a configuration nobody
ships them in for no gain. `tools/pa-probe/run.sh` therefore runs **each peer's own harness,
unmodified, exactly as the census does**, and says so.

## Running it

```
tools/build-probes.sh pa-probe          # build into output/s4-oracles/
tools/pa-probe/run.sh cobol             # one peer
tools/pa-probe/run.sh go python cobol    # several
NOBUILD=1 tools/pa-probe/run.sh rust-wasm rust-wasm-wasmtime
```

Reports land in `output/scratch/pa/` (gitignored). The runner **classifies by ARTIFACT, never by
exit code or mtime** — a harness that drops the `ORACLE` override at its container boundary runs
the real validator, exits 0, and writes a well-formed 778-check conformance report where a probe
report was expected. The discriminator is one key: a probe report has `cases`.

It also **refuses to start while another container holds the repo mount**, asked once per sweep
rather than once per peer, and the binary **refuses to write any path matching
`status/CONFORMANCE-REPORT`** and exits 4 — every peer's `run-s4.sh` defaults `-json-out` to
exactly that tracked path.

## Instrument validation — recorded, because a detector that has never fired has measured nothing

| peer | state | result |
|---|---|---|
| `go` | swept to `0.8.2.25` (vanguard, independently verified `9 of 9` by its own socket test) | **0 of 6 owed**, both controls PASS |
| `cobol` | unswept | **5 of 6 owed**, both controls PASS — and the three failure classes appear separately (`D2` CLOSED, `D4`/`D5` WRONG CODE, `D6`/`D7` DROPPED) |

The `go` row is agreement with an independently authored test, which is corroboration rather than
proof; the `cobol` row is what says the instrument can fire at all, and that it discriminates the
causes rather than answering one verdict for the class.

## Retirement condition

Stated so it is not left to judgement: **this probe retires when the executed check set carries
vectors on §4.11's framing and decode-boundary arms.** At that point `validate-peer` answers the
question and a second source of truth is a liability, not coverage — delete it rather than keep it.
