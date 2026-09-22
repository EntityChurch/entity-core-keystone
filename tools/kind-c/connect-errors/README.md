# `kind-c/connect-errors` — §4.7 connection-error table · **Kind C (independent check)**

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. This is the first Kind C artifact in
the repo.

## The term this exists under

> **An official full-green pass requires the independent test suite.** This is not it.

A peer is conformant because **`validate-peer`** — a suite this repo does not author — says so.
Nothing here supplements that verdict, overrides it, or enters a published number. That is the
operator's condition (2026-09-07) on which Kind C authorship was unblocked, and it is the reason
this can exist without becoming the overclaim the hold was protecting against: *the exam we do not
write is still the exam that counts.*

**Enforced structurally, not by this paragraph.** The binary refuses to write any path matching
`status/CONFORMANCE-REPORT` and exits 4 — because every peer's `run-s4.sh` defaults `-json-out` to
exactly that tracked path, so a bare `./run-s4.sh` under `ORACLE=` is the invocation where the
mistake is easiest to make and hardest to see. `tools/kind-c-gate.py` (in `make lint`) asserts the
same boundary over the tree and prints its counts.

## What it checks

The §4.7 connection-error table, plus the §4.5 negotiation rules that feed it: **12 MUST cases and
1 ADVISORY**, each carrying the sentence it was authored from, cited by section against
`protocol-generator/shared/spec-data/v0.8.2.11/` (SHA-256-pinned in that snapshot's `MANIFEST.md`).

The ADVISORY case is the point of the distinction. §4.5 says hello-time rejection of an
unverifiable `key_type` is *canonical guidance* and that rejecting later at `authenticate` is
*conformant*. Both answers are recorded and neither is scored a defect. **Flattening a MAY into a
MUST is how a second test set starts legislating instead of measuring**, which is the failure mode
that makes an independent lineage dangerous rather than useful.

## Derivation — the constraint that makes this worth having

**Authored from the spec, never from the oracle's source.** Reading the oracle to match its code
inverts the keystone's purpose: spec-vs-oracle divergence is the finding this structure exists to
produce, and it is unreachable if the check is derived from the thing it is meant to be independent
of. The wire plumbing (CBOR encoder, framing, handshake session) is copied from `tools/put-probe`
and that is deliberate and harmless — **transport is not semantics**, and that code has been driven
against all 46 peers, so borrowing it removes a class of instrument bugs rather than adding one.

## The controls — three, and they answer different questions

| Control | Asks | Failure means |
|---|---|---|
| `positive_valid_hello` | does a plain valid hello answer 200? | **the fault is ours.** The peer is `trusted: false`, **no case is executed**, exit 3 |
| `differential_registered_handler_501` | is an unknown op on a *registered non-connect* handler still `501 unsupported_operation`? | the peer made §4.7 row 10 global and traded §3.3's 501 row away |
| `differential_foreign_namespace_established` | is the same foreign URI refused `400 invalid_request` once **established**? | the URI is not recognised as foreign — **suspect this check, not the peer** |

**The second control is the concrete argument for a second lineage.** §4.7 row 10 makes an unknown
*connect* operation `400`; §3.3's 501 row makes an unknown operation on every *other* registered
handler `501`. The rules are adjacent, opposite, and one helper apart — a peer can satisfy row 10 by
making every unknown operation `400`, which trades one contract for another and looks exactly like a
fix. The oracle scores both, in different categories. Measured **together, in one instrument**, the
trade is visible; measured apart it is not.

**The third control was wrong on its first cut, and the way it was wrong is the lesson.** Sent
*unsigned*, it answered `401 authentication_failed` — the same status as the case it exists to
disambiguate — because an EXECUTE with no verified signer is auth-class by §5.2a whatever its
address. It varied **two** things at once (connection state *and* signature) and therefore
discriminated nothing. A control that cannot separate its own two explanations is not a control.

## Reading the output

- `cases N/N executed` is printed and asserted. A gate that examines zero things prints the same
  word as one that examines thirteen; a mismatch is exit 5 regardless of how the cases scored.
- A `preestablish_foreign_namespace` FAIL is reported **with** its differential's verdict and an
  explicit `note` saying which of the two readings the evidence supports. A FAIL whose differential
  also failed is *not* a finding about the peer, and the artifact says so in its own words rather
  than leaving the reader to infer it.
- `DEFERRED` appears only on ADVISORY cases and means *the other conformant answer* — not a defect.

## Running it

It parses argv by hand and tolerates the real validator's flags, so it drops into any peer's
harness unchanged:

```
tools/run-cohort-census.sh --probe kind-c-connect-errors [<peer>...]   # writes output/scratch/kind-c-connect-errors/
output/s4-oracles/kind-c-connect-errors -addr 127.0.0.1:7777 -peer go
output/s4-oracles/kind-c-connect-errors -dump                          # the case table, no peer needed
```

Exit codes: `0` all MUST pass · `1` a MUST failed or errored · `2` a differential control failed ·
`3` untrusted (positive control failed — our fault) · `4` refused to write a tracked report ·
`5` executed count ≠ defined count.

Build: `cd tools/kind-c/connect-errors && CGO_ENABLED=0 GOWORK=off go build -o ../../../output/s4-oracles/kind-c-connect-errors .`

## Lifetime

Unlike a Kind A probe, this does **not** expire when the oracle ships a vector on the surface — that
is the moment it starts doing its job, because from then on agreement is corroboration between two
independently authored readings and disagreement is a routable finding. What it must never become is
a private disagreement carried forward; **divergence is routed, always, and promptly.**
