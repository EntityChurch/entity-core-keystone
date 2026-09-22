# `host-seam-probe` — the H1 dispatch census · **Kind A (probe)**

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does not judge, it
does not gate, and it never appears in a published conformance number.

## The surface

**`docs/spec/SPEC-KEYSTONE-PEER.md` H1** — *a handler installed after construction is reachable by
dispatch* — at **v1.0**, digest `62e1a1dd156bfd3e7760a86bf4b75b0433bd5e234d37fd5bc79c5823c3cd938a`.
The wire mechanics are `ENTITY-CORE-PROTOCOL` §6.13(a) + §11.6.1 as pinned in
`protocol-generator/shared/spec-data/v0.8.2.11/`.

H1's own text says a profile naming only the registration call cannot tell a live host from a dead
map. This is the instrument that tells them apart, in the **entity-native (model 3)** shape: a body
stored as a `compute/literal` expression and reached through `expression_path`.

## Why it exists — nothing in the conformance set answers this

Verified against the pinned oracle (`78db4a9`, executed set `7aa6f3de…`), not assumed:

| check | what it actually does |
|---|---|
| `core_register_body_binding` | asserts the §11.6.1 entities were **bound**. Its PASS message is *"entity-native echo body bound at …"*. It never dispatches. |
| `unsupported_operation_on_registered_handler` | its `registeredURI` is **`system/tree`** — a *bootstrap* handler. "Registered" means present, not third-party-installed. |
| `validate_echo_dispatch` | dispatches `system/validate/echo`, also a built-in. The oracle's own comment records the dispatch half was deliberately *"moved off compute/literal"*. |

So a peer can bind all four §11.6.1 writes, score `778 · 0F`, and have nowhere for a body to run.

## What it does, per peer, in one session

1. **bind** — `system/tree:put` a `compute/literal` (value `42`) at `<pattern>/expr`
2. **register** — `system/handler:register` naming that `expression_path`
3. **landed** — `system/tree:get` the handler entity, and assert it carries `expression_path`
4. **DISPATCH** — an EXECUTE at `<pattern>`. **This is the measurement.**
5. **negative control** — the same dispatch at a never-registered sibling

The register request shape is the **oracle's own** (`sendCoreRegister`,
`cmd/internal/validate/core_register_gate.go`), not one derived here: it demonstrably round-trips on
the cohort, so re-deriving it would put a probe-side variable in front of the measurement.

The pattern sits under `app/validate/core-register/`, the one prefix the connection grants are known
to cover on all 46 peers — `core_register_body_binding` PASSes cohort-wide and SKIPs when the grants
do not reach. A fresh prefix would risk measuring the seed policy instead of the seam.

## Controls — all three mandatory, all three executed

- **Positive.** A plain valid `put` MUST answer 200 on a fresh connection. A peer whose control fails
  is `trusted: false` and its measurement is **suppressed**, not reported.
- **Landed.** Step 3, and it asserts the **field the measurement depends on**, not merely that
  something was written. *This is the control that caught the probe's own first fault* — see below.
- **Differential / negative.** The same dispatch at a sibling that was never registered MUST answer
  404. It varies exactly **one** thing — whether the register happened. Without it, a `404` at step 4
  cannot be told from a peer whose resolution never reached our path, and a `200` cannot be told from
  a peer that answers 200 to everything.

**Inherited from `put-probe`, with its scope stated:** the handshake capability material is replayed
as raw byte spans and every forwarded entry is re-decoded and re-hashed against the map key it is
filed under (§3.1). That licenses *agreement between an entry and its key* and **says nothing about
the keys being unique** — the encoder deduplicates by construction and reports the dropped count.

## Its first two runs were about the probe — budget them

The first run reported `go` as `BOUND-NOT-EVALUATED`: register 200, entity bound, dispatch
`501 no_handler_body`. `go` demonstrably *has* an evaluator.

The probe had encoded the register-request's `manifest` as a **full entity**
(`{type, data, content_hash}`) rather than a bare map. The peer's
`MapField(manifest, "expression_path")` therefore looked at the entity's top level, found nothing,
and bound a handler with **no body reference** — while still answering 200. The oracle's own
`RegisterRequestData` has `Manifest HandlerManifestData` as a plain struct field; `ToEntity` is
called on the *request*, never on the manifest.

Left unfixed, the roster run would have published **all 46 peers as non-hosts**. What made it
findable in one step was extending the LANDED control from *"was something bound"* to *"does what was
bound carry the field step 4 depends on"*.

## Verdicts

Deliberately not pass/fail. `BOUND-NOT-EVALUATED` is a **conformant** state for a core peer: §6.13(a)
is an extension surface, and a peer that binds correctly and has no evaluator is honest. What it is
not is a host.

| verdict | meaning |
|---|---|
| `EVALUATES` | dispatch answered 200 **and** returned the planted literal — the expression ran |
| `EVALUATES-UNVERIFIED` | 200, but the result did not carry the literal; reachable, not proven |
| `BOUND-NOT-EVALUATED` | bound with `expression_path`, dispatch 501 — stores a body, no evaluator |
| `REGISTER-DROPPED-EXPRESSION-PATH` | register answered 200 and bound a handler with no body reference |
| `NOT-RESOLVED` | 404 at a pattern register reported binding — §6.6 does not see what register wrote |
| `REGISTER-REFUSED` / `AUTHZ-REFUSED` / `CONTROL-FAILED` / `UNTRUSTED` | the row is not an H1 answer |

**`REGISTER-DROPPED-EXPRESSION-PATH` is resolved by the cohort, not by the peer.** From one peer it
cannot be told from a probe-side request fault. From the roster it can: if other peers persisted the
identical request, the peer is discarding the body reference at register. Filing it as a control
failure would blame ourselves for a peer property; filing it as a defect from one observation would
be the overclaim in the other direction.

## Running it

```
tools/build-probes.sh host-seam-probe              # → output/s4-oracles/host-seam-probe
tools/run-cohort-census.sh --probe host-seam-probe # all 46 → output/scratch/host-seam-probe/
tools/run-cohort-census.sh --probe host-seam-probe go rust   # a subset
output/s4-oracles/host-seam-probe -dump            # the exact bytes it sends
```

Per-peer JSON is gitignored: **re-run rather than cite a copy**, and scope any cohort read to peers
this run measured — a mixed-age probe directory reads as a measurement and is not one. A conformance
report appearing in `output/scratch/host-seam-probe/` means the `ORACLE` override was **dropped** at
a container boundary and the peer ran the real validator; classify by output *shape*, never by
trusting the harness.

## Superseding vector

**None yet.** No oracle check dispatches a third-party-installed body (see the table above). If one
ships, this probe is retired on that check set: it stops being cited as evidence, the source stays
for provenance and for the controls, and the finding keeps its measurement and its date.
