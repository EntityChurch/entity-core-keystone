# The keystone peer contract suite

**What it answers:** *is peer P, at this commit, something anyone can run, embed and extend through
the keystone interface?* Yes or no, per requirement, recomputable from committed evidence.

| File | What it is |
|---|---|
| `CONTRACT-DRAFT.md` | the provisional contract (v2.0-draft.1): every requirement, what defines it, what observes it |
| `requirements.toml` | the same requirement set as data — level, evidence, the driver cases and controls that decide each |
| `FIXTURE-HOST.md` | the exact contract host every language writes so one driver can measure it |
| `tools/peer-contract/driver/` | the wire driver — **one Go program for every language** |
| `tools/peer-contract/run.sh` | build the driver → the peer's `run-contract.sh` → `report.py` |
| `tools/peer-contract/plant.py` | proves the suite can fail on that peer (named defects must turn named cases red) |
| `tools/peer-contract/report.py` | computes the verdict; `--check` recomputes committed reports in `make lint` |

## The loop

```
consumer asks: "we want peer P for extension X"
        │
        ▼
tools/peer-contract/run.sh P          ──►  certified?  ── yes ──►  hand off: P's status/KEYSTONE-PEER-REPORT.json
        │                                     │
        │ P has no run-contract.sh            no: the report names every failing row
        ▼                                     ▼
bring P up (below)  ◄──────────────  implement the missing surface in P, re-run
```

A consumer never patches a peer and never re-measures what the report certifies. A consumer finding
against a certified peer is a defect in **this suite** first: it certified something false.

## Bringing a language up

A peer that already passes `--profile core` needs four things. Nothing in the suite changes.

1. **The surfaces.** `run_host(argv, configure)` as a library function; `register_handler(spec, body)
   → handle`; consumers registrable and removable after construction; the handler context; the
   path-permission predicate; an evaluator seam if the peer carries the module. `CONTRACT-DRAFT.md`
   §2–§4 says what each must do and which SDK section defines it.
2. **A contract host** in a separate package that depends only on the peer's package:
   `run_host(argv, install_fixtures)`, with the fixtures exactly as `FIXTURE-HOST.md` §2 specifies.
   `protocol-generator/rust/contract/host/src/main.rs` is the worked example (~330 lines).
3. **Local tests** for the three requirements the wire cannot observe, named with the requirement
   prefix: `embed_create__*`, `context_unforgeable__*` (the refusal and its positive control),
   `context_authority_chain__*`.
4. **`run-contract.sh`** (build both hosts, run the driver, run the local tests into `local.txt`),
   **`contract/artifacts.env`**, **`contract/bindings.toml`** (the language's spelling of each
   requirement) and **`contract/plants.json`** (a defect per requirement family, each naming the
   cases it must turn red).

Then:

```
tools/peer-contract/run.sh <peer>                 # scratch report; iterate until certified
tools/peer-contract/plant.py <peer> --to-status   # prove the suite goes red on this peer
tools/peer-contract/run.sh <peer> --to-status     # publish the report (it embeds the plant results)
```

## What `certified` means, exactly

- the peer's **committed** core conformance report: 0 failed at the pinned executed check set, no
  starved category;
- every **REQUIRED** row `pass` — for a driver row, every listed case passed **and** a listed control
  held in the same run; for a local row, at least `min_tests` prefixed tests ran and none failed;
- every **MODULE** row `pass`, or `declined` with a reason in `contract/declined.toml`.

A missing row is `unknown`, never `pass`. What the suite does not yet measure is listed as pending in
`CONTRACT-DRAFT.md` §5 and is not implied by a certification.

**What a certification is not.** It is a keystone measurement of keystone's own peer against
keystone's own contract. It is not core-protocol conformance (that is the oracle's, and is an input),
and it is not independent convergence.
