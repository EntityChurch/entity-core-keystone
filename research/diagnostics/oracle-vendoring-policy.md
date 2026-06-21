# Oracle vendoring policy — when & why we update `validate-peer`

**Status:** operative convention. Companion to `validate-peer-usage.md`.

The keystone's conformance gate (S5/S7/S8) is **defined against a Go-built binary**:
`validate-peer` (the live behavioral oracle) and `entity-peer` (the reference B-role
peer used by the §10.2 origination-core probe). Both are produced from the sibling
`entity-core-go` repo — the reference implementation *and* the conformance tool. This
doc pins down what that dependency is, how we keep it reproducible, and the rule for
**when** to re-vendor and **why**.

---

## 1. What we depend on (the dependency surface)

| Artifact | Source | Role | Hard dependency? |
|---|---|---|---|
| `validate-peer` | `entity-core-go/cmd/validate-peer` (+ `cmd/internal/validate/*`) | The oracle: drives a live peer through the category suite, emits the PASS/FAIL verdict. | **Yes** — it *is* the gate. |
| `entity-peer` | `entity-core-go/cmd/entity-peer` | Reference peer; the B-role dial target for §10.2 `origination-core` (`run-origination-core.sh`). | Soft — only the reference-peer-gated probe needs it. Our peers' own §7a reentry surface is what's actually tested. |
| `peer-manager` | `entity-core-go/cmd/peer-manager` | Multi-peer convergence harness; not used by `--profile core`. | No (extension/full only). |

Both binaries are **gitignored** (`**/output/`) and live **only** at repo-root
`output/s4-oracles/{validate-peer,entity-peer}`. They are *local tools*, not committed
source — the keystone validates *against* them, it does not derive peer code *from* them
(clean-room boundary). The pinned commit is recorded in each peer's `status/PHASE-S4.md`
and in `CONFORMANCE-MATRIX.md` (the "Oracle commit" column).

> **Strategic note for release.** Our conformance story currently requires a consumer to
> be able to *build the Go oracle*. That is fine for the keystone (we have the toolchain)
> but is a real coupling to surface to adopters: a peer's "PASS" is reproducible only with
> the pinned `entity-core-go` commit + Go toolchain. The byte-level codec corpus
> (`shared/test-vectors/`) is language-agnostic and self-contained; the *live behavioral*
> gate is not. Making the behavioral suite portable (vector-replayable, or a shipped
> oracle binary per platform) is an open release-track question, not solved here.

---

## 2. Provenance hygiene — build ONCE into repo-root, never per-peer

**The 649-vs-653 lesson.** Two binaries built from the *same* commit label
(`33f35fd`) differed by +4 warns because they were built at different times / trees and
dropped into different locations (one peer-local, one repo-root). Conformance numbers that
should be identical diverged purely from build provenance.

Rules:
1. **One oracle, one location.** Build into repo-root `output/s4-oracles/` only. Every
   peer's `run-s4.sh` / `run-origination-core.sh` defaults `ORACLE`/`REFPEER` to
   `/work/output/s4-oracles/...` (the mount maps repo-root → `/work`). Never build a
   per-peer copy under `protocol-generator/<lang>/output/`.
2. **Record the commit, not just the label.** "33f35fd" is not enough provenance if two
   builds disagree — the figure is `N·0F @ <commit>`, and the binary under
   `output/s4-oracles/` is the one source of truth at any moment.
3. **Preserve the prior binary** as `*.<oldcommit>.bak` on re-vendor, so a regression is
   bisectable.

---

## 3. The build procedure (reproducible)

> **Scripted.** This procedure is now `tools/oracle-bootstrap.sh` — the
> one-shot way to make the oracle from a fresh clone. Run it with no args and it builds
> the pin in `tools/oracle-pin.env`, installs into repo-root `output/s4-oracles/`, backs
> up the prior binaries, and writes a local `PROVENANCE.txt`. The manual steps below are
> what the script automates (kept for transparency / when the container isn't built).

**Mirror-stable provenance (the R1 fix).** The pin in `tools/oracle-pin.env` is *committed*
(the binaries are gitignored, so this env file is the only committed record of the gate).
It carries `core_gate_sha256` = `sha256(cmd/internal/validate/profile.go)` — the category
set that defines `--profile core`. **That hash, not the commit, is the identity that
matters:** if a rebuilt oracle reproduces it, its core surface is identical to what the
17-peer cohort converged against, regardless of what the commit hash became after a public
mirror-cutover. The script's fallback: if the pinned `ref` no longer resolves in the
sibling repo (history rewritten by the mirror), it builds the **sibling working-tree HEAD**
and warns — so "clone keystone + have entity-core-go next to it → run conformance" keeps
working with no commit-hash dependency. (`ec048…`-style hashes become decoration; the
`core_gate_sha256` is the contract.)

The manual procedure, done entirely in the `entity-core-keystone/go:latest` container,
against an **isolated archive** of the go commit (NOT the live `entity-core-go` working
tree — clean-room):

```sh
# 1. archive the target commit OUTSIDE entity-core-go
TMP=$(mktemp -d); (cd ../entity-core-go && git archive <COMMIT>) | tar -x -C "$TMP"
rm -f "$TMP/mise.toml"

# 2. build validate-peer + entity-peer (workspace: cmd uses ./core ./ext via go.work)
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --security-opt label=disable -v "$TMP":/src:Z -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS= entity-core-keystone/go:latest bash -c '
    export GOWORK=off
    for m in core ext cmd; do (cd /src/$m && go mod tidy); done   # populate go.sum
    unset GOWORK; cd /src/cmd
    go build -o /src/_out/validate-peer ./validate-peer
    go build -o /src/_out/entity-peer  ./entity-peer'

# 3. install into repo-root (back up the old one first)
cp output/s4-oracles/validate-peer output/s4-oracles/validate-peer.<OLD>.bak
cp "$TMP/_out/validate-peer" output/s4-oracles/validate-peer
cp "$TMP/_out/entity-peer"   output/s4-oracles/entity-peer
chmod +x output/s4-oracles/{validate-peer,entity-peer}; rm -rf "$TMP"
```

The build needs network once (module download); the *conformance run* is always
`--network=none` (oracle + peer share one container loopback).

---

## 4. WHEN to re-vendor (the decision rule)

Re-vendor is **gated on a core-profile-relevant change**, not on every go commit. Decide
with a single diff before building:

```sh
cd ../entity-core-go
git diff <VENDORED>..<TARGET> -- cmd/internal/validate/profile.go      # the core category SET
git diff --stat <VENDORED>..<TARGET> -- cmd/internal/validate/         # gate implementations
```

| Trigger | Re-vendor? | Why |
|---|---|---|
| `profile.go` core category list changed | **Yes — Tier-1 immediately** | The gate's surface moved; every peer must re-converge. |
| A core gate's *logic* changed (suite.go core path, typesystem core floor, §10.1 register, §7a handlers, §7b concurrency, resource_bounds) | **Yes** | A check that was WARN/SKIP may become FAIL, or a new core check appears. |
| A spec amendment landed that Go implemented as a **new/changed core gate** | **Yes** (this is the steady-state loop) | The keystone exists to track spec refinement; the oracle is how an amendment reaches the peers. |
| Only **extension** categories changed (relay, route, network, transport_family, WebSocket, encryption, peer-issued/registry, published_root, discovery…) | **Optional / cosmetic** | These auto-skip or matched-if-present-WARN under `--profile core`; they move the *total* and *warn/skip* counts but never `passed`/`failed`. Re-vendoring only changes the headline number, not the verdict. |
| Provenance/hygiene re-pin (no source change) | No | Don't rebuild "the same" commit — you risk a phantom warn delta (§2). |

**Worked example (`33f35fd` → go HEAD `e8524ed`):** the full `cmd/`
diff was ~5,300 insertions, but `validate-peer/main.go` was **+15 lines** (a `-ws-peers`
flag, extension), `profile.go` was **unchanged**, and everything else under
`cmd/internal/validate/` was relay/route/transport/publish (extension). Predicted impact:
core unaffected, total drifts up by extension noise. Confirmed: every peer went
**653·0F → 665·0F** — `passed` held at 292, the +12 was entirely `warned`/`skipped`. This
is the signature of an extension-only oracle bump: **re-vendor if you want one comparable
number cohort-wide, but no peer code changes and no verdict is at risk.**

---

## 5. WHY we pin at all (and don't float)

- **The oracle defines convergence (S8).** "Reproducible" here means *statistical
  convergence on conformance against a fixed oracle*. A floating oracle makes "PASS"
  unfalsifiable — you can't tell a peer regression from an oracle drift.
- **Supply-chain (S11).** The oracle is a dependency like any other: pinned, reproducible,
  re-pinned deliberately and reviewed — never incidental drift.
- **Bisectability.** When a peer flips to FAIL, the first question is "peer or oracle?".
  A pinned commit + preserved `.bak` answers it in one diff.

---

## 6. After re-vendoring — the run discipline

1. **Tier-1 first** (OCaml · Swift · Haskell · Go · Lean) — must converge to 0-FAIL before
   the new oracle is considered landed (tier policy, `CONFORMANCE-MATRIX.md` §4).
2. Tier-2 / Tier-3 catch up with capacity.
3. Update `CONFORMANCE-MATRIX.md` (Oracle commit + `--profile core` columns) and the
   per-peer `status/CONFORMANCE-REPORT.json` (regenerated by the run).
4. Record the bump in a stewardship scorecard handoff (the `HANDOFF-TO-ARCH-*RERUN*`
   pattern) so arch sees the cohort tracked the amendment.
