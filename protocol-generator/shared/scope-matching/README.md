# `shared/scope-matching/` — the typed scope-match contract (F40)

**Keystone-authored, language-agnostic.** This is *not* a vendored arch fixture — `test-vectors/`
holds those, and keystone does not author canonical bytes. This directory holds the **one reading**
of the 0.8.1 §5.2 typed scope-match rule that every generated peer is fixed against, plus a
runnable reference and a portable vector file.

> **Why it exists.** F40 split the cohort: 42 peers canonicalized every grant dimension, `sql`
> matched id-scope raw. Arch pinned the grammar (`entity-core-protocol` `6285c94`, §5.2). Fixing 42
> peers against 42 independent readings of one paragraph is how the *next* F40 gets created, so the
> reading is pinned here once and each peer ports **this** algorithm and **this** vector file.
>
> **Authority order.** The spec is normative; when the oracle ships the F40 vector it is the
> measurement. This directory is neither — it is keystone's transcription, kept honest by
> `reference.py`, which any peer's port must agree with case-for-case.

## The rule

0.8.1 §5.2 (`entity-core-protocol` `6285c94`):

> The `matches_scope` algorithm (§5.2) accesses these fields structurally but matches each dimension
> **by its scope type** (0.8.1, F40): `path-scope` values (handlers, resources) are canonicalized to
> absolute paths (§1.4) before comparison; `id-scope` values (operations, peers) are compared as
> literal identifiers. The two MUST NOT be interchanged.

> **id-scope pattern grammar (normative — 0.8.1, F40).** An id-scope pattern (`operations`, `peers`)
> matches the **raw value as a literal string** with exactly two wildcard forms: **bare `*`** matches
> any value, and a **trailing `/*`** matches by literal segment-prefix (`compute/*` matches
> `compute/apply`). id-scope **MUST NOT** apply the §5.4 path transforms: **no** leading-`/`
> universal-scope reading, **no** `/*/` interior peer-wildcard, **no** peer-relative→`/{local_peer_id}/…`
> qualification.

## Dimension → scope type (the whole table; there are only four)

| Grant dimension | Scope type | Matcher |
|---|---|---|
| `handlers` | `system/capability/path-scope` | canonicalize, then §5.4 `matches_pattern` |
| `resources` | `system/capability/path-scope` | canonicalize, then §5.4 `matches_pattern` |
| `operations` | `system/capability/id-scope` | **literal** — `matches_id_pattern` below |
| `peers` | `system/capability/id-scope` | **literal** — `matches_id_pattern` below |

## The algorithm (port this, verbatim in your idiom)

```
matches_id_pattern(value, pattern):          ; §5.2 id-scope, 0.8.1 F40
  if pattern == "*":        return true      ; bare star — any value
  if pattern ends with "/*":                 ; literal segment-prefix
    return value starts with pattern[0 : len(pattern)-1]      ; keep the "/", drop the "*"
  return value == pattern                    ; literal identity

matches_scope(value, scope, kind, local_peer_id):
  if kind == id:
    cover = λ pats . any(matches_id_pattern(value, p) for p in pats)
  else:                                      ; kind == path — unchanged §5.2/§5.4 behaviour
    cv = canonicalize(value, local_peer_id)
    cover = λ pats . any(matches_pattern(cv, canonicalize(p, local_peer_id)) for p in pats)
  if not cover(scope.include):  return false
  if scope.exclude is not null and cover(scope.exclude):  return false
  return true
```

Three notes that cost peers time if missed:

1. **`kind` is a required parameter, not a default.** Give it no default value. A default is how a
   later call site silently inherits the wrong matcher — which is the F40 defect, re-introduced.
   Every call site should be forced to name its dimension.
2. **The prefix keeps the slash.** `compute/*` → prefix `compute/`, so it matches `compute/apply`
   but **not** bare `compute`. This is exactly §5.4's `pattern without trailing "*"` rule; only the
   canonicalization is dropped.
3. **Path-form patterns are not *rejected*, they are matched *literally*.** `/*/get` simply fails to
   equal `get`. Do not add a validation error for path syntax in an id dimension — the spec makes it
   a non-match, not a fault.

## Call sites to convert

Every peer routes at least these; grep for the scope-match helper and check each caller:

| Call site | Spec | Dimension → kind |
|---|---|---|
| `check_permission` operation check | §5.2 | `operations` → **id** |
| `check_permission` handler check | §5.2 | `handlers` → path |
| `check_permission` peer check | §5.2 | `peers` → **id** |
| `check_permission` resource check | §5.2 | `resources` → path |
| `check_path_permission` (tree handler, defence-in-depth) | §6.3 | same four |
| capability-request / grant validation | §6.7 | same four |

**`scope_subset` (§5.5a delegation) is deliberately NOT converted here.** The F40 pin names
`matches_scope`; the §5.5a `scope_subset` pseudocode still canonicalizes uniformly, and whether F40
extends to it is an open question routed to arch
(`protocol-generator/shared/findings/bucket-B-cohort-application.md`). Peers leave
`scope_subset` alone until arch rules — changing it on our own guess is how the cohort re-splits.

## Files

| File | What |
|---|---|
| `id-scope-vectors.json` | Portable case set — the peer-side accept-path test every peer ports. |
| `reference.py` | Runnable reference matcher + fixture runner. `python3 reference.py` → per-case verdicts. |

`{local}` and `{remote}` in the vector file are **placeholders** each peer substitutes with a real
Base58 peer-id before running (canonicalization only cares that the local frame is a well-formed
segment). `scope_type` on each case says which matcher the case exercises; `expect` is the value
`matches_scope` must return.

Cases carrying `"informative": true` are *precision* cases (they pin what "literal" means) rather
than gate cases — a peer that skips them is not non-conformant, but the rest are mandatory.

## Why a peer-side test at all

The oracle's F40 vector had not landed when this was written, and even once it does, a
rejection-only probe would let a canonicalizing peer pass — the standing keystone countermeasure is
an **accept-path** unit test in the direction the oracle cannot cover
(`AGENTS.md`, "conformance-green can be vacuous"). `id.exclude.pathform` is the case that matters
most: on the canonicalizing (pre-F40) reading it denies, on the conformant reading it **allows**, so
it is the one case a peer cannot pass by accident.
