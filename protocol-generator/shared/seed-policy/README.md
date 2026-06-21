# Seed-policy convention (V7 §6.9a Peer Authority Bootstrap)

**Status:** keystone-owned cross-peer convention · authored in Phase B · applies to every generated `entity-core-protocol-<lang>` peer.

V7 §6.9a pins the **invariant** (a conformant peer establishes operable owner authority over its own namespace at init, and derives authenticate-time grants from a declared identity → capability seed policy read from `system/capability/policy/*`). The SDK builder shape is the spec's; the **cross-peer file format and CLI convention are keystone's** (§6.9a §3.6 split). This directory is that convention — so all generated peers are *operationally identical* on the bootstrap-authority surface (the S8/S6 convergence foreclosed against divergence).

This is a **convention doc**, not a normative spec. The normative contract is §6.9a + §6.9a.0–§6.9a.4 in `ENTITY-CORE-PROTOCOL.md`. Where this doc and the spec differ, the spec wins; flag the drift.

---

## 1. What a seed policy is

A declared mapping `grantee_identity → (scope, bounds)`, materialized into the tree at L0 (pre-capability) under `system/capability/policy/{key}` and consulted at §4.6 authenticate. It replaces the hardcoded `initialGrants()` / `openGrants()` fork that §6.9a declares **non-conformant**.

Two entries are always present (the §6.9a.0 minimum):

- **`self`** — the **peer-owner capability**: grantee = the peer's own identity, scope = full over `/{peer_id}/*`. A real root capability (not a template) materialized eagerly at peer-init. The generated peers use the **detached-signature shape uniformly** (§6.9a.0 shape 1): a `system/capability/token` at `system/capability/policy/{self_identity_hash_hex}`, self-signed per §5.5, signature at `system/signature/{cap_hash}`. (Keystone S8 decision — both §6.9a.0 shapes are floor-conformant, but generated peers standardize on detached-signature for *all* self-issued caps so the generated cohort never splits across shapes; detached is also the shape that supports cross-peer relay if ever needed.)
- **`default`** — the fallback scope for any other authenticated identity not explicitly named. A scope template (policy-entry), default = the §4.4 discovery floor.

Additional entries MAY name specific operator / admin / reader identities.

## 2. Authenticate-time derivation (v7.62 §8 + v7.64 dual-form)

```
on authenticate(remote_identity):                 # §4.6 — identity established
  identity_hash_hex := hex(content_hash(remote_identity_entity))
  peer_id_b58       := base58_form(remote_peer_id)
  policy_entry := read("system/capability/policy/" + identity_hash_hex)   # v7.64 dual-form
              ?? read("system/capability/policy/" + peer_id_b58)          # hex → Base58 → default
              ?? read("system/capability/policy/default")
  grant := UNION(discovery_floor, policy_entry.grant)   # v7.62 §8 union
  include grant in authenticate response.included
```

Subsequent `capability:request` resolves via SUBSET per v7.62 §8. First-contact canonicalization (Base58 → hex) is SHOULD; timing is impl-defined (eager at authenticate, or deferred to first request-time cap-match — both conformant).

## 3. File format

A seed-policy file is JSON: an object with an `entries` array. Each entry has a `grantee` key and a `grants` list (the §3.6 grant-entry shape), plus optional `bounds`. Schema: [`seed-policy.schema.json`](seed-policy.schema.json). Examples: [`examples/`](examples/).

```jsonc
{
  "version": 1,
  "entries": [
    {
      "grantee": "default",              // "self" | "default" | <identity_hash_hex> | <base58_peer_id>
      "grants": [
        { "handlers":   { "include": ["system/tree"] },
          "resources":  { "include": ["system/type/*", "system/handler/*"] },
          "operations": { "include": ["get"] } },
        { "handlers":   { "include": ["system/capability"] },
          "resources":  { "include": [] },
          "operations": { "include": ["request"] } }
      ]
      // "bounds": { "not_before": <ms>, "expires_at": <ms> }   // optional
    }
  ]
}
```

**Key forms** (§6.9a.1):
- `"self"` — sugar for the peer's own identity-hash-hex (always available locally; the owner cap). The generated peer materializes the owner cap regardless of whether `self` appears in the file.
- `"default"` — the literal sentinel `system/capability/policy/default` (v7.63 F8 — renamed from `*`).
- `<identity_hash_hex>` — 66 hex chars (SHA-256) / 98 (SHA-384), the §3.5 invariant-pointer hex of the grantee's `system/peer` entity content hash. Canonical.
- `<base58_peer_id>` — the grantee's Base58 PeerID (pre-contact affordance, when only the peer-id is known). Canonicalized to hex on first contact.

A `grants` value of a single wide-open grant under `default` (`{handlers:["*"], resources:["*","/*/*"], operations:["*"]}`) is the degenerate `default → *` policy — i.e. the retired `--debug-open-grants`. **Deprecated in v7.74, removed in v7.75.**

## 4. CLI convention (every generated peer, identical)

| Flag | Meaning |
|---|---|
| `--owner-identity <peer_id>` | The identity that owns this peer's namespace (the `self` entry's grantee). Default: the peer's own identity (self). |
| `--seed-policy <file>` | Path to a seed-policy JSON file. When omitted, the conformant default policy (`default` = §4.4 discovery floor) is used. |
| `--debug-open-grants` | **DEPRECATED** (v7.74; removed v7.75). Selects the degenerate `default → *` seed policy. Routes through the real §6.9a mechanism (NOT a hardcoded fork) and prints a deprecation warning. Prefer `--seed-policy` with a wide-open `default` entry if the open surface is genuinely needed (e.g. driving the full validate-peer grant-gated surface). |

The conformance harness drives a real owner seed (or `--debug-open-grants`'s degenerate equivalent) so the suite tests the real authority mechanism end-to-end, not a bypass.

## 5. Builder API (SDK shape, per-language idiom)

Every peer exposes, in its language idiom:
- `with_owner_identity(identity)` — set the `self`-entry grantee.
- `with_seed_policy(policy)` — supply a parsed seed policy.
- `with_seed_policy_from_file(path)` — load + parse a seed-policy file.

In the current generation (Phase B), this is the constructor `seedPolicy` parameter:
- **C#** — `new Peer(seedPolicy: SeedPolicy.Standard() | .DebugOpen() | .Of(...))`.
- **TS** — `new Peer({ seedPolicy: SeedPolicy.standard() | .debugOpen() | .of(...) })`.
- **OCaml** — `Peer.create ~seed ~open_grants` (the `open_grants` flag selects the degenerate default; a `~seed_policy` parameter is the forward shape).

`with_seed_policy_from_file` (JSON parse) is the next increment; the in-code builders above are the floor.

## 6. Generator template (S3 peer-machinery)

When generating a peer, the bootstrap step MUST:

1. Materialize the `self`-owner capability at L0 (detached-signature shape): a root cap, full local-namespace scope, grantee = owner identity, written at `system/capability/policy/{owner_hash_hex}` with its self-signature at `system/signature/{cap_hash}`.
2. Materialize the `default` entry (and any named entries) as policy-entries (or detached-sig caps) at `system/capability/policy/{key}`.
3. Wire §4.6 authenticate to the dual-form lookup of §2 (read both §6.9a.0 shapes: a cap-token whose detached sig verifies, or a policy-entry's `grants`), UNION'd with the discovery floor.
4. Expose the §4 CLI convention + the §5 builder API.
5. Retire any `initialGrants()/openGrants()` fork — it is non-conformant (§6.9a).

This convention is the source of truth the `/entity-rosetta` peer phase reads when emitting the bootstrap-authority surface.
