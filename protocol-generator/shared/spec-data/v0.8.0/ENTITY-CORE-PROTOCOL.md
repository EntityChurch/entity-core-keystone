# Entity Core Protocol — Normative Specification

**Version**: 0.8.0

**Status**: Active
**Supersedes**: ENTITY-CORE-PROTOCOL-V4.md
**Encoding**: ENTITY-CBOR-ENCODING.md (ECF — Entity Canonical Form, CBOR per RFC 8949 §4.2)

---

> **Path notation.** Paths in this document use peer-relative notation (without leading `/{peer_id}/`). All peer-relative paths resolve to the local peer's namespace: `system/tree` means `/{local_peer_id}/system/tree`. Every path in the entity tree is absolute at rest — rooted at a peer identity. See §1.4 for the path model. Cross-peer examples use absolute paths with explicit peer identities.

## 1. Foundations

### 1.1 Entity

The fundamental data unit. A typed payload with content-addressed identity.

```
Entity := {
  type:         string          ; Semantic type path
  data:         any             ; Typed payload
  content_hash: bytes           ; system/hash — format code + digest (§1.2)
}
```

All entities MUST include `content_hash`.

The entity is fundamentally `{type, data}` — content_hash is a computed property of that identity (§1.2). The protocol requires content_hash to always be present because the system uses it everywhere entities travel: for deduplication (content store lookup), verification (validate on receipt), referencing (hash values in data fields), and embedding (inner entity hash is part of outer entity bytes).

> Note: `entity` here refers to the abstract structural root `{type, data}`. Once a content hash has been resolved into a slot, the materialized form `{type, data, content_hash}` is the `core/entity` type used as a `type_ref` marker in field specs — see ENTITY-NATIVE-TYPE-SYSTEM.md §2.7.1, §3.1.1, and §8.1.

Implementations MAY optimize internal representations (lazy hash computation, caching, omitting the hash in memory structures) as long as entities include `content_hash` at every protocol boundary: handler returns, entity embedding (params, results, envelope included maps), storage, and wire transport. The observable behavior is that entities always carry their identity hash.

**Entity references** are `system/hash` byte strings in data fields. Entities reference other entities by including their content hash in the data payload.

**Envelope structure** bundles a root entity with referenced entities:

```
; Wire format — all hashes are flat byte strings (system/hash = bstr)
envelope := {
  root: {
    type: "system/protocol/execute",
    data: {
      request_id: "...",
      uri: "...",
      operation: "...",
      resource: {targets: ["peer_id/local/files/readme.md"]},
      params: {
        type: "system/tree/get-request",
        data: {},
        content_hash: h'00...'                     ; 33 bytes
      },
      author: h'00...',                            ; system/hash (33 bytes)
      capability: h'00...'                         ; system/hash (33 bytes)
    },
    content_hash: h'00...'                         ; 33 bytes
  },
  included: {
    h'00...': {                                    ; key = content_hash (bytes)
      type: "system/peer",
      data: { public_key, key_type },              ; v7.65: peer_id exits hashable basis
      content_hash: h'00...'
    },
    h'00...': {
      type: "system/signature",
      data: { target: h'00...', algorithm, signature, signer: h'00...' },
      content_hash: h'00...'
    },
    h'00...': {
      type: "system/capability/token",
      data: { grants, granter: h'00...', grantee: h'00...', created_at, parent: h'00...', ... },
      content_hash: h'00...'
    },
    ...
  }
}
```

The `included` map is a flat pool of all entities needed for the envelope. To resolve a reference, look up the hash in `included`. Signatures are found by scanning `included` for `system/signature` entities where `data.target` matches the target entity's content hash.

### 1.2 Content Hash

```
system/hash := bytes   ; varint format-code + digest (variable)
                       ; On wire: CBOR byte string (bstr)
```

A `system/hash` is a flat byte string. The leading bytes encode the format (encoding version + hash algorithm) as a multicodec-style LEB128 varint; the remaining bytes are the raw digest.

**Format codes — `content_hash_format` seed table (multicodec-style varint encoding; v7.67):**

| Code | Algorithm | Digest | Total | Status |
|------|-----------|--------|-------|--------|
| 0x00 | ECFv1-SHA-256 | 32 B | 33 B | **Production** (validated since v7.0) |
| 0x01 | ECFv1-SHA-384 | 48 B | 49 B | **Validated** (v7.67 Phase 1 — cross-impl byte-equal) |
| 0x02 | ECFv1-SHA-512 | 64 B | 65 B | Reserved (SHA-2 strongest; usually redundant with 0x01) |
| 0x03 | ECFv1-BLAKE3-256 | 32 B | 33 B | Allocated; cross-impl validation deferred (Phase 3a backlog) |
| 0x04 | ECFv1-SHA3-256 | 32 B | 33 B | Reserved (Keccak/sponge construction diversity) |
| 0x05 | ECFv1-SHA3-512 | 64 B | 65 B | Reserved (Keccak strongest) |
| 0x06 | ECFv1-BLAKE2b-256 | 32 B | 33 B | Reserved (BLAKE3 predecessor; wide deployment) |
| 0x07 | ECFv1-BLAKE2b-512 | 64 B | 65 B | Reserved (BLAKE2 strongest) |
| 0x08 | ECFv1-SHAKE128-256 | 32 B | 33 B | Reserved (XOF variant) |
| 0x09 | ECFv1-K12 | variable | variable | Reserved (fast Keccak variant) |
| 0x0A–0xEF | — | — | — | Reserved (future) |
| 0xF0–0xFD | — | — | — | Experimental range |
| 0xFE | — | — | — | Reserved (mirror of `key_type` experimental slot if needed) |
| 0xFF | — | — | — | Reserved for protocol use — DO NOT allocate as a `content_hash_format` (varint expansion, §1.5) |

Format codes are encoded as multicodec-style LEB128 varints (per §7.3): codes 0–127 encode as a single byte (no continuation bit), codes ≥128 extend to 2+ bytes (continuation bit set on each non-final byte). The currently allocated codes (`0x00`–`0x09`) all fall in the single-byte range; the on-wire encoding is byte-for-byte identical to a 1-byte fixed-width field. Future code allocations beyond 0x7F naturally extend to 2-byte varints without a wire-format break for existing values.

The format code encodes both the canonical encoding version and the hash function. The same data encoded under different ECF versions produces different digests. A format code pins both.

**Hash computation:**

```
content_hash(entity):
  encoded = ecf_v1_encode({type: entity.type, data: entity.data})
  digest = SHA256(encoded)
  return bytes([0x00]) + digest    ; 33 bytes
```

- Input: `{type, data}` only. `content_hash` itself is NOT hashed.
- Encoding: ECF v1 (deterministic CBOR per RFC 8949 §4.2, rules in §1.3).
- Same `{type, data}` → same hash. Different types → different hashes even with identical data.

**Display format (UI only, never on wire):**
```
"ecfv1-sha256:" + hex(hash[1:])    ; For logs, debuggers, human display
```

Implementations MUST validate total byte length matches format code.

**Content-hash format-code interpretation (normative, v7.66; reframed v7.67).** The leading varint of any `content_hash` is its `content_hash_format` code. Implementations supporting multiple format codes interpret this varint when decoding, verifying, or matching the hash. An implementation receiving a `content_hash` whose format code it does not support SHALL return `unsupported_content_hash_format` (per §4.7) rather than silently failing or treating an unknown-format hash as a content miss. How an implementation organizes its content store internally — per-format partitions, single unified space, or any other layout — is not specified by this section.

The `content_hash` address space is the tuple `(format_code, digest)`: the format byte is part of the address, not a routing key (consistent with the universal address space of §1.4). When an implementation receives a `system/hash` reference, it inspects the leading varint (format_code), selects the corresponding decoder/verifier from its supported set, and processes the digest. Cross-format references between supported formats are not conflicts — they are normal address resolution. An implementation that does not support a referenced format code returns `unsupported_content_hash_format` (§4.7).

**Varint expansion (normative, v7.67).** The integer value `255` is reserved on both the `content_hash_format` axis (this section) and the `key_type` axis (§1.5) and SHALL NOT be allocated as an algorithm code. Encodings with leading-byte value `≥ 0x80` are normal multi-byte LEB128 sequences per §7.3 and implementations MUST decode them correctly even when no current production allocation exceeds `0x7F`.

**Peer home (content) format.** The content store is an address space keyed by `(content_hash_format, digest)`. A peer authors its own content — stored entities, trie nodes, revision entries, handler-produced results, and **all derived/substrate state it persists (blobs, indexes, derived paths, content-store entries)** — under its **home format**, a deployment property defaulting to `content_hash_format = 0x00` (SHA-256, the §9.1 conformance floor). A peer's persistent state is **uniformly** its home format; authoring substrate under the *negotiated-active* format of whatever connection happened to write it (so that the same logical content lands at two hashes) is **non-conformant**. Per-connection wire/identity-surface entities still follow the active format (§4.5a); that is a separate surface. A peer MAY select a different validated home format; doing so places that peer's content in a **distinct address space** that does not dedup or converge with the SHA-256 space (or any other format's space) — content addressing's shared-space benefits (dedup, convergence, the universal tree) hold only *within* one format. The home format is distinct from a connection's **active format** (§4.5): the active format governs the per-connection wire/identity surface and is negotiated; the home format governs where the peer's content lives and is the peer's own choice. A single-format network (all peers one home format) shares one content address space and is the recommended deployment; mixing home formats across peers is the experimental two-address-space mode (§1.2a, §1.5).

### 1.2a Content format: standard compliance and the price of divergence

**Standard compliance is Ed25519 + SHA-256.** A conformant peer SHOULD support SHA-256 (`content_hash_format = 0x00`) — it is the universal interop fallback, always available, and the largest shared content address space. SHA-256 is the recommended home format and the format a peer SHOULD include in its advertised `hash_formats` (§4.5) to remain universally reachable.

The architecture does **not** lock content to SHA-256. A peer MAY:
- select a different validated home format (§1.2) — running a fully content-addressed SHA-384, BLAKE3, or future-PQ network;
- advertise a `hash_formats` set that omits SHA-256 (a "pure" non-default peer);
- or even use an unreserved/experimental hash for a closed high-efficiency deployment that accepts the collision risk (the peer is responsible for the consequences).

Divergence from the baseline is permitted and carries two trade-offs the diverging peer accepts:
- **(a) Restricted reach.** A peer that does not speak SHA-256 cannot interoperate with SHA-256-only peers (empty `hash_formats` intersection → reject, §4.7). It has chosen a smaller reachable set.
- **(b) No shared-space benefit.** Content authored under a non-default home format lives in its own address space; it does not dedup or converge with the SHA-256 universe. Cross-format, nothing matches by hash; the peer recreates content in the needed space or translates at the edge (the experimental bridge, §1.5).

A single-format network — all peers on one home format, whether SHA-256 or, for a deliberate deployment or a network-wide migration, another validated format — shares one content address space and is the recommended way to run. Wholesale migration (the reason hash-agility exists) is a network adopting a new home format together. Mixing home formats across peers within one interoperating set is experimental: the two-address-space trade-offs above apply in full, and cross-format content convergence requires bridge-translation, which is out of v1 scope (§1.5).

### 1.3 Entity Canonical Form (ECF)

Deterministic CBOR encoding rules:

- Map keys sorted by encoded byte length, then lexicographically
- Minimal integer encoding
- Definite lengths only
- Shortest float encoding preserving value
- No duplicate map keys
- All field values preserved — no omissions

Optional fields: SHOULD be absent (key not present) rather than present with a null or zero value when constructing new entities. Absent key and null key produce different bytes and different hashes. However, the presence of an optional field with a null or zero value is semantically valid — it signals that the originating type definition includes that field. Implementations MUST NOT reject entities that include optional fields with null or zero values. Implementations receiving null MUST preserve it when forwarding (Entity Fidelity, §1.8), SHOULD treat as equivalent to absent for application logic.

*Note: Two entities with identical logical content but different optional field presence will have different content hashes. This is intentional — they are structurally distinct entities. Cross-implementation hash comparison of independently-constructed messages is not a protocol goal; hash comparison is meaningful for forwarded and stored entities that maintain fidelity.*

Spec examples use CBOR diagnostic notation (RFC 8949 §8).

### 1.4 URI and Path Model

```
URI := "entity://" peer_id "/" path
```

URIs in protocol messages MAY be fully qualified or peer-relative. Peer-relative URIs (no `entity://` prefix) are implicitly scoped to the local peer. Fully qualified URIs are required when referencing another peer's data. During connection setup (§4), only peer-relative URIs are used because the remote peer's ID may not yet be known.

**Peer namespacing.** All paths are peer-namespaced. The entity tree on any peer holds data organized by peer identity:

```
/local_id/system/handler/system/tree        → H1 ; Local peer's handler index entry
/local_id/system/type/primitive/string      → H2 ; Local peer's type definition
/alice_id/local/files/readme.md             → H3 ; Alice's own data
/bob_id/local/files/readme.md               → H4 ; Alice's knowledge of bob's data
/bob_id/system/type/custom/thing            → H5 ; Alice's cache of bob's type
```

A path without a leading `/` (like `system/handler/tree`) is peer-relative — implicitly scoped to the local peer. This is notation, not a different addressing mode. All handlers are peer-local; there is no mechanism to install a handler in another peer's namespace.

Peers accumulate knowledge about other peers through synchronization and direct exchange. Another peer's data is stored under that peer's id: `/bob_id/system/type/...` on alice's peer is alice's cache of bob's type definitions.

**Local view.** Each peer maintains a local view of the entity tree. This view contains:

1. **Authoritative data** — entities under the local peer's namespace (`/local_id/...`). The local peer holds the private key and is the authority for this data. Other peers treat this data as the canonical source.

2. **Cached remote data** — entities under other peers' namespaces (`/bob_id/...`, `/carol_id/...`). This is the local peer's knowledge of what those peers have. It may be stale, incomplete, or obtained through intermediaries.

No single peer holds the complete tree. The universal entity tree is the union of all peers' authoritative data. Each peer's local view is a partial projection: complete for its own namespace, partial for others. Synchronization updates the cached data. Subscriptions keep it current. The cached namespace for a remote peer is structurally identical to that peer's own authoritative namespace — the same paths, the same types, the same semantics. The difference is authority: only the key holder's data is authoritative.

**Authority layers.** The entity tree has three layers of authority:

1. **Local tree control.** A peer has full write access to its entire local tree. It can write to any path — `/alice_id/data/file1`, `/bob_id/data/file1`. Nothing in the protocol prevents this. The local tree is the peer's own storage.

2. **Namespace authority (cryptographic).** The key holder for a peer_id is the authority for that namespace. Only Bob can produce entities signed with Bob's key. While Alice can write anything to `/bob_id/...` in her local tree, that does not make it authoritative. A third party can verify by checking Bob's signature — if Bob signed it, the content is what Bob claims.

3. **Trust and freshness.** Signatures prove authenticity (Bob signed this). They do not prove freshness (Bob may have changed it since signing). Freshness requires re-fetching from the authoritative peer or receiving updates through a subscription.

**Worked example — one cross-peer round-trip (informative).** This traces write → list → fetch across the universal address space on a single peer (Alice), tying together the Local view, the absolute-path storage rule, and the §1.7 content-store dedup. It is the end-to-end picture the per-line examples above describe in pieces:

```
; (1) WRITE — Alice caches one of Bob's entities into her local view.
;     The handler URI targets Alice (her local peer); the *resource target* is
;     an absolute path in Bob's namespace. Cap-check authorizes; nothing about
;     the path being foreign is special (§1.4 layer-1 local tree control).
EXECUTE entity://alice_id/system/tree  operation:"put"
  resource: {targets: ["/bob_id/local/files/readme.md"]}
  params:   {type:"system/tree/put-request", data:{entity: E}}   ; content_hash(E) = H

  ⇒ Content Store:  H → E                                  ; stored once, deduplicated
    Location Index: /bob_id/local/files/readme.md → H      ; bound under Bob's namespace

; (2) LIST — the universal tree root is a set of peer-ids Alice holds.
EXECUTE entity://alice_id/system/tree  operation:"get"
  resource: {targets: ["/"]}            ; trailing-slash / empty ⇒ list
  ⇒ system/tree/listing entries: { alice_id:{has_children:true}, bob_id:{has_children:true}, ... }
;   Listing /bob_id/local/files/ ⇒ { readme.md: {hash:H, has_children:false} }   ; a POINTER, not E

; (3) FETCH — resolve the hash to bytes (the second hop).
EXECUTE entity://alice_id/system/tree  operation:"get"
  resource: {targets: ["/bob_id/local/files/readme.md"]}
  params:   {type:"system/tree/get-request", data:{mode:"hash"}}   ; ⇒ H (the pointer)
;   then content-by-hash ⇒ E.   (Default-mode get dereferences in one call locally;
;   the HTTP poll surface splits it into the path→hash + hash→bytes two-hop — see
;   EXTENSION-NETWORK §6.5.3.1, since a static CDN cannot dereference.)
```

The invariant the example pins: **the tree returns a hash; the content store returns the bytes; the bytes live once even if many paths (on this or any peer) bind to `H`** (§1.7). Every layer that takes a path — store, listing, scope filter, dispatch — operates on the absolute `/{peer_id}/...` form unchanged; none may assume the local peer's id. A binding under `/bob_id/...` is Alice's *cache authority* over her own view of Bob's subtree; Bob's key remains the *namespace authority* for what is canonically true there (layers 1–2 above).

**URI normalization.** Wire URIs use the `entity://` scheme. Normalization strips the scheme and produces an absolute path. The `entity://` scheme maps to RFC 3986: the peer_id is the authority, the rest is the path. The leading `/` is the authority-path separator:

```
normalize(uri):
  if uri starts with "entity://":
    return "/" + uri[9:]    ; strip "entity://", prepend "/"
  return uri                ; already a path (absolute or peer-relative)
```

Examples:
- `"entity://alice_id/local/files/readme.md"` → `"/alice_id/local/files/readme.md"`
- `"entity://alice_id/system/tree"` → `"/alice_id/system/tree"`
- `"system/tree"` → `"system/tree"` (peer-relative, unchanged)
- `"/alice_id/system/tree"` → `"/alice_id/system/tree"` (already absolute)

Normalization produces absolute paths from URIs. Peer-relative paths pass through unchanged — canonicalization (§5.4) resolves them.

**Three addressing forms.** The system uses three representations at different layers:

| Form | Example | When used |
|------|---------|-----------|
| Fully qualified URI | `entity://alice_id/system/tree` | Wire protocol, cross-peer references |
| Absolute path | `/alice_id/system/tree` | Internal operations — the normal form. Leading `/` denotes universal tree root. |
| Peer-relative path | `system/tree` | Caller convenience — no peer_id segment. Resolved to local peer's namespace. |

Normalization strips the `entity://` scheme and prepends `/` to produce an absolute path. Canonicalization (§5.4) resolves peer-relative paths to absolute by prepending `/{local_peer_id}/`. A path like `/alice_id/system/tree` is NOT peer-relative — it already has a leading `/` and a peer_id segment.

**Peer-relative paths.** A peer-relative path has no leading `/` and no peer_id as its first segment. Peer-relative always resolves to the local peer's namespace: `system/tree` becomes `/{local_peer_id}/system/tree`. There is no path in the system that exists outside a peer namespace. Peer-relative is notation, not a different addressing mode. It is permitted in EXECUTE messages targeting the local peer, handler registration, and API-level convenience. Canonicalization resolves peer-relative paths to absolute for all internal operations: capability checking, pattern matching, tree storage, and subscription patterns.

**Storage representation.** All paths in the location index MUST be stored as absolute paths — `/{peer_id}/{rest}`. The leading `/` is part of the stored representation. Peer-relative input (omitting the peer ID) is a caller convenience; the peer canonicalizes it on input per §5.4.

**Resolution scope and path construction (informative — applies at every path-handling layer).** Path resolution is not a property of EXECUTE dispatch alone — it applies *wherever a path parameter is accepted*: listing render, scope filters, namespace enumeration, capability canonicalization, tree-walk, subscription matching, and any handler-internal function that takes a path. Two rules every such layer MUST observe: (1) **Form-agnostic input** — a peer-relative path (no leading `/`) is qualified to `/{local_peer_id}/...`; an **already-absolute** path (leading `/`, e.g. a cached remote namespace `/{other_peer_id}/...`) **passes through unchanged**. A layer MUST NOT re-qualify an already-absolute path — doing so yields the corrupt `/{local_id}//{other_id}/...` (the prepend-local double-segment bug). (2) **Normalized construction** — when building a path by concatenation, normalize the result to remove empty segments (`//`); do not assume a prefix parameter is in any particular form unless the operation's spec says so. This is the single most-recurring cross-impl bug class. The durable guard is the cross-impl `universal_address_space` conformance category, not this note; the note states the invariant the test enforces.

**Peer-relative paths in entity data.** Peer-relative paths that appear in entity data fields (typed as `system/tree/path`) resolve to the peer namespace of the entity's tree binding, not the reader's namespace. An entity at `/{peerB}/system/continuation/xyz` with field `target: "system/inbox"` resolves to `/{peerB}/system/inbox`. Entity data is peer-agnostic — the tree binding provides context. Entities without a tree binding (fetched by hash alone) have unresolvable peer-relative paths.

**Response paths.** All paths in protocol responses, handler results, and index query results are absolute paths — as stored. This includes query result match paths (EXTENSION-QUERY.md §4.3) and any operation that returns entity paths. **Exception — prefix-relative keys.** Operations that return keys relative to a prefix (trie binding keys in snapshots, diff added/removed/changed keys, listing child names) return prefix-relative strings. These are structural keys within a subtree, not paths (see EXTENSION-TREE.md §3, §4).

**Dispatch path resolution.** The dispatch chain resolves the target path by normalizing the URI (strip `entity://` scheme, prepend `/`) and then canonicalizing (prepend `/{local_peer_id}/` if the input is peer-relative, per §5.4). The result is always an absolute path starting with `/`:

```
dispatch_path(uri, local_peer_id):
  normalized = normalize(uri)                          ; strip entity:// scheme → absolute path
  canonical = canonicalize(normalized, local_peer_id)  ; resolve peer-relative to absolute
  validate_absolute_path(canonical)                    ; MUST — reject malformed peer_id segment
  return canonical
```

Examples:
- `"entity://alice_id/system/tree"` → `"/alice_id/system/tree"`
- `"entity://alice_id/local/files/readme.md"` → `"/alice_id/local/files/readme.md"`
- `"system/tree"` → `"/{local_peer_id}/system/tree"`
- `"local/files/readme.md"` → `"/{local_peer_id}/local/files/readme.md"`

There is no `extract_handler_path` operation that strips the peer ID. Canonicalization is one-directional: peer-relative → absolute (§5.4). The tree walk receives an absolute path and walks the actual tree.

**Inbound dispatch (wire listener).** When a peer receives an EXECUTE over the wire, the path MUST target the local peer's namespace. If the peer ID does not match the local peer, the peer MUST reject with status 400 (`invalid_request`). Synced remote peer data may include `system/handler` entities (e.g., `/{remote_peer_id}/system/tree`) — these are cached data describing the remote peer's handlers, not locally dispatchable handlers.

**Internal dispatch (handler sub-requests).** A local handler executing a sub-request MAY target a remote peer's namespace (e.g., `/{remote_peer_id}/local/files/readme.md`). The peer runtime recognizes that the canonicalized path targets a different peer and routes the request outbound to that peer's connection infrastructure. This is a locally-originated outbound request, not forwarding of an inbound request.

All handlers are peer-local. A peer processes only requests targeting itself. Cross-peer request forwarding is provided by the relay system extension or other domain-specific handlers — in those cases, the caller explicitly targets the relay handler's path, not the remote peer's URI directly.

**Path rules.** Paths are UTF-8 strings. Two characters are reserved:

| Character | Meaning |
|-----------|---------|
| `/` | Path segment separator; leading `/` denotes absolute path |
| `*` | Wildcard in capability grant patterns (§5.4) |

All other UTF-8 characters are valid in path segments. Paths MUST NOT contain null bytes. Paths MUST NOT contain empty segments (consecutive `/` separators).

**Absolute paths** start with `/` followed by a peer_id segment: `/{peer_id}/rest`. The leading `/` denotes the universal tree root. **Peer-relative paths** do not start with `/`: `system/tree`, `local/files/readme.md`. Peer-relative paths are resolved to the local peer's namespace by canonicalization (§5.4).

**Two ways peers are referenced.** Paths and entity-internal references use different representations of the same peer:

- **Paths use `peer_id`** (Base58 string per §1.5): `/{peer_id}/...` at the universal root; `system/peer/status/{peer_id}` and similar operational paths under §3.13. peer_id is human-readable, derivable from the public key alone (`Base58(key_type || hash_type || hash(pubkey))`), and stable across the peer's life unless its key changes. **Path segments MUST use canonical `peer_id` form per §1.5 v7.65 contract** (Ed25519 → `hash_type=0x00` identity-multihash); non-canonical forms in stored tree paths are non-conformant.
- **Entity-internal references use `content_hash`** (type `system/hash`): the `signer` field on signature entities (§3.5), the `grantee` and `granter` fields on capability entities (§3.6), and substrate references in attestation/quorum entities. content_hash is the canonical content hash of the referenced `system/peer` entity (per ECF, §1.2). **Under v7.65, `content_hash(system/peer)` is a pure function of `(public_key, key_type)` and is invariant under wire-form `peer_id` choice** — caps, signatures, attestations, and identity-bindings inherit this invariance.

Given one you can derive the other: peer_id is decoded from its Base58 wire form via `derive_peer_from_peer_id` (§7.4) to recover `(public_key, key_type, hash_type)`; content_hash is computed by hashing the canonical encoding of `system/peer({public_key, key_type})`. The substrate provides `resolve_peer(content_hash) → system/peer entity` for the hash → entity direction; the inverse is via decoding the wire peer_id (identity-multihash directly carries pubkey; SHA-256-form requires prior contact to recover pubkey).

**Reserved:** Paths starting with `./` or `../` are reserved for future directory-relative semantics. Implementations MUST reject them. Segments starting with `.` are valid (e.g., `.gitignore`, `.env`).

**Trailing slash semantics.** The trailing `/` appears in two contexts:

| Context | Trailing `/` Meaning | Reference |
|---------|---------------------|-----------|
| `get` request path parameter | List entries under prefix | §6.3 |
| Tree path (entity binding) | Not used — entities bind at paths without trailing `/` | §1.7 |

Entities are never bound at trailing-slash paths. The trailing `/` in a `get` request path is a signal to list entries, not a path to data.

**Peer wildcard in grants.** Grant resource patterns support a peer wildcard prefix `/*/` which matches any peer_id segment. All paths are absolute after canonicalization — peer-relative patterns are resolved to `/{local_peer_id}/...` before matching (§5.4), so `/*/` always operates on a real peer_id.

```
"/*/system/type/*"          ; All peers' type definitions
"/*/local/files/*"          ; All peers' files
"/{alice_id}/system/type/*" ; One specific peer's type definitions (absolute)
"system/type/*"             ; Local peer only (peer-relative, canonicalized)
```

The `/*/` prefix strips the first segment (peer_id) and matches the remainder against the rest of the pattern. Peer wildcard patterns MUST use the absolute form `/*/rest` in entity data. The bare form `*/rest` (without leading `/`) is rejected as ambiguous.

Grants may include `exclude` patterns within scope fields (§3.6) to narrow scope:

```
grant: {
  handlers:   {include: ["system/tree"]}
  resources:  {include: ["/*/system/type/*"], exclude: ["/{alice_id}/system/type/*"]}
  operations: {include: ["get"]}
}
```

Summary of grant pattern forms (used in scope `include` and `exclude` arrays). All patterns are peer-relative in entity data and canonicalized to absolute before matching:

| Pattern (in entity data) | After canonicalization | Meaning |
|--------------------------|----------------------|---------|
| `*` | `/{local_peer_id}/*` | Local peer, all paths |
| `pattern/*` | `/{local_peer_id}/pattern/*` | Local peer, subtree |
| `pattern` | `/{local_peer_id}/pattern` | Local peer, exact |
| `/*/*` | `/*/*` | All peers, all paths |
| `/*/pattern/*` | `/*/pattern/*` | All peers, subtree |
| `/{P}/pattern/*` | `/{P}/pattern/*` | Specific peer, subtree |

Bare `*` is peer-relative — it matches all paths under the local peer only. To match all peers, use `/*/*`. The leading `/` always signals universal tree scope.

Future extensions MAY define richer pattern syntax (e.g., peer set matching with `/{alice,bob}/path/*`).

### 1.5 Identity

```
KeyPair := {
  private_key: bytes[32]        ; Ed25519 seed
  public_key:  bytes[32]        ; Ed25519 public key
}

PeerID := Base58(varint(key_type) || varint(hash_type) || digest)
         ; canonical form per key_type — see canonical-form table below.
         ; For Ed25519 (key_type=0x01, hash_type=0x00 identity-multihash):
         ;   digest = public_key (raw 32 bytes; the digest IS the public key, v7.64).
         ; For algorithms with hash_type=0x01 (SHA-256-form; e.g. Ed448, ML-DSA-65):
         ;   digest = SHA-256(canonical_pubkey_encoding).
         ; Total: 34 bytes (Ed25519 / identity-form) for current values; varies by key_type.
```

`key_type` and `hash_type` are encoded as multicodec-style LEB128 varints (per §7.3). Codes 0–127 encode as a single byte (no continuation bit set); codes ≥128 extend to 2+ bytes naturally. The currently allocated `key_type` codes all fall in the single-byte range (e.g., Ed25519 = `0x01`); `hash_type` values likewise (identity-multihash = `0x00`, SHA-256-form = `0x01`). On-wire encoding is byte-for-byte identical to a 1-byte fixed-width field for these values. Future code allocations beyond `0x7F` extend to 2-byte varints without a wire-format break for existing values.

**Canonical form per `key_type` (v7.65 v1 contract, v7.66 extended, v7.67 seed table).** For each allocated `key_type`, exactly one `hash_type` is declared canonical. Wire `peer_id`s in tree-path segments and operational use MUST use canonical form. Declared allocations:

| `key_type` | Algorithm | Canonical `hash_type` | Pubkey | Rationale |
|---|---|---|---|---|
| `0x01` | Ed25519 | `0x00` identity-multihash | 32 B | Fits identity-form (raw pubkey ≤ 32 B; below 46-Base58 floor). The digest IS the public_key (v7.64). |
| `0x02` | Ed448 | `0x01` SHA-256-form | 57 B | Identity-form would produce a 59-byte raw segment, exceeding the 46-Base58 informative floor. SHA-256-form forces canonicalization. |
| `0x03` | ML-DSA-65 | `0x01` SHA-256-form | 1952 B | Kilobyte-scale pubkey; identity-form unworkable for the path substrate. SHA-256-form is the only viable option. |
| `0x04` | SLH-DSA-SHA2-128s | `0x00` identity-multihash | 32 B | Tiny pubkey — fits identity-form. The slot's defining property: small PK + big sig. |
| `0x05` | ML-DSA-44 | `0x01` SHA-256-form | 1312 B | As ML-DSA-65. |
| `0x06` | ML-DSA-87 | `0x01` SHA-256-form | 2592 B | As ML-DSA-65. |
| `0x07` | FALCON-512 | `0x01` SHA-256-form | 897 B | As ML-DSA-65. |
| `0x08` | SLH-DSA-SHA2-192s | `0x01` SHA-256-form | 48 B | 48 B raw segment is right at the floor; SHA-256-form for consistency with allocations above the cutoff. |
| `0x09` | secp256k1 | `0x00` identity-multihash | 33 B | Fits identity-form (compressed). |
| `0x0A` | P-256 (secp256r1) | `0x00` identity-multihash | 33 B | Fits identity-form (compressed). |
| `0xFE` | experimental-test | `0x01` SHA-256-form | 64 B (synthetic) | Test-only path-exercise allocation (v7.66; NOT for production). Fixed synthetic public_key `0xAA`×64; no sign/verify semantics. |

Future `key_type` allocations SHALL declare canonical `hash_type` at allocation time per the size-cutoff principle: identity-form (`hash_type=0x00`) for short keys (raw public_key ≤ 32 bytes); designated hash-form for long keys (where identity-form would exceed substrate-compatibility floors — filesystem 255-byte filename segments, HTTP URL ceilings, DB index limits).

**`key_type` seed table (v7.66 reserved-range, v7.67 allocations).** The 8-bit `key_type` space:

| Code | Algorithm | Status |
|---|---|---|
| 0x00 | — | Reserved (defensive against uninitialized-state confusion) |
| 0x01 | Ed25519 | **Production** (v7.65 validated) |
| 0x02 | Ed448 | **Validated** (v7.67 Phase 1 — cross-impl byte-equal) |
| 0x03 | ML-DSA-65 | Allocated; cross-impl validation deferred (Phase 3b backlog) |
| 0x04 | SLH-DSA-SHA2-128s | Reserved (small-PK / big-sig trade-off) |
| 0x05 | ML-DSA-44 | Reserved (smaller PQ parameter set) |
| 0x06 | ML-DSA-87 | Reserved (larger PQ parameter set) |
| 0x07 | FALCON-512 | Reserved (alternative PQ lattice family) |
| 0x08 | SLH-DSA-SHA2-192s | Reserved (mid-tier SPHINCS+) |
| 0x09 | secp256k1 | Reserved (crypto-wallet ecosystem interop) |
| 0x0A | P-256 (secp256r1) | Reserved (NIST classical / hardware-key interop) |
| 0x0B–0xEF | — | Reserved (future real algorithms) |
| 0xF0–0xFD | — | Experimental range (deployments may allocate without coordination) |
| 0xFE | experimental-test | Path-exercise stub (v7.66 §4; no sign/verify) |
| 0xFF | — | Reserved for protocol use — DO NOT allocate as a `key_type` (varint expansion, §1.2) |

Impls receiving a `key_type` they do not support MUST return `400 unsupported_key_type` (§4.7); for `0xFE` (or any other experimental allocation), refusal is conformant — only impls participating in the conformance suite agility-validation path implement `0xFE`.

**Two-layer `key_type` surface (v7.66 errata pin).** `key_type` appears on two structurally distinct surfaces and the two SHALL NOT be conflated:

- **Binary peer_id wire-format prefix** (this section): a varint-encoded byte. Ed25519 is `0x01`. `0xFE` is `0xFE`. The varint encoding is per §7.3.
- **`system/peer.data.key_type` entity-data field** (per §3.5): a `primitive/string`. The canonical lowercase-ASCII string per binary code: `0x01`→`"ed25519"`, `0x02`→`"ed448"`, `0x03`→`"ml-dsa-65"`, `0x04`→`"slh-dsa-sha2-128s"`, `0x05`→`"ml-dsa-44"`, `0x06`→`"ml-dsa-87"`, `0x07`→`"falcon-512"`, `0x08`→`"slh-dsa-sha2-192s"`, `0x09`→`"secp256k1"`, `0x0A`→`"p-256"`, `0xFE`→`"experimental-test"`. Future allocations declare their canonical string at allocation time.

`content_hash(system/peer)` is computed from the entity-data string surface (per v7.65 §3 P×I primitive discipline); the binary varint surface is presentation/routing only. The two are derivable from each other given the allocation table but encode independently on their respective surfaces.

**Why canonical form is mandated (cap-pattern operator-coherence).** Cap patterns are form-bearing strings (`peers: include = ["/{peer_id_form}/..."]`). Without canonical-form mandate, a peer arriving under a different `hash_type` for the same key produces a different `peer_id` string; string-match against the cap pattern fails; the operator's mental model ("this identity has this permission") diverges from system behavior. Forcing operator intent to match system behavior requires patterns to canonicalize, which requires wire form to canonicalize. The canonical form for Ed25519 is identity-multihash by universal property: it is the unique element of the form-fiber from which all other forms are computable (identity-form embeds the raw public_key, generating all other hash_type forms via local computation; hash forms are one-way images that do not generate identity-form).

**Wire-acceptance carve-out.** Implementations MAY decode `peer_id`s presented in non-canonical form (e.g., `hash_type=0x01` SHA-256-form for Ed25519) for backwards compatibility with older implementations. Implementations MUST canonicalize on acceptance: wire form is presentation; storage form is canonical. Before any tree-lookup, cap-state operation, or stored-policy entry, the impl MUST canonicalize: derive `(public_key, key_type)` from the presented form (post-handshake when pubkey is available; via the §6.2 lazy-canonicalize path when at mint time without prior contact); recompute canonical form; use canonical for storage and lookup. Impls SHOULD log non-canonical form acceptance at debug level. Impls MAY refuse non-canonical form at construction or handshake under stricter local policy (deployment choice).

**Multi-form-per-pubkey scope.** A peer publishing multiple wire forms of the same key is using behavior NOT part of the v1 conformance surface. Implementations MAY handle multi-form same-pubkey usage; tooling/subscriptions/caches MAY fragment across forms; behavior is implementation-defined. Cross-form correlation lives in IDENTITY/REGISTRY/POLICY layers (pubkey-canonical machinery), not the address layer.

**Cross-content-address-space identity is experimental (not v1) (v7.69).** The paragraph above covers multiple *peer_id wire-forms* of one key. A distinct, also-non-v1 case is one identity named under multiple **`content_hash_format`s** at once (a "two content-address-space" deployment). The core protocol does not forbid it, but v1 does not make identity-equality span content-address spaces: §4.5a keeps one active format per connection, so the question does not arise on the wire. A deployment that genuinely wants heterogeneous per-peer formats accepts two consequences. First, **two content stores' worth of addresses for the same data**: a lookup in one address space will not find content authored in the other, the entity is recreated in the address space where it is needed, and nothing matches by hash across the two. Second, recognition-across-forms therefore becomes a **substrate-level** `(public_key, key_type)` operation — equality at the *entity* layer, not address-level byte-equality. Both belong at the **edge**, never in the core verification algorithm: a **bridge-translator handler** that understands both content-address spaces, and/or internal multi-store / duplicate storage used deliberately to bridge networks. An extension specifying such a bridge-translator handler is welcome but out of v1 scope; cross-form correlation otherwise lives in the IDENTITY/REGISTRY/POLICY layers, never the address or capability layer of core.

### 1.5a Identity and Access Management

The core protocol alone gives each peer a self-rooted identity (the peer ID derived in §1.5) and capability chains rooted at that peer (§5.5). This is sufficient for single-device deployments and for peers that don't need recovery, multi-device recognition, or templated permission management.

Two extensions provide the canonical access-management surface beyond the bare core-protocol floor:

- **`system/role`** (`EXTENSION-ROLE.md`) — templated grant derivation. A peer with role assignments has its caps derived from role definitions, allowing permission management without per-cap issuance.
- **`system/attestation`** (`EXTENSION-ATTESTATION.md`) — substrate primitive: signed-claim entity (the edge type in the system's signed graph). Provides signature validation, supersedes-chain walks, liveness checks, and revocation lookups; consumed by quorum, identity, and any future signed-claim consumer.
- **`system/quorum`** (`EXTENSION-QUORUM.md`) — substrate primitive: K-of-N node + validator + lifecycle attestation conventions (`quorum-update`, `quorum-publish`). Pluggable signer-resolution (concrete | identity-resolved | …); consumed by identity, group, cluster, and any K-of-N-needing extension.
- **`system/identity`** (`EXTENSION-IDENTITY.md`) — structured composition layer over EXTENSION-ATTESTATION + EXTENSION-QUORUM expressing recognizable, recoverable, rotatable presence. Provides recovery (via K-of-N quorum), multi-device recognition (multiple agent peers attested by the same controller), and stable cross-peer recognition across rotations. Identity contributes the convention for `properties.kind`/`function`/`mode` on identity-context attestations and the validation predicates that orchestrate the substrate primitives' helpers; it actively composes the substrates by registering a resolver against EXTENSION-QUORUM at install time and orchestrating substrate ops + core cap-layer ops + sync-hook side effects in single user-visible flows.

Role and identity compose orthogonally. A peer may have role assignments without identity infrastructure (core protocol + role minimum) or with the full identity stack. Together they form a layered access surface: **core protocol (keys + caps) → `system/role` (templated grants) → `system/attestation` + `system/quorum` (signed-graph substrate) → `system/identity` (multi-key management as a composition layer) → `system/group` (collective identities, planned).** Each layer is independently usable; users self-select.

The substrate primitives `system/attestation` and `system/quorum` are reusable beyond identity (group, cluster, VC issuance, reputation, provenance, audit, transaction, governance — all consume them). Identity is one consumer among many.

Implementations of the core protocol alone remain conformant. The extensions are opt-in; this section is informative — it points at the canonical access-management surface without making any of those extensions normative for core conformance.

### 1.6 Wire Frame

```
Frame := [4 bytes: length (big-endian)] [length bytes: CBOR payload]
```

This defines the default TCP framing. The 4-byte length prefix supports frames up to ~4 GiB.

The core protocol places no restriction on entity size. Frame size limits are transport-specific — peers negotiate or agree on limits appropriate to their transport. TCP implementations SHOULD use a reasonable default frame limit (e.g., 16 MiB) to bound memory allocation for incoming messages. Other transports (QUIC, shared memory, etc.) define their own framing and limits.

**WebSocket transport.** WebSocket connections use the same length-prefixed framing as TCP — each frame is a 4-byte big-endian length prefix followed by a CBOR payload. Each WebSocket binary message MUST contain exactly one length-prefixed frame. Implementations MUST NOT split a frame across multiple WebSocket messages or batch multiple frames into a single WebSocket message. Text-mode WebSocket messages MUST NOT be used for protocol frames.

Implementations using stream-level WebSocket adapters (e.g., `AsyncRead`/`AsyncWrite` wrappers) MUST ensure each frame write produces a single WebSocket message. Implementations using message-level WebSocket APIs receive one complete frame per message. Receivers MAY validate that the WebSocket message length equals 4 + the length prefix value.

### 1.7 Storage

Two layers:

```
Entity Tree:   URI  → Hash    ; Mutable, location index
Content Store: Hash → Entity  ; Immutable, deduplicated
```

The entity tree is a logical namespace backed by a flat path→hash mapping, not a filesystem. A path may be simultaneously bound to an entity and serve as a prefix for child paths. For example, `system/type/system/handler` is bound to a type definition entity, AND `system/type/system/handler/operation-spec` exists as a child path. Listing entries reflect both dimensions independently: `hash` indicates entity binding (null if unbound), `has_children` indicates child path existence. Implementations MUST NOT assume that entity binding and child path existence are mutually exclusive.

**Remote peer data.** When a peer stores another peer's entities locally, the entities are stored in the content store (deduplicated by content hash) and bound in the location index under the remote peer's namespace:

```
Content Store: H4 → {type: "local/files/file", data: {...}}     ; Deduplicated
Location Index: bob_id/local/files/readme.md → H4               ; Under Bob's namespace
```

If two peers have the same content at different paths, the content store holds one copy:

```
Content Store: H1 → {type: "local/files/file", data: {content: "hello"}}
Location Index: alice_id/local/files/greeting.md → H1           ; Alice's path
Location Index: bob_id/local/files/hello.txt → H1               ; Bob's path (same content)
```

Remote data is structurally identical to local data — same entity types, same tree operations, same subscription mechanisms. The only difference is authority (§1.4).

### 1.8 Entity Fidelity

Implementations MUST maintain fidelity throughout the system:

1. **Validate on receipt**: Compute expected hash from `{type, data}`, compare with `content_hash`, reject on mismatch.
2. **Trust validated hash**: After validation, use `content_hash` for all subsequent operations. MUST NOT recompute from internal structures.
3. **Store original**: Store original entity content indexed by trusted hash.
4. **Forward original**: When re-transmitting, use stored original. MUST NOT re-serialize.
5. **Preserve unknown fields**: SHOULD preserve fields not understood. Enables forward compatibility and valid signatures through relay.

**Application — identity references.** A reference to another peer's identity (a cap `grantee`/`granter`, a `signature.signer`, any `system/hash` naming a `system/peer`) is the *authored* `content_hash` of that identity entity — the form its keyholder presents on the wire (carried as `signature.signer` during the handshake, §4.6). An implementation constructing such a reference MUST use that authored hash and MUST NOT recompute the identity entity's hash under its own `content_hash_format`. Under §4.5a there is one active format per connection, so the authored form and the local form coincide; the prohibition is the safety rail that keeps them coincident and is the direct consequence of item 2 ("trust validated hash … MUST NOT recompute from internal structures"). Re-deriving a received identity under the local format manufactures a second content_hash for one identity and breaks the §5.2 `grantee == author` / `signer == author` equality.

### 1.9 Namespace Design

The entity tree has two layers of organization. The structural layer — prefix-based dispatch, multi-dimensional capability grants, self-descriptive type and handler metadata — is mathematical. It emerges from the primitives and would be rediscovered by any implementation. The naming layer — hierarchical paths, domain grouping, consistent prefixes — is design. It operates within the space the structure leaves open.

The naming conventions align with the structural properties:

**Prefix alignment.** Each domain uses one name for its handler pattern, type prefix, and data prefix. The handler pattern appears in three structural roles (dispatch routing, grant authorization, resource scoping). Aligning all three to a single prefix produces self-documenting grants. Divergence between handler and resource prefixes is valid (the dimensions are structurally independent) and signals intentional cross-domain access.

**Containment.** Concepts that exist only within another concept's context live under its namespace. The connection handler exists only within the wire protocol domain — it has no local-only function — so it lives at `system/protocol/connect`. All other system handlers function on an isolated peer and sit at the top level.

**Independence.** Top-level `system/` entries represent structurally independent self-description components. Types, capabilities, tree operations, compute, and content each exist independently. Their namespace independence mirrors their structural independence.

**Domain over category.** Handler placement follows the domain it belongs to, not the fact that it's a handler. In entity-native computation, handlers dissolve into compute expressions at paths — "handler" is an organizational convention, not a computational primitive.

These conventions are choices, not requirements. The system functions identically with arbitrary path names. But coherent naming reduces grant complexity, makes security review navigable, and provides one consistent mental model across dispatch, authorization, and code organization.

**Operational state.** Paths under `system/transport/`, `system/config/`, `system/peer/`, and `system/connection/` are reserved for operational state entities (§3.13). These paths follow the same conventions: prefix alignment, containment, independence.

**Convention vs structure.** The path locations specified in this document (`system/type/*`, `system/handler/*`, `system/capability/grants/*`, `system/transport/*`, `system/config/*`, `system/peer/*`, `system/connection/*`) are the recommended convention for organizing core protocol system data. They are not structural requirements for interoperability. Interoperability depends on shared type vocabulary — the `type` field strings in entity data (e.g., `"system/handler/interface"`, `"system/type"`) — not on where entities are stored in the tree. The sole structurally fixed path is `system/protocol/connect` — the pre-authorized connection handler (§4.2). All other path locations are communicated through the initial capability grant (§4.4): the grant's `resources` patterns tell the connecting peer where to find system data on this peer. A connecting peer follows the granted patterns and processes discovered entities according to their types. Peers that follow the recommended convention benefit from predictable tree layout, simpler cross-implementation tooling, and reduced discovery cost. Peers that diverge remain conformant — they communicate their actual paths through grants.

### 1.10 Implementation Notes

**Storage backends are implementation-defined.** The protocol specifies content addressing, the tree's path-to-hash binding, the emit pathway, and capability rules. How a peer stores entities (memory only, mirrored to SQLite, IndexedDB, filesystem, mmap, embedded KV, or any combination) is an implementation choice. SYSTEM-COMPOSITION.md §6.6 describes the consumer-based pattern for adding persistence to memory-primary stores. Memory-only, persistent-only, and mirrored deployments are all conformant. Peer-to-peer interop is preserved by the boundary guarantees of the wire protocol and content addressing, not by shared internal storage architecture.

### 1.11 Boundary Conformance and Internal Divergence (normative)

The protocol's conformance contract is **at the boundary** — what bytes a peer emits to other peers and what bytes it accepts from them. The contract is not on internal architecture: how an implementation represents entities in memory, what additional features it provides for its own use, how it stores data, what custom extensions exist within its own network, and what optimizations it applies are all implementation choices.

An implementation that needs behavior outside the spec for legitimate internal reasons (a custom representation, an in-network extension, a vendor-specific feature, an alternative wire encoding inside its own cluster, etc.) is conformant as long as: **(a)** it emits canonical conformant bytes at the boundary to other peers, **(b)** it accepts only canonical conformant bytes at the boundary from other peers, and **(c)** it owns the translation bridge between its internal representation and the conformant boundary form. The implementer is responsible for the bridge; the spec doesn't legislate internal architecture.

Concretely, an implementation MAY:
- Use a different on-disk format than its wire format (storage divergence).
- Use a non-CBOR internal representation (in-memory divergence).
- Maintain in-network extensions other peers do not have (the bridge degrades them to opaque or strips them at the boundary).
- Use ECF features that are not part of the boundary contract (e.g. tags, per `ENTITY-CBOR-ENCODING.md §6.3` — strip at the boundary; re-add on ingress from same-cluster peers).

An implementation MUST NOT:
- Emit any byte sequence at the boundary that is not canonical ECF.
- Accept any byte sequence at the boundary that is not canonical ECF.
- Diverge in a way that breaks load-bearing boundary invariants (e.g. content-hash computation, signature verification, capability-chain verdict determinism — those are themselves the boundary contract and have no internal-divergence escape).

This pattern is the system's general answer to "what if the spec doesn't allow X?" — internally, however the implementer needs; at the boundary, conformant. The §6.3 tag-policy is one named instance; §1.10's storage-backend flexibility is another; the same shape applies to any future divergence consideration.

---

## 2. Type System

**Top-level type namespaces.** Every type defined by this specification lives in one of four top-level namespaces (`primitive/*`, `core/*`, `compute/*`, `system/*`), plus the bare structural root `entity`. Extension protocol types live at `system/{ext}/*`. The full rule, including the rationale for the `compute/*` exception and the criteria under which a future extension may claim a new top-level namespace, is normative in ENTITY-NATIVE-TYPE-SYSTEM.md §2.7. This document follows that convention throughout.

### 2.1 Type Definition

Every type is an entity of type `system/type`.

```
system/type := {
  name:        system/type/name                 ; Type name (e.g., "system/protocol/execute")
  extends:     system/type/name?                ; Parent type name (single inheritance)
  fields:      map<string, field-spec>?         ; Data field definitions (entity.data)
  layout:      [string]?                        ; Ordered field names for byte decomposition
                                                ; Only valid when extends is primitive/bytes
  type_params: [string]?                        ; Generic parameter names (e.g., ["T", "E"])
  type_args:   map<string, system/type/name>?   ; Concrete bindings when extending generic type
                                                ; See TYPE-SYSTEM §4.1
}
```

Types are stored at `system/type/{type_name}` in the entity tree.

The type extension (EXTENSION-TYPE.md, planned) adds a `constraints` field interpreted as an open-type extension field (§2.10).

### 2.2 Field Specification

```
system/type/field-spec := {
  type_ref:   system/type/name? ; Type name for value's type
  optional:   bool?             ; If true, field may be absent; default false
  array_of:   field-spec?       ; Element spec for arrays
  map_of:     field-spec?       ; Value spec for maps (keys default to strings; see key_type)
  union_of:   [field-spec]?     ; Variant field-specs — value must match one (first match wins)
  type_param: string?           ; Generic type parameter reference (resolved before validation)
  type_args:  map<string, system/type/name>?  ; Concrete bindings for a generic type_ref
  default:    any?              ; Default value when field absent (does NOT affect hashing)
  key_type:   system/type/name? ; Type for map keys; default "primitive/string"
  byte_size:  uint?             ; Fixed byte width within a structured primitive's layout
                                ; See TYPE-SYSTEM §4.2
}
```

**Invariant**: A field-spec MUST contain exactly one of `type_ref`, `array_of`, `map_of`, `union_of`, or `type_param`. Zero or more than one is an error. Applies recursively to nested field-specs. See ENTITY-NATIVE-TYPE-SYSTEM.md §4.2.

**Entity references**: Fields that reference other entities use `type_ref: "system/hash"`. The hash value identifies the referenced entity in the envelope's `included` map or the content store.

### 2.3 Value Constraints

Value constraints (range checks, pattern matching, enumeration) are defined by the type extension (EXTENSION-TYPE.md). Core type definitions describe structure only. The type extension adds a `constraints` field to type definitions as an open-type extension field (see §2.10 Open Types).

### 2.4 Primitive Types

Eight primitives mapping to CBOR value types:

| Type | CBOR Major Type | Description |
|------|----------------|-------------|
| `primitive/string` | 3 (text string) | UTF-8 text |
| `primitive/bytes` | 2 (byte string) | Binary data |
| `primitive/uint` | 0 (unsigned integer) | 0 to 2^64-1 |
| `primitive/int` | 0, 1 (unsigned + negative) | Signed integer |
| `primitive/float` | 7 (float16/32/64) | IEEE 754 floating point |
| `primitive/bool` | 7 (simple: true/false) | Boolean |
| `primitive/null` | 7 (simple: null) | Null value |
| `primitive/any` | Any | Unconstrained |

Type checking is strict: `primitive/bool` rejects integers 0/1. `primitive/int` accepts both unsigned (major type 0) and negative (major type 1). Integer types reject floats; float types reject integers.

### 2.5 Hash Type

`system/hash` is `primitive/bytes` — a flat byte string on the wire (CBOR bstr). The first byte is the format code (§1.2); the remaining bytes are the raw digest.

```
system/hash := primitive/bytes   ; 33 bytes for ecfv1-sha256 (code 0x00)
```

This is a core type used throughout the protocol for content addressing and entity references. All hash values — `content_hash` fields, `included` map keys, and entity references in data — use the same flat byte representation.

### 2.6 Path Type

`system/tree/path` is `primitive/string` — a tree-path-related string used for tree locations, handler routing, capability scoping, and pattern matching.

```
system/tree/path := primitive/string
```

This is a core type used throughout the protocol for tree addressing and naming-space references. All path values — handler patterns, resource targets, listing paths, capability scope patterns, and URI references — use the same string representation. Format rules are defined in §1.4 (path structure) and §5.4 (pattern syntax, canonicalization).

The entity system has four address primitives: content (hash), naming (path), type (name), and identity (peer-id). Each has a dedicated type.

### 2.7 Type Name Type

`system/type/name` is `primitive/string` — a type name string identifying a type definition (e.g., `"system/protocol/execute"`, `"primitive/string"`, `"system/handler/operation-spec"`).

```
system/type/name := primitive/string
```

This is a core type used throughout the protocol for type identity. All type name values — `type_ref` and `key_type` in field-specs, `name` and `extends` on type definitions, `input_type` and `output_type` on operation specs — use the same string representation. Convention maps type names to tree paths (`system/type/{type_name}`), but the name is the interop contract.

### 2.8 Peer ID Type

`system/peer-id` is `primitive/string` — a peer identity string. Base58-encoded `key_type || hash_type || digest` (§1.5, §7.4). For Ed25519 + SHA-256: 46 Base58 characters.

```
system/peer-id := primitive/string
```

This is a core type used in the protocol for peer identity. All peer ID values — `peer_id` on `system/peer` entities and connection messages — use the same string representation.

### 2.9 Inheritance

- A type MAY specify one parent via `extends`. Multiple inheritance is NOT supported.
- Child inherits all `fields` from parent.
- Child MUST NOT redefine a field that exists in the parent.
- Child MAY add new fields.

Constraint inheritance and narrowing rules are defined by the type extension (EXTENSION-TYPE.md).

### 2.10 Open Types

- Entities MAY contain fields in `data` not defined in the type.
- Unknown fields MUST be preserved on storage and forwarding.
- Implementations MUST NOT reject entities because of unknown fields.
- Type validation checks defined fields only.

Open types are load-bearing: content hashing covers all of `{type, data}` including unknown fields. Entity fidelity requires forwarding original bytes. A peer that strips or rejects unknown fields produces different hashes for the same entity, breaking content addressing for all downstream peers.

### 2.11 Type Conformance Levels

| Level | Name | Requirements |
|-------|------|------------|
| 0 | Unaware | No type system participation. Core protocol only. |
| 1 | Aware | Populate `system/type/*` at startup. Support type discovery via `system/tree` get. |
| 2 | Validating | Level 1 + type resolution with cycle detection + structural validation. |
| 2+ | Constrained | Level 2 + constraint validation. Requires type extension (EXTENSION-TYPE.md). |

Level 0 peers are fully functional protocol participants. Level 2 peers perform structural validation — field presence, field types, union matching. Constraint validation (value ranges, patterns, enumerations) is provided by the type extension at Level 2+.

---

## 3. Protocol Type Definitions

All protocol types defined as `system/type` entities. This section IS the message specification.

### 3.1 Envelope

```
system/protocol/envelope := {
  fields: {
    root:     {type_ref: "core/entity"}                ; Primary entity (materialized)
    included: {map_of: {type_ref: "core/entity"}, key_type: "system/hash"}
                                                       ; Bundled entities keyed by content hash (bytes)
  }
}
```

The envelope is an entity — it has a type, structured data, and can be content-hashed and stored.

`root`: The primary entity. Determines behavior — if root type is `system/protocol/execute`, peer processes as request.

`included`: Map of supporting entities keyed by their content hash (`system/hash` byte strings). Contains capabilities, identities, signatures, delegation chains, and any other entities referenced by the root entity's data fields. Map keys are CBOR byte strings (bstr), not text strings.

Entities in the `included` map carry `content_hash` per §1.1. The content_hash MUST match the map key. This redundancy is intentional — entities are self-describing and must survive serialization roundtrips through code that does not preserve map key context (delivery chains, continuation transforms, generic CBOR processing).

**Protocol scope.** The `included` map on `system/protocol/envelope` is for protocol-relevant entities: capabilities, identities, signatures, delegation chains, and entities directly referenced by protocol fields (e.g., hash references in EXECUTE `params`). Handlers returning multi-entity results — where the result bundles domain entities alongside the primary response — SHOULD use `system/envelope` (§3.1.1) as the result type, with domain entities in that inner envelope's own `included`. This keeps the outer protocol envelope focused on transport and authorization concerns.

**Wire transport optimization**: On the wire, implementations **MUST** validate each included entity's content_hash individually per entity fidelity (§1.8). Implementations are **NOT REQUIRED** to compute or validate the envelope's own content_hash during transport.

#### 3.1.1 General Envelope

```
system/envelope := {
  fields: {
    root:     {type_ref: "core/entity"}
    included: {map_of: {type_ref: "core/entity"}, key_type: "system/hash"}
  }
}
```

Structurally identical to `system/protocol/envelope`. The distinction is semantic:

- **`system/envelope`** — general entity bundle. Used by extract, ingest, handler responses that package entities. The system can process this (ingest included entities) without protocol-level implications.
- **`system/protocol/envelope`** — wire transport format. Root determines protocol behavior (EXECUTE → process as request). Includes carry protocol entities (capabilities, identities, signatures).

The same applies: entities in the `included` map carry `content_hash` matching the map key (§3.1).

### 3.2 EXECUTE

```
system/protocol/execute := {
  fields: {
    request_id: {type_ref: "primitive/string"}
    uri:        {type_ref: "system/tree/path"}
    operation:  {type_ref: "primitive/string"}
    resource:   {type_ref: "system/protocol/resource-target", optional: true}
    params:     {type_ref: "core/entity"}
    bounds:     {type_ref: "system/bounds", optional: true}
    deliver_to: {type_ref: "system/delivery-spec", optional: true}
    author:     {type_ref: "system/hash", optional: true}
    capability: {type_ref: "system/hash", optional: true}
  }
}
```

All EXECUTE requests MUST include `author` and `capability` — **except** requests targeting the connection path (§4). All referenced entities MUST be in the envelope's `included` map.

**Note**: Signature is NOT in EXECUTE. Signature found via target-matching in envelope — scan `included` for `system/signature` where `data.target` equals `execute.content_hash`.

`resource` is optional. When present, identifies the data paths being accessed as a `system/protocol/resource-target` — the dispatcher checks `grant.resources` against the target scope before handler dispatch (§5.2). When absent, no resource check at dispatch; the handler may still check internally. Since `resource` is in `data`, it is covered by the EXECUTE signature — the author commits to the target scope.

```
system/protocol/resource-target := {
  fields: {
    targets: {array_of: {type_ref: "system/tree/path"}}
    exclude: {array_of: {type_ref: "system/tree/path"}, optional: true}
  }
}
```

`targets` — Array of paths or patterns this operation accesses. MUST contain at least one entry. Each entry is a tree path in the same format as `grant.resources` patterns: canonicalized to absolute by the dispatcher. Peer-relative is permitted. Patterns (trailing `*`) are permitted for operations that scope over a subtree (e.g., snapshot, extract).

`exclude` — Optional array of paths or patterns to skip within the target scope. When absent, no exclusions (all targets are active). For pattern targets, caller excludes are part of the dispatch authorization check: if the grant excludes paths that overlap a target pattern, the caller MUST exclude them (or a superset) for the request to pass (§5.2). Grant excludes always take precedence — a caller exclude cannot grant access to paths the grant forbids, it can only confirm the caller isn't requesting them.

**Path-as-resource convention (SHOULD).** When a handler operation acts on a tree path that the caller needs authorization for, that path SHOULD be carried in the EXECUTE's `resource` field rather than as a path-typed field inside `params`. Putting it in `resource` lets the dispatch layer's standard capability check do the authorization. Putting it in `params` works too, but the handler then has to perform its own authorization check against the path the caller actually targeted — duplicating what the protocol already provides. Operation-specific options that don't require their own authorization (budgets, modes, write targets created under the handler's grant, data fields stored in the constructed entity) belong in `params`. `system/tree:get`/`put` (§6.3) is the reference shape — paths in resource, options in params.

**Empty-params wire shape (normative).** `params` is required (no `optional: true` in the field spec). When an operation has no params content, the `params` field MUST be a `primitive/any` entity whose `data` is the canonical CBOR encoding of an empty map (the single-byte sequence `a0` per ENTITY-CBOR-ENCODING.md). The canonical encoding makes the params content_hash stable across implementations. An operation is declared as taking no params via the handler manifest's `operations[op].input_type` — when absent, or when explicitly set to `primitive/any`, the operation has no params content and the empty-params shape applies. Handlers MUST accept the empty-params shape for such operations and SHOULD reject mismatched payload **types** (e.g., a non-`primitive/any` entity passed where empty params is expected) with **400 `unexpected_params`**. Rejection MUST be on the entity type, not on the presence of extra fields inside a `primitive/any` data map — this preserves forward compatibility, so a future spec revision can add an optional field to a currently-empty-params op without breaking old callers.

`bounds` is optional. If absent, the receiving peer applies its own defaults (§5.9).

`deliver_to` is optional. When present, the handler delivers results as an EXECUTE to the delivery URI instead of returning an EXECUTE_RESPONSE. See EXTENSION-INBOX.md. Peers that do not implement inbox delivery ignore this field and return a normal EXECUTE_RESPONSE.

**Signature**: The request author signs the EXECUTE entity. The signature is a separate `system/signature` entity in `included` where `signature.data.target` equals the EXECUTE's content hash. Since the content hash covers `{type, data}`, and `author`, `capability`, `bounds`, and `deliver_to` are in `data`, they are all covered by the signature.

**Request ID**: The requester generates `request_id`. It is part of the signed EXECUTE data.

- **Format**: Any non-empty string. UUIDs are **RECOMMENDED**.
- **Scope**: The combination `(author, request_id)` uniquely identifies a request.
- **Correlation**: The receiver correlates an EXECUTE_RESPONSE to its EXECUTE by `request_id`.

### 3.3 EXECUTE_RESPONSE

```
system/protocol/execute/response := {
  fields: {
    request_id:      {type_ref: "primitive/string"}
    status:          {type_ref: "primitive/uint"}
    result:          {type_ref: "core/entity"}
    budget_consumed: {type_ref: "primitive/uint", optional: true}
      ; Operations consumed during this EXECUTE's processing.
      ; Optional metadata for cross-peer budget accounting.
      ; Absent means each peer enforces its budget independently.
  }
}
```

Status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 207 | Partial success — binding committed but cascade halted. See SYSTEM-COMPOSITION.md §2.7A for the `system/tree/partial-result` response envelope. |
| 400 | Bad request |
| 401 | Authentication failed (also: `capability_revoked` per `EXTENSION-ROLE.md` §5.5; `unresolvable_grantee` per §5.5 of this doc — cap's `grantee` does not resolve to a present `system/peer` entity) |
| 403 | Forbidden — request-time authorization DENY (§5.2). Default `code` = `capability_denied`; more-specific authorization codes: `scope_exceeds_authority` (capability handler request subset-validation, §6.2). See §5.2 verdict-to-status mapping. |
| 404 | Not found |
| 409 | Conflict (duplicate_request_id, path_exists) |
| 429 | Rate limited |
| 500 | Internal error |
| 501 | Not supported |
| 503 | Service unavailable |

Error responses use `system/protocol/error` as the result entity type:

```
system/protocol/error := {
  fields: {
    code:    {type_ref: "primitive/string"}    ; Programmatic identifier (e.g., "capability_denied")
    message: {type_ref: "primitive/string", optional: true}  ; Human-readable detail
  }
}
```

Error codes are scoped per handler — connection errors (§4.7), tree errors (EXTENSION-TREE.md Appendix A), and domain handler errors each define their own `code` values. The `status` field on EXECUTE_RESPONSE provides the numeric category; `result.data.code` provides the specific error within that category.

**Authorization-path code discipline (normative, v7.71).** A request-time authorization `DENY` (§5.2) MUST be surfaced with `status` per §5.2 (403 default; the single `unresolvable_grantee → 401` carve-out plus the `capability_revoked → 401` in-flight cascade carve-out per EXTENSION-ROLE.md §5.5) and `result.data.code` set to the authorization domain's defined code — `capability_denied` by default, or a more-specific defined authorization code (`scope_exceeds_authority`, `unresolvable_grantee`, `capability_revoked`) where one applies. Implementations MUST NOT surface a generic catch-all default (e.g. `verification_failed`) on an authorization path; the catch-all is a sign that an authorization failure escaped its defined code. Capability expiry (§5.6 / §5.2 validity check) surfaces as the default `capability_denied` — there is no separate `capability_expired` string. The §3.3 status row is the single source of truth for `status`; the authorization codes live in their domain homes (§5.2, §6.2, EXTENSION-ROLE.md §5.5); this paragraph and the §3.3 403 row pointer keep them paired without spawning a parallel registry. Enforcement vectors: GUIDE-CONFORMANCE §9 capability-handler row, `AUTHZ-*` matrix.

**Result carrier and dispatch-surface equivalence (normative).** A handler's `result` is an entity of the operation's declared `output_type`. When a handler returns a **multi-entity result** — domain entities bundled alongside the primary response — the result entity MUST be a `system/envelope` (§3.1.1) carrying those entities in its own `included` map; the outer protocol envelope's `included` is reserved for protocol entities (capabilities, identities, signatures — §3.1). This is the cross-peer wire contract: a peer receiving an `EXECUTE_RESPONSE` for a multi-entity op MUST find the domain subtree in the result envelope's `included`, never in an out-of-band channel. A handler's result MUST be identical regardless of dispatch surface — external EXECUTE (wire `EXECUTE_RESPONSE`), internal sub-dispatch (one handler invoking another in-process), or remote dispatch to another peer. In particular, a `system/envelope` result's `included` subtree MUST be preserved on every surface; internal and remote dispatch MUST NOT drop it or collapse the result to a subset of its fields. Consumers that dispatch handlers internally and read the result back — notably `compute/apply` (EXTENSION-COMPUTE.md §4.1) for navigation/materialization and continuation chains (EXTENSION-CONTINUATION.md §2.1) forwarding a result to the next step — therefore receive the complete result an external caller would. The in-process representation of a result is implementation-private; only the cross-surface equivalence and the `system/envelope` wire carrier are normative.

**Request-side envelope-`included` preservation (normative).** Symmetrically, an EXECUTE envelope's `included` map MUST be preserved on every dispatch surface — local handler invocation, internal sub-dispatch (`ctx.execute`), and remote cross-peer dispatch — so a handler and its downstream continuations resolve hash references from `included` (e.g. via `hctx.Included`) consistently regardless of how the EXECUTE arrived. A dispatcher routing a locally-originated envelope to a remote peer MUST forward `included` (carried in the cross-peer envelope's own `included`); it MUST NOT drop the map before the wire. This is the request-side dual of the result-carrier rule above — the same defect class (a wire-construction site silently dropping `included`) on the inbound/forward direction. It is load-bearing for any chain or continuation that consumes a bundled entity — notably the `include_payload` mirror recipe (EXTENSION-SUBSCRIPTION.md §2.2), where the source-bundled changed entity must survive to the subscriber's continuation for `deref_included` (EXTENSION-CONTINUATION.md §2.2) to resolve it. (Receivers that ingest `included` into the content store on receipt satisfy by-hash *resolvability*; this rule additionally requires the `included` **map itself** to reach the continuation, because a pure transform like `deref_included` reads the envelope map, not the store.)

**Optional `budget_consumed` field.** Peers MAY include a `budget_consumed` field on EXECUTE_RESPONSE to report how many operations the EXECUTE's processing consumed. This enables cross-peer budget accounting for trusted peer groups (e.g., peers operated by the same entity, cluster members, federated deployments where operational cost matters). Semantics:

- **Absent (default)**: No cross-peer budget accounting. Each peer enforces its own budget independently based on the EXECUTE's `bounds` field (§5.9). This is the default behavior — implementations MUST NOT assume cross-peer budget accounting unless `budget_consumed` is present.
- **Present**: The responding peer reports operations consumed. The requesting peer MAY deduct `budget_consumed` from its local budget pool for cross-peer resource coordination.

When to include: A peer SHOULD include `budget_consumed` when the peers are in a trusted relationship and the operation is significant enough that cross-peer accounting matters. A peer MAY omit it when peers don't trust each other for resource accounting or the operation is lightweight.

**Trust model.** `budget_consumed` is a trust signal, not an authorization signal. A misreporting peer could claim low consumption to manipulate a trusting caller's accounting, but the caller's authorization is still enforced per-operation by the receiver — budget accounting is for resource management only. The mechanism for configuring which peers' reports to trust is implementation-defined: per-peer trust configuration, per-capability signaling, or global settings all satisfy the spec.

These are the only two wire message types. Any message that is neither EXECUTE nor EXECUTE_RESPONSE is invalid; the connection MUST be closed.

### 3.4 Params and Result as Entities

The `params` and `result` fields are typed as `core/entity` — they contain materialized entities `{type, data, content_hash}`, not raw data values. The `core/entity` type (ENTITY-NATIVE-TYPE-SYSTEM.md §8.1) describes this materialized form: every materialized entity carries its type path, typed payload, and identity hash. The bare structural root `entity` (§3.1.1 of TYPE-SYSTEM) is a separate type and not used as a `type_ref` marker — see TYPE-SYSTEM §2.7.1 for the distinction.

**Validation**: Implementations SHOULD validate `params.content_hash` and `result.content_hash` against their `{type, data}` on receipt, consistent with entity fidelity (§1.8). The outer EXECUTE/EXECUTE_RESPONSE content_hash covers the params/result bytes (including the embedded content_hash), so the EXECUTE hash is valid even if the params hash is not independently checked. However, handlers that use `params.content_hash` for sub-requests or storage SHOULD validate it to prevent propagation of incorrect hashes. Implementations MAY defer validation to handler processing time rather than dispatch time.

### 3.5 Supporting Types

```
system/peer := {                                  ; v7.65 — peer_id is NOT a hashable field
  fields: {
    public_key: {type_ref: "primitive/bytes"}     ; Raw key bytes (32 bytes for Ed25519; 64 bytes for 0xFE experimental-test)
    key_type:   {type_ref: "primitive/string"}    ; Canonical lowercase-ASCII string per the §1.5 seed table
                                                  ; (e.g. "ed25519"=0x01, "ed448"=0x02, "ml-dsa-65"=0x03,
                                                  ; "experimental-test"=0xFE); future allocations per §1.5
  }
}

; P×I primitive discipline: peer_id MUST NOT appear in
; the system/peer entity's hashable basis. content_hash(system/peer) is a pure
; function of (public_key, key_type) and is invariant under wire-form peer_id
; choice. The wire peer_id (Base58 per §1.5) is a presentation/routing handle
; derived from (public_key, key_type) and the chosen hash_type; conveyed at the
; wire layer (handshake, gossip, cap chains' peers: IdScope patterns) but does
; NOT contribute to content_hash. Caps, signatures, attestations, and identity
; bindings reference content_hash, not the wire peer_id.
;
; Composition with v7.64: v7.64 entities (with peer_id field in data) and v7.65
; entities (without) coexist by content_hash. Pre-v7.65 cap chains remain
; verifiable byte-for-byte against the entities they reference. Post-v7.65 cap
; chains use the new canonical content_hash. Chains MAY interleave; each link
; verifies if its referenced content_hash is locatable.

system/signature := {
  fields: {
    target:    {type_ref: "system/hash"}         ; Content hash of signed entity
    signer:    {type_ref: "system/hash"}         ; Hash of signer's peer entity
    algorithm: {type_ref: "primitive/string"}    ; e.g., "ed25519"
    signature: {type_ref: "primitive/bytes"}     ; Raw signature bytes
  }
}
```

**Signature model**: Signatures point TO the content they sign. The signed entity does NOT reference the signature. To find a signature for an entity, scan the envelope's `included` map for `system/signature` entities where `data.target` equals the entity's content hash.

**The `signer` field is normative.** Verification algorithms (§5.2, §5.5) MUST compare `signer` against the expected identity hash (the EXECUTE's `author` or the capability's `granter`). This provides defense-in-depth: even if an attacker includes a valid signature from a different signer, the `signer` check ensures only the expected party's signature is accepted. Implementations MUST NOT skip this check.

**Signature storage in the tree.** The envelope model (scanning `included` for target-matching signatures) applies to in-flight entities. For entities persisted in the tree, implementations SHOULD store signatures using the invariant pointer pattern:

```
{peer_id}/system/signature/{content_hash_hex}  →  system/signature entity
```

Where `{peer_id}` is the signer's peer identity (base58) and `{content_hash_hex}` is the hex-encoded content hash of the entity that was signed (including the format code byte). For ECFv1-SHA-256, this is 66 hex characters starting with `00`.

To verify whether Peer B signed an entity with content hash H: construct path `bob_id/system/signature/{hex(H)}`, get entity at path, verify `target == H`, verify `signer == bob_peer_hash`, verify cryptographic signature using Bob's public key.

This convention gives signatures four properties: (1) **Discoverable** — given a content hash and a peer_id, the signature path is deterministic. (2) **Cacheable** — when Alice caches Bob's data under `bob_id/...`, she also caches Bob's signatures under `bob_id/system/signature/...`. (3) **Forwardable** — when Carol asks Alice for Bob's data, Alice can include Bob's signatures. Carol can verify Bob's authority without contacting Bob. (4) **Multi-party** — each signer's signature lives in their own namespace. Multiple peers signing the same content produce signatures at parallel paths.

**Hex encoding convention.** Content hashes in invariant pointer paths use hex encoding (lowercase, format code included). This provides visual distinction from peer IDs (base58, mixed case, 46 chars vs hex, lowercase, 66 chars) and a stable format code prefix (`00` = ECFv1-SHA-256).

**Convention, not requirement — except for chain-participating capabilities (normative — v7.44).** The invariant pointer pattern is SHOULD-level *in general*. The normative requirement for a single EXECUTE is §5.2: requests MUST be verified via envelope target-matching. **However:** a `system/capability/token` that can appear as a link (root or interior) in an authority chain that is **transported and re-verified away from its issuer** — cross-peer dispatch chains (EXTENSION-CONTINUATION.md §4.3), forwarded delegated tokens, any chain bundled by `collect_authority_chain`/`CollectChainBundle` — MUST have its signature discoverable at the invariant pointer path above. Rationale: the only general, peer-agnostic mechanism that *finds a detached signature to bundle it into transport* (and that the receiver's resolver/`§2656` ingest expects) is the invariant pointer path constructed from `(signer, target)`. A signature stored only at an extension-private path is invisible to that machinery, so the chain cannot be transported and the cap is unverifiable cross-peer — even though it is internally valid. This binds the extension that *locally mints* such a cap (rather than receiving it via envelope ingest, which §2656 already binds correctly): it MUST bind the signature at the invariant pointer path (it MAY *additionally* bind at an extension-private path for its own bookkeeping). Surfaced by EXTENSION-ROLE role-derived caps (core root caps per ROLE PR-1) binding their signature only at `{RoleDerivedTokenPath}/signature`, making a role-derived-rooted cross-peer continuation chain untransportable. Revocation does **not** have this defect — not because it "keys on the cap-path binding," but because revocation discovery uses a fundamentally safer *strategy*. `capability_path_for` (§5.1) resolves an extension/application-issued cap's path via an **observational reverse index (hash→path, built by recording bindings)**; that is scheme-agnostic by construction — the verifier need not know ROLE's path scheme because it recorded where it bound things. For caps with no recorded binding (wire-only caps from `request`/`delegate`), `is_revoked` performs an **explicit revocation marker check** at `system/capability/revocations/{root_hash_hex}` (§5.1 + §6.2 v7.62) — both classes converge on the same is-revoked decision, with no fail-open hole. Signature discovery had only the *path-construction* strategy (`findBoundSignature` constructs the invariant path) with no observational fallback and no equivalent marker mechanism, which is why an extension-private location made it silently invisible. The general SHOULD stands for caps that never leave their issuer.

**Discovery locality — general principle (normative — v7.45).** The signature case above is one instance of a class. Generalizing it once, so each extension does not re-derive-and-miss it (the recurring failure mode): **any entity that generic, cross-peer or cross-consumer core machinery must *discover* (not merely fetch by a hash it already holds) MUST be discoverable by one of two strategies — (A) *observational/recorded* discovery (the discoverer records location/derived state as it ingests or issues, e.g. the §5.5 revocation reverse index, substrate attestation indexes rebuilt from held entities per SYSTEM-COMPOSITION.md §6.7.4), with a fail-closed default when unresolved; or (B) a *core-general constructable path* (e.g. the §3.5 invariant pointer `/{signer}/system/signature/{target_hex}`, constructable with no extension knowledge). It MUST NOT rely on *path-construction against an extension-private scheme* — that is the defect class (the discoverer must know a convention it cannot derive; works locally and for the issuer, springs apart cross-peer/cross-consumer, and is typically masked by conformance tests that assert the divergent convention).** Content-addressed lookup (fetch a held hash) is scheme-free and exempt. An extension introducing a new discoverable entity MUST state which strategy it uses and (for A) its fail-closed behavior. This converts "audit indefinitely for new instances" into a checkable invariant; it is the discovery-side analog of §5.2's three-slot capability-provenance note.

### 3.6 Capability Types

```
system/capability/grant := {
  fields: {
    token: {type_ref: "system/hash"}
  }
}
; Used as result type when delivering capabilities.

system/capability/path-scope := {
  fields: {
    include: {array_of: {type_ref: "system/tree/path"}}
    exclude: {array_of: {type_ref: "system/tree/path"}, optional: true}
  }
}
; Scope for path-valued grant dimensions (handlers, resources).
; Values are tree paths, prefixes, or patterns.
; Both use matches_pattern (§5.4).

system/capability/id-scope := {
  fields: {
    include: {array_of: {type_ref: "primitive/string"}}
    exclude: {array_of: {type_ref: "primitive/string"}, optional: true}
  }
}
; Scope for identifier-valued grant dimensions (operations, peers).
; Values are operation names or peer identifiers.
; Both use matches_pattern (§5.4).

system/capability/grant-entry := {
  fields: {
    handlers:    {type_ref: "system/capability/path-scope"}    ; Handler scope
    resources:   {type_ref: "system/capability/path-scope"}    ; Data path scope
    operations:  {type_ref: "system/capability/id-scope"}      ; Operation scope
    peers:       {type_ref: "system/capability/id-scope", optional: true}
                                                               ; Peer scope
    constraints: {map_of: {type_ref: "primitive/any"}, optional: true}
                 ; Domain-specific narrowing fields, handler-interpreted.
                 ; String keys → handler-specific values.
                 ; Each key is a named restriction. Absent = unconstrained.
                 ; Adding a key narrows access. Removing a key widens access.
                 ; During delegation: child MUST retain all parent constraint keys
                 ; and values MUST be byte-equal (§5.6).
    allowances:  {map_of: {type_ref: "primitive/any"}, optional: true}
                 ; Domain-specific expanding fields, handler-interpreted.
                 ; String keys → handler-specific values.
                 ; Each key is a named privilege. Absent = most restricted.
                 ; Adding a key expands access. Removing a key narrows access.
                 ; During delegation: child MUST NOT add keys parent doesn't have
                 ; and values MUST be byte-equal (§5.6).
  }
}

system/capability/delegation-caveats := {
  fields: {
    no_delegation:         {type_ref: "primitive/bool", optional: true}
                           ; If true, cannot delegate further.
    max_delegation_depth:  {type_ref: "primitive/uint", optional: true}
                           ; Maximum chain depth from this capability.
    max_delegation_ttl:    {type_ref: "primitive/uint", optional: true}
                           ; Maximum lifetime (ms) for delegated capabilities.
  }
}

system/capability/multi-granter := {
  fields: {
    signers:    {array_of: {type_ref: "system/hash"}}    ; identity hashes allowed to sign
    threshold:  {type_ref: "primitive/uint"}              ; K — how many of `signers` must sign
  }
}
; Multi-signature granter for K-of-N root capabilities (§3.6 "Multi-signature
; granter"). Inline in the cap's data; no separate entity. Each `signers` entry
; is an identity hash (same form `granter` carries in the single-sig case).
; Restricted to root caps (parent: null) by the M3 validity constraint.

system/capability/token := {
  fields: {
    grants:              {array_of: {type_ref: "system/capability/grant-entry"}}
    granter:             {union_of: [
                            {type_ref: "system/hash"},                     ; single-sig (today's behavior)
                            {type_ref: "system/capability/multi-granter"}  ; multi-sig root (M1/M2)
                          ]}                                  ; Granter's peer-entity hash, OR a multi-granter
    grantee:             {type_ref: "system/hash"}   ; Hash of grantee's peer entity
                                                      ; (per v7.39 PR-3: MUST resolve to a present
                                                      ; system/peer entity in local store or
                                                      ; wire envelope's included map; per-link in
                                                      ; chain; zero-hash and other unresolvable
                                                      ; hashes rejected at chain validation with
                                                      ; status 401 `unresolvable_grantee`)
    parent:              {type_ref: "system/hash", optional: true}  ; Delegation parent
                                                      ; (MUST be null when granter is a multi-granter — M3)
    created_at:          {type_ref: "primitive/uint"}     ; ms since epoch
    expires_at:          {type_ref: "primitive/uint", optional: true}
    not_before:          {type_ref: "primitive/uint", optional: true}
    delegation_caveats:  {type_ref: "system/capability/delegation-caveats", optional: true}
    resource_limits:     {type_ref: "system/resource-limits", optional: true}
  }
}
```

**Multi-signature granter (root-only K-of-N caps).** The `granter` field is polymorphic: either a single `system/hash` (single-sig, identical to prior behavior) or a `system/capability/multi-granter` carrying `{signers, threshold}`. A multi-sig cap expresses "this group of K-of-N peers jointly issued this root authority" (joint accounts, escrow, dual control, threshold approval, personal multi-device authority). The verifier finds K signatures from the constituent `signers` set instead of one from a single granter (§5.5 M4/M6). Single-sig caps verify identically to before — this is a strict superset.

**M3 — validity constraint (normative).** A capability whose `granter` is a multi-granter MUST have `parent: null` — multi-sig caps are root-only. (Polymorphic `granter` without polymorphic `grantee` means a non-root multi-sig cap cannot satisfy chain linkage `hash_equals(parent.grantee, child.granter)`; mid-chain multi-sig is deferred.) A multi-granter MUST satisfy: `len(signers) ≥ 2` (use single-sig for N=1), no duplicate `signers` entries, and `threshold` ∈ [2, len(signers)] (K=0/K=1/K>N invalid). These are checked **at chain-walk entry in `verify_capability_chain` for every entity in the chain (MUST)**, SHOULD before adding a cap to the content store, and MAY at envelope decode. **Error-code normalization:** regardless of which pipeline layer detects an M3 violation, when the rejected entity is a `system/capability/token` the caller MUST be surfaced `403 capability_denied` (not `400 bad_request`) — the response shaper translates a structural-decode rejection to a capability rejection keyed on the failed entity's `type`. **Precedence:** M3 structural validity is checked *before* signature verification on the same cap, so M3 violations surface as `403 capability_denied` rather than `401`.

**Scope types.** Two scope types provide typed structure for grant dimensions. `system/capability/path-scope` is for dimensions whose values are tree paths (handlers, resources) — its `include` and `exclude` arrays hold `system/tree/path` values. `system/capability/id-scope` is for dimensions whose values are identifiers (operations, peers) — its arrays hold `primitive/string` values. Both have the same `{include, exclude}` structure. The `matches_scope` algorithm (§5.2) accesses these fields structurally and works uniformly across both types.

**Grant-entry fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `handlers` | `system/capability/path-scope` | Yes | Handler patterns — which handlers can be called (e.g., `{include: ["system/tree"]}`). Uses `matches_pattern` (§5.4). |
| `resources` | `system/capability/path-scope` | Yes | Data path patterns — which paths can be accessed. `exclude` on this scope replaces the former top-level `exclude` field. |
| `operations` | `system/capability/id-scope` | Yes | Allowed operations (e.g., `{include: ["get"]}`). Uses `matches_pattern`; `{include: ["*"]}` matches any operation. |
| `peers` | `system/capability/id-scope` | No | Peer scope — which peers the grant applies to. When absent, defaults to local peer only (`{include: [local_peer_id]}` constructed at evaluation time). Peer IDs are explicit — there is no `"self"` alias. |
| `constraints` | `map_of: primitive/any` | No | Domain-specific narrowing fields (string keys → any values). Handler-interpreted. Keys can't be dropped and values must be byte-equal during delegation (§5.6). |
| `allowances` | `map_of: primitive/any` | No | Domain-specific expanding fields (string keys → any values). Handler-interpreted. Keys can't be added and values must be byte-equal during delegation (§5.6). |

**Optional field defaults.** All optional fields on capability tokens have well-defined absent behavior:

| Field | When absent |
|-------|-------------|
| `parent` | Root capability — granter must be local peer (§5.5) |
| `expires_at` | No expiration — capability valid indefinitely |
| `not_before` | Immediately valid — no activation delay |
| `delegation_caveats` | Unrestricted delegation — grantee may delegate freely |
| `resource_limits` | No resource constraints — peer defaults apply (§5.9) |
| `peers` (on grant-entry) | Local peer only — `{include: [local_peer_id]}` at evaluation |
| `constraints` | No domain-specific restrictions — handler applies its defaults |
| `allowances` | No domain-specific expansions — handler applies its most restricted mode |

These fields exist because the full computational model (inbox delivery, subscriptions, compute) requires them. A simple request-response peer may never populate them. The algorithms (§5.5, §5.6, §5.7) treat absent fields as unconstrained — checks are skipped when the field is null.

**Capability signature**: The capability is signed by the granter. The signature is found via target-matching — scan `included` for `system/signature` where `data.target` equals the capability's content hash and `data.signer` equals the capability's `granter`.

**Capability handler operation types:**

```
system/capability/request := {
  fields: {
    grants:  {array_of: {type_ref: "system/capability/grant-entry"}}
                        ; Requested scope — the peer asks for this, the handler decides.
                        ; Handler validates these are a subset of (caller's cap) ∩ (policy entry).
    ttl_ms:  {type_ref: "primitive/uint", optional: true}
                        ; Requested lifetime in ms.
  }
}

system/capability/revoke-request := {
  fields: {
    token:   {type_ref: "system/hash"}                   ; Hash of capability token to revoke
    reason:  {type_ref: "primitive/string", optional: true}
                                                          ; Optional human-readable reason;
                                                          ; persisted into the revocation marker.
  }
}

system/capability/revocation := {
  fields: {
    token:       {type_ref: "system/hash"}                ; Hash of the revoked token
    reason:      {type_ref: "primitive/string", optional: true}
                                                          ; Mirrors revoke-request.reason
    revoked_at:  {type_ref: "primitive/uint"}             ; Wall-clock millis since Unix epoch
                                                          ; (handler-set; caller-supplied values
                                                          ; MUST be ignored — see §6.2 cross-cutting
                                                          ; timestamp convention)
  }
}
; Persisted marker entity at system/capability/revocations/{cap_hash_hex}
; where {cap_hash_hex} is the §3.5 invariant-pointer hex form of the
; revoked token's content hash (lowercase, format-code byte included;
; 66 hex characters for ECFv1-SHA-256). NOT the input to the revoke op
; — that is system/capability/revoke-request.

system/capability/delegate-request := {
  fields: {
    parent:  {type_ref: "system/hash"}                    ; Parent capability token's content hash
    grants:  {array_of: {type_ref: "system/capability/grant-entry"}}
                                                          ; Child grants (MUST be subset of parent's
                                                          ; via matches_scope §5.2)
    ttl_ms:  {type_ref: "primitive/uint", optional: true}
                                                          ; Optional child TTL; MUST NOT exceed
                                                          ; parent's remaining TTL
  }
}
; Delegate v1 is self-attenuation only: grantee = caller's authenticated
; identity always. No grantee field. Handler checks parent.grantee ==
; caller's authenticated identity (direct hold, not chain-walk). Third-party
; delegation (grantee = some other peer) is deferred to a future amendment.
;
; Delegate v1 is ALSO same-peer-only: caller MUST equal local_peer. A remote
; caller invoking delegate is rejected with 501 unsupported_operation. Cross-
; peer self-attenuation is performed client-side (construct + sign child cap
; locally from the parent); the handler offers no help there. Rationale (v7.63):
; chain linkage hash_equals(parent.grantee, child.granter) + grantee = caller
; force child.granter = caller, requiring the caller's signature on the child
; cap. The handler runs on the issuer peer and does not hold a remote caller's
; keypair, so cross-peer delegate cannot produce a chain-valid child under the
; v1 shape. Cross-peer delegate is deferred alongside third-party grantee? —
; the two share the "who signs the child cap and how" question.

system/capability/policy-entry := {
  fields: {
    peer_pattern: {type_ref: "primitive/string"}          ; Matches the path segment exactly;
                                                          ; "00abc123..." (66-hex peer hash) or the
                                                          ; literal "default" (fallback for unknown peers).
                                                          ; The glyph "*" is NOT valid as a literal
                                                          ; fallback segment — "*" is the core glob char
                                                          ; (resource-target / grant-entry patterns);
                                                          ; using it as a literal segment overloads
                                                          ; the glyph. (v7.63: renamed from "*".)
    grants:       {array_of: {type_ref: "system/capability/grant-entry"}}
    ttl_ms:       {type_ref: "primitive/uint", optional: true}
                                                          ; Optional; null = no expiry
                                                          ; (issuer can still revoke)
    notes:        {type_ref: "primitive/string", optional: true}
                                                          ; Operator-facing comment, NOT load-bearing
  }
}
; Persisted at system/capability/policy/{peer_pattern}. Consulted by
; the capability handler's request op (§6.2) and by §4.4's
; authenticate-response initial-grant builder.
```

The `request` operation accepts a `system/capability/request` describing the desired scope. The handler evaluates the request via subset-validation against the caller's authenticated cap AND the matched policy entry (§6.2), returning a `system/capability/grant` containing the issued token. The `revoke` operation accepts a `system/capability/revoke-request`; the handler unbinds the token (if it has a known storage path) and writes a `system/capability/revocation` marker at `system/capability/revocations/{cap_hash_hex}` (§6.2). The `configure` operation accepts a `system/capability/policy-entry` and writes it at `system/capability/policy/{peer_pattern}`. The `delegate` operation accepts a `system/capability/delegate-request` (parent hash + narrowed grants); the handler validates that the caller is the local peer (else returns `501 unsupported_operation` — v7.63 F1), that the caller holds the parent directly (`parent.grantee == caller's authenticated identity`), and that grants are a proper subset of parent's; mints a self-attenuated child token signed with the local peer's keypair (which IS the caller's keypair under the same-peer constraint), and returns it.

**Cap-pattern peer-reference canonicalization.** Peer references in cap patterns (`peers:` IdScope: `"/{peer_id}/path"`) MUST be canonical form per §1.5. Three normative implementation behaviors:

1. **At mint with pubkey available** — a non-canonical Base58 in `peers: include = [...]` is canonicalized before storage; the stored policy carries canonical form only. Available when the impl has prior contact with the named peer (pubkey recorded at handshake).
2. **At match-time** — the runtime `peer_id` is canonical per §1.5 mandate + wire-acceptance canonicalize-on-storage rule; string-comparison against stored canonical-form patterns proceeds normally.
3. **At mint without pubkey (lazy canonicalize)** — when an operator mints a cap pattern using a non-canonical Base58 handle for a peer the impl has not previously contacted, the impl MUST accept the mint with the non-canonical form, recording the pattern as `pending-canonicalization`. On first contact with the named peer (handshake reveals pubkey), the impl MUST canonicalize the pending pattern in place and emit a debug log. Subsequent matches against the canonicalized pattern follow rule 2.

Lazy canonicalization preserves the paste-handle UX affordance from v7.64 (operator pastes any-form handle; system normalizes once peer connects). The transient `pending-canonicalization` state is bounded (one canonicalization event per pattern; idempotent via the v7.64 self-healing dual-form policy machinery, whose semantic narrows to legacy-decode under v7.65).

### 3.7 Handler Types

```
system/handler/manifest := {
  fields: {
    pattern:         {type_ref: "system/tree/path"}
    name:            {type_ref: "primitive/string"}
    operations:      {map_of: {type_ref: "system/handler/operation-spec"}}
    max_scope:       {array_of: {type_ref: "system/capability/grant-entry"}, optional: true}
    internal_scope:  {array_of: {type_ref: "system/capability/grant-entry"}, optional: true}
    expression_path: {type_ref: "system/tree/path", optional: true}
                     ; When present, the handler is compute-backed: dispatch evaluates
                     ; the expression at this path instead of calling language-native code.
                     ; Absent for language-native handlers (the common case).
  }
}

system/handler := {
  fields: {
    interface:       {type_ref: "system/tree/path"}
                     ; Tree path of the system/handler/interface entity (e.g.,
                     ; "system/handler/system/tree"). The single source of truth for the
                     ; public contract (pattern, name, operations). Resolve to navigate
                     ; from dispatch target to public contract.
    max_scope:       {array_of: {type_ref: "system/capability/grant-entry"}, optional: true}
                     ; Maximum tree access for this handler, regardless of request capability.
                     ; Absent = unscoped. System handlers (system/*) SHOULD NOT set max_scope.
    internal_scope:  {array_of: {type_ref: "system/capability/grant-entry"}, optional: true}
                     ; Declares the handler's internal needs. Used by the handlers handler
                     ; (§6.2) to construct the handler's grant during registration.
    expression_path: {type_ref: "system/tree/path", optional: true}
                     ; When present, dispatch evaluates the compute expression at this path
                     ; instead of calling language-native code (EXTENSION-COMPUTE).
  }
}

system/handler/operation-spec := {
  fields: {
    input_type:  {type_ref: "system/type/name", optional: true}
    output_type: {type_ref: "system/type/name", optional: true}
  }
}
```

**Handler-op input/output type registration convention (normative).** When a handler operation's `input_type` or `output_type` is an extension-defined entity type that does not pre-exist as a semantic type in the broader vocabulary (e.g., `system/capability/request` already exists as the capability-request type and is referenced directly by `system/capability:request`), the canonical type name MUST follow the pattern `{handler-path}/{op-name}-request` and `{handler-path}/{op-name}-result`. The handler manifest's `input_type` / `output_type` fields reference these canonical names; implementations register the type definitions at `system/type/{type_name}` during handler installation (per §3 type-registry conventions). Tooling and code generators rely on this pattern to derive op shapes without per-extension knowledge.

The core protocol's own core handlers already follow this convention: `system/handler:register` uses `system/handler/register-request` / `system/handler/register-result`; `system/type:validate` uses `system/type/validate-request` / `system/type/validate-result` (per §6.2). Extension handler ops (attestation, quorum, identity, role, compute, continuation, subscription, revision, network, inbox, group, type, history, clock, transaction, query, and any future extension) inherit this convention; their conformance sections reference §3.7 rather than restating the rule.

```

system/handler/interface := {
  fields: {
    pattern:    {type_ref: "system/tree/path"}
    name:       {type_ref: "primitive/string"}
    operations: {map_of: {type_ref: "system/handler/operation-spec"}}
  }
}
```

The **manifest** (`system/handler/manifest`) is the registration input — what callers provide to `system/handler:register`. It carries the full declaration including security configuration. The manifest is a request parameter, not a stored entity.

The **handler** (`system/handler`) is the dispatch target — what tree walk finds at pattern paths. It holds a path reference to the interface entity plus private configuration (`max_scope`, `internal_scope`, `expression_path`). The `interface` field structurally links the handler to its public contract.

The **interface** (`system/handler/interface`) is the external contract — the single source of truth for the handler's pattern, name, and operations. It does not include security configuration, which MUST NOT be exposed to connecting peers. Stored at `system/handler/{pattern}` for discovery.

The handlers handler (§6.2) decomposes the manifest into handler + interface entities during registration.

The dispatch mechanism (§6.6) uses `system/handler` entities at canonical pattern paths. Handler interface entities do not participate in dispatch. The type check (`entity.type == "system/handler"`) provides structural separation.

**`pattern` field semantics.** The `pattern` field in `system/handler/manifest` and `system/handler/interface` is typed `system/tree/path` and **MAY** include glob notation (e.g., `"system/type/constraint/*"`) for human-readable advertisement. The dispatcher does NOT interpret this field — handler resolution is by ENTITY-CORE-PROTOCOL.md §6.6 longest-prefix walk against `system/handler` entities at literal prefix paths. See §6.6 "Registration paths vs spec-advertised patterns" and `GUIDE-EXTENSION-DEVELOPMENT.md` §4.9 for the universal convention and corpus examples. Discovery consumers reading `HandlerInfo.pattern` (SDK-OPERATIONS §9.1) MUST handle this convention: the field is advertisement, not a dispatch URI.

### 3.8 Connection Types

```
system/protocol/connect/hello := {
  fields: {
    peer_id:      {type_ref: "system/peer-id"}
    nonce:        {type_ref: "primitive/bytes"}        ; random(32)
    protocols:    {array_of: {type_ref: "primitive/string"}}
    timestamp:    {type_ref: "primitive/uint"}          ; ms since epoch
    hash_formats: {array_of: {type_ref: "primitive/string"}, optional: true}
    key_types:    {array_of: {type_ref: "primitive/string"}, optional: true}
    compression:  {array_of: {type_ref: "primitive/string"}, optional: true}
    encryption:   {array_of: {type_ref: "primitive/string"}, optional: true}
  }
}

system/protocol/connect/authenticate := {
  fields: {
    peer_id:    {type_ref: "system/peer-id"}
    public_key: {type_ref: "primitive/bytes"}    ; Raw key bytes
    key_type:   {type_ref: "primitive/string"}   ; e.g., "ed25519"
    nonce:      {type_ref: "primitive/bytes"}     ; Other peer's nonce echoed back
  }
}
; Signature is delivered via target-matching in envelope.
```

### 3.9 Tree Types

```
system/tree/listing-entry := {
  fields: {
    hash:         {type_ref: "system/hash", optional: true}
    has_children: {type_ref: "primitive/bool"}
  }
}

system/tree/listing := {
  fields: {
    path:      {type_ref: "system/tree/path"}
    entries:   {map_of: {type_ref: "system/tree/listing-entry"}}
    count:     {type_ref: "primitive/uint"}        ; Total entries under prefix (in-scope filtered)
    offset:    {type_ref: "primitive/uint"}        ; Offset of first returned entry
    next_page: {type_ref: "system/hash", optional: true}  ; content hash of the next listing page
                                                          ;   (system/tree/listing); absent on last/only page.
                                                          ;   See EXTENSION-NETWORK §6.5.3.1 (static HTTP pagination).
  }
}
```

Each entry maps a name to a `system/tree/listing-entry`. `hash` and `has_children` are independent dimensions (§1.7): `hash` is the content hash of the entity bound at the path (absent if no entity is bound), `has_children` indicates whether child paths exist under this prefix. A path may have both (entity and children), either one, or neither (which would not appear in a listing).

```
system/tree/get-request := {
  fields: {
    tree_id:  {type_ref: "primitive/string", optional: true}
    mode:     {type_ref: "primitive/string", optional: true}
                                    ; "entity" (default) | "hash"
                                    ; Ignored when resource is a listing request (trailing /).
    limit:    {type_ref: "primitive/uint", optional: true}
                                    ; Maximum entries to return. Default: implementation-defined.
                                    ; Capped by agreed frame size.
    offset:   {type_ref: "primitive/uint", optional: true}
                                    ; Skip this many entries. Default: 0.
                                    ; Entries are ordered lexicographically by path segment.
  }
}
; The target path is carried by execute.resource, not params.
; Trailing "/" or empty string on resource: return listing.
; Otherwise: return entity at path.

system/tree/put-request := {
  fields: {
    entity:        {type_ref: "core/entity", optional: true}
                                    ; Present: store entity and bind path.
                                    ; Absent or null: remove binding at path.
    expected_hash: {type_ref: "system/hash", optional: true}
                                    ; Conditional write (CAS). Three cases:
                                    ; - ABSENT: the put is unconditional.
                                    ; - PRESENT and non-zero: the put MUST succeed only if
                                    ;   the current binding at the target path has this
                                    ;   content hash; if the hash differs OR no binding
                                    ;   exists, return 409 hash_mismatch.
                                    ; - PRESENT and the ZERO hash (the reserved empty/
                                    ;   all-zero value — never a valid content hash, so it
                                    ;   is unambiguous and distinct from omitting the field):
                                    ;   CAS-create. The put MUST succeed only if the path is
                                    ;   currently UNBOUND; if a binding exists, return 409
                                    ;   hash_mismatch.
                                    ; Applies to both write (entity present) and remove
                                    ; (entity absent/null) operations. The three cases let a
                                    ; caller thread a prior-state hash uniformly: a known
                                    ; prior hash gates replace; the zero hash gates create;
                                    ; omission is unconditional. (See EXTENSION-SUBSCRIPTION
                                    ; §2.3 include_payload mirror recipe, which threads a
                                    ; notification's previous_hash — zero on a created event —
                                    ; into expected_hash so the bootstrap write is a clean
                                    ; CAS-create rather than an unconditional overwrite.)
    tree_id:       {type_ref: "primitive/string", optional: true}
  }
}
; The target path is carried by execute.resource, not params.
```

### 3.10 Types Handler Types

```
system/type/validate-request := {
  fields: {
    entity:    {type_ref: "core/entity"}             ; The entity to validate
    type_name: {type_ref: "system/type/name"}        ; Type to validate against (e.g., "system/protocol/execute")
  }
}

system/type/validate-result := {
  fields: {
    valid:  {type_ref: "primitive/bool"}
    errors: {array_of: {type_ref: "primitive/string"}, optional: true}
  }
}
```

### 3.11 Bounds, Callback, and Resource Types

```
system/bounds := {
  fields: {
    ttl:            {type_ref: "primitive/uint", optional: true}
    budget:         {type_ref: "primitive/uint", optional: true}
    chain_id:       {type_ref: "primitive/string", optional: true}
    parent_chain_id:{type_ref: "primitive/string", optional: true}
                     ; Parent chain's chain_id. Set when a continuation dispatches
                     ; a new sub-chain (fan-out, dynamic construction). The new chain
                     ; gets a fresh chain_id and records its parent here. Absent for
                     ; root chains. Enables process tree reconstruction via field
                     ; queries. See PROPOSAL-CONTINUATION-MODEL.md (C1).
    cascade_depth:  {type_ref: "primitive/uint", optional: true}
                     ; Current cascade depth in the emit pathway. Propagated
                     ; across peer boundaries via subscription notification
                     ; bounds. Receiving peers continue cascading from this
                     ; value rather than resetting to 0. See SYSTEM-COMPOSITION.md §3.4.
    visited:        {array_of: {type_ref: "system/tree/path"}, optional: true}
  }
}

system/delivery-spec := {
  fields: {
    uri:       {type_ref: "system/tree/path"}
    operation: {type_ref: "primitive/string", optional: true}
  }
}

system/resource-limits := {
  fields: {
    max_budget:         {type_ref: "primitive/uint", optional: true}
    max_ttl:            {type_ref: "primitive/uint", optional: true}
    max_visited_length: {type_ref: "primitive/uint", optional: true}
  }
}
```

### 3.12 Handlers Handler Types

```
system/handler/register-request := {
  fields: {
    manifest:        {type_ref: "system/handler/manifest"}
    types:           {map_of: {type_ref: "system/type"}, optional: true}
    requested_scope: {array_of: {type_ref: "system/capability/grant-entry"}, optional: true}
  }
}

system/handler/register-result := {
  fields: {
    pattern:  {type_ref: "system/tree/path"}
    grant:    {type_ref: "system/capability/token"}
  }
}

; unregister has no params content — the pattern is carried in EXECUTE.resource
; per the path-as-resource convention (§3.2). Callers send an empty-params shape:
;   {type: "primitive/any", data: <canonical CBOR empty map>}
```

`manifest` — The `system/handler` entity to register. The installation path is carried in `EXECUTE.resource.targets[0]` as `system/handler/{pattern}` (§3.2 path-as-resource convention). `manifest.pattern` MAY also be set as descriptive data; if present, it MUST match the resource-derived pattern, otherwise the handler rejects with **400 `manifest_pattern_mismatch`**. If `manifest.pattern` is absent, the handler derives it from the resource path.

`types` — Optional map of type name to type definition. These are installed at `system/type/{type_name}` during registration.

`requested_scope` — Optional scope declaration. If provided, the handlers handler uses this to create the handler's grant (attenuated from the peer root capability). If absent, the handler's `internal_scope` field is used.

`pattern` — For unregister, the pattern of the handler to remove.

`grant` — The capability grant created for the registered handler.

### 3.13 Operational State Types

Operational state types describe a peer's runtime configuration, transport bindings, and peer relationships. These are tree entities — stored via `put`, readable via `get`, listable via trailing-slash `get`, and subscribable via EXTENSION-SUBSCRIPTION.md. No new handlers are required; all operational state is managed through the tree handler.

Conforming peers SHOULD populate these entities for entity-native self-description, subscribability, and crash recovery. Non-population loses these properties but does not affect protocol interoperability. See §9.2.

```
system/transport := {
  fields: {
    protocol:   {type_ref: "primitive/string"}
                ; "tcp", "quic", "udp", "bluetooth", "websocket"
    addresses:  {array_of: {type_ref: "primitive/string"}}
                ; "0.0.0.0:4040", "[::]:4040"
    status:     {type_ref: "primitive/string"}
                ; "listening", "stopped", "error", "observed"
    parameters: {map_of: {type_ref: "primitive/any"}, optional: true}
                ; Transport-specific: frame_limit, keepalive, etc.
  }
}
```

Stored at `system/transport/{protocol}` for local transports. Remote peer transports at `system/peer/transport/{peer_id}/{protocol}` (same type, reused for peer discovery data).

*WebSocket addresses.* The `system/transport/websocket` entity's `addresses` field carries full WebSocket URLs (e.g., `"ws://192.168.1.42:4041"`, `"wss://peer.example.com/ws"`). Peers discover remote WebSocket endpoints by reading `system/peer/transport/{peer_id}/websocket`. Whether to use TLS (`wss://`), a dedicated port, or a path on a shared port is an operational decision — the transport entity carries the complete URL regardless of topology.

```
system/config := {
  fields: {
    concern:    {type_ref: "primitive/string"}
                ; "connection", "capability", "bounds", etc.
    parameters: {map_of: {type_ref: "primitive/any"}}
                ; Configuration key-value pairs
  }
}
```

Stored at `system/config/{concern}`. Open-ended configuration — the `concern` string identifies the subsystem, `parameters` carries its configuration. Domain handlers MAY define their own config entities under `system/config/` with domain-specific types (e.g., `system/config/local-files/shared` storing a `local/files/root-config` entity).

```
system/peer/status := {
  fields: {
    peer_id:      {type_ref: "system/peer-id"}
                  ; The observed peer
    status:       {type_ref: "primitive/string"}
                  ; "connected", "disconnected", "suspect"
    connected_at: {type_ref: "primitive/uint", optional: true}
                  ; ms since epoch, when connection established
    last_seen:    {type_ref: "primitive/uint", optional: true}
                  ; ms since epoch, last message received
    connection:   {type_ref: "system/tree/path", optional: true}
                  ; Path to connection entity (system/connection/{peer_id})
  }
}
```

Stored at `system/peer/status/{peer_id}`. State transitions: `(unknown) → connected → suspect → disconnected`. Reconnection returns to `connected`. The `connection` field is a path reference to the corresponding `system/connection` entity.

```
system/peer/self/status := {
  fields: {
    phase:                 {type_ref: "primitive/string"}
                           ; "starting" | "ready" | "draining"
    started_at:            {type_ref: "primitive/uint", optional: true}
                           ; ms since epoch, when phase first reached "ready"
    last_phase_transition: {type_ref: "primitive/uint", optional: true}
                           ; ms since epoch, last phase change
  }
}
```

Stored at `system/peer/self/status` (single entity per peer). The local peer's own runtime status — analog of `system/peer/status/{peer_id}` (which describes OBSERVED REMOTE peers). State transitions: `(unknown) → starting → ready → draining → (process exit)`. The `phase` value answers "do I expect responses?" for external observers: `ready` = yes; `starting` and `draining` = limited or no. A `stopped` value was considered and rejected: it is not reliably reachable from durable storage in the crash case. Observers detect a peer that is no longer running via connectivity absence (`system/peer/status/{peer_id}.status = "disconnected"`), not via this self-status entity. A process running multiple peers maintains a separate `system/peer/self/status` entity per peer, scoped to that peer's tree. The initial capability grant per §4.4 SHOULD include read access to `system/peer/self/status` so connecting peers and diagnostic tooling can observe lifecycle; this is a deployment-policy decision.

```
system/peer/alias := {
  fields: {
    name:    {type_ref: "primitive/string"}
             ; "alice-laptop", "build-server"
    peer_id: {type_ref: "system/peer-id"}
             ; The peer this name resolves to
  }
}
```

Stored at `system/peer/alias/{name}`. Local name resolution — an `/etc/hosts` analog for the entity system. Resolution is tree lookup at the path; no URI-level redirects. Alias names are local conventions, not protocol identifiers.

```
system/connection := {
  fields: {
    peer_id:        {type_ref: "system/peer-id"}
                    ; Remote peer
    transport:      {type_ref: "primitive/string"}
                    ; "tcp", "quic", "websocket"
    address:        {type_ref: "primitive/string"}
                    ; "192.168.1.42:4040"
    status:         {type_ref: "primitive/string"}
                    ; "active", "draining", "closed"
    established_at: {type_ref: "primitive/uint"}
                    ; ms since epoch
    parameters:     {map_of: {type_ref: "primitive/any"}, optional: true}
                    ; Negotiated: protocol_version, hash_format, compression, encryption
  }
}
```

Stored at `system/connection/{peer_id}`. Written through the emit pathway on connection establishment. Updated on close or failure. Referenced by `system/peer/status` via the `connection` path reference field.

**Operational state path conventions:**

| Path | Content |
|------|---------|
| `system/peer/self` | Local peer's `system/peer` entity (ENTITY-CORE-PROTOCOL.md §3.5; SHOULD-tier — see below) |
| `system/transport/{protocol}` | Local transport bindings |
| `system/config/{concern}` | Peer configuration |
| `system/peer/status/{peer_id}` | Known peer status (remote peer observation) |
| `system/peer/self/status` | Local peer's own runtime status |
| `system/peer/alias/{name}` | Human-readable peer names |
| `system/peer/transport/{peer_id}/{protocol}` | Remote peer transport data |
| `system/connection/{peer_id}` | Active connection state |

**Local-peer entity placement.** The local peer's `system/peer` entity (§3.5) SHOULD be bound at the path `system/peer/self`. This makes the entity tree-walkable by handlers that need it; the content_hash of the entity is computable by reading `self` and hashing the canonical encoding.

Conformance: peers that don't populate `system/peer/self` are still core-conformant. They lose tree-walkability for the local-peer entity; handlers that need the entity's content_hash can still compute it from peer_id (the entity content is `{peer_id}`, deterministic from peer_id).

Foreign-peer `system/peer` entities are NOT bound at fixed tree paths. They are content-addressed and reached via `envelope.included` (§6.5) or by content_hash lookup in the local content store. The `system/peer` entity content (`{peer_id}`) is deterministic from peer_id, so binding foreign entities at tree paths adds no information beyond what the operational-state subtrees (`system/peer/status/`, `system/peer/transport/`) already enumerate.

**Three distinct things use the name `system/peer`** — disambiguating:

| Name | What it is |
|------|-----------|
| `system/peer-id` | Type — Base58 string identifier (§2.8) |
| `system/peer` | Entity type — `{peer_id}` keypair-bearing entity (§3.5) |
| `system/peer/...` | Tree subtree — hosts `self`, operational state collections (`status/`, `alias/`, `transport/`); no `system/peer` handler |

---

## 4. Connection Establishment

### 4.1 Flow

```
Initiator                           Responder
    |                                    |
    +- EXECUTE hello ------------------->|
    |<-------------- EXECUTE_RESPONSE hello -+  (responder's hello data)
    |                                    |
    +- EXECUTE authenticate ------------->|
    |<------ EXECUTE_RESPONSE authenticate -+  (initiator's initial capability)
    |                                    |
    |<---------- EXECUTE authenticate ---+
    +- EXECUTE_RESPONSE authenticate --->|      (responder's initial capability)
    |                                    |
    |       Connection Established       |
    |                                    |
    +- EXECUTE (authenticated) --------->|
    |<---------------- EXECUTE_RESPONSE -+
```

The initiator sends EXECUTE hello; the responder replies with EXECUTE_RESPONSE containing the responder's hello data. Both sides then exchange authenticate requests — each authenticate EXECUTE receives an EXECUTE_RESPONSE carrying the initial capability token. Total: 3 EXECUTEs + 3 EXECUTE_RESPONSEs = 6 wire messages. Every EXECUTE receives an EXECUTE_RESPONSE — connection setup follows the same request-response pattern as the rest of the protocol.

**Mandatory core is legs 1–2; the reverse `authenticate` (leg 3) is reachability-gated.** The diagram's leg 3 (the responder sending an `authenticate` *to* the initiator) is the symmetric form, established only when the initiator is itself a serving/reachable peer the responder can later call back into. It is **OPTIONAL** and gated on the initiator's reachability:

- A responder **MUST NOT** proactively send a leg-3 `authenticate` to an initiator that has not indicated it accepts inbound dispatch. A **client-style initiator** (request/response only; does not serve inbound EXECUTEs — browser, CLI, conformance harness) is a fully conformant participant and **MUST be able to complete the handshake via legs 1–2 alone**, without receiving leg 3. An unsolicited inbound `authenticate` corrupts a client-style initiator's next read.
- The signalling mechanism by which a serving initiator opts into leg 3 (a `hello` "accepts-inbound" capability, or initiator-requested reverse capability) is **deferred** — no reference impl currently sends leg 3 (the diagram is aspirational on that leg). When a serving-initiator use case surfaces, the mechanism is pinned then. Until then, leg 3 is "the future symmetric form, gated; not yet sent."

### 4.2 Pre-Authorization Rules

- `system/protocol/connect` is the sole pre-authorized path.
- EXECUTE targeting this path MUST be accepted without `author` or `capability` fields.
- EXECUTE targeting any other path without auth fields MUST be rejected (status 403).
- The connection handler MUST enforce ordering: `hello` before `authenticate`.
- After connection is established, subsequent connection requests on the same connection MUST be rejected with status 409. Implementations MUST NOT issue a new capability token on reconnect.

Connection state is per-connection. A new connection requires a new handshake sequence.

### 4.3 URIs During Connection Setup

During connection setup, URIs are peer-relative (`"uri": "system/protocol/connect"`) because the remote peer's ID is not yet known. After connection is established, URIs MAY be either fully qualified or peer-relative (§1.4). Peer-relative URIs are implicitly scoped to the receiving peer. Fully qualified URIs are required only when referencing data belonging to another peer (e.g., cached remote data stored under that peer's id prefix).

### 4.4 Initial Capability Delivery

**Hello response:** The responder's EXECUTE_RESPONSE to the hello operation carries the responder's hello data as the result entity:

```cbor
; Hello EXECUTE_RESPONSE envelope
{
  "root": {
    "type": "system/protocol/execute/response",
    "data": {
      "request_id": "hello-001",
      "status": 200,
      "result": {
        "type": "system/protocol/connect/hello",
        "data": {
          "peer_id": "2KZFresponder...",
          "nonce": h'...',
          "protocols": ["entity-core/1.0"],
          "timestamp": 1737900000000
        },
        "content_hash": h'00...'
      }
    },
    "content_hash": h'00...'
  }
}
```

If the responder cannot negotiate compatible parameters (no common protocols, hash formats, or key types), it responds with an error status and the appropriate error code (see §4.7). The initiator does not need to infer negotiation failure from silence — the response is explicit.

**Authenticate response:** The initial capability is delivered in the EXECUTE_RESPONSE to the authenticate operation:
- `result` is an entity of type `system/capability/grant`
- `result.data.token` contains the capability token content hash
- The token entity, granter identity, and capability signature are in the envelope's `included` map

**Normative wire example:**

```cbor
; Authenticate EXECUTE_RESPONSE envelope
{
  "root": {
    "type": "system/protocol/execute/response",
    "data": {
      "request_id": "abc-123",
      "status": 200,
      "result": {
        "type": "system/capability/grant",
        "data": {
          "token": h'00...'                    ; Hash of capability token entity
        },
        "content_hash": h'00...'
      }
    },
    "content_hash": h'00...'
  },
  "included": {
    h'00...': {                                ; Capability token entity
      "type": "system/capability/token",
      "data": {
        "grants": [...],
        "granter": h'00...',                   ; Hash of granter identity
        "grantee": h'00...',                   ; Hash of grantee identity
        "created_at": 1737900000000
      },
      "content_hash": h'00...'
    },
    h'00...': {                                ; Granter's peer entity
      "type": "system/peer",
      "data": {
        "peer_id": "...",
        "public_key": h'...',
        "key_type": "ed25519"
      },
      "content_hash": h'00...'
    },
    h'00...': {                                ; Signature on capability token
      "type": "system/signature",
      "data": {
        "target": h'00...',                    ; Capability token's content hash
        "signer": h'00...',                    ; Granter's identity hash
        "algorithm": "ed25519",
        "signature": h'...'
      },
      "content_hash": h'00...'
    }
  }
}
```

Implementations SHOULD grant at least the following initial scope (the connecting peer depends on these capabilities being available):

```
grants: [
  { handlers:   {include: ["system/tree"]},
    resources:  {include: ["system/type/*", "system/handler/*"]},
    operations: {include: ["get"]} },
  { handlers:   {include: ["system/capability"]},
    resources:  {include: []},
    operations: {include: ["request"]} }
]
```

Implementations MAY grant additional scope beyond this minimum. The initial scope SHOULD be limited to read-only system operations unless the implementation has a specific reason to grant broader access. Handler capability grants live at `system/capability/grants/*`, outside the initial scope.

Each grant is self-describing: `handlers` says which handler can be called, `resources` says which data paths can be accessed, `operations` says what can be done. Path dimensions (`handlers`, `resources`) use `system/capability/path-scope`; identifier dimensions (`operations`, `peers`) use `system/capability/id-scope`. Both scope types have the same `{include, exclude}` structure. The first grant authorizes reading type definitions and handler discovery information through the tree handler. The second grant authorizes requesting capabilities through the capability handler. The capability handler grant has empty `resources: {include: []}` because the handler does not access tree paths — it processes capability operations directly. Neither grant specifies `peers`, defaulting to local peer only.

**Policy-table consultation at authenticate-response.** When peer B's authenticate handler builds the initial capability grant for connecting peer A, it consults the `system/capability/policy/*` table (glob — all entries under the policy subtree) for any per-peer grants matching peer A's authenticated identity (exact-match-or-`default`-fallback per §6.2 baseline policy surface — v7.63 F8). The initial grant scope delivered to A is the **union** of the SHOULD floor above and the matched policy entry's grants. Implementations without a policy table populated for peer A deliver only the SHOULD floor.

**No-op when capability handler is not installed.** Policy-table consultation at handshake is conditional on the `system/capability` handler being registered on peer B. Peers that do not install the capability handler deliver only the SHOULD floor — the lookup is a no-op against an empty/absent table. The SHOULD floor itself is a core protocol contract independent of the capability extension; only the policy-additive layer depends on the handler. (Per §6.2 the capability handler is MUST, so this clause is a forward-compat statement; non-conformant peers that omit the handler deliver the floor and nothing else.)

**The two-trigger-point story.** Same evaluation source (the policy table) consulted at two trigger points — handshake (delivers per-peer grants up front) and `system/capability:request` (peer asks for additional/different/narrower grants at runtime). Single source of truth.

**Why handshake is `union` and runtime-request is `subset-validation` (opposite topology).** At authenticate-time, the peer-side authority is the SHOULD floor (a minimum) plus the policy entry (additive operator allowance) — initial grants build UP from nothing. At request-time, the caller already holds an authenticated cap (a maximum); the policy entry is a further constraint; the request payload narrows further still — runtime requests narrow DOWN from an existing cap. Same policy table, opposite assembly direction, by design.

**Worked example.** Peer A connects to peer B.

- SHOULD floor: read `system/type/*`, read `system/handler/*`, `system/capability:request`.
- B's policy table entry for A's hash: `[{handler: 'system/tree', operation: 'get'}]`.
- **Handshake delivers (union):** floor ∪ policy entry = floor + `tree:get`.
- Later, A calls `system/capability:request {grants: [{handler: 'system/tree', operation: 'put'}]}` on B.
- **Request evaluates (subset-validation per §6.2):** the request asks for `tree:put`. Caller's auth cap covers `floor + tree:get` — does NOT cover `tree:put`. Returns `403 scope_exceeds_authority`.
- A re-issues `request {grants: [{handler: 'system/tree', operation: 'get'}]}`.
- **Request evaluates:** the request asks for `tree:get`. Caller's auth cap covers it; policy entry covers it. Validation passes; handler mints a token covering `tree:get` and returns it.

### 4.5 Hello Defaults and Negotiation

If `hash_formats` is absent, defaults to `["ecfv1-sha256"]`. If `key_types` is absent, defaults to `["ed25519"]`.

**Negotiation**: Each hello field that is an array of options represents capabilities the peer supports, listed in preference order. The responder computes the relationship between the two lists upon receiving the initiator's hello and includes its own hello data in the EXECUTE_RESPONSE. If a required field cannot be satisfied, the responder returns an error EXECUTE_RESPONSE (see §4.7).

Two negotiation shapes apply, because the fields differ in whether they are **identity-bound**:

- **Single active value** (`hash_formats`, `compression`, `encryption`). These are *not* identity-bound — either peer can produce output in any value it supports. The intersection is taken in the **initiator's** preference order and the **first match** becomes the **single active value for the connection** (the responder honors the first value the initiator lists that it also supports — deterministic from the initiator's list). For `hash_formats` this active value is the connection's **active `content_hash_format`**: both peers MUST author every entity transmitted on this connection under it, and MUST NOT transmit an entity whose `content_hash_format` is outside the negotiated active value (§4.5a). An empty `hash_formats` intersection MUST be rejected with `400 incompatible_hash_format` (§4.7).
- **Accept-set** (`key_types`). A `key_type` **is** identity-bound: each peer signs with the fixed key its identity holds and cannot adopt another. `key_types` therefore advertises the set of `key_type`s a peer can **verify**, not a value to be collapsed to one. The negotiation requirement is **mutual verifiability**: each peer's own identity `key_type` MUST appear in the other peer's advertised `key_types` set. If either peer's own `key_type` is absent from the other's set, the responder MUST reject with `400 unsupported_key_type` (the unsupported-`key_type` reject point below). There is no single "connection `key_type`"; each peer authors and signs under its own. The responder-side gate (own `key_type` ∈ initiator's set) is the MUST. The *symmetric* earliest-reject guarantee — that an incompatibility is caught at hello rather than at `authenticate` (§4.6) — rests on both peers advertising their **full** accept-set; a peer SHOULD advertise every `key_type` it can verify. A peer that deliberately advertises a narrowed set MAY cause an otherwise-compatible counterparty to reject later at `authenticate` rather than at hello — a conformant but non-canonical reject point.

"Single active value" and "accept-set" are normative terms: every negotiated hello field is one or the other. A field is an accept-set iff it is identity-bound (tied to a fixed property of the peer's keypair that cannot be chosen per-connection); otherwise it is a single active value. Future negotiation fields MUST be classified accordingly.

**Unsupported `key_type` canonical reject point (v7.66 closeout clarification).** Hello negotiation is the canonical earliest reject point for an unsupported `key_type`: when `key_types` intersection is empty, the responder MUST return `400 unsupported_key_type` (per §4.7) at the hello step. Implementations MAY ALSO reject an unsupported `key_type` later in the handshake (at `authenticate`, on `peer_id` decode, or on first wire `system/peer` entity received) AS A FALLBACK or DEFENSE-IN-DEPTH; rejecting at multiple surfaces is conformant. The v7.66 `AGILITY-UNKNOWN-1` conformance vector is satisfied if `400 unsupported_key_type` is emitted at any handshake surface; hello-time reject is the canonical guidance for new implementations (matches Rust's choice; simplifies cross-impl conformance reasoning; aligns with the §4.5 negotiation contract).

| Field | Required | Default | Negotiation |
|-------|----------|---------|-------------|
| `protocols` | Yes | — | Intersection, must be non-empty |
| `hash_formats` | No | `["ecfv1-sha256"]` | **Single active value** — first match in initiator order; the connection's active `content_hash_format` (§4.5a) |
| `key_types` | No | `["ed25519"]` | **Accept-set** — each peer's own `key_type` must be in the other's set (mutual verifiability); each peer signs with its own |
| `compression` | No | none | Single active value; empty = no compression |
| `encryption` | No | none | Single active value; empty = no encryption |

### 4.5a Authoring under the active `content_hash_format` (normative)

The `hash_formats` negotiation (§4.5) selects one **active `content_hash_format`** per connection. For the lifetime of that connection:

1. Every entity a peer authors **on the wire/identity surface** for transmission on this connection — the EXECUTE and EXECUTE_RESPONSE envelope framing, the capabilities it mints for this connection, signatures, and the identity entity it presents — MUST be content-hashed under the active format. This is the surface where identity-equality (`grantee == author`, `signer == author`; §5.2) is evaluated; keeping it single-format per connection is what makes that equality byte-exact.
2. A peer MUST NOT author a **wire/identity-surface** entity under a format outside the negotiated active value. **Content entities** (handler-produced results, stored data, tree nodes, async-delivery and subscription-notification bodies) are NOT required to be re-authored under the active format — they carry their own home-format (§1.2) `content_hash` and travel self-describing; the receiver validates them by their declared format byte. When the sender's home format differs from the connection active format, such content does not converge with the receiver's same-logical-input content (the §1.2 / §1.5 two-address-space case); this is expected, not an error.
3. **Relay carve-out.** An entity a peer *received earlier* under a different format and is merely *relaying* by reference follows §1.8 fidelity — it is forwarded as its original bytes, never re-authored. Relaying such a reference *across a connection whose active format differs* is the cross-content-address-space case, out of v1 scope per §1.5 (a translator handler's concern, not core's).
4. Consequently, **within a single connection there is exactly one `content_hash_format` in play** for authored traffic, and identity-equality comparisons (`grantee == author`, `signer == author`; §5.2) remain correct as byte-wise hash equality (§5.3). A peer MUST NOT re-derive a *received* identity's `content_hash` under a different (e.g. its own preferred) format in order to construct a reference to that identity — doing so manufactures a second form and breaks the equality (§1.8).
5. **Cap chains do not cross format boundaries in v1.** A cap chain has a self-consistent `content_hash_format` (§5.5 freeze). Combined with item 2, a chain authored under format X cannot be transmitted on a connection whose active format is Y ≠ X. A peer that mints persistent caps under its home format and then connects to a peer that negotiates a *different* active format MUST mint **fresh** chains under the connection's active format for that peer — a persistent-cap cache does not traverse a format downgrade.

Two peers whose `hash_formats` sets are **disjoint** cannot establish a connection (empty intersection → reject, §4.7). A peer that wishes to interoperate broadly SHOULD advertise every format it supports. The active format is a **property of the connection**, not of a peer: a peer that prefers SHA-384 negotiates **down** to SHA-256 with a SHA-256-only peer and authors SHA-256 on that connection.

### 4.6 Authenticate Signature

The authenticate operation uses target-matching signatures. The signature authenticates an authenticate entity:

```
; Construct authenticate entity from params
authenticate_entity = Entity {
  type: "system/protocol/connect/authenticate",
  data: { peer_id, public_key, key_type, nonce }
}
authenticate_hash = content_hash(authenticate_entity)

; Construct peer entity (the signer's peer)
peer_entity = Entity {
  type: "system/peer",
  data: { peer_id, public_key, key_type }
}
peer_hash = content_hash(peer_entity)

; Sign the authenticate entity's content hash
message = authenticate_hash       ; Sign full hash bytes (format code + digest)
signature_bytes = ed25519_sign(private_key, message)

; Create signature entity
signature_entity = Entity {
  type: "system/signature",
  data: {
    target: authenticate_hash,
    signer: peer_hash,
    algorithm: "ed25519",
    signature: signature_bytes
  }
}

; Include peer and signature in envelope
envelope.included[peer_hash] = peer_entity
envelope.included[signature_entity.content_hash] = signature_entity
```

**Proof-of-possession (normative).** On an `authenticate` EXECUTE on `system/protocol/connect`, the responder reconstructs the authenticate entity from params, computes its hash, and MUST perform all three checks:

1. **Nonce-echo (replay resistance).** The responder retains, per connection, the `nonce` it issued in this peer's `hello` response, and MUST verify `authenticate.nonce` equals that issued nonce. A mismatch — or an `authenticate` received before any hello nonce was issued — MUST be rejected with status **401 `invalid_nonce`**. (Without this, an authenticate signature captured on one connection is replayable on another.)
2. **Proof of possession.** The responder MUST locate a `system/signature` in the envelope `included` whose `target` is the authenticate entity's content hash, and MUST verify that signature against `authenticate.public_key`. An **absent** signature and an **invalid** signature MUST both be rejected with status **401 `authentication_failed`**.
3. **Identity binding.** The responder MUST verify that `authenticate.peer_id` is the peer-id derived from `authenticate.public_key` (per the §1.5 / §7.4 construction `Base58(key_type ‖ hash_type ‖ hash(public_key))`). A mismatch MUST be rejected with status **401 `identity_mismatch`**. (Without this, step 2 proves possession of *some* private key but not the key for the identity the caller claims — grants resolve by `remote_peer_id`, so an unbound proof lets a caller act under another peer's identity.)

The responder MUST also verify `authenticate.peer_id == hello.peer_id` for the same connection (the connection's claimed identity does not change mid-handshake; combined with step 3 this binds the whole handshake to one key).

**Connection-auth is the authentication boundary (status).** All proof-of-possession failures above (nonce mismatch, absent/invalid signature, identity mismatch) are **authentication** failures and MUST be reported with status **401**, and the responder MUST emit the coded `401` EXECUTE_RESPONSE **before** closing the connection (§4.1's "every EXECUTE receives an EXECUTE_RESPONSE" — a bare socket close is indistinguishable from a network fault and is non-conformant on connect-auth failure). After the connection is established, verification of authenticated EXECUTEs (`verify_request`, §5.2) is **authorization**: a `DENY` is reported with **403**, except `unresolvable_grantee` which remains **401** (§3.6 / §5.5).

**Hardening (SHOULD).** The responder SHOULD recompute the authenticate entity's content hash from its `{type, data}` before using it as the signature target, rather than trusting the wire-supplied `content_hash` (consistent with §5.2 validate-before-trust). The issued nonce SHOULD be a fresh ≥32-byte CSPRNG value per connection and SHOULD be single-use — a responder SHOULD NOT accept a second `authenticate` against the same issued nonce, and SHOULD invalidate the issued nonce on connection-state transition. `hello.timestamp` is informational, not an anti-replay input — the nonce is the anti-replay mechanism. The responder SHOULD validate `public_key` length against `key_type` up front (one rejection path for a malformed key) and MUST reject a `key_type` outside the known/negotiated set with **400 `unsupported_key_type`**.

### 4.7 Connection Error Codes

This table is a **normative MUST-emit contract**: clients key error handling off `result.data.code`, so the code and status for each failure are fixed across implementations (an impl that collapses several of these to one code, or returns a different status, is non-conformant). The three §4.6 proof-of-possession failures are all **401** (the connection handshake is the authentication boundary — §4.6).

| Failure | result.data.code | Status |
|---------|------------|--------|
| Incompatible protocol versions | `incompatible_protocol` | 400 |
| No common hash formats | `incompatible_hash_format` | 400 |
| No common key types | `incompatible_key_type` | 400 |
| Unsupported / unknown key type | `unsupported_key_type` | 400 |
| Unsupported `content_hash_format` (v7.66 §1.2 dispatch) | `unsupported_content_hash_format` | 400 |
| Nonce mismatch / absent / pre-hello (§4.6 step 1) | `invalid_nonce` | 401 |
| Absent or invalid authenticate signature (§4.6 step 2) | `authentication_failed` | 401 |
| `peer_id` not derived from `public_key`, or `hello`/`authenticate` peer_id mismatch (§4.6 step 3) | `identity_mismatch` | 401 |
| Connection already established | `connection_already_established` | 409 |
| Out-of-order operation (e.g., authenticate before hello) | `connection_sequence_error` | 400 |

The responder MUST emit the coded error EXECUTE_RESPONSE before closing the connection on any of the above (§4.6 status boundary). `invalid_signature` (the pre-v7.61 spelling for the step-2 failure) is superseded by `authentication_failed`; impls emitting `invalid_signature` for a connect-auth signature failure should migrate.

### 4.8 Inbound frame processing concurrency

This specification defines the wire protocol and dispatch semantics from the caller's perspective. Without an explicit rule on whether implementations process incoming frames sequentially or concurrently with outbound dispatch initiated from handlers, an implementation may default to synchronous inline dispatch, producing a deadlock class on bidirectional symmetric P2P: each peer's serve task waits for its own handler to complete, the other side's response cannot be read, both sides time out. The fix is a normative concurrency invariant on the inbound-frame-processing layer.

**Implementations MUST support inbound frame processing concurrent with outbound dispatch initiated from handlers.** Specifically: while a handler is processing a frame received on a connection, the implementation MUST be able to read and dispatch additional frames received on that same connection, and the implementation MUST be able to send outbound EXECUTEs (including responses to those additional frames) without waiting for the original handler to complete.

This is a **correctness requirement, not a performance requirement.** It does not mandate any particular dispatch architecture — worker pools, per-frame goroutines, request-response multiplexing, async-task-per-frame are all valid. It does **forbid** architectures where inbound frame processing blocks on outbound dispatch on the same connection.

Implementations MAY bound concurrency via worker pools, semaphores, or back-pressure. Implementations MAY queue dispatched work. The requirement is that inbound frame processing not block on outbound dispatch from the same connection. Implementations MAY apply per-handler timeouts, per-connection concurrency caps, or any other resource-bounding strategy that does not violate the MUST above.

**Store-safety under concurrent dispatch (v7.75).** Because inbound frames may be processed concurrently (above) and handlers may dispatch concurrently (§6.11), a handler's reads and writes against the peer's content store and tree index occur concurrently with those of other in-flight requests. **Implementations MUST make the content store and tree index safe under concurrent access from per-request dispatch.** A peer whose store data-races under concurrent dispatch (e.g., an unsynchronized map mutated from multiple request threads) is non-conformant — a data race is a crash, and a crash is a §4.9 resilience violation. The synchronization mechanism is impl-defined (serialize behind a single writer, reader-writer lock, sharded locks, single-writer actor/mailbox, or a natively concurrent store); a single-threaded or cooperative-async runtime that never touches the store from two threads satisfies this trivially. This was surfaced by the §7b concurrency gate, where two generated peers passed every functional vector yet crashed (double-free) or stalled (race on read) under sustained concurrent dispatch.

**Composition with other invariants.** This invariant is the connection-level analog of the version-transcription-writer enumeration pattern (EXTENSION-REVISION.md §4.4.4 v3.2) and the cross-peer chain-construction registry (ENTITY-CORE-PROTOCOL.md §5.8 v7.46) — all three close gaps where the protocol's silence on a structural property allowed impls to make a buggy choice. The fix shape is identical: state the invariant once, normatively, with clear boundaries on what does and does not count.

### 4.9 Resilience under sustained load (v7.75)

§4.8 makes inbound/outbound concurrency a correctness requirement and lets implementations bound concurrency by any mechanism (worker pools, semaphores, back-pressure, queues). It does not say what MUST happen when offered load exceeds what the peer can serve. That silence let peers that pass the entire functional conformance suite ship and still **fall over** under sustained concurrent load — caught by the §7b concurrency gate (GUIDE-CONFORMANCE §7b), where one generated peer crashed (thread/store exhaustion) and another stalled while passing every functional vector. A substrate is something other peers build on *because it stays up*; staying up under load is therefore a normative property of the substrate, not an optimization.

**Under sustained concurrent load and connection churn, a conformant peer MUST:**

- **(a) Stay responsive** — continue to accept, process, and respond to the requests it admits; it MUST NOT deadlock, livelock, or stop making progress.
- **(b) Bound its resource use** — memory, file descriptors, threads/tasks, and connections MUST NOT grow without bound under sustained load or under repeated connect→request→close churn. A per-request or per-connection resource leak is non-conformant.
- **(c) Deliver or signal — never silently drop.** For every request the peer admits, it MUST either complete it and respond, or emit an explicit failure signal (an error response, a back-pressure/refusal status, or a connection close carrying a coded error per §4.7/§6.12). Admitting a request and discarding it with no response and no error is non-conformant. *This is the sharpest single requirement in this section: an always-there substrate that loses work without a trace cannot be retried against, because the caller does not know what was lost.*
- **(d) Not crash** — overload MUST NOT terminate the peer process or leave a handler thread/task panicked-and-unrecovered. A store data race (§4.8) is a crash for the purpose of this clause.
- **(e) Recover** — when offered load subsides, the peer MUST return to normal latency and throughput without operator intervention (no permanent degradation, no wedged state).

**The mechanism is impl-defined and unconstrained**, exactly as in §4.8: an implementation MAY shed load (refuse with a coded error before admitting), apply back-pressure (block or slow the producer), bound a queue (and refuse over the bound), or scale workers — any strategy that produces outcomes (a)–(e). What it MUST NOT do is admit unbounded work, drop admitted work silently, leak per-request resources, or crash.

**This is an outcome contract, not a performance bar.** It says nothing about absolute throughput or latency, which are language- and deployment-dependent. A slow peer that degrades gracefully — slows down, sheds with a coded refusal, recovers when load drops — is conformant; a fast peer that drops silently or crashes is not. Conformance is verified by ratio/invariant probes (no latency runaway, no unbounded resource growth, no silent loss, no crash, recovery after load subsides), per-language-fair, not by cross-language absolute numbers. These outcomes are exercised by GUIDE-CONFORMANCE §7b T2.1 (sustained load) and T2.2 (connection churn), which run under the `concurrency` category — so a conformant §6.11 peer that holds (a)–(e) needs no additional category to be gated against §4.9.

### 4.10 Resource bounds and admission control (v7.75)

§4.9 keeps a peer up under the load it admits; this section governs what it admits. An unbounded substrate is a self-DoS surface — a single oversized envelope can exhaust memory and a deeply-nested capability chain can exhaust CPU on signature verification. The protocol is deliberately silent on *what* the limit values are (language- and deployment-dependent) but **not** on the requirement to *have* and *enforce* finite bounds and to reject over-limit input cleanly. **(a) + (b) are MUSTs**; they **ratify observed convergence** — a cross-impl audit found 6/6 reference peers already enforced (a) (all at 16 MiB) and 4/6 already enforced (b) (all at 64) with nothing in the spec telling them to. Gated by the validate-peer `resource_bounds` category.

- **(a) Maximum inbound envelope/payload size (MUST).** The peer MUST reject an inbound EXECUTE whose wire size exceeds its configured maximum with `413 payload_too_large`, before fully buffering or decoding it where the transport allows. The default maximum MUST be finite (an unbounded/absent default is non-conformant). This is **allocation-safety** — an unbounded payload forcing unbounded allocation is the same no-crash class as §4.9, not merely "DoS hygiene." *Emission shape*: because the over-size condition may be detected before the `request_id` is parsed, the peer SHOULD emit a `413` EXECUTE_RESPONSE correlated by `request_id` when the id is available, and otherwise MAY close the connection after a best-effort coded frame (the caller's §6.11(c) deadline backstops the no-id case; §4.9(c) "deliver-or-signal" is satisfied by the refusal or the close).
- **(b) Maximum capability-chain depth (MUST).** Capability-chain verification (§5.5) costs O(depth) signature verifications; the peer MUST reject a presented chain exceeding its configured maximum depth with **`400 chain_depth_exceeded`** rather than walking an attacker-controlled chain unboundedly. The default maximum MUST be finite. The status is **400, not 403** — a too-deep chain is a client-correctable *structural excess*, not an authorization denial; using 403 would conflate "too deep" with "you lack the capability" and the caller could not distinguish them.
- **(c) Connection / handshake admission (SHOULD + external-layer carve-out).** A peer SHOULD bound concurrent connections and refuse over-bound connections cleanly (`503 too_many_connections` or a connection close). This is **not a MUST**: connection admission is commonly owned by the layer below the peer (systemd socket limits, a reverse proxy, the OS fd limit), so a peer MAY rely on an external admission layer rather than self-limiting. Per-source rate-limiting is out of scope (firewall/proxy territory). The `resource_bounds` gate scores (c) as a non-failing WARN.

**Values are informative recommended defaults, not normative constants.** The contract is "enforce a finite *declared* bound and reject over-limit cleanly while continuing to serve" — never "pick this number." A deployment MAY raise, lower, or widen the bounds and stay conformant. Naming defaults (16 MiB / 64) serves only generator consistency and gives the gate a concrete over-limit input.

| Bound | Recommended default (non-normative) |
|---|---|
| Max inbound envelope/payload size (a) | 16 MiB |
| Max capability-chain depth (b) | 64 |

**Rejection is clean, not collapse:** hitting a bound returns the coded error (or refuses the connection) and the peer keeps serving — it MUST NOT crash or degrade service to in-flight requests (composes with §4.9). The per-request deadline (§6.11(c), `recv_timeout`/503) is the time-domain analog and is already a MUST.

**Error codes (component home for admission control / resource bounds, per §3.3 per-component scoping):**

| `code` | `status` | Trigger |
|---|---|---|
| `payload_too_large` | 413 | Inbound EXECUTE wire size exceeds the configured maximum (§4.10(a)) |
| `chain_depth_exceeded` | 400 | Presented capability chain exceeds the configured maximum depth (§4.10(b), §5.5) — non-authz status by design |
| `too_many_connections` | 503 | Concurrent-connection bound exceeded (§4.10(c), SHOULD); an implementation MAY instead refuse by closing the connection |

---

## 5. Capability System

### 5.1 Verification

Every authenticated EXECUTE MUST include `author` and `capability` in data. Peers MUST reject requests missing either with status 403. The request must also have a valid signature in the envelope.

**Revocation model.** Revocation is a tree operation: `put(path, null)` removes the capability's binding from the tree. The capability entity remains in the content store and in any caller's cached `included` map — the tree is the mutable authority layer that determines which capabilities the peer still honors. A chain whose root entity is no longer bound in the tree is revoked, regardless of whether the chain is cryptographically valid.

Chain verification (§5.5) validates cryptographic integrity using the `included` map (caller-provided). Revocation checking is an orthogonal layer that validates the peer still honors the root. Chain verification without revocation checking is sufficient for freshly-issued capabilities; revocation checking is required when capabilities are persisted and may outlive their issuance (e.g., compute subgraph installation grants, long-lived delegated tokens).

**`is_revoked` algorithm.** Implementations that support revocation provide the following check. The algorithm walks the delegation chain via the content store, falling back to the envelope's `included` map when available — supporting both persisted capabilities (e.g., compute installation grants in the content store) and fresh-wire capabilities (whose ancestors may only be in the envelope's included map). The root is then checked against TWO mechanisms: the path-binding check (catches caps whose root path was deleted) and an explicit revocation marker check (catches wire-only caps with no known storage path, and provides defense-in-depth for path-bound caps):

```
is_revoked(capability, ctx):
  ; Walk the delegation chain to the root capability
  current = capability
  visited = set()
  while current.data.parent is not null:
    if current.content_hash in visited:
      return true                            ; Chain cycle = revoked (defensive)
    visited.add(current.content_hash)
    ; Try content store first (persisted capabilities),
    ; fall back to envelope included map (fresh-wire capabilities).
    parent = ctx.content_store.get(current.data.parent)
    if parent is null and ctx.included is not null:
      parent = ctx.included.get(current.data.parent)
    if parent is null:
      return true                            ; Parent unresolvable in either source
    current = parent

  ; current is now the root capability
  root_tree_path = ctx.capability_path_for(current.content_hash)
  if root_tree_path is not null:
    stored = ctx.entity_tree.get(root_tree_path)
    if stored is null:
      return true                            ; Root deleted from tree = revoked
    if not hash_equals(stored.content_hash, current.content_hash):
      return true                            ; Bound entity differs from expected root
  ; If root_tree_path is null (wire-only cap), fall through to marker check.

  ; Explicit revocation marker check
  ; (covers wire-only caps; defense-in-depth for path-bound caps)
  marker_path = "system/capability/revocations/" || hex(current.content_hash)
  if ctx.entity_tree.get(marker_path) is not null:
    return true

  return false
```

A cap whose root has no known storage path is no longer ambiguous (no `unknown_root_policy` indirection): it is revoked iff a marker exists at `system/capability/revocations/{root_hash_hex}`. The `system/capability:revoke` operation writes that marker for both path-bound and wire-only caps (§6.2), so both classes converge on the same is-revoked check.

**Context requirements for `is_revoked`.** `is_revoked(capability, ctx)` can be called from two contexts:

1. **Verification context** (from `verify_request`, see §5.2): constructed by the dispatch chain at the wire boundary, before the handler is resolved. Contains peer-level services only.
2. **Handler execution context** (from extensions that call `is_revoked` explicitly, e.g., compute's reactive re-evaluation): the full handler context built in §6.5 step 7, a superset of the verification context.

Both contexts MUST expose the following methods when the peer supports revocation:

| Method | Purpose | Nullable? |
|---|---|---|
| `ctx.content_store.get(hash)` | Retrieve entity by content hash | Returns null on miss |
| `ctx.entity_tree.get(path)` | Retrieve entity at tree path | Returns null on miss |
| `ctx.capability_path_for(hash)` | Take a content hash; return the canonical storage path under `system/capability/grants/...` if the cap is stored there, or null for wire-only caps | Returns null if no known storage |
| `ctx.included` | The envelope's `included` map during wire verification, merged with the local content store. Impls MUST populate this from the active envelope when one is available — fallback lookup against `included` is the mechanism that lets cross-peer chain-walks succeed without round-trip GETs | MAY be null in post-envelope contexts (e.g., compute reactive re-eval) |
| `ctx.supports_revocation` | Boolean flag: revocation checking enabled | — |

Implementations MAY use a single data structure for both contexts (with the handler context adding handler-specific fields on top) or MAY use separate structures. The method names are illustrative — implementations MAY expose equivalent functionality under different names. The algorithm's logic MUST produce the same decisions regardless of representation or naming.

**`capability_path_for(hash)` lookup.** Takes a content hash; returns the canonical storage path where the root capability is stored, or null if the cap is wire-only. The core protocol defines storage conventions for the categories of capabilities it issues directly:

- **Handler grants**: `system/capability/grants/{pattern}` (established in §6.2, §6.8)
- **Handler grants index entries**: implementations MAY also track them at secondary paths

For user-delegated capabilities and application-issued capabilities, the storage path is application-defined. Implementations SHOULD maintain a reverse index (capability content hash → stored tree path) when issuing or recording capabilities for revocation support, so `capability_path_for` runs in O(1). Implementations MAY fall back to a scan of known capability storage locations when the reverse index is absent.

**Unknown root is no longer ambiguous.** Earlier revisions of this protocol had an `unknown_root_policy()` indirection (fail-closed vs fail-open) for caps whose root had no known storage path. That indirection is replaced by the revocation marker check above: a cap with no `capability_path_for` result is revoked iff `system/capability/revocations/{root_hash_hex}` exists. Both path-bound and wire-only caps converge on the same is-revoked check; implementations MUST NOT silently fail-open on wire-only caps.

**Conformance.** Revocation checking is **MUST-level for the basic verification algorithm in §5.2 when `verify_ctx.supports_revocation = true`** (v7.63 F2 — lifted from SHOULD). The opt-in remains the `supports_revocation` flag: implementations without any persistent-capability extension MAY set the flag `false` and skip the check. When the flag is true, `is_revoked` MUST run in `verify_request` step 4 and MUST honor its rejection on both path-bound and wire-only caps — an impl that writes the marker on `revoke` but does not read it in `verify_request` silently fails open on wire-only cap revocation, which contradicts v7.62's marker mechanism. Revocation checking is also MUST-level for extensions that depend on it for correctness (e.g., `EXTENSION-COMPUTE.md §7.2` reactive re-evaluation using installation grants). Extensions that require revocation checking MUST explicitly state this dependency and MUST provide `is_revoked(capability, ctx)` as part of their handler context.

Chain verification (§5.5) and revocation checking compose: full verification is `verify_capability_chain(capability, included, local_peer_id) AND NOT is_revoked(capability, ctx)`. Implementations MAY combine them into a single pass for efficiency, as long as both conditions are checked.

### 5.2 Verification Algorithm

```
verify_request(envelope, local_peer_id, verify_ctx):
  execute = envelope.root
  included = envelope.included

  ; 1. Validate content hash
  ; A tampered content hash is a structural envelope corruption — surfaces as
  ; AUTHZ_DENY (matching existing oracle/impl behavior); not strictly an
  ; authentication failure since the envelope's signer is not yet probed.
  if not hash_equals(content_hash(execute), execute.content_hash):
    return AUTHZ_DENY

  ; 2. Find and verify signature (target-matching) — authentication-class.
  ; The envelope has no verified signer here; failures are AUTH_DENY (the
  ; request itself cannot be authenticated).
  signature = find_signature(execute.content_hash, included)
  if signature is null:
    return AUTH_DENY
  if not hash_equals(signature.data.signer, execute.data.author):
    return AUTH_DENY

  author = included[execute.data.author]
  if author is null: return AUTH_DENY
  if not verify_signature(signature, author):
    return AUTH_DENY

  ; 3. Verify capability integrity — authorization-class.
  ; Past step 2 the envelope IS authenticated; failures here are AUTHZ_DENY
  ; (authenticated but unauthorized).
  capability = included[execute.data.capability]
  if capability is null: return AUTHZ_DENY
  if not hash_equals(capability.data.grantee, execute.data.author):
    return AUTHZ_DENY
  if not verify_capability_chain(capability, included, local_peer_id):
    return AUTHZ_DENY

  ; 4. Revocation check (MUST-level when verify_ctx.supports_revocation = true;
  ; see §5.1). Authorization-class.
  ; Persistent-capability extensions (compute installation grants, continuation
  ; dispatch capabilities, inbox deliver tokens, subscription tokens) benefit
  ; automatically. Implementations without persistent-capability extensions
  ; MAY skip via verify_ctx.supports_revocation = false for performance.
  if verify_ctx.supports_revocation and is_revoked(capability, verify_ctx):
    return AUTHZ_DENY

  ; Permission check (check_permission) is separate — called after
  ; handler resolution in the dispatch chain (§6.5), which provides
  ; the handler pattern needed for handler scope checking.
  return ALLOW

find_signature(target_hash, included):
  for hash, entity in included:
    if entity.type == "system/signature":
      if hash_equals(entity.data.target, target_hash):
        return entity
  return null

find_signature_by_signer(target_hash, signer_id, included):
  ; Multi-sig (§5.5 M4/M6/M7) needs signatures located by BOTH target and signer,
  ; since multiple constituents sign the same target. find_signature stays
  ; unchanged for single-sig and for the §5.2 step-1 EXECUTE-signature lookup.
  ; Signature lookups are scoped to the envelope's included (signatures are wire
  ; artifacts); identity-entity lookups follow each call site's resolution scope.
  for hash, entity in included:
    if entity.type == "system/signature":
      if hash_equals(entity.data.target, target_hash) and
         hash_equals(entity.data.signer, signer_id):
        return entity
  return null

matches_scope(value, scope, local_peer_id):
  ; Uniform scope check for all grant dimensions.
  ; Returns true if `value` is included and not excluded by `scope`.
  matched = false
  for pattern in scope.include:
    if matches_pattern(canonicalize(value, local_peer_id),
                       canonicalize(pattern, local_peer_id)):
      matched = true
      break
  if not matched: return false
  if scope.exclude is not null:
    for pattern in scope.exclude:
      if matches_pattern(canonicalize(value, local_peer_id),
                         canonicalize(pattern, local_peer_id)):
        return false
  return true

check_permission(execute, capability, handler_pattern, local_peer_id):
  ; Called after handler resolution (§6.5). Checks whether the capability
  ; grants the requested operation on the resolved handler and resource.
  ; Checks all four grant dimensions: handler, operation, peer, resource.
  ; When resource is present, the same grant must match all four dimensions.
  ; When resource is absent, resource dimension is unchecked at dispatch —
  ; handler may still check internally (§6.3, §6.7).
  operation = execute.data.operation
  target_peer = extract_peer(execute.data.uri, local_peer_id)
  resource_target = execute.data.resource                          ; may be null

  for grant in capability.data.grants:
    if not matches_scope(operation, grant.operations, local_peer_id):
      continue
    if not matches_scope(handler_pattern, grant.handlers, local_peer_id):
      continue
    peers_scope = grant.peers or {include: [local_peer_id]}
    if not matches_scope(target_peer, peers_scope, local_peer_id):
      continue
    ; Resource check — only when resource is present
    if resource_target is not null:
      if not check_resource_scope(resource_target, grant.resources, local_peer_id):
        continue
    return ALLOW
  return DENY

check_grant_covers(handler_path, operation, resource_target, capability, local_peer_id):
  ; Grant-probe helper for extensions that need to pre-flight-check capability
  ; coverage without constructing a synthetic EXECUTE. Same scope-matching logic
  ; as check_permission — the only difference is the target tuple is supplied
  ; directly rather than extracted from an EXECUTE.
  ;
  ; handler_path is the URI the dispatch would target (e.g., "system/tree" or
  ;   "/{peerB}/local/files") — used both for handler scope matching and to
  ;   extract the target peer for the peer scope check.
  ; resource_target MAY be null — when null, resource dimension is unchecked
  ;   (same semantics as check_permission when execute.resource is absent).
  ;
  ; Callers: extensions pre-flight-checking capability coverage, e.g., compute's
  ; install audit (EXTENSION-COMPUTE.md §3.3). Implementations MAY share the
  ; scope-matching inner loop between check_grant_covers and check_permission.

  target_peer = extract_peer(handler_path, local_peer_id)
  handler_pattern = handler_path

  for grant in capability.data.grants:
    if not matches_scope(operation, grant.operations, local_peer_id):
      continue
    if not matches_scope(handler_pattern, grant.handlers, local_peer_id):
      continue
    peers_scope = grant.peers or {include: [local_peer_id]}
    if not matches_scope(target_peer, peers_scope, local_peer_id):
      continue
    if resource_target is not null:
      if not check_resource_scope(resource_target, grant.resources, local_peer_id):
        continue
    return ALLOW
  return DENY

check_resource_scope(resource_target, grant_resources_scope, local_peer_id):
  ; Full scope check. The effective target scope (targets minus caller
  ; excludes) must be within the effective grant scope (includes minus
  ; grant excludes).
  ;
  ; For concrete targets: check grant include coverage + not in grant exclude.
  ; For pattern targets: check grant include coverage + every overlapping
  ; grant exclude must be covered by a caller exclude.

  caller_exclude = resource_target.exclude or []
  grant_include = grant_resources_scope.include
  grant_exclude = grant_resources_scope.exclude or []

  for target in resource_target.targets:
    ct = canonicalize(target, local_peer_id)
    ; Validate concrete path targets at the protocol boundary.
    ; Pattern targets (ending in *) go through pattern matching, not tree access.
    if not is_pattern(ct):
      validate_absolute_path(ct)

    ; Skip targets fully covered by caller's own exclude.
    ; (Caller targeted it then excluded it — redundant but valid. Effective
    ; target doesn't include it, so no authorization needed.)
    if is_covered_by(ct, caller_exclude, local_peer_id):
      continue

    ; Target must be covered by grant include.
    if not is_covered_by(ct, grant_include, local_peer_id):
      return false

    if is_pattern(ct):
      ; Pattern target: for each grant exclude that overlaps this target,
      ; the caller must have a corresponding exclude that covers it.
      ; Otherwise the effective target includes paths the grant forbids.
      for ge in grant_exclude:
        cge = canonicalize(ge, local_peer_id)
        if not patterns_overlap(ct, cge):
          continue
        ; This grant exclude carves out paths within our target.
        ; Caller must also exclude them (or a superset).
        if not is_covered_by(cge, caller_exclude, local_peer_id):
          return false
    else:
      ; Concrete target: must not be in grant exclude.
      for ge in grant_exclude:
        cge = canonicalize(ge, local_peer_id)
        if matches_pattern(ct, cge):
          return false

  return true

is_covered_by(path_or_pattern, pattern_set, local_peer_id):
  ; True if some pattern in the set covers the input.
  for p in pattern_set:
    if matches_pattern(path_or_pattern, canonicalize(p, local_peer_id)):
      return true
  return false

strip_wildcard(pattern):
  ; Extract the prefix from a pattern for overlap comparison.
  if pattern ends with "/*":
    return pattern[0 : len(pattern) - 2]   ; strip trailing "/*"
  if pattern == "*":
    return ""                               ; match-all has empty prefix
  return pattern                            ; concrete path unchanged

patterns_overlap(a, b):
  ; True if any concrete path could match both patterns.
  ; For prefix-wildcard patterns: one prefix contains the other.
  ; Works for concrete paths too — strip_wildcard on a concrete path
  ; returns the path itself, and the starts_with check is correct.
  prefix_a = strip_wildcard(a)
  prefix_b = strip_wildcard(b)
  return starts_with(prefix_a, prefix_b) or starts_with(prefix_b, prefix_a)

is_pattern(path):
  return path contains "*"

extract_peer(uri, local_peer_id):
  ; Extract the peer ID from a URI path.
  ; Short-form paths (no peer prefix) belong to the local peer.
  first = first_segment(uri)
  if is_peer_id(first): return first
  return local_peer_id
```

**Verification context (`verify_ctx`).** The `verify_request` algorithm takes a `verify_ctx` parameter — a **peer-level verification context** constructed by the dispatch chain at the wire boundary, before handler resolution. It is distinct from the handler execution context (built later in §6.5 step 7, after the handler is resolved). The verification context contains peer-level services that the peer already exposes:

```
verify_ctx = {
  content_store:       peer.content_store,       ; hash → entity lookup
  entity_tree:         peer.entity_tree,         ; path → entity lookup; also serves
                                                 ; revocation-marker lookups under
                                                 ; system/capability/revocations/{hex}
  included:            envelope.included,        ; fresh-wire capability source
  capability_path_for: peer.capability_path_for, ; hash → tree path lookup, or null
                                                 ; for wire-only caps (no fail-open;
                                                 ; null falls through to marker check
                                                 ; per §5.1)
  supports_revocation: peer.supports_revocation  ; feature flag
}
```

The same methods exposed on `verify_ctx` are also available on the full handler execution context (which is built later and is a superset — it also includes handler_grant, caller_capability, and handler-specific fields). Extensions like compute that call `is_revoked` from reactive paths use the handler context; its peer-service methods produce the same results as `verify_ctx`. Implementations MAY share a single representation between the two contexts (e.g., a single `peer_ctx` struct that dispatch augments with handler-specific fields in step 7). The distinction is conceptual — what matters is that the methods are available whenever `is_revoked` runs.

**Revocation checking in `verify_request`.** Step 4 of `verify_request` invokes `is_revoked` (§5.1) to catch capabilities that have been revoked since issuance. **Implementations that advertise `verify_ctx.supports_revocation = true` MUST invoke `is_revoked` and MUST honor its rejection on both path-bound and wire-only caps** (v7.63 F2 — lifted from SHOULD). The marker check at `system/capability/revocations/{root_hash_hex}` (§5.1 + §6.2) is the only mechanism that catches wire-only caps; an impl that writes the marker on `revoke` but does not read it here silently fails open on wire-only cap revocation, which contradicts v7.62's marker mechanism.

- Implementations that support any persistent-capability extension (compute, continuation, inbox, subscription, or any extension that stores a capability for later dispatch) MUST enable revocation checking (`supports_revocation = true`).
- Implementations without any such extension MAY disable it (`false`) to skip the per-request cost. The opt-out is the `supports_revocation` flag; when the flag is true, the wire-in above is the load-bearing mechanism.

Performance mitigation: adding a tree lookup to every EXECUTE verification has cost. Implementations SHOULD maintain a reverse index (`capability_hash → storage_path`) for O(1) root lookup; MAY cache "not revoked at time T" results with a short TTL; MAY short-circuit the walk at the first resolvable ancestor when a cached result is available. These are implementation strategies, not normative requirements — the normative requirement is that `is_revoked` runs and produces correct results when `supports_revocation` is enabled.

**Cross-extension coverage.** Integrating `is_revoked` into `verify_request` means every extension benefits automatically:
- Compute's installation grants are checked on every reactive sub-dispatch
- Continuation's stored `dispatch_capability` is checked on every continuation advance
- Inbox's `deliver_token` is checked on re-dispatch
- Subscription's dispatch tokens are checked on every notification
- Any future extension that stores a capability for later use gets the check for free

**Cross-peer capability provenance — the three slots.** A capability presented in an EXECUTE has three independent identity slots, each checked at a different point. Conflating them is the single recurring source of cross-peer capability bugs; this note states how the existing checks above compose (it adds no mechanism):

- **Root** — the peer that owns the resource being acted on. A chain can authorize action on peer X's resource only if it roots at an authority X conferred. Checked by `verify_capability_chain` (§5.5) at X.
- **Grantee (of the leaf)** — the *wielder*: the identity that authors the EXECUTE. `verify_request` step 3 (above) hard-DENYs unless `capability.data.grantee == execute.data.author`. The cap must be granted to whoever presents it.
- **In-chain granters** — every party that attenuated along the way, including any installer/minter that pre-mints a cap for later use. The install-time creator-authority check (`check_creator_authority`, §5.5) requires only that the writer appear as a granter *somewhere* in the chain — **not** that the chain roots at the writer.

In the local / same-peer case all three collapse onto one identity (a peer mints from its own authority and immediately wields it: root == sole in-chain granter == grantee). That collapse is precisely why a model reasoned about only locally silently omits two of the three slots — and why specs/guides validated against the local case have repeatedly needed correction when a cross-peer flow forced the slots apart (e.g. EXTENSION-CONTINUATION.md §3.1a in-chain reconciliation; EXTENSION-CONTINUATION.md §4.2 case 3 grantee). For **any** cross-peer capability-bearing operation, fill all three slots explicitly: **root = the resource owner; grantee = the EXECUTE author; in-chain granters = the attenuators (including any installer).** EXTENSION-SUBSCRIPTION.md §1.2 (subscribe caller cap + deliver_token — the three-cap content is all in EXTENSION-SUBSCRIPTION.md §1.2; there is no §1.3) and EXTENSION-CONTINUATION.md §4.2 case 3 (cross-peer `dispatch_capability`) are instances of this one model, not independent designs.

**Verdict-to-status mapping (normative, v7.73).** `verify_request` returns one of `ALLOW`, `AUTH_DENY`, or `AUTHZ_DENY`. The dispatcher MUST map:

- `AUTH_DENY` → status **401** with code `authentication_failed` (the request-time authentication boundary, parallel to §4.6's connect-time authentication boundary).
- `AUTHZ_DENY` → status **403** with code `capability_denied` by default, or a more-specific defined authorization code per §3.3 (e.g. `scope_exceeds_authority`, `capability_revoked` when known per v7.72 Class C).

The carve-out `unresolvable_grantee` → **401** (§3.6 / §5.5) remains — it is structurally authz (the grantee is missing) but surfaces as 401 by spec choice (PR-3 carve-out). The §3.3 status table is the single source of truth for the (status, code) tuple; this paragraph maps verdicts to that table. The §5.2a enumeration below pins the per-failure mapping for the load-bearing request-time surfaces.

### 5.2a Verdict-to-status enumeration (normative, v7.73)

The table below enumerates the request-time surfaces a `verify_request` evaluation can DENY on, with the discriminator `auth-class` (the envelope cannot be authenticated; 401) vs `authz-class` (authenticated but unauthorized; 403). This is the load-bearing extension of the §5.2 mapping — the §3.3 status table remains authoritative for the (status, code) tuple, this enumeration pins which surface routes to which row.

**Discriminator**: a request-time failure is **auth-class (401)** when the EXECUTE itself cannot be authenticated (no/bad author, no/bad/missing signature) — the envelope has no verified signer. It is **authz-class (403)** when the EXECUTE *is* authenticated but the verified signer's capability does not authorize the operation. The `verify_request` AUTHZ_DENY → 403 default applies to authz-class only; the auth-class half belongs to §3.5/§4.6 vocabulary.

| Surface | Failure | Status | Code | Class |
|---|---|---|---|---|
| Connect-time (§4.6) | Nonce mismatch | 401 | `invalid_nonce` | auth |
| Connect-time (§4.6) | Signature invalid against `authenticate.public_key` | 401 | `authentication_failed` | auth |
| Connect-time (§4.6) | peer_id ↔ public_key binding wrong | 401 | `identity_mismatch` | auth |
| Request-time (§5.2 step 2) | Author absent | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 2) | Author not in envelope `included` | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 2) | Signature absent | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 2) | Signature wrong target | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 2) | Signer ≠ author | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 2) | Signature tampered | **401** | `authentication_failed` | auth |
| Request-time (§5.2 step 3) | Capability absent | 403 | `capability_denied` | authz |
| Request-time (§5.2 step 3) | Capability not in envelope `included` | 403 | `capability_denied` | authz |
| Request-time (§5.2 step 3) | Capability grantee ≠ EXECUTE author | 403 | `capability_denied` | authz |
| Request-time (§5.5) | Forged root capability | 403 | `capability_denied` | authz |
| Request-time (§5.4) | Operation / handler / resource scope denied | 403 | `capability_denied` | authz |
| Request-time (§5.2) | Expired / not-before-violated capability | 403 | `capability_denied` | authz |
| Request-time (§5.2) | Leaf-cap grantee unresolvable in store/included (PR-3) | 401 | `unresolvable_grantee` | authz-carve-out |
| Request-time (§5.2 step 4) | Capability revoked (core, default) | 403 | `capability_denied` | authz |
| Request-time (§5.2 step 4) | Capability revoked (core, when `is_revoked` knows) | 403 | `capability_revoked` | authz (v7.72 Class C — preferred-when-known) |
| Request-time (§5.5) | Capability revoked (ROLE-extension in-flight cascade) | 401 | `capability_revoked` | EXTENSION-ROLE.md §5.5 cascade |
| Request-time (§6.2) | Scope exceeds authority (`request` op) | 403 | `scope_exceeds_authority` | authz |

Conformance: `validate-peer`'s `security` and `authz` categories assert these exact (status, code) tuples; conformance vectors `AUTHZ-DELEGATE-GRANT-1`, `AUTHZ-DENY-DEFAULT-1`, `AUTHZ-SCOPE-EXCEEDS-1`, `AUTHZ-GRANTEE-1`, `AUTHZ-REVOKED-1`, `AUTHZ-NO-CATCHALL-1`, `AUTHZ-EXPIRED-1` and `chain_mid_link_expiry_denied` pin the authz rows; the security category pins the auth rows.

### 5.3 Hash Comparison

Hash comparison is byte-wise equality of the full hash bytes:

```
hash_equals(a, b):
  return a == b    ; Byte-wise equality (format code + digest)
```

### 5.4 Pattern Matching

```
canonicalize(path, local_peer_id):
  ; Resolve peer-relative paths to absolute form.
  ; Reserved — reject directory-relative paths (§1.4).
  if path starts with "./" or path starts with "../":
    return error("reserved: directory-relative paths")
  ; Reject bare peer wildcard — ambiguous without leading /.
  if path starts with "*/":
    return error("ambiguous: use /*/rest for peer wildcard patterns")
  ; Already absolute — pass through.
  if path starts with "/": return path
  ; Peer-relative — resolve to local peer.
  ; Includes bare "*" → /{local_peer_id}/* (local peer, all paths).
  return "/" + local_peer_id + "/" + path

validate_absolute_path(path):
  ; MUST be called after canonicalization on all tree paths (dispatch, storage,
  ; entity data path-reference fields). Every absolute path in the system MUST
  ; have a valid peer_id as its first segment — this is structural, not optional.
  ; NOT called on patterns — patterns may have wildcard segments (e.g., /*/*)
  ; which are valid pattern syntax but not valid peer_ids.
  if not starts_with(path, "/"):
    return error("not absolute")
  segments = split(path[1:], "/")   ; skip leading /
  if not is_peer_id(segments[0]):
    return error("invalid peer_id segment")
  return ok

is_peer_id(segment):
  ; Peer IDs are Base58-encoded (§1.5, §7.4): Base58(key_type || hash_type || digest).
  ; For Ed25519 + SHA-256: 2 prefix bytes + 32 digest bytes = 34 bytes → 46 Base58 characters.
  ; Future algorithms (larger keys, longer hashes) produce longer peer IDs.
  ; 46 is the minimum — no supported algorithm produces fewer bytes.
  ; All characters must be in the Base58 alphabet (§8.5).
  ; Implementations MAY raise the minimum based on their supported algorithm set.
  if len(segment) < 46: return false
  for ch in segment:
    if ch not in BASE58_ALPHABET: return false
  return true

matches_pattern(path, pattern):
  ; Both path and pattern MUST be canonicalized (absolute) before calling.
  ; Bare "*" is never a top-level input (canonicalizes to /{local}/*).
  ; The "*" check handles recursive sub-patterns from peer wildcard stripping.
  if pattern == "*": return true

  ; Peer wildcard: /*/rest — match any peer's subtree
  if pattern starts with "/*/":
    remainder = pattern[3:]              ; strip "/*/"
    ; path is /{peer_id}/rest — extract rest after peer segment
    second_slash = index_of(path[1:], "/")
    if second_slash < 0: return false
    path_rest = path[second_slash + 2:]  ; rest after /{peer_id}/
    ; Recurse on sub-path (both unprefixed after peer segment stripped)
    return matches_pattern(path_rest, remainder)

  ; Subtree: pattern/* — prefix match
  if pattern ends with "/*":
    prefix = pattern without trailing "*"
    return path starts with prefix

  ; Exact match
  return path == pattern
```

Callers MUST canonicalize both the path and the pattern before calling `matches_pattern`. The `check_permission` algorithm (§5.2) canonicalizes handlers and grant patterns using the local peer_id. Handler path-level checks (§6.3) do the same for data paths. Canonicalization ensures all paths and patterns are absolute — `/*/` always has a real peer_id to strip, and peer-relative grant patterns match their absolute equivalents.

**No reverse canonicalization.** There is no operation that removes a peer ID prefix from a path. Canonicalization is one-directional: peer-relative → absolute. If a handler needs a key relative to a known prefix (e.g., for trie binding construction), it MUST trim the full known prefix (`/{known_peer_id}/{known_prefix}`), not strip an arbitrary peer ID. Stripping an arbitrary peer ID loses information in multi-peer scenarios: `/{peerA}/data/file` stripped to `data/file` is indistinguishable from `/{peerB}/data/file` stripped to `data/file`. Trimming a known prefix preserves the invariant that the caller knows exactly which peer's data it is operating on.

Pattern types in entity data (peer-relative, canonicalized to absolute before matching):
- `*` → `/{local_peer_id}/*`: local peer, all paths
- `pattern/*` → `/{local_peer_id}/pattern/*`: local peer, subtree
- `pattern` → `/{local_peer_id}/pattern`: local peer, exact
- `/*/*`: all peers, all paths
- `/*/pattern/*`: all peers, subtree
- `/{P}/pattern/*`: specific peer, subtree

**Structured grants.** Each grant entry has six fields (§3.6):

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| `handlers` | `system/capability/path-scope` | Yes | Handler scope — which handlers can be called |
| `resources` | `system/capability/path-scope` | Yes | Data path scope — which paths can be accessed (with optional excludes) |
| `operations` | `system/capability/id-scope` | Yes | Operation scope — which operations are authorized |
| `peers` | `system/capability/id-scope` | No | Peer scope — which peers the grant applies to. Default: local peer only (§3.6) |
| `constraints` | `map_of: primitive/any` | No | Domain-specific narrowing fields — handler-interpreted. Keys can't be dropped during delegation (§5.6). |
| `allowances` | `map_of: primitive/any` | No | Domain-specific expanding fields — handler-interpreted. Keys can't be added during delegation (§5.6). |

Each field has exactly one semantic purpose. `handlers` answers *who processes the request*. `resources` answers *what data can be accessed*. `operations` answers *what can be done*. `peers` answers *which peers are in scope*. `constraints` answers *what domain-specific restrictions apply* (narrowing — absence means unconstrained). `allowances` answers *what domain-specific expansions are granted* (expanding — absence means most restricted). Path dimensions use `system/capability/path-scope`; identifier dimensions use `system/capability/id-scope`. Both have `include` (required) and `exclude` (optional) arrays. Domain-specific dimensions use `map_of: primitive/any` — CBOR maps with string keys and handler-interpreted values.

All scope fields support pattern matching (§5.4) including `*` for match-all. `operations: {include: ["*"]}` matches any operation — this enables root/admin grants without enumerating every handler's operations. Specific operation names are exact-matched (no prefix/suffix patterns). The `exclude` array within any scope uses the same pattern matching as `include`.

`resources` MAY have an empty include array `{include: []}` for handlers that do not access tree paths. The capability handler, for example, processes `request`, `delegate`, and `revoke` operations without reading or writing tree data. An empty `resources.include` signals that the grant authorizes handler access only — `check_permission` passes (handler + operation match) and no path-level scope is granted. `check_path_permission` returns DENY for all paths when no resources match, which is correct — the handler does not need path access.

**Two-level authorization model.** Every request requires both handler scope and path scope authorization:

1. **Dispatch scope** (`check_permission`, §5.2): The capability MUST contain a grant where the `handlers` scope matches the resolved handler pattern, the `operations` scope includes the requested operation, and the `peers` scope includes the target peer. When the EXECUTE includes a `resource` field, the same grant's `resources` scope must also cover the resource. This check happens at dispatch, before the handler runs. All matched dimensions must come from a single grant entry.

2. **Path scope** (handler-specific, defense-in-depth): Each handler enforces path-level checks against the same capability. The tree handler uses `check_path_permission` (§6.3), which uses `matches_scope` against `handlers`, `operations`, and `resources` scopes. Domain handlers implement equivalent checks. When `resource` is present, this is a secondary defense-in-depth check — the dispatch-level `check_permission` handles the primary resource check. When `resource` is absent, handler-level path checks are the sole resource enforcement. Excludes within `resources.exclude` are applied at this level via `matches_scope`.

3. **Both levels MUST pass.** Handler scope alone does not authorize any data access. A matching `resources` entry alone does not authorize reaching the handler.

4. **Leading slashes required.** All canonicalized paths start with `/` (§1.4). The canonical form is `/{peer_id}/rest/of/path`. Peer-relative paths (`rest/of/path`) are resolved to absolute form by canonicalization (§5.4). Pattern matching operates on absolute paths and absolute patterns.

The initial grants (§4.4) demonstrate structured grants:
```
{ handlers:   {include: ["system/tree"]},
  resources:  {include: ["system/type/*", "system/handler/*"]},
  operations: {include: ["get"]} }
{ handlers:   {include: ["system/capability"]},
  resources:  {include: []},
  operations: {include: ["request"]} }
```

Each grant is self-describing: handler, data paths, and operations are all visible. Path dimensions use `system/capability/path-scope`; identifier dimensions use `system/capability/id-scope`.

**Delegation and attenuation.** Parent grants broad access:

```
; Parent: full files access through tree and files handlers
grants: [
  { handlers:   {include: ["system/tree", "local/files"]},
    resources:  {include: ["local/files/*"]},
    operations: {include: ["get", "put", "read-metadata"]} }
]

; Delegated: read-only, tree handler only, restricted to home subtree
grants: [
  { handlers:   {include: ["system/tree"]},
    resources:  {include: ["local/files/home/*"]},
    operations: {include: ["get"]} }
]
```

Valid attenuation: `{include: ["system/tree"]}` ⊂ `{include: ["system/tree", "local/files"]}`, `{include: ["get"]}` ⊂ `{include: ["get", "put", "read-metadata"]}`, `{include: ["local/files/home/*"]}` ⊂ `{include: ["local/files/*"]}`. All three dimensions narrow.

**Cross-handler data access.** A grant's `handlers` and `resources` scopes are independent — a handler can be authorized to access data paths outside its own namespace:

```
{ handlers:   {include: ["system/tree"]},
  resources:  {include: ["local/files/*", "local/processes/*"]},
  operations: {include: ["get", "put"]} }
```

This authorizes the tree handler to read and write at file and process paths. The handler and the data it accesses are separate dimensions.

### 5.5 Delegation Chain Verification

**Cap-chain format-code freeze (v7.66 normative).** A cap chain's "format-code" is the `content_hash_format` (per §1.2) of the cap entities themselves — i.e., the leading varint of each link's own `content_hash`. A cap chain whose links have `content_hash_format = X` SHALL NOT be extended with links at format `Y ≠ X` unless the chain's effective signer set re-signs the cross-format boundary. Implementations SHALL refuse to verify cap chains crossing format-code boundaries without a continuous signer-set re-signing event. Verification of prior-format entities under prior-format chains remains valid indefinitely. A cap chain's links MAY reference target entities (via `system/hash` fields such as `grantee`, `granter`, `signer`) under a different `content_hash_format` than the chain itself; resolution of those targets uses the §1.2 format-code-in-hash interpretation (NOT this freeze rule). The freeze applies to the chain's own link `content_hash`es, not to signed targets. Today only `0x00` is in production use; the freeze rule is structurally inert and exists to constrain future format-code transitions when proposed.

**Shared chain-walk primitive.** All authority-chain traversal in the protocol uses a single shared walker. The walker always walks to root — no early return on match or any other condition. Chain reachability is enforced by construction.

```
collect_authority_chain(cap, resolve_fn):
  ; Walks the full authority chain from cap to root (parent = null).
  ; Returns ordered [cap, parent, grandparent, ..., root] or error.
  ; resolve_fn controls where parent entities are looked up.
  ; This is the ONLY place in the protocol where parent-chain
  ; resolution happens.
  chain = []
  current = cap
  depth = 0
  max_depth = 64                 ; Implementation-defined; 64 SHOULD be default

  while current is not null:
    if depth > max_depth:
      return error(ChainTooDeep)
    chain.append(current)
    if current.data.parent is null:
      return chain               ; root reached — full chain collected
    current = resolve_fn(current.data.parent)
    if current is null:
      return error(ChainUnreachable)
    depth += 1
```

`max_depth` bounds the cost of collecting before validation. Implementations MUST enforce the default of 64 unless they can demonstrate validation cost remains bounded at their chosen limit.

**Dispatch-time chain verification.** `verify_capability_chain` collects the full chain, then validates each level:

```
verify_capability_chain(capability, included, local_peer_id):
  ; Evaluation timestamp: sampled ONCE per verdict (v7.76). `t` is a Layer-1
  ; input (§5.10) — the verdict is a function of the chain and `t`, and per-link
  ; re-sampling is forbidden (it would make the verdict depend on wall-clock
  ; drift within a single chain walk). Callers MAY pass `t` in instead of
  ; sampling here; every conformant impl already samples once at request entry.
  t = now()
  chain = collect_authority_chain(capability, fn(hash) { included[hash] })
  if is_error(chain):
    return DENY

  ; M3 structural validity (multi-sig) — checked for every entity BEFORE any
  ; signature verification, so M3 violations surface as 403 capability_denied.
  for entity in chain:
    if entity.data.granter is a multi-granter:
      if entity.data.parent is not null: return DENY          ; multi-sig is root-only
      multi = entity.data.granter
      if len(multi.signers) < 2: return DENY
      if has_duplicates(multi.signers): return DENY
      if multi.threshold < 2 or multi.threshold > len(multi.signers): return DENY

  ; Root check — root granter must be the local peer (M6: generalized for multi-sig)
  root = chain[len(chain) - 1]
  if root.data.granter is a hash:
    ; Single-sig root — unchanged
    root_granter = included[root.data.granter]
    if root_granter is null or root_granter.data.peer_id != local_peer_id:
      return DENY
  else:
    ; Multi-sig root: the local peer MUST be in the signer set AND have signed.
    ; (Root check runs before the per-link loop; this branch verifies its own
    ;  signature rather than relying on Site 1.) Generalizes "root granter must
    ;  be local peer" to "local peer must have jointly authorized this root."
    multi = root.data.granter
    local_in_validated_signers = false
    for candidate in multi.signers:
      candidate_identity = included[candidate]
      if candidate_identity is null: continue
      if candidate_identity.data.peer_id != local_peer_id: continue
      sig = find_signature_by_signer(root.content_hash, candidate, included)
      if sig is null: continue
      if verify_signature(sig, candidate_identity):
        local_in_validated_signers = true
        break
    if not local_in_validated_signers: return DENY

  ; Per-level validation
  for i in 0 .. len(chain) - 1:
    current = chain[i]

    ; Signature (M4: branch on granter shape)
    if current.data.granter is a hash:
      ; Single-sig path (unchanged)
      sig = find_signature(current.content_hash, included)
      if sig is null: return DENY
      granter = included[current.data.granter]
      if granter is null: return DENY
      if not hash_equals(sig.data.signer, current.data.granter): return DENY
      if not verify_signature(sig, granter): return DENY
    else:
      ; Multi-sig path: K valid signatures from the constituent signer set.
      ; The multi-granter is structurally valid here (M3 pass ran above); the
      ; threshold-range guard is defensive. Consults only embedded signer hashes
      ; and signatures — no identity-status/revocation check (that lives in the
      ; identity extension; core multi-sig sees concrete identity hashes only).
      multi = current.data.granter
      if multi.threshold < 2 or multi.threshold > len(multi.signers): return DENY
      seen = empty set
      valid = 0
      for candidate in multi.signers:
        if candidate in seen: continue          ; defensive dedupe
        seen.add(candidate)
        candidate_identity = included[candidate]
        if candidate_identity is null: continue
        sig = find_signature_by_signer(current.content_hash, candidate, included)
        if sig is null: continue
        if verify_signature(sig, candidate_identity):
          valid += 1
          if valid >= multi.threshold: break
      if valid < multi.threshold: return DENY

    ; Grantee resolution (per v7.39 PR-3). grantee MUST resolve to a present
    ; system/peer entity in either the local content store or the wire
    ; envelope's included map. Lookup table is the same as for granter resolution
    ; (no new envelope field required). Per-link, not just at the leaf —
    ; every cap in the chain has its own grantee, and each MUST resolve.
    ; Self-caps (grantee == granter, e.g., handler grants and root self-caps)
    ; resolve naturally because the granter's identity is already required above.
    ; Caps with unresolvable grantee (zero-hash, or any other hash not present)
    ; are rejected with status 401 `unresolvable_grantee` at chain validation.
    grantee_identity = included[current.data.grantee]
    if grantee_identity is null: return DENY    ; 401 unresolvable_grantee

    ; Temporal validity (`t` sampled once at function entry — v7.76; NOT re-sampled per link)
    if current.data.not_before is not null and t < current.data.not_before: return DENY
    if current.data.expires_at is not null and current.data.expires_at < t: return DENY

    ; Delegation (not for root — root has no parent)
    if i < len(chain) - 1:
      parent = chain[i + 1]
      if not hash_equals(parent.data.grantee, current.data.granter): return DENY
      if not is_attenuated(current, parent, local_peer_id): return DENY
      if not check_delegation_caveats(parent, current, i): return DENY

  ; (The root's signature was already verified by the per-link loop above —
  ;  it iterates 0 .. len(chain)-1 inclusive; the i < len(chain)-1 guard only
  ;  skips the root's *delegation* check, not its signature. The former
  ;  redundant root-signature tail block was removed with the M4 multi-sig
  ;  amendment, where it no longer type-checks for multi-granter roots.)

  return ALLOW
```

**Behavioral note — error precedence.** When chain reachability and per-level validation both fail (e.g., bad signature at level 0 AND unreachable parent at level 1), `ChainUnreachable`/`ChainTooDeep` takes precedence — the walker errors before validation runs. Both fail closed; the difference is which error code fires. Implementations with negative tests asserting on specific error codes for compound-failure cases will need updating.

**Root trust.** Root capabilities MUST be granted by the local peer — the granter's identity entity MUST have `peer_id == local_peer_id`. The peer is the sole root authority for its own capabilities. **For a multi-sig root** (granter is a `system/capability/multi-granter`), this invariant generalizes to: the local peer MUST be in the cap's `signers` set AND MUST have signed (M6 above). The K-of-N group jointly authorizes the cap *at issuance*; subsequent use is locally rooted — this primitive is about who jointly authorized the cap, not about who can use it from where. (So joint-account/escrow consumers each hold their *own* multi-sig cap rooted at their own runtime peer, referencing the same logical joint authority; cross-peer use of another participant's cap is not a model this primitive supports — that would need polymorphic grantee, which is out of scope.) The peer issues root capabilities during connection setup (§4.4) and through its capability management logic. All subsequent capabilities trace back to these peer-issued roots through delegation chains. The peer controls what grants it issues and to whom — a connecting peer's identity, group membership, or role can inform the initial grant, but the local peer is always the granter.

**Creator-authorization check.** Extensions that embed capability references in entity data (for later dispatch by a system handler) need to verify that the writer of the entity is in the embedded capability's authority chain. The following helper uses `collect_authority_chain` and returns the collected chain alongside the result, so callers can persist the chain without re-walking:

```
check_creator_authority(cap, writer_identity, ctx):
  ; Collects the full chain, checks reachability, then checks identity.
  ; Three outcomes:
  ;   error(ChainUnreachable) → 404, chain is broken
  ;   (false, chain)          → 403, writer not in chain
  ;   (true, chain)           → chain valid, writer authorized, chain
  ;                             available for persistence
  chain = collect_authority_chain(cap, fn(hash) {
    ctx.included[hash] ?? ctx.content_store.get(hash)
  })
  if is_error(chain):
    return (false, [], chain.error)

  found = false
  for entity in chain:
    if entity.data.granter is a hash:
      if hash_equals(entity.data.granter, writer_identity):
        found = true
        break             ; identity check can stop — chain already fully walked
    else:
      ; Multi-sig granter (M7, strict-with-signature): the writer counts as in
      ; the chain only if they are in the signer set AND actually signed this
      ; link — being listed-but-unsigned does not authorize.
      multi = entity.data.granter
      if writer_identity not in multi.signers: continue
      sig = find_signature_by_signer(entity.content_hash, writer_identity, ctx.included)
      if sig is null: continue
      ; Identity-entity lookup mirrors collect_authority_chain's dual-lookup.
      writer_identity_entity = ctx.included[writer_identity] ?? ctx.content_store.get(writer_identity)
      if writer_identity_entity is null: continue
      if verify_signature(sig, writer_identity_entity):
        found = true
        break

  return (found, chain, nil)
```

Callers map the three outcomes to status codes. On `not found`, the caller MUST NOT persist the collected chain — rejected requests do not contribute to local state.

Status: SHOULD. Implementations SHOULD share one `collect_authority_chain` implementation across all chain-walk use sites. Extensions using `check_creator_authority`: continuation install (EXTENSION-CONTINUATION), subscription subscribe (EXTENSION-SUBSCRIPTION), compute install audit static-literal capability check (EXTENSION-COMPUTE).

#### 5.5a Cap-Resource Canonicalization (normative)

Capability resource patterns canonicalize identically to request paths (per §1.4 / §5.4). The same rule that applies to incoming request paths applies uniformly to the patterns recorded in a cap's `resources` array.

- **No leading `/` (peer-relative form):** the pattern is local-peer-namespace-only. A bare `*` means `/{granter_peer_id}/*` — the granter's own namespace, NOT a universal cross-peer wildcard.
- **Leading `/` (absolute / universal form):** the leading `/` is the signal that the pattern names a peer position explicitly. The first segment after `/` is the peer; the remainder is the path within that peer's namespace. The peer position MUST be either `{specific_peer_id}` (a named peer) or `*` (all peers). Cross-peer authority MUST be expressed in this form.

Examples:
- `*` → `/{granter_peer_id}/*` (peer-local wildcard, current peer only)
- `path/x` → `/{granter_peer_id}/path/x` (peer-local specific path)
- `/{specific_peer_id}/path/x` (specific peer, absolute)
- `/*/path/x` (all peers, specific path)
- `/*/*` (all peers, all paths — open-access)

Open-access caps (e.g., dev-mode connection caps) MUST include `/*/*` plus `peers: ["*"]` for full cross-peer coverage. Capabilities are security-critical; bare `*` MUST NOT be interpreted as universal — the safer "local-namespace-only" reading is the only conformant interpretation. Cross-impl test vector: TV-CAP-RESOURCE-CANONICALIZATION (per VALIDATION-MATRIX-IDENTITY-FOUNDATIONS).

**Cross-peer dispatch caps MUST use explicit resource form (normative).** The §5.5a canonicalization rule above governs how a peer-relative pattern resolves — it canonicalizes against the **granter's** `peer_id`, not the local/verifier `peer_id`. A capability's resource patterns canonicalize against its granter's `peer_id`. Consequently, peer-relative resource patterns (bare `*`, `system/foo`, etc.) on a capability are **granter-local**: they authorize action only within the granter's own namespace.

A capability minted to authorize action against **another peer's** namespace (cross-peer dispatch) MUST express its resources in explicit cross-peer form — either a fully-qualified URI (`entity://{target_peer_id}/...`), an absolute path (`/{target_peer_id}/...`), or a cross-peer wildcard (`/*/...` / `/*/*`). A bare peer-relative resource on a foreign-granted cap does NOT authorize the target peer's namespace; presenting such a cap cross-peer MUST fail at dispatch with **403 `capability_denied`**.

This is the documented consequence of §5.5a's granter-frame canonicalization, not a new rule. The subtlety is that canonicalizing cap resources against the verifier's `local_peer_id` rather than the granter's `peer_id` leaves the bug latent — the two are byte-identical for same-peer capabilities, so only the foreign-granter case (a cap minted by one peer and presented against another) exposes it. The conformance vector `captok_form_dispatch_minted_pl_presented_xpeer` exercises exactly that case.

**Operator-facing consequence**: cross-peer cap minting helpers (test fixtures, integration test scaffolds, role-derived token helpers, multi-sig helpers) MUST use explicit cross-peer form for cap resources. Helpers that use peer-relative form on foreign-granted caps are non-conformant. Conformance vector: `captok_form_dispatch_minted_pl_presented_xpeer` (V2(a), per GUIDE-CONFORMANCE §9).

**§5.5a applies on three surfaces (normative).** The granter-frame canonicalization rule above applies wherever a capability's resource patterns are matched against a target path:

1. **Dispatch boundary** — when `verify_request` checks whether a presented capability covers an incoming request's target path. Conformance gate: V2(a) `captok_form_dispatch_minted_pl_presented_xpeer`.
2. **Chain attenuation per-link** — when `verify_capability_chain` walks parent → child links and checks `is_attenuated(child, parent)`, the resource subset-check on each link MUST canonicalize each side against THAT link's own granter `peer_id`. Conflating the per-link frames lets a foreign-granted bare `*` (which should canonicalize to `/{granter}/*`, the granter's own namespace) silently canonicalize to the verifier's `/{verifier}/*` and falsely pass attenuation. Conformance gates: `AUTHZ-ATTENUATION-FOREIGN-GRANTER-1` (V1' standard), `AUTHZ-ATTENUATION-FOREIGN-GRANTER-DEEP` (4-link, two foreign mids — rules out first/last-link special-casing), `AUTHZ-ATTENUATION-FOREIGN-GRANTER-WILDCARD-LEAF` (wildcard-vs-wildcard subset arithmetic).
3. **Handler-internal re-check** — when a handler re-authorizes a params-derived path per §3.2 (confused-deputy) against the caller's capability, the resource pattern MUST canonicalize against the capability's granter `peer_id`. **Gated indirectly by V2(a) in iterate-all-grants architectures** (the common case): any cap whose grant would escalate via params-path re-check also trips V2(a) at dispatch, because the same canonicalization site governs both checks. Impls that ship a **grant-indexed re-check** architecture (where a specific grant is consulted at re-check rather than iterate-all-admits-first-match) MUST canonicalize the re-check resource pattern against the source grant's granter; conformance gating for such architectures is out of scope here (no current implementation exhibits this shape).

**Dual-bug-shape footnote (informative).** TWO structurally distinct implementation architectures can exhibit the per-link chain-walk bug class:

- **Canon-against-wrong-frame.** The chain walk canonicalizes resources per-link, but against `local_peer_id` instead of the link's granter.
- **No-canon-before-wildcard-shortcircuit.** The chain walk has a bare-`*` universal-wildcard short-circuit that fires BEFORE per-link canonicalization, so foreign-granted `*` slips through as universal-match without ever being canonicalized.

Both surface as 200 admit on the `AUTHZ-ATTENUATION-FOREIGN-GRANTER-*` vectors; both fix via per-side granter canonicalization before any subset-check or wildcard match. The normative requirement is per-side granter canonicalization regardless of implementation architecture.

### 5.6 Attenuation Rules

Child MUST be <= parent (can only restrict, never amplify). Exclude checking is **per-scope** — each child scope must inherit the excludes of the parent scope that covers it. This prevents a delegating peer from splitting grants to move an exclude onto a grant whose resources don't overlap, bypassing the exclusion:

**Expiration nil-vs-finite rule (normative).** When the parent capability has a finite `expires_at` and the child capability has `expires_at: null`, the child is treated as infinite — which exceeds any finite parent — and `is_attenuated` MUST return `false` (see step 2 of the pseudocode below, line `if child.data.expires_at is null: return false`). The strict reading is the only conformant reading. A child cap that elides `expires_at` while chaining from a finite-expires parent is non-conformant. Implementations that wrap a synthetic capability around a grant-list for an attenuation check (e.g., role's `is_attenuated(synthetic_cap_from(derived_grants), caller_capability)` per `EXTENSION-ROLE.md` §4.3 step 5) MUST construct the synthetic cap's `expires_at` such that this rule does not spuriously fail; the conventional construction is `expires_at = MIN(parent.expires_at, role.ttl, caller_capability.expires_at)` taking only the defined values into the minimum.

```
is_attenuated(child, parent, local_peer_id):
  ; 1. Every child grant must be covered by some parent grant
  for child_grant in child.data.grants:
    if not grant_covered_by(child_grant, parent.data.grants, local_peer_id):
      return false

  ; 2. Child expiration must not exceed parent's
  ;    null expires_at = no expiration (infinite)
  if parent.data.expires_at is not null:
    if child.data.expires_at is null: return false    ; child infinite, parent finite
    if child.data.expires_at > parent.data.expires_at: return false

  return true

grant_covered_by(child_grant, parent_grants, local_peer_id):
  ; A child grant is covered if SOME parent grant authorizes
  ; at least everything the child grant authorizes.
  for parent_grant in parent_grants:
    if grant_subset(child_grant, parent_grant, local_peer_id):
      return true
  return false

grant_subset(child_grant, parent_grant, local_peer_id):
  ; All four scope dimensions must be subsets of the parent's.
  if not scope_subset(child_grant.handlers, parent_grant.handlers, local_peer_id):
    return false
  if not scope_subset(child_grant.operations, parent_grant.operations, local_peer_id):
    return false
  if not scope_subset(child_grant.resources, parent_grant.resources, local_peer_id):
    return false
  child_peers = child_grant.peers or {include: [local_peer_id]}
  parent_peers = parent_grant.peers or {include: [local_peer_id]}
  if not scope_subset(child_peers, parent_peers, local_peer_id):
    return false

  ; Constraint attenuation: key retention + byte equality.
  ; Type is map_of (CBOR map). Reject non-map values defensively.
  parent_constraints = parent_grant.constraints or {}
  child_constraints = child_grant.constraints or {}
  if not is_map(parent_constraints) or not is_map(child_constraints):
    return false
  for key in keys(parent_constraints):
    if key not in keys(child_constraints):
      return false                  ; Key dropped — escalation
    if not bytes_equal(parent_constraints[key], child_constraints[key]):
      return false                  ; Value changed — deny by default

  ; Allowance attenuation: key containment + byte equality.
  child_allowances = child_grant.allowances or {}
  parent_allowances = parent_grant.allowances or {}
  if not is_map(child_allowances) or not is_map(parent_allowances):
    return false
  for key in keys(child_allowances):
    if key not in keys(parent_allowances):
      return false                  ; Key added — escalation
    if not bytes_equal(child_allowances[key], parent_allowances[key]):
      return false                  ; Value changed — deny by default

  return true

scope_subset(child_scope, parent_scope, local_peer_id):
  ; Every child include pattern must be covered by some parent include
  for child_pattern in child_scope.include:
    cc = canonicalize(child_pattern, local_peer_id)
    if not any(matches_pattern(cc, canonicalize(pp, local_peer_id))
               for pp in parent_scope.include):
      return false
  ; Child must inherit all parent excludes
  if parent_scope.exclude is not null:
    for parent_ex in parent_scope.exclude:
      cp = canonicalize(parent_ex, local_peer_id)
      child_has = false
      if child_scope.exclude is not null:
        for child_ex in child_scope.exclude:
          if matches_pattern(cp, canonicalize(child_ex, local_peer_id)):
            child_has = true
            break
      if not child_has: return false
  return true
```

**Constraints and allowances.** Grant entries have two domain-specific fields with opposite semantics:

- **Constraints** (`map_of: primitive/any`, optional) narrow access. Each key is a named restriction interpreted by the handler. Absent means unconstrained — the handler applies its widest defaults. Adding a constraint key during delegation is safe (narrows). The core prevents key removal and value changes.

- **Allowances** (`map_of: primitive/any`, optional) expand access. Each key is a named privilege interpreted by the handler. Absent means most restricted — the handler applies its safest defaults. Removing an allowance key during delegation is safe (narrows). The core prevents key addition and value changes.

`bytes_equal` compares the canonical CBOR encoding of two values. This is a structural comparison — the core does not interpret the values, it only checks whether they are identical. The byte equality default is deliberately conservative: constraint and allowance values cannot be changed during delegation. This means unknown value modifications are treated as potential escalation.

Implementations that provide handler-mediated value verification MAY relax the byte equality check for keys where the owning handler has verified that the child value is a valid attenuation of the parent value. The relaxation MUST produce results equal to or stricter than the conformance algorithm. The mechanism for handler-mediated relaxation is implementation-defined; a future specification may standardize a contract between the capability handler and domain handlers for value-level attenuation verification.

**Key naming convention.** Constraint and allowance maps are flat — keys from different handlers share the same map on a grant entry. Handlers SHOULD prefix keys with their handler pattern (`{handler_pattern}/{field_name}`) to avoid conflicts when grants span multiple handlers. Short (unprefixed) keys are acceptable when the handler is the only consumer.

**Split grants during delegation.** A child capability MAY have more grants than its parent, provided every child grant is covered by some parent grant. Each child grant is independently checked against the parent grants — no 1:1 mapping is required.

When the parent scope has excludes, all child scopes covered by that parent scope MUST carry the same excludes (per `scope_subset` above). The child may ADD excludes (further restricting) but must not remove any. Carrying irrelevant excludes has no runtime cost — they simply never match during `matches_scope`.

### 5.7 Delegation Caveats

Delegation caveats constrain how a capability may be further delegated. They are distinct from resource-level constraints (bounds, resource_limits) which constrain request execution.

The `delegation_caveats` block on a capability token contains three optional fields:

| Field | Description |
|-------|-------------|
| `no_delegation` | If true, cannot delegate further |
| `max_delegation_depth` | Maximum chain depth from this capability |
| `max_delegation_ttl` | Maximum lifetime (ms) for delegated capabilities |

```
check_delegation_caveats(parent, child, depth):
  caveats = parent.data.delegation_caveats
  if caveats is null:
    return true

  if caveats.no_delegation == true:
    return false
  if caveats.max_delegation_depth is not null:
    if depth >= caveats.max_delegation_depth: return false
  if caveats.max_delegation_ttl is not null:
    if child.data.expires_at is null:
      return false             ; Infinite lifetime exceeds any finite limit
    child_ttl = child.data.expires_at - child.data.created_at
    if child_ttl > caveats.max_delegation_ttl: return false

  return true
```

**Delegation depth example.** `max_delegation_depth` controls how many delegation hops from this capability are permitted. With `max_delegation_depth: 1`, exactly one delegation is allowed:

```
root (local peer) → child (max_delegation_depth: 1) → grandchild
                                                       ^^^^^^^^^
                                                       depth=0: 0 >= 1? No → ALLOW

root → child (max_delegation_depth: 1) → grandchild → great-grandchild
                                                       ^^^^^^^^^^^^^^^
                                                       depth=0: pass
       check at depth=1: 1 >= 1? Yes → DENY (chain too deep from child)
```

`max_delegation_depth: 0` combined with `no_delegation: false` is equivalent to "this capability itself may be used but MUST NOT be delegated further" — any child would be checked at depth=0, and `0 >= 0` is true, so delegation is denied. However, `no_delegation: true` is the preferred way to express this.

Delegation caveats are enforced per-link in the chain walk (§5.5) — each parent's caveats are checked against its direct child at every step. A child MAY set its own delegation caveats (which constrain its delegates), but cannot escape a parent's constraints because the chain verification checks every ancestor. Unknown fields in the `delegation_caveats` block follow standard open type rules (§2.10): preserved on forwarding, not enforced by peers that do not understand them. Protocol version negotiation (§4.5) ensures peers agree on the field set.

### 5.8 Chain Inclusion and the Cross-Peer Chain-Construction Registry

When using a delegated capability, the **entire chain** MUST be in the envelope's `included` map. For each capability in the chain: the capability entity, the granter's identity entity, and the signature entity.

**Cross-peer chain-construction registry (normative).** A *cross-peer chain-construction site* is any place in this protocol or an extension that constructs a capability authority chain for an EXECUTE that may be dispatched to, and re-verified by, a peer other than the one that built it. The verified set of such sites:

| Site | Constructs |
|---|---|
| §6.5 dispatch chain | the per-EXECUTE capability chain at the wire boundary |
| `EXTENSION-SUBSCRIPTION.md` §1.2 | subscribe caller capability + deliver_token |
| `EXTENSION-CONTINUATION.md` §4.2 case 3 | the cross-peer `dispatch_capability` |
| `EXTENSION-ROLE.md` §5.6 (`:delegate`) | the member-to-member delegation cap (interior link over the delegator's role-derived root) |
| `EXTENSION-COMPUTE.md` §2.3 N7 (cross-peer `compute/closure` transfer-then-apply) | the chain for the apply'd dispatch when a transferred closure's captured scope carries capability-bearing entities (**wire deferred** per N7 — same-peer is the exercised path today; the **registration + provenance obligation is normative now**, so building the wire is "implement the registered rule," not re-spec it) |

**Explicit non-sites** (look like a site, are not — recording the boundary is part of the registry's value): `EXTENSION-COMPUTE` reactive re-evaluation is *local-only* (`EXTENSION-COMPUTE.md` §7.5 — its cross-peer data flow is the subscription/inbox seam writing into the local tree, already covered by the SUBSCRIPTION/INBOX rows; reactive re-evaluation does not itself construct or dispatch a cross-peer chain). *(Note: cross-peer `compute/closure` transfer-then-apply — the registered site above — is a distinct operation from reactive re-eval; a closure carrying capability-bearing scope across a trust boundary and applied on the receiver IS a chain-construction site. Which identity fills each §5.2 slot for a transferred-closure apply — the confused-deputy question, since the captured cap was granted to the closure's author, not the applying peer — is resolved when the wire is built; registering the site now guarantees that question is answered, not silently defaulted.)*

Every registered site MUST satisfy §5.2 (the three identity slots — root / grantee / in-chain granters), §3.5 (signature discoverability for chain-participating capabilities), and the chain-inclusion rule above (the full chain + per-link signatures travel in `included`). **An extension that introduces a new cross-peer chain-construction site MUST add it to this registry in the same change that introduces it** — registration is a normative requirement, not optional documentation (mirrors the §3.5 discovery-locality clause's "MUST state which strategy it uses").

**Conformance topology (normative).** A registered site's cross-peer provenance is conformant only if it is verified by a party that constructed **no link** in the chain. A verifier that issued a link holds the local identity-collapse (§5.2: root == grantee == in-chain granter in the same-peer case) and therefore cannot witness the cross-peer seam; only a non-issuing third-party verifier exercises the property the registry exists to guarantee. This is why same-peer/local validation can pass while the cross-peer provenance is wrong, and it is the single property that makes the registry self-checking rather than an open-ended audit.

### 5.9 Bounds Propagation

Bounds travel with operations through the system.

**Defaults**: If EXECUTE arrives without `bounds`, the peer applies its own defaults:

| Field | Recommended Default |
|-------|-------------------|
| `ttl` | 64 |
| `budget` | 100000 |
| `chain_id` | generated UUID |
| `visited` | [] |

**Propagation on dispatch**: When a handler issues a derived operation:
- TTL decrement at dispatch layer
- Budget from remaining after handler consumed
- chain_id inherited
- visited appended on remote dispatch

**Bounds error codes**:

| Code | Meaning |
|------|---------|
| `ttl_exhausted` | TTL reached 0 |
| `budget_exhausted` | Budget reached 0 |
| `cycle_detected` | Repeated peer in visited (strict policy) |

### 5.10 Verdict determinism and policy layering (normative)

Capability verification has two architecturally separate layers. Implementations and extensions MUST preserve the distinction.

**Layer 1 — Cap-chain verdict.** The determination of whether a chain is structurally valid: signatures, structural linkage (§5.5), attenuation (§5.6), delegation caveats (§5.7), TTL evaluated against a single **evaluation timestamp `t` sampled once per verdict** (§5.5; v7.76), and revocation entries discoverable via the §5.5 reverse-index mechanism. The verdict on a cross-peer-relevant chain MUST be a function of the chain and these Layer 1 inputs only; the verdict MUST be identical across conformant peers given the same Layer 1 state **and the same evaluation timestamp `t`**.

**Time as a Layer-1 input (normative, v7.76).** `t` is a declared per-verdict input, not hidden local state. It MUST be sampled once per verdict and applied to every link's temporal check (§5.5); per-link re-sampling of `now()` is non-conformant. Two conformant peers evaluating the same chain at materially different `t` near a TTL boundary legitimately reach different verdicts — this is not a Layer-1 leak, because `t` is an enumerated input rather than concealed state. (This makes the cross-peer determinism MUST satisfiable: TTL is a Layer-1 input, but its evaluation is relative to `t`.)

**Revocation as a convergent Layer-1 input (normative, v7.76).** Revocation markers are content-addressed and discoverable via the §5.5 reverse index, so revocation is a Layer-1 input — but a *convergent* one: observation is asynchronous (a peer may not yet have synced a marker another peer has) and consultation is tier-conditional. A peer with `supports_revocation = false` (§5.1) treats its observed revocation-entry set as empty. Accordingly, the cross-peer determinism MUST holds **given the same Layer 1 state — including the same set of *observed* revocation entries — among peers of the same revocation-support tier.** This is not arbitrary Layer-2 divergence: revocation markers are designed to converge (unlike local banlists/rate-limits, which never do). A core-tier peer is consistent with a full-tier peer that has observed no revocation entries; they diverge only on *different* observed Layer-1 state, which is permitted. All other Layer 1 inputs (signatures, linkage, attenuation, caveats, TTL-against-`t`) are instantaneously observable by every conformant peer.

**Layer 2 — Local policy.** Any additional gate a peer applies to a valid chain before honoring a request. MAY use arbitrary local state (local identity-cert bindings, local banlists, local rate limits, deployment-specific allow/deny rules, etc.). Free to diverge across peers — that is what policy is.

**Extension contract (normative).** Extensions MAY install Layer 2 post-gates over Layer 1 verdicts. Extensions MUST NOT introduce a hook into Layer 1 that, on a cross-peer-relevant chain, can yield a different verdict than the bare Layer 1 algorithm would. The `IdentityBindingChecker` (`EXTENSION-IDENTITY.md` §12.3) is the canonical example of a Layer 2 hook that is *adjacent to* Layer 1 in implementation but architecturally separate from it; future extension hooks follow the same contract.

**Implementation guidance (SHOULD).** Implementations SHOULD expose Layer 1 as a distinct entry point (a `verify_chain`-style function that consults no extension state) from the composite authorization path (a `verify_request`/`authorize_dispatch`-style function that composes Layer 1 with installed Layer 2 post-gates). This separation makes Layer 1 determinism auditable by inspection of a single function and prevents accidental scope-widening of Layer 2 hooks into Layer 1 in future refactors. The Go reference impl's separation (`core/capability/delegation.go:VerifyChain` for Layer 1; `core/protocol/auth.go:VerifyRequestWithBinding` for Layer 1 + post-gate) is the recommended shape; a composed impl that respects Layer 1 determinism is also conformant.

**Rationale.** Composable cap-based recipes (e.g. the convergent-mirror recipe per `EXTENSION-SUBSCRIPTION.md` §2.2; cross-peer dispatch chains per `EXTENSION-CONTINUATION.md` §4.2; delegated tokens; collected authority chains per §5.8) require Layer 1 verdicts to be deterministic across peers in order to have a cross-impl correctness argument at all. A Layer 1 leak — local-only state silently modulating what looks like the chain verdict — makes such recipes non-debuggable (the reject signal stops meaning what it should) and convergence-breaking (peers reach different states on the same chain). Local policy divergence is fully sanctioned; what is forbidden is local policy masquerading as protocol. The v3.8 / v3.9 history in `EXTENSION-IDENTITY.md §12.3` is the worked failure case.

---

## 6. Handler Model

### 6.1 Registration

Handler manifests are stored as `system/handler` entities at their pattern path (e.g., `system/tree` for the tree handler, `system/capability` for the capability handler). The handler's pattern path is the canonical location — the entity at the path IS the handler.

The `system/handler` handler (§6.2) manages handler lifecycle. Its `register` operation stores the manifest at the pattern path, installs associated type definitions, and creates the handler's capability grant at `system/capability/grants/{pattern}`. A secondary index at `system/handler/{pattern}` provides handler discovery.

Bootstrap handlers (`system/tree`, `system/handler`, `system/type`, `system/protocol/connect`) are pre-loaded during system initialization (§6.9). All other handlers register through the `system/handler` handler.

Implementations MAY maintain an in-memory dispatch index derived from tree state for performance. The tree is the source of truth; the index is a cache. The observable behavior MUST be: handler manifests exist at their pattern paths, and dispatch resolves handlers by longest prefix match against paths containing `system/handler` entities.

**Native vs entity-native execution.** After handler resolution (§6.6), two execution paths exist. When `expression_path` is absent, the implementation provides language-native operation logic (compiled code, runtime closures). The mechanism for associating language-native code with a handler manifest is implementation-defined; SDK-OPERATIONS.md §11.6 specifies the SDK-level contract for this binding.

When the handler manifest includes `expression_path` (EXTENSION-COMPUTE), dispatch evaluates the compute expression at that path. The handler body is an entity — fully inspectable and transferable. Entity-native dispatch:

1. **Verify handler grant exists.** The grant at `system/capability/grants/{pattern}` MUST be present and non-empty. Missing grant → `permission_denied`. Without this check, the expression would run with no capability ceiling.
2. **Build evaluation scope** from the request context: `{operation, params, resource, caller_capability}`. The expression accesses these via `compute/lookup/scope` (EXTENSION-COMPUTE.md §2.1).
3. **Set eval context.** `ctx.capability = handler_grant` (the handler grant is the expression's authority). `ctx.subgraph_root = expression_path` (for relative path resolution). `ctx.caller_capability` and `ctx.author` propagate from the outer dispatch context for history.
4. **Invoke the compute evaluator** with the expression, scope, budget, and eval context. The mechanism (dispatch to `system/compute:eval`, direct callback) is implementation-defined.
5. **Unwrap the result.** `compute/result` → extract `value` field. `compute/error` → error response. Bare primitive (number, string, boolean) → wrap as `{type: "primitive/any", data: <primitive>}`. Entity result → return as-is. The wire format requires typed entities in `ExecuteResponse.Result`.

The expression runs under the handler grant — the handler's declared `internal_scope` is the ceiling for all impure operations, regardless of the caller's capability. The caller's capability is available in the evaluation scope for voluntary restriction (see EXTENSION-COMPUTE.md §4.1, `compute/apply` `capability` field) and propagated for history attribution.

**One handler per path.** A pattern path has one `system/handler` entity. Whether the handler is language-native or entity-native depends on whether `expression_path` is set. Implementations that maintain a dispatch index (§6.6) MUST keep it consistent with the tree — the tree is the source of truth.

### 6.2 System Handlers

System handlers live under `system/*` paths. Implementations MUST NOT allow user-installed handlers to register at `system/*` paths.

```
Tree Handler:
  pattern:    "system/tree"
  operations: { get: {...}, put: {...} }

Handlers Handler:
  pattern:    "system/handler"
  operations: {
    register:   {input_type: "system/handler/register-request",
                 output_type: "system/handler/register-result"}
    unregister: {input_type: "system/handler/unregister-request"}
  }

Types Handler:
  pattern:    "system/type"
  operations: {
    validate: {input_type: "system/type/validate-request", output_type: "system/type/validate-result"}
  }

Capability Handler:
  pattern:    "system/capability"
  operations: {
    request:    {input_type: "system/capability/request",          output_type: "system/capability/grant"}
    revoke:     {input_type: "system/capability/revoke-request"}
    configure:  {input_type: "system/capability/policy-entry"}
    delegate:   {input_type: "system/capability/delegate-request", output_type: "system/capability/grant"}
  }

Connection Handler:
  pattern:    "system/protocol/connect"
  operations: { hello: {...}, authenticate: {...} }
```

Implementations MUST provide the tree, handlers, connection, **and capability** handlers. Capability tokens MAY also be exchanged via connection setup and envelope inclusion (§4.4) without invoking the capability handler — the handler is the runtime entry point for in-band capability management, while §4.4 covers initial-grant delivery. Implementations MUST provide all four operations on the capability handler (`request`, `revoke`, `configure`, `delegate`). Implementations SHOULD provide the types handler. Type data at `system/type/*` paths is accessed through the tree handler (§6.3). The types handler provides the `validate` operation for entity validation against type definitions. The type extension (EXTENSION-TYPE.md) adds further operations (compare, converge, compatible, adopt, reconcile).

**Capability handler operation status codes.** A capability handler that registers but does not implement an operation MUST return status **501 `unsupported_operation`** for that operation. The three status codes the handler emits are distinct:

- **`404 handler_not_found`** — no handler is registered at the dispatch path. The peer has no notion of the operation at all.
- **`501 unsupported_operation`** — a handler IS registered at the path, but does not implement the named operation. The caller's authority is irrelevant; the operation does not exist on this handler.
- **`403 scope_exceeds_authority`** — a handler is registered and supports the operation, but the caller's authority does not cover the request (or, on `request`, the requested grants exceed the caller's authenticated cap or the matched policy entry).

501 here is a deliberate semantic stretch on HTTP 501 ("method not supported by origin server") vs HTTP 405 ("method not allowed for target resource"); 405 is reserved for HTTP-level method routing in transport bridges. Both are real HTTP codes; no new code is minted.

**Cross-cutting timestamp convention.** All `expires_at`, `revoked_at`, `created_at`, and `ttl_ms`-derived expiry timestamps in `system/capability/*` types are wall-clock milliseconds since Unix epoch, set by the handler from server wall-clock at the moment the entity is constructed. A caller-supplied `revoked_at` or `created_at` MUST be ignored by the handler (replay-surface defense). `ttl_ms` is a duration; the handler computes `expires_at = now_ms() + ttl_ms`.

**Advertisement discipline.** An advertised grant — whether in the §4.4 initial scope or in any operator-configured connection grant set — MUST only reference handlers registered on this peer at connection time. Advertising a grant for an unregistered handler is non-conformant. The cross-peer behavior of an unbacked advertisement is `404 handler_not_found` at the dispatch boundary, which breaks the contract the grant implies.

**`request`/`delegate` result envelope shape.** The `request` and `delegate` operations return inline; no tree writes occur. The result envelope's `included` map MUST carry:

1. The issued token entity (referenced by `grant.token`).
2. Its signature entity (`system/signature` at the ENTITY-CORE-PROTOCOL.md §3.5 invariant-pointer path).
3. The granter identity entity (`system/peer`).

The `included` map MAY carry the full authority-chain bundle (parent token, parent's signature, parent's granter identity, recursively to the chain root) for cross-peer use; SDKs targeting cross-peer dispatch SHOULD include the full chain by default to avoid forcing the verifier into cross-peer GET roundtrips. (Mirrors the §4.4 authenticate-response precedent.)

The handlers handler manages handler lifecycle. The `register` operation executes the following five normative writes:

1. Stores the handler manifest at the pattern path `{pattern}`.
2. Installs associated types at `system/type/{type_name}` (per `register-request.types`).
3. Creates the handler's capability grant at `system/capability/grants/{pattern}`.
4. **Creates the grant-signature entity at `system/signature/{grant_hash}`** per the ENTITY-CORE-PROTOCOL.md §3.5 invariant-pointer-by-hash convention, where `{grant_hash}` is the `content_hash` of the grant entity created in step 3. The dispatcher MUST verify this signature at this path before treating the grant as authoritative. (This follows the address-space convention used everywhere else — `system/peer/{hash}`, `system/type/{type_name}`, `system/handler/{pattern}`.)
5. Derives a `system/handler/interface` entity stored at `system/handler/{pattern}`.

The `unregister` operation reverses all five steps; the grant-signature at `system/signature/{grant_hash}` is removed alongside the grant at `system/capability/grants/{pattern}`.

**Behavioral presence is normative** (v7.74 §6.13(a)). A peer claiming `--profile core` (§9.0) MUST execute the five writes above when `register` is invoked; returning `501 unsupported_operation` for `register` or `unregister` is non-conformant. The §9.5 type-floor publication of `register-request` / `register-result` is necessary but not sufficient — the operation's behavioral presence (not just the vocabulary) is the conformance contract.

**Resource carries the install path (§3.2 path-as-resource).** Both `register` and `unregister` derive the pattern from `EXECUTE.resource.targets[0]` (`system/handler/{pattern}`). The handler path is the caller's authorization target — the standard dispatch capability check on `resource` validates that the caller may install/remove a handler at that path. The handler MUST require exactly one resource target and reject anything else with **400 `ambiguous_resource`**. Example: `EXECUTE system/handler operation: "register" resource: {targets: ["system/handler/local/files"]} params: <register-request>`.

`unregister` has no params content beyond the resource — the pattern lives entirely in resource. Callers send the empty-params shape per §3.2.

To list registered handlers, use the tree handler: `EXECUTE system/tree operation: "get" resource: {targets: ["system/handler/"]}` — no dedicated list operation is needed because the handler index is tree data.

**Registration capability.** Registering a handler requires a capability with:

```
; For system handler paths
{ handlers:   {include: ["system/handler"]},
  operations: {include: ["register"]},
  resources:  {include: ["system/*"]} }

; For domain handler paths
{ handlers:   {include: ["system/handler"]},
  operations: {include: ["register"]},
  resources:  {include: ["local/*"]} }
```

The `resources` scope on the handlers handler determines where handlers can be installed. System handler registration requires `system/*` scope. Domain handler registration requires the appropriate domain scope. Bootstrap handlers bypass this — they exist before the capability system (§6.9).

**Handlers handler — write authorization.** The `register` operation writes handler manifests (at pattern paths), type definitions (at `system/type/*`), and handler grants (at `system/capability/grants/*`). All writes are handler-authorized — the handlers handler manages these paths under its own grant. The `unregister` operation removes the same paths. The caller's capability authorizes calling the handlers handler with the register/unregister operation; the handler's own grant authorizes the tree writes. The handlers handler is high-privilege — it creates capability grants for new handlers. The attenuation chain (peer root → handlers handler grant → new handler grant) ensures issued grants cannot exceed the handlers handler's own scope.

**Capability handler — baseline policy surface.** The capability handler consults config entities at `system/capability/policy/{peer_pattern}` to determine what grants to issue for a given caller. Like all paths under `system/...`, this is the local peer's namespace (per §1.4 universal-address-space model); each peer has its own policy table at this path, and `{peer_pattern}` denotes *which remote peer's calls the entry applies to*, not where the entry lives. The path's `{peer_pattern}` is exactly one of two forms:

- A specific peer identity hash — the ENTITY-CORE-PROTOCOL.md §3.5 invariant-pointer hex form: the lowercase hex of the content_hash bytes (1 format-code byte + digest), per §1.2 — length depends on the active `content_hash_format` (66 hex chars for ECFv1-SHA-256, 98 for ECFv1-SHA-384, etc.). Example for SHA-256: `system/capability/policy/00abc123...`.
- The literal segment `default` (default-for-unknown-peers): `system/capability/policy/default` (v7.63 F8 — renamed from `*`).

**Resolution: exact-match-or-`default`-fallback.** An exact match on `{caller_peer_hex}` takes precedence; otherwise the `default` entry is the fallback; if no `default` entry exists, the caller has no policy entry. No other pattern forms are defined — partial-prefix matchers (`00abc*`, `00abcdef*`) are NOT valid; impls MUST NOT accept them. (Peer IDs are uniform random hashes; partial prefixes have no semantic meaning the operator can reason about and open a typo attack surface.) Note on `*`: the glyph `*` is the core glob/pattern character (resource-target field values, grant-entry patterns); v7.62 used it as a literal fallback segment here, which overloaded the glyph. v7.63 F8 renames the literal segment to `default`. After this rename, any `*` appearing in a policy-namespace reference (e.g., `system/capability/policy/*`) is unambiguously glob — "any entry under the policy subtree" — consistent with the protocol's standard convention everywhere else.

**Evaluation contract for `request`:** when `system/capability:request` runs, the handler:

1. Resolves the caller's authenticated identity (§5.5; the identity attached to the EXECUTE envelope's signature).
2. Looks up the policy entry at `system/capability/policy/{caller_peer_hex}`; falls back to `system/capability/policy/default` if no specific match (v7.63 F8 — was `policy/*`).
3. Validates the request payload's `grants` (the caller's specific ask) as a subset of BOTH:
   - The caller's authenticated cap's grants (attenuation floor — §5.2 `matches_scope`).
   - The matched policy entry's grants (per-peer ceiling), if a policy entry exists.
   If no policy entry exists AND the caller's authenticated cap does not cover the request, returns `403 scope_exceeds_authority`. If a policy entry exists but the request exceeds either bound, also returns `403 scope_exceeds_authority`.
4. Mints a token with the request's `grants` (now validated as bounded by both ceilings); returns it per the result envelope shape (above).

**Subset-validation, not intersection.** §5.2 `matches_scope` is a binary subset predicate; the core protocol defines no `intersect_scope` primitive over 4D grant-entry scopes. Subset-validation lets the caller ask for the narrower scope they want; the handler validates the ask is bounded. The request payload IS the answer. (Future work MAY define `intersect_scope` if a use case surfaces where the caller cannot know the right subset to ask for.)

**Never widens.** Both the caller's authenticated cap and the policy entry are upper bounds. The request can ask for narrower; can never escape either bound. Pure-attenuation flow (caller's cap → narrower child for same peer) works without a policy entry by skipping the policy ceiling — step 3 only enforces bounds that exist.

**Writing policy entries.** Recommended canonical path: `system/capability:configure` with a `system/capability/policy-entry` payload. The handler writes the entity at `system/capability/policy/{peer_pattern}` under its own grant (per the handler-self-authorization model above). Direct `system/tree:put` against `system/capability/policy/*` also works if the operator's cap covers it (capabilities govern all writes; there is no mechanism to forbid raw `tree:put`, and there should not be — same pattern as `system/role:assign` vs raw `tree:put` on role's namespace per EXTENSION-ROLE.md §1.3). The configure op is the **recommended** path for future audit/validation/normalization invariants; raw `tree:put` skips those.

**Bootstrap of the configure cap.** Authority to call `system/capability:configure` is governed by holding a cap that covers it, like every other handler op. How that initial configure-cap reaches the operator is **implementation-defined bootstrap** — deployments MAY embed an operator-identity cap at startup config, derive it from the keypair holder via an install-time convention, or use any other out-of-band mechanism. The spec does not mandate a single bootstrap shape; the contract is "to call configure, hold a cap covering configure." (Bootstrap is already implementation-defined elsewhere in the core protocol — initial grants, identity install — and there is no reason to special-case configure.)

**Capability handler — universal revocation entry point.** The `revoke` operation is the universal entry point for marking a single capability token invalid. The handler's behavior is path-agnostic and uniform across all caps:

- If the token has a known capability storage path (via §5.1 `capability_path_for`), the handler unbinds the tree entry AND writes a revocation marker at `system/capability/revocations/{cap_hash_hex}` (defense in depth — covers both `is_revoked` checks).
- If the token has no known storage path (inline-returned tokens from `request`/`delegate`, wire-only caps), the handler writes the marker only.

The handler does NOT cross-dispatch to `system/role` or any other handler. Role-derived caps stored under `system/capability/grants/role-derived/{context}/{peer_hex}/{hash}` are tree-unbound by their full path; the underlying role assignment entity at `system/role/{context}/assignment/{peer_hex}` is unaffected (it is the assignment, not the cap). The operator's mental model is "use the entry point that matches the verb":

- `system/capability:revoke {token}` — this specific cap is dead.
- `system/role:unassign {peer, role}` — this peer's role is removed; cascade re-derives.
- `system/role:exclude {peer, context}` — this peer is banned from this role context (kills all role-derived caps for the peer in that context).

Cross-handler routing is not the spec's job; per-handler verbs that map cleanly to operator intent are.

**Authorization on `revoke`.** The caller MUST hold a cap covering `system/capability:revoke` on the target token. This is the same authz model every other handler write uses (§3.6 grant-entry over `(handlers, resources, operations, peers)`) — no carve-out, no granter-identity check. A caller who is the granter of a cap they want to disavow holds revoke authority over it naturally; the operator's revoke cap covers caps the operator is authorized to manage. Scope failures use `403 scope_exceeds_authority`.

**Self-namespace authorization.** `request` and `delegate` operations return tokens inline — no tree writes. `revoke` writes (when unbinding + marker) and `configure` writes (policy entries) are handler-authorized — the capability handler manages its own namespace (`system/capability/policy/*`, `system/capability/revocations/*`) under its own grant.

**Handler index.** The canonical location for a handler manifest is its pattern path (e.g., `system/tree`, `system/capability`). The `system/handler/*` namespace is a secondary index for discovery:

```
system/handler/                               handler index
  system/tree                                  system/handler/interface entity
  system/type                                 system/handler/interface entity
  system/capability                            system/handler/interface entity
  system/protocol/connect                      system/handler/interface entity
  system/handler                              system/handler/interface entity (self-referential)
  local/files                                  system/handler/interface entity

system/capability/grants/                      handler capability grants
  system/tree                                  tree handler's grant
  system/type                                 types handler's grant
  system/capability                            capability handler's grant
  system/protocol/connect                      connect handler's grant
  system/handler                              handlers handler's own grant
  local/files                                  files handler's grant
```

Handler index entries are `system/handler/interface` entities (§3.7) — the handler's external contract, the single source of truth for pattern, name, and operations. The handlers handler decomposes the manifest into two stored entities during registration:

```
process_registration(request):
  manifest = request.data.manifest
  interface_path = "system/handler/" + manifest.data.pattern

  ; 1. Interface entity (public contract, single source of truth)
  interface = Entity {
    type: "system/handler/interface",
    data: {
      pattern:    manifest.data.pattern,
      name:       manifest.data.name,
      operations: manifest.data.operations
    }
  }

  ; 2. Handler entity (dispatch target, references interface)
  handler = Entity {
    type: "system/handler",
    data: {
      interface:       interface_path,
      max_scope:       manifest.data.max_scope,
      internal_scope:  manifest.data.internal_scope,
      expression_path: manifest.data.expression_path
    }
  }

  ; 3. Build and store the grant
  grant_scope = manifest.data.requested_scope or manifest.data.internal_scope or []
  grant = Entity {
    type: "system/capability/token",
    data: {
      granter:    local_peer_identity_hash,
      grantee:    local_peer_identity_hash,       ; peer granting to itself for the handler
      parent:     peer_root_capability_hash,       ; MAY reference peer root (informational, not required for validation)
      created_at: now(),
      grants:     grant_scope                      ; MAY be empty (pure-functional handler)
    }
  }
  grant_signature = sign(content_hash(grant), local_peer_keypair)   ; signature entity over grant's content hash

  ; 4. Store at five locations (v7.74 §6.13(a) / §3.4 convergence — five normative writes)
  store interface       at {interface_path}                          ; discovery index
  store handler         at {pattern}                                 ; dispatch target
  store grant           at system/capability/grants/{pattern}        ; authorization
  store grant_signature at system/signature/{content_hash(grant)}    ; §3.5 invariant-pointer (v7.74 convergence)
```

**Grant issuance contract (normative).** The grant entity at `system/capability/grants/{pattern}` MUST set `granter` to the local peer's identity hash and MUST be signed by the local peer's keypair (signature over the grant's content hash). `parent` MAY reference the peer's root capability for audit/diagnostic purposes but is not required for validation — handler grants are self-issued; the local peer is the root authority for grants it issues to its own handlers. The `grants` array is built from `requested_scope` (or `internal_scope` when absent) and MAY be empty — a valid scoping indicating the handler has no impure authority. A handler with an empty grant is a pure-functional handler — it runs, but any impure operation (`compute/lookup/tree`, `compute/apply` handler dispatch, `store`) fails its per-op capability check because nothing in the grant covers the target.

Two locations for each handler: the pattern path (canonical `system/handler`, used by dispatch) and `system/handler/{pattern}` (index `system/handler/interface`, used for discovery). The handler entity's `interface` field structurally links the two — resolve the path to navigate from dispatch target to public contract. Handler capability grants are stored at `system/capability/grants/{pattern}`.

**Handler index entries do not participate in handler dispatch.** Dispatch (§6.6) walks the tree from the URI to find `system/handler` entities at canonical pattern paths. Index entries at `system/handler/{pattern}` have type `system/handler/interface` — the type check (`entity.type == "system/handler"`) structurally excludes them from dispatch.

**Operation name validity:** Capability grant `operations.include` arrays contain operation names that SHOULD be declared by some handler's `operations` map. The standard operation names are: `hello`, `authenticate` (connection handler); `get`, `put` (tree handler); `register`, `unregister` (handlers handler); `request`, `revoke`, `configure`, `delegate` (capability handler); `validate` (types handler). Extension operations (e.g., `snapshot`, `diff`, `merge`, `extract`, `create`, `destroy` for the tree extension) are defined in their respective extension specs. Unknown operation names in grants are not errors (forward compatibility) but SHOULD generate warnings during capability validation.

### 6.3 System Tree Handler

The tree handler provides direct access to the entity tree (location index + content store). All tree reads and writes go through this handler via two operations.

**`get`** — Read an entity or list entries.

```
; Entity read
EXECUTE system/tree  operation: "get"
  resource: {targets: ["peer_id/local/files/readme.md"]}
  params: {type: "system/tree/get-request", data: {}}

; Hash-only read
EXECUTE system/tree  operation: "get"
  resource: {targets: ["peer_id/local/files/readme.md"]}
  params: {type: "system/tree/get-request", data: {mode: "hash"}}

; Listing (trailing / on resource target)
EXECUTE system/tree  operation: "get"
  resource: {targets: ["peer_id/local/files/"]}
  params: {type: "system/tree/get-request", data: {}}
```

When the target path does not end with `/`: returns the entity bound at the path (`primitive/any`). When `mode` is `"hash"`, returns only the content hash (`system/hash`).

When the target path ends with `/` or is the empty string: returns `system/tree/listing` — one level of entries under the path used as a prefix. `mode` is ignored.

**`put`** — Store an entity (or remove a binding).

```
; Write
EXECUTE system/tree  operation: "put"
  resource: {targets: ["peer_id/local/files/readme.md"]}
  params: {type: "system/tree/put-request", data: {entity: {...}}}

; Remove
EXECUTE system/tree  operation: "put"
  resource: {targets: ["peer_id/local/files/readme.md"]}
  params: {type: "system/tree/put-request", data: {}}
```

When `entity` is present: stores the entity in the content store and binds the path to its content hash in the location index.

When `entity` is absent or null: removes the binding at the path. The entity remains in the content store (garbage collection is implementation-defined).

**Capability model**: The tree handler enforces two-level authorization (§5.4):

1. **Dispatch scope**: The capability MUST contain a grant with `handlers` matching `system/tree`, `operations` including the requested operation, and `resources` covering the resource target scope. This is checked by `check_permission` (§5.2) before the handler runs.
2. **Path scope** (defense-in-depth): The tree handler performs `check_path_permission` as a secondary check. This is essential for backward compatibility with requests that omit `resource`, and for paths resolved at handler time (e.g., merge resolving snapshot content into individual writes).

Both checks MUST pass. A handler match alone does not authorize any path access. A path match alone does not authorize calling the tree handler.

```
check_path_permission(operation, path, capability, handler_pattern, local_peer_id):
  ; Called by the tree handler after check_permission (§5.2) passes.
  ; Defense-in-depth: re-checks resource authorization at the handler level.
  ; Essential when execute.resource is absent (sole enforcement) and for
  ; paths resolved at handler time (not known at dispatch time). When
  ; execute.resource is present, this is a secondary check — dispatch
  ; already verified the resource target scope.
  canonical_path = canonicalize(path, local_peer_id)

  for grant in capability.data.grants:
    if not matches_scope(handler_pattern, grant.handlers, local_peer_id):
      continue
    if not matches_scope(operation, grant.operations, local_peer_id):
      continue
    if not matches_scope(canonical_path, grant.resources, local_peer_id):
      continue
    return ALLOW
  return DENY
```

**Listing filter.** When the tree handler returns a listing, each entry MUST be individually checked against the request's capability using `check_path_permission`. Entries for which `check_path_permission` returns DENY MUST be omitted from the listing. The listing's `count` field MUST reflect the filtered entry count, not the source tree's total count.

```
filter_listing(listing, operation, prefix, capability, handler_pattern, local_peer_id):
  ; Informative — filters listing entries against capability scope.
  filtered_entries = {}
  for (name, entry) in listing.data.entries:
    entry_path = prefix + name
    if check_path_permission(operation, entry_path, capability, handler_pattern, local_peer_id) == ALLOW:
      filtered_entries[name] = entry
  return listing with entries = filtered_entries, count = len(filtered_entries)
```

Pagination (`offset`, `limit`) applies to the filtered result set. Implementations MUST first filter entries against the request capability, then apply offset and limit to the filtered entries. This prevents callers from observing the existence or count of entries outside their capability scope.

**Security: Two-level authorization.** The tree handler is an instance of the system-wide two-level authorization model (§5.4). The `handlers` scope establishes handler scope. The `resources` scope establishes path scope (with excludes). Both MUST pass. See §5.4 for the full security model.

**Tree-handler access is kernel-level (normative principle).** The `system/tree:get` and `system/tree:put` operations provide direct access to the location index and content store, bypassing every domain handler's validation logic. This is intentional — the tree handler is the lowest-level data primitive — but it means writes via `tree:put` skip the semantic validation that domain handlers perform on their own entity types.

For load-bearing entity types — types whose data carries semantic content that affects later runtime behavior (capability references, dispatch targets, state-machine fields, scoped grants) — the proper creation path is the owning handler's operation. The handler validates and persists under its own grant. Application-level capability grants SHOULD cover the handler's create operation rather than raw `tree:put` to the handler's managed namespace. Direct `tree:put` is permitted (the kernel exposes it by design) but bypasses the handler's semantic validation. Entities created via `tree:put` are not guaranteed to satisfy the invariants the handler's create operation would have enforced (capability embedding, scope coherence, chain-root integrity). Direct `tree:put` is appropriate for system-extension code (handlers writing to their own managed namespaces) and for administrative/bootstrap contexts.

The protocol cannot structurally prevent direct `tree:put` — kernel access exists by design. Extensions and applications operating outside this convention are accepting unvalidated state. This is a *convention*, not a *reservation*: operators relying on the invariants for security or correctness should configure capability grants accordingly. Affected extensions surface this principle locally via "Coherent Capability" sub-sections in their specs.

**Peers vs resources.** The `peers` field on a grant entry specifies network scope — which peers the grant authorizes interaction with. Peer IDs that appear as prefixes in `resources` paths are a different concern: they identify local tree namespace (e.g., cached data stored under a remote peer's ID prefix). These are orthogonal. A grant with `peers` absent (defaulting to local peer only) authorizes operations on the local peer, but may include resource paths like `/{remote_peer_id}/data/*` for cached copies.

**`tree_id` parameter**: All tree operations accept an optional `tree_id` for non-default trees. See EXTENSION-TREE.md for non-default tree operations. Without `tree_id`, operations target the default tree.

**System data paths.** Many `system/*` paths store data entities that are accessed through the tree handler for reads and writes:

| Path | Content | Data access | Domain operations |
|------|---------|-------------|-------------------|
| `system/handler/*` | Handler index (`system/handler/interface` entities) | Tree handler | Handlers handler (`register`, `unregister`) |
| `system/type/*` | Type definitions | Tree handler | Types handler (`validate`) |
| `system/capability/grants/*` | Handler capability grants | Tree handler | Handlers handler (`register`, `unregister`) |
| `system/tree/instances/*` | Non-default tree configs | Tree handler | None |
| `system/subscription/*` | Active subscriptions | Tree handler | Subscription handler (`subscribe`, `unsubscribe`) |
| `system/inbox/*` | Inbox deliveries | Tree handler | `system/inbox` handler (EXTENSION-INBOX.md §3) |
| `system/continuation/suspended/*` | Suspended continuations | Tree handler | `system/continuation` handler (EXTENSION-CONTINUATION.md §3) |
| `system/transport/*` | Transport bindings | Tree handler | None |
| `system/config/*` | Peer configuration | Tree handler | None |
| `system/peer/status/*` | Known peer status | Tree handler | None |
| `system/peer/alias/*` | Peer name aliases | Tree handler | None |
| `system/peer/transport/*` | Remote peer transports | Tree handler | None |
| `system/connection/*` | Active connections | Tree handler | None |

Handler manifests at pattern paths (e.g., `system/tree`, `system/capability`, `system/type`) are also data entities accessible through the tree handler. `EXECUTE system/tree operation: "get" resource: {targets: ["system/capability"]}` returns the capability handler's manifest entity. The dispatch mechanism uses the entity type (`system/handler`) to distinguish handlers from data when resolving dispatch targets (§6.6).

To read a type definition: `EXECUTE system/tree operation: "get" resource: {targets: ["system/type/primitive/string"]}`. To validate an entity against a type: `EXECUTE system/type operation: "validate" resource: {targets: ["system/type/app/user"]} params: {type: "system/type/validate-request", data: {entity: ..., type_name: "app/user"}}`. To list all handlers: `EXECUTE system/tree operation: "get" resource: {targets: ["system/handler/"]}`.

**Handler/tree relationship.** The tree handler provides universal data access for the entity tree. `EXECUTE system/tree operation: "get/put"` goes directly to the location index and content store — it does NOT dispatch through domain handlers. Dedicated handlers exist for domain-specific operations beyond data access: the types handler provides `validate`, the capability handler provides `request`/`delegate`/`revoke`, and so on. Handlers MAY implement their own data access operations when domain logic requires handler involvement — for example, a local files handler that must interact with the host filesystem, or a handler that needs to intercept reads for domain-specific processing. This is a design choice, not the default. When the tree handler already provides the needed data access, there is no reason for a domain handler to re-implement `get`/`put`.

The tree handler, the handlers handler, the connection handler, the capability handler, the types handler, the inbox handler (EXTENSION-INBOX.md), the continuation handler (EXTENSION-CONTINUATION.md), and the subscription handler (EXTENSION-SUBSCRIPTION.md) are system handlers with registered patterns. All other `system/*` paths are data managed by the system and accessed through the tree handler.

### 6.4 Domain Handlers

Domain handlers register at non-system paths and implement domain-specific operations:

```
Files Handler:
  pattern:    "local/files"
  operations: { read-metadata: {...}, watch: {...}, ... }
```

Domain handlers MAY declare `get`, `put`, or any other operation name. These are reached via the handler's own URI, separate from the tree handler:

- `EXECUTE system/tree operation: "get" resource: {targets: ["local/files/readme.md"]}` — tree access (resource target identifies the data path)
- `EXECUTE entity://peer/local/files/readme.md operation: "read-metadata" resource: {targets: ["local/files/readme.md"]}` — handler access (if declared)

The tree handler does not delegate to domain handlers. If a domain handler declares `get`, callers choose which path to use based on whether they want direct tree access or domain-specific behavior.

**URI vs resource separation.** The URI carries handler routing — dispatch resolves the handler by longest prefix match on the URI. The URI's path suffix after the handler pattern is available to the handler for internal routing. The `resource` field carries the authorization target — the data paths being accessed as a `system/protocol/resource-target` with `{targets, exclude}`. The URI and resource targets are often the same, but need not be. For example, a handler at `system/type` receiving URI `system/type/constraints/range` uses the suffix for internal routing; the `resource` may target `system/type/primitive/integer` (the type being validated). The caller doesn't need to know whether `system/type/constraints` is a separate handler or a subpath of `system/type`.

### 6.5 Dispatch Chain

```
Frame received
  |
  +- Decode CBOR frame → envelope
  +- Validate root entity hash
  +- Validate each included entity hash
  |
  +- Root is EXECUTE?
  |   |
  |   +- URI = system/protocol/connect AND connection not established?
  |   |   → Connection handler (no auth required)
  |   |
  |   +- Otherwise:
  |       +- Build verify_ctx (peer-level services: content_store, entity_tree,
  |       |   included, capability_path_for, supports_revocation)
  |       +- Verify request integrity (§5.2 verify_request(envelope, local_peer_id, verify_ctx))
  |       |   (hash, signature, capability chain, grantee, revocation if enabled)
  |       +- Canonicalize URI path (§1.4, §5.4)
  |       +- Reject if peer_id != local_peer_id (§1.4 inbound dispatch)
  |       +- Resolve handler from tree (§6.6)
  |       |   (walk path segments, find system/handler entity → no match → 404)
  |       +- Check permission (§5.2 check_permission)
  |       |   (handler + operation + peer + resource → 403 on deny)
  |       +- Resolve handler grant from system/capability/grants/{pattern}
  |       +- Build handler execution context with handler_grant + caller capability
  |       +- Handler processes operation
  |           (handler uses context for scope-aware execution per authority model)
  |
  +- Root is EXECUTE_RESPONSE?
  |   → Correlate by request_id, deliver to waiting caller
  |
  +- Other type?
      → Invalid. Close connection.
```

Connection pre-authorization is the sole dispatch special case. All other inbound requests follow the same path: verify integrity, canonicalize URI path (§1.4), reject if peer ID is not local (§1.4), resolve handler (tree walk), check permission (all four grant dimensions), resolve handler grant, build execution context, dispatch.

**Envelope.included signature ingestion (normative, dispatcher-level).** After the included-entity hash validation step in the dispatch chain above (and before handler resolution), implementations MUST ingest signature entities from `envelope.included` and bind them at the invariant pointer paths so subsequent handler validation can find them via tree lookup.

Algorithm:

```
ingest_envelope_signatures(envelope, ctx):
  ; Walk envelope.included; for each entity of type system/signature, persist
  ; into the content store and bind at the invariant pointer path.
  ; Peer entities (system/peer) referenced from signature entities are
  ; also ingested if not already present locally.

  for h, entity in envelope.included:
    if entity.type == "system/signature":
      ; Persist signature entity to content store (idempotent on content_hash)
      ctx.content_store.put(entity)

      ; Recover signer's peer_id via the system/peer entity at entity.signer
      signer_peer = ctx.resolve_peer(entity.signer)
      if signer_peer is null:
        ; Signer peer not yet known locally; ingest from envelope if present
        signer_peer = envelope.included.get(entity.signer)
        if signer_peer is null: continue   ; cannot bind; skip
        ctx.content_store.put(signer_peer)

      ; Bind at invariant pointer path
      path = "/" + signer_peer.peer_id +
             "/system/signature/" + hex(entity.target)
      existing = ctx.entity_tree.get(path)
      if existing is not null and existing.content_hash != entity.content_hash:
        ; Path conflict — same path, different signature content_hash.
        ; Cannot occur under correct content addressing; treat as protocol violation.
        return error("signature_path_conflict")
      if existing is null:
        ctx.entity_tree.put(path, entity)
```

**Scope (uniform).** Ingestion runs once per envelope at the dispatcher's envelope-unwrap step, before any handler is selected. It applies uniformly to ALL handler ops: kernel ops (`system/tree:put`), substrate ops (`system/attestation:verify`, `system/quorum:verify`, etc.), identity ops, and any extension's handler ops. A handler that validates against bound signatures (e.g., `system/attestation:verify` looking up via `find_signature_by_signer`) can rely on signatures arriving via `envelope.included` being bound at their canonical invariant-pointer paths by the time it runs.

**Cross-peer sync equivalence.** The same invariant paths are populated by cross-peer sync via the standard sync mechanism. The signature verifier reads the local tree path; it does not distinguish whether a signature arrived via envelope-ingestion or via sync. Both routes produce identical post-state.

**Idempotency.** Re-running `ingest_envelope_signatures` on the same envelope is a no-op: the content-store puts are idempotent on `content_hash`; the tree binds are idempotent on identical content_hash at identical paths. The path-conflict error is not reachable on identical re-execution.

**Failure semantics.** A `signature_path_conflict` error indicates either a malformed envelope (different signature contents claiming the same invariant path) or storage corruption. Implementations MUST reject the envelope with status 400 (`signature_path_conflict`) and not proceed to handler dispatch. Other ingestion failures (transient I/O during content_store.put or entity_tree.put) MUST short-circuit envelope processing and return status 500; implementations MUST NOT proceed to handler dispatch with partial ingestion state.

**Substrate-only consumers.** This section establishes a general dispatcher-level surface. Consumer extensions (identity, group, future VC / reputation / cluster) need NOT define their own signature-ingestion mechanisms — they call into the substrate primitives (`find_signature_by_signer` per `EXTENSION-ATTESTATION.md` §4.0) and find signatures already bound at the invariant paths.

**Scope is intentionally narrow (informative).** This algorithm ingests only `system/signature` entities and their referenced `system/peer` entities. Other entities in `envelope.included` — capability tokens, attestations, peer entities not referenced by signatures, application entities — remain available to handlers in-memory through the envelope's `included` map but are NOT persisted to the content store and NOT bound at any tree path by the dispatcher. The handler accesses them by content hash via the envelope-included lookup. Signatures are the narrow case because they are looked up by *target hash*, not by their own content hash — the lookup at `/{signer_peer_id}/system/signature/{target_hash_hex}` requires the signature to be bound at that exact tree path on the local peer; there is no other path to find it. Every other entity currently in use is content-addressed and the in-memory `included` map suffices.

**Invariant-pointer pattern is now normative for envelope-arrival.** Prior to v7.37, the `/{signer_peer_id}/system/signature/{target_hash_hex}` invariant pointer was a recommended convention for signature storage — implementations followed it for sync compatibility but envelope-arrival ingestion was undefined. With this section, path-binding ingested signatures at the invariant pointer is normative MUST. Cross-peer sync continues to populate the same paths as a corollary; the dispatcher binding here is the local-write equivalent of a sync arrival landing a signature at its canonical path.

**First instance of dispatcher-level entity ingestion (informative).** This is the first dispatcher-level mechanism in the core protocol that mutates local tree state in response to entities arriving in `envelope.included`. If a future entity type surfaces that requires canonical-path binding at envelope arrival (similar to how signatures require it for `find_signature_by_signer`), the specification of that ingestion lands as a targeted amendment to this section — naming the entity type, the canonical path pattern, and any conflict / failure semantics. A generic registration hook for extensions to inject their own envelope-arrival processors was considered and deferred: the per-amendment model keeps the dispatcher's mutation surface auditable and avoids opening a generic-extension hook before a second concrete consumer surfaces. When a second consumer surfaces, the architecture team revisits the design (extend this section per-case, or open a registration hook then). Until then: signatures are the only dispatcher-ingested entity type; everything else flows through the in-memory `included` map.

Request integrity (§5.2 `verify_request`) validates hash, signature, capability chain, and grantee match. Permission check (§5.2 `check_permission`) verifies the capability grants the operation on the resolved handler via the `handlers` field, the `operations` field, the `peers` field, and — when `resource` is present — the `resources` field against the resource target scope. All four dimensions must match from a single grant entry. When the resource target contains pattern targets, `check_resource_scope` performs full scope checking: every grant exclude that overlaps a target must be covered by a caller exclude (§5.2). The handler execution context provides the handler with: the handler's own grant (from `system/capability/grants/{pattern}`), the caller's verified capability, the EXECUTE entity, the matched pattern, the URI suffix, and the resource target. The handler dispatches sub-requests with its own grant through standard EXECUTE dispatch; the caller's capability is available as context information (§6.8). Handler-level path authorization (§6.3 `check_path_permission`) is defense-in-depth when `resource` is present, and sole enforcement when `resource` is absent.

### 6.6 Path Dispatch

Handler dispatch resolves handlers by walking backward from the canonicalized path through path segments, checking each prefix in the tree for a `system/handler` entity. The first match is the longest prefix — depth gives priority naturally:

```
resolve_handler(path):
  ; Walk backward through path segments to find a handler.
  ; The input is a path (peer_id/rest) from dispatch_path (§1.4).
  ; The first system/handler entity found is the longest prefix match.

  segments = split(path, "/")
  for i = len(segments) down to 1:
    prefix = join(segments[0..i], "/")
    entity = tree_get(prefix)
    if entity is not null and entity.type == "system/handler":
      suffix = path[len(prefix)..]
      return {handler: entity, pattern: prefix, suffix: suffix}
  return null                    ; no match → 404

  ; Implementations MAY use a pre-built dispatch index for performance.
  ; The index MUST produce equivalent results to the tree walk.
```

The `pattern` returned is the handler's tree location (e.g., `/{peer_id}/system/tree`). The `suffix` is the remainder after the handler's location (e.g., `/instances/backup`).

The tree walk checks `entity.type == "system/handler"` at each path. This is a type-directed filter during path-directed dispatch. The tree may have entities at intermediate paths that aren't handlers — those are data. Only `system/handler` entities are dispatch targets. A type definition at `system/type/primitive/string` is not a handler — it has type `system/type`. The types handler at `system/type` is — it has type `system/handler`. Same tree, different types, different roles.

Examples with handler manifests at: `/{P}/system/tree`, `/{P}/system/handler`, `/{P}/system/type`, `/{P}/system/capability`, `/{P}/system/protocol/connect`, `/{P}/local/files` (where `{P}` is the local peer ID):

```
resolve_handler("/{P}/system/tree"):
  Check "/{P}/system/tree" → system/handler entity. Found.
  → tree handler, pattern="/{P}/system/tree", suffix=""

resolve_handler("/{P}/system/tree/instances/backup"):
  Check "/{P}/system/tree/instances/backup" → no entity (or not system/handler)
  Check "/{P}/system/tree/instances" → no entity
  Check "/{P}/system/tree" → system/handler entity. Found.
  → tree handler, pattern="/{P}/system/tree", suffix="/instances/backup"

resolve_handler("/{P}/system/type/primitive/string"):
  Check "/{P}/system/type/primitive/string" → entity exists, type is system/type. Not a handler.
  Check "/{P}/system/type/primitive" → no entity.
  Check "/{P}/system/type" → system/handler entity. Found.
  → types handler, pattern="/{P}/system/type", suffix="/primitive/string"

resolve_handler("/{P}/local/files/readme.md"):
  Check "/{P}/local/files/readme.md" → no entity.
  Check "/{P}/local/files" → system/handler entity. Found.
  → files handler, pattern="/{P}/local/files", suffix="/readme.md"

resolve_handler("/{P}/local/processes/shell"):
  Check "/{P}/local/processes/shell" → no entity.
  Check "/{P}/local/processes" → no entity (or not system/handler).
  Check "/{P}/local" → no entity.
  Check "/{P}" → no entity (or not system/handler).
  → null (no match → 404)
```

**Performance.** The tree walk does at most `depth` tree reads (typically 3-6 for entity URIs). Each tree read is an O(1) hash-map lookup on the location index. Total: O(depth), which is O(1) for practical URI depths. Implementations that maintain a dispatch index can resolve handlers in O(log n) or O(1) with a trie. The index is a cache derived from tree state — it MUST be rebuilt or updated when handler manifests are added or removed. The spec describes the tree-walk semantics; implementations choose the mechanism.

**Scope of the contract.** §6.6 applies to every dispatch invocation, regardless of how the request entered the implementation. Wire-receive dispatch (inbound EXECUTE envelopes), handler-internal sub-dispatch (via the handler context's Execute callback), and SDK in-process dispatch (helpers exposed to applications embedded in the same process) MUST all resolve handlers through the tree-walk semantics above, or through a cache that produces observably identical results. An in-memory handler registry that contains only compiled implementations is not by itself a conforming cache: it misses entity-native handlers (§3.7 `expression_path`), which exist only as tree entities. An SDK that bypasses tree-walk for local dispatch and consults only such a registry is non-conformant; entity-native handlers registered via `system/handler:register` (§6.2) would be invisible to its callers even though they are reachable over the wire from another peer. The equivalence requirement is over handler resolution outcomes — language-native and entity-native alike — not over the mechanism used to reach them.

**Uniformity across handler shape.** §6.6 dispatch semantics MUST be uniform across handler shape. A handler resolved via tree-walk may be backed by a compiled implementation or an entity-native expression (§3.7 `expression_path`); the dispatcher MUST treat both identically at every dispatch boundary — synchronous request/response, `deliver_to` async delivery, capability and grant validation, bounds inheritance, async-spawn semantics, and any subsequent flow that hooks the handler invocation. Implementations MUST NOT branch their dispatch wrappers (e.g., async-delivery, retry, durability) on whether the resolved handler is compiled or entity-native. The contract is over dispatch outcomes; the mechanism that invokes the handler body is an implementation detail.

**Dispatch uniformity at the caller-visible boundary (v7.74 B3 ruling, normative).** The dispatch chain (§6.5) and the longest-prefix tree-walk dispatch above MUST NOT special-case on a handler's **caller-visible identity**: whether the handler's body is a compiled-in native callable, an SDK-registered runtime callable bound via §6.2 / §6.13(a), or (in extension-equipped peers) a compute / entity-native handler whose body is a tree expression — the resolve → permission-check → invoke path is identical from the caller's perspective. Implementations MUST NOT branch the dispatch chain on `handler.is_compute()` / `handler.is_native()` / equivalent shape interrogation.

**Substrate fork at resolution time (clarifying carve-out, normative).** Implementations MAY (and inherently must) branch at **resolution time** on whether a body is an in-process callable or a stored-expression body needing evaluation — this branch decides **which evaluator** to invoke (in-process trait/interface dispatch, or the compute expression evaluator), not **which authorization model** applies. The fail-closed → 403 no-eval invariant + status/body split apply equally to both branches; the cap-check happens before the resolution branch fires. The pre-dispatch caller cannot observe which branch was taken; the response shape is identical.

Three invariants apply uniformly across both branches:

1. **Longest-prefix resolution.** The tree-walk decides which handler entity governs the path; no shape branch.
2. **Fail-closed on missing grant.** A handler whose grant chain does not cover the request returns `403 capability_denied` (or the more-specific defined authz code per v7.71 / v7.73 §PR-8) **without invoking the handler body**, regardless of which evaluator the resolution branch would have invoked.
3. **Status / body split.** Eval-time permission errors during handler execution surface as `200` responses with a `compute/error` body (or the impl's equivalent); request-level / dispatch-level denials surface as `4xx`. This matches the §5.2a verdict-to-status mapping and the v7.71 / v7.73 authz contracts. Applies to both branches.

Rationale: a community installing custom handlers via §6.13(a), or eventually installing a compute extension, MUST get identical dispatch semantics for their handlers as they do for the bootstrap and core handlers. The substrate is uniform at the caller-visible boundary; the resolution-time branch is impl-internal plumbing for which evaluator handles the body, which the spec explicitly permits.

**Registration paths vs spec-advertised patterns** (informative cross-reference). The tree-walk above visits each canonical path segment in sequence; the literal `*` is not a path segment that occurs in any canonical dispatch path. Handler manifests **MAY** carry advertisement-only glob notation in their `pattern` field (e.g., `"system/type/constraint/*"`), but the dispatcher does not interpret this field — the **registration path** at which the `system/handler` entity is bound is the literal prefix (e.g., `system/type/constraint`, without trailing `/*`). Every handler resolves via prefix containment. See `GUIDE-EXTENSION-DEVELOPMENT.md` §4.9 for the normative convention, the examples in the corpus, and the recurring authoring pitfall this resolves.

### 6.7 Security Layers

| Layer | Scope | Responsibility |
|-------|-------|---------------|
| 0: Wire | Envelope structure | Reject malformed messages |
| 1: Capability | System-level auth | Check handler + operation + peer + resource (when present) |
| 2: Handler | Domain semantics + path-level auth | Validate params, defense-in-depth path checks |

**Structural enforcement**: The tree extension (EXTENSION-TREE.md §8) provides view trees — capability-scoped projections of the entity tree. When view trees are implemented, handlers receive a filtered tree view matching the request's capability grants. Path-level tree access becomes structurally enforced: handlers cannot access paths outside the grants, providing defense in depth alongside handler-level domain security. Handlers remain capability-aware for domain-specific constraints. The content extension provides complementary scoping for the content store. Implementations targeting production multi-peer environments SHOULD implement view trees.

**Handler-level scoping**: When a handler declares `max_scope` (§3.7), the view tree is scoped by the intersection of the request's capability grants and the handler's max_scope — the handler cannot exceed either bound. This constrains partially-trusted handler code independently of request authorization. See EXTENSION-TREE.md §8 for intersection semantics.

**Resolution-first dispatch and the information-leak trade-off (informative).** The dispatch chain (§6.5) resolves the handler before checking permission: an unauthorized request to a handler that is not registered returns **404 `handler_not_found`**, not **403 `capability_denied`**. This is intentional and conformant — §5.2 `check_permission` requires the resolved handler pattern as input and so MUST run after resolution. The trade-off is that 404 reveals non-existence: a caller without any grants can probe which handler patterns are installed on a peer by sending EXECUTE requests and reading the status code. In deployments where handler-existence is itself sensitive (e.g., bridge nodes exposing internal handlers only on private interfaces), implementations MAY layer a network boundary or a deployment-wide cap-check before the dispatch chain. The default spec contract is resolution-first because handler scope is part of the cap-check input; deployments that need masking ship it at a layer above §6.5.

### 6.8 Handler Authority Model

Every handler — system or domain — operates within the capability model. Key properties:

- **All handlers have grants.** Every handler, including system handlers, SHOULD receive only the capability grants it needs. No handler has inherent authority beyond its grants.
- **Handler grants are created during registration.** The `system/handler` handler creates handler grants during the `register` operation and stores them at `system/capability/grants/{pattern}`. The grant is derived from the peer's root capability, attenuated to the handler's declared scope. The `internal_scope` field on the handler manifest (§3.7) declares the handler's internal needs (e.g., tree paths for configuration and type definitions). The handlers handler translates this declaration into an actual capability grant, subject to the operator's configured policy.
- **Handler tree access goes through capability enforcement.** The default enforcement mechanism is full EXECUTE dispatch — a handler's tree access is an EXECUTE to the tree handler, subject to the same dispatch chain (§6.5) as any external request. View trees (EXTENSION-TREE.md §8) provide structural enforcement as an optimization of this model — same security outcome, less dispatch overhead.
- **Authority only narrows.** The delegation chain from operator → peer root → handler grant → request effective → sub-request uses the same monotonic attenuation as cross-peer delegation (§5.6).
- **Cross-peer requests use separate grants.** A handler's internal grant authorizes operations within the local peer. Remote peer capabilities are separate grants obtained through connection setup or capability exchange. The remote peer enforces its own capability model independently.

At dispatch time, the system resolves the handler's grant from `system/capability/grants/{pattern}` and provides it to the handler alongside the caller's verified capability and the EXECUTE entity.

**Dispatch-time grant validation (normative).** Before invoking a handler, the dispatcher MUST verify the handler's grant entity:

1. **Presence.** The grant entity exists at `system/capability/grants/{pattern}`. If absent → `permission_denied`.
2. **Authority.** The `granter` field equals the local peer's identity hash (direct equality). Handler grants are self-issued — the local peer is the root authority for grants it issues to its own handlers. Chain-walking via `parent` is not required. A grant whose `granter` is not the local peer MUST be rejected — cross-peer grant copy is a category error.
3. **Signature.** The signature verifies against the local peer's public key.
4. **Temporal validity.** `not_before` and `expires_at` (if present) are within range.

A grant that fails any check is treated identically to a missing grant: dispatch MUST return `permission_denied`. The dispatcher MUST NOT fall back to the caller's capability when the handler grant is missing or invalid — that would invert the ceiling model (the handler would run with the caller's authority instead of its own bounded grant).

**Empty grants are valid.** A grant with an empty `grants` array (no scope entries) is a valid, signed grant for a pure-functional handler. The handler is registered, the grant is present and verified, but the handler has no impure authority. Any impure operation in the handler's expression or code fails its per-op capability check because nothing in the grant covers the target. This is correct — pure-functional handlers need no impure authority.

The handler dispatches sub-requests using its own grant — sub-requests are standard EXECUTE operations, subject to the same dispatch chain (§6.5) as any external request, with the handler acting as the local peer. The caller's capability is context information: handlers MAY inspect it for scope decisions, constraint enforcement, audit, or to further restrict sub-requests. How a peer exposes these inputs to handlers and what convenience mechanisms it provides (e.g., caller-restricted execution, view trees) is implementation-defined. The handler execution context structure is implementation-defined — the spec defines what information is available (handler grant, caller capability, execute entity, pattern, suffix, resource target, peer identities, request correlation), not how it is represented. Bootstrap handler grants are installed during system initialization (§6.9). Post-bootstrap handler grants are created by the `register` operation.

**Write authorization.** A handler's tree writes are authorized by the capability appropriate to the write target. This is a domain-level decision — the handler knows at design time which mode applies to each write.

- **Caller-specified paths.** When a handler writes to paths determined by the caller's request (URI, resource targets, params), the handler MUST verify the caller's capability covers the write path using `check_path_permission`. The caller's capability is the authorization for these writes. If the caller's capability does not cover the path, the write MUST fail — the handler MUST NOT substitute its own grant.

- **Handler-managed paths.** When a handler writes to paths within its own managed namespace (paths covered by the handler's grant but not by the caller's request), the handler's own grant authorizes the write. These are writes the handler would make regardless of which caller triggered the operation — metadata updates, state management, infrastructure writes.

- **Autonomous writes.** When a handler writes without an external caller (subscription delivery, background sync, scheduled operations), the handler is both the author (local peer identity) and the authority (handler grant).

- **Peer-level writes.** Code that writes to the entity tree outside the handler dispatch chain (administrative operations, application integration, post-construction setup) bypasses capability verification — no dispatch check, no `check_path_permission`. The peer is operating as the tree owner. Implementations that bypass dispatch SHOULD still provide execution context (peer identity as author, peer root capability or administrative grant as capability) so that the emit pathway can record attribution. However, the recorded capability was not verified through the dispatch chain — it is informational, not a security assertion. Implementations that require verified authorization on all writes SHOULD route all writes through the dispatch chain.

A single handler operation MAY produce writes in both caller-authorized and handler-authorized modes. The `chain_id` from bounds context correlates writes across a handler chain regardless of which capability authorized individual writes.

Extensions that record execution context (e.g., EXTENSION-HISTORY) record the capability that authorized each specific write, not a blanket "caller capability" or "handler grant" for the entire operation. Extensions SHOULD include a write authorization section documenting the authorization mode for each operation's writes.

**Context propagation.** When a handler dispatches an internal sub-request, the child handler execution context SHOULD inherit:

- **Author**: The original external caller's identity, propagated through the chain. This is the entity that initiated the request chain.
- **Caller capability**: The original external caller's capability, propagated through the chain. Available as context information for: (a) handlers that need to check caller authorization on caller-specified paths, and (b) the emit pathway, which records it as `caller_capability` in history transitions (EXTENSION-HISTORY.md §2.1).
- **Handler grant**: Freshly resolved for the child handler from `system/capability/grants/{pattern}`. Each handler in the chain gets its own grant.
- **chain_id**: From bounds context, correlating all writes in the chain regardless of which capability authorized individual writes.

For autonomous operations (no external caller), the author is the local peer identity and the caller capability is absent. The handler grant is the sole authority.

**Propagated caller capability is not a dispatch gate (normative).** The authorization decision for an internal sub-request is made on the **executing handler's grant** (§6.5), never on the propagated caller capability. The propagated `caller_capability` exists for exactly two purposes: (a) a caller-specified-path authorization check a handler performs voluntarily when it acts on a path the caller named, and (b) history attribution via the emit pathway (EXTENSION-HISTORY.md §2.1). An implementation MUST NOT fall back to the propagated caller capability to authorize a sub-dispatch that the executing handler's own grant does not permit — doing so is a confused-deputy escalation. This is the dual of "No silent escalation" below: that rule forbids a handler substituting *its own* grant for a caller's failed write; this rule forbids substituting the *caller's* (often broader) capability for the handler's own dispatch authorization.

**Capability validity.** Whenever a capability is checked — at dispatch, at a handler-level permission check, at a sub-dispatch — it MUST be valid (not expired, not revoked). A revoked capability never passes a check, even if the same capability passed a check earlier in the same operation. Handlers are not required to add extra re-verification of already-checked capabilities between writes within a single operation. The dispatch check (§6.5) and the handler's per-path checks (`check_path_permission`) are the normal verification points. Handlers MAY re-verify capabilities before writes in long-running operations that span significant time between check points — this is domain-specific.

**No silent escalation.** When a handler receives a caller's capability that does not cover a specific write, the handler MUST NOT silently substitute its own grant to make the write succeed on the caller's behalf. The handler uses its own grant only for writes to its managed namespace — paths that the handler would write to regardless of the caller's request. If a caller-authorized write fails capability checking, the operation fails.

### 6.9 Bootstrap

Three handlers MUST exist from system initialization, before any handler registration can occur:

| Handler | Pattern | Role |
|---------|---------|------|
| Tree | `system/tree` | Tree access — the foundation |
| Handlers | `system/handler` | Handler lifecycle management |
| Connect | `system/protocol/connect` | Connection establishment — pre-authorized |

The types handler (`system/type`) SHOULD be bootstrapped if the implementation supports type validation (§2.11 Level 2+). Type *definitions* at `system/type/*` are required regardless — they are data entities accessed through the tree handler. The types handler adds the `validate` operation.

Bootstrap handlers are special: they exist before the `system/handler` handler can register anything. Their manifests, types, and grants are installed during system initialization. The spec describes the observable state after initialization: bootstrap handler manifests exist at their pattern paths, their types exist at `system/type/*`, their grants exist at `system/capability/grants/{pattern}`, interface entities exist at `system/handler/*`, and dispatch resolves them.

All other handlers — system extension handlers (`system/capability`, `system/compute`, `system/content/*`, `system/inbox`, `system/continuation`, `system/subscription`) and domain handlers (`local/files`, `local/processes`, etc.) — register through the `system/handler` handler after the system is initialized. The subscription extension registers a handler at `system/subscription` for subscription lifecycle (`subscribe`, `unsubscribe`). Subscription entities are stored at `system/subscription/*` and are also accessible as data through the tree handler.

**Bootstrap sequence** (informative — implementations MAY vary the order):

```
System initialization:
  1. Create empty tree (location index + content store)
  2. Install primitive types at system/type/primitive/*
  3. Install system types at system/type/system/*
  4. Install bootstrap handler manifests at pattern paths:
       system/tree, system/handler, system/protocol/connect
       (and system/type if type validation is provided)
  5. Derive and install interface entities at system/handler/* index
  6. Create capability grants at system/capability/grants/*
  7. Build dispatch index from tree state (if maintaining an index)
  8. System is live — further handlers register through system/handler
```

Steps 1-7 are implementation-internal. The observable state after initialization is normative.

**Self-reference.** Two bootstrap handlers are self-referential:

- `system/tree`: The tree handler's manifest is stored in the tree, readable through itself. `EXECUTE system/tree operation: "get" resource: {targets: ["system/tree"]}` returns the tree handler's manifest. The handler reads itself — no circularity because the handler exists as running code and the manifest is data about it.
- `system/handler`: The handlers handler manages all handler registration, including (conceptually) its own. But it doesn't register itself — it's bootstrap. Its self-reference is informational: it appears in its own index at `system/handler/system/handler`.

### 6.9a Peer Authority Bootstrap (v7.74 Phase 2, normative)

> Cross-referenced from §6.9 (Bootstrap). The peer authority bootstrap is the substrate that makes B1's V2.0/L1 cap-check ("cap-check the register act at the same dispatch boundary as every other op") work in practice — the peer-owner cap exists at peer-init, satisfies the cap-check vacuously for peer-owner-initiated registration, and is the root from which all other grants attenuate.

A conformant peer MUST establish, at initialization, **operable owner authority** over its own namespace `/{peer_id}/*` as a root capability (the **peer-owner capability**; artifact shape per §6.9a.0 — detached-signature or tree-as-trust-root). This peer-owner capability is the namespace-root authority from which all other grants attenuate.

A peer MUST derive authenticate-time grants from a **declared identity → capability seed policy** that the peer reads at startup and consults during §4.6 authenticate. Hardcoded fork logic between `initialGrants()` / `openGrants()` (or equivalent debug-mode wildcards) is non-conformant.

#### 6.9a.0 Owner-cap artifact shape (normative — both forms floor-conformant)

The peer-owner capability and seed policy entries MAY take **either** of two artifact shapes, both floor-conformant for L0 self-issued entries. The shape distinction reflects two structurally-different (and both sound) trust anchors:

1. **Detached-signature shape.** The seed cap is a `system/capability/token` entity written at `system/capability/policy/{key}` (per §6.9a.1 dual-form), self-signed per §5.5, with the detached signature stored at `system/signature/{cap_hash}` per §3.5 invariant-pointer-by-hash convention. The signature is the trust anchor — the cap is attestable apart from where it lives. **Required** if the cap will ever be relayed cross-peer (e.g., a granter-not-equal-verifier flow); required for any cap whose authority extends beyond the issuing peer's local namespace.

2. **Tree-as-trust-root shape.** The seed cap is a `policy-entry`-typed entity (impl-defined type label per §9.4; e.g., `TYPE_CAP_POLICY_ENTRY`) written directly at `system/capability/policy/{key}`, carrying `(grantee, scope, bounds)`. No detached signature. The local tree's L0 write authority IS the trust anchor — the entry is authoritative because it was written by the peer about itself at L0, into a tree only the peer's key-holder can author. Live-read at authenticate (v7.62 §8 union-with-discovery-floor); the dispatcher treats the entry as a granted cap by inspection.

Both shapes are correct expressions of operable owner authority for entries the peer issues to itself at L0. For cross-peer relay, the detached-signature shape is required (a remote verifier cannot consult the issuer's local tree); for self-issued bootstrap entries, the tree-as-trust-root shape is sound. A peer MAY use one shape exclusively or mix shapes per entry (`self`-owner as tree-root, `operator` cap as signed token).

**Conformance gate**: the operational outcome — `authenticate(remote_identity)` returns a grant carrying the seed policy's authority for `remote_identity`, AND the dispatcher accepts a request authorized by that grant on a target within scope — is the test. Artifact shape (signed-token-with-detached-sig vs. tree-root-policy-entry) is **impl-private per §9.4**. The validator harness MUST NOT enumerate artifact paths; it MUST exercise the wire round-trip and observe operational acceptance. This mirrors §10.1's behavioral-gate principle and is the inverse of §6.2 / §3.4's permissive→convergent ruling — there the artifact pattern was uniform across invariant-pointers; here two structurally-distinct trust anchors are both correct.

**In-process / embedded peers** (normative clarification). A peer that hosts the key-holder in-process and accepts no inbound authenticate (e.g., a WASM frontend, a CLI tool that owns its own namespace, an embedded peer with no listening socket) MUST still materialize the `self`-owner seed entry at peer-init. The bootstrap is the supply; wire `authenticate` is not the only path to operable authority. This case must be normatively distinguished because the dominant SDK consumer shape (browser/WASM, embedded) takes none of the wire-authenticate path for its own namespace.

**The seed policy** is a declared mapping of `(grantee_identity, scope, bounds)` entries, with a `default` entry for identities not explicitly named. The minimum required entries:

- **`self` entry**: grantee = the peer's own identity; scope = full over `/{peer_id}/*` (the owner capability). Materialized eagerly at peer-init; entity-native and queryable.
- **`default` entry**: grantee = any other authenticated identity not explicitly named; scope SHOULD default to the §4.4 discovery floor (`system/type/*` + `system/handler/*` read; `system/capability:request` invoke). A `default → *` wildcard scope is permitted but corresponds to `debug_open_grants`; deprecated in v7.74, removed in v7.75.

Additional entries MAY name specific operator / admin / reader identities with declared scope.

**Bootstrap L0 write-set (extended).** Per §6.9, bootstrap writes happen at L0 (pre-capability). The L0 write-set MUST include:

1. The peer's own identity entity (§1.5).
2. The 4 bootstrap handler manifests (§6.9).
3. The core type entities (§9.5 floor).
4. **The seed capability entities** materialized from the seed policy, including the `self`-owner entry. Each seed entry is a root capability authored in one of the two §6.9a.0 shapes, stored at `system/capability/policy/{key}` per the v7.64 dual-form discipline (hex form or Base58 form per §6.9a.1 below; `self`-owner entry is always hex form).

All four are L0 bootstrap writes; everything after bootstrap flows through L1 dispatch under the seed capabilities.

**Authenticate-time derivation (the wiring; v7.62 §8 substrate + v7.64 dual-form lookup).** §4.6 authenticate establishes the remote identity. The peer then consults the seed policy via the v7.64 dual-form lookup, composing with v7.62 §8 union/subset semantics:

```
on authenticate(remote_identity):           ; §4.6 — identity established (401-class on failure)
  identity_hash_hex := hex(content_hash(remote_identity_entity))
  peer_id_b58       := base58_form(remote_peer_id)

  ; v7.64 dual-form lookup (hex → Base58 → default)
  policy_entry := tree.read("system/capability/policy/" + identity_hash_hex)
                ?? tree.read("system/capability/policy/" + peer_id_b58)
                ?? tree.read("system/capability/policy/default")

  ; v7.64 §2.3 first-contact canonicalization (SHOULD; idempotent / self-healing)
  ; Canonicalization timing is impl-defined — illustrated inline here, deferred to
  ; first cap-match at request-time is equally conformant (e.g., Go's deferred model).
  if policy_entry matched the Base58 form:
    tree.write("system/capability/policy/" + identity_hash_hex, policy_entry)
    tree.delete("system/capability/policy/" + peer_id_b58)

  grant := UNION(discovery_floor, policy_entry.grant)   ; v7.62 §8 union at authenticate
  include grant in authenticate response.included
```

Subsequent `capability:request` operations resolve via SUBSET (the requested grant ⊆ the authenticated grants) per v7.62 §8.

Authentication establishes *who*; the policy lookup mints *what*; §5.2 dispatch later enforces *this request*. Three concerns, three machinery.

#### 6.9a.1 Seed capability storage path (normative — applies v7.64 dual-form discipline)

The seed policy table is keyed by the grantee's address per the v7.64 dual-form policy discipline. The dual-form discipline remains the canonical resolution discipline for `system/capability/policy/*` paths. **No new path mechanism is introduced** — §6.9a adds the bootstrap-write of seed entries on top of the existing dual-form substrate.

**Two key forms** (per v7.64 §2.1 / §2.2):

1. **Hex form (canonical):** `system/capability/policy/{identity_content_hash_hex}` — the lowercase hex of the grantee's `system/peer` entity content_hash bytes (1 format-code byte + digest, §3.5 invariant-pointer-by-hash convention). Length depends on the active `content_hash_format` per §1.2 — e.g., 66 hex chars for ECFv1-SHA-256, 98 for ECFv1-SHA-384; impls MUST NOT assume a fixed length. Use this form when the writer has the grantee's public key / `system/peer` entity. Always available for the local peer's own `self`-owner entry.

2. **Base58 form (pre-contact affordance):** `system/capability/policy/{peer_id_base58}` — the grantee's Base58 PeerID per §1.5 (~46 Base58 chars for Ed25519). Use this form when the operator has only the grantee's peer-id and cannot derive hex locally — hashed-key peer-ids (`hash_type = 0x01`) don't carry the public key in the peer-id.

**Resolution at authenticate-time** (per v7.64 §2.2):

1. Try **hex form** first. If present, that's the match.
2. If absent, try **Base58 form**. If present, that's the match.
3. If both absent, fall through to `system/capability/policy/default`.

**First-contact canonicalization** (per v7.64 §2.3, SHOULD): when a Base58-form policy entry matches, the peer SHOULD canonicalize — write an equivalent hex-form entry at the identity-hash path carrying the same `(scope, bounds)`, then delete the Base58-form entry. Independently idempotent per v7.64 §2.3.

**Canonicalization timing is impl-defined** per v7.64 §2.3 (SHOULD, no when-clause). The pseudocode in §6.9a illustrates canonicalization inline at authenticate-time; impls MAY defer canonicalization to first cap-match at request-time. Both timings satisfy v7.64 §2.3. Conformance tests the eventual canonicalized state, not the precise timing.

**The `self`-owner seed entry** is always written in **hex form** — the local peer always has its own public key at peer-init.

**`default` entry**: stored at the literal path `system/capability/policy/default` (v7.64 §2.1 / §2.2 — not a form, a sentinel; v7.63 F8 — renamed from `*`).

**Seed-cap signatures — applies to the detached-signature shape only**: when a seed capability uses the detached-signature shape (§6.9a.0 shape 1), the cap is self-signed per §5.5 and the signature is stored at `system/signature/{cap_hash}` per §3.5 invariant-pointer-by-hash convention (the same convention §6.2 / §3.4 pinned for grant signatures). The signature path is INDEPENDENT of the policy path — storing the cap entity at `system/capability/policy/{key}` does NOT also store its signature at that path. The dispatcher MUST verify the seed cap's signature at `system/signature/{cap_hash}` before treating the cap as authoritative. For the tree-as-trust-root shape (§6.9a.0 shape 2), no detached signature exists — the dispatcher MAY treat the policy-entry as authoritative by L0-write-authority inspection, no signature verification step.

**Identity-keying scales beyond single-key**: under the hex-form canonical path, quorum, controller, and operator identities key uniformly by their identity-entity content_hash. The Base58 form is peer-id-keyed by definition; quorum / controller / operator identities work in hex form only. Consistent with the substrate-stack split's promise: principal authority is identity-rooted, not peer-rooted.

#### 6.9a.2 Authenticate response carries the policy-derived grant (normative)

Per §4.4 (Initial Capability Delivery), the authenticate response carries an `included` map of granted capability entities. Under §6.9a, the included map MUST contain the capability derived from the seed-policy lookup for the authenticated identity (UNION'd with the §4.4 discovery floor per v7.62 §8). This is the path by which a remote peer receives authority over the local peer's namespace.

**In-process peers**: per §6.9a, the `self`-owner entry materializes at peer-init regardless of wire authenticate. An in-process key-holder owns its namespace via the L0-materialized seed entry directly; no `authenticate` round-trip is required.

#### 6.9a.3 Conformance scope is peer-as-shipped (normative)

The §9.1 floor MUSTs for §6.9a (principal-level owner cap; policy-derived authenticate grant) are satisfied by **the peer as shipped to operators**. Implementations that supply the owner cap at the SDK binding layer (e.g., `mint_owner_self_cap()` in a Rust SDK; `mintOwnerSelfCap` in an embedded Go SDK) MAY satisfy the MUST via the binding layer when the binding is part of the conformance-tested peer. The validate-peer harness tests the peer-as-shipped, not the core peer in isolation. This makes (4) — SDK consumers materializing the owner cap at the binding layer — explicitly conformant rather than a gap that the spec ignores.

#### 6.9a.4 Relationship to per-handler self-grants (informative)

Core implementations ship per-handler self-grants at peer-init. These per-handler self-grants are the existing mechanism by which the peer-itself invokes its own handlers internally via the dispatch chain.

The principal-level `self`-owner seed entry introduced by §6.9a is a **NEW write at L0 in ADDITION** to the existing per-handler self-grants. The two serve different roles and need not be merged:

- **Principal-level `self`-owner seed entry (§6.9a)**: scope `/{peer_id}/*` for the peer's own identity; the wire-time authority that lets the key-holder operator administer the peer's namespace (install handlers, configure policy, etc.) over the wire.
- **Per-handler self-grants (existing)**: per-handler scope for peer-internal dispatch — the mechanism by which the peer-itself can invoke its own handlers without each handler needing to be explicitly granted to "self" at runtime.

Implementations that wish to consolidate the two (replace per-handler self-grants with attenuated views of the principal-level `self`-owner cap) MAY do so as an internal refactor; the conformance contract is presence of the principal-level entry at L0.

**`debug_open_grants` retirement.** `debug_open_grants` / `--debug-grants` is the degenerate seed policy `default → *`. Deprecated in v7.74; removed in v7.75. SDK builders ship `with_seed_policy(...)` and `with_owner_identity(...)` as the migration affordance for embedder trust-bootstrap cases (e.g., Tauri backend / WASM frontend).

### 6.10 Emit Pathway

A tree write produces events — the notifications that state has changed. The emit pathway is the mechanism by which these events reach extension consumers.

**Primitive.** Emit is the atomic state crossing: a mutation executes up to two steps — **Store** (write the entity to the content store) and **Bind** (update the tree binding at the target path). Each step fires an event when it does real work. The Store step fires a **content-store event** (carrying `(hash, entity)`) when the entity is new to the store; no event fires on re-put of an existing hash. The Bind step fires a **tree-change event** when the binding at the path changes; no event fires on re-bind to the current hash. A `tree_put` executes both steps in sequence (either, both, or neither event fires depending on state). A direct `content_store.put` executes only the Store step.

**Tree-change event shape (normative, v7.74 §6.13(c) / B2 ruling).** The tree-change event carries the field inventory:

| Field | Type | Semantics |
|---|---|---|
| `event_type` | `primitive/string` | One of `"created"`, `"modified"`, `"deleted"` — derived per the rule below |
| `path` | `system/tree/path` | The absolute peer-rooted path whose binding changed |
| `new_hash` | `system/hash` \| null | The hash of the entity newly bound at `path`. `null` if the path is being unbound (operational delete) |
| `previous_hash` | `system/hash` \| null | The hash previously bound at `path`, or `null` if the path was previously unbound |
| `context` | impl-defined | The execution context — see §6.8a (core fields) and SYSTEM-COMPOSITION.md §1.4 for full composition-layer structure |

**`event_type` derivation (normative):**

- `"created"` if `previous_hash` is null/absent.
- `"deleted"` if `new_hash` is null/absent (operational unbind — `system/tree:delete` or impl equivalent).
- `"modified"` otherwise.

**Bind to a `system/deletion-marker` entity fires `"modified"`, NOT `"deleted"`.** The marker's deletion-presentation role is a tree-handler listing-visibility convention (§6.3 listing filter) — NOT an emit semantic. The two mechanisms are decoupled: operational unbind fires `deleted` at emit; marker-bind makes the path appear absent in listings without firing a delete event. Impls that want marker-binds to fire `"deleted"` events implement a future bridge ruling explicitly bridging the listing-visibility and emit semantics; the emit semantic stays operational/null-based.

**Field-name vocabulary** is impl-defined; the spec contract is field semantics. Vocabulary varies across implementations (e.g., `ChangeType`/`Modified`, `change_type`/`Modified`, `kind`/`"updated"`). The semantic — created/modified/deleted derived per the rule above — is the conformance contract.

**Content-store event shape (normative).** The content-store event (Store step) carries `(hash, entity)` — the content-addressed pair just written. It does **NOT** carry execution context (execution context is a tree-change-event concept). Impl-private extra fields (e.g., `is_new: bool` indicating first-store-of-hash) are MAY.

**tree.put is atomic at the binding level only.** The location-index binding update is atomic; readers observe either the pre-write or post-write binding, never a partial state. The tree layer does NOT provide transactional semantics across the emit cascade: consumer processing occurs post-commit, and a Phase 1 consumer's error signal does not reverse the binding update. See SYSTEM-COMPOSITION.md §2.7 for cascade-halt semantics and error propagation.

**Consumers.** Extensions register as emit pathway consumers. System extensions that consume events include: query index maintenance (EXTENSION-QUERY), clock advancement (EXTENSION-CLOCK), history recording (EXTENSION-HISTORY), subscription notification (EXTENSION-SUBSCRIPTION), and compute re-evaluation (EXTENSION-COMPUTE). Domain handlers and application code MAY also register as consumers.

**Composition.** The consumer model — synchronous versus asynchronous delivery, consumer ordering, cascade depth tracking, execution context threading, convergence behavior — is specified in SYSTEM-COMPOSITION.md. Peers implementing multiple system extensions MUST follow the composition requirements in that document.

**Core protocol without extensions.** A peer implementing only the core protocol (no system extensions) has a trivial emit pathway: tree writes produce events with no consumers. The emit pathway adds no overhead and no requirements to core-only peers.

### 6.11 Transport Reentry Contract

Receive handlers MAY initiate cross-peer EXECUTE dispatch (via the injected `hctx.Execute` closure or its equivalent in each implementation) from inside their handler body, including dispatches that target the same peer whose inbound EXECUTE the handler is currently processing.

**Transports MUST support this reentrant dispatch pattern without serializing on inbound transport state.** Specifically:

**(a)** An implementation that pools connections per peer-pair MUST NOT hold per-connection serialization across the send+recv cycle of an outbound EXECUTE. Multiple outbound EXECUTE calls on the same pooled connection MUST be able to proceed concurrently.

**(b)** Response routing MUST tolerate out-of-order replies on a single connection. The `request_id` field on each `EXECUTE_RESPONSE` (§3 wire format) is the demultiplexing key; responses MUST be routed to the awaiting caller by `request_id`, irrespective of receive order on the wire. (In peer-as-client-and-server setups, the routing side is whichever end originated the outbound EXECUTE and now awaits the response — i.e., the client of this request.)

**(c)** Per-request deadlines MUST be enforced at the request layer, not via connection-wide deadline primitives (e.g., `net.Conn.SetDeadline` or equivalent) that would race across concurrent in-flight requests on the same connection.

Implementations MAY satisfy this contract via:
- **Reader-task / reader-goroutine demultiplexing** — a single reader per connection routes inbound frames to per-request response channels (the pattern adopted by all three reference implementations this revision)
- **Dial-per-dispatch** — no pooling; each EXECUTE gets its own connection (more expensive but trivially conformant)
- **Any other mechanism** that produces equivalent concurrent-dispatch semantics

The mechanism is impl-private and unobservable at the spec layer. The contract is purely behavioral. This parallels the §1.11 boundary-conformance / internal-divergence principle (transports are part of the implementation surface; the wire contract is what the spec binds).

**Rationale.** Receive handlers commonly dispatch outbound RPC back to the source peer — for example, the closure-completion fetch pattern in SDK-EXTENSION-OPERATIONS §11 (`EnsureClosure` + `AtPeer` from inside a subscription delivery handler). Transports that serialize per-connection deadlock under bidirectional symmetric load: the outbound subscription delivery holds the pooled connection while waiting for the receiver's response; the receiver's handler reenters via the same pooled connection in the reverse direction and contends on the lock its own outbound dispatch holds. The deadlock cycle forms deterministically at N=2 concurrent symmetric writers (mesh topologies with N≥3 sidesteps it via timing skew, but only probabilistically).

**Connection-teardown contract** (informative). On connection teardown, in-flight requests SHOULD be resolved (either with their response or with a connection-broken error) before the connection is removed from the pool, so callers are not left hanging indefinitely. The mechanism is impl-private — e.g., dropping all pending response senders on reader-task exit immediately resolves all awaiters with a connection-broken error.

**Request-id uniqueness scope** (informative). The `request_id` namespace is per-connection. Implementations MAY use a per-connection atomic counter; two separate connections to the same remote peer can reuse `request_id`s without collision because each connection's pending-response map is independent.

**Profile applicability (v7.74, normative).** §6.11's reentrant-dispatch contract applies to all conformance profiles. A peer claiming `--profile core` (§9.0) MUST satisfy §6.11(a)–(c) AND MUST expose to handlers a path to initiate outbound EXECUTE dispatch routed through this contract (§6.13(b)). The fact that no *core* handler is specified to originate outbound EXECUTE does **not** relax the contract: the substrate hosts the seam because handlers registered via §6.2 / §6.13(a) may originate. The validate-peer oracle's `origination` category being excluded from `--profile core` is a single-peer-mode test limit (can't catch origination-side bugs without a `-reference-peer`), NOT a capability-scope ruling.

Companion to `EXTENSION-CONTINUATION.md` v1.19 §3.10 (chain-error marker convention; cites §6.12 below for per-request transport codes).

### 6.12 Per-request transport error codes

The per-request transport layer (ENTITY-CORE-PROTOCOL.md §3.3 wire framing + §6.11 reentry contract) emits failures when no wire `EXECUTE_RESPONSE` is received for an outbound EXECUTE. Per §3.3 line 742, error codes are scoped per component; this section is the canonical home for per-request transport codes (sibling to §4.7 Connection Error Codes, which covers connection-establishment-layer codes only).

The transport layer constructs a `system/protocol/error` shape (§3.3) with the relevant `code` and `status` when one of these conditions fires; the description is what downstream consumers (e.g., EXTENSION-CONTINUATION.md §3.10 chain-error markers) record.

| `code` | `status` | Trigger |
|---|---|---|
| `recv_timeout` | 503 | Per-request deadline (§6.11(c)) fired before any response received. The deadline is the request-layer timer required by §6.11(c); connection-wide deadline primitives that would race across concurrent in-flight requests MUST NOT be used. |
| `connection_broken` | 503 | Transport closed before response. Includes: peer closed the connection, local close due to error, reader-task exit while pending responses awaited resolution (per §6.11 informative teardown contract). |
| `protocol_error` | 502 | Response received but malformed. Includes: decode failure on the wire envelope; missing required envelope fields per §3.3; **AND**: an error response (`status >= 400`) without a required `code` field — that is a protocol violation by the responding handler and surfaces here at the transport layer because the consumer has no other code to record. |

Additional per-request transport codes MAY be reserved by future spec amendments. Impls MAY emit non-reserved codes for impl-specific transport-layer conditions (e.g., TLS handshake mid-stream failures); consumers MUST treat unknown codes as informational (no reactive behavior beyond what the consuming layer specifies).

**Path-safety.** Codes used downstream as path segments (e.g., EXTENSION-CONTINUATION.md §3.10.5 `{reason}`) MUST conform to ENTITY-CORE-PROTOCOL.md §1.4 path-segment rules. All codes in the table above are path-safe.

**Code scoping cross-reference.** §3.3 line 742 establishes that error codes are scoped per emitting component. Component code-namespace homes today:

- Connection (handshake / connect-establishment) — §4.7
- Per-request transport — §6.12 (this section)
- Admission control / resource bounds — §4.10 (v7.75: `payload_too_large`/413, `chain_depth_exceeded`/400, `too_many_connections`/503-SHOULD)
- Tree handler — `EXTENSION-TREE.md` Appendix A
- Continuation engine — `EXTENSION-CONTINUATION.md` Appendix A
- Domain handlers — each handler's own appendix (per §3.3 line 742)

### 6.13 Extensibility Hook Presence (v7.74, normative)

A conformant peer MUST keep three extensibility hooks present and reachable, **even when no consumer or caller invokes them**. The hooks are core protocol's contract with anything layered above it; they MUST NOT be stubbed. Generated and hand-written peers built precisely to a gate that didn't check behavioral presence have shipped non-conformant against this contract; v7.74 pins the substrate as a behavioral MUST so the gate can verify it.

**(a) Handler registration.** The handlers handler (§6.2) MUST implement `register` and `unregister` operations behaviorally — the operations execute the five normative writes specified in §6.2 (manifest at pattern path, types at `system/type/{type_name}`, grant at `system/capability/grants/{pattern}`, grant-signature at `system/signature/{grant_hash}` per §3.5 invariant-pointer, interface at `system/handler/{pattern}`). A `501 unsupported_operation` response on `register` or `unregister` from a peer claiming `--profile core` is non-conformant. The §9.5 type-floor publication of `register-request` / `register-result` is necessary but not sufficient: the operation's **behavioral presence** — not just the vocabulary — is the conformance contract.

**(b) Handler-initiated outbound dispatch.** The runtime MUST expose to handlers a way to initiate outbound EXECUTE dispatch (e.g., a `hctx.Execute(target, EXECUTE) → EXECUTE_RESPONSE` closure, or the language-idiomatic equivalent), routing through the §6.11 transport reentry contract (reader-task / pending-response correlation), **even when no core handler originates outbound EXECUTEs.** The seam (reader-task + `request_id` correlation map + handler-reachable execute closure) is required of every peer because the substrate MUST support handler-driven outbound dispatch the moment any handler is registered that needs it — including handlers registered at runtime via §6.13(a). A peer that stubs the outbound seam ("we don't ship handlers that originate, so we didn't build it") foreclosed extensibility.

**(c) Emit pathway.** §6.10 already specifies the emit pathway. The hook MUST be live: tree writes produce tree-change events with the field inventory and `event_type` derivation pinned in §6.10. Even with zero consumers, the events are produced (and discarded); the consumer-registration primitive (§6.10) MUST be reachable so a future extension can register one without the peer being rebuilt. Cited here as the precedent and the model for (a) and (b).

**Mechanism is impl-defined per §9.4.** §9.4 already places handler-context representation, sub-request dispatch mechanism, dispatch index maintenance, and bootstrap initialization order in the implementation-defined column. §6.13 adds no new mechanism prescription — it pins **behavioral presence**, not architecture. One-thread-per-connection, async-task-per-frame, native registry binding, FFI binding into an SDK-supplied callable, eio effects, Lwt promises — all valid. The mechanism is impl-private; the hook being live is normative.

**Conformance gate.** Three additions to `validate-peer --profile core` exercise (a) and (b) behaviorally — a core-tier dynamic-register check (register-and-dispatch round-trip), a core-tier minimal-origination check, and machine-linking of `coreProfileCategories` to §9.0/§9.1/§9.5. The behavioral round-trip verifies what static manifest introspection cannot.

## 7. Algorithms

Algorithms are classified by normative status:

| Status | Meaning |
|--------|---------|
| **NORMATIVE** | Deterministic. All implementations MUST produce identical output for identical input. Interoperability depends on exact reproduction. |
| **CONFORMANCE** | Same outcome required. Implementations MAY use different logic but MUST produce the same ALLOW/DENY (or equivalent) result for all inputs. Verifiable by conformance test suite. |
| **REFERENCE** | Illustrative. Describes expected behavior but implementations may vary in approach. Outcome matters, exact steps do not. |

Algorithms in §5 (verification, permission checking, pattern matching, chain verification, attenuation, delegation caveats) are **CONFORMANCE** — different implementations are acceptable if they produce identical security decisions.

### 7.1 Content Hash Computation — NORMATIVE

```
content_hash(entity):
  hashable = {type: entity.type, data: entity.data}
  encoded = ecf_encode(hashable)
  digest = SHA256(encoded)
  return bytes([0x00]) + digest    ; 33 bytes: format code + digest
```

### 7.2 Content Hash Validation — NORMATIVE

```
validate_hash(received_entity):
  expected = content_hash(received_entity)
  if not hash_equals(expected, received_entity.content_hash):
    REJECT
  ; After validation, content_hash is TRUSTED
```

### 7.3 Signature Computation — NORMATIVE

```
sign_entity(entity, private_key):
  message = entity.content_hash         ; Sign full hash bytes (format code + digest)
  signature = ed25519_sign(private_key, message)
  return signature

verify_entity_signature(entity, public_key, signature_bytes):
  message = entity.content_hash         ; Full hash bytes
  return ed25519_verify(public_key, message, signature_bytes)
```

Signatures are computed over the full `system/hash` bytes (format code + digest). This binds the signature to the hash format — a signature made under ECFv1-SHA-256 is distinct from one under any other format.

Ed25519 is the production signing algorithm. As of v7.67 the §1.5 `key_type` seed table also **validates** Ed448 (`0x02`, cross-impl byte-equal) and allocates ML-DSA-65 (`0x03`) plus a reserved candidate set; the §1.2 `content_hash_format` seed table validates SHA-384 (`0x01`) alongside production SHA-256 (`0x00`). Algorithm selection is not negotiated metadata — a signature's verifier is dispatched from the signer's `key_type` (§1.5), and a `content_hash`'s digest function from its leading format code (§1.2). Which algorithms a conformant implementation MUST support is specified in §9.1.

**Multicodec-style varint encoding (normative).** All format-code fields in this protocol — hash format codes (§1.2), peer-ID `key_type` and `hash_type` (§1.5) — are encoded as multicodec-style LEB128 varints. Encoding rules: codes 0–127 (`0x00`–`0x7F`) encode as a single byte with no continuation bit set; codes 128–16383 encode as 2 bytes (continuation bit set on the first byte); etc. The currently allocated code values are all < 128 and encode byte-for-byte identically to a 1-byte fixed-width field; future code allocations beyond `0x7F` extend to 2-byte varints naturally without a wire-format break for existing values.

This format is a strict subset of multicodec encoding (used by IPFS / libp2p / Filecoin), with our private code subset rather than the official multicodec table. Tools that decode multicodec varints decode our codes without modification (they see "code N of unknown codec," but the decoding succeeds). DID-ecosystem interop — if pursued — uses the DID Bridge pattern (DID Document Multikey encoding lives inside verification methods, not in the DID itself); the bridge handles encoding without any further internal format change.

### 7.4 Peer ID Derivation — NORMATIVE

See §1.5 canonical-form per `key_type` table — this algorithm defers to that table for the choice of `hash_type` and digest construction.

```
derive_peer_id(public_key, key_type):
  hash_type = canonical_hash_type(key_type)         ; per §1.5 canonical-form table
                                                    ;   Ed25519 (0x01) → 0x00 identity-multihash
                                                    ;   Ed448, ML-DSA-*, FALCON, etc. → 0x01 SHA-256-form
  digest = compute_digest(hash_type, public_key)    ; 0x00 → public_key (raw bytes)
                                                    ; 0x01 → SHA-256(canonical_pubkey_encoding)
  data = varint(key_type) || varint(hash_type) || digest
  return base58_encode(data)                        ; Bitcoin alphabet
```

For Ed25519 (`key_type=0x01`, `hash_type=0x00` identity-multihash), `data` is byte-for-byte `bytes([0x01, 0x00]) || public_key` — the digest IS the raw public_key (v7.64; see §1.5). For algorithms with SHA-256-form canonical (Ed448, ML-DSA-65, etc.), `digest = SHA-256(canonical_pubkey_encoding)` per the §1.5 table.

The pre-v7.64 SHA-256-form for Ed25519 (`hash_type=0x01`, digest = SHA-256 of pubkey) is **NOT** a valid construction form for v7.65+ — it is the §1.5 wire-acceptance carve-out (decode-only for backwards compat). Implementations MUST construct using canonical `hash_type` per the §1.5 table; non-canonical wire forms received on decode MUST canonicalize before storage per §1.5 line 493. The varint reframing is wire-compatible with the prior fixed-width encoding for all current single-byte values and provides forward-compatibility for future code allocations beyond `0x7F`.

### 7.5 Type Resolution — REFERENCE

```
resolve_type(type_path, type_store, visited={}):
  if type_path in visited: ERROR "circular inheritance"
  visited = visited + {type_path}

  type_def = type_store.lookup("system/type/" + type_path)
  if type_def is null: ERROR "unknown type"

  if type_def.data.extends is null:
    return type_def

  parent = resolve_type(type_def.data.extends, type_store, visited)
  merged_fields = parent.fields + type_def.fields
  if overlap(parent.fields, type_def.fields): ERROR "field redefinition"

  return {fields: merged_fields}
```

Resolution depth SHOULD be limited to 64 levels. Cycles MUST be detected.

### 7.6 Type Validation — REFERENCE

```
validate_entity(entity, resolved_type):
  errors = []

  ; Stage 1: Validate data fields
  for (name, field_spec) in resolved_type.fields:
    value = entity.data[name]
    if value is absent:
      if field_spec.default is not null:
        continue
      if not field_spec.optional: errors.add("missing required field: " + name)
    else:
      errors.addAll(validate_value(value, field_spec))

  ; Stage 2: Unknown fields — NOT errors (open types)

  return errors
```

---

## 8. Constants

### 8.1 Key Types

Quick reference for the active tier; the full allocation + canonical-form seed table is authoritative in §1.5.

| Value | Algorithm | String | Key Size | Signature Size | Status |
|-------|-----------|--------|----------|----------------|--------|
| 0x01 | Ed25519 | `"ed25519"` | 32 bytes | 64 bytes | **Required** |
| 0x02 | Ed448 | `"ed448"` | 57 bytes | 114 bytes | **Validated** (v7.67 Phase 1) |
| 0x03 | ML-DSA-65 | `"ml-dsa-65"` | 1952 bytes | 3309 bytes | Allocated; validation deferred (Phase 3b) |

### 8.2 Hash Formats

Quick reference for the active tier; the full allocation seed table is authoritative in §1.2.

| Value | Algorithm | Digest Size | Hello String | Status |
|-------|-----------|-------------|--------------|--------|
| 0x00 | ECFv1-SHA-256 | 32 bytes | `"ecfv1-sha256"` | **Required** |
| 0x01 | ECFv1-SHA-384 | 48 bytes | `"ecfv1-sha384"` | **Validated** (v7.67 Phase 1) |
| 0x02 | ECFv1-SHA-512 | 64 bytes | `"ecfv1-sha512"` | Reserved |
| 0x03 | ECFv1-BLAKE3-256 | 32 bytes | `"ecfv1-blake3"` | Allocated; validation deferred (Phase 3a) |

### 8.3 Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 207 | Partial success (binding committed, cascade halted) |
| 400 | Bad request |
| 401 | Authentication failed |
| 403 | Forbidden |
| 404 | Not found |
| 409 | Conflict |
| 429 | Rate limited |
| 500 | Internal error |
| 501 | Not supported |
| 503 | Service unavailable |

**The connection handshake is the authentication boundary.** `401` is the **authentication** code: it covers all `system/protocol/connect` proof-of-possession failures (§4.6 — nonce/signature/identity-binding) and the single post-establishment `unresolvable_grantee` case. `403` is the **authorization** code: a `verify_request` `DENY` on an authenticated EXECUTE (§5.2). Connect-auth failures MUST emit the coded `401` before closing the connection (a bare close is non-conformant — §4.6).

### 8.4 Protocol Version

`"entity-core/1.0"`

### 8.5 Base58 Alphabet (Bitcoin)

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

---

## 9. Conformance

**Substrate principle (v7.74, normative-adjacent).** A conformant core peer is an **extensible substrate**: it provides the hooks (register, dispatch, emit, capability, connect — see §6.13) and does not constrain what a builder layers on top. A community can install custom handlers, build cross-peer messaging, ship their own subscription / history / revision / compute / query semantics — all without installing any architecture-supplied extension and without adopting SYSTEM-COMPOSITION's multi-extension cascade choreography. Architecture-supplied extensions (EXTENSION-SUBSCRIPTION, EXTENSION-HISTORY, EXTENSION-COMPUTE, EXTENSION-REVISION, EXTENSION-QUERY, etc.) and SYSTEM-COMPOSITION (the cross-extension emergent-properties guide) are *one set of choices*; nothing at the core layer privileges them over a community's alternative composition.

Core protocol is the substrate, not the system. The conformance discussion that follows (§9.0–§9.5) specifies the substrate; it deliberately does not specify what an extension-set or composition must do for a peer to be "useful." The hook-presence MUSTs in §9.1 (and §6.13's behavioral-presence pins) draw the line: **core = the live hooks; everything above = optional and replaceable.**

### 9.0 Conformance Profiles (v7.72)

A peer claims a **conformance profile** when it presents itself to a conformance oracle. Two profiles are defined:

- **`core`** — The peer implements the core protocol only. It publishes the §9.5 Core Type Floor (53 types) and no others; it registers the core handlers (`system/tree`, `system/handler`, `system/capability`, `system/protocol/connect`, and SHOULD `system/type`); it implements only the core operations on each (no EXTENSION-TREE.md §9 ops; no EXTENSION-ROLE delegation cascades; no EXTENSION-SUBSCRIPTION handlers; etc.). A core peer is the minimal substrate.
- **`full`** — The peer implements the core protocol plus an arbitrary set of installed extensions. It publishes the §9.5 floor plus each installed extension's types; it registers core handlers plus extension handlers; it implements each extension's normative surface.

**The profile is a publication contract, not an impl-architecture mandate.** A peer is `core` if it publishes 53 types and registers no extension handlers; a peer is `full` if it ships any extension. Reference impls (Go/Rust/Python) flatten extension type registration into their core registration function; this is conformant for full-peer deployments. Per-extension type-provider seams (Go's `TypeProvider.RegisterTypes`) are optional.

**Oracle-side contract.** A conformance oracle scoring a peer under `--profile core` (or equivalent):

- Runs the core-profile category set: `connectivity`, `encoding`, `universal_address_space`, `peer_canonicalization`, `format_agility`, `crypto_agility`, `negotiation`, `multisig`, `type_system`, `handlers`, `tree_operations`, `capability`, `authz`, `security`, `concurrency`, `resource_bounds`. (Other categories are extension-only and skipped under `--profile core` with diagnostic.)
- Scores `type_system` against the §9.5 53-type floor. Types outside the floor are matched-if-present, not-a-FAIL-if-absent (same precedent as `isProvisionalType` for `system/substitute/*`).
- Scores `tree_operations` against §9.5a (the `CORE-TREE-*` vector set) and §1.4 path rules. EXTENSION-TREE.md §9 ops (`snapshot`, `diff`, `merge`, `extract`, `tracked`) are skipped under `--profile core`.
- Scores `handlers` against the core handler set (`system/tree`, `system/handler`, `system/capability`, `system/protocol/connect`, `system/type`). Extension handlers (`subscription`, `continuation`, `inbox`, `revision`, …) are matched-if-present, not-a-FAIL-if-absent. For the `tree` handler entry, the expected op-set under `--profile core` is `{"get", "put"}`; the EXTENSION-TREE.md §9 ops are matched-if-present.
- Scores `security` and `authz` with three per-check carve-outs: any check that routes through an extension-specific handler (`system/subscription`, `system/role`) or expects an extension-specific code (ROLE §5.5 `capability_revoked`/401) is skipped under `--profile core` with diagnostic; the equivalent core-handler-routed check is run instead.

**Profile-claim signaling.** How a peer signals its profile to the oracle is implementation-defined — a runtime flag, a manifest entity, an out-of-band protocol message, or operator-supplied configuration are all valid. The spec contract is the *publication* shape; the *claim* mechanism is the oracle's concern.

**§9.1 floor applies under both profiles.** Every peer (core or full) MUST clear §9.1 (the universal MUST-implement floor). `--profile core` adds the publication/registration constraints; it does not relax §9.1.

**Outbound-dispatch seam under `--profile core` (v7.74).** §4.8 (inbound concurrent with outbound-from-handlers) and §6.11 (transport reentry contract) are part of the §9.1 floor under **both** profiles. The validate-peer oracle's `origination` category is excluded from `--profile core` because single-peer mode cannot catch origination-side bugs without a `-reference-peer`; that category-skip is a **test-harness limit**, NOT a capability-scope ruling. Every peer hosts handlers that may originate (via §6.13(a) registration); the substrate must support them. See §6.13(b) for the behavioral-presence MUST.

**Non-functional floor under `--profile core` (v7.75).** §4.8 store-safety, §4.9 (resilience under sustained load), and §4.10(a)+(b) (resource bounds) are part of the §9.1 floor under **both** profiles. The `concurrency` category (added to the set above this cycle — it previously ran as an oracle carve-out) exercises §4.8/§6.11 correctness *and*, via its T2.1/T2.2 checks (GUIDE-CONFORMANCE §7b), the §4.9 resilience outcomes; no separate `resilience` category is required. The `resource_bounds` category gates §4.10: over-`max_payload` → `413 payload_too_large` + keeps-serving (MUST); over-`max_chain_depth` → `400 chain_depth_exceeded` + keeps-serving (MUST); connection flood → SHOULD, scored as a non-failing WARN (external-layer carve-out, §4.10(c)). These gates check clean coded rejection + keeps-serving, NOT absolute throughput or a particular limit value.

### 9.1 MUST Implement

- Wire framing (§1.6)
- ECF encoding for content hashing (§1.2, §1.3)
- Content hash validation on receipt (§1.8, §7.2)
- Entity fidelity (§1.8)
- Two wire message types: EXECUTE and EXECUTE_RESPONSE (§3.2, §3.3)
- Request ID correlation
- Envelope structure with per-entity hash validation (§3.1)
- Connection handler with hello and authenticate operations (§4)
- Pre-authorization rules (§4.2)
- Peer ID derivation (§7.4; canonical `hash_type`/digest form per the §1.5 table — §7.4 defers to §1.5, cite §1.5 for the form)
- Ed25519 signatures (§7.3)
- `system/hash` as flat byte string (§1.2)
- Hash comparison by byte equality (§5.3)
- Signature target-matching verification (§5.2)
- Capability verification algorithm (§5.2)
- Pattern matching and scope checking via `matches_scope` (§5.2, §5.4)
- Dispatch-level resource authorization via `check_resource_scope` when `resource` is present (§5.2) — full scope checking: effective target scope (targets minus caller excludes) within effective grant scope (includes minus grant excludes)
- Structured grant attenuation: handlers, operations, resources, peers scope subset checks; constraint key retention + byte equality; allowance key containment + byte equality (§5.6)
- Delegation chain verification (§5.5)
- Delegation caveat checking (§5.7)
- System tree handler with `get` and `put` operations (§6.3) — `resource` field carries target scope as `system/protocol/resource-target`
- Two-level capability check for tree operations (§6.3) — dispatch scope via `check_permission`, defense-in-depth path scope via `check_path_permission`
- System path reservation — user handlers MUST NOT register at `system/*` (§6.2)
- Handler manifests at pattern paths as `system/handler` entities (§6.1)
- Handlers handler with `register` and `unregister` operations (§6.2)
- Bootstrap handler initialization: `system/tree`, `system/handler`, `system/protocol/connect` (§6.9); `system/type` if type validation is provided
- Handler grant storage at `system/capability/grants/{pattern}` (§6.8)
- Handler index at `system/handler/*` with `system/handler/interface` entities (§6.2)
- `system/handler/interface` type recognition (§3.7)
- Type index at `system/type/*` (§7.5)
- Tree listing entry filtering against request capability (§6.3) — listing entries for paths the capability does not cover MUST be omitted
- Unknown field preservation (§2.10)
- Validate total hash byte length matches format code (§1.2)
- Path validation (§1.4) — no null bytes, no leading slash, no empty segments
- Dispatch routing (§1.4) — reject EXECUTE targeting non-self peer_id with status 400
- Connection handler ordering enforcement (§4.2) — hello before authenticate
- Connection uniqueness (§4.2) — reject subsequent connection requests with status 409
- Connect-time proof-of-possession (§4.6) — nonce-echo (401 `invalid_nonce`), signature verification against `authenticate.public_key` (401 `authentication_failed`), and peer_id↔public_key identity binding (401 `identity_mismatch`); `hello`/`authenticate` peer_id equality on the same connection
- Auth boundary status (§4.6, §5.2, §8.3) — connect-auth failures emit coded 401 *before* close; request-time `verify_request` DENY maps to 403 (except `unresolvable_grantee` → 401)
- Connection error-code contract (§4.7) — emit the pinned `result.data.code`/status for each connect failure (clients key off the code)
- Auth field requirement (§5.1) — author and capability required on all authenticated EXECUTE
- Root capability trust (§5.5) — root capability granter must be local peer (or, for a multi-sig root, local peer in `signers` AND signed — §5.5 M6)
- Multi-signature granter verification (§3.6, §5.5) — when a cap's `granter` is a `system/capability/multi-granter`: enforce M3 validity (root-only, N≥2, no dup signers, K∈[2,N]) before signature; verify K-of-N signatures from the `signers` set; normalize M3 violations to `403 capability_denied`. Single-sig caps verify identically.
- Invalid message handling (§3.3) — close connection on messages that are neither EXECUTE nor EXECUTE_RESPONSE
- Pattern canonicalization (§5.4) — canonicalize both path and pattern before calling matches_pattern
- **Behavioral presence of `register` / `unregister` on the handlers handler** (§6.2 five-write contract, §6.13(a)) — a `501 unsupported_operation` response on these operations from a peer claiming `--profile core` is non-conformant; the five normative writes (manifest, types, grant, grant-signature at `system/signature/{grant_hash}`, interface) MUST execute (v7.74 §6.13(a))
- **Handler-reachable outbound dispatch closure** (§6.13(b)) — the runtime exposes to handlers a path to initiate cross-peer EXECUTE dispatch routed through the §6.11 transport reentry contract; the mechanism is impl-private. A peer that stubs the outbound seam ("we don't ship handlers that originate") is non-conformant (v7.74 §6.13(b)).
- **Emit pathway live with normative event shape** (§6.10, §6.13(c)) — tree writes produce tree-change events with the field inventory `{event_type, path, new_hash, previous_hash, context}` and the `event_type` derivation pinned in §6.10; bind-to-`system/deletion-marker` fires `"modified"`, NOT `"deleted"` (v7.74 §6.13(c) / B2 ruling).
- **Peer-owner capability at L0** (§6.9a) — at peer-init, the peer materializes operable owner authority over `/{peer_id}/*` as a root capability (artifact shape per §6.9a.0 — detached-signature or tree-as-trust-root; BOTH floor-conformant), stored at `system/capability/policy/{self_identity_hash_hex}` (hex form per v7.64 §2.1). A peer that ships without this entry (relying on `debug_open_grants` or equivalent hardcoded fork) is non-conformant. **Conformance scope is peer-as-shipped** (§6.9a.3); SDK binding-layer materialization counts (v7.74 Phase 2 §6.9a).
- **Policy-derived authenticate grant** (§6.9a / §6.9a.2) — the §4.6 authenticate response carries an `included` map containing the grant derived from the seed-policy lookup for the authenticated identity (UNION'd with the §4.4 discovery floor per v7.62 §8), per the v7.64 dual-form discipline (hex → Base58 → default resolution); hardcoded `initialGrants()` / `openGrants()` fork logic is non-conformant (v7.74 Phase 2 §6.9a).
- **Store-safety under concurrent dispatch** (§4.8) — the content store and tree index MUST be safe under concurrent access from per-request dispatch; an unsynchronized store that data-races under concurrent dispatch is non-conformant (a data race is a crash). Mechanism impl-defined; single-threaded/cooperative-async runtimes satisfy it trivially (v7.75 §4.8).
- **Resilience floor under sustained load** (§4.9) — under sustained concurrent load and connection churn a peer MUST stay responsive (no deadlock/livelock), bound its resource use (no per-request/per-connection leak), **deliver-or-signal (never silently drop an admitted request)**, not crash, and recover when load subsides. Outcome contract (mechanism unconstrained), gated by GUIDE-CONFORMANCE §7b T2.1/T2.2 via the `concurrency` category (v7.75 §4.9).
- **Resource-bounds enforcement** (§4.10) — the peer MUST enforce a finite maximum inbound envelope/payload size (reject over-limit with `413 payload_too_large`) and a finite maximum capability-chain depth (reject with `400 chain_depth_exceeded` — non-authz status), rejecting over-limit input cleanly while continuing to serve. Limit *values* are impl/deployment-defined with safe defaults (recommended 16 MiB / 64, non-normative); *enforcement* is the floor. Gated by the validate-peer `resource_bounds` category (3-way GREEN v7.75). Connection admission (§4.10(c)) is a SHOULD with an external-layer carve-out, not part of this MUST (v7.75 §4.10).

### 9.2 SHOULD Implement

- Root grant tracking and revocation — implementations SHOULD maintain a reverse index (capability content hash → stored tree path) to support O(1) `is_revoked` lookup per §5.1. Implementations that support long-lived or persisted capabilities (e.g., compute subgraph installation grants) SHOULD provide `is_revoked(capability, ctx)` per the algorithm in §5.1.
- Integrated revocation checking in `verify_request` — implementations supporting any persistent-capability extension (compute, continuation, inbox, subscription, or equivalent) SHOULD enable `verify_ctx.supports_revocation` so that revoked capabilities are rejected at the dispatch boundary automatically (§5.2 step 4). Extensions that depend on revocation for correctness SHOULD require this to be enabled.
- `check_grant_covers` helper (§5.2) — implementations SHOULD expose this alongside `check_permission` and `check_path_permission` so extensions have a canonical grant-probe primitive for pre-flight checks.
- `budget_consumed` field on EXECUTE_RESPONSE (§3.3) — implementations in trusted peer groups SHOULD include this metadata for cross-peer budget coordination. Implementations outside trusted groups MAY omit it.
- Type system Level 1
- Bounds defaults when EXECUTE arrives without bounds
- Tree listing pagination
- Tree extension (EXTENSION-TREE.md) — bulk operations, non-default trees, view trees for structural capability enforcement
- Operational state types (§3.13) — populate `system/transport/*`, `system/config/*`, `system/peer/status/*`, `system/peer/alias/*`, `system/connection/*` entities for entity-native self-description and subscribability. Include operational state types in bootstrap type index.

### 9.3 MAY Implement

- Type system Level 2 (validation)
- Additional hash formats beyond SHA-256
- Additional key types beyond Ed25519
- Capability resource_limits enforcement
- Visited list strict policy (cycle detection)
- Frame-level compression via hello negotiation
- Frame-level encryption via hello negotiation
- System extensions (inbox, subscription, content, tree extended operations)
- Standard library handlers (files, processes, shell)
- User-defined extensions and handlers

### 9.4 Implementation-Defined

- Conformance-profile claim mechanism (§9.0) — how a peer signals `core` vs `full` to a conformance oracle: runtime flag, manifest entity, out-of-band, operator config. The publication shape is the spec contract; the claim mechanism is oracle-defined.
- Storage backend
- Dispatch index maintenance strategy (§6.6) — implementations MAY use an in-memory dispatch index for performance; the tree walk semantics are normative, the index mechanism is implementation-defined
- Bootstrap initialization order (§6.9) — the observable state after initialization is normative, the initialization sequence is implementation-defined
- Remote capability management (§6.8) — how the peer stores and selects grants received from remote peers for outbound requests
- Handler execution context representation and sub-request dispatch mechanism (§6.8) — the spec defines what information is available to handlers; implementations choose how to expose it and what convenience mechanisms to provide
- Concurrent request handling
- Connection pooling
- Caching strategies
- Bounds default values
- Visited list enforcement policy
- Request ID format
- Duplicate in-flight request_id handling

### 9.5 Core Type Floor Manifest (v7.72)

A peer claiming **`--profile core`** (§9.0) MUST publish exactly the following 53 types at `system/type/*` and SHOULD NOT publish any others. Types are listed by their canonical name; the entity shape is defined in the cited section of this spec.

**Primitives (8)** — §2.4:
```
primitive/any              primitive/bool             primitive/bytes
primitive/float            primitive/int              primitive/null
primitive/string           primitive/uint
```

**Structural roots / envelopes (5)** — §1.1, §3.1:
```
entity                     core/entity                core/envelope
system/envelope            system/protocol/envelope
```

**Identity / hash / signature (4)** — §1.2, §1.5, §3.5:
```
system/hash                system/peer
system/peer-id             system/signature
```

**Protocol surface (6)** — §3.1, §3.2, §3.3, §3.8:
```
system/protocol/connect/authenticate    system/protocol/connect/hello
system/protocol/error                   system/protocol/execute
system/protocol/execute/response        system/protocol/resource-target
```

**Capability (12)** — §3.6, §6.2:
```
system/capability/grant                 system/capability/grant-entry
system/capability/id-scope              system/capability/path-scope
system/capability/request               system/capability/revocation
system/capability/revoke-request        system/capability/delegate-request
system/capability/delegation-caveats    system/capability/policy-entry
system/capability/token                 system/capability/multi-granter
```

**Handler machinery (6)** — §3.7, §3.12, §6.1:
```
system/handler                          system/handler/interface
system/handler/manifest                 system/handler/operation-spec
system/handler/register-request         system/handler/register-result
```

**Tree (5)** — §3.9, §6.3:
```
system/tree/get-request                 system/tree/put-request
system/tree/listing                     system/tree/listing-entry
system/tree/path
```

**Type-system bootstrap (3)** — §2.1, §2.2, §2.7:
```
system/type                             system/type/field-spec
system/type/name
```

**Operational (4)** — §1.2a, §3.11, §3.13:
```
system/bounds                           system/resource-limits
system/delivery-spec                    system/deletion-marker
```

**Total: 53 types.**

**Blurry-edge rulings (v7.72 §3.2):**

- `system/delivery-spec` is **CORE** — referenced by `system/protocol/execute`'s `ExecuteData` shape. Subscription/continuation extensions also reference it; that does not move it out of core.
- `system/capability/{delegate-request, revoke-request, policy-entry}` are **CORE** — the capability handler is core (§6.2 MUST, line 2893), its `delegate`/`revoke`/`configure` operations are core, and the operation-input types are the operation contract.
- `system/deletion-marker` is **CORE** — deletion is core (§1.2a; ENTITY-NATIVE-TYPE-SYSTEM.md §4.9). Format-relative behavior per v7.70 §1.2 erratum.

**Full-peer publication.** A peer claiming `--profile full` publishes the 53 types above plus the types of each installed extension, per each extension's own type list. Reference impls' monolithic `RegisterCoreTypes` (Go) / `all_core_types` (Rust) / `ALL_TYPE_DEFINITIONS` (Python) registers all extension types alongside core; this is conformant for `--profile full`. A future deployment shipping `--profile core` from a reference impl would either register only the 53 (impl refactor — deferred to backlog) or run the reference impl with no extensions installed (publication is what matters; absence of extension handlers under §9.0 means absence of their types under the contract).

**Oracle scoring.** Under `--profile core`, `type_system` matches the 53; any type outside the floor is matched-if-present, not-a-FAIL-if-absent (precedent: `isProvisionalType` for `system/substitute/*` in the validate-peer reference oracle).

**Publication semantics.** "Publish" means **tree-bound `system/type` entities at `system/type/{name}`**, visible via `system/tree:get`. The `system/type` *handler* (§6.2) provides the `validate` operation on top of the published entities and is SHOULD-implement per §9.2; the publication contract itself does not depend on the handler being installed. Type entities are bound during handler registration per §6.2 `process_registration` step 3 ("installs associated types at `system/type/{type_name}`"); a core peer that ships only the four MUST-implement handlers (`system/tree`, `system/handler`, `system/capability`, `system/protocol/connect`) still publishes the 53 core type entities at their `system/type/*` paths because the bootstrap handlers' `register` calls bind them — independent of whether the `system/type` handler is installed.

### 9.5a Core Tree Operations Vector Set (v7.72)

A peer claiming **`--profile core`** MUST pass the following tree-operations vectors. These are normative for the core profile; the validate-peer reference oracle exposes them under `tree_operations` when `--profile core` is active.

| Vector | Asserts | Reference |
|---|---|---|
| `CORE-TREE-PUT-1` | `system/tree:put` on a fresh path returns 200; subsequent `system/tree:get` returns the put entity (byte-identical). | §6.3 |
| `CORE-TREE-PUT-CAS-1` | `system/tree:put` with `expected_hash = zero` (the §3.9 zero-hash CAS-create marker, v7.50): on a bound path → 409 `hash_mismatch`; on an unbound path → 200 (CAS-create). | §3.9, v7.50 |
| `CORE-TREE-PUT-CAS-2` | `system/tree:put` with non-zero `expected_hash` matching the current binding → 200; non-matching → 409 `hash_mismatch`. | §3.9 |
| `CORE-TREE-DELETE-1` | `system/tree:put` of `system/deletion-marker` at a bound path → 200; subsequent `get` returns the marker (not the prior entity); listing omits the path under the §6.3 filter convention. | §1.2a, ENTITY-NATIVE-TYPE-SYSTEM.md §4.9 |
| `CORE-TREE-LISTING-1` | `system/tree:get` on a prefix path returns a `system/tree/listing` entity whose `entries` enumerate exactly the bound paths under the prefix the caller's capability covers; listing entries for paths the cap does not cover are omitted (§6.3). | §6.3, §9.1 |
| `CORE-TREE-PATH-FLEX-1` | Path validation per §1.4: reject null byte (400); reject leading slash in caller-supplied paths (400); reject `./` and `../` (400 per §5.4 canonicalize); accept multi-segment paths and Unicode segments; the existing `path_reject_empty_segment` pin is part of this vector. | §1.4, §5.4 |

These vectors are also required reading for any conformance oracle implementing `--profile core` — they are the spec-derived behavioral pins the oracle scores against. EXTENSION-TREE.md §9 operations (`snapshot`, `diff`, `merge`, `extract`, `tracked`) are NOT part of this vector set and are skipped under `--profile core`.

---

## 10. Related Specifications

| Document | Scope |
|----------|-------|
| ENTITY-CBOR-ENCODING.md | Wire encoding (ECF, deterministic CBOR, framing) |
| EXTENSION-TREE.md | Extended tree operations: snapshots, diffs, merges, extract, non-default trees |
| EXTENSION-INBOX.md | Async inbox delivery (system extension) |
| EXTENSION-CONTINUATION.md | Continuation execution chaining (system extension) |
| EXTENSION-SUBSCRIPTION.md | Change subscriptions via inbox delivery (system extension) |
| EXTENSION-COMPUTE.md | Entity-native computation model (system extension) |
| EXTENSION-CONTENT.md | Content chunking and transfer (system extension) |
| EXTENSION-NETWORK.md | Connection lifecycle, reconnection, subscription restoration (system extension) |
| EXTENSION-TYPE.md | Type constraints and validation operations (planned) |
| MIGRATION-HISTORY.md | Version negotiation and change history (V2 → V3 → V4 → V7) |
