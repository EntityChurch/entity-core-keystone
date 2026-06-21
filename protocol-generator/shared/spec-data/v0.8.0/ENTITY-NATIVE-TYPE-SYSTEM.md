# Entity-Native Type System Specification

**Version**: 4.2.1

**Status**: Active
**Depends:** ENTITY-CORE-PROTOCOL.md

This specification defines the entity-native type system for the Entity Core Protocol. Type definitions are themselves entities in the tree, enabling structural type composition and inheritance without external schema languages. Value-level constraint validation is provided by the type extension (EXTENSION-TYPE.md, planned).

---

> **Path notation.** Paths in this document use peer-relative notation (without leading `/{peer_id}/`). All peer-relative paths resolve to the local peer's namespace: `system/tree` means `/{local_peer_id}/system/tree`. Every path in the entity tree is absolute at rest — rooted at a peer identity. See ENTITY-CORE-PROTOCOL.md §1.4 for the path model. Cross-peer examples use absolute paths with explicit peer identities.

## 1. Introduction

### 1.1 Purpose

This document specifies:
- Fourteen bootstrap types that seed the type system (8 primitives + 2 meta-types + `system/hash` + `system/tree/path` + `system/type/name` + `system/identity/peer-id`)
- How type definitions are structured as entities
- How types compose via the `extends` mechanism
- How the type extension adds value constraints (reference to EXTENSION-TYPE.md)
- Algorithms for type resolution and entity validation
- Type definitions for all core protocol entities

### 1.2 Scope

This specification covers:
- Type definition structure and semantics
- Primitive type registry
- Type composition via the `extends` mechanism
- Type resolution and structural validation algorithms
- Core entity types and protocol type definitions
- Implementation conformance levels

Out of scope:
- Entity Definition Language (EDL) syntax
- Handler dispatch based on entity type
- Type-directed code generation
- Schema migration strategies

### 1.3 Terminology

| Term | Definition |
|------|------------|
| Type entity | An entity of type `system/type` that defines a type |
| Bootstrap type | One of the 14 seed types required to define all other types |
| Type path | Short path identifying a type (e.g., `primitive/string`, `system/protocol/connect/hello`) |
| Type resolution | Process of expanding a type path to its effective field set |
| Field-spec | A field specification defining the shape and optionality of a field |
| Constraint | A restriction on the values a field may hold |
| Structural compatibility | Two types that expand to the same effective field set |

### 1.4 Notation

- **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** per RFC 2119
- CBOR diagnostic notation (RFC 8949 §8) for all examples
- Type paths shown without the `system/type/` prefix for brevity; resolution prepends this prefix (see §11.1)
- Comments in examples use `;` (CBOR diagnostic convention)

### 1.5 Relationship to Other Specifications

| Document | Relationship |
|----------|-------------|
| ENTITY-CORE-PROTOCOL.md | Defines protocol semantics; this spec defines type structure for protocol entities |
| ENTITY-CBOR-ENCODING.md | Defines wire encoding (ECF), content hashing, and type-to-CBOR mapping |
| RFC 2119 | Requirement level keywords |
| RFC 8949 | CBOR encoding and diagnostic notation |
| RFC 8610 | CDDL (generated from type definitions, §13) |

### 1.6 What the Type System Is

The entity type system is a **data shape description language** — not a programming language type system. Its primary role is enabling peers to understand each other's data and determine structural compatibility, not to provide compile-time guarantees or drive code generation.

**What the type system provides:**

- **Self-description.** Every entity carries a type string. The type definition is itself an entity in the tree. A peer can discover what types another peer speaks by reading `system/type/*`. This completes the self-description picture: the tree describes the peer's data, and the type system describes the shape of that data.

- **Compatibility checking.** Two peers exchanging entities can compare type definitions to determine whether they understand each other's data. Type resolution (§6) and structural compatibility (§12) are the core tools for answering the question: "can I meaningfully process this entity?" The type extension adds constraint narrowing for value-level compatibility.

- **Validation at boundaries.** The structural validation algorithm (§7) checks whether an entity's fields conform to its declared type — field presence, field types, union matching. This is a boundary check — applied when entities arrive from external sources, when handlers produce output, or when an implementation chooses to enforce strictness. Value-level constraint validation (ranges, patterns, enumerations) is provided by the type extension (EXTENSION-TYPE.md). Implementations at conformance Level 0 and Level 1 are fully functional protocol participants without performing any validation.

- **Shared vocabulary.** Type definitions give names to data shapes that would otherwise be implicit. `system/capability/path-scope` and `system/capability/id-scope` name the concept of an include/exclude pattern set. `system/tree/snapshot` names a captured tree state. The type system is as much about shared understanding as it is about enforcement.

**What the type system is not:**

- **Not a compiler type system.** There is no type inference, no type checking at "compile time," no borrow checker, no lifetime analysis. Entity types describe data shapes; they do not constrain computation. The type extension adds value-level constraints; the compute extension (future) addresses computational constraints.

- **Not a code generation specification.** The spec defines how to describe, resolve, and validate types — not how to generate Rust structs, Go types, or Python dataclasses from them. Implementations MAY generate host-language types from entity type definitions (and the `entity-core-derive` pattern shows this works well), but this is an implementation choice, not a protocol requirement.

- **Not exhaustive.** Open types (§2.4) mean entities can always contain fields not described by their type. Entity fidelity — preserving what you receive, including unknown fields — is more fundamental than type conformance. A peer that strips unknown fields is broken; a peer that doesn't validate types is merely Level 0.

- **Not a validation language.** Core type definitions describe structure (what fields exist, what shapes they have). Value-level validation (ranges, patterns, enumerations) is provided by the type extension. This separation reflects the system's architecture: structure is universal, validation is opinionated.

**Relationship to programming language types:**

Programming languages use types for different purposes: memory layout (C), safety guarantees (Rust), dispatch (Haskell), documentation (TypeScript). The entity type system is closest to **schema languages** (JSON Schema, Protobuf, Avro) — it describes data exchanged between systems, not data manipulated within a single program. The key differences from most schema languages are that entity types are themselves entities (self-describing, content-addressed, stored in the tree) and that the type vocabulary is extensible through composition rather than a fixed schema language.

Features like `union_of` and generics (`type_params`/`type_param`) expand the descriptive vocabulary — they let types express "this field is a string or a number" or "this is a collection parameterized by element type." These map to different host-language features depending on the language (Rust enums, Go interfaces, Python unions; Rust generics, Go type parameters, Python TypeVars). The spec does not prescribe the mapping. After generic resolution (§6.6), all types are fully concrete — the validation algorithm never encounters unresolved type parameters.

**Conformance is incremental.** A peer can participate fully in the protocol at Level 0 (type-unaware). Level 1 adds discoverability. Level 2 adds validation. Each level is useful independently. The type system is an overlay that enriches the protocol, not a prerequisite for it.

---

## 2. Design Principles

### 2.1 Universal Dereferencing

All type references, including primitives, resolve to entities in the tree. There are no special cases. The path `primitive/string` resolves to a type entity at `system/type/primitive/string` (see §11.1). This uniformity enables:
- Type discovery via tree traversal
- No special-case code for primitive types
- Consistent resolution logic for all type references

### 2.2 Composition over Inheritance

The `extends` mechanism adds fields from a parent type to a child type. It MUST NOT override fields. A child type gains all parent fields and MAY add new fields. There is no method dispatch or polymorphic behavior.

### 2.3 Constraints (Extension)

Value constraints are defined by the type extension (EXTENSION-TYPE.md). The type extension's narrowing principle — a child type's constraints MUST be equal to or more restrictive than its parent's — guarantees Liskov substitution: any entity valid for the child type is also valid for the parent type. See EXTENSION-TYPE.md for constraint semantics.

### 2.4 Open Types by Default

Entities MAY contain fields not defined in the type. Unknown fields MUST be preserved. This enables forward compatibility with newer entity versions. Implementations MUST NOT reject entities solely because they contain unknown fields, unless operating in strict mode.

**Null vs absent:** When a field-spec has `"optional": true`, the field SHOULD be absent from the entity (key not present in the map) rather than present with a null value. Absent and null produce different CBOR bytes and therefore different content hashes. Validators SHOULD treat null values on optional fields as equivalent to absent for validation purposes. See ENTITY-CORE-PROTOCOL.md §2.7 for the full rationale.

### 2.5 Content-Addressed Types

Type entities have content hashes like all entities. To prevent hash divergence across implementations, type definitions MUST NOT include `description` or other documentation fields in `data`. Types are identified by structure, not documentation.

### 2.6 Self-Referential Bootstrap

The type `system/type` defines itself. This circularity is resolved by treating the 14 bootstrap types as built-in. Implementations MUST recognize bootstrap types without requiring them to be resolved from the tree.

### 2.7 Top-Level Type Namespaces

The type registry is organized into four top-level namespaces. The namespace a type lives in is determined by what kind of type it is, not by which extension defines it.

| Namespace | Population | Membership | Examples |
|-----------|------------|------------|----------|
| `primitive/*` | 8 types | Closed (bootstrap) — atomic value types defined by the type-system bootstrap (§3). New primitives require a core-spec change. | `primitive/string`, `primitive/uint`, `primitive/any` |
| `core/*` | 2 types | Closed (bootstrap) — transmission/materialization shapes used at the entity boundary. New entries require a core-spec change. | `core/entity` (materialized form), `core/envelope` (transmission bundle) |
| `compute/*` | ~17 types | Open within the compute extension. Reserved for that extension's expression-node types. | `compute/apply`, `compute/literal`, `compute/lookup/tree` |
| `system/*` | ~120+ types | Open per extension. All other spec-defined types: protocol request/response wrappers, handler manifests, persisted metadata, capability machinery, etc. Each extension claims one or more sub-prefixes. | `system/handler/interface`, `system/role/assignment`, `system/compute/install-request` |

Plus one bare exception: the type `entity` (no prefix), the abstract structural root described in §3.1.1.

User-defined types live outside these reserved prefixes.

**Why the split is not arbitrary.** `primitive/*` and `core/*` are closed bootstrap — they describe the substrate that makes any type definition possible at all. Changing them changes the kernel. `system/*` is the registry's open, growing surface — every extension's protocol types live there. `compute/*` is a special case (see §2.7.2). The bare `entity` precedes the namespacing entirely (see §2.7.1).

#### 2.7.1 Bare `entity`: the structural root

The type `entity` (no prefix) is the abstract structural root: every entity type structurally specializes `{type, data}`, and `content_hash` is derived from this structural shape (per ENTITY-CBOR-ENCODING.md §4.2). Defined in §3.1.1.

`entity` sits outside the four-namespace structure deliberately. It is the structure those namespaces themselves describe: types are entities, type definitions are entries in a registry that already presupposes `entity`. There is no enclosing context for `entity` to live under, and giving it one (e.g., `core/entity-root`) would suggest a containing structure that doesn't exist. Implementations bootstrap `entity` together with the type system as a single primordial structure (the "co-arising" property described in §3.1.1).

Treat `entity` as a singular exception to the four-namespace rule, not as precedent for further bare-prefix types.

**Distinct from `core/entity` (§8.1).** `core/entity` is the materialized form `{type, data, content_hash}` that an entity takes once a hash has been resolved into a slot. It is used as a `type_ref` marker in field specs to require "this slot holds a real, identity-bearing entity, not raw CBOR." Bare `entity` is the abstract root; `core/entity` is the concrete materialized form. Both exist deliberately and are not duplicates — see §3.1.1 and §8.1 for full treatment.

#### 2.7.2 Compute as established precedent

The compute extension's expression-node types live at `compute/*` (no `system/` prefix). The rationale is ergonomic: expression nodes appear repeatedly nested inside user-authored compute graphs, and a `system/compute/` prefix on every node would dominate the syntax of those graphs without adding information.

The compute extension's *protocol-level* types — request/response wrappers, persisted manifests, handler-internal metadata — follow the standard convention and live at `system/compute/*` (e.g., `system/compute/install-request`, `system/compute/subgraph`). The split is consistent with the general rule: expression nodes at `compute/*`, protocol types at `system/compute/*`.

#### 2.7.3 Claiming a top-level namespace

A future extension MAY claim a top-level namespace (other than `primitive/`, `core/`, `compute/`, or `system/`) via a spec amendment, when **all three** of the following hold:

1. The types in question are user-authored composition nodes — they appear inside data the caller writes, not in protocol wrappers the handler exchanges.
2. They appear repeatedly nested inside user-written entity graphs (a single such type is not enough; rule of thumb: the prefix would appear 5+ times in a representative composition).
3. The `system/` prefix would meaningfully degrade the readability of those compositions. Whether a degradation is "meaningful" is judged by the proposing author and reviewed at proposal time; the bar is restrictive by design.

An extension that claims a top-level namespace on these grounds keeps its protocol-level types at `system/{ext}/*` per the standard convention. The namespace claim covers expression nodes only.

Plausible future candidates (illustrative only, not pre-judged): a query/predicate language, a view/projection language, a revision merge-resolution language. Each must be argued on its own merits at the time it's proposed. Extensions whose types are primarily protocol shapes — even large ones — do not qualify. Size is not the criterion; the criterion is whether the types are user-composed expression nodes.

### 2.8 Value Fields vs Entity Fields (Wire Shape)

A field-spec's `type_ref` (and the inner `type_ref` inside `array_of` / `map_of`) governs the **wire shape** of the value at that field. Two cases:

| `type_ref` form | Wire shape | What's on the wire |
|---|---|---|
| `type_ref: "core/entity"` | **Entity envelope** — `{type, data, content_hash?}` | The type travels with the element; the slot holds a materialized, identity-bearing entity. |
| `type_ref: <primitive>` (e.g., `primitive/string`, `primitive/uint`) | **Bare value** | The slot holds the primitive value directly (a string, an integer, a bytestring, etc.). |
| `type_ref: <named type>` (e.g., `system/type/violation`, `app/user`) | **Bare value record** | The slot holds a flat record matching the named type's `fields` shape. The type is implicit from the field-spec — it does NOT appear as a `type` field on the value. |

Implementations **MUST NOT** wrap primitive or named-type values as entity envelopes; consumers **MUST NOT** expect to find a `type` key on bare-value records. The same rule applies at the top level of `type_ref` outside of `array_of` / `map_of` (i.e., a scalar field with `type_ref: <named-type>` is a flat record; a scalar field with `type_ref: "core/entity"` is an envelope).

**Inside `array_of` / `map_of`, the inner `type_ref` governs each element identically.** An `array_of {type_ref: "system/type/violation"}` field is an array of flat violation records, not an array of `{type: "system/type/violation", data: {...}}` envelopes. Conversely, an `array_of {type_ref: "core/entity"}` field is an array of envelopes, because each element carries its own `type` (the elements may be heterogeneous in type).

**When to use which.** Reach for `type_ref: "core/entity"` when the slot holds entities whose types are heterogeneous, whose hashes need to be addressable independently, or whose membership in the entity graph as identity-bearing nodes is load-bearing (subscriptions, continuations, attestations, signed authority chains). Reach for `type_ref: <named-type>` when the slot holds homogeneous flat records whose interpretation is bound by the field-spec itself and the records do not need independent entity identity (validation reports, comparison results, structured params/results).

Both forms are encoded in canonical ECF (`ENTITY-CBOR-ENCODING.md`); the entity-envelope form has additional structural keys, the bare-value form does not. **The same bytes-on-the-wire rule applies to both: the encoder MUST emit canonical ECF for whichever shape the field-spec declares.** Cross-impl divergence on this rule causes silent interop failure — receivers reading a field as one shape when the sender encoded the other will see field-not-found / unexpected-shape errors rather than a clear "wire shape mismatch" diagnostic. The rule is therefore normatively pinned here for both encoders and decoders.

The present section consolidates this convention (the `core/entity` entity-envelope marker) into the normative type-system text and pins the `array_of` / `map_of` clarification surfaced by the EXTENSION-TYPE v1.1 cross-impl Phase 1 closeout.

---

## 3. Primitive Types

### 3.1 Primitive Type Registry

Eight primitive types define the foundational values of the entity type system. Primitives are defined by what they represent, not how they encode. See ENTITY-CBOR-ENCODING.md for the CBOR mapping.

| Primitive | Description |
|-----------|-------------|
| `primitive/string` | UTF-8 text. Variable length. |
| `primitive/bytes` | Binary data. Variable length. |
| `primitive/uint` | Unsigned integer. 0 to 2^64-1. |
| `primitive/int` | Signed integer. -2^63 to 2^63-1. |
| `primitive/float` | IEEE 754 floating point. |
| `primitive/bool` | Boolean. true or false. |
| `primitive/null` | Null value. Distinct from absent (see §2.4). |
| `primitive/any` | Unconstrained. Any value is valid. |

### 3.1.1 Entity Type

`entity` is the abstract structural root — every type in the system structurally specializes `{type, data}`. It has no namespace prefix because it precedes the namespacing structure (see §2.7.1).

```
entity := {
  fields: {
    type: {type_ref: "primitive/string"}     ; Entity type path
    data: {type_ref: "primitive/any"}         ; Typed payload
  }
}
```

`content_hash` is *derived* from this structural shape per ENTITY-CBOR-ENCODING.md §4.2, not declared as a field. The structural type describes what is hashed; the hash is a function of the structural type, not part of it.

`entity` is not a primitive — primitives describe raw values that go in `data`. `entity` describes the structure that carries those values.

**Co-arising.** The entity structure and the type system are mutually defining — entities need types (every entity has a `type` field), and types need entities (type definitions are entities in the tree). Neither comes first. They co-arise as a single informational structure. The `entity` type definition describes the structure that already exists before the type system can describe anything. Implementations bootstrap both together — the structure and its description are primordial, discovered rather than constructed.

**Distinct from `core/entity`.** `core/entity` (§8.1) is the materialized form `{type, data, content_hash}` — what an entity looks like once a content hash has been resolved into a slot. It is used as a `type_ref` marker in field specs to require "this slot holds a real, identity-bearing entity, not raw CBOR." Bare `entity` is the abstract structural root; `core/entity` is the concrete materialized form. Both exist deliberately:

- Bare `entity` describes what an entity *structurally is* (used in foundational reasoning, hashing rules, type-system bootstrap).
- `core/entity` describes what a materialized entity *looks like in a slot* (used as a `type_ref` marker to validate that a field holds a real entity rather than raw CBOR).

### 3.2 Primitive Type Entities

Each primitive is an entity of type `system/type` with only a `name` field:

```cbor
; primitive/string type entity
{
  "type": "system/type",
  "data": {
    "name": "primitive/string"
  }
}
```

All 8 primitives follow this pattern. They have no `fields` or `extends`.

Implementations MUST pre-populate all 8 primitive type entities at `system/type/primitive/*` at startup.

---

## 4. Meta-Types

Two meta-types define the structure of type definitions themselves.

### 4.1 system/type

The meta-type. Defines the structure of all type definitions, including itself.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/type",
    "fields": {
      "name":        {"type_ref": "system/type/name"},
      "extends":     {"type_ref": "system/type/name", "optional": true},
      "fields":      {"map_of": {"type_ref": "system/type/field-spec"}, "optional": true},
      "layout":      {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "type_params": {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "type_args":   {"map_of": {"type_ref": "system/type/name"}, "optional": true}
    }
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `system/type/name` | Yes | Type name (e.g., `"system/protocol/connect/hello"`) |
| `extends` | `system/type/name` | No | Parent type name for composition |
| `fields` | map of field-spec | No | Data field definitions (go in `entity.data`) |
| `layout` | array of `primitive/string` | No | Ordered field names specifying concatenation order within a byte string representation. Only valid when the type extends `primitive/bytes`. Implementations MUST reject `layout` on types that do not extend `primitive/bytes`. |
| `type_params` | array of `primitive/string` | No | Parameter names for generic type definitions. Each name can be referenced by `type_param` in field-specs. Only valid on generic type definitions. |
| `type_args` | map of `system/type/name` | No | Concrete type bindings when extending a generic type. Keys are parameter names from the parent's `type_params`; values are concrete type names. Only valid when `extends` references a type with `type_params`. |

**Value constraints.** The type extension (EXTENSION-TYPE.md) adds a `constraints` field to type definitions as an open-type extension field (§2.4). Core type definitions describe structure only. See EXTENSION-TYPE.md for constraint semantics, narrowing rules, and the constraint handler dispatch model.

A type with no `fields` is valid (e.g., primitive types).

**Entity references**: Fields that reference other entities use `type_ref: "system/hash"`. The hash byte string identifies the referenced entity in the envelope's `included` map or the content store.

### 4.2 system/type/field-spec

Defines the shape of a single field.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/type/field-spec",
    "fields": {
      "type_ref":   {"type_ref": "system/type/name", "optional": true},
      "optional":   {"type_ref": "primitive/bool", "optional": true},
      "array_of":   {"type_ref": "system/type/field-spec", "optional": true},
      "map_of":     {"type_ref": "system/type/field-spec", "optional": true},
      "union_of":   {"array_of": {"type_ref": "system/type/field-spec"}, "optional": true},
      "type_param": {"type_ref": "primitive/string", "optional": true},
      "type_args":  {"map_of": {"type_ref": "system/type/name"}, "optional": true},
      "default":    {"type_ref": "primitive/any", "optional": true},
      "key_type":   {"type_ref": "system/type/name", "optional": true},
      "byte_size":  {"type_ref": "primitive/uint", "optional": true}
    }
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type_ref` | `system/type/name` | See below | Type name for the value's type |
| `optional` | `primitive/bool` | No | If `true`, field may be absent. Default: `false` |
| `array_of` | `system/type/field-spec` | See below | Element spec for array fields |
| `map_of` | `system/type/field-spec` | See below | Value spec for map fields (keys default to strings) |
| `union_of` | array of `system/type/field-spec` | See below | Variants — value must match at least one (first match wins) |
| `type_param` | `primitive/string` | See below | References a generic type parameter by name. Resolved during `resolve_generic` (§6.6) |
| `type_args` | map of `system/type/name` | No | Concrete type bindings for a generic `type_ref`. Keys are parameter names; values are concrete type names. |
| `default` | `primitive/any` | No | Default value for the field when absent. When a field has a `default`, the field is valid when absent regardless of `optional` — the default implies the field has a meaningful absent state. Does NOT affect instance hashing — absent fields remain absent in hash computation. Applied at the processing layer. |
| `key_type` | `system/type/name` | No | Type for map keys. Default: `"primitive/string"`. Only valid when `map_of` is present. `key_type` MUST reference a concrete primitive type or a type that extends a concrete primitive. `key_type` MUST NOT be `primitive/any`. Heterogeneous map keys create ambiguous sort ordering in any deterministic encoding. `primitive/string` is RECOMMENDED as the default key type. |
| `byte_size` | `primitive/uint` | No | Fixed byte width of a field within a structured primitive's layout. Only meaningful when the field belongs to a type with a `layout`. The last field in the layout MAY omit `byte_size`, in which case it consumes the remaining bytes. Multi-byte integer fields use big-endian (network byte order). |

**Exactly-one-of invariant:** A field-spec MUST contain exactly one of `type_ref`, `array_of`, `map_of`, `union_of`, or `type_param`. `key_type`, `optional`, `default`, `type_args`, and `byte_size` are modifiers, not alternatives. Implementations MUST reject field-specs that contain zero or more than one of the five primary fields.

- `type_ref` present: Field holds a single value of the referenced type
- `array_of` present: Field holds an array; each element matches the nested field-spec
- `map_of` present: Field holds a map; each value matches the nested field-spec. Keys are `primitive/string` by default, or the type specified by `key_type`
- `union_of` present: Field holds a value matching one of the variant field-specs. Validation tries each variant in order; the first match wins. See `validate_union` (§7.3.1)
- `type_param` present: Field type is determined by a generic type parameter. Only valid within types that declare `type_params`. The string value references a parameter name. Resolved to a concrete `type_ref` during `resolve_generic` (§6.6) before validation

The nested field-spec in `array_of`, `map_of`, and `union_of` follows the same exactly-one-of invariant, enabling nested collections and compound unions.

**Examples:**

```cbor
; Simple string field
{"type_ref": "primitive/string"}

; Optional uint field
{"type_ref": "primitive/uint", "optional": true}

; Optional field with default
{"type_ref": "primitive/string", "optional": true, "default": "unknown"}

; Array of strings
{"array_of": {"type_ref": "primitive/string"}}

; Map of any values
{"map_of": {"type_ref": "primitive/any"}}

; Array of arrays of strings
{"array_of": {"array_of": {"type_ref": "primitive/string"}}}

; Union of string or uint
{"union_of": [{"type_ref": "primitive/string"}, {"type_ref": "primitive/uint"}]}

; Generic type parameter reference
{"type_param": "T"}
```

### 4.3 Value Constraints (Extension)

Value constraints (range checks, pattern matching, enumeration) are defined by the type extension (EXTENSION-TYPE.md). Core type definitions describe structure only.

The type extension defines `system/type/constraint` and the constraint handler dispatch model. See EXTENSION-TYPE.md for the constraint architecture.

### 4.4 Bootstrap Summary

The complete set of 14 bootstrap types:

| # | Type Path | Purpose |
|---|-----------|---------|
| 1 | `primitive/string` | UTF-8 text |
| 2 | `primitive/bytes` | Binary data |
| 3 | `primitive/uint` | Unsigned integer (0 to 2^64-1) |
| 4 | `primitive/int` | Signed integer |
| 5 | `primitive/float` | IEEE 754 floating point |
| 6 | `primitive/bool` | Boolean (true/false) |
| 7 | `primitive/null` | Null value |
| 8 | `primitive/any` | Unconstrained value |
| 9 | `system/hash` | Content hash (flat byte string: format code + digest) |
| 10 | `system/type` | Type definition structure (meta-type) |
| 11 | `system/type/field-spec` | Field specification |
| 12 | `system/tree/path` | Tree path (naming-space address) |
| 13 | `system/type/name` | Type name (type identity) |
| 14 | `system/identity/peer-id` | Peer identity (Base58-encoded) |
| 15 | `entity` | Structural root type (`{type, data}`); content_hash derived per ECF |

Implementations MUST treat these 14 types as built-in. They MUST be recognized without tree lookup and MUST be populated in the entity tree at startup.

### 4.5 system/hash

The hash type for content addressing and entity references. Part of the bootstrap set.

`system/hash` extends `primitive/bytes` — on the wire it is a CBOR byte string. The type system describes the internal byte structure: the first byte is the format code identifying the encoding version and hash algorithm, and the remaining bytes are the raw digest.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/hash",
    "extends": "primitive/bytes",
    "fields": {
      "format_code": {"type_ref": "primitive/uint", "byte_size": 1},
      "digest":      {"type_ref": "primitive/bytes"}
    },
    "layout": ["format_code", "digest"]
  }
}
```

**Field decomposition:**
```
Encoded (33 bytes for SHA-256):  [0x00] [32 bytes SHA-256 digest]
                                  ^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^
                                  format_code (byte_size: 1)  digest (remaining)
```

| Format Code | Algorithm | Total Size |
|-------------|-----------|------------|
| 0x00 | ECFv1-SHA-256 | 33 bytes |
| 0x01 | ECFv1-SHA-384 | 49 bytes |
| 0x02 | ECFv1-SHA-512 | 65 bytes |

Encoding is unchanged — `system/hash` extends `primitive/bytes`, so it encodes as a CBOR byte string (bstr). The `fields` and `layout` describe the byte structure for entity-native code; they do not affect encoding. All hash values — `content_hash` fields, `included` map keys, and entity references in data — use the same flat byte representation. See ENTITY-CORE-PROTOCOL.md §1.2, §2.5.

**Implementation note:** Implementations MAY treat hashes as opaque byte values (simpler, works everywhere) OR decompose into `format_code` + `digest` for internal operations (e.g., partition content stores by format code, use digest-aligned keys). Both are correct. The type system describes the structure; how implementations use that information is their choice.

### 4.6 system/tree/path

The tree path type for naming-space addresses. Part of the bootstrap set.

`system/tree/path` extends `primitive/string` — on the wire it is a CBOR text string. The type distinguishes tree paths (dereferenceable locations in the entity tree) from arbitrary strings. Fields typed as `system/tree/path` hold tree locations such as `/alice_id/system/handler/system/tree` (absolute) or `system/handler/system/tree` (peer-relative).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/tree/path",
    "extends": "primitive/string"
  }
}
```

Encoding is unchanged — `system/tree/path` extends `primitive/string`, so it encodes as a CBOR text string (tstr). Validation treats it as a string with the following form constraints:

**Valid forms** (see ENTITY-CORE-PROTOCOL.md §1.4):

| Form | Example | Detection |
|------|---------|-----------|
| URI | `entity://peer_id/system/tree` | Starts with `entity://` |
| Absolute path | `/{peer_id}/system/tree` | Starts with `/` |
| Peer-relative path | `system/tree` | Neither of the above |

**Validation rules** (applied after form detection):
- URI form: strip `entity://` prefix, validate remaining path per absolute rules.
- Absolute: first segment after `/` MUST be a valid peer_id (Base58, >= 46 chars; 46 is the minimum for Ed25519+SHA-256). No empty segments. No trailing `/`.
- Peer-relative: no leading `/`. No empty segments. No trailing `/`. MUST NOT start with `./` or `../` (reserved for future directory-relative semantics).
- All forms: MUST NOT contain null bytes. Segments starting with `.` are valid (e.g., `.gitignore`).

The type extension (EXTENSION-TYPE.md) MAY add further value constraints.

**Rationale:** Paths are the naming-space address primitive — the counterpart to `system/hash` (content-space address). Every field that holds a tree location (URIs, handler patterns, resource targets, visited lists) benefits from the type distinction. This enables type-aware tooling to distinguish dereferenceable locations from arbitrary text without changing wire encoding or validation algorithms.

### 4.7 system/type/name

The type name type for type identity. Part of the bootstrap set.

`system/type/name` extends `primitive/string` — on the wire it is a CBOR text string. The type distinguishes type names (slash-separated namespace paths identifying type definitions) from arbitrary strings. Fields typed as `system/type/name` hold type identifiers such as `"system/protocol/execute"` or `"primitive/string"`.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/type/name",
    "extends": "primitive/string"
  }
}
```

Encoding is unchanged — `system/type/name` extends `primitive/string`, so it encodes as a CBOR text string (tstr). Validation treats it as a string. The type extension (EXTENSION-TYPE.md) MAY add value constraints (e.g., format validation for slash-separated paths).

**Rationale:** Type names are the type-space address primitive. Convention maps type names to tree paths (`system/type/{type_name}`), but the name is the interop contract — the same type name means the same structural definition regardless of where or whether it's stored. Every field that holds a type reference (`type_ref`, `extends`, `input_type`, `output_type`, `key_type`, `type_args`, `entity_type`) benefits from the type distinction.

### 4.8 system/identity/peer-id

The peer identity type. Part of the bootstrap set.

`system/identity/peer-id` extends `primitive/string` — on the wire it is a CBOR text string. The type distinguishes peer identifiers (Base58-encoded `key_type || hash_type || digest`) from arbitrary strings. For Ed25519 + SHA-256: 46 Base58 characters. Fields typed as `system/identity/peer-id` hold peer identity values.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/identity/peer-id",
    "extends": "primitive/string"
  }
}
```

Encoding is unchanged — `system/identity/peer-id` extends `primitive/string`, so it encodes as a CBOR text string (tstr). Validation treats it as a string. The type extension (EXTENSION-TYPE.md) MAY add value constraints (e.g., Base58 format validation, length check).

**Rationale:** Peer IDs are the identity-space address primitive. Every field that holds a peer identifier (`peer_id` on identity entities and connection messages) benefits from the type distinction. The four address primitives — `system/hash` (content), `system/tree/path` (naming), `system/type/name` (type), `system/identity/peer-id` (identity) — are now all typed.

### 4.9 system/deletion-marker

The canonical deletion marker. A zero-field entity used by EXTENSION-REVISION (and any future extension that needs an explicit deletion signal in a content-addressed structure) to record intentional path deletion in a version's trie. Registered as a core type at peer init alongside `system/hash`, `system/tree/path`, `system/type/name`, and `system/identity/peer-id`; available always; not owned by EXTENSION-REVISION (the merge logic that consumes deletion markers lives in EXTENSION-REVISION.md §4.4.4 / §6.1, but the type itself is core because deletion semantics are generic).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/deletion-marker",
    "fields": {}
  }
}
```

**Canonical encoding (normative).** The entity follows standard ECF encoding (ENTITY-CBOR-ENCODING.md). The `data` field for a `fields: {}` schema is the CBOR empty map (`0xa0`), per ECF's standard treatment of zero-field types — NOT a CBOR empty byte string (`0x40`) and NOT CBOR null (`0xf6`). All implementations MUST produce this encoding via their standard ECF encoder; no special-casing is required.

**The canonical hash:**

```
CANONICAL_DELETION_MARKER_HASH = ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6
```

This hash is mechanically derivable from ECF rules; any implementation that ships standard ECF will produce this value. Implementations MUST verify their local computation matches the value above as part of conformance testing — any deviation signals an ECF-encoding bug that MUST be fixed before the implementation can claim conformance.

**Format-relative (v7.70).** The deletion marker is a **content entity** — it lives in the content address space, not in an identifier namespace. Its `content_hash` is therefore **format-relative**: `content_hash(deletion_marker_entity)` computed under the operative `content_hash_format` (the trie's / peer's home format, ENTITY-CORE-PROTOCOL.md §1.2). The value above is the marker's instance in the **SHA-256 address space** (`content_hash_format = 0x00`) and the conformance test vector — it is **not** a universal constant recognized across all formats. A SHA-384-home trie's deletion marker is the SHA-384 hash of the same zero-field entity. Within a single-format network (the recommended deployment) every peer's marker hash matches, so the O(1) hash-equality recognition and the merge-classification "deletion markers are canonical / same hash on every peer" hold exactly as before. Across home formats (the experimental two-address-space case, ENTITY-CORE-PROTOCOL.md §1.2a / §1.5) the markers differ like all content; recognition against a foreign-format trie MUST fall back to entity-layer recognition (load the entity, check `type == "system/deletion-marker"`). Implementations MUST compute the marker hash under the trie's format rather than assuming the SHA-256 value, and MUST NOT treat the SHA-256 value as recognized across all formats. (Contrast: a referential *identifier* such as COMPUTE's `subgraph_id` stays SHA-256-pinned — it is a name, not content. The principle: names are pinned, content is format-relative.)

**Semantics.** A deletion marker bound at a path in a version's trie records that the path was *intentionally deleted* between the version's parent and the version itself. It is distinguished from path absence, which means *no opinion* (per EXTENSION-REVISION.md §4.4.4 — three-way merge classifies absence as preserved-from-the-other-side, not deletion).

**Live-tree invariant.** Deletion markers MUST NOT be bound in the live location index. Version-transcription operations (per EXTENSION-REVISION.md §4.4.4 — `merge`, fast-forward, `checkout`, `push` recipient-side apply, `cherry-pick`, `revert`) translate marker bindings to live-tree unbinds at apply time. Live deletion is expressed by `tree:put(path, null)` (core §6.3; EXTENSION-TREE.md §3.1) — unchanged from current semantics.

**Application use.** Applications binding `system/deletion-marker` entities directly via `tree:put(path, marker_entity)` is not protocol-prohibited (the tree layer does not interpret entity types) but is **undefined application-level behavior**: the binding persists in the writer's live tree while remote peers' merge-apply translates it to an unbind, producing local-vs-remote asymmetry. Applications expressing deletion SHOULD use `tree:put(path, null)`, the canonical delete API; direct binding of marker entities is not recommended.

**Audit metadata.** Deleter identity, deletion timestamp, and prior binding hash are recorded in EXTENSION-HISTORY's `deleted` events, not on the deletion-marker entity. No information is lost by the canonical form; audit data lives at a different layer.

**Informative note.** This entity serves the role that CRDT literature (Cassandra, Riak, Dynamo) calls a *tombstone*. The protocol's term "deletion marker" describes the property without inheriting the skeuomorphic-permanence connotation tombstones carry — a deletion marker in this protocol is bound to a specific version's trie and gets pruned with the version under standard revision retention (EXTENSION-REVISION.md §6.6); it is not a permanent memorial.

---

## 5. Type Composition

### 5.1 The extends Mechanism

A type MAY specify an `extends` field referencing a parent type. The child type includes all fields from the parent in addition to its own.

```cbor
; system/protocol/envelope extends core/envelope
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/envelope",
    "extends": "core/envelope"
  }
}
```

This type inherits `root` and `included` from `core/envelope`. The type extension (EXTENSION-TYPE.md) MAY add constraints narrowing what `root` may contain.

**Rules:**
- The child type MUST NOT redefine a field that exists in the parent. Name collision between parent and child fields is an error.
- The child type MAY add new fields not present in the parent.

### 5.2 Constraint Inheritance

Constraint inheritance and narrowing rules are defined by the type extension (EXTENSION-TYPE.md). Core type composition handles structural field inheritance only.

### 5.3 Single Inheritance

A type MUST extend at most one parent. Multiple inheritance is not supported.

**Rationale:** Single inheritance avoids field name conflicts and diamond inheritance problems. Composition through `system/hash` reference fields provides an alternative for combining behaviors from multiple sources.

### 5.4 Composition Examples

```cbor
; core/envelope defines the base structure
{
  "type": "system/type",
  "data": {
    "name": "core/envelope",
    "fields": {
      "root": {"type_ref": "primitive/any"},
      "included": {"map_of": {"type_ref": "primitive/any"}, "optional": true}
    }
  }
}

; system/protocol/envelope extends with no additional structural fields
; (constraint narrowing of root type is a type extension concern)
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/envelope",
    "extends": "core/envelope"
  }
}
```

Each level of extension adds structural fields. The type extension (EXTENSION-TYPE.md) can additionally add constraints that narrow inherited fields.

### 5.5 Type Patterns

The `extends` mechanism, combined with `fields`, produces three distinct type patterns. These patterns determine how a type encodes (see ENTITY-CBOR-ENCODING.md for the encoding mapping).

#### 5.5.1 Structured Types

A type with fields and no `extends` (or extending another structured type). This is the normal case — most types in the protocol.

```cbor
{
  "name": "system/protocol/connect/hello",
  "fields": {
    "peer_id":   {"type_ref": "system/identity/peer-id"},
    "nonce":     {"type_ref": "primitive/bytes"},
    "protocols": {"array_of": {"type_ref": "primitive/string"}},
    "timestamp": {"type_ref": "primitive/uint"}
  }
}
```

**Encoding:** CBOR map with string keys, sorted per ECF.
**Validation:** Check each field exists (if required) and matches its type.
**Relationship to primitives:** HAS-A. The type has fields that are primitives.

#### 5.5.2 Extended Primitives

A type that extends a primitive. Narrows the primitive's meaning through the type path.

```cbor
{
  "name": "system/timestamp",
  "extends": "primitive/uint"
}
```

**Encoding:** Same as the extended primitive. A `system/timestamp` encodes as the same CBOR type as `primitive/uint`.
**Validation:** Validate as the primitive type.
**Relationship to primitives:** IS-A. The type IS the primitive. The type extension (EXTENSION-TYPE.md) MAY add value constraints (e.g., min: 0).

#### 5.5.3 Structured Primitives

A type that extends a primitive AND has fields. The primitive determines encoding. The fields describe the internal structure of the primitive value. The entity system is self-describing — the type tells you what the bytes mean.

For types extending `primitive/bytes`, the type system fully specifies the byte layout via the `layout` and `byte_size` fields (§4.1, §4.2).

```cbor
{
  "name": "system/hash",
  "extends": "primitive/bytes",
  "fields": {
    "format_code": {"type_ref": "primitive/uint", "byte_size": 1},
    "digest":      {"type_ref": "primitive/bytes"}
  },
  "layout": ["format_code", "digest"]
}
```

**Encoding:** Same as the extended primitive. `system/hash` extends `primitive/bytes`, so it encodes as a CBOR byte string. The fields do NOT change the encoding — they describe what the bytes mean, not how they encode.
**Validation:** Validate as the primitive (it's a byte string), then optionally decompose and validate fields.
**Relationship to primitives:** IS-A with structure. The type IS the primitive, AND the type system knows its internal parts.

**Layout field semantics:** In a structured primitive's layout, `type_ref` specifies the semantic interpretation of the extracted bytes, not a CBOR data item type. A field with `{"type_ref": "primitive/uint", "byte_size": 1}` means "extract 1 byte and interpret as an unsigned integer" — not "expect a CBOR major type 0 data item." The entire structured primitive encodes as a single CBOR byte string; layout fields describe regions within that byte string.

**Where this applies:**
- **primitive/bytes** — byte layout. Fields describe byte regions with `layout` and `byte_size`.
- **primitive/string** — no layout. Strings have variable-length delimited components, not fixed byte offsets. `layout` is NOT valid on string-extending types. The type extension MAY add constraints (e.g., `pattern`).
- **primitive/uint, int, float** — no layout. These are scalars. The type extension MAY add constraints (e.g., min/max).
- **primitive/bool, null** — never. Nothing to decompose.

**With vs without layout:** A `layout` field makes decomposition machine-readable — the same generic algorithm works for any structured primitive that provides a layout. Types without `layout` that have fields on a primitive-extending type use those fields as semantic annotations only — the handler is responsible for decomposition.

---

## 6. Type Resolution Algorithm

### 6.1 Resolution Process

Type resolution expands a type path into its effective definition: the complete set of fields including all inherited members.

```
resolve(type_path, visited = {}, type_args = null):
  if type_path in visited:
    ERROR "Circular extends detected: " + type_path
  visited = visited + {type_path}

  type_def = lookup("system/type/" + type_path)
  if type_def is null:
    ERROR "Type not found: " + type_path

  ; Resolve generic type parameters if present
  if type_def has "type_params" and type_args is not null:
    type_def = resolve_generic(type_def, type_args)

  if type_def has "extends":
    parent = resolve(type_def.extends, visited, type_def.type_args or null)
    return merge(parent, type_def)
  else:
    return {
      fields: type_def.fields or {}
    }
```

### 6.2 Cycle Detection

The `visited` set tracks type paths encountered during resolution. If a type path appears in `visited`, the extends chain contains a cycle. Implementations MUST detect cycles and report an error. Implementations MUST NOT enter infinite loops.

### 6.3 Field Merging

When merging a parent definition with a child definition:

```
merge(parent, child):
  ; Check for name collisions
  for field_name in child.fields:
    if field_name in parent.fields:
      ERROR "Field collision: " + field_name + " already defined in parent"

  ; Merge fields (union)
  merged_fields = parent.fields + child.fields

  return {
    fields: merged_fields
  }
```

### 6.4 Constraint Narrowing Rules

Constraint narrowing rules are defined by the type extension (EXTENSION-TYPE.md). Core type resolution handles structural field merging only.

### 6.5 Caching

Implementations SHOULD cache resolved type definitions. Because types are content-addressed, the resolved definition for a given type hash is immutable and safe to cache indefinitely. Cache invalidation is only needed if the type entity at a path is replaced (the path now points to a different hash).

### 6.6 Generic Type Resolution

When a type definition has `type_params`, it is a generic type. Concrete types extend generic types by providing `type_args` that bind parameter names to concrete type paths. The `resolve_generic` function substitutes all `type_param` references with concrete `type_ref` values before validation:

```
resolve_generic(type_def, type_args):
  ; Substitute type_param references with concrete types from type_args.
  ; Runs BEFORE validation — the result contains only concrete types.
  resolved_fields = {}
  for field_name, field_spec in type_def.fields:
    resolved_fields[field_name] = substitute_field_spec(field_spec, type_args)
  return type_def with fields = resolved_fields

substitute_field_spec(field_spec, type_args):
  if field_spec has type_param:
    param_name = field_spec.type_param
    if param_name not in type_args:
      ERROR "Unbound type parameter: " + param_name
    ; Replace type_param with concrete type_ref
    return field_spec with {type_param: removed, type_ref: type_args[param_name]}

  if field_spec has array_of:
    return field_spec with array_of = substitute_field_spec(field_spec.array_of, type_args)

  if field_spec has map_of:
    return field_spec with map_of = substitute_field_spec(field_spec.map_of, type_args)

  if field_spec has union_of:
    return field_spec with union_of = [
      substitute_field_spec(variant, type_args)
      for variant in field_spec.union_of
    ]

  ; type_ref — check for type_args on the reference itself
  if field_spec has type_args:
    ; Propagate type_args substitution to nested generic references
    substituted_args = {}
    for key, val in field_spec.type_args:
      if val in type_args:
        substituted_args[key] = type_args[val]
      else:
        substituted_args[key] = val
    return field_spec with type_args = substituted_args

  return field_spec    ; No substitution needed
```

**Example: Generic pair type**

```cbor
; Generic definition
{"type": "system/type", "data": {
  "name": "collection/pair",
  "type_params": ["A", "B"],
  "fields": {
    "first":  {"type_param": "A"},
    "second": {"type_param": "B"}
  }
}}

; Concrete type extending the generic
{"type": "system/type", "data": {
  "name": "my/string-int-pair",
  "extends": "collection/pair",
  "type_args": {"A": "primitive/string", "B": "primitive/int"}
}}
```

After `resolve_generic`, the effective fields of `my/string-int-pair` are:
```cbor
{"first": {"type_ref": "primitive/string"}, "second": {"type_ref": "primitive/int"}}
```

### 6.7 Evolution Rules

Type evolution refers to changes to a type definition over time. Changes are classified by whether they preserve backward compatibility (existing instances remain valid) and forward compatibility (new instances are valid under old definitions).

**Backward-safe changes** (existing instances remain valid under the new definition):
- Add an optional field (no default required — existing instances lack it, which is valid)
- Add a field with a default value (existing instances lack it, default applies)
- Add a variant to `union_of`
- Widen a constraint (type extension — higher max, lower min, more values)

**Backward-breaking changes** (existing instances may become invalid):
- Add a required field without a default
- Remove a field
- Change a field's `type_ref` to an incompatible type
- Remove a variant from `union_of`
- Narrow a constraint (type extension — lower max, higher min, fewer values)

**Forward-safe changes** (new instances are valid under the old definition):
- Add any field (unknown fields are preserved per open type rules, §2.4)
- Add a constraint (type extension — old definition doesn't check it)

**Forward-breaking changes** (new instances may be invalid under the old definition):
- Remove a required field (old definition expects it)
- Widen a constraint (type extension — new values may exceed old limits)

Implementations SHOULD document which evolution rules they enforce. The open type model (ENTITY-CORE-PROTOCOL.md §2.7) provides natural forward compatibility for field additions — unknown fields are preserved, not rejected.

---

## 7. Validation Algorithm

### 7.1 Validation Overview

Validation checks whether an entity conforms to its declared type. Validation is performed against the resolved effective definition (§6).

### 7.2 Validation Stages

Validation proceeds in two stages:

```
validate(entity, type_path):
  ; Stage 1: Resolve type
  type_def = resolve(type_path)
  if error: return error

  ; Stage 2: Validate data fields (structural)
  for field_name, field_spec in type_def.fields:
    value = entity.data[field_name]
    if value is absent:
      if field_spec.default is not null:
        ; Absent field with default is valid.
        ; Default is applied at the processing layer, not during validation.
        ; The entity's content_hash is computed over {type, data} as-is —
        ; absent fields remain absent in hash computation.
        continue
      if not field_spec.optional:
        report_error("Missing required field: " + field_name)
      continue
    validate_value(value, field_spec)

  ; Unknown fields (open type behavior)
  ; Unknown fields in entity.data are preserved, not errors
  ; See ENTITY-CORE-PROTOCOL.md §2.7

  return collected_errors
```

### 7.3 Value Validation

Validates a single value against a field-spec:

```
validate_value(value, field_spec):
  if field_spec has type_ref:
    validate_primitive(value, field_spec.type_ref)

  else if field_spec has array_of:
    if value is not array:
      report_error("Expected array")
      return
    for element in value:
      validate_value(element, field_spec.array_of)

  else if field_spec has map_of:
    if value is not map:
      report_error("Expected map")
      return
    expected_key_type = field_spec.key_type or "primitive/string"
    for key, val in value:
      validate_primitive(key, expected_key_type)
      validate_value(val, field_spec.map_of)

  else if field_spec has union_of:
    validate_union(value, field_spec.union_of)

  else if field_spec has type_param:
    ; type_param should be resolved by resolve_generic (§6.6) before validation.
    ; If encountered here, the generic was not resolved — treat as error.
    report_error("Unresolved type parameter: " + field_spec.type_param)
```

Primitive validation checks the CBOR encoding type per ENTITY-CBOR-ENCODING.md (type-to-encoding mapping). For non-primitive type references (e.g., `type_ref: "file/metadata"`), the referenced value is expected to be a nested object whose structure matches the referenced type. Implementations MAY recursively validate nested objects against their declared types.

### 7.3.1 Union Validation

Validates a value against a union of variant field-specs. The first matching variant wins:

```
validate_union(value, variants):
  for variant in variants:
    if try_validate_value(value, variant):
      return                     ; First match wins
  report_error("Value does not match any union variant")

try_validate_value(value, field_spec):
  ; Attempt validation without reporting errors.
  ; Returns true if validation succeeds, false otherwise.
  ; Used for union discrimination — errors from non-matching
  ; variants are discarded.
  ...  ; Implementation-defined error suppression
```

**Kinded discrimination.** When all variants in a `union_of` have distinct CBOR major types (e.g., string vs uint vs array), implementations SHOULD optimize by dispatching on the value's encoding type rather than trying each variant sequentially. This is an optimization, not a requirement — the semantics are defined by first-match.

### 7.4 Constraint Checking

Constraint checking is defined by the type extension (EXTENSION-TYPE.md). Core validation checks structural conformance only — field presence, field types, union matching. Value-level predicates (range checks, pattern matching, enumeration) are evaluated by the type extension's constraint handler dispatch model.

The constraint checking semantics (RE2 regex syntax, glob matching, CBOR equality, NaN handling, length/count measurement) are specified in EXTENSION-TYPE.md.

### 7.5 Hash Reference Validation

When a field has `type_ref: "system/hash"`, core validates that the value is a valid byte string conforming to the `system/hash` structure. Constraint-based validation of the referenced entity's type (e.g., `type_pattern` or `one_of` checks) is provided by the type extension (EXTENSION-TYPE.md).

### 7.6 Error Reporting

Implementations SHOULD collect all validation errors rather than stopping at the first error. Each error SHOULD include:
- Field name where the error occurred
- Expected value or constraint
- Actual value found

This enables callers to understand and fix all issues in a single validation pass.

---

## 8. Core Entity Types

These types describe the transmission/materialization shapes used at the entity boundary — `core/entity` describes one materialized entity in a slot, `core/envelope` describes a bundle of materialized entities for transmission. Both live in the `core/*` namespace per §2.7. The abstract structural root `entity` is defined in §3.1.1.

### 8.1 core/entity

The materialized form an entity takes once a content hash has been resolved into a slot. Used as a `type_ref` marker in field specs to require that a slot holds a real, identity-bearing entity rather than raw CBOR.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "core/entity",
    "fields": {
      "type":         {"type_ref": "primitive/string"},
      "data":         {"type_ref": "primitive/any"},
      "content_hash": {"type_ref": "system/hash"}
    }
  }
}
```

`core/entity` carries `content_hash` as a declared field because it describes the materialized representation — the form an entity has when resolved into a slot, where the hash is carried alongside `type` and `data`. This is distinct from bare `entity` (§3.1.1), which is the abstract structural root from which `content_hash` is *derived*. See §2.7 for namespace conventions and §3.1.1 for the structural root.

**Type-ref marker usage.** Fields in protocol message types and other entity definitions use `{type_ref: "core/entity"}` to require materialized entities and `{type_ref: "primitive/any"}` to accept raw CBOR values:

- `{type_ref: "primitive/any"}` — field contains a raw CBOR value (string, number, map, etc.); accepts anything including a CBOR map that happens to look like an entity.
- `{type_ref: "core/entity"}` — field contains a materialized entity `{type, data, content_hash}`; raw CBOR values that don't match the three-field structure are rejected.

Fields typed as `primitive/any` accept any value, including entities (an entity is a CBOR map). Fields typed as `core/entity` require the three-field materialized structure.

**Why `core/`.** `core/entity` lives in the `core/*` namespace alongside `core/envelope` (§8.3). Both are transmission/materialization shapes used at the entity boundary — `core/entity` describes one materialized entity in a slot, `core/envelope` describes a bundle of materialized entities for transmission. The shared namespace reflects the shared role.

### 8.2 Entity References

Entity references are `system/hash` byte strings stored directly in the `data` fields. There is no separate `refs` map. Example:

```cbor
{
  "type": "system/protocol/execute",
  "data": {
    "request_id": "...",
    "uri": "...",
    "operation": "...",
    "resource": {"targets": ["..."]},  ; optional — resource target scope for authorization
    "params": {...},
    "author": h'00...',        ; system/hash (33 bytes)
    "capability": h'00...'     ; system/hash (33 bytes)
  },
  "content_hash": h'00...'    ; system/hash (33 bytes)
}
```

Referenced entities are looked up in the envelope's `included` map by their content hash.

### 8.3 core/envelope

An envelope bundles a root entity with related entities for transmission.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "core/envelope",
    "fields": {
      "root":     {"type_ref": "primitive/any"},
      "included": {"map_of": {"type_ref": "primitive/any"}, "key_type": "system/hash", "optional": true}
    }
  }
}
```

The `root` field contains the primary entity. The `included` map contains supporting entities keyed by content hash. See ENTITY-CORE-PROTOCOL.md §3.1 for envelope semantics.

---

## 9. Protocol Types

These types define the contents of the `data` field for each protocol message type. Entity references use `system/hash` fields. Auth fields (`author`, `capability`) on `system/protocol/execute` are OPTIONAL in the type definition. ENTITY-CORE-PROTOCOL.md §3.2 requires them for authenticated requests (except connection). Signatures are found via target-matching in the envelope.

### 9.1 system/protocol/envelope

The protocol envelope extends `core/envelope` for protocol messages. The type extension MAY add constraints narrowing the root to protocol message types (e.g., `type_pattern: "system/*"`).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/envelope",
    "extends": "core/envelope"
  }
}
```

### 9.2 system/protocol/connect/hello

Connection initiation message. Exchanges peer identity, nonce challenge, and protocol capabilities.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/connect/hello",
    "fields": {
      "peer_id":      {"type_ref": "system/identity/peer-id"},
      "nonce":        {"type_ref": "primitive/bytes"},
      "protocols":    {"array_of": {"type_ref": "primitive/string"}},
      "timestamp":    {"type_ref": "primitive/uint"},
      "hash_formats": {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "key_types":    {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "compression":  {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "encryption":   {"array_of": {"type_ref": "primitive/string"}, "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `peer_id` | Sender's peer ID (base58-encoded) |
| `nonce` | 32 random bytes for challenge |
| `protocols` | Supported protocol versions (e.g., `["entity-core/1.0"]`) |
| `timestamp` | Milliseconds since Unix epoch |
| `hash_formats` | Supported hash formats; defaults to `["ecfv1-sha256"]` if absent |
| `key_types` | Supported signature key types; defaults to `["ed25519"]` if absent |
| `compression` | Supported compression algorithms; absent = none |
| `encryption` | Supported encryption algorithms; absent = none |

### 9.3 system/protocol/connect/authenticate

Identity proof. The signature is a separate `system/signature` entity found via target-matching in the envelope (see ENTITY-CORE-PROTOCOL.md §4.6).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/connect/authenticate",
    "fields": {
      "peer_id":    {"type_ref": "system/identity/peer-id"},
      "public_key": {"type_ref": "primitive/bytes"},
      "key_type":   {"type_ref": "primitive/string"},
      "nonce":      {"type_ref": "primitive/bytes"}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `peer_id` | Sender's peer ID |
| `public_key` | Raw Ed25519 public key (32 bytes) |
| `key_type` | Key algorithm, always `"ed25519"` |
| `nonce` | The other peer's nonce (echoed back) |

The signature is found by scanning the envelope's `included` map for a `system/signature` entity where `data.target` equals the authenticate entity's content hash. See ENTITY-CORE-PROTOCOL.md §4.6 for the full connection sequence.

### 9.4 system/protocol/execute

Universal operation request. Dispatched to handlers by path.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/execute",
    "fields": {
      "request_id": {"type_ref": "primitive/string"},
      "uri":        {"type_ref": "system/tree/path"},
      "operation":  {"type_ref": "primitive/string"},
      "resource":   {"type_ref": "system/protocol/resource-target", "optional": true},
      "params":     {"type_ref": "primitive/any"},
      "bounds":     {"type_ref": "system/bounds", "optional": true},
      "deliver_to": {"type_ref": "system/delivery-spec", "optional": true},
      "author":     {"type_ref": "system/hash", "optional": true},
      "capability": {"type_ref": "system/hash", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `request_id` | Unique identifier for request/response correlation |
| `uri` | Target entity URI — handler routing address |
| `operation` | Operation to perform (e.g., `"get"`, `"put"`, `"validate"`) |
| `resource` | Resource target scope — `{targets, exclude}` checked against grant `resources` at dispatch (optional) |
| `params` | Operation-specific parameters |
| `bounds` | Resource bounds for the request (optional) |
| `deliver_to` | Delivery spec for async result delivery (optional) |
| `author` | Hash of requester's identity entity |
| `capability` | Hash of capability token authorizing the operation |

When `resource` is present, the dispatcher performs full scope checking against `grant.resources` before handler dispatch — the effective target scope (targets minus caller excludes) must fit within the effective grant scope (includes minus grant excludes). All four grant dimensions (handler, operation, peer, resource) are verified at dispatch. When absent, resource authorization is deferred to the handler. See `system/protocol/resource-target` (§9.4a) for the type definition.

All referenced entities MUST be in the envelope's `included` map. The signature is found via target-matching — scan `included` for `system/signature` where `data.target` equals the EXECUTE's content hash. ENTITY-CORE-PROTOCOL.md §3.2 requires `author`, `capability`, and a valid signature for authenticated requests.

### 9.4a system/protocol/resource-target

Resource target scope for EXECUTE requests. Identifies the data paths being accessed.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/resource-target",
    "fields": {
      "targets": {"array_of": {"type_ref": "system/tree/path"}},
      "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `targets` | Array of paths or patterns this operation accesses. MUST contain at least one entry. Patterns (trailing `*`) permitted for bulk operations. Peer-namespaced, canonicalized by dispatcher. |
| `exclude` | Paths or patterns to skip within the target scope (optional). For pattern targets, caller excludes are part of the dispatch authorization check — if the grant excludes paths overlapping a target pattern, the caller MUST exclude them for the request to pass. |

Different from `system/capability/path-scope` (`{include, exclude}`) by design: grant scope expresses authorization ("what you may access"), resource target expresses execution intent ("what you're accessing"). Same shape, different semantics. `targets` (not `include`) emphasizes this distinction.

### 9.5 system/protocol/execute/response

Result of an EXECUTE request.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/execute/response",
    "fields": {
      "request_id": {"type_ref": "primitive/string"},
      "status":     {"type_ref": "primitive/uint"},
      "result":     {"type_ref": "primitive/any"}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `request_id` | Correlates to the originating EXECUTE |
| `status` | HTTP-style status code (200, 400, 403, 404, 500) |
| `result` | Operation result or error details |

### 9.6 system/protocol/error

Error entity used as the `result` in EXECUTE_RESPONSE for error status codes. Error codes are scoped per handler — connection errors, tree errors, and domain handler errors each define their own `code` values. The `status` field on EXECUTE_RESPONSE provides the numeric category; `result.data.code` provides the specific error.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/error",
    "fields": {
      "code":    {"type_ref": "primitive/string"},
      "message": {"type_ref": "primitive/string", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `code` | Programmatic error identifier (e.g., `"capability_denied"`, `"parse_error"`) |
| `message` | Human-readable detail (optional) |

### 9.7 system/capability/grant

Used as result type when delivering capabilities.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/grant",
    "fields": {
      "token": {"type_ref": "system/hash"}
    }
  }
}
```

The `token` field is a `system/hash` referencing the capability token entity, which MUST be included in the envelope's `included` map.

### 9.8 system/capability/path-scope

Scope for path-valued grant dimensions (handlers, resources). Values are tree paths, prefixes, or patterns.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/path-scope",
    "fields": {
      "include": {"array_of": {"type_ref": "system/tree/path"}},
      "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}
```

### 9.8a system/capability/id-scope

Scope for identifier-valued grant dimensions (operations, peers). Values are operation names or peer identifiers.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/id-scope",
    "fields": {
      "include": {"array_of": {"type_ref": "primitive/string"}},
      "exclude": {"array_of": {"type_ref": "primitive/string"}, "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `include` | Patterns that authorize access. Uses `matches_pattern` (ENTITY-CORE-PROTOCOL.md §5.4). |
| `exclude` | Patterns that carve out exceptions from `include` (optional). Uses `matches_pattern`. |

Both scope types share the same `{include, exclude}` structure. The `matches_scope` algorithm (ENTITY-CORE-PROTOCOL.md §5.2) accesses these fields structurally and works uniformly across both types.

### 9.9 system/capability/grant-entry

Defines a single grant rule within a capability token. Each grant specifies which handlers can be called, which data paths can be accessed, which operations are authorized, and an optional peer scope.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/grant-entry",
    "fields": {
      "handlers":    {"type_ref": "system/capability/path-scope"},
      "resources":   {"type_ref": "system/capability/path-scope"},
      "operations":  {"type_ref": "system/capability/id-scope"},
      "peers":       {"type_ref": "system/capability/id-scope", "optional": true},
      "constraints": {"type_ref": "primitive/any", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `handlers` | Handler scope — which handlers can be called (e.g., `{include: ["system/tree"]}`). Uses `matches_scope` (ENTITY-CORE-PROTOCOL.md §5.2). |
| `resources` | Data path scope — which paths can be accessed. `exclude` within this scope carves out paths. Applied during path-level checks. Per-grant — excludes on one grant do not affect other grants. |
| `operations` | Operation scope — which operations are authorized (e.g., `{include: ["get"]}`). `{include: ["*"]}` matches any operation. |
| `peers` | Peer scope — which peers the grant applies to (optional). When absent, defaults to local peer only (`{include: [local_peer_id]}` constructed at evaluation time). Peer IDs are explicit — no aliases. |
| `constraints` | Domain-specific constraints interpreted by the handler (optional). No fixed schema — handlers define what keys they understand. The core algorithms do not inspect this field; it is preserved through delegation and available to handlers during authorization. |

### 9.10 system/capability/delegation-caveats

Restrictions on further delegation of a capability.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/delegation-caveats",
    "fields": {
      "no_delegation":        {"type_ref": "primitive/bool", "optional": true},
      "max_delegation_depth": {"type_ref": "primitive/uint", "optional": true},
      "max_delegation_ttl":   {"type_ref": "primitive/uint", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `no_delegation` | If `true`, the capability cannot be delegated further |
| `max_delegation_depth` | Maximum chain depth from this capability |
| `max_delegation_ttl` | Maximum lifetime (ms) for delegated capabilities |

Unknown fields in `delegation_caveats` follow open type semantics (ENTITY-CORE-PROTOCOL.md §2.7) — they are preserved, not rejected.

### 9.11 system/capability/token

Defines the permissions granted to a peer. All references use `system/hash` fields. The signature is found via target-matching in the envelope.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/token",
    "fields": {
      "grants":             {"array_of": {"type_ref": "system/capability/grant-entry"}},
      "granter":            {"type_ref": "system/hash"},
      "grantee":            {"type_ref": "system/hash"},
      "parent":             {"type_ref": "system/hash", "optional": true},
      "created_at":         {"type_ref": "primitive/uint"},
      "expires_at":         {"type_ref": "primitive/uint", "optional": true},
      "not_before":         {"type_ref": "primitive/uint", "optional": true},
      "delegation_caveats": {"type_ref": "system/capability/delegation-caveats", "optional": true},
      "resource_limits":    {"type_ref": "system/resource-limits", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `grants` | Array of `system/capability/grant-entry` (each with `handlers`, `resources`, `operations` scopes, optional `peers` scope and `constraints`) |
| `granter` | Hash of granter's identity entity |
| `grantee` | Hash of grantee's identity entity |
| `parent` | Hash of parent capability for delegation chains (absent for root capabilities) |
| `created_at` | Creation timestamp (ms since epoch) |
| `expires_at` | Expiration timestamp (ms); absent = no expiry |
| `not_before` | Valid-from timestamp (ms); absent = immediate |
| `delegation_caveats` | Delegation restrictions (see `system/capability/delegation-caveats`) |
| `resource_limits` | Operation constraints (optional) |

The capability signature is found via target-matching — scan `included` for `system/signature` where `data.target` equals the capability's content hash and `data.signer` equals `granter`. See ENTITY-CORE-PROTOCOL.md §3.6.

### 9.12 system/capability/request

Params type for the capability handler `request` operation.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/request",
    "fields": {
      "grants":  {"array_of": {"type_ref": "system/capability/grant-entry"}},
      "ttl_ms":  {"type_ref": "primitive/uint", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `grants` | Requested scope — the peer asks for this; the handler decides what to actually grant |
| `ttl_ms` | Requested lifetime in milliseconds (optional) |

### 9.13 system/capability/revocation

Params type for the capability handler `revoke` operation.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/capability/revocation",
    "fields": {
      "token":  {"type_ref": "system/hash"},
      "reason": {"type_ref": "primitive/string", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `token` | Content hash of the capability token to revoke |
| `reason` | Human-readable reason for revocation (optional) |

---

## 10. Supporting Types

### 10.1 system/peer

Represents a peer's cryptographic identity. (Renamed from `system/identity` in v7.40; the entity type is `system/peer`. The `system/identity/...` namespace is owned by EXTENSION-IDENTITY, a separate handler extension.)

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/peer",
    "fields": {
      "peer_id":    {"type_ref": "system/peer-id"},
      "public_key": {"type_ref": "primitive/bytes"},
      "key_type":   {"type_ref": "primitive/string"}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `peer_id` | Base58-encoded peer identifier (derived from public key) |
| `public_key` | Raw public key bytes (32 bytes for Ed25519) |
| `key_type` | Key algorithm (e.g., `"ed25519"`). See ENTITY-CORE-PROTOCOL.md §1.5 for identity model. |

### 10.2 system/signature

Proves authorship or approval of an entity. Signatures point TO the content they sign (target-matching model).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/signature",
    "fields": {
      "target":    {"type_ref": "system/hash"},
      "signer":    {"type_ref": "system/hash"},
      "algorithm": {"type_ref": "primitive/string"},
      "signature": {"type_ref": "primitive/bytes"}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `target` | Content hash of the signed entity |
| `signer` | Hash of signer's identity entity |
| `algorithm` | Signature algorithm (e.g., `"ed25519"`). See ENTITY-CORE-PROTOCOL.md §3.5 for signature model. |
| `signature` | Raw signature bytes |

The signature is computed over the target entity's content hash digest bytes. See ENTITY-CORE-PROTOCOL.md §7.3.

### 10.3 system/handler

Describes a registered handler's capabilities. Handlers are dispatched by longest-prefix matching on the URI path (see ENTITY-CORE-PROTOCOL.md §6.6).

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/handler",
    "fields": {
      "pattern":    {"type_ref": "system/tree/path"},
      "name":       {"type_ref": "primitive/string"},
      "operations": {"map_of": {"type_ref": "system/handler/operation-spec"}},
      "max_scope":  {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": true},
      "internal_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `pattern` | Path pattern this handler matches (e.g., `"system/*"`, `"*"`) |
| `name` | Human-readable handler name |
| `operations` | Map of operation name → `system/handler/operation-spec` (e.g., `{"get": {...}, "put": {...}}`) |
| `max_scope` | Maximum tree access for this handler, regardless of request capability. When present and view trees are implemented, effective scope is the intersection of request capability grants and max_scope. Absent = unscoped. System handlers SHOULD NOT set max_scope. |
| `internal_scope` | Declares the handler's internal needs (e.g., tree paths for reading type definitions, handler configuration). Used by the handlers handler (ENTITY-CORE-PROTOCOL.md §6.2) to construct the handler's grant during registration. Informational and transparent to the operator — it tells the operator what the handler needs, not what it gets. |

### 10.4 system/handler/operation-spec

Describes the input and output types for a handler operation.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/handler/operation-spec",
    "fields": {
      "input_type":  {"type_ref": "system/type/name", "optional": true},
      "output_type": {"type_ref": "system/type/name", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `input_type` | Expected type name for params entity (optional) |
| `output_type` | Expected type name for result entity (optional) |

### 10.5 system/handler/interface

External-facing handler description for peer discovery. Contains the handler's pattern, name, and operations — the information a connecting peer needs to construct capability requests. Does not include `max_scope` or `internal_scope`, which are operator-facing security configuration that MUST NOT be exposed to connecting peers.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/handler/interface",
    "fields": {
      "pattern":    {"type_ref": "system/tree/path"},
      "name":       {"type_ref": "primitive/string"},
      "operations": {"map_of": {"type_ref": "system/handler/operation-spec"}}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `pattern` | Handler pattern path (matches the handler's canonical location) |
| `name` | Human-readable handler name |
| `operations` | Map of operation name → `system/handler/operation-spec` |

The `pattern` field identifies which handler this describes. By convention, it matches the handler's canonical location in the tree. Connecting peers use it to construct capability requests. The handlers handler derives interface entities from full manifests during registration and stores them at `system/handler/{pattern}` (§6.2 of the core protocol).

### 10.6 system/bounds

Resource bounds for request processing. Controls traversal depth and resource consumption.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/bounds",
    "fields": {
      "ttl":      {"type_ref": "primitive/uint", "optional": true},
      "budget":   {"type_ref": "primitive/uint", "optional": true},
      "chain_id": {"type_ref": "primitive/string", "optional": true},
      "visited":  {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `ttl` | Hops remaining (decremented at each forwarding peer) |
| `budget` | Work units remaining (decremented by handler processing) |
| `chain_id` | Correlation identifier for distributed request tracing |
| `visited` | URIs visited during request processing (cycle detection) |

### 10.7 system/delivery-spec

Specifies a delivery target for asynchronous result delivery.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/delivery-spec",
    "fields": {
      "uri":       {"type_ref": "system/tree/path"},
      "operation": {"type_ref": "primitive/string", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `uri` | Target URI for delivery |
| `operation` | Operation to invoke on the delivery target (optional, defaults to `"receive"`) |

### 10.8 system/resource-limits

Constraints on resource consumption for capability tokens.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/resource-limits",
    "fields": {
      "max_budget":         {"type_ref": "primitive/uint", "optional": true},
      "max_ttl":            {"type_ref": "primitive/uint", "optional": true},
      "max_visited_length": {"type_ref": "primitive/uint", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `max_budget` | Maximum budget value allowed in requests |
| `max_ttl` | Maximum TTL value allowed in requests |
| `max_visited_length` | Maximum length of the visited list |

### 10.9 Tree Types

These types define the request and response structures for tree operations.

#### 10.9.1 system/tree/listing-entry

Describes a single entry in a tree listing response.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/tree/listing-entry",
    "fields": {
      "hash":         {"type_ref": "system/hash", "optional": true},
      "has_children": {"type_ref": "primitive/bool"}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `hash` | Content hash of the entity at this path. Absent if no entity is bound (path is a prefix only). |
| `has_children` | Whether sub-paths exist under this entry |

#### 10.9.2 system/tree/listing

Response type for tree listing requests. Over EXECUTE, a listing is requested by a trailing-slash path; over static HTTP (EXTENSION-NETWORK.md §6.5.3.1) it is the named `{path}{tree_listing_suffix}` object.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/tree/listing",
    "fields": {
      "path":      {"type_ref": "system/tree/path"},
      "entries":   {"map_of": {"type_ref": "system/tree/listing-entry"}},
      "count":     {"type_ref": "primitive/uint"},
      "offset":    {"type_ref": "primitive/uint"},
      "next_page": {"type_ref": "system/hash", "optional": true}
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `path` | The prefix path that was listed |
| `entries` | Map of entry name → `system/tree/listing-entry` |
| `count` | Total entries under prefix, in-scope filtered (may exceed returned entries if paginated) |
| `offset` | Offset of first returned entry |
| `next_page` | Optional. Content hash of the next listing page (`system/tree/listing`); absent on the last/only page. Static-HTTP pagination, EXTENSION-NETWORK.md §6.5.3.1. |

#### 10.9.3 system/tree/get-request

Request params for tree get operations.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/tree/get-request",
    "fields": {
      "tree_id": {"type_ref": "primitive/string", "optional": true},
      "mode":    {"type_ref": "primitive/string", "optional": true},
      "limit":   {"type_ref": "primitive/uint", "optional": true},
      "offset":  {"type_ref": "primitive/uint", "optional": true}
    }
  }
}
```

The target path is carried by `execute.resource`, not params. Trailing `/` or empty string on `resource` returns listing; otherwise returns entity at path.

| Field | Description |
|-------|-------------|
| `tree_id` | Target tree identifier (optional; default tree if absent) |
| `mode` | `"entity"` (default) or `"hash"` — whether to return full entity or just hash. Ignored for listings. |
| `limit` | Maximum entries to return for listings. Default: implementation-defined. |
| `offset` | Skip this many entries for listings. Default: 0. Entries ordered lexicographically by path segment. |

#### 10.9.4 system/tree/put-request

Request params for tree put operations.

```cbor
{
  "type": "system/type",
  "data": {
    "name": "system/tree/put-request",
    "fields": {
      "entity":  {"type_ref": "primitive/any", "optional": true},
      "tree_id": {"type_ref": "primitive/string", "optional": true}
    }
  }
}
```

The target path is carried by `execute.resource`, not params.

| Field | Description |
|-------|-------------|
| `entity` | Entity to store and bind at path. Absent or null: remove binding at path. |
| `tree_id` | Target tree identifier (optional; default tree if absent) |

---

## 11. Type Registration

### 11.1 Registration Path Convention

Type entities are stored in the entity tree at:

```
system/type/{type_path}
```

The `type_path` is the value of the type entity's `name` field. For example:

| Type Path | Tree Location |
|-----------|--------------|
| `primitive/string` | `system/type/primitive/string` |
| `system/type` | `system/type/system/type` |
| `system/protocol/connect/hello` | `system/type/system/protocol/connect/hello` |
| `core/entity` | `system/type/core/entity` |

When resolving a type reference, implementations prepend `system/type/` to the short type path to form the tree lookup path.

### 11.2 Startup Registration

At startup, implementations MUST populate the entity tree with:

1. All 14 bootstrap types (§4.4) at `system/type/*`
2. Core entity types (§8) at `system/type/*`
3. Protocol types for supported message types (§9) at `system/type/*`
4. Supporting types (§10) at `system/type/*`

These entities MUST be stored as regular entities at their registration paths, with valid content hashes.

### 11.3 Dynamic Registration

Implementations MAY support registering additional types at runtime via `put` operations to `system/type/*` paths. Dynamically registered types:
- MUST conform to the `system/type` structure
- MUST have valid content hashes
- SHOULD be validated (extends chains resolved, structural fields verified) before registration

### 11.4 Type Discovery

Type entities are stored in the entity tree at `system/type/*` paths. Two handlers provide access:

1. **Data access** uses the tree handler (ENTITY-CORE-PROTOCOL.md §6.3). The target path is carried by `execute.resource`. The tree handler is the universal data accessor for reading and writing entities in the tree.
2. **Domain operations** use the types handler (ENTITY-CORE-PROTOCOL.md §6.2). The types handler provides the `validate` operation for entity validation against type definitions. The type extension (EXTENSION-TYPE.md) adds further operations (compare, converge, compatible, adopt, reconcile).

**Read a type definition** (tree handler):

```
EXECUTE system/tree  operation: "get"
  resource: {targets: ["system/type/primitive/string"]}
  params: {type: "system/tree/get-request", data: {}}

→ Returns: {type: "system/type", data: {name: "primitive/string", ...}, content_hash: ...}
```

**List types under a prefix** (tree handler, trailing `/` on target triggers listing):

```
EXECUTE system/tree  operation: "get"
  resource: {targets: ["system/type/"]}
  params: {type: "system/tree/get-request", data: {}}

→ Returns: {type: "system/tree/listing", data: {path: "system/type/", entries: {...}, count: ..., offset: ...}}
```

**Validate an entity against a type** (types handler):

```
EXECUTE system/type  operation: "validate"
  resource: {targets: ["system/type/app/user"]}
  params: {type: "system/type/validate-request", data: {
    entity: {type: "app/user", data: {name: "Alice"}, content_hash: ...},
    type_name: "app/user"
  }}

→ Returns: {type: "system/type/validate-result", data: {valid: true}}
```

**Browse type prefixes** (tree handler):

```
; List primitive types
EXECUTE system/tree  operation: "get"
  resource: {targets: ["system/type/primitive/"]}
  params: {type: "system/tree/get-request", data: {}}

; List system types
EXECUTE system/tree  operation: "get"
  resource: {targets: ["system/type/system/"]}
  params: {type: "system/tree/get-request", data: {}}
```

**Capability requirements:** Data access requires a grant on handler `system/tree` with resources `system/type/*` — the initial capability (§4.4 of the core protocol) provides this. Domain operations require a grant on handler `system/type` with the requested operation (e.g., `validate`). Both follow the two-level authorization model (handler scope + path/operation scope).

This enables peers to discover each other's type registries for interoperability assessment. Type resolution is performed locally on fetched type entities. Validation can be performed locally or via the types handler's `validate` operation.

---

## 12. Structural Compatibility

### 12.1 The Problem

Two implementations may define the same logical type differently:
- Implementation A defines a flat type with all fields inline
- Implementation B defines the same type using `extends` for composition

These definitions have different content hashes but expand to the same effective structure.

### 12.2 Compatibility Determination

Two types are structurally compatible if their resolved effective definitions (§6.1) have the same fields with the same type references. To determine compatibility:

```
structurally_compatible(type_a, type_b):
  resolved_a = resolve(type_a)
  resolved_b = resolve(type_b)

  ; Compare fields
  if resolved_a.fields != resolved_b.fields: return false

  ; Constraints do not affect structural compatibility
  return true
```

Structural compatibility means the same entity data is valid for both types. Constraint differences may mean one type accepts entities the other rejects, but the structural shape is identical.

### 12.3 Content Hash vs Structural Identity

| Relationship | Implication |
|-------------|-------------|
| Same content hash | Identical type definitions (same structure, same encoding) |
| Different hash, structurally compatible | Same effective fields after resolution |
| Different hash, different structure | Different types |

Same content hash implies structural compatibility, but structural compatibility does not imply same content hash. Implementations SHOULD use content hashes for exact matching and structural comparison for interoperability assessment.

---

## 13. Schema Generation

### 13.1 CDDL Generation

Type definitions can be used to generate CDDL schemas (RFC 8610) for validation tooling. The generated CDDL SHOULD follow the ECF-CDDL format defined in ENTITY-CBOR-ENCODING.md §7.5.

**Mapping from type system to CDDL:**

| Type System Construct | CDDL Output |
|-----------------------|-------------|
| `{"type_ref": "primitive/string"}` | `tstr` |
| `{"type_ref": "primitive/bytes"}` | `bstr` |
| `{"type_ref": "primitive/uint"}` | `uint` |
| `{"type_ref": "primitive/int"}` | `int` |
| `{"type_ref": "primitive/float"}` | `float` |
| `{"type_ref": "primitive/bool"}` | `bool` |
| `{"type_ref": "primitive/null"}` | `null` |
| `{"type_ref": "primitive/any"}` | `any` |
| `{"array_of": {"type_ref": "T"}}` | `[* T]` |
| `{"map_of": {"type_ref": "T"}}` | `{* tstr => T}` (default string keys) |
| `{"map_of": {"type_ref": "T"}, "key_type": "system/hash"}` | `{* bstr => T}` |
| `{"...", "optional": true}` | `? field: type` |

### 13.2 Operations

Schema generation MAY be implemented as a handler operation:

```
EXECUTE system/type/{type_path}
  operation: "generate-schema"
  params: {"format": "cddl"}
```

This is an OPTIONAL extension. The type system is usable without schema generation support.

---

## 14. Implementation Requirements

### 14.1 Conformance Levels

Four conformance levels enable incremental adoption:

| Level | Name | Scope | Description |
|-------|------|-------|-------------|
| 0 | Unaware | Core protocol | Peer does not emit or consume type entities. Core protocol only. |
| 1 | Aware | Core type system | Peer populates type entities in tree; supports type discovery via GET. |
| 2 | Validating | Core type system | Peer resolves types, validates entities structurally against type definitions. |
| 2+ | Constrained | Type extension | Level 2 + constraint validation. Requires type extension (EXTENSION-TYPE.md). |

Level 0 peers are fully functional protocol participants. Level 2 peers perform structural validation — field presence, field types, union matching. The type system is an overlay that adds discoverability and validation without breaking existing behavior. Constraint validation (value ranges, patterns, enumerations) is provided by the type extension at Level 2+.

### 14.2 Level 1 Requirements

Level 1 implementations MUST:
1. Populate `system/type/*` with bootstrap types at startup
2. Populate `system/type/*` with protocol and supporting types at startup
3. Support GET with trailing slash on `system/type/` for type discovery
4. Include valid content hashes on all type entities

Level 1 implementations are NOT required to validate entities against types or resolve extends chains.

### 14.3 Level 2 Requirements

Level 2 implementations MUST, in addition to Level 1:
1. Implement the type resolution algorithm (§6) with cycle detection
2. Implement the structural validation algorithm (§7) — field presence and field type checking
3. Detect and reject circular extends chains
4. Validate the exactly-one-of invariant on field-specs (§4.2) — five-way: `type_ref | array_of | map_of | union_of | type_param`
5. Implement `validate_union` (§7.3.1) for `union_of` field-specs
6. Handle `default` values on field-specs: absent fields with defaults are valid (§7.2)
7. Validate default values against their field-spec at type registration time
8. Implement `resolve_generic` (§6.6) for generic type parameter substitution

Level 2 implementations SHOULD:
1. Cache resolved type definitions (§6.5)
2. Report all validation errors, not just the first
3. Detect kinded discrimination for union optimization (§7.3.1)

### 14.4 Level 2+ Requirements (Type Extension)

Level 2+ implementations install the type extension (EXTENSION-TYPE.md) and additionally:
1. Implement constraint validation via the constraint handler dispatch model
2. Enforce constraint narrowing rules during type registration
3. Support the standard constraint handler (`system/type/constraint`) with all 12 constraint fields

---

## 15. Security Considerations

### 15.1 Type Confusion Attacks

Since the content hash covers `{type, data}`, altering the `type` field invalidates the hash. Implementations MUST validate the content hash (ENTITY-CORE-PROTOCOL.md §1.8) BEFORE performing type validation. This ensures the type field has not been tampered with. Type validation then operates on hash-verified content.

### 15.2 Constraint Bypass via Unknown Fields

Open types (§2.4) preserve unknown fields. An attacker could include fields not defined in the type to influence handler behavior. Handlers MUST validate only known fields from the type definition and SHOULD ignore unknown fields for security-sensitive decisions.

### 15.3 Denial of Service

Deeply nested extends chains or recursive type references could cause excessive computation. Implementations SHOULD limit resolution depth to a RECOMMENDED maximum of 64 levels. Implementations MUST detect cycles (§6.2) to prevent infinite loops.

---

## Appendix A: Bootstrap Type Test Vectors

Each bootstrap type is shown in CBOR diagnostic notation as a complete entity. Implementations MUST produce matching content hashes for these definitions.

### A.1 Primitive Types

All primitive type entities share the same structure, differing only in `name`:

```cbor
; primitive/string
{
  "type": "system/type",
  "data": {"name": "primitive/string"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/bytes
{
  "type": "system/type",
  "data": {"name": "primitive/bytes"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/uint
{
  "type": "system/type",
  "data": {"name": "primitive/uint"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/int
{
  "type": "system/type",
  "data": {"name": "primitive/int"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/float
{
  "type": "system/type",
  "data": {"name": "primitive/float"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/bool
{
  "type": "system/type",
  "data": {"name": "primitive/bool"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/null
{
  "type": "system/type",
  "data": {"name": "primitive/null"},
  "content_hash": "ecfv1-sha256:<computed>"
}

; primitive/any
{
  "type": "system/type",
  "data": {"name": "primitive/any"},
  "content_hash": "ecfv1-sha256:<computed>"
}
```

**ECF data encoding for all primitives:**

Each primitive's data is `{"name": "<path>"}`. The ECF encoding is a single-entry CBOR map with key `"name"` and text string value.

```
; ECF of {"name": "primitive/string"}:
; A1 (map, 1 pair) 64 6E616D65 ("name") 70 7072696D69746976652F737472696E67 ("primitive/string")
```

### A.2 Meta-Types

```cbor
; system/type (the meta-type - defines itself)
{
  "type": "system/type",
  "data": {
    "name": "system/type",
    "fields": {
      "name":        {"type_ref": "system/type/name"},
      "extends":     {"type_ref": "system/type/name", "optional": true},
      "fields":      {"map_of": {"type_ref": "system/type/field-spec"}, "optional": true},
      "layout":      {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "type_params": {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "type_args":   {"map_of": {"type_ref": "system/type/name"}, "optional": true}
    }
  },
  "content_hash": h'00...'
}

; system/type/field-spec
{
  "type": "system/type",
  "data": {
    "name": "system/type/field-spec",
    "fields": {
      "type_ref":   {"type_ref": "system/type/name", "optional": true},
      "optional":   {"type_ref": "primitive/bool", "optional": true},
      "array_of":   {"type_ref": "system/type/field-spec", "optional": true},
      "map_of":     {"type_ref": "system/type/field-spec", "optional": true},
      "union_of":   {"array_of": {"type_ref": "system/type/field-spec"}, "optional": true},
      "type_param": {"type_ref": "primitive/string", "optional": true},
      "type_args":  {"map_of": {"type_ref": "system/type/name"}, "optional": true},
      "default":    {"type_ref": "primitive/any", "optional": true},
      "key_type":   {"type_ref": "system/type/name", "optional": true},
      "byte_size":  {"type_ref": "primitive/uint", "optional": true}
    }
  },
  "content_hash": h'00...'
}

; system/type/constraint — moved to type extension (EXTENSION-TYPE.md), no longer a bootstrap type

; system/hash
{
  "type": "system/type",
  "data": {
    "name": "system/hash",
    "extends": "primitive/bytes",
    "fields": {
      "format_code": {"type_ref": "primitive/uint", "byte_size": 1},
      "digest":      {"type_ref": "primitive/bytes"}
    },
    "layout": ["format_code", "digest"]
  },
  "content_hash": h'00...'
}

; system/tree/path
{
  "type": "system/type",
  "data": {
    "name": "system/tree/path",
    "extends": "primitive/string"
  },
  "content_hash": h'00...'
}

; system/type/name
{
  "type": "system/type",
  "data": {
    "name": "system/type/name",
    "extends": "primitive/string"
  },
  "content_hash": h'00...'
}

; system/identity/peer-id
{
  "type": "system/type",
  "data": {
    "name": "system/identity/peer-id",
    "extends": "primitive/string"
  },
  "content_hash": h'00...'
}
```

Content hashes marked `<computed>` MUST be calculated by each implementation using ECF encoding of `{type, data}` and SHA-256 hashing per ENTITY-CBOR-ENCODING.md §4.2. Reference implementations SHOULD publish the exact hash values.

---

## Appendix B: Protocol Type Definitions

Complete protocol and supporting type definitions in CBOR diagnostic notation. These supplement §9 and §10 with a consolidated reference.

```cbor
; --- Core Entity Types ---

; entity (bare — structural root; content_hash derived per ECF, not declared)
{
  "type": "system/type",
  "data": {
    "name": "entity",
    "fields": {
      "type": {"type_ref": "primitive/string"},
      "data": {"type_ref": "primitive/any"}
    }
  }
}

; core/entity (materialized form — used as type_ref marker for "this slot holds a real entity")
{
  "type": "system/type",
  "data": {
    "name": "core/entity",
    "fields": {
      "type":         {"type_ref": "primitive/string"},
      "data":         {"type_ref": "primitive/any"},
      "content_hash": {"type_ref": "system/hash"}
    }
  }
}

; Entity references are system/hash values in data fields.

; core/envelope
{
  "type": "system/type",
  "data": {
    "name": "core/envelope",
    "fields": {
      "root":     {"type_ref": "primitive/any"},
      "included": {"map_of": {"type_ref": "primitive/any"}, "key_type": "system/hash", "optional": true}
    }
  }
}

; --- Protocol Types ---

; system/protocol/envelope
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/envelope",
    "extends": "core/envelope"
  }
}

; system/protocol/connect/hello
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/connect/hello",
    "fields": {
      "peer_id":      {"type_ref": "system/identity/peer-id"},
      "nonce":        {"type_ref": "primitive/bytes"},
      "protocols":    {"array_of": {"type_ref": "primitive/string"}},
      "timestamp":    {"type_ref": "primitive/uint"},
      "hash_formats": {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "key_types":    {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "compression":  {"array_of": {"type_ref": "primitive/string"}, "optional": true},
      "encryption":   {"array_of": {"type_ref": "primitive/string"}, "optional": true}
    }
  }
}

; system/protocol/connect/authenticate (signature via target-matching in envelope)
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/connect/authenticate",
    "fields": {
      "peer_id":    {"type_ref": "system/identity/peer-id"},
      "public_key": {"type_ref": "primitive/bytes"},
      "key_type":   {"type_ref": "primitive/string"},
      "nonce":      {"type_ref": "primitive/bytes"}
    }
  }
}

; system/protocol/resource-target (execution target scope for EXECUTE requests)
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/resource-target",
    "fields": {
      "targets": {"array_of": {"type_ref": "system/tree/path"}},
      "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}

; system/protocol/execute (author and capability are system/hash in data)
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/execute",
    "fields": {
      "request_id": {"type_ref": "primitive/string"},
      "uri":        {"type_ref": "system/tree/path"},
      "operation":  {"type_ref": "primitive/string"},
      "resource":   {"type_ref": "system/protocol/resource-target", "optional": true},
      "params":     {"type_ref": "primitive/any"},
      "bounds":     {"type_ref": "system/bounds", "optional": true},
      "deliver_to": {"type_ref": "system/delivery-spec", "optional": true},
      "author":     {"type_ref": "system/hash", "optional": true},
      "capability": {"type_ref": "system/hash", "optional": true}
    }
  }
}

; system/protocol/execute/response
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/execute/response",
    "fields": {
      "request_id": {"type_ref": "primitive/string"},
      "status":     {"type_ref": "primitive/uint"},
      "result":     {"type_ref": "primitive/any"}
    }
  }
}

; system/protocol/error
{
  "type": "system/type",
  "data": {
    "name": "system/protocol/error",
    "fields": {
      "code":    {"type_ref": "primitive/string"},
      "message": {"type_ref": "primitive/string", "optional": true}
    }
  }
}

; --- Capability Types ---

; system/capability/grant
{
  "type": "system/type",
  "data": {
    "name": "system/capability/grant",
    "fields": {
      "token": {"type_ref": "system/hash"}
    }
  }
}

; system/capability/path-scope
{
  "type": "system/type",
  "data": {
    "name": "system/capability/path-scope",
    "fields": {
      "include": {"array_of": {"type_ref": "system/tree/path"}},
      "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}

; system/capability/id-scope
{
  "type": "system/type",
  "data": {
    "name": "system/capability/id-scope",
    "fields": {
      "include": {"array_of": {"type_ref": "primitive/string"}},
      "exclude": {"array_of": {"type_ref": "primitive/string"}, "optional": true}
    }
  }
}

; system/capability/grant-entry
{
  "type": "system/type",
  "data": {
    "name": "system/capability/grant-entry",
    "fields": {
      "handlers":    {"type_ref": "system/capability/path-scope"},
      "resources":   {"type_ref": "system/capability/path-scope"},
      "operations":  {"type_ref": "system/capability/id-scope"},
      "peers":       {"type_ref": "system/capability/id-scope", "optional": true},
      "constraints": {"type_ref": "primitive/any", "optional": true}
    }
  }
}

; system/capability/delegation-caveats
{
  "type": "system/type",
  "data": {
    "name": "system/capability/delegation-caveats",
    "fields": {
      "no_delegation":        {"type_ref": "primitive/bool", "optional": true},
      "max_delegation_depth": {"type_ref": "primitive/uint", "optional": true},
      "max_delegation_ttl":   {"type_ref": "primitive/uint", "optional": true}
    }
  }
}

; system/capability/token
{
  "type": "system/type",
  "data": {
    "name": "system/capability/token",
    "fields": {
      "grants":             {"array_of": {"type_ref": "system/capability/grant-entry"}},
      "granter":            {"type_ref": "system/hash"},
      "grantee":            {"type_ref": "system/hash"},
      "parent":             {"type_ref": "system/hash", "optional": true},
      "created_at":         {"type_ref": "primitive/uint"},
      "expires_at":         {"type_ref": "primitive/uint", "optional": true},
      "not_before":         {"type_ref": "primitive/uint", "optional": true},
      "delegation_caveats": {"type_ref": "system/capability/delegation-caveats", "optional": true},
      "resource_limits":    {"type_ref": "system/resource-limits", "optional": true}
    }
  }
}

; --- Supporting Types ---

; system/peer
{
  "type": "system/type",
  "data": {
    "name": "system/peer",
    "fields": {
      "peer_id":    {"type_ref": "system/peer-id"},
      "public_key": {"type_ref": "primitive/bytes"},
      "key_type":   {"type_ref": "primitive/string"}
    }
  }
}

; system/signature (target-matching model)
{
  "type": "system/type",
  "data": {
    "name": "system/signature",
    "fields": {
      "target":    {"type_ref": "system/hash"},
      "signer":    {"type_ref": "system/hash"},
      "algorithm": {"type_ref": "primitive/string"},
      "signature": {"type_ref": "primitive/bytes"}
    }
  }
}

; system/handler
{
  "type": "system/type",
  "data": {
    "name": "system/handler",
    "fields": {
      "pattern":        {"type_ref": "system/tree/path"},
      "name":           {"type_ref": "primitive/string"},
      "operations":     {"map_of": {"type_ref": "system/handler/operation-spec"}},
      "max_scope":      {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": true},
      "internal_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": true}
    }
  }
}

; system/handler/operation-spec
{
  "type": "system/type",
  "data": {
    "name": "system/handler/operation-spec",
    "fields": {
      "input_type":  {"type_ref": "system/type/name", "optional": true},
      "output_type": {"type_ref": "system/type/name", "optional": true}
    }
  }
}

; system/handler/interface
{
  "type": "system/type",
  "data": {
    "name": "system/handler/interface",
    "fields": {
      "pattern":    {"type_ref": "system/tree/path"},
      "name":       {"type_ref": "primitive/string"},
      "operations": {"map_of": {"type_ref": "system/handler/operation-spec"}}
    }
  }
}

; system/bounds
{
  "type": "system/type",
  "data": {
    "name": "system/bounds",
    "fields": {
      "ttl":      {"type_ref": "primitive/uint", "optional": true},
      "budget":   {"type_ref": "primitive/uint", "optional": true},
      "chain_id": {"type_ref": "primitive/string", "optional": true},
      "visited":  {"array_of": {"type_ref": "system/tree/path"}, "optional": true}
    }
  }
}

; system/delivery-spec
{
  "type": "system/type",
  "data": {
    "name": "system/delivery-spec",
    "fields": {
      "uri":       {"type_ref": "system/tree/path"},
      "operation": {"type_ref": "primitive/string", "optional": true}
    }
  }
}

; system/resource-limits
{
  "type": "system/type",
  "data": {
    "name": "system/resource-limits",
    "fields": {
      "max_budget":         {"type_ref": "primitive/uint", "optional": true},
      "max_ttl":            {"type_ref": "primitive/uint", "optional": true},
      "max_visited_length": {"type_ref": "primitive/uint", "optional": true}
    }
  }
}

; --- Tree Types ---

; system/tree/listing-entry
{
  "type": "system/type",
  "data": {
    "name": "system/tree/listing-entry",
    "fields": {
      "hash":         {"type_ref": "system/hash", "optional": true},
      "has_children": {"type_ref": "primitive/bool"}
    }
  }
}

; system/tree/listing
{
  "type": "system/type",
  "data": {
    "name": "system/tree/listing",
    "fields": {
      "path":      {"type_ref": "system/tree/path"},
      "entries":   {"map_of": {"type_ref": "system/tree/listing-entry"}},
      "count":     {"type_ref": "primitive/uint"},
      "offset":    {"type_ref": "primitive/uint"},
      "next_page": {"type_ref": "system/hash", "optional": true}
    }
  }
}

; system/tree/get-request (target path carried by execute.resource, not params)
{
  "type": "system/type",
  "data": {
    "name": "system/tree/get-request",
    "fields": {
      "tree_id": {"type_ref": "primitive/string", "optional": true},
      "mode":    {"type_ref": "primitive/string", "optional": true},
      "limit":   {"type_ref": "primitive/uint", "optional": true},
      "offset":  {"type_ref": "primitive/uint", "optional": true}
    }
  }
}

; system/tree/put-request (target path carried by execute.resource, not params)
{
  "type": "system/type",
  "data": {
    "name": "system/tree/put-request",
    "fields": {
      "entity":  {"type_ref": "primitive/any", "optional": true},
      "tree_id": {"type_ref": "primitive/string", "optional": true}
    }
  }
}

; --- Types Handler Types ---

; system/type/validate-request
{
  "type": "system/type",
  "data": {
    "name": "system/type/validate-request",
    "fields": {
      "entity":    {"type_ref": "core/entity"},
      "type_name": {"type_ref": "system/type/name"}
    }
  }
}

; system/type/validate-result
{
  "type": "system/type",
  "data": {
    "name": "system/type/validate-result",
    "fields": {
      "valid":  {"type_ref": "primitive/bool"},
      "errors": {"array_of": {"type_ref": "primitive/string"}, "optional": true}
    }
  }
}
```

---

## Appendix C: Validation Test Cases

### C.1 Valid Entities

```cbor
; Valid system/protocol/connect/hello entity
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "nonce": "dGVzdG5vbmNl",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000
  }
}
; Expected: VALID (all required fields present, correct types)

; Valid hello with optional hash_formats
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "nonce": "dGVzdG5vbmNl",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000,
    "hash_formats": ["ecfv1-sha256", "ecfv1-blake3"]
  }
}
; Expected: VALID (optional field present)

; Valid hello with unknown field (open type)
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "nonce": "dGVzdG5vbmNl",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000,
    "future_field": "some_value"
  }
}
; Expected: VALID (unknown fields preserved, not rejected)
```

### C.2 Invalid Entities

```cbor
; Missing required field (nonce absent)
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000
  }
}
; Expected: INVALID ("Missing required field: nonce")

; Wrong type for field (timestamp is string, expected uint)
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "nonce": "dGVzdG5vbmNl",
    "protocols": ["entity-core/1.0"],
    "timestamp": "1737900000000"
  }
}
; Expected: INVALID ("timestamp: expected uint, got string")

; Wrong type for field (protocols is string, expected array)
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFB3QwX7nM...",
    "nonce": "dGVzdG5vbmNl",
    "protocols": "entity-core/1.0",
    "timestamp": 1737900000000
  }
}
; Expected: INVALID ("protocols: expected array, got string")
```

### C.3 Constraint Validation

```cbor
; system/protocol/envelope with valid root type
{
  "type": "system/protocol/envelope",
  "data": {
    "root": {
      "type": "system/protocol/connect/hello",
      "data": {"peer_id": "...", "nonce": "...", "protocols": ["entity-core/1.0"], "timestamp": 0}
    },
    "included": {}
  }
}
; Expected: VALID (root type matches "system/*")

; system/protocol/envelope with invalid root type
{
  "type": "system/protocol/envelope",
  "data": {
    "root": {
      "type": "content/blob",
      "data": {"content": h'DEADBEEF'}
    },
    "included": {}
  }
}
; Expected: INVALID ("root: type content/blob does not match pattern system/*")
```

### C.4 Field-Spec Invariant Violations

```cbor
; Invalid field-spec: no type_ref, array_of, or map_of
{"optional": true}
; Expected: INVALID ("field-spec must contain exactly one of type_ref, array_of, map_of, union_of, type_param")

; Invalid field-spec: both type_ref and array_of present
{"type_ref": "primitive/string", "array_of": {"type_ref": "primitive/string"}}
; Expected: INVALID ("field-spec must contain exactly one of type_ref, array_of, map_of, union_of, type_param")
```

---

## Appendix D: References

### Normative References

- **ENTITY-CORE-PROTOCOL.md** - Entity Core Protocol Specification
- **ENTITY-CBOR-ENCODING.md** - Entity CBOR Encoding Specification (ECF, wire format, content hashing)
- **RFC 2119** - Key words for use in RFCs to Indicate Requirement Levels
  https://www.rfc-editor.org/rfc/rfc2119.html
- **RFC 8949** - Concise Binary Object Representation (CBOR)
  https://www.rfc-editor.org/rfc/rfc8949.html
- **RFC 8610** - Concise Data Definition Language (CDDL)
  https://www.rfc-editor.org/rfc/rfc8610.html

### Informative References

- **ENTITY-NATIVE-TYPES.md** - Exploratory proposal for entity-native types (superseded by this document)
- **TYPE-SYSTEM-COMPARATIVE-ANALYSIS.md** - Analysis of type systems in Rust, Haskell, TypeScript, Go, Scala, and Python
