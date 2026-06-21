# Entity CBOR Encoding Specification

**Version**: 1.5
**Status**: Active

This specification defines the encoding format for the Entity Core Protocol. All compliant implementations MUST follow this specification to ensure interoperability.

**The normative conformance contract for this specification is `Appendix E: Conformance Test Vectors`.** An implementation of ECF is conformant iff it produces the required canonical bytes (and rejects the required non-canonical bytes) for every vector in the current published version of the appendix's fixture file. The body of this spec defines *what* canonical ECF is; Appendix E is *how* conformance is verified.

---

> **Path notation.** Paths in this document use peer-relative notation (without leading `/{peer_id}/`). All peer-relative paths resolve to the local peer's namespace: `system/tree` means `/{local_peer_id}/system/tree`. Every path in the entity tree is absolute at rest — rooted at a peer identity. See ENTITY-CORE-PROTOCOL.md §1.4 for the path model. Cross-peer examples use absolute paths with explicit peer identities.

## 1. Introduction

### 1.1 Purpose

This document specifies:
- The wire format for Entity Protocol messages
- The canonical encoding for content-addressable hashing
- The type-to-CBOR encoding mapping (how entity types map to CBOR data items)
- The type system for Entity data structures
- Requirements for deterministic serialization

### 1.2 Scope

This specification covers encoding only. Message semantics, authentication, capabilities, and protocol flow are defined in ENTITY-CORE-PROTOCOL.md.

### 1.3 Terminology

| Term | Definition |
|------|------------|
| CBOR | Concise Binary Object Representation (RFC 8949) |
| ECF | Entity Canonical Form - the deterministic encoding used for hashing |
| CDDL | Concise Data Definition Language (RFC 8610) |
| Diagnostic notation | Human-readable CBOR representation (RFC 8949 §8) |

### 1.4 Notation

- **MUST**, **MUST NOT**, **SHOULD**, **MAY** per RFC 2119
- Byte sequences shown as hex: `A2 64 74797065`
- CDDL used for type definitions
- Diagnostic notation used for examples

---

## 2. Why CBOR

Entity Core uses CBOR (RFC 8949) as its encoding format for three reasons:

### 2.1 Type Preservation

JSON has a single "number" type that maps to IEEE 754 float64, limiting integer precision to 53 bits. CBOR has distinct types:

| CBOR Type | Range | JSON Equivalent |
|-----------|-------|-----------------|
| Unsigned integer | 0 to 2^64-1 | Number (lossy > 2^53) |
| Negative integer | -1 to -2^64 | Number (lossy) |
| Float16/32/64 | IEEE 754 | Number |
| Byte string | Any bytes | String (base64 encoded) |
| Text string | UTF-8 | String |

### 2.2 Deterministic Encoding

RFC 8949 Section 4.2 defines deterministic encoding rules. Given the same semantic data, all conformant encoders produce identical bytes. This is essential for content-addressable hashing.

### 2.3 Self-Describing Format

CBOR encodes type information in the wire format. A decoder can parse any CBOR without a schema, enabling:
- Forwarding of unknown entity types
- Generic debugging tools
- Schema evolution

---

## 3. CBOR Fundamentals

This section provides the CBOR knowledge required to implement Entity Core. For complete details, see RFC 8949.

### 3.1 Major Types

CBOR data items begin with an initial byte encoding the major type (3 bits) and additional information (5 bits):

```
+---+---+---+---+---+---+---+---+
| Major |    Additional info    |
+---+---+---+---+---+---+---+---+
  7   6   5   4   3   2   1   0
```

| Major Type | Meaning | Additional Info |
|------------|---------|-----------------|
| 0 | Unsigned integer | Value or length indicator |
| 1 | Negative integer | Value is -1 minus the encoded number |
| 2 | Byte string | Length in bytes |
| 3 | Text string | Length in bytes (UTF-8) |
| 4 | Array | Number of items |
| 5 | Map | Number of key-value pairs |
| 6 | Tag | Tag number (see §6) |
| 7 | Simple/float | Special values and floats |

### 3.2 Integer Encoding

Integers encode in the minimal number of bytes:

| Value Range | Encoding | Example |
|-------------|----------|---------|
| 0-23 | Single byte (value in additional info) | `17` → `11` |
| 24-255 | 2 bytes (24 + 1 byte value) | `100` → `18 64` |
| 256-65535 | 3 bytes (25 + 2 byte value) | `1000` → `19 03E8` |
| 65536-2^32-1 | 5 bytes (26 + 4 byte value) | `1000000` → `1A 000F4240` |
| 2^32-2^64-1 | 9 bytes (27 + 8 byte value) | Large values |

Negative integers use major type 1 with value = -1 - n:
- `-1` → `20` (major type 1, additional info 0)
- `-100` → `38 63` (major type 1, additional info 24, value 99)

### 3.3 Strings

**Byte strings** (major type 2): Raw binary data
```
44 DEADBEEF     # 4-byte string containing 0xDEADBEEF
```

**Text strings** (major type 3): UTF-8 encoded text
```
65 68656C6C6F   # 5-byte text string "hello"
```

### 3.4 Arrays and Maps

**Arrays** (major type 4): Ordered sequences
```
83              # Array of 3 items
   01           # 1
   02           # 2
   03           # 3
```

**Maps** (major type 5): Key-value pairs
```
A2              # Map with 2 pairs
   63 666F6F    # Key: "foo"
   01           # Value: 1
   63 626172    # Key: "bar"
   02           # Value: 2
```

### 3.5 Simple Values

Major type 7 encodes special values:

| Byte | Value |
|------|-------|
| `F4` | false |
| `F5` | true |
| `F6` | null |
| `F7` | undefined (SHOULD NOT use) |

### 3.6 Floating Point

Major type 7 also encodes IEEE 754 floats:

| Prefix | Precision | Size |
|--------|-----------|------|
| `F9` | Half (16-bit) | 3 bytes |
| `FA` | Single (32-bit) | 5 bytes |
| `FB` | Double (64-bit) | 9 bytes |

Example: `1.5` as half-precision → `F9 3E00`

---

## 4. Entity Canonical Form (ECF)

ECF is the deterministic encoding used for computing content hashes. All implementations MUST produce identical ECF bytes for semantically identical data.

### 4.1 Canonical Encoding Rules

Per RFC 8949 Section 4.2, with Entity-specific clarifications:

**Rule 1: Minimal integer encoding**
```
MUST:  01        # Value 1
WRONG: 18 01     # Value 1 with unnecessary length byte
```

**Rule 2: Map keys sorted by encoded length, then lexicographically**
```
Input:  {"bb": 1, "a": 2, "ccc": 3}

Sorted by encoded key bytes:
  "a"   → 61 61       (2 bytes)
  "bb"  → 62 6262     (3 bytes)
  "ccc" → 63 636363   (4 bytes)

ECF: A3 6161 02 626262 01 63636363 03
```

**Rule 3: Definite lengths only**
```
MUST:  83 01 02 03           # Array(3) with items
WRONG: 9F 01 02 03 FF        # Indefinite array with break
```

**Rule 4: Shortest float encoding preserving value**
```
1.0  → F9 3C00     # Half-precision (3 bytes)
1.1  → FB 3FF199...# Double required for precision (9 bytes)
```

**Rule 4a: Canonical float special values**

Special values MUST use these exact bytes (all have float16 as shortest encoding per RFC 8949 §4.2):

| Value | Encoding | Hex Bytes |
|-------|----------|-----------|
| NaN | float16, canonical quiet NaN | `F9 7E00` |
| -0.0 | float16, negative zero | `F9 8000` |
| +Infinity | float16 | `F9 7C00` |
| -Infinity | float16 | `F9 FC00` |

Implementations MUST encode these values as specified. No implementation choices to diverge on.

**Rule 5: No duplicate map keys**

Duplicate keys are encoding errors. Implementations MUST reject them.

**Rule 6: All field values preserved — no omissions**

All fields present in the logical data MUST be encoded. Implementations MUST NOT omit fields (e.g., dropping null-valued or default-valued fields). If a field exists in the data, it appears in the encoding.

### 4.2 Content Hash Computation

The content hash identifies an entity by its data payload. It is a function of TWO components:

1. **Encoding format** - How content is serialized (ECF)
2. **Hash algorithm** - How bytes are hashed (SHA-256)

```
content_hash = hash_algorithm(encoding_format({type, data}))
```

For the current protocol version:
```
content_hash = SHA-256(ECF({type, data}))
```

**What is hashed:**
- `type`: Entity type string
- `data`: Entity data payload

**What is NOT hashed:**
- `content_hash`: The hash itself (it is computed from `{type, data}`)

**Design rationale**: Hashing `{type, data}` ensures that entities with different types always have different hashes, even if their data is identical. This eliminates ambiguity in the content store (a hash uniquely identifies a typed entity) and aligns the content hash with signature computation (both use the same `{type, data}` input). Content deduplication across types is achieved through the type system's composition mechanism (see ENTITY-NATIVE-TYPE-SYSTEM.md §5).

**Example:**

```
Entity:
  type: "system/protocol/connect/hello"
  data: {
    peer_id: "2KZF...",
    timestamp: 1737900000000,
    protocols: ["entity-core/1.0"],
    nonce: "abc123"
  }

ECF encoding of {type, data} (diagnostic notation):
{
  "data": {
    "nonce": "abc123",
    "peer_id": "2KZF...",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000
  },
  "type": "system/protocol/connect/hello"
}

Note: Keys sorted by encoded byte length, then lexicographically.

Hash: SHA-256(ecf_bytes) → "ecfv1-sha256:9f2c..."
```

### 4.3 Hash Format Registry

Content hashes encode BOTH the encoding format and hash algorithm. This enables protocol evolution without breaking existing content.

**Format Registry:**

| Code | Name | Encoding | Algorithm | Digest Size | Status |
|------|------|----------|-----------|-------------|--------|
| 0x00 | ecfv1-sha256 | ECF v1 | SHA-256 | 32 bytes | **Active (Required)** |
| 0x01 | ecfv1-sha384 | ECF v1 | SHA-384 | 48 bytes | Reserved |
| 0x02 | ecfv1-sha512 | ECF v1 | SHA-512 | 64 bytes | Reserved |
| 0x03 | ecfv1-sha3-256 | ECF v1 | SHA3-256 | 32 bytes | Reserved |
| 0x04 | ecfv1-blake3 | ECF v1 | BLAKE3 | 32 bytes | Reserved |
| 0x10-0x1F | ecf2-* | ECF v2 | varies | varies | Reserved (future encoding) |
| 0xFE | (private) | varies | varies | varies | Application-specific |
| 0xFF | (extension) | - | - | - | Future expansion |

**Format code semantics:**
- Codes 0x00-0x0F: ECF v1 with various hash algorithms
- Codes 0x10-0x1F: Reserved for ECF v2 (if encoding rules ever change)
- Code 0xFE: Private use for application-specific formats
- Code 0xFF: Reserved for extension mechanism if >254 formats needed

### 4.4 Hash String Representation

**Canonical form (explicit):**
```
ecfv1-sha256:7a3b9c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
└────┬────┘ └────────────────────────────┬───────────────────────────────────┘
   Format                            Hex digest (64 chars = 32 bytes)
```

**Grammar:**
```
hash        = format-name ":" hex-digest
format-name = "ecfv1-sha256"      ; code 0x00 (required)
            / "ecfv1-sha384"      ; code 0x01 (reserved)
            / "ecfv1-sha512"      ; code 0x02 (reserved)
            / "ecfv1-sha3-256"    ; code 0x03 (reserved)
            / "ecfv1-blake3"      ; code 0x04 (reserved)
hex-digest  = 1*HEXDIG          ; length must match format
```

The `ecfv1-sha256:` prefix explicitly encodes both the canonical encoding format (ECF) and the hash algorithm (SHA-256), enabling future protocol evolution.

### 4.5 Hash Wire Encoding

In CBOR wire format, hashes are encoded as byte strings with a format code prefix:

```
hash-bytes = format-code digest
format-code = OCTET              ; see registry (§4.3)
digest = *OCTET                  ; length determined by format
```

**Example (ecfv1-sha256):**
```cbor
; 33 bytes total: 1 byte code + 32 bytes digest
h'00 7a3b9c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
 │  └──────────────────────────────┬─────────────────────────────────┘
 │                               Digest (32 bytes)
 └── Format code: 0x00 (ecfv1-sha256)
```

**Conversion between string and wire:**
```
string_to_wire("ecfv1-sha256:7a3b9c..."):
  → h'00' + unhex("7a3b9c...")

wire_to_string(h'00 7a3b9c...'):
  → "ecfv1-sha256:" + hex(digest)
```

### 4.6 Format Evolution

The format registry enables protocol evolution:

1. **New hash algorithm:** Add code (e.g., 0x04 for BLAKE3)
2. **New encoding format:** Reserve code range (e.g., 0x10-0x1F for ECF v2)
3. **Peers advertise capabilities:** `hash_formats` field in HELLO
4. **Content remains addressable:** Old hashes continue to work

**Rules for evolution:**
- `ecfv1-sha256` (code 0x00) is REQUIRED for all peers
- Additional formats are OPTIONAL
- Unknown formats SHOULD be preserved when forwarding entities
- Peers MAY index content under multiple formats for interoperability

### 4.7 Format Capability Advertisement

Peers advertise supported hash formats in the HELLO message:

```cddl
hello = {
  peer_id: tstr,
  protocols: [+ tstr],
  timestamp: uint,
  nonce: bstr,                   ; 32 random bytes
  ? hash_formats: [+ tstr],     ; Supported formats, defaults to ["ecfv1-sha256"]
  ? key_types: [+ tstr],        ; Supported key types, defaults to ["ed25519"]
  * tstr => any
}
```

**Example:**
```cbor
{
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZF...",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000,
    "nonce": "dGVzdG5vbmNl...",
    "hash_formats": ["ecfv1-sha256", "ecfv1-blake3"],
    "key_types": ["ed25519"]
  }
}
```

**Interpretation:**
- If `hash_formats` is absent, assume `["ecfv1-sha256"]` only
- If `key_types` is absent, assume `["ed25519"]` only
- Peers SHOULD use mutually supported formats and key types when possible
- Peers MUST always be able to verify `ecfv1-sha256` hashes
- Peers MUST always be able to verify `ed25519` signatures

**Construction-vs-verification asymmetry (normative, v7.73).** The `content_hash` construction path (encoder) serialises whatever `format_code` the caller supplies — it does not gate on the registry. This preserves forward-compatibility: an impl that ships before a new format-code allocation can still serialise and forward the new format if a higher layer (handler, application, future agility codec) supplies the code. The `content_hash` verification path (decoder) MUST reject any unsupported or unallocated `format_code` with `unsupported_content_hash_format` (per this section's "MUST always be able to verify `ecfv1-sha256`" rule and §4.6 format-evolution semantics), since the verifier cannot recompute and check what it cannot interpret. Conformance vectors testing these surfaces — ECF `content_hash.4` (encode-side, exercises caller-supplied format code 128) for construction; agility `VARINT-MULTIBYTE-1` (decode-side, exercises a hash with format `0x80 01`) for verification — are not contradictory; they exercise the two halves of this asymmetry.

---

## 5. Wire Format

### 5.1 Frame Structure

Messages are transmitted as length-prefixed CBOR:

```
+------------------+------------------+
| Length (4 bytes) | CBOR Payload     |
| Big-endian u32   | (Length bytes)   |
+------------------+------------------+
```

Maximum message size SHOULD be 16 MiB (16,777,216 bytes)

### 5.2 Message Encoding

All protocol messages are CBOR-encoded using deterministic encoding (RFC 8949 §4.2). Senders MUST use deterministic encoding. Receivers MUST validate content hashes by re-encoding to ECF and computing the hash - never trust a claimed hash without verification.

### 5.3 Envelope Structure

Messages are wrapped in envelopes:

```
envelope = {
  "root": entity,
  "included": { hash-bytes => entity, ... }  ; optional, keyed by content hash
}

entity = {
  "type": text,
  "data": any,
  "content_hash": hash-bytes                  ; 33 bytes (see §4.5)
}

hash-bytes = bytes                            ; format-code (1 byte) + digest (32 bytes)
```

**Wire format details:**
- `content_hash`: CBOR byte string, 33 bytes (format code 0x00 + 32-byte SHA-256 digest)
- `included` keys: CBOR byte strings (same format as content_hash)
- See §4.5 for hash wire encoding specification

---

## 6. CBOR Tags

Tags add semantic meaning to data items without changing the underlying value.

### 6.1 Tag Structure

A tag is an integer (0 to 2^64-1) preceding a data item:

```
Tag number + Data item
```

Example - epoch timestamp:
```
C1                    # Tag 1 (epoch time)
1B 00000194A5B76A00   # Unsigned integer
```

### 6.2 Standard Tags

Entity Core recognizes these IANA-registered tags:

| Tag | Meaning | Data Item | Use in Entity Core |
|-----|---------|-----------|-------------------|
| 0 | Date/time string | tstr | ISO 8601 timestamps |
| 1 | Epoch timestamp | int/float | Unix timestamps |
| 2 | Positive bignum | bstr | Integers > 2^64 |
| 3 | Negative bignum | bstr | Integers < -2^64 |
| 32 | URI | tstr | Entity URIs |
| 37 | Binary UUID | bstr(16) | Request IDs, stream IDs |
| 55799 | Self-describe CBOR | any | File magic bytes |

### 6.3 Tag Handling Rules (Option B — reject on receive)

Entity Core protocol messages MUST NOT use CBOR tags on data fields, and conformant implementations MUST reject any received frame containing CBOR tags on data fields with `400 non_canonical_ecf`. Field semantics are defined by the type system (see `ENTITY-NATIVE-TYPE-SYSTEM.md`), not by CBOR tags.

**Why tags are excluded.** Tagged and untagged values produce different ECF bytes and different content hashes. Entity Core relies on deterministic hashing for integrity, so tag usage must be uniform. The uniform rule is: tags are not part of ECF.

**Encoding (normative).** Implementations MUST NOT emit CBOR tags on data fields in protocol messages.

**Decoding (normative).** Implementations MUST reject any received protocol frame containing a CBOR tag on a data field. Rejection returns `400 non_canonical_ecf`. Detection is at decode time: any CBOR major-type-6 item encountered in a data-field position is a rejection condition. Detection covers any CBOR major-type-6 item appearing anywhere within an entity's `data` field at any nesting depth (top-level, inside nested arrays/maps, inside `included` entities' data fields, etc.). The envelope and entity-wrapper CBOR shapes are fixed maps and contain no positions where a tag could legally be placed; any tag encountered in those structures is a structurally invalid frame rejected by ordinary decoder validation. Implementations MUST NOT silently strip tags, MUST NOT preserve them through forwarding, and MUST NOT attempt to interpret them.

**Exception (file storage only).** Tag 55799 (self-describing CBOR) MAY be used as a file format marker per §6.4 but MUST NOT appear in wire protocol messages.

**Internal divergence (informative).** An implementation whose internal architecture uses tags for legitimate reasons (an in-network extension, a custom representation, a vendor-specific use case) is conformant at the boundary as long as it strips tags before egress to other peers and conforms to the canonical ECF contract on the wire. The boundary is where conformance is required; internal architecture is the implementer's choice. See `ENTITY-CORE-PROTOCOL.md` §1.11 ("Boundary Conformance and Internal Divergence") for the general principle.

**Forward-compatibility for tags.** If a future ECF feature ever requires CBOR tags, the spec amends this section to whitelist the specific tags with their canonical form and conformance vectors. The current MUST-reject is universal; future tag-using features come via deliberate spec amendment, *not* via silent preservation. (This is a different layer from `ENTITY-CORE-MACHINE-SPEC.md §1.8` step 5, which addresses unknown *map-key fields* — field-level forward-compat — rather than unknown CBOR major types.)

Conformance test vectors for tag rejection live in `Appendix E` under the `tag_reject` category.

### 6.4 Tag 55799: Self-Describing CBOR

When storing CBOR to files, prefix with tag 55799:

```
D9 D9F7 <CBOR data>
```

This identifies the file as CBOR (similar to PNG magic bytes). Do NOT use for wire protocol messages.

---

## 7. Type System

Entity data types are defined using CDDL (RFC 8610).

### 7.1 Primitive Types

```cddl
; Boolean
bool = true / false

; Integers
uint = uint .size 8        ; 0 to 2^64-1
int = int .size 8          ; -2^63 to 2^63-1
uint32 = uint .size 4      ; 0 to 2^32-1

; Floating point
float32 = float .size 4    ; IEEE 754 single
float64 = float .size 8    ; IEEE 754 double

; Strings
tstr                       ; UTF-8 text
bstr                       ; Binary bytes

; Null
null
```

### 7.2 Compound Types

```cddl
; Homogeneous array
[* element-type]           ; Zero or more
[+ element-type]           ; One or more
[? element-type]           ; Zero or one

; Map with string keys
{ * tstr => any }          ; Any string keys

; Specific structure
{
  required-field: type,
  ? optional-field: type,
  * tstr => any            ; Additional properties allowed
}
```

### 7.3 Entity Core Types

```
; Content hash - see §4.5 for wire encoding
hash-bytes = bytes              ; Wire format: format-code (1 byte) + digest (32 bytes)
hash-string = text              ; Display format: "ecfv1-sha256:<64 hex chars>" (for logs/UI only)

; Entity URI
entity-uri = text               ; Format: "entity://<peer-id>/<path>"

; Timestamp (milliseconds since Unix epoch)
timestamp = uint

; Peer identifier (base58-encoded public key hash)
peer-id = text
```

**Important:** On the wire, hashes are ALWAYS `hash-bytes` (CBOR byte string). The string format `hash-string` is for display, logging, and debugging only - never transmitted on the wire.

### 7.4 Open Types

All Entity structures allow additional properties:

```cddl
my-type = {
  known-field: tstr,
  * tstr => any            ; Unknown fields preserved
}
```

This enables:
- Forward compatibility (new fields ignored by old implementations)
- Application-specific extensions
- Forwarding entities without full schema knowledge

### 7.5 CDDL Canonical Format (ECF-CDDL)

Type definitions stored in `system/type` entities use a canonical CDDL format to ensure deterministic content hashes. This format is called **ECF-CDDL** (Entity Canonical Format CDDL).

#### 7.5.1 Field Ordering

Fields MUST be ordered as follows:
1. **Required fields** - sorted alphabetically by field name
2. **Optional fields** - sorted alphabetically by field name (prefixed with `?`)
3. **Open type marker** - `* tstr => any` always last

This ordering groups required fields together for human readability while maintaining deterministic output.

#### 7.5.2 Spacing and Delimiters

**No spaces inside brackets or braces:**
```cddl
; Correct
[* tstr]
{* tstr => any}

; Incorrect
[ * tstr ]
{ * tstr => any }
```

**Colon after field names with single space before type:**
```cddl
field_name: tstr,
? optional_field: int,
```

#### 7.5.3 Indentation and Structure

- **Two-space indentation** per nesting level
- **Opening brace** `{` on its own line (for multi-field types)
- **Closing brace** `}` on its own line
- **Trailing comma** after each field definition
- **No trailing comma** on the open type marker

**Multi-line format (for type definitions with fields):**
```cddl
{
  required_field: tstr,
  another_required: int,
  ? optional_field: bool,
  * tstr => any
}
```

**Single-line format (for inline types):**
```cddl
{* tstr => any}
[* tstr]
```

#### 7.5.4 Complete Example

Given a type with required fields `name`, `count` and optional fields `description`, `tags`:

```cddl
{
  count: uint,
  name: tstr,
  ? description: tstr,
  ? tags: [* tstr],
  * tstr => any
}
```

Note:
- Required fields `count`, `name` come first (alphabetically)
- Optional fields `description`, `tags` come after (alphabetically, with `?` prefix)
- Open type marker `* tstr => any` is last (no trailing comma)

#### 7.5.5 Type Mappings

| Data Type | ECF-CDDL |
|-----------|----------|
| String | `tstr` |
| Signed integer | `int` |
| Unsigned integer | `uint` |
| Float (64-bit) | `float64` |
| Boolean | `bool` |
| Null | `null` |
| Any value | `any` |
| Array of T | `[* T]` |
| Map of T | `{* tstr => T}` (default string keys) |
| Union of A, B | `A / B` |
| Open object | `{* tstr => any}` |

### 7.6 Type-to-Encoding Mapping

This section is the single source of truth for how entity types defined in ENTITY-NATIVE-TYPE-SYSTEM.md map to CBOR data items. The type system defines types semantically (what they represent); this section defines their encoding (how they serialize to CBOR).

#### 7.6.1 Primitive Type Mapping

| Type | CBOR Encoding | CDDL |
|------|---------------|------|
| `primitive/string` | Major type 3 (text string), UTF-8 | `tstr` |
| `primitive/bytes` | Major type 2 (byte string) | `bstr` |
| `primitive/uint` | Major type 0 (unsigned integer) | `uint` |
| `primitive/int` | Major type 0 or 1 (unsigned or negative) | `int` |
| `primitive/float` | Major type 7, float16/float32/float64 | `float` |
| `primitive/bool` | Major type 7, simple values true (`0xF5`) / false (`0xF4`) | `bool` |
| `primitive/null` | Major type 7, simple value null (`0xF6`) | `null` |
| `primitive/any` | Any valid CBOR data item | `any` |

When validating a value against a primitive type, implementations MUST check the CBOR major type. Type checking is strict: integer types reject floats, and float types reject integers. `primitive/int` accepts both unsigned integers (major type 0) and negative integers (major type 1). `primitive/float` accepts IEEE 754 half-, single-, and double-precision floats.

#### 7.6.2 Compound Type Mapping

| Pattern | CBOR Encoding |
|---------|---------------|
| Structured type (fields, no primitive `extends`) | CBOR map, string keys, sorted per ECF |
| Constrained primitive (`extends` primitive + constraints) | Same as extended primitive |
| Structured primitive (`extends` primitive + fields) | Same as extended primitive |
| `array_of` | CBOR array |
| `map_of` | CBOR map, key type per field-spec |
| `union_of` | Whichever CBOR encoding the matched variant uses |

**The encoding rule:** `extends` determines encoding. If a type extends a primitive, it encodes as that primitive, regardless of whether it has fields or constraints. Types with no `extends` (or extending a structured type) encode as CBOR maps.

**`union_of` encoding:** A `union_of` field-spec lists variant field-specs. The CBOR encoding is the encoding of whichever variant the value matches. There is no discriminator tag — the value simply IS the CBOR encoding of the matched variant type. Validation tries each variant in order; the first match wins (ENTITY-NATIVE-TYPE-SYSTEM.md §7.3.1).

**`default` and encoding:** The `default` field on a field-spec does NOT affect encoding or hashing. Absent optional fields remain absent in CBOR (key not present in map). Defaults are applied at the processing layer, not the encoding layer. An entity with an absent field and one with the default value explicitly present are structurally distinct and produce different content hashes.

**`type_param` and encoding:** The `type_param` field-spec is resolved to a concrete `type_ref` before validation and encoding. It does not appear in wire data. See ENTITY-NATIVE-TYPE-SYSTEM.md §6.6 for resolution.

See ENTITY-NATIVE-TYPE-SYSTEM.md §5.5 for detailed documentation of the three type patterns (structured types, constrained primitives, structured primitives).

---

## 8. Diagnostic Notation

CBOR diagnostic notation (RFC 8949 §8) provides human-readable representation.

### 8.1 Syntax

| CBOR Type | Diagnostic |
|-----------|------------|
| Unsigned int | `42` |
| Negative int | `-1` |
| Byte string | `h'DEADBEEF'` |
| Text string | `"hello"` |
| Array | `[1, 2, 3]` |
| Map | `{"a": 1, "b": 2}` |
| Tag | `1(1737900000000)` |
| False | `false` |
| True | `true` |
| Null | `null` |
| Float | `1.5` |

### 8.2 Examples

**Hello message:**
```
{
  "type": "system/protocol/connect/hello",
  "data": {
    "nonce": h'A1B2C3D4E5F6...',
    "peer_id": "2KZF...",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000
  }
}
```

**With tag (timestamp):**
```
{
  "type": "system/protocol/connect/hello",
  "data": {
    "timestamp": 1(1737900000000)
  }
}
```

### 8.3 Converting to/from JSON

For debugging, CBOR can be displayed as JSON with conventions:

| CBOR | JSON Display |
|------|--------------|
| Byte string | `{"$bytes": "<base64>"}` |
| Tag n(value) | `{"$tag": n, "value": <value>}` |
| Large uint (>2^53) | `{"$uint": "<decimal string>"}` |

This is for display only, not wire format.

---

## 9. Implementation Requirements

### 9.1 Encoder Requirements

Encoders MUST:
1. Use deterministic encoding (RFC 8949 §4.2)
2. Sort map keys by encoded byte length, then lexicographically
3. Use minimal integer encoding
4. Use definite-length encoding only
5. Reject duplicate map keys

### 9.2 Decoder Requirements

Decoders MUST:
1. Accept any valid CBOR (not just deterministic)
2. Preserve unknown tags
3. Preserve additional map properties
4. Reject duplicate map keys
5. Validate UTF-8 in text strings

### 9.3 Hash Requirements

Hash computation MUST:
1. Extract the `type` and `data` fields
2. Re-encode `{type, data}` to ECF (deterministic CBOR)
3. Hash the ECF bytes (SHA-256 for format code 0x00)
4. Format string as `ecfv1-sha256:<64 hex lowercase>`
5. Wire encode as `0x00` + 32-byte digest

**Hash validation:** Receivers MUST always verify claimed hashes by recomputing them. The claimed hash is untrusted until validated against the actual content.

**Type handling:** The `type` field is included in the content hash. Entities with different types always have different hashes. Type validation is the receiver's responsibility at the application layer (see ENTITY-NATIVE-TYPE-SYSTEM.md).

**Format handling:**
- Implementations MUST support `ecfv1-sha256` (code 0x00)
- Implementations MAY support additional formats from the registry
- Unknown format codes SHOULD be preserved when forwarding

### 9.4 Hash Storage

Content-addressed storage implementations:
- MUST store content once regardless of hash format
- MUST index content by its `ecfv1-sha256` hash (minimum)
- MAY index content by additional hash formats for interoperability
- MUST verify hash matches content before serving

### 9.5 Interoperability Testing

Implementations MUST pass the shared test vector suite (see Appendix A) before deployment.

---

## 10. Security Considerations

### 10.1 Hash Collisions

SHA-256 provides collision resistance. The format registry (§4.3) provides a path for algorithm evolution if weaknesses are discovered, without requiring protocol breaking changes.

### 10.2 Denial of Service

- Maximum message size: 16 MiB
- Maximum nesting depth: 64 levels
- Maximum map keys: 65536

Implementations SHOULD enforce these limits.

### 10.3 Canonicalization Attacks

Always re-encode to ECF before hashing. Never hash received wire bytes directly, as they may be valid but non-canonical.

---

## Appendix A: Test Vectors

Implementations MUST produce identical ECF bytes and hashes for these test cases.

All hashes use format `ecfv1-sha256` (code 0x00).

### A.1 Primitive Values

```
Test: empty_map
Input: {}
ECF hex: A0
Wire hash: 00 c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0
String hash: ecfv1-sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0

Test: empty_entity
Input: {"type": "system/empty", "data": {}}
ECF hex: A2 64 64617461 A0 64 74797065 6C 73797374656D2F656D707479
Wire hash: 00 5f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b
String hash: ecfv1-sha256:5f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b
Note: This is the v1 corpus's `content_hash.1` test — the full-entity content_hash construction
over the minimal {type, data} shape. Differs from `empty_map` above which hashes the bare CBOR
empty map (0xA0). Prior spec revisions (v5/v6/v7 ≤ 1.4) listed `empty_map` with hash
44136fa3… — that value never matched sha256(0xA0); no implementation computed it; superseded
by v1 corpus cross-bless (see Appendix E §E.4).

Test: single_uint
Input: {"value": 42}
ECF hex: A1 65 76616C7565 18 2A
Hash: ecfv1-sha256:...

Test: large_uint
Input: {"value": 9007199254740993}
ECF hex: A1 65 76616C7565 1B 0020000000000001
Hash: ecfv1-sha256:...

Test: negative_int
Input: {"value": -1}
ECF hex: A1 65 76616C7565 20
Hash: ecfv1-sha256:...

Test: boolean_true
Input: {"flag": true}
ECF hex: A1 64 666C6167 F5
Hash: ecfv1-sha256:...

Test: boolean_false
Input: {"flag": false}
ECF hex: A1 64 666C6167 F4
Hash: ecfv1-sha256:...

Test: null_value
Input: {"value": null}
ECF hex: A1 65 76616C7565 F6
Hash: ecfv1-sha256:...

Test: empty_string
Input: {"s": ""}
ECF hex: A1 61 73 60
Hash: ecfv1-sha256:...

Test: unicode_string
Input: {"text": "hello 世界"}
ECF hex: A1 64 74657874 6C 68656C6C6F20E4B896E7958C
Hash: ecfv1-sha256:...

Test: byte_string
Input: {"data": h'DEADBEEF'}
ECF hex: A1 64 64617461 44 DEADBEEF
Hash: ecfv1-sha256:...
```

### A.2 Key Ordering

```
Test: key_ordering
Input: {"z": 1, "a": 2, "bb": 3, "aaa": 4}
Expected order: a, z, bb, aaa (by encoded length, then lexicographic)
ECF hex: A4 6161 02 617A 01 626262 03 63616161 04
Hash: ecfv1-sha256:...
```

### A.3 Nested Structures

```
Test: nested_map
Input: {"outer": {"inner": {"deep": 1}}}
ECF hex: A1 65 6F75746572 A1 65 696E6E6572 A1 64 64656570 01
Hash: ecfv1-sha256:...

Test: array_of_ints
Input: {"arr": [1, 2, 3]}
ECF hex: A1 63 617272 83 01 02 03
Hash: ecfv1-sha256:...
```

### A.4 Entity Hash

```
Test: hello_entity
Input: {
  "type": "system/protocol/connect/hello",
  "data": {
    "peer_id": "2KZFtest",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000,
    "nonce": "testnonce"
  }
}
ECF encoding of {type, data} (keys sorted):
{
  "data": {
    "nonce": "testnonce",
    "peer_id": "2KZFtest",
    "protocols": ["entity-core/1.0"],
    "timestamp": 1737900000000
  },
  "type": "system/protocol/connect/hello"
}

Note: Both `type` and `data` are hashed. Keys sorted by encoded length.
Hash: ecfv1-sha256:...
```

---

## Appendix B: CDDL Prelude

Standard CDDL definitions used in Entity Core schemas:

```cddl
; RFC 8610 standard prelude (excerpt)
any = #
uint = #0
nint = #1
int = uint / nint
bstr = #2
tstr = #3
bytes = bstr
text = tstr
tdate = #6.0(tstr)
time = #6.1(number)
number = int / float
float16 = #7.25
float32 = #7.26
float64 = #7.27
float = float16 / float32 / float64
false = #7.20
true = #7.21
bool = true / false
nil = #7.22
null = nil
undefined = #7.23

; Entity Core extensions

; Hash - ALWAYS bytes on wire (see §4.5)
; Wire format: format-code (1 byte) + digest (32 bytes for SHA-256)
; Display format (logs/UI only): "ecfv1-sha256:<64 hex chars>"
hash = bstr .size (33..65)       ; format-code + digest (wire format)

; String representation for display/debugging (NOT used on wire)
; hash-display = "ecfv1-sha256:" followed by hex digest

entity-uri = tstr
peer-id = tstr
timestamp = uint
```

---

## Appendix C: References

### Normative References

- **RFC 8949** - Concise Binary Object Representation (CBOR)
  https://www.rfc-editor.org/rfc/rfc8949.html

- **RFC 8610** - Concise Data Definition Language (CDDL)
  https://www.rfc-editor.org/rfc/rfc8610.html

- **RFC 2119** - Key words for use in RFCs
  https://www.rfc-editor.org/rfc/rfc2119.html

- **FIPS 180-4** - Secure Hash Standard (SHA-256)
  https://csrc.nist.gov/publications/detail/fips/180/4/final

### Informative References

- **CBOR Playground** - Online encoder/decoder
  https://cbor.me

- **RFC 8742** - CBOR Sequences
  https://www.rfc-editor.org/rfc/rfc8742.html

- **IANA CBOR Tags Registry**
  https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml

---

## Appendix D: IPFS DAG-CBOR Comparison

IPFS's DAG-CBOR codec is the closest existing system to Entity Core's encoding. This appendix documents the similarities, differences, and potential interoperability.

### D.1 Overview

DAG-CBOR is part of IPLD (InterPlanetary Linked Data), the data model layer for IPFS. Both Entity Core and DAG-CBOR chose CBOR for the same reasons: type preservation and deterministic encoding.

### D.2 Specification Comparison

| Aspect | Entity Core ECF | IPFS DAG-CBOR |
|--------|-----------------|---------------|
| Base specification | RFC 8949 | RFC 8949 |
| Determinism | RFC 8949 §4.2 | RFC 8949 §4.2 + additional rules |
| Map key types | Strings only | Strings only |
| Key ordering | Length, then lexicographic | Length, then lexicographic |
| Integer encoding | Minimal bytes | Minimal bytes |
| Length encoding | Definite only | Definite only |

### D.3 Key Differences

**1. Float Encoding**

| System | Rule | Rationale |
|--------|------|-----------|
| Entity Core | Shortest encoding preserving value | Wire efficiency |
| DAG-CBOR | Always 64-bit double | Implementation simplicity |

```
Value 1.5:
  Entity Core: F9 3E00        (3 bytes, half-precision)
  DAG-CBOR:    FB 3FF8000... (9 bytes, double)
```

Entity Core choice rationale: Determinism is maintained because the same value always produces the same shortest encoding. The 64-bit-always rule adds overhead without benefit.

**2. Tag Restrictions**

| System | Allowed Tags | Rationale |
|--------|--------------|-----------|
| Entity Core | All tags preserved | Extensibility |
| DAG-CBOR | Only Tag 42 (CID links) | Simplicity |

Entity Core choice rationale: Preserving unknown tags enables application-specific semantics and future protocol extensions without breaking existing implementations.

**3. Link Representation**

| System | Format | Location |
|--------|--------|----------|
| Entity Core | Flat byte string (format code + digest) | In `data` fields as `system/hash` values |
| DAG-CBOR | Tag 42 + binary CID | Inline anywhere |

**Entity Core:**
```cbor
{
  "type": "example",
  "data": {
    "parent": h'00abc123...'               ; system/hash — flat bstr (33 bytes)
  }
}
```

**DAG-CBOR:**
```cbor
{
  "type": "example",
  "data": {...},
  "parent": 42(h'00017112200abc123...')    ; CID inline
}
```

Entity Core choice rationale: Entity references are `system/hash` byte strings in data fields. Referenced entities are resolved from the envelope's `included` map by content hash. This enables:
- Uniform representation (same bytes everywhere: data fields, content_hash, included keys)
- Envelope-based resolution (all referenced entities travel together)
- Named fields (references are explicit data fields, not inline links)

**4. Hash/CID Format**

| System | Format | Self-Describing |
|--------|--------|-----------------|
| Entity Core | `h'00...'` (format code + digest) | Encoding + algorithm in first byte |
| IPFS | CID (multibase + version + codec + multihash) | Full |

**Entity Core hash (wire — CBOR byte string):**
```
h'007a3b9c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
```

**Entity Core hash (display only, never on wire):**
```
ecfv1-sha256:7a3b9c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
```

**IPFS CID (v1, dag-cbor, sha256):**
```
bafyreihq5qz7b2e3h7o5z3v2c4t6n8m9k1l2j3h4g5f6d7s8a9w0e1r2t3y4
```

Entity Core choice rationale: Single byte string format on wire — no struct, no map, just bytes. The format code (first byte) identifies encoding format and hash algorithm. The string format `ecfv1-sha256:<hex>` is for display/debugging only.

### D.4 Canonical Encoding Comparison

Both systems follow RFC 8949 §4.2 with these shared rules:

1. **Integers**: Minimal byte encoding
2. **Map keys**: Sorted by encoded length, then byte-wise lexicographic
3. **Lengths**: Definite encoding only (no indefinite/streaming)
4. **Duplicates**: No duplicate map keys

**Additional DAG-CBOR rules not in Entity Core:**
- Floats must be 64-bit
- Only Tag 42 allowed
- IEEE 754 special values (NaN, Infinity) forbidden

**Additional Entity Core rules not in DAG-CBOR:**
- Hash computed over `{type, data}` (type is part of identity)
- Entity references are `system/hash` byte strings in `data` fields

### D.5 Interoperability Options

**Option 1: Entity in IPFS (read-only)**

Store Entity content in IPFS as DAG-CBOR:
```cbor
{
  "type": "example/document",
  "data": {
    "title": "Hello",
    "content": "World"
  }
}
```

This produces a valid CID. Entity hash will differ due to:
- Different float encoding (if floats present)
- `system/hash` byte strings translated to Tag 42 CID links

**Option 2: IPFS bridge entities**

Create Entity references to IPFS content:
```json
{
  "type": "bridge/ipfs",
  "data": {
    "cid": "bafyreihq5qz7b2e3h7o5z3v2c4t6n8m9k1l2j3h4g5f6d7s8a9w0e1r2t3y4",
    "codec": "dag-cbor"
  }
}
```

**Option 3: Dual hashing**

Compute both hashes for content that needs IPFS interop:
```json
{
  "type": "content/file",
  "data": {
    "content": "<bytes>",
    "ipfs_cid": "Qm..."
  }
}
```

### D.6 Why Not Adopt DAG-CBOR Exactly?

| DAG-CBOR Rule | Trade-off | Decision |
|---------------|-----------|----------|
| 64-bit floats only | +Simplicity, -Efficiency | Keep shortest encoding |
| Tag 42 only | +Simplicity, -Extensibility | Keep all tags |
| CID format | +IPFS native, -Complexity | Keep flat byte string (format code + digest) |
| Inline links | +Flexibility, -Clarity | Keep typed system/hash byte references |

Entity Core prioritizes:
1. **Efficiency**: Shortest valid encoding
2. **Extensibility**: Preserve unknown tags
3. **Clarity**: Typed entity references in data fields
4. **Simplicity**: Human-readable hash format

### D.7 Conversion Between Formats

**Entity → DAG-CBOR:**
```
1. Extract data from entity
2. Convert system/hash byte strings to Tag 42 CID links
3. Re-encode floats as 64-bit
4. Remove any tags other than 42
5. Encode as DAG-CBOR
```

**DAG-CBOR → Entity:**
```
1. Decode DAG-CBOR
2. Extract Tag 42 links → system/hash byte strings in data fields
3. Keep float encoding as-is
4. Wrap in {type, data} structure
5. Re-encode as ECF for Entity hash
```

Note: Round-trip produces different hashes due to encoding differences.

### D.8 References

- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
- [IPLD Data Model](https://ipld.io/docs/data-model/)
- [CID Specification](https://github.com/multiformats/cid)
- [Multihash](https://multiformats.io/multihash/)
- [Multicodec](https://github.com/multiformats/multicodec)

---

## Appendix E: Conformance Test Vectors (normative)

The normative conformance artifact for this specification. An implementation of ECF is conformant iff it produces the required canonical bytes for every `encode_equal` vector and rejects the required wire bytes for every `decode_reject` vector in the current published version of the fixture file.

This appendix supersedes the illustrative test vectors in Appendix A as the conformance gate. Appendix A's in-line examples remain as documentation; Appendix E is the authoritative artifact.

### E.1 Categories

The appendix covers two scopes:

- **Class A — canonical encoding** (rows below the divider): pure ECF-encoding correctness over arbitrary canonical inputs. The original scope of v1.4.
- **Class B — protocol-surface conformance** (added v1.5): the content-addressing, identity, and envelope-shape surfaces every peer shares. These compose canonical encoding with hash, signature, and envelope rules; they belong here because they are wire-level conformance gates (a divergence here is a peer-interop break, not an internal implementation choice).

| Category | Coverage | Kind |
|---|---|---|
| **`float`** | Rule 4 minimization (f16/f32/f64 boundaries); Rule 4a special floats (NaN, ±Inf, ±0, subnormal min). Initial seed: 14 vectors from Python's W2 verification battery — 4 large-magnitude parametrized + 7 small-magnitude specials + 3 non-f16-representable. The appendix may grow to add explicit subnormal vectors as Python's battery extends. | `encode_equal` |
| **`int`** | Major-type-0/1 minimization at boundaries: 0, 23, 24, 255, 256, 65535, 65536, 2³¹, 2³²-1, 2³², 2⁶³-1, 2⁶³, and signed analogs (-1, -24, -25, -256, …). | `encode_equal` |
| **`map_keys`** | RFC 8949 §4.2.1 deterministic key ordering: pure text keys, pure byte keys, mixed (text + byte) keys, large keys near length-prefix boundaries, identical-prefix keys. | `encode_equal` |
| **`length`** | Definite vs indefinite encoding: arrays/maps/strings/bytes at length boundaries (0, 23, 24, 255, 256, 65535, 65536). Canonical MUST be definite-length; this category confirms the *absence* of indefinite-length output for any canonical input. | `encode_equal` |
| **`primitive`** | bool, null, primitive boundaries; empty containers; mixed-primitive maps. | `encode_equal` |
| **`nested`** | Composite shapes exercising deep nesting + mixed types: entities with `included` maps, hash-keyed maps, the `system/envelope` carrier shape. | `encode_equal` |
| **`tag_reject`** | §6.3 rejection vectors: tags 0, 1, 32, 37 wrapping their canonical data in `data` field positions; tag 55799 in wire frame (the explicitly forbidden case); nested tag inside `included` entity data. | `decode_reject` |
| — Class B — | — | — |
| **`content_hash`** | Construction `varint(format_code) ‖ SHA256(ECF({type, data}))` over a small set of `{type, data}` entities. MUST include the empty-`data` boundary (`{type: "system/empty", data: {}}`) and a multi-field-`data` case spanning the map-key sort rules. The `format_code` varint is the multicodec-style LEB128 (per §1.5); include at least one synthetic `format_code ≥ 0x80` so multi-byte varint encoding is exercised (forward-compat). | `encode_equal` |
| **`peer_id`** | Construction `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` (§1.2 / §7.3). Round-trip vectors over the parse/format surface: parse a known peer-id string, re-format the parsed components, compare to original. MUST include at least one synthetic `key_type ≥ 0x80` value so multi-byte varint encoding in the peer-id prefix is exercised. | `encode_equal` |
| **`signature`** | Deterministic Ed25519 sign/verify over a canonical-ECF-encoded entity. Vectors use fixed deterministic Ed25519 seeds (named in `.diag` as hex literals); Ed25519's RFC 8032 signing is deterministic by construction, so produced signatures are reproducible across impls. Each vector encodes the signed entity, signs the canonical bytes, and verifies; the `canonical` output bytes are the produced signature. | `encode_equal` |
| **`envelope`** | `system/envelope/v1` carrier shape (root + included): vectors construct a small envelope with a signed root and a single included signature entity; `canonical` bytes are the full envelope encoding. Verifies (a) canonical envelope-map encoding under the same map-key rules, (b) by-content-hash lookup of the signature entity referenced from the root. | `encode_equal` |

**Class B vectors compose Class A.** A Class B vector's `canonical` bytes are derived by (i) encoding subordinate values per Class A rules and then (ii) applying the Class B construction (hash / sign / wrap). If a Class A vector fails for an impl, the corresponding Class B vectors that exercise the same subordinate value SHOULD also fail; the categories localize the failure but are not independent of the underlying encoding correctness.

**Scope discipline.** Adding a Class B category is a normative scope extension and follows the same change discipline as adding a Class A category (spec amendment, peer round, cross-bless before publication). Class B exists to make protocol-interop conformance gateable from a single fixture; it does not replace per-extension conformance for non-universal surfaces (e.g. TREE, NETWORK, ROLE).

Initial total: ~120–140 vectors (final count locked at v1 cross-bless).

### E.2 Fixture format

The normative fixture is `conformance-vectors-v{N}.cbor` — a canonical-ECF-encoded CBOR array of vector maps. Each vector map:

```cddl
vector = {
  "id":            tstr,      ; "<category>.<n>" — e.g. "float.7", "tag_reject.1"
  "description":   tstr,      ; one-line semantic
  "kind":          tstr,      ; "encode_equal" | "decode_reject"
  ? "input":       any,       ; REQUIRED iff kind == "encode_equal"; absent for "decode_reject"
  "canonical":     bstr       ; for encode_equal: the required canonical output bytes
                              ; for decode_reject: the wire bytes to feed the decoder
}
```

The `canonical` field carries dual semantics by `kind`:
- **`encode_equal`** — the canonical output the encoder MUST produce when given `input`.
- **`decode_reject`** — the wire-bytes input the decoder MUST reject (typically with `400 non_canonical_ecf` for tag-policy violations; specific error codes per category as documented).

Human-editable source: `conformance-vectors-v{N}.diag` (CBOR diagnostic notation, RFC 8949 §8). Non-normative; a build script generates the binary `.cbor` from the `.diag` source.

**Canonical fixture location** (in-tree): `test-vectors/ecf-conformance/conformance-vectors-v1.cbor` (+ `.diag`).

### E.3 Conformance harness

Each implementation runs:

1. Load `conformance-vectors-v{N}.cbor` via the impl's CBOR decoder. (A decoder bug here is itself a conformance failure — the harness exercises the decoder before any vector test.)
2. For each vector, branch on `kind`:
   - **`encode_equal`** — encode `input` via the impl's canonical ECF encoder; compare bit-for-bit with `canonical`; pass iff byte-identical.
   - **`decode_reject`** — feed `canonical` (wire bytes) to the impl's decoder; pass iff the decoder rejects with the expected error code.
3. Report pass/fail per vector and per category.

### E.4 Cross-impl byte-equality (v1 publication procedure)

`encode_equal` vectors' `canonical` bytes are not produced by any single named impl. **The spec — the canonical-encoding rules in §§3–9 — is the reference.** Every conformant impl produces the same canonical bytes for the same input by virtue of implementing those rules correctly. There is no privileged producer.

**v1 publication procedure.**

1. The architecture team authors the `.diag` source — `id`, `description`, `kind`, and (for `encode_equal`) `input`. The `canonical` field is left unfilled at this stage.
2. Each conformant impl loads the `.diag` (or the `.cbor` build-script output of it), runs every `input` through its canonical ECF encoder, and emits a per-vector `(id, bytes)` pair.
3. The architecture team diffs the emitted bytes across all impls. v1 is locked when every impl produces byte-identical output for every `encode_equal` vector.
4. Any pre-publication divergence is triaged: either an impl bug (fixed in the impl) or a spec ambiguity (fixed in the spec; vector retried). Bytes are not chosen by majority vote — the spec arbitrates.
5. Once locked, the `canonical` field is populated with the converged bytes; the `.cbor` build script regenerates from `.diag`; the fixture is committed at the canonical path.

The cross-impl conformance loop, including the validate-peer-driven harness and the divergence-handling protocol, is described in `GUIDE-CONFORMANCE.md`.

`decode_reject` vectors do not require encoder cross-blessing — their `canonical` field is an intentionally non-canonical wire byte sequence, authored directly by the architecture team and validated only by the rejection behavior each impl's decoder produces.

### E.5 Growth policy

- **Any new spec feature that introduces a new CBOR construct** (a future-whitelisted tag, a big int, a new container) MUST land with corresponding vectors in the same change. No exceptions; this is the conformance-coverage discipline that prevents latent encoder corners from going undetected (the W2 pattern, where cbor2's float16 gap stayed latent for months until the first float-carrying entity exposed it).
- **Any new cross-impl divergence found in production** MUST be reduced to a vector and added to the appendix. The vector is the artifact-of-record; the bug report points at it.
- **The vector set is versioned** with the appendix. Implementations cite which version they pass. New vectors are additive; old vectors don't change.

### E.6 Compliance reporting

Conformance reports MUST cite the version of `conformance-vectors-v{N}.cbor` that the implementation passes. A report of "passes v1" means every vector in `conformance-vectors-v1.cbor` (the set committed to the canonical fixture location at version v1) returns pass under §E.3 semantics.

Implementations choosing the `ENTITY-CORE-MACHINE-SPEC.md §1.8` lossless-parse+canonical-re-encode mechanism MUST additionally verify that round-tripping each `encode_equal` vector's `canonical` bytes through their decoder and re-encoder produces byte-identical output (the §1.8 clause (a) precondition).
