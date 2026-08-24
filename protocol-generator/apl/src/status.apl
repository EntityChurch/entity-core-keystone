⍝ entity-core-protocol-apl — src/status.apl
⍝
⍝ Error model = status-code + signal (profile [error_model]). Every fallible
⍝ codec op returns / sets an EC_*-aligned status the caller tests; the C-ABI
⍝ returns these same int32 codes. The codec-side leaf-reject kinds are
⍝ distinguished negatives that map onto the §400 non_canonical_ecf surface at
⍝ the peer layer (S3). Loaded first (all other modules reference these).
⍝ UPPERCASE constant names per [naming] (A-APL-007).

⍝ ── C-ABI-aligned codes (entitycore_codec.h §6; the numeric values ARE the ABI)
EC_OK←0
EC_INVALID_ARGUMENT←¯1
EC_OUT_OF_SPACE←¯2
EC_DECODE_ERROR←¯3
EC_ENCODE_ERROR←¯4
EC_HASH_MISMATCH←¯5
EC_SIGNATURE_INVALID←¯6
EC_KEY_INVALID←¯7
EC_PEERID_INVALID←¯8
EC_ARENA_EXHAUSTED←¯9
EC_INTERNAL_ERROR←¯99

⍝ ── codec-side leaf reject kinds (EC_*-aligned distinguished negatives) ──
EC_NON_CANONICAL_ECF←¯101
EC_TRUNCATED_INPUT←¯102
EC_TAG_REJECTED←¯103
EC_BAD_SEED←¯104
EC_UNSUPPORTED_CONTENT_HASH_FMT←¯105
EC_UNSUPPORTED_KEY_TYPE←¯106

⍝ ── ECF value-kind discriminant (the explicit major-type intent — A-APL-011).
⍝ APL arrays do NOT carry the CBOR major type; a value is a nested (kind payload)
⍝ pair whose kind makes int-vs-float AND byte-vs-text intent EXPLICIT, never
⍝ inferred from APL storage.
EV_ABSENT←¯1
EV_UINT←0
EV_NINT←1
EV_BYTES←2
EV_TEXT←3
EV_ARRAY←4
EV_MAP←5
EV_FLOAT←7
EV_BOOL←20
EV_NULL←22

MAX_DEPTH←64
