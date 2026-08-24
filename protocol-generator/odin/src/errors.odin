package entity_core

// Codec_Error — the value-return error surface for the whole codec (profile
// [error_model]: no exceptions; a trailing error value; `.None` == success;
// propagate with `or_return`). Protocol-status faults map an error value →
// §5.2a/§6.12 status code at the peer boundary (S3); at S2 these are the ECF /
// content-hash / peer-id / signature faults only.
//
// NEVER panic on protocol-input faults — panic is reserved for true unreachable
// / programmer error. A malformed corpus vector, a non-canonical wire byte, a
// tag on a data field: all return a Codec_Error, never a crash.
Codec_Error :: enum {
	None = 0,
	Truncated,               // ran off the end of the input
	Non_Canonical_Ecf,       // non-minimal argument, indefinite length, reserved info, bad UTF-8, trailing bytes
	Tag_Rejected,            // any CBOR major-type-6 tag (invariant N2 / §6.3)
	Duplicate_Key,           // §4.1 Rule 5 — duplicate map key
	Depth_Exceeded,          // §10.2 nesting limit (64)
	Unsupported_Value,       // encoder asked to emit a value it cannot represent
	Unsupported_Key_Type,    // peer-id key-type outside the registry (peer layer)
	Unsupported_Hash_Format, // content-hash format-code outside the registry (verify side, peer layer)
	Bad_Seed,                // Ed25519 seed not 32 bytes
	Bad_Base58,              // non-alphabet character in a Base58 string
	Bad_Entity,              // {type,data} shape missing a required field
	Content_Hash_Mismatch,   // §1.8 — carried content_hash != recomputed (peer layer)
	Included_Key_Mismatch,   // §3.1 — included map key != entity hash (peer layer)
}
