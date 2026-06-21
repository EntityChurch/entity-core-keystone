--  Entity_Core.Errors — the exception hierarchy (profile [error_model]).
--
--  Ada's idiomatic error mechanism is the exception, with one user-defined
--  exception per failure class. Codec-decode failures raise Codec_Error
--  subtypes; crypto failures raise Crypto_Error subtypes. (Ada has no
--  exception inheritance, so the "hierarchy" in profile.toml is conceptual —
--  here it is a flat set of distinct exceptions, grouped by comment. The
--  dispatcher boundary at S3 maps each to a protocol status code.)
--
--  Codec_Error / its kin map to 400 non_canonical_ecf at the S3 boundary.

package Entity_Core.Errors is

   --  Codec (decode-side) failures — 400 non_canonical_ecf.
   Codec_Error           : exception;   -- generic codec failure
   Non_Canonical_Ecf     : exception;   -- indefinite/reserved length, non-minimal, etc.
   Truncated_Input       : exception;   -- ran off the end of the input
   Tag_Rejected          : exception;   -- a CBOR major-type-6 tag (N2)
   Duplicate_Key         : exception;   -- duplicate map key after canonical sort (Rule 5)
   Trailing_Bytes        : exception;   -- bytes left over after a top-level item

   --  Crypto failures.
   Crypto_Error          : exception;
   Bad_Seed              : exception;
   Unsupported_Key_Type  : exception;
   Unsupported_Hash_Type : exception;

   --  Protocol (peer-layer, S3) failures. Each maps to a status code at the
   --  dispatcher boundary (profile [error_model]):
   --    Authentication_Error    -> 401
   --    Authorization_Error     -> 403
   --    Chain_Depth_Exceeded    -> 400 chain_depth_exceeded (§4.10; structural)
   --    Payload_Too_Large       -> 413 payload_too_large (§4.10; length-prefix)
   Protocol_Error           : exception;
   Authentication_Error     : exception;
   Authorization_Error      : exception;
   Unresolvable_Grantee     : exception;   -- §5.5 carve-out: 401, not 403
   Chain_Depth_Exceeded     : exception;
   Payload_Too_Large        : exception;

   --  Transport (L4) failures — §6.12 per-request codes live at the dispatcher.
   Transport_Error          : exception;

end Entity_Core.Errors;
