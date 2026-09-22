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

   --  A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
   --  content_hash is not content_hash({type, data}), or an `included` entry
   --  whose MAP KEY does not bind to the entity filed under it.
   --
   --  A DISTINCT EXCEPTION rather than a Non_Canonical_Ecf with a different
   --  message, because §4.11's classifier has to tell this cause from the
   --  tag-policy one and Ada has no exception inheritance to lean on: the
   --  classifier's `when` arms are the dispatch, so the cause must BE the
   --  exception identity. Matching on Exception_Message would put the code one
   --  string edit away from silently re-collapsing.
   --
   --  §5.2a (0.8.2.24 N4/N5): "A peer that refuses at the decode boundary MUST
   --  answer 400 hash_mismatch [MUST] ... 400 non_canonical_ecf is NOT conformant
   --  here [MUST]." That code is ENTITY-CBOR-ENCODING §6.3's, for a CBOR
   --  tag-policy violation, and a mis-keyed `included` entry carries NO TAG: its
   --  encoding is canonical, what is false is the claim the KEY makes, and the
   --  remedy `non_canonical_ecf` selects (re-encode) sends an honest caller to the
   --  wrong layer. This peer raised Non_Canonical_Ecf for every decode-boundary
   --  refusal until 0.8.2.24 — measured on the wire, arc-probe B1/B2.
   Hash_Mismatch            : exception;

   --  Transport (L4) failures — §6.12 per-request codes live at the dispatcher.
   Transport_Error          : exception;

end Entity_Core.Errors;
