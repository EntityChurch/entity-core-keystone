--  Entity_Core.Codec.Hash — content_hash construction.
--
--  ENTITY-CBOR-ENCODING.md §4.2 / §9.3:
--    content_hash = varint(format_code) || HASH(ECF({type, data}))
--
--  format_code 16#00# = ecfv1-sha256 (the required §9.1 floor). The varint
--  prefix is LEB128 (N1) — a synthetic code >= 16#80# exercises the multi-byte
--  path (corpus content_hash.4). SHA-256 from libsodium (profile
--  [codec].sha256_source). SHA-384 (format_code 16#01#) is the DEFERRED agility
--  higher bar (A-ADA-002), not in libsodium; the construction side here is
--  SHA-256-only for the core floor.

with Interfaces;
with Entity_Core.Bytes;
with Entity_Core.Codec.Value;

package Entity_Core.Codec.Hash is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;

   --  Canonical ECF of the {type, data} entity. The encoder sorts keys, so
   --  "data" precedes "type" (both 5 encoded bytes, lexicographic).
   function Ecf_Of_Entity (Typ : String; Data : Ecf_Value) return Byte_Array;

   --  content_hash bytes: varint(format_code) || SHA-256(ECF({type, data})).
   --  Core floor uses format_code 0 (SHA-256). Any non-zero code still emits
   --  varint(code) || SHA-256 on the CONSTRUCTION side (receive-side dispatch
   --  / rejection of unsupported codes is the S3 peer surface) — matching the
   --  cohort's content_hash.4 expectation.
   function Content_Hash
     (Format_Code : Interfaces.Unsigned_64;
      Typ         : String;
      Data        : Ecf_Value) return Byte_Array;

end Entity_Core.Codec.Hash;
