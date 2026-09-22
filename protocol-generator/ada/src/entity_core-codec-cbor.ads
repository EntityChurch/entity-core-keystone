--  Entity_Core.Codec.Cbor — hand-rolled canonical ECF (CBOR).
--
--  Why hand-rolled (profile [codec], A-005): ECF (ENTITY-CBOR-ENCODING.md §4,
--  RFC 8949 §4.2 with Entity clarifications) needs (a) length-then-lex map-key
--  ordering on ENCODED key bytes (NOT pure RFC-8949 bytewise), (b) shortest-
--  float minimisation incl. f16, (c) recursive major-type-6 tag rejection on
--  decode (N2), (d) full uint64/nint range, (e) empty-map = single byte 16#A0#
--  (N3). No Ada CBOR library offers these; a faithful ECF codec must own the
--  canonical layer regardless. std-only (Interfaces + the value model).

with Entity_Core.Bytes;
with Entity_Core.Codec.Value;

package Entity_Core.Codec.Cbor is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;

   --  Canonical-encode V into a freshly-allocated byte array.
   function Encode (V : Ecf_Value) return Byte_Array
     with Post => (if Kind (V) = K_Map and then Map_Length (V) = 0
                   then Encode'Result'Length = 1);  -- N3: empty map = 16#A0#

   --  Append the canonical encoding of V to Buf.
   procedure Encode_Into (Buf : in out Byte_Vector; V : Ecf_Value);

   --  Decode a single top-level ECF item from S. Rejects tags (N2),
   --  indefinite/reserved length args, and trailing bytes. Raises the
   --  Entity_Core.Errors codec exceptions on malformed input.
   function Decode (S : Byte_Array) return Ecf_Value;

   --  Decode S for the sole purpose of REPORTING a rejection, not of accepting
   --  one. Identical to Decode except that a major-type-6 tag yields the item it
   --  wrapped instead of raising Tag_Rejected.
   --
   --  Why this exists (§6.3, a conformance requirement rather than a
   --  convenience): the tag rule is "Implementations MUST reject any received
   --  protocol frame containing a CBOR tag on a data field. Rejection returns
   --  400 non_canonical_ecf." Rejecting by dropping the frame on the floor
   --  satisfies the first sentence and violates the second -- the peer owes the
   --  sender a status, and §4.9(c) deliver-or-signal says the same from the
   --  other direction. But the status must ride a response correlated by
   --  request_id, and the strict decoder cannot reach the request_id in a frame
   --  it refuses to parse. This recovers exactly that much and nothing more.
   --
   --  This is NOT a weakening of the tag reject. The frame stays rejected: the
   --  value this returns is never converted to an entity, never stored, never
   --  forwarded and never interpreted, so §6.3's MUST NOT silently strip / MUST
   --  NOT preserve / MUST NOT attempt to interpret all still hold. The strict
   --  Decode path that every real ingestion route uses is unchanged, which is
   --  what keeps the tag_reject wire-conformance vectors meaningful.
   function Decode_Salvage (S : Byte_Array) return Ecf_Value;

end Entity_Core.Codec.Cbor;
