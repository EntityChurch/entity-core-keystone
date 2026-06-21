--  Entity_Core.Codec.Varint — multicodec-style LEB128 (V7 §1.5, §7.3 NORMATIVE).
--
--  Invariant N1: format codes, key_type and hash_type are framed as LEB128
--  varints, NOT fixed bytes. Every currently-allocated code is < 16#80# (one
--  byte), so this is byte-identical to a fixed field today — but a future code
--  >= 16#80# extends to 2+ bytes and a fixed-width impl breaks silently. Corpus
--  vectors content_hash.4 (format_code 128) and peer_id.3 (key_type 128) prove
--  the multi-byte path.
--
--  Native: Interfaces.Unsigned_64 + shift/mask (the no-unsigned-trap advantage).

with Interfaces;
with Entity_Core.Bytes;

package Entity_Core.Codec.Varint is

   use Entity_Core.Bytes;

   --  Append the LEB128 encoding of N to V.
   procedure Encode (V : in out Byte_Vector; N : Interfaces.Unsigned_64);

   --  Decode one varint from S starting at 1-based Pos. Returns the value and
   --  sets Consumed to the number of bytes read. Raises Truncated_Input on a
   --  never-terminating varint.
   procedure Decode
     (S        : Byte_Array;
      Pos      : Positive;
      Value    : out Interfaces.Unsigned_64;
      Consumed : out Positive)
     with Pre => Pos <= S'Last + 1;

end Entity_Core.Codec.Varint;
