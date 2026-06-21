--  Entity_Core.Codec.Peer_Id — peer identifier format/parse (V7 §1.5 / §7.3).
--
--    peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
--
--  key_type / hash_type are LEB128 varints (N1). For the canonical Ed25519
--  identity-multihash form (§1.5 v7.64/v7.65 canonical-form table; A-ADA-001):
--  key_type 16#01# = ed25519, hash_type 16#00# (identity-multihash), digest =
--  the RAW 32-byte public_key (NO SHA-256). The stale §7.4 SHA-256 form is
--  decode-only and NOT a construction path. libsodium returns the raw 32-byte
--  pubkey directly, so the construction is trivial.
--
--  The corpus peer_id vectors pin hash_type=16#01# over an opaque 32-byte
--  digest; Format is construction-agnostic over the component values and
--  reproduces them faithfully. A synthetic key_type >= 16#80# (peer_id.3)
--  exercises the multi-byte varint prefix.

with Interfaces;
with Entity_Core.Bytes;

package Entity_Core.Codec.Peer_Id is

   use Entity_Core.Bytes;

   --  Format the peer-id string for explicit components.
   function Format
     (Key_Type  : Interfaces.Unsigned_64;
      Hash_Type : Interfaces.Unsigned_64;
      Digest    : Byte_Array) return String;

   --  Canonical Ed25519 identity-multihash peer_id from a raw 32-byte pubkey
   --  (key_type=1, hash_type=0, digest = raw pubkey). A-ADA-001.
   function From_Ed25519_Public (Public_Key : Byte_Array) return String
     with Pre => Public_Key'Length = 32;

   type Components is record
      Key_Type  : Interfaces.Unsigned_64;
      Hash_Type : Interfaces.Unsigned_64;
      Digest    : Byte_Array (1 .. 64);  -- max digest we carry; Digest_Length tells the real size
      Digest_Length : Natural;
   end record;

   function Parse (S : String) return Components;

end Entity_Core.Codec.Peer_Id;
