--  Entity_Core.Codec.Base58 — Bitcoin-alphabet base58 (hand-rolled).
--
--  Standard byte-array long-division; no bignum dependency (profile
--  [codec].base58_library = hand-rolled). Leading zero bytes map to leading '1'
--  characters and vice-versa. Used for peer_id formatting (§1.5 / §7.3).

with Entity_Core.Bytes;

package Entity_Core.Codec.Base58 is

   use Entity_Core.Bytes;

   Alphabet : constant String :=
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

   function Encode (Input : Byte_Array) return String;

   --  Raises Constraint_Error on an invalid base58 character.
   function Decode (S : String) return Byte_Array;

end Entity_Core.Codec.Base58;
