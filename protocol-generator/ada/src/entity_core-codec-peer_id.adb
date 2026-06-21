with Entity_Core.Codec.Base58;
with Entity_Core.Codec.Varint;

package body Entity_Core.Codec.Peer_Id is

   ------------
   -- Format --
   ------------
   function Format
     (Key_Type  : Interfaces.Unsigned_64;
      Hash_Type : Interfaces.Unsigned_64;
      Digest    : Byte_Array) return String
   is
      Raw : Byte_Vector;
   begin
      Varint.Encode (Raw, Key_Type);
      Varint.Encode (Raw, Hash_Type);
      Raw.Append (Digest);
      declare
         R : constant String := Base58.Encode (Raw.To_Array);
      begin
         Raw.Clear;
         return R;
      end;
   end Format;

   --------------------------
   -- From_Ed25519_Public --
   --------------------------
   function From_Ed25519_Public (Public_Key : Byte_Array) return String is
   begin
      --  §1.5 canonical form: key_type=1 (ed25519), hash_type=0 (identity-
      --  multihash), digest = raw public key (A-ADA-001).
      return Format (1, 0, Public_Key);
   end From_Ed25519_Public;

   -----------
   -- Parse --
   -----------
   function Parse (S : String) return Components is
      Raw : constant Byte_Array := Base58.Decode (S);
      KT, HT   : Interfaces.Unsigned_64;
      C1, C2   : Positive;
      Result   : Components;
   begin
      Varint.Decode (Raw, Raw'First, KT, C1);
      Varint.Decode (Raw, Raw'First + C1, HT, C2);
      declare
         Off : constant Positive := Raw'First + C1 + C2;
         Len : constant Natural := Raw'Last - Off + 1;
      begin
         Result.Key_Type := KT;
         Result.Hash_Type := HT;
         Result.Digest_Length := Len;
         Result.Digest := (others => 0);
         if Len > 0 then
            Result.Digest (1 .. Len) := Raw (Off .. Raw'Last);
         end if;
      end;
      return Result;
   end Parse;

end Entity_Core.Codec.Peer_Id;
