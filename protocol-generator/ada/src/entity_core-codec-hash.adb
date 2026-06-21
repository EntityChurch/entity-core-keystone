with Entity_Core.Codec.Cbor;
with Entity_Core.Codec.Varint;
with Entity_Core.Crypto;

package body Entity_Core.Codec.Hash is

   --------------------
   -- Ecf_Of_Entity --
   --------------------
   function Ecf_Of_Entity (Typ : String; Data : Ecf_Value) return Byte_Array is
      Pairs : constant Pair_Vector :=
        ((Key => Make_Text ("type"), Value => Make_Text (Typ)),
         (Key => Make_Text ("data"), Value => Data));
      Entity : constant Ecf_Value := Make_Map (Pairs);
   begin
      return Cbor.Encode (Entity);
   end Ecf_Of_Entity;

   ------------------
   -- Content_Hash --
   ------------------
   function Content_Hash
     (Format_Code : Interfaces.Unsigned_64;
      Typ         : String;
      Data        : Ecf_Value) return Byte_Array
   is
      Ecf    : constant Byte_Array := Ecf_Of_Entity (Typ, Data);
      Digest : constant Entity_Core.Crypto.Sha256_Digest :=
        Entity_Core.Crypto.Sha256 (Ecf);
      Prefix : Byte_Vector;
   begin
      Varint.Encode (Prefix, Format_Code);
      declare
         P : constant Byte_Array := Prefix.To_Array;
         Result : Byte_Array (1 .. P'Length + Digest'Length);
      begin
         Result (1 .. P'Length) := P;
         Result (P'Length + 1 .. Result'Last) := Digest;
         Prefix.Clear;
         return Result;
      end;
   end Content_Hash;

end Entity_Core.Codec.Hash;
