with Entity_Core.Errors;

package body Entity_Core.Codec.Varint is

   use type Interfaces.Unsigned_64;
   use type Interfaces.Unsigned_8;

   ------------
   -- Encode --
   ------------
   procedure Encode (V : in out Byte_Vector; N : Interfaces.Unsigned_64) is
      Rest : Interfaces.Unsigned_64 := N;
   begin
      loop
         declare
            Low : constant Octet := Octet (Rest and 16#7F#);
         begin
            Rest := Interfaces.Shift_Right (Rest, 7);
            if Rest = 0 then
               V.Append (Low);
               exit;
            else
               V.Append (Low or 16#80#);
            end if;
         end;
      end loop;
   end Encode;

   ------------
   -- Decode --
   ------------
   procedure Decode
     (S        : Byte_Array;
      Pos      : Positive;
      Value    : out Interfaces.Unsigned_64;
      Consumed : out Positive)
   is
      Acc   : Interfaces.Unsigned_64 := 0;
      Shift : Natural := 0;
      I     : Positive := Pos;
      Count : Natural := 0;
   begin
      loop
         if I > S'Last then
            raise Entity_Core.Errors.Truncated_Input
              with "truncated varint";
         end if;
         declare
            B : constant Octet := S (I);
         begin
            Acc := Acc or Interfaces.Shift_Left
                            (Interfaces.Unsigned_64 (B and 16#7F#), Shift);
            I := I + 1;
            Count := Count + 1;
            exit when (B and 16#80#) = 0;
            Shift := Shift + 7;
         end;
      end loop;
      Value := Acc;
      Consumed := Count;
   end Decode;

end Entity_Core.Codec.Varint;
