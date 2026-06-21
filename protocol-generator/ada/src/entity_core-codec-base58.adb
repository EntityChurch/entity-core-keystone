with Interfaces;

package body Entity_Core.Codec.Base58 is

   use type Interfaces.Unsigned_8;

   ------------
   -- Encode --
   ------------
   function Encode (Input : Byte_Array) return String is
      Len   : constant Natural := Input'Length;
      Zeros : Natural := 0;
   begin
      --  Count leading zero bytes.
      for B of Input loop
         exit when B /= 0;
         Zeros := Zeros + 1;
      end loop;

      declare
         Size : constant Natural := (Len * 138 / 100) + 1;
         B58  : array (0 .. Size - 1) of Natural := (others => 0);
         High : Integer := Size - 1;
      begin
         for I in Input'Range loop
            declare
               Carry : Natural := Natural (Input (I));
               J     : Integer := Size - 1;
            begin
               while J > High or else Carry /= 0 loop
                  Carry := Carry + 256 * B58 (J);
                  B58 (J) := Carry mod 58;
                  Carry := Carry / 58;
                  exit when J = 0;
                  J := J - 1;
               end loop;
               High := J;
            end;
         end loop;

         --  Skip leading zeros in B58.
         declare
            Start : Natural := 0;
         begin
            while Start < Size and then B58 (Start) = 0 loop
               Start := Start + 1;
            end loop;

            declare
               Result : String (1 .. Zeros + (Size - Start));
               Pos    : Positive := 1;
            begin
               for K in 1 .. Zeros loop
                  Result (Pos) := '1';
                  Pos := Pos + 1;
               end loop;
               for K in Start .. Size - 1 loop
                  Result (Pos) := Alphabet (Alphabet'First + B58 (K));
                  Pos := Pos + 1;
               end loop;
               return Result;
            end;
         end;
      end;
   end Encode;

   -----------
   -- Value --
   -----------
   function Char_Value (C : Character) return Integer is
   begin
      case C is
         when '1' .. '9' => return Character'Pos (C) - Character'Pos ('1');
         when 'A' .. 'H' => return Character'Pos (C) - Character'Pos ('A') + 9;
         when 'J' .. 'N' => return Character'Pos (C) - Character'Pos ('J') + 17;
         when 'P' .. 'Z' => return Character'Pos (C) - Character'Pos ('P') + 22;
         when 'a' .. 'k' => return Character'Pos (C) - Character'Pos ('a') + 33;
         when 'm' .. 'z' => return Character'Pos (C) - Character'Pos ('m') + 44;
         when others     => return -1;
      end case;
   end Char_Value;

   ------------
   -- Decode --
   ------------
   function Decode (S : String) return Byte_Array is
      Len  : constant Natural := S'Length;
      Ones : Natural := 0;
   begin
      for C of S loop
         exit when C /= '1';
         Ones := Ones + 1;
      end loop;

      declare
         Size : constant Natural := (Len * 733 / 1000) + 1;  -- log(58)/log(256)
         B256 : array (0 .. Size - 1) of Natural := (others => 0);
         High : Integer := Size - 1;
      begin
         for I in S'Range loop
            declare
               D     : constant Integer := Char_Value (S (I));
               Carry : Natural;
               J     : Integer := Size - 1;
            begin
               if D < 0 then
                  raise Constraint_Error with "invalid base58 character";
               end if;
               Carry := Natural (D);
               while J > High or else Carry /= 0 loop
                  Carry := Carry + 58 * B256 (J);
                  B256 (J) := Carry mod 256;
                  Carry := Carry / 256;
                  exit when J = 0;
                  J := J - 1;
               end loop;
               High := J;
            end;
         end loop;

         declare
            Start : Natural := 0;
         begin
            while Start < Size and then B256 (Start) = 0 loop
               Start := Start + 1;
            end loop;

            declare
               Result : Byte_Array (1 .. Ones + (Size - Start));
               Pos    : Positive := 1;
            begin
               for K in 1 .. Ones loop
                  Result (Pos) := 0;
                  Pos := Pos + 1;
               end loop;
               for K in Start .. Size - 1 loop
                  Result (Pos) := Octet (B256 (K));
                  Pos := Pos + 1;
               end loop;
               return Result;
            end;
         end;
      end;
   end Decode;

end Entity_Core.Codec.Base58;
