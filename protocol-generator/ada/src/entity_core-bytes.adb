with Ada.Unchecked_Deallocation;

package body Entity_Core.Bytes is

   procedure Free is
     new Ada.Unchecked_Deallocation (Byte_Array, Octet_Array_Access);

   --  Lowercase nibble table — the A-ADA-003 pin made concrete.
   Hex_Digits : constant array (Interfaces.Unsigned_8 range 0 .. 15) of Character :=
     ('0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

   ------------
   -- Length --
   ------------
   function Length (V : Byte_Vector) return Natural is (V.Len);

   ------------------------
   -- Ensure_Capacity     --
   ------------------------
   procedure Ensure (V : in out Byte_Vector; Extra : Natural) is
      Needed   : constant Natural := V.Len + Extra;
      Old_Cap  : constant Natural := (if V.Store = null then 0 else V.Store'Length);
   begin
      if Needed <= Old_Cap then
         return;
      end if;
      declare
         New_Cap : Natural := (if Old_Cap = 0 then 64 else Old_Cap * 2);
      begin
         while New_Cap < Needed loop
            New_Cap := New_Cap * 2;
         end loop;
         declare
            New_Store : constant Octet_Array_Access :=
              new Byte_Array (1 .. New_Cap);
         begin
            if V.Store /= null then
               New_Store (1 .. V.Len) := V.Store (1 .. V.Len);
               Free (V.Store);
            end if;
            V.Store := New_Store;
         end;
      end;
   end Ensure;

   ------------
   -- Append --
   ------------
   procedure Append (V : in out Byte_Vector; B : Octet) is
   begin
      Ensure (V, 1);
      V.Len := V.Len + 1;
      V.Store (V.Len) := B;
   end Append;

   procedure Append (V : in out Byte_Vector; A : Byte_Array) is
   begin
      if A'Length = 0 then
         return;
      end if;
      Ensure (V, A'Length);
      V.Store (V.Len + 1 .. V.Len + A'Length) := A;
      V.Len := V.Len + A'Length;
   end Append;

   --------------
   -- To_Array --
   --------------
   function To_Array (V : Byte_Vector) return Byte_Array is
   begin
      if V.Len = 0 then
         return Empty_Bytes;
      end if;
      return V.Store (1 .. V.Len);
   end To_Array;

   -------------
   -- Element --
   -------------
   function Element (V : Byte_Vector; I : Positive) return Octet is
     (V.Store (I));

   -----------
   -- Clear --
   -----------
   procedure Clear (V : in out Byte_Vector) is
   begin
      if V.Store /= null then
         Free (V.Store);
      end if;
      V.Len := 0;
   end Clear;

   ------------
   -- To_Hex --
   ------------
   function To_Hex (A : Byte_Array) return String is
      use type Interfaces.Unsigned_8;
      Result : String (1 .. A'Length * 2);
      Pos    : Positive := 1;
   begin
      for B of A loop
         Result (Pos)     := Hex_Digits (B / 16);
         Result (Pos + 1) := Hex_Digits (B mod 16);
         Pos := Pos + 2;
      end loop;
      return Result;
   end To_Hex;

   --------------
   -- From_Hex --
   --------------
   function From_Hex (S : String) return Byte_Array is
      use type Interfaces.Unsigned_8;

      function Nibble (C : Character) return Interfaces.Unsigned_8 is
      begin
         case C is
            when '0' .. '9' =>
               return Interfaces.Unsigned_8 (Character'Pos (C) - Character'Pos ('0'));
            when 'a' .. 'f' =>
               return Interfaces.Unsigned_8 (Character'Pos (C) - Character'Pos ('a') + 10);
            when 'A' .. 'F' =>
               return Interfaces.Unsigned_8 (Character'Pos (C) - Character'Pos ('A') + 10);
            when others =>
               raise Constraint_Error with "non-hex character in From_Hex";
         end case;
      end Nibble;

      Result : Byte_Array (1 .. S'Length / 2);
      Idx    : Positive := S'First;
   begin
      for I in Result'Range loop
         Result (I) := Nibble (S (Idx)) * 16 + Nibble (S (Idx + 1));
         Idx := Idx + 2;
      end loop;
      return Result;
   end From_Hex;

end Entity_Core.Bytes;
