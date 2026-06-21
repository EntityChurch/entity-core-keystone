package body Entity_Core.Protocol.Cbor_Util is

   ------------
   -- Map_Of --
   ------------
   function Map_Of (Items : Kv_List) return Ecf_Value is
      Pairs : Pair_Vector (Items'Range);
   begin
      for I in Items'Range loop
         Pairs (I) := (Key => Items (I).Key, Value => Items (I).Value);
      end loop;
      return Make_Map (Pairs);
   end Map_Of;

   ---------------
   -- Empty_Map --
   ---------------
   function Empty_Map return Ecf_Value is
      Empty : Pair_Vector (1 .. 0);
   begin
      return Make_Map (Empty);
   end Empty_Map;

   -------
   -- K --
   -------
   function K (S : String) return Ecf_Value is (Make_Text (S));

   --------------
   -- Array_Of --
   --------------
   function Array_Of (Items : Value_Vector) return Ecf_Value is
   begin
      return Make_Array (Items);
   end Array_Of;

   -----------------
   -- Text_Array1 --
   -----------------
   function Text_Array1 (A : String) return Ecf_Value is
      One : constant Value_Vector (1 .. 1) := (1 => Make_Text (A));
   begin
      return Make_Array (One);
   end Text_Array1;

   ---------
   -- Has --
   ---------
   function Has (V : Ecf_Value; Key : String) return Boolean is
      Found  : Boolean;
      Result : Ecf_Value;
   begin
      if Kind (V) /= K_Map then
         return False;
      end if;
      Map_Get (V, Key, Found, Result);
      return Found;
   end Has;

   ----------------
   -- Text_Field --
   ----------------
   function Text_Field (V : Ecf_Value; Key : String; Default : String := "") return String is
      Found  : Boolean;
      Result : Ecf_Value;
   begin
      if Kind (V) /= K_Map then
         return Default;
      end if;
      Map_Get (V, Key, Found, Result);
      if Found and then Kind (Result) = K_Text then
         return As_Text (Result);
      end if;
      return Default;
   end Text_Field;

   -----------------
   -- Bytes_Field --
   -----------------
   function Bytes_Field (V : Ecf_Value; Key : String; Found : out Boolean) return Byte_Array is
      Got    : Boolean;
      Result : Ecf_Value;
   begin
      Found := False;
      if Kind (V) /= K_Map then
         return Empty_Bytes;
      end if;
      Map_Get (V, Key, Got, Result);
      if Got and then Kind (Result) = K_Bytes then
         Found := True;
         return As_Bytes (Result);
      end if;
      return Empty_Bytes;
   end Bytes_Field;

   function Bytes_Field (V : Ecf_Value; Key : String) return Byte_Array is
      Found : Boolean;
   begin
      return Bytes_Field (V, Key, Found);
   end Bytes_Field;

   ----------------
   -- Uint_Field --
   ----------------
   function Uint_Field (V : Ecf_Value; Key : String; Found : out Boolean)
                        return Interfaces.Unsigned_64 is
      Got    : Boolean;
      Result : Ecf_Value;
   begin
      Found := False;
      if Kind (V) /= K_Map then
         return 0;
      end if;
      Map_Get (V, Key, Got, Result);
      if Got and then Kind (Result) = K_Uint then
         Found := True;
         return As_Uint (Result);
      end if;
      return 0;
   end Uint_Field;

   -----------
   -- Field --
   -----------
   function Field (V : Ecf_Value; Key : String; Found : out Boolean) return Ecf_Value is
      Result : Ecf_Value;
   begin
      Found := False;
      if Kind (V) /= K_Map then
         return Make_Null;
      end if;
      Map_Get (V, Key, Found, Result);
      if Found then
         return Result;
      end if;
      return Make_Null;
   end Field;

   function Field (V : Ecf_Value; Key : String) return Ecf_Value is
      Found : Boolean;
   begin
      return Field (V, Key, Found);
   end Field;

   -------------
   -- Is_True --
   -------------
   function Is_True (V : Ecf_Value; Key : String) return Boolean is
      Found  : Boolean;
      Result : Ecf_Value;
   begin
      if Kind (V) /= K_Map then
         return False;
      end if;
      Map_Get (V, Key, Found, Result);
      return Found and then Kind (Result) = K_Bool and then As_Bool (Result);
   end Is_True;

   ---------------
   -- Text_List --
   ---------------
   function Text_List (V : Ecf_Value; Key : String; Found : out Boolean) return Value_Vector is
      Got : Boolean;
      Arr : Ecf_Value;
   begin
      Found := False;
      if Kind (V) /= K_Map then
         return Value_Vector'(1 .. 0 => Make_Null);
      end if;
      Map_Get (V, Key, Got, Arr);
      if not Got or else Kind (Arr) /= K_Array then
         return Value_Vector'(1 .. 0 => Make_Null);
      end if;
      Found := True;
      declare
         N : constant Natural := Array_Length (Arr);
         Out_V : Value_Vector (1 .. N);
      begin
         for I in 1 .. N loop
            Out_V (I) := Array_Element (Arr, I);
         end loop;
         return Out_V;
      end;
   end Text_List;

   -------------------
   -- Octets_Equal --
   -------------------
   function Octets_Equal (A, B : Byte_Array) return Boolean is
      use type Interfaces.Unsigned_8;
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      declare
         Bi : Positive := B'First;
      begin
         for Ai in A'Range loop
            if A (Ai) /= B (Bi) then
               return False;
            end if;
            if Bi < B'Last then
               Bi := Bi + 1;
            end if;
         end loop;
      end;
      return True;
   end Octets_Equal;

end Entity_Core.Protocol.Cbor_Util;
