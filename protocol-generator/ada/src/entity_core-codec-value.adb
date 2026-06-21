with Ada.Unchecked_Deallocation;

package body Entity_Core.Codec.Value is

   --  The Float payload legitimately holds IEEE specials (NaN / +/-Inf / -0.0);
   --  see Entity_Core.Codec.Cbor. Disable compiler-inserted validity checks so
   --  storing/returning a special float is not mis-flagged as invalid data.
   pragma Validity_Checks (Off);
   pragma Suppress (Validity_Check);

   procedure Free is new Ada.Unchecked_Deallocation (Value_Vector, Value_Vector_Access);
   procedure Free is new Ada.Unchecked_Deallocation (Pair_Vector, Pair_Vector_Access);
   procedure Free is new Ada.Unchecked_Deallocation (Byte_Array, Byte_Array_Access);
   procedure Free is new Ada.Unchecked_Deallocation (String, String_Access);

   ------------
   -- Adjust -- deep-copy the access-typed children so values are value-semantic
   ------------
   overriding procedure Adjust (Object : in out Ecf_Value) is
   begin
      if Object.Bin /= null then
         Object.Bin := new Byte_Array'(Object.Bin.all);
      end if;
      if Object.Str /= null then
         Object.Str := new String'(Object.Str.all);
      end if;
      if Object.Items /= null then
         Object.Items := new Value_Vector'(Object.Items.all);
      end if;
      if Object.Pairs /= null then
         Object.Pairs := new Pair_Vector'(Object.Pairs.all);
      end if;
   end Adjust;

   --------------
   -- Finalize -- deep-free children (idempotent — null after free)
   --------------
   overriding procedure Finalize (Object : in out Ecf_Value) is
   begin
      if Object.Bin /= null then
         Free (Object.Bin);
      end if;
      if Object.Str /= null then
         Free (Object.Str);
      end if;
      if Object.Items /= null then
         Free (Object.Items);
      end if;
      if Object.Pairs /= null then
         Free (Object.Pairs);
      end if;
   end Finalize;

   ---------------------------------------------------------------------------
   --  Constructors
   ---------------------------------------------------------------------------
   function Make_Uint (N : Interfaces.Unsigned_64) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Uint;
         V.U := N;
      end return;
   end Make_Uint;

   function Make_Nint (N : Interfaces.Unsigned_64) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Nint;
         V.U := N;
      end return;
   end Make_Nint;

   function Make_Int (V : Interfaces.Integer_64) return Ecf_Value is
      use type Interfaces.Integer_64;
   begin
      if V >= 0 then
         return Make_Uint (Interfaces.Unsigned_64 (V));
      else
         --  value = -1 - n  =>  n = -1 - value = -(value) - 1.
         --  For V in -2**63 .. -1, -1 - V fits in Unsigned_64.
         return Make_Nint (Interfaces.Unsigned_64 (-(V + 1)));
      end if;
   end Make_Int;

   function Make_Bytes (B : Byte_Array) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Bytes;
         V.Bin := new Byte_Array'(B);
      end return;
   end Make_Bytes;

   function Make_Text (S : String) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Text;
         V.Str := new String'(S);
      end return;
   end Make_Text;

   function Make_Array (Items : Value_Vector) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Array;
         V.Items := new Value_Vector'(Items);
      end return;
   end Make_Array;

   function Make_Map (Pairs : Pair_Vector) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Map;
         V.Pairs := new Pair_Vector'(Pairs);
      end return;
   end Make_Map;

   function Make_Bool (B : Boolean) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Bool;
         V.B := B;
      end return;
   end Make_Bool;

   function Make_Null return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Null;
      end return;
   end Make_Null;

   function Make_Float (X : Long_Float) return Ecf_Value is
   begin
      return V : Ecf_Value do
         V.Kind := K_Float;
         V.F := X;
      end return;
   end Make_Float;

   ---------------------------------------------------------------------------
   --  Accessors
   ---------------------------------------------------------------------------
   function Kind (V : Ecf_Value) return Value_Kind is (V.Kind);

   function As_Uint (V : Ecf_Value) return Interfaces.Unsigned_64 is (V.U);
   function As_Nint (V : Ecf_Value) return Interfaces.Unsigned_64 is (V.U);
   function As_Bytes (V : Ecf_Value) return Byte_Array is (V.Bin.all);
   function As_Text (V : Ecf_Value) return String is (V.Str.all);
   function As_Bool (V : Ecf_Value) return Boolean is (V.B);
   function As_Float (V : Ecf_Value) return Long_Float is (V.F);

   function Array_Length (V : Ecf_Value) return Natural is
     (if V.Items = null then 0 else V.Items'Length);

   function Array_Element (V : Ecf_Value; I : Positive) return Ecf_Value is
     (V.Items (I));

   function Map_Length (V : Ecf_Value) return Natural is
     (if V.Pairs = null then 0 else V.Pairs'Length);

   function Map_Pair (V : Ecf_Value; I : Positive) return Pair is
     (V.Pairs (I));

   procedure Map_Get
     (V     : Ecf_Value;
      Key   : String;
      Found : out Boolean;
      Result : out Ecf_Value) is
   begin
      Found := False;
      if V.Pairs = null then
         return;
      end if;
      for P of V.Pairs.all loop
         if Kind (P.Key) = K_Text and then As_Text (P.Key) = Key then
            Found := True;
            Result := P.Value;
            return;
         end if;
      end loop;
   end Map_Get;

end Entity_Core.Codec.Value;
