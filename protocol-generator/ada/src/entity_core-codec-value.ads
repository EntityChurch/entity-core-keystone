--  Entity_Core.Codec.Value — the ECF value model (A-ADA-009 / A-JAVA-010).
--
--  THE load-bearing data-model decision for this peer. V7 §1.1: an entity's
--  `data` is an ARBITRARY ECF value, NOT necessarily a map. Ada's strong
--  static typing makes "model data as a discriminated variant over the whole
--  ECF value space" the must-get-right decision: a map-only model would compile
--  clean, pass S2/S3, then 500 on the first scalar-data entity at the live S4
--  oracle. So Ecf_Value is a DISCRIMINATED RECORD VARIANT over every ECF value
--  kind; an entity's `data` field is one such value.
--
--  Integers (the no-unsigned-trap Ada advantage, profile [idiom]):
--    * Uint kind  = CBOR major 0; stores the full Unsigned_64 bit pattern.
--    * Nint kind  = CBOR major 1; stores n where the value is -1 - n. So
--      Nint(0) = -1 and Nint(16#FFFF_FFFF_FFFF_FFFF#) = -2**64. This covers the
--      whole 0..2**64-1 (uint) and -1..-2**64 (nint) spec range natively, with
--      NO BigInteger/ulong workaround (unlike Java/C#).
--
--  Floats: a single Float64 value carries every finite float; the specials
--  (NaN / +/-Inf / -0.0) ride in the same Long_Float and are detected at encode
--  time for the shortest-float ladder. Bool / Null are distinct kinds so that
--  absent /= null /= false /= 0 on the wire (ECF §1.3).
--
--  Memory: Ecf_Value is a controlled (Finalizable) type; Array_Items and
--  Map_Pairs are access-typed children that are deep-copied on Adjust and
--  deep-freed on Finalize, so values are value-semantic (copy = deep copy) and
--  leak-free without caller bookkeeping.

with Ada.Finalization;
with Interfaces;
with Entity_Core.Bytes;

package Entity_Core.Codec.Value is

   use Entity_Core.Bytes;

   type Value_Kind is
     (K_Uint, K_Nint, K_Bytes, K_Text, K_Array, K_Map,
      K_Bool, K_Null, K_Float);

   type Ecf_Value is new Ada.Finalization.Controlled with private;

   --  An owned, freshly-allocated array of values (caller need not free).
   type Value_Vector is array (Positive range <>) of Ecf_Value;

   type Pair is record
      Key   : Ecf_Value;
      Value : Ecf_Value;
   end record;

   type Pair_Vector is array (Positive range <>) of Pair;

   ---------------------------------------------------------------------------
   --  Constructors
   ---------------------------------------------------------------------------
   function Make_Uint (N : Interfaces.Unsigned_64) return Ecf_Value
     with Post => Kind (Make_Uint'Result) = K_Uint;

   --  N is the stored magnitude (value = -1 - N).
   function Make_Nint (N : Interfaces.Unsigned_64) return Ecf_Value
     with Post => Kind (Make_Nint'Result) = K_Nint;

   --  Signed convenience: value V < 0 -> Nint, V >= 0 -> Uint.
   function Make_Int (V : Interfaces.Integer_64) return Ecf_Value;

   function Make_Bytes (B : Byte_Array) return Ecf_Value
     with Post => Kind (Make_Bytes'Result) = K_Bytes;

   function Make_Text (S : String) return Ecf_Value
     with Post => Kind (Make_Text'Result) = K_Text;

   function Make_Array (Items : Value_Vector) return Ecf_Value
     with Post => Kind (Make_Array'Result) = K_Array;

   function Make_Map (Pairs : Pair_Vector) return Ecf_Value
     with Post => Kind (Make_Map'Result) = K_Map;

   function Make_Bool (B : Boolean) return Ecf_Value
     with Post => Kind (Make_Bool'Result) = K_Bool;

   function Make_Null return Ecf_Value
     with Post => Kind (Make_Null'Result) = K_Null;

   function Make_Float (X : Long_Float) return Ecf_Value
     with Post => Kind (Make_Float'Result) = K_Float;

   ---------------------------------------------------------------------------
   --  Accessors
   ---------------------------------------------------------------------------
   function Kind (V : Ecf_Value) return Value_Kind;

   function As_Uint (V : Ecf_Value) return Interfaces.Unsigned_64
     with Pre => Kind (V) = K_Uint;
   function As_Nint (V : Ecf_Value) return Interfaces.Unsigned_64
     with Pre => Kind (V) = K_Nint;
   function As_Bytes (V : Ecf_Value) return Byte_Array
     with Pre => Kind (V) = K_Bytes;
   function As_Text (V : Ecf_Value) return String
     with Pre => Kind (V) = K_Text;
   function As_Bool (V : Ecf_Value) return Boolean
     with Pre => Kind (V) = K_Bool;
   function As_Float (V : Ecf_Value) return Long_Float
     with Pre => Kind (V) = K_Float;

   function Array_Length (V : Ecf_Value) return Natural
     with Pre => Kind (V) = K_Array;
   function Array_Element (V : Ecf_Value; I : Positive) return Ecf_Value
     with Pre => Kind (V) = K_Array and then I <= Array_Length (V);

   function Map_Length (V : Ecf_Value) return Natural
     with Pre => Kind (V) = K_Map;
   function Map_Pair (V : Ecf_Value; I : Positive) return Pair
     with Pre => Kind (V) = K_Map and then I <= Map_Length (V);

   --  Convenience: look up a text-keyed value in a map; returns whether found.
   procedure Map_Get
     (V     : Ecf_Value;
      Key   : String;
      Found : out Boolean;
      Result : out Ecf_Value)
     with Pre => Kind (V) = K_Map;

private

   type Value_Vector_Access is access Value_Vector;
   type Pair_Vector_Access  is access Pair_Vector;
   type Byte_Array_Access   is access Byte_Array;
   type String_Access       is access String;

   type Ecf_Value is new Ada.Finalization.Controlled with record
      Kind  : Value_Kind := K_Null;
      U     : Interfaces.Unsigned_64 := 0;   -- Uint / Nint payload
      F     : Long_Float := 0.0;             -- Float payload
      B     : Boolean := False;              -- Bool payload
      Bin   : Byte_Array_Access := null;     -- Bytes payload
      Str   : String_Access := null;         -- Text payload
      Items : Value_Vector_Access := null;   -- Array payload
      Pairs : Pair_Vector_Access := null;    -- Map payload
   end record;

   overriding procedure Adjust   (Object : in out Ecf_Value);
   overriding procedure Finalize (Object : in out Ecf_Value);

end Entity_Core.Codec.Value;
