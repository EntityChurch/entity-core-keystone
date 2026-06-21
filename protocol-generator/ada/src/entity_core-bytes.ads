--  Entity_Core.Bytes — wire-byte primitives.
--
--  Wire bytes are Interfaces.Unsigned_8 carried in a growable vector
--  (Byte_Vector) for encode output and an indexable slice (Byte_Array) for
--  decode input. Profile [idiom].stream_element_array: we use
--  Interfaces.Unsigned_8 rather than Character/String to avoid any
--  char-encoding ambiguity over the raw octets.
--
--  Strong typing: Octet is the wire octet; Byte_Array a 1-based array of them.
--  A hand-rolled growable vector keeps the dependency surface minimal (no
--  Ada.Containers needed for the encode buffer) and matches the cohort's
--  hand-rolled stance.

with Interfaces;

package Entity_Core.Bytes is

   subtype Octet is Interfaces.Unsigned_8;

   --  1-based octet array (the natural Ada index base; index 1 = first byte).
   type Byte_Array is array (Positive range <>) of Octet;

   Empty_Bytes : constant Byte_Array (1 .. 0) := (others => 0);

   ---------------------------------------------------------------------------
   --  Byte_Vector — a growable, amortised-doubling octet buffer used as the
   --  canonical-encode output sink. Hand-rolled (no Ada.Containers dep).
   ---------------------------------------------------------------------------
   type Byte_Vector is tagged private;

   function Length (V : Byte_Vector) return Natural;

   procedure Append (V : in out Byte_Vector; B : Octet)
     with Post => Length (V) = Length (V'Old) + 1;

   procedure Append (V : in out Byte_Vector; A : Byte_Array)
     with Post => Length (V) = Length (V'Old) + A'Length;

   --  Snapshot the current contents as a freshly-allocated 1-based array.
   function To_Array (V : Byte_Vector) return Byte_Array
     with Post => To_Array'Result'Length = Length (V)
                  and then To_Array'Result'First = 1;

   --  Byte at 1-based position I (1 .. Length).
   function Element (V : Byte_Vector; I : Positive) return Octet
     with Pre => I <= Length (V);

   procedure Clear (V : in out Byte_Vector)
     with Post => Length (V) = 0;

   ---------------------------------------------------------------------------
   --  Hex helpers. HEX-CASE PIN (A-ADA-003 / A-CL-009): rendering MUST be
   --  LOWERCASE a-f via an explicit nibble->char table. Ada's hex builtins
   --  (Integer'Image, 16#..#, Integer_IO Base=>16) all emit UPPERCASE, which
   --  would pass Ada-to-Ada loopback but 404 against the lowercase Go oracle.
   ---------------------------------------------------------------------------
   function To_Hex (A : Byte_Array) return String
     with Post => To_Hex'Result'Length = A'Length * 2;

   function From_Hex (S : String) return Byte_Array
     with Pre => S'Length mod 2 = 0,
          Post => From_Hex'Result'Length = S'Length / 2;

private

   type Octet_Array_Access is access Byte_Array;

   type Byte_Vector is tagged record
      Store : Octet_Array_Access := null;
      Len   : Natural            := 0;
   end record;

end Entity_Core.Bytes;
