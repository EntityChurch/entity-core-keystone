--  Entity_Core.Protocol.Cbor_Util — constructor + accessor helpers over the S2
--  Ecf_Value model, plus the address-space lowercase-hex convention.
--
--  Keeps the peer code reading at the protocol altitude (map/array builders,
--  typed field reads) instead of restating the codec value model inline. The
--  hex helper is the codec's lowercase To_Hex (A-ADA-003) — re-exported so the
--  peer-layer paths are lowercase by construction (the §3.4/§3.5 tree-path keys
--  are case-sensitive and must match the Go oracle's hex.EncodeToString).

with Interfaces;
with Entity_Core.Bytes;
with Entity_Core.Codec.Value;

package Entity_Core.Protocol.Cbor_Util is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;

   ---------------------------------------------------------------------------
   --  Builders. A small key/value pair-list accumulator keeps map building
   --  readable without exposing the Pair_Vector indexing everywhere.
   ---------------------------------------------------------------------------
   type Kv is record
      Key   : Ecf_Value;
      Value : Ecf_Value;
   end record;

   type Kv_List is array (Positive range <>) of Kv;

   --  Build a map from a key/value list (keys are arbitrary Ecf_Values; the
   --  canonical encoder sorts on encode, so insertion order is irrelevant).
   function Map_Of (Items : Kv_List) return Ecf_Value
     with Post => Kind (Map_Of'Result) = K_Map;

   --  The canonical empty map (encodes to the single byte 16#A0#).
   function Empty_Map return Ecf_Value
     with Post => Kind (Empty_Map'Result) = K_Map
                  and then Map_Length (Empty_Map'Result) = 0;

   --  Text-key helper for Kv lists (the common case).
   function K (S : String) return Ecf_Value
     with Post => Kind (K'Result) = K_Text;

   --  Build an array from a value vector.
   function Array_Of (Items : Value_Vector) return Ecf_Value
     with Post => Kind (Array_Of'Result) = K_Array;

   --  Build a one-element text array (the handshake-list common case: this peer
   --  advertises exactly one protocol / hash_format / key_type today).
   function Text_Array1 (A : String) return Ecf_Value
     with Post => Kind (Text_Array1'Result) = K_Array
                  and then Array_Length (Text_Array1'Result) = 1;

   ---------------------------------------------------------------------------
   --  Typed field reads over a map value (null-safe: a missing or ill-typed
   --  key yields the documented "not found" signal). Each takes a K_Map value;
   --  a non-map V simply yields "not found".
   ---------------------------------------------------------------------------

   --  True iff V is a map carrying Key (any value kind).
   function Has (V : Ecf_Value; Key : String) return Boolean;

   --  Text field, or Default if absent / not-text.
   function Text_Field (V : Ecf_Value; Key : String; Default : String := "") return String;

   --  Bytes field; Found is False (and result Empty_Bytes) if absent / not-bytes.
   function Bytes_Field (V : Ecf_Value; Key : String; Found : out Boolean) return Byte_Array;
   function Bytes_Field (V : Ecf_Value; Key : String) return Byte_Array;

   --  Unsigned field; Found is False (and result 0) if absent / not-uint.
   function Uint_Field (V : Ecf_Value; Key : String; Found : out Boolean)
                        return Interfaces.Unsigned_64;

   --  Sub-value field (Found out; returns Make_Null on absent).
   function Field (V : Ecf_Value; Key : String; Found : out Boolean) return Ecf_Value;
   function Field (V : Ecf_Value; Key : String) return Ecf_Value;

   --  True iff Key is present and maps to the boolean True.
   function Is_True (V : Ecf_Value; Key : String) return Boolean;

   ---------------------------------------------------------------------------
   --  Array helpers.
   ---------------------------------------------------------------------------

   --  Collect the text elements of array field Key into a fresh string list;
   --  Found is False if the field is absent or not an array. Non-text elements
   --  are skipped.
   function Text_List (V : Ecf_Value; Key : String; Found : out Boolean) return Value_Vector;

   ---------------------------------------------------------------------------
   --  Hex (lowercase — A-ADA-003). Re-exported from the codec's To_Hex so the
   --  peer-layer address-space paths are lowercase by construction.
   ---------------------------------------------------------------------------
   function Hex (A : Byte_Array) return String renames Entity_Core.Bytes.To_Hex;
   function Unhex (S : String) return Byte_Array renames Entity_Core.Bytes.From_Hex;

   --  Octet equality (length + content).
   function Octets_Equal (A, B : Byte_Array) return Boolean;

end Entity_Core.Protocol.Cbor_Util;
