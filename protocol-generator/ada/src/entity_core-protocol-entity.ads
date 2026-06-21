--  Entity_Core.Protocol.Entity — a materialized entity {type, data,
--  content_hash} (§1.1, §3.4) on top of the S2 codec value model.
--
--  The content_hash covers ONLY {type, data} (§1.1); the wire form (To_Cbor)
--  carries content_hash as a third field so entities are self-describing across
--  serialization (§3.1). The two forms stay distinct: the hash is never computed
--  over a map that already contains the content_hash field.
--
--  §1.1 / A-JAVA-010 / A-ADA-009 (the load-bearing data-model decision): an
--  entity's `data` is an ARBITRARY ECF value, NOT necessarily a map. We hold the
--  RAW Ecf_Value (which may be a scalar — e.g. a primitive/string payload) and
--  the field-read helpers in Cbor_Util are null-safe over a non-map data. A
--  map-only model would compile clean, pass loopback, then 500 on the first
--  scalar-data entity at the live oracle.
--
--  Materialized_Entity is a value type (Ecf_Value is controlled / value-
--  semantic), so copies are independent and there is no aliasing to defend
--  (contrast the Java no_byte_array_aliasing defensive-copy discipline — Ada's
--  value semantics give it for free).

with Entity_Core.Bytes;
with Entity_Core.Codec.Value;

package Entity_Core.Protocol.Entity is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;

   type Materialized_Entity is private;

   --  Content_Hash is the 33-byte (format byte 16#00# || 32-byte SHA-256) hash;
   --  a distinct subtype documents the length invariant at every boundary.
   Hash_Length : constant := 33;
   subtype Content_Hash is Byte_Array (1 .. Hash_Length);

   ---------------------------------------------------------------------------
   --  Construction.
   ---------------------------------------------------------------------------

   --  Materialize an entity of Typ with arbitrary ECF Data (§1.1), computing
   --  content_hash under the ecfv1-sha256 floor (format_code 16#00#).
   function Make (Typ : String; Data : Ecf_Value) return Materialized_Entity
     with Post => Hash (Make'Result)'Length = Hash_Length;

   ---------------------------------------------------------------------------
   --  Accessors.
   ---------------------------------------------------------------------------
   function Type_Name (E : Materialized_Entity) return String;

   --  The raw `data` value (§1.1) — may be any ECF node, not just a map.
   function Data (E : Materialized_Entity) return Ecf_Value;

   --  The 33-byte content_hash.
   function Hash (E : Materialized_Entity) return Content_Hash;

   ---------------------------------------------------------------------------
   --  Field reads off data (null-safe over a non-map data via Cbor_Util).
   ---------------------------------------------------------------------------
   function Text (E : Materialized_Entity; Key : String; Default : String := "") return String;
   function Byte_Field (E : Materialized_Entity; Key : String; Found : out Boolean) return Byte_Array;
   function Byte_Field (E : Materialized_Entity; Key : String) return Byte_Array;

   --  A nested entity carried at Key (a wire cbor-map) — re-materialized; Found
   --  is False if the field is absent or not a well-formed entity map.
   function Entity_Field (E : Materialized_Entity; Key : String; Found : out Boolean)
                          return Materialized_Entity;

   ---------------------------------------------------------------------------
   --  Wire form.
   ---------------------------------------------------------------------------

   --  The wire cbor-map {type, data, content_hash}.
   function To_Cbor (E : Materialized_Entity) return Ecf_Value
     with Post => Kind (To_Cbor'Result) = K_Map;

   --  Re-materialize a wire entity cbor-map: recompute the hash from {type,
   --  data} and validate against the carried content_hash (§1.8 fidelity). We
   --  trust our recomputed hash, not the wire bytes (§5.2 validate-before-
   --  trust). Raises Entity_Core.Errors.Non_Canonical_Ecf on a fidelity break
   --  or a missing/ill-typed type field.
   function Of_Cbor (M : Ecf_Value) return Materialized_Entity
     with Pre => Kind (M) = K_Map;

private

   --  We hold the {type, data} basis as a single map value plus the cached hash.
   --  Type and Data are extracted on demand from the basis (both always present
   --  by construction). Ecf_Value is controlled, so the record is value-semantic
   --  and copies deep-copy; no manual aliasing management.
   type Materialized_Entity is record
      Basis : Ecf_Value;        -- {type, data} (the hashable basis)
      H     : Content_Hash := (others => 0);
   end record;

end Entity_Core.Protocol.Entity;
