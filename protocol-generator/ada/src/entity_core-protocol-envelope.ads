--  Entity_Core.Protocol.Envelope — the protocol envelope (§3.1).
--
--  A `root` entity plus an `included` map of protocol entities keyed by
--  content_hash. `included` is the §5.8 authority carrier (caps, peer
--  identities, signatures travel here). N5: the included map MUST survive
--  across every dispatch surface — it is never dropped before the wire.
--
--  Held as an insertion-ordered vector of (hash, entity) pairs so a wire
--  round-trip is deterministic; lookup is by content_hash octets.

with Ada.Containers.Vectors;
with Entity_Core.Bytes;
with Entity_Core.Codec.Value;
with Entity_Core.Protocol.Entity;

package Entity_Core.Protocol.Envelope is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Entity;

   type Included_Item is record
      Hash   : Content_Hash := (others => 0);
      Ent    : Materialized_Entity;
   end record;

   package Included_Vectors is
     new Ada.Containers.Vectors (Index_Type => Positive, Element_Type => Included_Item);

   type Protocol_Envelope is record
      Root     : Materialized_Entity;
      Included : Included_Vectors.Vector;
   end record;

   --  An envelope with no included entities (the handshake legs).
   function Of_Root (Root : Materialized_Entity) return Protocol_Envelope;

   --  Append an included entity (keyed by its own content_hash). De-dups by hash.
   procedure Add (E : in out Protocol_Envelope; Ent : Materialized_Entity);

   --  Find an included entity by content_hash; Found is False if absent.
   function Included_Get (E : Protocol_Envelope; H : Byte_Array; Found : out Boolean)
                          return Materialized_Entity;

   ---------------------------------------------------------------------------
   --  Wire form.
   ---------------------------------------------------------------------------
   function To_Cbor (E : Protocol_Envelope) return Ecf_Value
     with Post => Kind (To_Cbor'Result) = K_Map;

   --  Parse a wire envelope cbor-map. Enforces the §3.1 included-key ==
   --  content_hash check on parse (N5). Raises Errors.Non_Canonical_Ecf on a
   --  missing root or a key/hash mismatch.
   function Of_Cbor (M : Ecf_Value) return Protocol_Envelope
     with Pre => Kind (M) = K_Map;

end Entity_Core.Protocol.Envelope;
