--  Entity_Core.Protocol.Store — the content-addressed store + tree index
--  (foundation, §1.7), as a PROTECTED OBJECT. THE headline concurrency finding.
--
--  §1.7 two layers:
--     Content_Store : hash-hex -> entity   (immutable, content-addressed, dedup)
--     Entity_Tree   : path     -> hash-hex (mutable location index)
--
--  §4.8 DATA-RACE SAFETY — the centerpiece (profile [concurrency]).
--  The store lives INSIDE a protected object (Safe_Store). Reads are protected
--  FUNCTIONS (shared, concurrent), writes are protected PROCEDURES (exclusive).
--  Mutual exclusion is enforced by the LANGUAGE — there is no lock to forget and
--  no map to race. The two store-race fall-overs that drove §4.8 into the v7.75
--  floor (Zig double-free panic, CL hash-table corruption) are STRUCTURALLY
--  UNREPRESENTABLE here: a caller cannot reach the underlying maps except through
--  the protected operations, which the runtime serializes. This is the cleanest
--  §4.8 story in the cohort — the protected object IS the §4.8 guarantee.
--
--  Paths are the canonical absolute form /{peer_id}/rest (§1.4); the dispatcher
--  canonicalizes before calling in. The content store is keyed by the lowercase-
--  hex content_hash (A-ADA-003) so a Byte_Array works as a string map key.

with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Strings.Hash;
with Entity_Core.Bytes;
with Entity_Core.Protocol.Entity;

package Entity_Core.Protocol.Store is

   use Entity_Core.Bytes;
   use Entity_Core.Protocol.Entity;

   --  Content store: hash-hex string -> entity.
   package Content_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type        => String,
      Element_Type    => Materialized_Entity,
      Hash            => Ada.Strings.Hash,
      Equivalent_Keys => "=");

   --  Entity tree: path string -> hash-hex string. ORDERED so listings come out
   --  in sorted segment order (§3.9) without a post-sort.
   package Tree_Maps is new Ada.Containers.Indefinite_Ordered_Maps
     (Key_Type     => String,
      Element_Type => String);

   type String_Ptr is access String;

   --  One-level listing row: a segment, its bound hash-hex (or null if a pure
   --  interior node), and whether the segment has deeper descendants.
   type List_Row is record
      Segment      : String_Ptr;
      Hash_Hex     : String_Ptr;   --  null => interior-only node
      Has_Children : Boolean := False;
   end record;

   type List_Rows is array (Positive range <>) of List_Row;

   ---------------------------------------------------------------------------
   --  Safe_Store — the protected object (§4.8). All access to the two maps
   --  goes through here; the runtime serializes writers and allows concurrent
   --  readers, so the store stays consistent under simultaneous inbound
   --  dispatches by construction.
   ---------------------------------------------------------------------------
   protected type Safe_Store is

      --  Content store (immutable, dedup on first write).
      procedure Put_Entity (E : Materialized_Entity);
      function Get_By_Hash (H : Byte_Array; Found : out Boolean) return Materialized_Entity;

      --  Tree (location index).
      procedure Bind (Path : String; E : Materialized_Entity);
      procedure Unbind (Path : String);
      function Hash_At (Path : String) return String;   --  "" if unbound
      function Get_At (Path : String; Found : out Boolean) return Materialized_Entity;

      --  One-level listing under Prefix (a trailing slash is added if absent),
      --  sorted by segment (§3.9). Caller frees the returned access strings via
      --  Free_Rows.
      function Listing (Prefix : String) return List_Rows;

   private
      Content : Content_Maps.Map;
      Tree    : Tree_Maps.Map;
   end Safe_Store;

   type Store_Access is access Safe_Store;

   --  Free the access strings in a List_Rows result.
   procedure Free_Rows (Rows : in out List_Rows);

end Entity_Core.Protocol.Store;
