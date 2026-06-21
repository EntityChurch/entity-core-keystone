with Ada.Unchecked_Deallocation;
with Entity_Core.Protocol.Cbor_Util;

package body Entity_Core.Protocol.Store is

   use Entity_Core.Protocol.Cbor_Util;

   procedure Free_Str is new Ada.Unchecked_Deallocation (String, String_Ptr);

   ----------------
   -- Safe_Store --
   ----------------
   protected body Safe_Store is

      ----------------
      -- Put_Entity --
      ----------------
      procedure Put_Entity (E : Materialized_Entity) is
         Key : constant String := Hex (Hash (E));
      begin
         if not Content.Contains (Key) then
            Content.Insert (Key, E);
         end if;
      end Put_Entity;

      -----------------
      -- Get_By_Hash --
      -----------------
      function Get_By_Hash (H : Byte_Array; Found : out Boolean) return Materialized_Entity is
         Key : constant String := Hex (H);
         C   : constant Content_Maps.Cursor := Content.Find (Key);
      begin
         if Content_Maps.Has_Element (C) then
            Found := True;
            return Content_Maps.Element (C);
         end if;
         Found := False;
         return Make ("primitive/any", Empty_Map);
      end Get_By_Hash;

      ----------
      -- Bind --
      ----------
      procedure Bind (Path : String; E : Materialized_Entity) is
         Key : constant String := Hex (Hash (E));
      begin
         if not Content.Contains (Key) then
            Content.Insert (Key, E);
         end if;
         Tree.Include (Path, Key);
      end Bind;

      ------------
      -- Unbind --
      ------------
      procedure Unbind (Path : String) is
      begin
         if Tree.Contains (Path) then
            Tree.Delete (Path);
         end if;
      end Unbind;

      -------------
      -- Hash_At --
      -------------
      function Hash_At (Path : String) return String is
         C : constant Tree_Maps.Cursor := Tree.Find (Path);
      begin
         if Tree_Maps.Has_Element (C) then
            return Tree_Maps.Element (C);
         end if;
         return "";
      end Hash_At;

      ------------
      -- Get_At --
      ------------
      function Get_At (Path : String; Found : out Boolean) return Materialized_Entity is
         TC : constant Tree_Maps.Cursor := Tree.Find (Path);
      begin
         if Tree_Maps.Has_Element (TC) then
            declare
               CC : constant Content_Maps.Cursor :=
                 Content.Find (Tree_Maps.Element (TC));
            begin
               if Content_Maps.Has_Element (CC) then
                  Found := True;
                  return Content_Maps.Element (CC);
               end if;
            end;
         end if;
         Found := False;
         return Make ("primitive/any", Empty_Map);
      end Get_At;

      -------------
      -- Listing --
      -------------
      function Listing (Prefix : String) return List_Rows is
         P    : constant String :=
           (if Prefix'Length > 0 and then Prefix (Prefix'Last) = '/'
            then Prefix else Prefix & "/");
         Plen : constant Natural := P'Length;

         --  Two ordered maps keyed by segment (the result is sorted by segment,
         --  §3.9): one for the bound hash-hex, one for the has-children flag.
         package Seg_Hash_Maps is new Ada.Containers.Indefinite_Ordered_Maps
           (Key_Type => String, Element_Type => String);
         package Seg_Kid_Maps is new Ada.Containers.Indefinite_Ordered_Maps
           (Key_Type => String, Element_Type => Boolean);

         Hashes : Seg_Hash_Maps.Map;
         Kids   : Seg_Kid_Maps.Map;
      begin
         for C in Tree.Iterate loop
            declare
               Path : constant String := Tree_Maps.Key (C);
            begin
               if Path'Length > Plen
                 and then Path (Path'First .. Path'First + Plen - 1) = P
               then
                  declare
                     Rest  : constant String :=
                       Path (Path'First + Plen .. Path'Last);
                     Slash : Natural := 0;
                  begin
                     for I in Rest'Range loop
                        if Rest (I) = '/' then
                           Slash := I;
                           exit;
                        end if;
                     end loop;
                     if Slash /= 0 then
                        Kids.Include (Rest (Rest'First .. Slash - 1), True);
                     else
                        Hashes.Include (Rest, Tree_Maps.Element (C));
                        if not Kids.Contains (Rest) then
                           Kids.Include (Rest, False);
                        end if;
                     end if;
                  end;
               end if;
            end;
         end loop;

         --  Union the segment sets (ordered merge) into the result.
         declare
            All_Segs : Seg_Kid_Maps.Map := Kids;
            N        : Natural;
         begin
            for C in Hashes.Iterate loop
               if not All_Segs.Contains (Seg_Hash_Maps.Key (C)) then
                  All_Segs.Include (Seg_Hash_Maps.Key (C), False);
               end if;
            end loop;
            N := Natural (All_Segs.Length);
            declare
               Rows : List_Rows (1 .. N);
               Idx  : Positive := 1;
            begin
               for C in All_Segs.Iterate loop
                  declare
                     Seg : constant String := Seg_Kid_Maps.Key (C);
                  begin
                     Rows (Idx).Segment := new String'(Seg);
                     Rows (Idx).Has_Children := Seg_Kid_Maps.Element (C);
                     if Hashes.Contains (Seg) then
                        Rows (Idx).Hash_Hex := new String'(Hashes.Element (Seg));
                     else
                        Rows (Idx).Hash_Hex := null;
                     end if;
                     Idx := Idx + 1;
                  end;
               end loop;
               return Rows;
            end;
         end;
      end Listing;

   end Safe_Store;

   ---------------
   -- Free_Rows --
   ---------------
   procedure Free_Rows (Rows : in out List_Rows) is
   begin
      for R of Rows loop
         if R.Segment /= null then
            Free_Str (R.Segment);
         end if;
         if R.Hash_Hex /= null then
            Free_Str (R.Hash_Hex);
         end if;
      end loop;
   end Free_Rows;

end Entity_Core.Protocol.Store;
