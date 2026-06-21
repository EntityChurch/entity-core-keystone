with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Envelope is

   use Entity_Core.Protocol.Cbor_Util;

   -------------
   -- Of_Root --
   -------------
   function Of_Root (Root : Materialized_Entity) return Protocol_Envelope is
   begin
      return E : Protocol_Envelope do
         E.Root := Root;
      end return;
   end Of_Root;

   ---------
   -- Add --
   ---------
   procedure Add (E : in out Protocol_Envelope; Ent : Materialized_Entity) is
      H : constant Content_Hash := Hash (Ent);
   begin
      for It of E.Included loop
         if Octets_Equal (It.Hash, H) then
            return;  --  already present
         end if;
      end loop;
      E.Included.Append (Included_Item'(Hash => H, Ent => Ent));
   end Add;

   ------------------
   -- Included_Get --
   ------------------
   function Included_Get (E : Protocol_Envelope; H : Byte_Array; Found : out Boolean)
                          return Materialized_Entity is
   begin
      for It of E.Included loop
         if Octets_Equal (It.Hash, H) then
            Found := True;
            return It.Ent;
         end if;
      end loop;
      Found := False;
      return Make ("primitive/any", Empty_Map);
   end Included_Get;

   -------------
   -- To_Cbor --
   -------------
   function To_Cbor (E : Protocol_Envelope) return Ecf_Value is
      N : constant Natural := Natural (E.Included.Length);
      Pairs : Pair_Vector (1 .. N);
      Idx   : Positive := 1;
   begin
      for It of E.Included loop
         Pairs (Idx) := (Key   => Make_Bytes (It.Hash),
                         Value => To_Cbor (It.Ent));
         Idx := Idx + 1;
      end loop;
      return Map_Of (((Key => K ("root"),     Value => To_Cbor (E.Root)),
                      (Key => K ("included"), Value => Make_Map (Pairs))));
   end To_Cbor;

   -------------
   -- Of_Cbor --
   -------------
   function Of_Cbor (M : Ecf_Value) return Protocol_Envelope is
      Root_Found : Boolean;
      Root_V     : constant Ecf_Value := Field (M, "root", Root_Found);
      Inc_Found  : Boolean;
      Inc_V      : constant Ecf_Value := Field (M, "included", Inc_Found);
   begin
      if not Root_Found or else Kind (Root_V) /= K_Map then
         raise Entity_Core.Errors.Non_Canonical_Ecf with "envelope: missing root";
      end if;
      return E : Protocol_Envelope do
         E.Root := Of_Cbor (Root_V);
         if Inc_Found and then Kind (Inc_V) = K_Map then
            for I in 1 .. Map_Length (Inc_V) loop
               declare
                  P : constant Pair := Map_Pair (Inc_V, I);
               begin
                  if Kind (P.Key) /= K_Bytes then
                     raise Entity_Core.Errors.Non_Canonical_Ecf
                       with "envelope: included key not bytes";
                  end if;
                  if Kind (P.Value) /= K_Map then
                     raise Entity_Core.Errors.Non_Canonical_Ecf
                       with "envelope: included value not a map";
                  end if;
                  declare
                     Ent : constant Materialized_Entity := Of_Cbor (P.Value);
                  begin
                     --  §3.1: the included content_hash MUST equal the map key (N5).
                     if not Octets_Equal (As_Bytes (P.Key), Hash (Ent)) then
                        raise Entity_Core.Errors.Non_Canonical_Ecf
                          with "included key != content_hash";
                     end if;
                     Add (E, Ent);
                  end;
               end;
            end loop;
         end if;
      end return;
   end Of_Cbor;

end Entity_Core.Protocol.Envelope;
