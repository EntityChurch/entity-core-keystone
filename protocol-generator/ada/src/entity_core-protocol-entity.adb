with Entity_Core.Codec.Hash;
with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Entity is

   use Entity_Core.Protocol.Cbor_Util;

   ----------
   -- Make --
   ----------
   function Make (Typ : String; Data : Ecf_Value) return Materialized_Entity is
      Basis_V : constant Ecf_Value :=
        Map_Of (((Key => K ("type"), Value => Make_Text (Typ)),
                 (Key => K ("data"), Value => Data)));
      H_Bytes : constant Byte_Array :=
        Entity_Core.Codec.Hash.Content_Hash (Format_Code => 0, Typ => Typ, Data => Data);
   begin
      return E : Materialized_Entity do
         E.Basis := Basis_V;
         E.H     := H_Bytes;
      end return;
   end Make;

   ---------------
   -- Type_Name --
   ---------------
   function Type_Name (E : Materialized_Entity) return String is
     (Text_Field (E.Basis, "type"));

   ----------
   -- Data --
   ----------
   function Data (E : Materialized_Entity) return Ecf_Value is
     (Field (E.Basis, "data"));

   ----------
   -- Hash --
   ----------
   function Hash (E : Materialized_Entity) return Content_Hash is (E.H);

   ----------
   -- Text --
   ----------
   function Text (E : Materialized_Entity; Key : String; Default : String := "") return String is
     (Text_Field (Data (E), Key, Default));

   ----------------
   -- Byte_Field --
   ----------------
   function Byte_Field (E : Materialized_Entity; Key : String; Found : out Boolean) return Byte_Array is
     (Bytes_Field (Data (E), Key, Found));

   function Byte_Field (E : Materialized_Entity; Key : String) return Byte_Array is
      Found : Boolean;
   begin
      return Bytes_Field (Data (E), Key, Found);
   end Byte_Field;

   ------------------
   -- Entity_Field --
   ------------------
   function Entity_Field (E : Materialized_Entity; Key : String; Found : out Boolean)
                          return Materialized_Entity is
      Sub : constant Ecf_Value := Field (Data (E), Key, Found);
   begin
      if not Found or else Kind (Sub) /= K_Map or else not Has (Sub, "type") then
         Found := False;
         return Make ("primitive/any", Empty_Map);
      end if;
      begin
         return Of_Cbor (Sub);
      exception
         when others =>
            Found := False;
            return Make ("primitive/any", Empty_Map);
      end;
   end Entity_Field;

   -------------
   -- To_Cbor --
   -------------
   function To_Cbor (E : Materialized_Entity) return Ecf_Value is
   begin
      return Map_Of (((Key => K ("type"), Value => Make_Text (Type_Name (E))),
                      (Key => K ("data"), Value => Data (E)),
                      (Key => K ("content_hash"), Value => Make_Bytes (E.H))));
   end To_Cbor;

   -------------
   -- Of_Cbor --
   -------------
   function Of_Cbor (M : Ecf_Value) return Materialized_Entity is
      Type_Found : Boolean;
      Data_Found : Boolean;
      Type_V     : constant Ecf_Value := Field (M, "type", Type_Found);
      Data_V     : constant Ecf_Value := Field (M, "data", Data_Found);
   begin
      if not Type_Found or else Kind (Type_V) /= K_Text then
         raise Entity_Core.Errors.Non_Canonical_Ecf with "entity: missing/invalid type";
      end if;
      if not Data_Found then
         raise Entity_Core.Errors.Non_Canonical_Ecf with "entity: missing data";
      end if;
      declare
         E : constant Materialized_Entity := Make (As_Text (Type_V), Data_V);
         Carried_Found : Boolean;
         Carried : constant Byte_Array := Bytes_Field (M, "content_hash", Carried_Found);
      begin
         if Carried_Found and then not Octets_Equal (Carried, E.H) then
            raise Entity_Core.Errors.Non_Canonical_Ecf
              with "content_hash mismatch (§1.8 fidelity)";
         end if;
         return E;
      end;
   end Of_Cbor;

end Entity_Core.Protocol.Entity;
