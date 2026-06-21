--  run_conformance — the ECF wire-conformance harness (S2 gate).
--
--  Mirrors the Java/Zig precedent: load the normative fixture
--  (conformance-vectors-v1.cbor), DECODE it with THIS peer's own decoder (a
--  decoder bug is itself a conformance failure per ENTITY-CBOR-ENCODING.md
--  §E.3), run every vector through the codec, and byte-compare the produced
--  bytes against the embedded cross-blessed `canonical`. Byte-identity to the
--  fixture == oracle PASS. The fixture carries its own Go x Rust x Python
--  byte-locked canonical bytes, so no running Go binary is needed at S2 (the Go
--  wire-conformance binary is the fixture PRODUCER, not a runtime checker).
--
--  Dispatch by category:
--    decode_reject              -> the decoder MUST reject the canonical bytes.
--    content_hash               -> Content_Hash(format_code, type, data).
--    peer_id                    -> ECF-text(Base58(varint(kt)||varint(ht)||digest)).
--    signature                  -> Ed25519 sign over ECF({type,data}).
--    everything else            -> re-encode the decoded `input` canonically.
--
--  Usage: run_conformance [path-to-fixture.cbor]

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;          use Ada.Text_IO;
with Interfaces;

with Entity_Core.Bytes;           use Entity_Core.Bytes;
with Entity_Core.Codec.Value;     use Entity_Core.Codec.Value;
with Entity_Core.Codec.Cbor;
with Entity_Core.Codec.Hash;
with Entity_Core.Codec.Peer_Id;
with Entity_Core.Crypto;

procedure Run_Conformance is

   package Cbor renames Entity_Core.Codec.Cbor;

   use type Interfaces.Unsigned_8;

   Default_Path : constant String :=
     "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor";

   ---------------------------------------------------------------------------
   --  Read an entire file into a Byte_Array.
   ---------------------------------------------------------------------------
   function Read_File (Path : String) return Byte_Array is
      package SIO renames Ada.Streams.Stream_IO;
      use type Ada.Streams.Stream_Element_Offset;
      F   : SIO.File_Type;
      Len : Natural;
   begin
      SIO.Open (F, SIO.In_File, Path);
      Len := Natural (SIO.Size (F));
      declare
         Result : Byte_Array (1 .. Len);
         SEA    : Ada.Streams.Stream_Element_Array
                    (1 .. Ada.Streams.Stream_Element_Offset (Len));
         Last   : Ada.Streams.Stream_Element_Offset;
      begin
         SIO.Read (F, SEA, Last);
         SIO.Close (F);
         for I in 1 .. Len loop
            Result (I) := Octet (SEA (Ada.Streams.Stream_Element_Offset (I)));
         end loop;
         return Result;
      end;
   end Read_File;

   ---------------------------------------------------------------------------
   --  Category = the id text up to the first '.'.
   ---------------------------------------------------------------------------
   function Category (Id : String) return String is
   begin
      for I in Id'Range loop
         if Id (I) = '.' then
            return Id (Id'First .. I - 1);
         end if;
      end loop;
      return Id;
   end Category;

   function Get (M : Ecf_Value; Key : String) return Ecf_Value is
      Found : Boolean;
      Result : Ecf_Value;
   begin
      Map_Get (M, Key, Found, Result);
      if not Found then
         raise Constraint_Error with "missing key: " & Key;
      end if;
      return Result;
   end Get;

   function Has (M : Ecf_Value; Key : String) return Boolean is
      Found : Boolean;
      Result : Ecf_Value;
   begin
      Map_Get (M, Key, Found, Result);
      return Found;
   end Has;

   function Bytes_Equal (A, B : Byte_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Bytes_Equal;

   ---------------------------------------------------------------------------
   --  Run one vector. Returns True on PASS; sets Msg on FAIL.
   ---------------------------------------------------------------------------
   function Run_Vector
     (VM  : Ecf_Value;
      Msg : out String;
      Msg_Last : out Natural) return Boolean
   is
      Id   : constant String := As_Text (Get (VM, "id"));
      Kind_S : constant String := As_Text (Get (VM, "kind"));
      Canon : constant Byte_Array := As_Bytes (Get (VM, "canonical"));
      Cat  : constant String := Category (Id);

      procedure Set_Msg (S : String) is
      begin
         Msg (Msg'First .. Msg'First + S'Length - 1) := S;
         Msg_Last := Msg'First + S'Length - 1;
      end Set_Msg;
   begin
      Msg_Last := Msg'First - 1;

      if Kind_S = "decode_reject" then
         --  The decoder MUST reject these wire bytes.
         declare
            Discard : Ecf_Value;
         begin
            Discard := Cbor.Decode (Canon);
            Set_Msg ("decoder accepted a reject vector");
            return False;
         exception
            when others =>
               return True;  --  correctly rejected
         end;
      end if;

      --  encode_equal: produce bytes per category, compare to Canon.
      declare
         function Produce return Byte_Array is
         begin
            if Cat = "content_hash" then
               declare
                  Input : constant Ecf_Value := Get (VM, "input");
                  Typ   : constant String := As_Text (Get (Input, "type"));
                  Data  : constant Ecf_Value := Get (Input, "data");
                  FC    : Interfaces.Unsigned_64 := 0;
               begin
                  if Has (Input, "format_code") then
                     FC := As_Uint (Get (Input, "format_code"));
                  end if;
                  return Entity_Core.Codec.Hash.Content_Hash (FC, Typ, Data);
               end;

            elsif Cat = "peer_id" then
               declare
                  Input : constant Ecf_Value := Get (VM, "input");
                  KT    : constant Interfaces.Unsigned_64 := As_Uint (Get (Input, "key_type"));
                  HT    : constant Interfaces.Unsigned_64 := As_Uint (Get (Input, "hash_type"));
                  Dig   : constant Byte_Array := As_Bytes (Get (Input, "digest"));
                  Pid   : constant String :=
                    Entity_Core.Codec.Peer_Id.Format (KT, HT, Dig);
               begin
                  --  canonical bytes are the ECF encoding of the peer-id text.
                  return Cbor.Encode (Make_Text (Pid));
               end;

            elsif Cat = "signature" then
               declare
                  Input  : constant Ecf_Value := Get (VM, "input");
                  Seed_B : constant Byte_Array := As_Bytes (Get (Input, "seed"));
                  Ent    : constant Ecf_Value := Get (Input, "entity");
                  Typ    : constant String := As_Text (Get (Ent, "type"));
                  Data   : constant Ecf_Value := Get (Ent, "data");
                  Msg_B  : constant Byte_Array :=
                    Entity_Core.Codec.Hash.Ecf_Of_Entity (Typ, Data);
                  Seed   : Entity_Core.Crypto.Seed_Bytes;
               begin
                  Seed := Seed_B (Seed_B'First .. Seed_B'First + 31);
                  return Entity_Core.Crypto.Sign (Seed, Msg_B);
               end;

            else
               --  float / int / map_keys / length / primitive / nested /
               --  envelope: re-encode the decoded input value canonically.
               return Cbor.Encode (Get (VM, "input"));
            end if;
         end Produce;

      begin
         declare
            Got : constant Byte_Array := Produce;
         begin
            if Bytes_Equal (Got, Canon) then
               return True;
            end if;
            Set_Msg ("want " & To_Hex (Canon) & " got " & To_Hex (Got));
            return False;
         end;
      exception
         when E : others =>
            Set_Msg ("exception during produce: "
                     & Ada.Exceptions.Exception_Name (E));
            return False;
      end;
   end Run_Vector;

   ---------------------------------------------------------------------------
   --  Main
   ---------------------------------------------------------------------------
   Path : constant String :=
     (if Ada.Command_Line.Argument_Count >= 1
      then Ada.Command_Line.Argument (1)
      else Default_Path);

   Pass : Natural := 0;
   Fail : Natural := 0;

begin
   declare
      Raw     : constant Byte_Array := Read_File (Path);
      Fixture : constant Ecf_Value := Cbor.Decode (Raw);
   begin
      if Kind (Fixture) /= K_Array then
         Put_Line ("FATAL: fixture is not a CBOR array");
         Ada.Command_Line.Set_Exit_Status (2);
         return;
      end if;

      for I in 1 .. Array_Length (Fixture) loop
         declare
            VM : constant Ecf_Value := Array_Element (Fixture, I);
            --  Meta entries carry no "kind"; skip (not counted).
            Found : Boolean;
            Dummy : Ecf_Value;
         begin
            Map_Get (VM, "kind", Found, Dummy);
            if Found then
               declare
                  Id : constant String := As_Text (Get (VM, "id"));
                  Msg  : String (1 .. 4096);
                  Last : Natural;
                  OK   : constant Boolean := Run_Vector (VM, Msg, Last);
               begin
                  if OK then
                     Pass := Pass + 1;
                  else
                     Fail := Fail + 1;
                     Put_Line ("FAIL " & Id & "  " & Msg (Msg'First .. Last));
                  end if;
               end;
            end if;
         end;
      end loop;
   end;

   New_Line;
   Put_Line ("== ECF conformance:" & Natural'Image (Pass) & "/"
             & Natural'Image (Pass + Fail) & " PASS,"
             & Natural'Image (Fail) & " FAIL ==");

   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Ada.Command_Line.Set_Exit_Status (0);
   end if;
end Run_Conformance;
