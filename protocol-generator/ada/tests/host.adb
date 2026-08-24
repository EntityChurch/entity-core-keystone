--  host — standalone S4-ready host for entity-core-protocol-ada.
--
--  Boots a peer on a localhost port and prints a `LISTENING <port>` line (and a
--  `PEER <peer_id>` line) so a harness can scrape the bound port + identity,
--  then parks forever (the harness kills the process). Flags:
--    --port N               bind port (0 = auto, the default)
--    --name NAME            load a persistent Ed25519 identity from the standard
--                           on-disk location ~/.entity/peers/NAME/keypair (the
--                           entity-core PEM keypair: base64 of a 32-byte seed
--                           between BEGIN/END ENTITY PRIVATE KEY lines — the
--                           convention the Go entity-peer --name and peer-manager
--                           use). Without --name/--seed a fixed test seed is used.
--    --seed B               seed byte (repeated 32x) for a deterministic identity
--    --debug-open-grants    degenerate [default → *] admin seed (non-conformant)
--    --validate             bootstrap the §7a system/validate/* handlers (OFF
--                           by default — the keystone --validate opt-in)

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Environment_Variables;
with Entity_Core.Bytes;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Handlers;
with Entity_Core.Protocol.Transport;

procedure Host is
   use Ada.Command_Line;
   use Entity_Core.Bytes;

   --  Standard-alphabet base64 sextet value, or -1 for a non-alphabet char.
   function B64_Val (C : Character) return Integer is
   begin
      case C is
         when 'A' .. 'Z' => return Character'Pos (C) - Character'Pos ('A');
         when 'a' .. 'z' => return Character'Pos (C) - Character'Pos ('a') + 26;
         when '0' .. '9' => return Character'Pos (C) - Character'Pos ('0') + 52;
         when '+'        => return 62;
         when '/'        => return 63;
         when others     => return -1;
      end case;
   end B64_Val;

   --  Load the 32-byte Ed25519 seed from ~/.entity/peers/NAME/keypair, a PEM
   --  whose body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
   function Load_Seed_From_Name (Name : String) return Entity_Core.Crypto.Seed_Bytes is
      Home : constant String :=
        (if Ada.Environment_Variables.Exists ("HOME")
         then Ada.Environment_Variables.Value ("HOME") else "/root");
      Path  : constant String := Home & "/.entity/peers/" & Name & "/keypair";
      F     : Ada.Text_IO.File_Type;
      Acc   : Natural := 0;   --  bit accumulator
      Nbits : Natural := 0;   --  bits currently buffered
      Count : Natural := 0;
      Seed  : Entity_Core.Crypto.Seed_Bytes := (others => 0);
   begin
      Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (F) loop
         declare
            Line : constant String := Ada.Text_IO.Get_Line (F);
         begin
            --  Skip the PEM armor lines; decode the base64 body.
            if not (Line'Length >= 5
                    and then Line (Line'First .. Line'First + 4) = "-----")
            then
               for K in Line'Range loop
                  declare
                     V : constant Integer := B64_Val (Line (K));
                  begin
                     if V >= 0 then
                        Acc := Acc * 64 + V;
                        Nbits := Nbits + 6;
                        if Nbits >= 8 then
                           Nbits := Nbits - 8;
                           Count := Count + 1;
                           if Count <= Seed'Length then
                              Seed (Count) := Octet ((Acc / (2 ** Nbits)) mod 256);
                           end if;
                           Acc := Acc mod (2 ** Nbits);
                        end if;
                     end if;
                  end;
               end loop;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (F);
      if Count /= Seed'Length then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "host: --name " & Name & ": expected a 32-byte seed, got"
            & Natural'Image (Count) & " bytes");
         Set_Exit_Status (2);
         raise Program_Error;
      end if;
      return Seed;
   end Load_Seed_From_Name;

   Port        : Natural := 0;
   Open_Grants : Boolean := False;
   Validate    : Boolean := False;
   Seed        : Entity_Core.Crypto.Seed_Bytes := (others => 1);
begin
   declare
      I : Positive := 1;
   begin
      while I <= Argument_Count loop
         declare
            A : constant String := Argument (I);
         begin
            if A = "--port" and then I < Argument_Count then
               Port := Natural'Value (Argument (I + 1));
               I := I + 1;
            elsif A = "--name" and then I < Argument_Count then
               Seed := Load_Seed_From_Name (Argument (I + 1));
               I := I + 1;
            elsif A = "--seed" and then I < Argument_Count then
               Seed := (others => Octet (Natural'Value (Argument (I + 1))));
               I := I + 1;
            elsif A = "--debug-open-grants" then
               Open_Grants := True;
            elsif A = "--validate" then
               Validate := True;
            end if;
         end;
         I := I + 1;
      end loop;
   end;

   declare
      Peer  : Entity_Core.Protocol.Handlers.Peer_Access;
      L     : Entity_Core.Protocol.Transport.Listener_Access;
      Bound : Natural;
   begin
      Entity_Core.Protocol.Handlers.Create (Peer, Seed, Open_Grants, Validate);
      Entity_Core.Protocol.Transport.Start_Listener (L, Peer, Port, Bound);
      Ada.Text_IO.Put_Line ("LISTENING" & Natural'Image (Bound));
      Ada.Text_IO.Put_Line ("PEER " & Entity_Core.Protocol.Handlers.Local_Peer (Peer));
      Ada.Text_IO.Flush;
      --  park forever; the harness kills the process.
      loop
         delay 3600.0;
      end loop;
   end;
end Host;
