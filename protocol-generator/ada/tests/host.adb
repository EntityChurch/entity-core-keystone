--  host — standalone S4-ready host for entity-core-protocol-ada.
--
--  Boots a peer on a localhost port and prints a `LISTENING <port>` line (and a
--  `PEER <peer_id>` line) so a harness can scrape the bound port + identity,
--  then parks forever (the harness kills the process). Flags:
--    --port N               bind port (0 = auto, the default)
--    --seed B               seed byte (repeated 32x) for a deterministic identity
--    --debug-open-grants    degenerate [default → *] admin seed (non-conformant)
--    --validate             bootstrap the §7a system/validate/* handlers (OFF
--                           by default — the keystone --validate opt-in)

with Ada.Command_Line;
with Ada.Text_IO;
with Entity_Core.Bytes;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Handlers;
with Entity_Core.Protocol.Transport;
with Entity_Core.Protocol.Identity;

procedure Host is
   use Ada.Command_Line;
   use Entity_Core.Bytes;

   Port        : Natural := 0;
   Seed_Byte   : Octet   := 1;
   Open_Grants : Boolean := False;
   Validate    : Boolean := False;
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
            elsif A = "--seed" and then I < Argument_Count then
               Seed_Byte := Octet (Natural'Value (Argument (I + 1)));
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
      Seed : constant Entity_Core.Crypto.Seed_Bytes :=
        Entity_Core.Protocol.Identity.Seed_Of_Byte (Seed_Byte);
      Peer : Entity_Core.Protocol.Handlers.Peer_Access;
      L    : Entity_Core.Protocol.Transport.Listener_Access;
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
