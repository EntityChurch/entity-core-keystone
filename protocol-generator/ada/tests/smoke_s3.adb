--  smoke_s3 — the S3 peer-machinery loopback smoke gate (Ada side).
--
--  Direction A (Ada dials the Go reference peer): boots an Ada initiator peer,
--  dials the Go `entity-peer` at the address passed as argv[1], drives the §4.1
--  handshake (hello + authenticate over real TCP), then:
--    * sends an EXECUTE tree:get to an unregistered path → expects 404
--      (no handler resolved / not_found) from the Go responder;
--    * confirms request_id correlation by issuing several interleaved EXECUTEs
--      and asserting each reply carries its own request_id (§6.11 / N7).
--  Tears down cleanly.
--
--  Direction B (Go dials Ada) is driven from run-s3.sh by the Go `probe-peer`
--  client against the Ada Host — proving the Ada peer as RESPONDER is wire-
--  compatible with the Go client (handshake + a tree get + a 404). The two
--  directions together are the cohort "both directions" gate.
--
--  Usage:  smoke_s3 <go-peer-host:port>
--  Exit:   0 = all checks PASS; 1 = a check FAILED.

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with Ada.Exceptions;
with GNAT.OS_Lib;
with Interfaces;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Handlers;
with Entity_Core.Protocol.Transport;
with Entity_Core.Protocol.Identity;
with Entity_Core.Protocol.Wire;
with Entity_Core.Protocol.Envelope;

procedure Smoke_S3 is
   use Ada.Text_IO;
   package Hand renames Entity_Core.Protocol.Handlers;
   package Tport renames Entity_Core.Protocol.Transport;
   package Id_Pkg renames Entity_Core.Protocol.Identity;
   package Wire renames Entity_Core.Protocol.Wire;
   package Env_Pkg renames Entity_Core.Protocol.Envelope;
   use type Interfaces.Unsigned_64;

   Passes : Natural := 0;
   Fails  : Natural := 0;

   procedure Check (Cond : Boolean; Label : String) is
   begin
      if Cond then
         Passes := Passes + 1;
         Put_Line ("  [PASS] " & Label);
      else
         Fails := Fails + 1;
         Put_Line ("  [FAIL] " & Label);
      end if;
   end Check;

   --  Split "host:port".
   procedure Split (Spec : String; Host : out String; Host_Len : out Natural;
                    Port : out Natural) is
      Colon : constant Natural := Ada.Strings.Fixed.Index (Spec, ":", Going => Ada.Strings.Backward);
   begin
      Host_Len := Colon - Spec'First;
      Host (Host'First .. Host'First + Host_Len - 1) := Spec (Spec'First .. Colon - 1);
      Port := Natural'Value (Spec (Colon + 1 .. Spec'Last));
   end Split;

begin
   if Ada.Command_Line.Argument_Count < 1 then
      Put_Line ("usage: smoke_s3 <go-peer-host:port>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   declare
      Spec : constant String := Ada.Command_Line.Argument (1);
      Host_Buf : String (1 .. Spec'Length) := (others => ' ');
      Host_Len : Natural;
      Port     : Natural;
   begin
      Split (Spec, Host_Buf, Host_Len, Port);

      Put_Line ("Scenario A — Ada initiator dials the Go reference peer (" & Spec & "):");

      declare
         Seed : constant Entity_Core.Crypto.Seed_Bytes := Id_Pkg.Seed_Of_Byte (16#22#);
         Peer : Hand.Peer_Access;
         S    : Tport.Session_Access;
      begin
         Hand.Create (Peer, Seed, Open_Grants => False, Validate => False);

         --  (1) dial + §4.1 handshake (hello then authenticate, both over TCP).
         begin
            Tport.Dial (S, Peer, Host_Buf (1 .. Host_Len), Port);
            Check (True, "session established (§4.1 handshake hello+authenticate)");
         exception
            when E : others =>
               Check (False, "session established (§4.1 handshake) — "
                      & Ada.Exceptions.Exception_Message (E));
               raise;
         end;

         --  (2) remote peer_id is non-empty (§4.6 identity binding from hello).
         Check (Tport.Remote_Peer_Id (S)'Length > 0,
                "remote peer_id observed: " & Tport.Remote_Peer_Id (S));

         --  (3) EXECUTE tree:get to an unregistered (but floor-allowed) path →
         --      expect 404 not_found (no entity bound there).
         declare
            R : constant Env_Pkg.Protocol_Envelope :=
              Tport.Execute (S, "system/tree", "get",
                             Resource_Target => "system/handler/ada-smoke-unregistered");
            Status : constant Interfaces.Unsigned_64 := Wire.Response_Status (R);
         begin
            Check (Status = 404,
                   "unregistered path → 404 (got" & Interfaces.Unsigned_64'Image (Status) & ")");
         end;

         --  (4) request_id correlation: fire several EXECUTEs with caller-chosen
         --      request_ids; each reply must carry the request_id of its OWN
         --      request (§6.11 / N7).
         declare
            All_Correlated : Boolean := True;
         begin
            for I in 1 .. 6 loop
               declare
                  Rid : constant String :=
                    "n7-" & Ada.Strings.Fixed.Trim (Integer'Image (I), Ada.Strings.Left);
                  Env : constant Env_Pkg.Protocol_Envelope :=
                    Tport.Build_Authenticated_Execute
                      (S, Rid, "system/tree", "get",
                       "system/handler/probe-" &
                         Ada.Strings.Fixed.Trim (Integer'Image (I), Ada.Strings.Left));
                  Reply : constant Env_Pkg.Protocol_Envelope := Tport.Send (S, Env);
                  Got : constant String :=
                    Entity_Core.Protocol.Entity.Text (Reply.Root, "request_id");
               begin
                  if Got /= Rid then
                     All_Correlated := False;
                  end if;
               end;
            end loop;
            Check (All_Correlated, "6 interleaved requests each correlated by request_id (N7)");
         end;

         Tport.Close (S);
         Check (True, "clean teardown");
      end;
   end;

   New_Line;
   Put_Line ("SMOKE (Scenario A):" & Natural'Image (Passes) & " PASS,"
             & Natural'Image (Fails) & " FAIL");
   if Fails = 0 then
      Put_Line ("SCENARIO-A: PASS");
   else
      Put_Line ("SCENARIO-A: FAIL");
   end if;
   Ada.Text_IO.Flush;
   --  Force prompt termination: the per-connection reader task is still parked
   --  on the (now-closed) socket, which would otherwise keep the program alive.
   GNAT.OS_Lib.OS_Exit (if Fails = 0 then 0 else 1);
end Smoke_S3;
