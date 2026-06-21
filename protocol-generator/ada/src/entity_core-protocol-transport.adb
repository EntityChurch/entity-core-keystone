with Ada.Calendar;
with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Strings.Hash;
with Ada.Unchecked_Deallocation;
with Interfaces;
with System;
with System.Address_To_Access_Conversions;
with Entity_Core.Bytes;
with Entity_Core.Codec.Value;
with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Protocol.Identity;
with Entity_Core.Protocol.Capability;
with Entity_Core.Protocol.Wire;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Transport is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Cbor_Util;
   use Entity_Core.Protocol.Entity;
   package Id_Pkg renames Entity_Core.Protocol.Identity;
   package Cap renames Entity_Core.Protocol.Capability;
   package Wire renames Entity_Core.Protocol.Wire;
   package Hand renames Entity_Core.Protocol.Handlers;

   use type Interfaces.Unsigned_64;

   --  A pending-reply slot: holds the response envelope when it arrives.
   type Reply_Slot is record
      Ready : Boolean := False;
      Reply : Env_Pkg.Protocol_Envelope;
   end record;
   type Reply_Slot_Access is access all Reply_Slot;

   package Pending_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type        => String,
      Element_Type    => Reply_Slot_Access,
      Hash            => Ada.Strings.Hash,
      Equivalent_Keys => "=");

   ---------------------------------------------------------------------------
   --  Demux_Table — the §6.11 / N7 request_id correlation map, a PROTECTED
   --  OBJECT. The reader Routes a response into its waiting caller's slot; the
   --  caller polls the slot. Mutual exclusion on the map is language-enforced —
   --  the protected-object demux the profile fixed.
   ---------------------------------------------------------------------------
   protected type Demux_Table is
      procedure Register (Request_Id : String; Slot : Reply_Slot_Access);
      procedure Route (Request_Id : String; Reply : Env_Pkg.Protocol_Envelope;
                       Routed : out Boolean);
      procedure Unregister (Request_Id : String);
   private
      Pending : Pending_Maps.Map;
   end Demux_Table;

   protected body Demux_Table is
      procedure Register (Request_Id : String; Slot : Reply_Slot_Access) is
      begin
         Pending.Include (Request_Id, Slot);
      end Register;

      procedure Route (Request_Id : String; Reply : Env_Pkg.Protocol_Envelope;
                       Routed : out Boolean) is
         C : constant Pending_Maps.Cursor := Pending.Find (Request_Id);
      begin
         if Pending_Maps.Has_Element (C) then
            declare
               Slot : constant Reply_Slot_Access := Pending_Maps.Element (C);
            begin
               Slot.Reply := Reply;
               Slot.Ready := True;
            end;
            Routed := True;
         else
            Routed := False;
         end if;
      end Route;

      procedure Unregister (Request_Id : String) is
      begin
         if Pending.Contains (Request_Id) then
            Pending.Delete (Request_Id);
         end if;
      end Unregister;
   end Demux_Table;

   ---------------------------------------------------------------------------
   --  Write_Guard — serialize concurrent writers on one socket (§6.11: inbound
   --  responses + outbound requests share the stream). The protected procedure
   --  gives the mutual exclusion in-language.
   ---------------------------------------------------------------------------
   protected type Write_Guard is
      procedure Write (Socket : Sock.Socket_Type; Payload : Byte_Array);
   end Write_Guard;

   protected body Write_Guard is
      procedure Write (Socket : Sock.Socket_Type; Payload : Byte_Array) is
      begin
         Wire.Write_Frame (Socket, Payload);
      end Write;
   end Write_Guard;

   ---------------------------------------------------------------------------
   --  Connection — per-connection state + the reader task.
   ---------------------------------------------------------------------------
   task type Reader_Task (Conn : access Connection);
   type Reader_Task_Access is access Reader_Task;

   type Connection is limited record
      Socket  : Sock.Socket_Type;
      Peer    : Hand.Peer_Access;
      Conn_St : Hand.Conn_State;
      Demux   : Demux_Table;
      Writer  : Write_Guard;
      Reader  : Reader_Task_Access;
      Closed  : Boolean := False;
   end record;

   --  §6.11 reentry seam (forward decl — installed by the reader, defined below
   --  near Send where Await is in scope). Matches Hand.Outbound_Proc.
   function Connection_Outbound
     (Ctx : System.Address;
      Req : Env_Pkg.Protocol_Envelope;
      Rid : String;
      Ok  : out Boolean)
      return Env_Pkg.Protocol_Envelope;

   --------------------
   -- Set_No_Delay --
   --------------------
   procedure Set_No_Delay (S : Sock.Socket_Type) is
   begin
      --  §7b: TCP_NODELAY on every connection socket (Nagle off) — small
      --  EXECUTE_RESPONSE frames flush promptly (the Zig finding).
      Sock.Set_Socket_Option
        (S, Sock.IP_Protocol_For_TCP_Level, (Sock.No_Delay, True));
   exception
      when others => null;   --  best-effort; loopback still works without it
   end Set_No_Delay;

   ---------------------------------------------------------------------------
   --  Reentry-only async dispatch (§6.11). Needs_Async is True precisely for an
   --  inbound dispatch-outbound EXECUTE — the one handler that must originate
   --  back over this connection and await its reply (so it can't run on the
   --  reader, which has to demux that reply). Every other EXECUTE runs
   --  synchronously on the reader → no per-request task under the §7b load
   --  gates (sustained-load / churn stay cheap).
   ---------------------------------------------------------------------------
   function Needs_Async (Env : Env_Pkg.Protocol_Envelope) return Boolean is
      Uri : constant String := Text (Env.Root, "uri");
      Tail : constant String := "system/validate/dispatch-outbound";
   begin
      return Uri'Length >= Tail'Length
        and then Uri (Uri'Last - Tail'Length + 1 .. Uri'Last) = Tail;
   exception
      when others => return False;
   end Needs_Async;

   type Dispatch_Job is record
      Conn : Connection_Access;
      Env  : Env_Pkg.Protocol_Envelope;
   end record;
   type Dispatch_Job_Access is access Dispatch_Job;

   task type Dispatch_Task (Job : Dispatch_Job_Access);

   procedure Free_Job is new Ada.Unchecked_Deallocation
     (Dispatch_Job, Dispatch_Job_Access);

   task body Dispatch_Task is
      Conn : constant Connection_Access := Job.Conn;
      My   : Dispatch_Job_Access := Job;
   begin
      declare
         Is_Resp : Boolean;
         Resp : constant Env_Pkg.Protocol_Envelope :=
           Hand.Dispatch (Conn.Peer, Conn.Conn_St, Job.Env, Is_Resp);
      begin
         if Is_Resp and then not Conn.Closed then
            Conn.Writer.Write (Conn.Socket, Wire.Frame_Of_Envelope (Resp));
         end if;
      end;
      Free_Job (My);
   exception
      when others =>
         Free_Job (My);
   end Dispatch_Task;

   type Dispatch_Task_Access is access Dispatch_Task;

   procedure Start_Dispatch
     (Conn : Connection_Access; Env : Env_Pkg.Protocol_Envelope)
   is
      Job : constant Dispatch_Job_Access :=
        new Dispatch_Job'(Conn => Conn, Env => Env);
      T   : Dispatch_Task_Access;
      pragma Unreferenced (T);
   begin
      T := new Dispatch_Task (Job);   --  task owns + frees the Job
   end Start_Dispatch;

   ---------------------------------------------------------------------------
   --  Reader_Task body: the §6.11 demux loop. EXECUTE_RESPONSE → route; EXECUTE
   --  → dispatch + write the response. Inbound stays concurrent with any
   --  outbound the session issues because that runs on a different task (N6).
   ---------------------------------------------------------------------------
   task body Reader_Task is
   begin
      --  §6.11: install the reentry-outbound seam on this connection so a
      --  handler (dispatch-outbound) can originate back over the same socket.
      Conn.Conn_St.Outbound     := Connection_Outbound'Access;
      Conn.Conn_St.Outbound_Ctx := Conn.all'Address;
      Read_Loop :
      loop
         declare
            At_Eof  : Boolean;
            Payload : constant Byte_Array := Wire.Read_Frame (Conn.Socket, At_Eof);
         begin
            exit Read_Loop when At_Eof or else Conn.Closed;
            begin
               declare
                  Env : constant Env_Pkg.Protocol_Envelope :=
                    Wire.Envelope_Of_Frame (Payload);
               begin
                  if Type_Name (Env.Root) = "system/protocol/execute/response" then
                     declare
                        Rid    : constant String := Text (Env.Root, "request_id");
                        Routed : Boolean;
                     begin
                        Conn.Demux.Route (Rid, Env, Routed);
                     end;
                  elsif Needs_Async (Env) then
                     --  §6.11 reentry: a dispatch-outbound handler must
                     --  originate back over THIS connection and await its
                     --  reentry EXECUTE_RESPONSE. Run it on a child task so the
                     --  reader stays free to demux that response (the F-WB28
                     --  deadlock class). Bounded to the reentry op only → no
                     --  per-request task storm under the §7b load gates.
                     Start_Dispatch (Conn, Env);
                  else
                     --  All other inbound EXECUTEs dispatch synchronously on
                     --  the reader (one-task-per-connection, A-ADA-006 — the
                     --  store is the §4.8 protected object so cross-connection
                     --  dispatch is data-race-safe). No per-request task, so
                     --  the §7b sustained-load / churn gates stay cheap.
                     declare
                        Is_Resp : Boolean;
                        Resp : constant Env_Pkg.Protocol_Envelope :=
                          Hand.Dispatch (Conn.Peer, Conn.Conn_St, Env, Is_Resp);
                     begin
                        if Is_Resp and then not Conn.Closed then
                           Conn.Writer.Write
                             (Conn.Socket, Wire.Frame_Of_Envelope (Resp));
                        end if;
                     end;
                  end if;
               end;
            exception
               when others =>
                  null;   --  skip a malformed frame; keep reading (resilience)
            end;
         exception
            when others =>
               exit Read_Loop;   --  framing fault / closed socket ends the reader
         end;
      end loop Read_Loop;
      Conn.Closed := True;
   end Reader_Task;

   ---------------------------------------------------------------------------
   --  Listener accept loop (its own task).
   ---------------------------------------------------------------------------
   task type Accept_Task (L : Listener_Access);

   task body Accept_Task is
   begin
      Accept_Loop :
      loop
         exit Accept_Loop when L.Stopped;
         declare
            Client : Sock.Socket_Type;
            From   : Sock.Sock_Addr_Type;
         begin
            Sock.Accept_Socket (L.Server, Client, From);
            Set_No_Delay (Client);
            declare
               C : constant Connection_Access := new Connection;
            begin
               C.Socket := Client;
               C.Peer := L.Peer;
               --  one task per connection (A-ADA-006).
               C.Reader := new Reader_Task (C);
            end;
         exception
            when others =>
               exit Accept_Loop;   --  server socket closed → stop accepting
         end;
      end loop Accept_Loop;
   end Accept_Task;

   type Accept_Task_Access is access Accept_Task;

   --------------------
   -- Start_Listener --
   --------------------
   procedure Start_Listener
     (L          : out Listener_Access;
      Peer       : Hand.Peer_Access;
      Port       : Natural;
      Bound_Port : out Natural)
   is
      Lis : constant Listener_Access := new Listener;
      Acc : Accept_Task_Access;
      pragma Unreferenced (Acc);
   begin
      Sock.Create_Socket (Lis.Server);
      Sock.Set_Socket_Option (Lis.Server, Sock.Socket_Level, (Sock.Reuse_Address, True));
      Lis.Addr.Addr := Sock.Loopback_Inet_Addr;
      Lis.Addr.Port := Sock.Port_Type (Port);
      Sock.Bind_Socket (Lis.Server, Lis.Addr);
      Sock.Listen_Socket (Lis.Server, 64);
      Lis.Peer := Peer;
      declare
         Bound : constant Sock.Sock_Addr_Type := Sock.Get_Socket_Name (Lis.Server);
      begin
         Bound_Port := Natural (Bound.Port);
      end;
      Acc := new Accept_Task (Lis);
      L := Lis;
   end Start_Listener;

   ----------
   -- Stop --
   ----------
   procedure Stop (L : Listener_Access) is
   begin
      if L /= null then
         L.Stopped := True;
         begin
            Sock.Close_Socket (L.Server);
         exception
            when others => null;
         end;
      end if;
   end Stop;

   ---------------------------------------------------------------------------
   --  Client: send/await + the §4.1 handshake.
   ---------------------------------------------------------------------------

   --  Await a correlated reply on a registered slot. A bounded poll with a
   --  deadline keeps it simple and never deadlocks the reader (N7): the reader
   --  task fills Slot.Ready; we never block IN the reader.
   function Await
     (Conn : Connection_Access; Slot : Reply_Slot_Access; Request_Id : String)
      return Env_Pkg.Protocol_Envelope
   is
      use Ada.Calendar;
      Deadline : constant Time := Clock + 10.0;   --  10s loopback ceiling
   begin
      loop
         if Slot.Ready then
            Conn.Demux.Unregister (Request_Id);
            return Slot.Reply;
         end if;
         exit when Conn.Closed or else Clock > Deadline;
         delay 0.002;
      end loop;
      Conn.Demux.Unregister (Request_Id);
      raise Entity_Core.Errors.Transport_Error
        with "no correlated reply for " & Request_Id;
   end Await;

   ---------------------------------------------------------------------------
   --  §6.11 reentry seam — the connection-side outbound dispatch the handler
   --  layer calls via Conn_State.Outbound. Writes the outbound EXECUTE on the
   --  SAME inbound socket (serialized by Writer) and awaits the correlated
   --  EXECUTE_RESPONSE by request_id (the reader task fills the slot). The
   --  Ctx address is the Connection the inbound EXECUTE arrived on.
   ---------------------------------------------------------------------------
   package Conn_Conv is
     new System.Address_To_Access_Conversions (Connection);

   function Connection_Outbound
     (Ctx : System.Address;
      Req : Env_Pkg.Protocol_Envelope;
      Rid : String;
      Ok  : out Boolean)
      return Env_Pkg.Protocol_Envelope
   is
      Conn : constant Connection_Access :=
        Connection_Access (Conn_Conv.To_Pointer (Ctx));
      Slot : constant Reply_Slot_Access := new Reply_Slot;
   begin
      --  Register the request_id, write the outbound EXECUTE on the SAME socket
      --  (Writer-serialized), and await the correlated EXECUTE_RESPONSE. The
      --  per-connection reader (free because dispatch-outbound runs on a child
      --  task) routes the reply into Slot — the §6.11 demux that avoids the
      --  reentry deadlock under concurrent dispatch (t1_2).
      Conn.Demux.Register (Rid, Slot);
      Conn.Writer.Write (Conn.Socket, Wire.Frame_Of_Envelope (Req));
      declare
         Reply : constant Env_Pkg.Protocol_Envelope := Await (Conn, Slot, Rid);
      begin
         Ok := True;
         return Reply;
      end;
   exception
      when others =>
         Ok := False;
         return Env_Pkg.Of_Root
           (Wire.Make_Response (Rid, 503, Wire.Error_Result ("reentry_failed")));
   end Connection_Outbound;

   ----------
   -- Send --
   ----------
   function Send (S : Session_Access; Request : Env_Pkg.Protocol_Envelope)
                  return Env_Pkg.Protocol_Envelope is
      Rid  : constant String := Text (Request.Root, "request_id");
      Slot : constant Reply_Slot_Access := new Reply_Slot;
   begin
      S.Conn.Demux.Register (Rid, Slot);
      S.Conn.Writer.Write (S.Conn.Socket, Wire.Frame_Of_Envelope (Request));
      return Await (S.Conn, Slot, Rid);
   exception
      when others =>
         return Reply : Env_Pkg.Protocol_Envelope do
            Reply := Env_Pkg.Of_Root
              (Wire.Make_Response (Rid, 503, Wire.Error_Result ("connection_broken")));
         end return;
   end Send;

   ---------------------
   -- Next_Request_Id --
   ---------------------
   function Next_Request_Id (S : Session_Access) return String is
   begin
      S.Req_Counter := S.Req_Counter + 1;
      declare
         Img : constant String := Integer'Image (S.Req_Counter);
      begin
         return "req-" & Img (Img'First + 1 .. Img'Last);   --  drop leading space
      end;
   end Next_Request_Id;

   ---------------
   -- Handshake --
   ---------------
   --  Drive the §4.1 forward handshake as initiator: hello then authenticate.
   --  On success populate the session with the §4.4 capability the responder
   --  minted (kept inside the session for subsequent authenticated EXECUTEs).
   procedure Handshake (S : Session_Access) is
      Local : constant Id_Pkg.Peer_Identity := Hand.Identity (S.Initiator);
   begin
      --  ── hello ──
      declare
         Nonce : constant Byte_Array (1 .. 32) := (others => 16#11#);
         Hello : constant Materialized_Entity :=
           Make ("system/protocol/connect/hello",
             Map_Of (((Key => K ("peer_id"),      Value => Make_Text (Id_Pkg.Peer_Id (Local))),
                      (Key => K ("nonce"),        Value => Make_Bytes (Nonce)),
                      (Key => K ("protocols"),    Value => Text_Array1 ("entity-core/1.0")),
                      (Key => K ("timestamp"),    Value => Make_Uint (0)),
                      (Key => K ("hash_formats"), Value => Text_Array1 ("ecfv1-sha256")),
                      (Key => K ("key_types"),    Value => Text_Array1 ("ed25519")))));
         R1 : constant Env_Pkg.Protocol_Envelope :=
           Send (S, Env_Pkg.Of_Root
             (Wire.Make_Execute (Next_Request_Id (S), "system/protocol/connect", "hello", Hello)));
      begin
         if Wire.Response_Status (R1) /= 200 then
            raise Entity_Core.Errors.Authentication_Error with "hello failed";
         end if;
         declare
            Found : Boolean;
            Remote_Hello : constant Materialized_Entity := Wire.Response_Result (R1, Found);
            Remote_Pid : constant String := Text (Remote_Hello, "peer_id");
            Nonce_Found : Boolean;
            Remote_Nonce : constant Byte_Array :=
              Byte_Field (Remote_Hello, "nonce", Nonce_Found);
         begin
            if Remote_Pid'Length <= S.Remote_Buf'Length then
               S.Remote_Buf (1 .. Remote_Pid'Length) := Remote_Pid;
               S.Remote_Len := Remote_Pid'Length;
            end if;

            --  ── authenticate ──
            declare
               Auth : constant Materialized_Entity :=
                 Make ("system/protocol/connect/authenticate",
                   Map_Of (((Key => K ("peer_id"),    Value => Make_Text (Id_Pkg.Peer_Id (Local))),
                            (Key => K ("public_key"), Value => Make_Bytes (Id_Pkg.Public_Key (Local))),
                            (Key => K ("key_type"),   Value => Make_Text ("ed25519")),
                            (Key => K ("nonce"),      Value => Make_Bytes (Remote_Nonce)))));
               Auth_Sig : constant Materialized_Entity := Id_Pkg.Sign (Local, Auth);
               R2_Env : Env_Pkg.Protocol_Envelope :=
                 Env_Pkg.Of_Root
                   (Wire.Make_Execute (Next_Request_Id (S), "system/protocol/connect",
                                       "authenticate", Auth));
            begin
               Env_Pkg.Add (R2_Env, Id_Pkg.Peer_Entity (Local));
               Env_Pkg.Add (R2_Env, Auth_Sig);
               declare
                  R2 : constant Env_Pkg.Protocol_Envelope := Send (S, R2_Env);
               begin
                  if Wire.Response_Status (R2) /= 200 then
                     raise Entity_Core.Errors.Authentication_Error with "authenticate failed";
                  end if;
                  --  Capture the §4.4 minted capability: the grant result names
                  --  the token by hash; the token + granter identity + cap
                  --  signature ride in R2.included. Stash them for subsequent
                  --  authenticated EXECUTEs (§5.8 authority chain in `included`).
                  declare
                     Grant_Found : Boolean;
                     Grant : constant Materialized_Entity := Wire.Response_Result (R2, Grant_Found);
                     Tok_Found, Tok_E_Found : Boolean;
                     Tok_H : constant Byte_Array := Byte_Field (Grant, "token", Tok_Found);
                  begin
                     if Grant_Found and then Tok_Found then
                        declare
                           Token : constant Materialized_Entity :=
                             Env_Pkg.Included_Get (R2, Tok_H, Tok_E_Found);
                        begin
                           if Tok_E_Found then
                              declare
                                 Gr_Found, Sig_Found : Boolean;
                                 Gr_H : constant Byte_Array := Byte_Field (Token, "granter", Gr_Found);
                                 Granter : constant Materialized_Entity :=
                                   (if Gr_Found
                                    then Env_Pkg.Included_Get (R2, Gr_H, Gr_Found)
                                    else Make ("primitive/any", Empty_Map));
                                 Sig : constant Materialized_Entity :=
                                   Cap.Find_Signature (R2, Hash (Token), Sig_Found);
                              begin
                                 if Gr_Found and then Sig_Found then
                                    S.Cap_Token := Token;
                                    S.Cap_Granter := Granter;
                                    S.Cap_Sig := Sig;
                                    S.Has_Cap := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end;
               end;
            end;
         end;
      end;
   end Handshake;

   ----------
   -- Dial --
   ----------
   procedure Dial
     (S          : out Session_Access;
      Initiator  : Hand.Peer_Access;
      Host       : String;
      Port       : Natural)
   is
      Sess : constant Session_Access := new Session;
      C    : constant Connection_Access := new Connection;
      Addr : Sock.Sock_Addr_Type;
   begin
      Sock.Create_Socket (C.Socket);
      Addr.Addr := Sock.Inet_Addr (Host);
      Addr.Port := Sock.Port_Type (Port);
      Sock.Connect_Socket (C.Socket, Addr);
      Set_No_Delay (C.Socket);
      C.Peer := Initiator;          --  client also serves (§6.11 reentry capable)
      C.Reader := new Reader_Task (C);
      Sess.Conn := C;
      Sess.Initiator := Initiator;
      S := Sess;
      Handshake (Sess);
   end Dial;

   --------------------
   -- Remote_Peer_Id --
   --------------------
   function Remote_Peer_Id (S : Session_Access) return String is
     (S.Remote_Buf (1 .. S.Remote_Len));

   --------------------------------
   -- Build_Authenticated_Execute --
   --------------------------------
   function Build_Authenticated_Execute
     (S          : Session_Access;
      Request_Id : String;
      Uri        : String;
      Operation  : String;
      Resource_Target : String := "")
      return Env_Pkg.Protocol_Envelope
   is
      Resource : constant Ecf_Value :=
        (if Resource_Target = "" then Make_Null
         else Wire.Resource_Target (Resource_Target));
      Cap_H : constant Byte_Array :=
        (if S.Has_Cap then Byte_Array (Hash (S.Cap_Token)) else Empty_Bytes);
      Exec : constant Materialized_Entity :=
        Wire.Make_Execute (Request_Id, Uri, Operation, Wire.Empty_Params,
                           Id_Pkg.Identity_Hash (Hand.Identity (S.Initiator)),
                           Cap_H, Resource);
      Exec_Sig : constant Materialized_Entity :=
        Id_Pkg.Sign (Hand.Identity (S.Initiator), Exec);
      Env : Env_Pkg.Protocol_Envelope := Env_Pkg.Of_Root (Exec);
   begin
      --  §5.8 authority chain in `included`: the minted cap token + granter
      --  identity + cap signature, then our own identity + the request sig.
      if S.Has_Cap then
         Env_Pkg.Add (Env, S.Cap_Token);
         Env_Pkg.Add (Env, S.Cap_Granter);
         Env_Pkg.Add (Env, S.Cap_Sig);
      end if;
      Env_Pkg.Add (Env, Id_Pkg.Peer_Entity (Hand.Identity (S.Initiator)));
      Env_Pkg.Add (Env, Exec_Sig);
      return Env;
   end Build_Authenticated_Execute;

   -------------
   -- Execute --
   -------------
   function Execute
     (S         : Session_Access;
      Uri       : String;
      Operation : String;
      Resource_Target : String := "")
      return Env_Pkg.Protocol_Envelope
   is
      Rid : constant String := Next_Request_Id (S);
   begin
      return Send (S, Build_Authenticated_Execute (S, Rid, Uri, Operation, Resource_Target));
   end Execute;

   -----------
   -- Close --
   -----------
   procedure Close (S : Session_Access) is
   begin
      if S /= null and then S.Conn /= null then
         S.Conn.Closed := True;
         begin
            Sock.Close_Socket (S.Conn.Socket);
         exception
            when others => null;
         end;
      end if;
   end Close;

end Entity_Core.Protocol.Transport;
