--  Entity_Core.Protocol.Transport — TCP listener + dialer + connection tasks
--  (L4). THE Ada concurrency idiom in action (profile [concurrency], A-ADA-006).
--
--  TASK TOPOLOGY DECISION (A-ADA-006, decided at S3): ONE TASK PER CONNECTION.
--  The accept loop spawns a Connection_Task for each accepted socket; the dialer
--  spawns one for the client side. Rationale: GNAT maps tasks to OS threads, so
--  a blocking socket read in one connection's task does NOT stall any other
--  connection (no cooperative-pool starvation — the §7b Swift trap is sidestepped
--  STRUCTURALLY, not by a backpressure knob). A bounded pool would have to keep
--  socket I/O per-task / non-blocking to avoid that trap; one-task-per-connection
--  removes the question entirely, and the §4.8 store-safety is already handled by
--  the protected-object store (so the tasks share no unsynchronized state). This
--  is the simplest topology that satisfies N6 (inbound concurrent with outbound)
--  + N7 (reentrant demux) for a --profile core peer.
--
--  §6.11 / N7 DEMUX: each connection carries a PROTECTED-OBJECT request_id map
--  (Demux_Table). An inbound EXECUTE_RESPONSE is routed to its awaiting outbound
--  caller by request_id; an inbound EXECUTE is dispatched (the response written
--  back on the same socket). Writes are serialized by a protected Write_Lock per
--  connection (inbound responses + outbound requests share the stream).
--
--  §7b TRANSPORT: TCP_NODELAY is set on every connection socket (Nagle off) so
--  small EXECUTE_RESPONSE frames flush promptly (the Zig finding).

with GNAT.Sockets;
with Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Envelope;
with Entity_Core.Protocol.Handlers;

package Entity_Core.Protocol.Transport is

   package Sock renames GNAT.Sockets;
   package Env_Pkg renames Entity_Core.Protocol.Envelope;

   ---------------------------------------------------------------------------
   --  Server: a running listener bound to 127.0.0.1:port.
   ---------------------------------------------------------------------------
   type Listener is limited private;
   type Listener_Access is access Listener;

   --  Bind 127.0.0.1:Port (0 => auto) and spawn the accept loop. Returns the
   --  bound port via Bound_Port.
   procedure Start_Listener
     (L          : out Listener_Access;
      Peer       : Entity_Core.Protocol.Handlers.Peer_Access;
      Port       : Natural;
      Bound_Port : out Natural);

   procedure Stop (L : Listener_Access);

   ---------------------------------------------------------------------------
   --  Client: a dialed, authenticated session (§4.4) — drives the loopback.
   ---------------------------------------------------------------------------
   type Session is limited private;
   type Session_Access is access Session;

   --  Open a client connection to Host:Port and complete the §4.1 handshake as
   --  initiator (hello then authenticate). On success the session holds the
   --  remote peer_id + the §4.4 capability the responder minted.
   procedure Dial
     (S          : out Session_Access;
      Initiator  : Entity_Core.Protocol.Handlers.Peer_Access;
      Host       : String;
      Port       : Natural);

   function Remote_Peer_Id (S : Session_Access) return String;

   --  Send an authenticated EXECUTE and await its correlated EXECUTE_RESPONSE
   --  (request_id demux). The §5.8 authority chain travels in `included`.
   function Execute
     (S         : Session_Access;
      Uri       : String;
      Operation : String;
      Resource_Target : String := "")
      return Env_Pkg.Protocol_Envelope;

   --  Send a raw EXECUTE envelope (caller-built) and await its correlated reply.
   function Send (S : Session_Access; Request : Env_Pkg.Protocol_Envelope)
                  return Env_Pkg.Protocol_Envelope;

   --  Build a fully-authenticated EXECUTE envelope for the given request_id +
   --  resource target (signed, with the §4.4 cap + identities in `included`).
   --  Exposed so a harness can exercise request_id correlation with caller-
   --  chosen request_ids (N7).
   function Build_Authenticated_Execute
     (S          : Session_Access;
      Request_Id : String;
      Uri        : String;
      Operation  : String;
      Resource_Target : String := "")
      return Env_Pkg.Protocol_Envelope;

   function Next_Request_Id (S : Session_Access) return String;

   procedure Close (S : Session_Access);

private

   --  Forward declarations of the connection machinery (in the body).
   --  `access all` so the §6.11 reentry seam can recover a Connection_Access
   --  from a System.Address (Address_To_Access_Conversions yields access-all).
   type Connection;
   type Connection_Access is access all Connection;

   type Listener is limited record
      Server  : Sock.Socket_Type;
      Addr    : Sock.Sock_Addr_Type;
      Peer    : Entity_Core.Protocol.Handlers.Peer_Access;
      Stopped : Boolean := False;
   end record;

   type Session is limited record
      Conn       : Connection_Access;
      Initiator  : Entity_Core.Protocol.Handlers.Peer_Access;
      Remote_Buf : String (1 .. 64) := (others => ' ');
      Remote_Len : Natural := 0;
      Req_Counter : Natural := 0;
      --  the §4.4 capability the responder minted at authenticate, plus the
      --  granter identity + cap signature it carried — attached to subsequent
      --  authenticated EXECUTEs in `included` (§5.8).
      Has_Cap    : Boolean := False;
      Cap_Token  : Entity_Core.Protocol.Entity.Materialized_Entity;
      Cap_Granter : Entity_Core.Protocol.Entity.Materialized_Entity;
      Cap_Sig    : Entity_Core.Protocol.Entity.Materialized_Entity;
   end record;

end Entity_Core.Protocol.Transport;
