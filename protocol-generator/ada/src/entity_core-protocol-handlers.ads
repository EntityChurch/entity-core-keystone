--  Entity_Core.Protocol.Handlers — the handler contract + the four MUST system
--  handlers + the §6.5 dispatch chain (the peer "brain").
--
--  This is the pure protocol layer: a function from an inbound envelope to an
--  outbound EXECUTE_RESPONSE envelope. Transport (tasks / sockets / demux) lives
--  in Entity_Core.Protocol.Transport and is NOT visible here — the brain is
--  synchronous and testable in isolation; the store it touches is the §4.8
--  protected object, so concurrent inbound dispatches are data-race-safe by
--  construction (Dispatch may run on many connection tasks at once).
--
--  IDIOM (the single-dispatch ladder, profile [concurrency]/[idiom]): each MUST
--  handler is a tagged type deriving Handler with a dispatching Handle
--  primitive; the operation switch is a CASE statement inside each Handle. This
--  is the Ada OO analogue of the Java nested-handler / switch ladder and the C#
--  match — the §6.6 dispatch KEY is (handler, operation); the mechanism (Ada
--  tagged dispatch + a case ladder) is idiom, not protocol.
--
--  HANDLER INTERFACE CONTRACT only — NO concrete domain handlers (local/files,
--  …). The §7a system/validate/* conformance handlers are built behind the
--  Validate opt-in (host --validate, OFF by default).

with System;
with Entity_Core.Bytes;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Envelope;
with Entity_Core.Protocol.Identity;
with Entity_Core.Protocol.Store;

package Entity_Core.Protocol.Handlers is

   use Entity_Core.Bytes;

   ---------------------------------------------------------------------------
   --  Per-connection handshake state (§4.2). One Conn_State per accepted
   --  connection; the transport owns it and passes it into Dispatch.
   ---------------------------------------------------------------------------
   Max_Pid : constant := 64;
   Nonce_Length : constant := 32;

   --  §6.11 reentry seam. The transport installs Outbound on each accepted
   --  connection: it writes Req (an outbound EXECUTE envelope) on the SAME
   --  socket and blocks for the matching EXECUTE_RESPONSE (request_id demux),
   --  returning it. A null Outbound means "no reentry channel" (e.g. the
   --  in-isolation brain tests) → the handler honest-fails. The result-out
   --  Ok flag distinguishes a delivered response from a timeout/closed link.
   type Outbound_Proc is access function
     (Ctx : System.Address;
      Req : Entity_Core.Protocol.Envelope.Protocol_Envelope;
      Rid : String;
      Ok  : out Boolean)
      return Entity_Core.Protocol.Envelope.Protocol_Envelope;

   type Conn_State is record
      Established  : Boolean := False;
      Issued_Nonce : Byte_Array (1 .. Nonce_Length) := (others => 0);
      Has_Nonce    : Boolean := False;
      Hello_Pid    : String (1 .. Max_Pid) := (others => ' ');
      Hello_Pid_Len : Natural := 0;
      --  §6.11 reentry: outbound-over-the-inbound-connection seam.
      Outbound     : Outbound_Proc := null;
      Outbound_Ctx : System.Address := System.Null_Address;
   end record;

   ---------------------------------------------------------------------------
   --  The peer: bootstrap state + handler registry + the dispatch chain.
   ---------------------------------------------------------------------------
   type Peer_Type is limited private;
   type Peer_Access is access all Peer_Type;

   --  Construct + bootstrap a peer from a 32-byte seed. Open_Grants selects the
   --  degenerate [default → *] admin seed (non-conformant debug); Validate
   --  bootstraps the §7a conformance handlers (OFF by default).
   procedure Create
     (Peer        : out Peer_Access;
      Seed        : Entity_Core.Crypto.Seed_Bytes;
      Open_Grants : Boolean := False;
      Validate    : Boolean := False);

   function Local_Peer (Peer : Peer_Access) return String;
   function Identity (Peer : Peer_Access)
                      return Entity_Core.Protocol.Identity.Peer_Identity;
   function Store (Peer : Peer_Access)
                   return access Entity_Core.Protocol.Store.Safe_Store;

   --  The §6.5 dispatch chain. Returns the EXECUTE_RESPONSE envelope for an
   --  inbound EXECUTE, or sets Is_Response False for a non-EXECUTE root (§3.3
   --  server side ignores non-EXECUTE — the transport closes such a connection).
   function Dispatch
     (Peer : Peer_Access;
      Conn : in out Conn_State;
      Env  : Entity_Core.Protocol.Envelope.Protocol_Envelope;
      Is_Response : out Boolean)
      return Entity_Core.Protocol.Envelope.Protocol_Envelope;

private

   use Entity_Core.Protocol.Identity;

   type Peer_Type is limited record
      Id          : Peer_Identity;
      St          : Entity_Core.Protocol.Store.Store_Access;
      Local_Buf   : String (1 .. Max_Pid) := (others => ' ');
      Local_Len   : Natural := 0;
      Open_Grants : Boolean := False;
      Validate    : Boolean := False;
   end record;

end Entity_Core.Protocol.Handlers;
