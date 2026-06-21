(* Transport (L4) — TCP listener + per-connection serve loop via stdlib
   [Unix] + [Thread] (§1.6 framing, §4.8 inbound concurrency, §6.11 reentry).

   Concurrency model: one reader thread per connection demuxes inbound frames
   (§6.11). An EXECUTE_RESPONSE is routed to the awaiting outbound caller by
   [request_id]; an EXECUTE is dispatched on its OWN thread (§4.8) so a handler
   that originates an outbound EXECUTE (§6.13(b)) and awaits its response does NOT
   block the reader — the reader keeps reading and routes the response back. Writes
   (inbound responses + outbound requests share the fd) are serialized by a mutex.

   The handler-facing outbound seam (§6.13(b)) is the per-connection [outbound]
   primitive below, exposed to handlers via [Peer.conn.outbound]. Even though no
   core handler originates, the seam is present and routed through §6.11 reentry —
   the substrate must support a handler-initiated outbound the moment one is
   registered (§6.13(a)). [Condition.wait] has no stdlib timeout; a never-arriving
   response is bounded by connection close (which broadcasts all pending waiters). *)

type io = {
  fd : Unix.file_descr;
  write_mutex : Mutex.t;
  pending_mutex : Mutex.t;
  pending : (string, Model.envelope option ref * Condition.t) Hashtbl.t;
  mutable closed : bool;
}

let make_io (fd : Unix.file_descr) : io =
  { fd; write_mutex = Mutex.create (); pending_mutex = Mutex.create ();
    pending = Hashtbl.create 16; closed = false }

(* Serialized framed write (responses + outbound requests share the fd). *)
let write_framed (io : io) (env : Model.envelope) : unit =
  Mutex.lock io.write_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock io.write_mutex)
    (fun () -> Wire.write_frame io.fd (Wire.frame_of_envelope env))

(* Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11 demux). *)
let route_response (io : io) (env : Model.envelope) : unit =
  let request_id = Option.value ~default:"" (Model.text_field env.Model.root "request_id") in
  Mutex.lock io.pending_mutex;
  (match Hashtbl.find_opt io.pending request_id with
   | Some (slot, cond) -> slot := Some env; Condition.broadcast cond
   | None -> ());
  Mutex.unlock io.pending_mutex

(* §6.13(b) outbound primitive: send a request envelope, await its correlated
   EXECUTE_RESPONSE. Blocks the calling (dispatch worker) thread; the reader routes
   the response. Returns None if the connection closes first. *)
let outbound (io : io) (request : Model.envelope) : Model.envelope option =
  let request_id = Option.value ~default:"" (Model.text_field request.Model.root "request_id") in
  let slot = ref None in
  let cond = Condition.create () in
  Mutex.lock io.pending_mutex;
  Hashtbl.replace io.pending request_id (slot, cond);
  Mutex.unlock io.pending_mutex;
  write_framed io request;
  Mutex.lock io.pending_mutex;
  while !slot = None && not io.closed do
    Condition.wait cond io.pending_mutex
  done;
  Hashtbl.remove io.pending request_id;
  Mutex.unlock io.pending_mutex;
  !slot

(* Wake every pending outbound waiter on connection close. *)
let close_io (io : io) : unit =
  Mutex.lock io.pending_mutex;
  io.closed <- true;
  Hashtbl.iter (fun _ (_, cond) -> Condition.broadcast cond) io.pending;
  Mutex.unlock io.pending_mutex

(* The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on its
   own thread (§4.8). [on_execute] dispatches one inbound EXECUTE and writes its
   response. Returns when the connection closes / a malformed frame ends it. *)
let read_loop (io : io) ~(on_execute : Model.envelope -> unit) : unit =
  let rec loop () =
    match (try Some (Wire.read_frame io.fd) with Wire.Closed | End_of_file | Unix.Unix_error _ | Failure _ -> None) with
    | None -> ()
    | Some payload ->
        (match (try Some (Wire.envelope_of_frame payload) with _ -> None) with
         | None -> ()  (* malformed frame: §3.3 invalid → drop; loop continues *)
         | Some env ->
             if String.equal env.Model.root.Model.typ "system/protocol/execute/response" then
               route_response io env
             else
               let _ : Thread.t = Thread.create on_execute env in ());
        loop ()
  in
  (try loop () with _ -> ())

(* Serve one accepted connection. A fresh per-connection [Peer.conn] holds the
   handshake state and the §6.13(b) outbound seam (wired to this connection's io). *)
let serve_connection (peer : Peer.t) (fd : Unix.file_descr) : unit =
  let io = make_io fd in
  let conn = Peer.new_conn () in
  conn.Peer.outbound <- Some (fun req -> outbound io req);
  let on_execute env =
    (* Per-request isolation: an exception on one adversarial request must NOT tear
       down the connection (§3.3 every EXECUTE receives a response). *)
    let resp = try Peer.dispatch peer conn env with _ -> Peer.internal_error_response env in
    match resp with
    | Some resp -> (try write_framed io resp with _ -> ())
    | None -> ()
  in
  read_loop io ~on_execute;
  close_io io;
  (try Unix.close fd with _ -> ())

(* Listen on 127.0.0.1:[port] (0 = auto). Returns the socket and the bound port. *)
let listen ~(port : int) : Unix.file_descr * int =
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
  Unix.listen sock 64;
  let bound =
    match Unix.getsockname sock with Unix.ADDR_INET (_, p) -> p | _ -> port
  in
  (sock, bound)

let accept_loop (peer : Peer.t) (sock : Unix.file_descr) : unit =
  let rec loop () =
    match (try Some (Unix.accept sock) with _ -> None) with
    | Some (fd, _) ->
        let _ : Thread.t = Thread.create (fun () -> serve_connection peer fd) () in
        loop ()
    | None -> ()
  in
  loop ()
