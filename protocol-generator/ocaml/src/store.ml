(* Storage — the two layers of §1.7:

     Content Store: hash  → entity   (immutable, content-addressed, dedup)
     Entity Tree:   path  → hash      (mutable location index)

   In-memory minimal impl (the S3 foundation surface). A path may be both bound
   to an entity AND a prefix for child paths (§1.7) — listing reports the two
   dimensions independently. Paths here are the canonical absolute form
   "/{peer_id}/rest" (§1.4); the peer canonicalizes before calling in. *)

(* ── emit pathway (§6.10 / v7.74 §6.13(c)) ────────────────────────────────────

   Tree writes produce events; the bus delivers them to registered consumers. The
   hook is LIVE even with zero consumers (events are produced and discarded) so a
   future extension can register a consumer without the peer being rebuilt — the
   §6.13(c) MUST. A core-only peer registers zero consumers. Field names are the
   §6.10 normative inventory; [event_type] derives from the null-hash rule. A bind
   to a [system/deletion-marker] fires "modified", NOT "deleted" — classification
   keys on a null [new_hash] only (bind always has a new_hash), never on type. *)

(* Content-store event (§6.10 Store step): carries (hash, entity) ONLY — no context. *)
type content_store_event = { hash : string; entity : Model.entity }

(* Tree-change event (§6.10 Bind step). [context] is impl-defined (§6.8a); inert in core. *)
type tree_change_event = {
  event_type : string;                 (* "created" | "modified" | "deleted" *)
  path : string;
  new_hash : string option;
  previous_hash : string option;
}

(* ── thread safety ────────────────────────────────────────────────────────────

   `transport.ml` spawns a THREAD PER CONNECTION and another per inbound EXECUTE, and
   both tables below are shared by all of them. `Hashtbl` is not safe under concurrent
   mutation, and the failure is not an exception — it is a WRONG ANSWER. OCaml 5.2.1's
   `Hashtbl.resize` assigns the new, EMPTY bucket array into `h.data` before repopulating
   it, and `insert_all_buckets` opens with another large allocation, i.e. a poll point at
   which the table is observable as empty (read in the pinned toolchain, not inferred from
   another release). A concurrent `find_opt` there misses a key that is present, so a
   `tree get` answers 404 for an entity the peer holds.

   That was live: `concurrency/t2_1_sustained_load` failed 2 of 40 `--profile core` runs
   with "4/10000 sustained requests dropped (first error: tree get status 404)". Scoping
   §6.5 signature ingestion (peer.ml) removed the driver that pushed the table across
   resize thresholds — 0 of 80 after — but that is the driver and this is the defect: any
   concurrent `tree.put` can still grow the table, and `listing` iterates one table while
   another thread may be writing it. One mutex over both tables closes the class.

   EVENTS FIRE AFTER THE LOCK IS RELEASED. §6.10 delivery is sync-inline and a consumer is
   third-party code that may call back into the store; holding the lock across it would
   deadlock on a non-recursive mutex. Each operation therefore computes its events under
   the lock and emits them outside it. Internal `*_locked` helpers exist because `bind`
   performs the Store step and the Bind step as ONE critical section — a reader must never
   see a path bound to an entity the content store does not yet hold. *)
type t = {
  mu : Mutex.t;                                (* guards `content` and `tree` *)
  content : (string, Model.entity) Hashtbl.t;  (* content_hash bytes → entity *)
  tree : (string, string) Hashtbl.t;           (* path → content_hash bytes *)
  mutable content_consumers : (content_store_event -> unit) list;
  mutable tree_consumers : (tree_change_event -> unit) list;
}

let create () : t =
  { mu = Mutex.create (); content = Hashtbl.create 512; tree = Hashtbl.create 512;
    content_consumers = []; tree_consumers = [] }

(* Run [f] under the store lock, releasing it on the exception path too. *)
let with_lock (t : t) (f : unit -> 'a) : 'a =
  Mutex.lock t.mu;
  match f () with
  | v -> Mutex.unlock t.mu; v
  | exception e -> Mutex.unlock t.mu; raise e

(* Register an emit consumer (§6.10 consumer-registration primitive). Reachable any
   time, incl. post-bootstrap. Delivery is sync-inline (impl-defined per §9.4). *)
let register_content_consumer (t : t) (f : content_store_event -> unit) : unit =
  t.content_consumers <- f :: t.content_consumers

let register_tree_consumer (t : t) (f : tree_change_event -> unit) : unit =
  t.tree_consumers <- f :: t.tree_consumers

let derive_event_type previous_hash new_hash =
  match previous_hash, new_hash with
  | None, _ -> "created"
  | _, None -> "deleted"
  | _ -> "modified"

(* ── content store ────────────────────────────────────────────────────────── *)

(* §6.10 Store step: a content-store event fires only when the entity is new to the
   store (a re-put of an existing hash fires nothing). A direct put executes only this. *)
(* Caller holds t.mu. Returns the events to fire once it is released. *)
let put_entity_locked (t : t) (e : Model.entity) : content_store_event list =
  if not (Hashtbl.mem t.content e.hash) then begin
    Hashtbl.replace t.content e.hash e;
    [ { hash = e.hash; entity = e } ]
  end else []

let fire_content (t : t) (evs : content_store_event list) : unit =
  List.iter (fun ev -> List.iter (fun f -> f ev) t.content_consumers) evs

let put_entity (t : t) (e : Model.entity) : unit =
  fire_content t (with_lock t (fun () -> put_entity_locked t e))

let get_by_hash (t : t) (h : string) : Model.entity option =
  with_lock t (fun () -> Hashtbl.find_opt t.content h)

(* ── entity tree (location index) ─────────────────────────────────────────── *)

(* §6.10 Bind step: a tree-change event fires when the binding at the path changes
   (no event on a re-bind to the current hash). [bind] runs Store then Bind. *)
let bind (t : t) ~(path : string) (e : Model.entity) : unit =
  (* Store step and Bind step are ONE critical section: a concurrent reader must not be
     able to see the path bound to an entity the content store does not hold yet. *)
  let cevs, tevs =
    with_lock t (fun () ->
      let cevs = put_entity_locked t e in
      let previous = Hashtbl.find_opt t.tree path in
      let changed =
        match previous with None -> true | Some h -> not (String.equal h e.hash) in
      Hashtbl.replace t.tree path e.hash;
      let tevs =
        if changed then
          [ { event_type = derive_event_type previous (Some e.hash);
              path; new_hash = Some e.hash; previous_hash = previous } ]
        else [] in
      (cevs, tevs))
  in
  fire_content t cevs;
  List.iter (fun ev -> List.iter (fun f -> f ev) t.tree_consumers) tevs

let unbind (t : t) ~(path : string) : unit =
  let tevs =
    with_lock t (fun () ->
      let previous = Hashtbl.find_opt t.tree path in
      Hashtbl.remove t.tree path;
      match previous with
      | None -> []
      | Some _ ->
          [ { event_type = "deleted"; path; new_hash = None; previous_hash = previous } ])
  in
  List.iter (fun ev -> List.iter (fun f -> f ev) t.tree_consumers) tevs

let hash_at (t : t) ~(path : string) : string option =
  with_lock t (fun () -> Hashtbl.find_opt t.tree path)

let get_at (t : t) ~(path : string) : Model.entity option =
  (* One critical section, not `hash_at` then `get_by_hash`: two separately-locked
     lookups can straddle a concurrent unbind/rebind and answer from a torn view. *)
  with_lock t (fun () ->
    match Hashtbl.find_opt t.tree path with
    | Some h -> Hashtbl.find_opt t.content h
    | None -> None)

(* One-level listing under [prefix] (a path ending in "/", or the empty key after
   the peer segment). Returns (segment, hash option, has_children) per
   system/tree/listing-entry (§3.9). A bound path contributes a hash; a path that
   is also a prefix of deeper paths contributes has_children. *)
let listing (t : t) ~(prefix : string) : (string * string option * bool) list =
  let prefix = if String.length prefix > 0 && prefix.[String.length prefix - 1] = '/'
    then prefix else prefix ^ "/" in
  let plen = String.length prefix in
  (* child-segment → (bound hash option, has deeper children) *)
  let acc : (string, string option ref * bool ref) Hashtbl.t = Hashtbl.create 64 in
  let note seg hash_opt deeper =
    match Hashtbl.find_opt acc seg with
    | Some (h, c) ->
        (match hash_opt with Some _ -> h := hash_opt | None -> ());
        if deeper then c := true
    | None -> Hashtbl.replace acc seg (ref hash_opt, ref deeper) in
  (* The iteration is inside the lock: `Hashtbl.iter` over a table another thread is
     writing can traverse a bucket array that is being replaced. `acc` is local, so it
     needs none. No consumer is invoked here, so there is nothing to defer. *)
  with_lock t (fun () ->
    Hashtbl.iter
      (fun path hash ->
        if String.length path > plen && String.sub path 0 plen = prefix then begin
          let rest = String.sub path plen (String.length path - plen) in
          match String.index_opt rest '/' with
          | None -> note rest (Some hash) false        (* direct child, bound *)
          | Some i -> note (String.sub rest 0 i) None true  (* deeper child path *)
        end)
      t.tree);
  Hashtbl.fold (fun seg (h, c) acc -> (seg, !h, !c) :: acc) acc []
  |> List.sort (fun (a, _, _) (b, _, _) -> String.compare a b)
