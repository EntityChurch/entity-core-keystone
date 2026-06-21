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

type t = {
  content : (string, Model.entity) Hashtbl.t;  (* content_hash bytes → entity *)
  tree : (string, string) Hashtbl.t;           (* path → content_hash bytes *)
  mutable content_consumers : (content_store_event -> unit) list;
  mutable tree_consumers : (tree_change_event -> unit) list;
}

let create () : t =
  { content = Hashtbl.create 512; tree = Hashtbl.create 512;
    content_consumers = []; tree_consumers = [] }

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
let put_entity (t : t) (e : Model.entity) : unit =
  if not (Hashtbl.mem t.content e.hash) then begin
    Hashtbl.replace t.content e.hash e;
    List.iter (fun f -> f { hash = e.hash; entity = e }) t.content_consumers
  end

let get_by_hash (t : t) (h : string) : Model.entity option =
  Hashtbl.find_opt t.content h

(* ── entity tree (location index) ─────────────────────────────────────────── *)

(* §6.10 Bind step: a tree-change event fires when the binding at the path changes
   (no event on a re-bind to the current hash). [bind] runs Store then Bind. *)
let bind (t : t) ~(path : string) (e : Model.entity) : unit =
  put_entity t e;
  let previous = Hashtbl.find_opt t.tree path in
  let changed = match previous with None -> true | Some h -> not (String.equal h e.hash) in
  Hashtbl.replace t.tree path e.hash;
  if changed then
    List.iter
      (fun f -> f { event_type = derive_event_type previous (Some e.hash);
                    path; new_hash = Some e.hash; previous_hash = previous })
      t.tree_consumers

let unbind (t : t) ~(path : string) : unit =
  let previous = Hashtbl.find_opt t.tree path in
  Hashtbl.remove t.tree path;
  match previous with
  | None -> ()
  | Some _ ->
      List.iter
        (fun f -> f { event_type = "deleted"; path; new_hash = None; previous_hash = previous })
        t.tree_consumers

let hash_at (t : t) ~(path : string) : string option = Hashtbl.find_opt t.tree path

let get_at (t : t) ~(path : string) : Model.entity option =
  match hash_at t ~path with Some h -> get_by_hash t h | None -> None

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
  Hashtbl.iter
    (fun path hash ->
      if String.length path > plen && String.sub path 0 plen = prefix then begin
        let rest = String.sub path plen (String.length path - plen) in
        match String.index_opt rest '/' with
        | None -> note rest (Some hash) false        (* direct child, bound *)
        | Some i -> note (String.sub rest 0 i) None true  (* deeper child path *)
      end)
    t.tree;
  Hashtbl.fold (fun seg (h, c) acc -> (seg, !h, !c) :: acc) acc []
  |> List.sort (fun (a, _, _) (b, _, _) -> String.compare a b)
