(* Self-tests for surfaces the v1 corpus does NOT exercise but the spec range
   requires (codec-review heuristic: conformance-green ≠ bug-free — probe the
   uncovered ranges). Chiefly the full uint64/nint64 range above i64-max, which
   is where OCaml's 63-bit native int would silently truncate if integers were
   not carried as unsigned Int64. *)

open Entitycore_codec

let fails = ref 0
let check name cond = if not cond then (incr fails; Printf.printf "FAIL %s\n" name)

let hex s = String.concat "" (List.map (Printf.sprintf "%02x") (List.of_seq (Seq.map Char.code (String.to_seq s))))
let unhex h =
  String.init (String.length h / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (i * 2) 2)))

let () =
  (* uint64 max = 2^64-1 → 0x1b ffffffffffffffff (above i64-max; OCaml int63 would truncate) *)
  let umax = Cbor.Uint (-1L) in (* -1L bits = 0xFFFFFFFFFFFFFFFF, unsigned 2^64-1 *)
  check "uint64-max encode" (String.equal (hex (Cbor.encode umax)) "1bffffffffffffffff");
  check "uint64-max roundtrip" (Cbor.decode (Cbor.encode umax) = umax);

  (* nint min = -2^64 → major 1, arg 2^64-1 → 0x3b ffffffffffffffff *)
  let nmin = Cbor.Nint (-1L) in
  check "nint64-min encode" (String.equal (hex (Cbor.encode nmin)) "3bffffffffffffffff");

  (* uint just above i64-max: 2^63 = 0x8000000000000000 *)
  let u63 = Cbor.Uint 0x8000000000000000L in
  check "uint 2^63 encode" (String.equal (hex (Cbor.encode u63)) "1b8000000000000000");
  check "uint 2^63 roundtrip" (Cbor.decode (Cbor.encode u63) = u63);

  (* peer-id format → parse round-trip (parse surface is uncovered by corpus) *)
  let comps = Peer_id.{ key_type = 1; hash_type = 1;
                        digest = unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" } in
  let pid = Peer_id.format comps in
  let back = Peer_id.parse pid in
  check "peer-id roundtrip"
    (back.key_type = comps.key_type && back.hash_type = comps.hash_type
     && String.equal back.digest comps.digest);

  (* multi-byte varint key_type round-trip through peer-id *)
  let big = Peer_id.{ key_type = 128; hash_type = 1; digest = comps.digest } in
  let back2 = Peer_id.parse (Peer_id.format big) in
  check "peer-id multibyte-keytype roundtrip" (back2.key_type = 128);

  (* base58 decode(encode x) = x, including leading-zero preservation *)
  let raw = unhex "0000abcdef" in
  check "base58 leading-zero roundtrip" (String.equal (Base58.decode (Base58.encode raw)) raw);

  (* Ed25519 sign/verify round-trip on a fixed seed (verify surface) *)
  let seed = unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" in
  let msg = "entity-core ocaml self-test" in
  let sg = Sign.sign ~seed msg in
  let pub = Sign.public_of_seed seed in
  check "ed25519 sign/verify" (Sign.verify ~pub ~signature:sg ~msg);
  check "ed25519 reject-tamper" (not (Sign.verify ~pub ~signature:sg ~msg:(msg ^ "!")));

  (* decoder rejects a bare CBOR tag (major 6) anywhere — N2 *)
  check "tag-reject bare" (try ignore (Cbor.decode (unhex "c100")); false with Cbor.Decode_error _ -> true);

  (* ── F3 emit pathway (§6.10 / §6.13(c)): event-type derivation + no-op suppression ── *)
  let st = Store.create () in
  let evs = ref [] in
  Store.register_tree_consumer st (fun ev -> evs := ev.Store.event_type :: !evs);
  let mk b = Model.make ~typ:"primitive/any" (Cbor.Map [ (Cbor.Text "v", Cbor.Text b) ]) in
  Store.bind st ~path:"/p/x" (mk "one");   (* created *)
  Store.bind st ~path:"/p/x" (mk "two");   (* modified *)
  Store.bind st ~path:"/p/x" (mk "two");   (* no-op re-bind → suppressed *)
  Store.unbind st ~path:"/p/x";            (* deleted *)
  check "F3 emit event-type derivation + no-op suppression"
    (List.rev !evs = [ "created"; "modified"; "deleted" ]);
  (* deletion-marker bind fires "modified", not "deleted" (keys on null new_hash only) *)
  let mevs = ref [] in
  let st2 = Store.create () in
  Store.register_tree_consumer st2 (fun ev -> mevs := ev.Store.event_type :: !mevs);
  Store.bind st2 ~path:"/p/z" (mk "live");
  Store.bind st2 ~path:"/p/z" (Model.make ~typ:"system/deletion-marker" (Cbor.Map []));
  check "F3 deletion-marker bind → modified" (List.rev !mevs = [ "created"; "modified" ]);

  (* ── F1 register live (§6.13(a) / §6.2): 5 writes + entity-native dispatch ── *)
  let peer = Peer.create ~seed ~open_grants:true () in
  let pp = "app/test/echo" in
  let at rel = "/" ^ peer.Peer.local_peer ^ "/" ^ rel in
  let manifest =
    Cbor.Map
      [ (Cbor.Text "pattern", Cbor.Text pp);
        (Cbor.Text "name", Cbor.Text "echo");
        (Cbor.Text "operations", Cbor.Map [ (Cbor.Text "compute", Cbor.Map []) ]);
        (Cbor.Text "expression_path", Cbor.Text (pp ^ "/expr")) ]
  in
  let reg_req = Model.make ~typ:"system/handler/register-request" (Cbor.Map [ (Cbor.Text "manifest", manifest) ]) in
  let reg_exec =
    Model.make ~typ:"system/protocol/execute"
      (Cbor.Map
         [ (Cbor.Text "operation", Cbor.Text "register");
           (Cbor.Text "resource", Cbor.Map [ (Cbor.Text "targets", Cbor.Array [ Cbor.Text ("system/handler/" ^ pp) ]) ]);
           (Cbor.Text "params", Model.to_cbor reg_req) ])
  in
  let r = Peer.handlers_handler peer reg_exec in
  check "F1 register → 200" (r.Peer.status = 200 && String.equal r.Peer.result.Model.typ "system/handler/register-result");
  let typ_at rel = match Store.get_at peer.Peer.store ~path:(at rel) with Some e -> e.Model.typ | None -> "" in
  check "F1 write: manifest" (String.equal (typ_at pp) "system/handler");
  check "F1 write: interface" (String.equal (typ_at ("system/handler/" ^ pp)) "system/handler/interface");
  check "F1 write: grant" (String.equal (typ_at ("system/capability/grants/" ^ pp)) "system/capability/token");
  (match Store.get_at peer.Peer.store ~path:(at ("system/capability/grants/" ^ pp)) with
   | Some g -> check "F1 write: grant-signature at §3.5 pointer"
                 (Store.get_at peer.Peer.store ~path:(at ("system/signature/" ^ Model.hex g.Model.hash)) <> None)
   | None -> check "F1 write: grant-signature at §3.5 pointer" false);
  (* entity-native dispatch round-trip: bind compute/literal(42), dispatch → compute/result 42 *)
  Store.bind peer.Peer.store ~path:(at (pp ^ "/expr"))
    (Model.make ~typ:"compute/literal" (Cbor.Map [ (Cbor.Text "value", Cbor.Uint 42L) ]));
  let d = Peer.entity_native_dispatch peer (at pp) in
  check "F1 dispatch round-trip → compute/result 42"
    (d.Peer.status = 200 && String.equal d.Peer.result.Model.typ "compute/result"
     && (match Model.field d.Peer.result "value" with Some (Cbor.Uint 42L) -> true | _ -> false));
  (* unregister reverses the writes (incl. grant-sig) *)
  let unreg_exec =
    Model.make ~typ:"system/protocol/execute"
      (Cbor.Map
         [ (Cbor.Text "operation", Cbor.Text "unregister");
           (Cbor.Text "resource", Cbor.Map [ (Cbor.Text "targets", Cbor.Array [ Cbor.Text ("system/handler/" ^ pp) ]) ]) ])
  in
  let u = Peer.handlers_handler peer unreg_exec in
  check "F1 unregister → 200 + manifest removed"
    (u.Peer.status = 200 && Store.get_at peer.Peer.store ~path:(at pp) = None);

  (* ── F2 outbound seam (§6.13(b) / §6.11): reader-demux + request_id correlation ──
     A socketpair stands in for a reentrant connection. The reader routes responses
     by request_id; the "remote" end echoes a 200 for the outbound request. Proves the
     §6.11 reentry primitive end-to-end (write request → reader routes correlated
     response → outbound unblocks) — the machinery the handler-facing closure rides. *)
  let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let io = Transport.make_io a in
  let _reader : Thread.t = Thread.create (fun () -> Transport.read_loop io ~on_execute:(fun _ -> ())) () in
  let _remote : Thread.t =
    Thread.create
      (fun () ->
        let payload = Wire.read_frame b in
        let env = Wire.envelope_of_frame payload in
        let rid = Option.value ~default:"" (Model.text_field env.Model.root "request_id") in
        let resp = Wire.make_response ~request_id:rid ~status:200 ~result:Wire.empty_params in
        Wire.write_frame b (Wire.frame_of_envelope { Model.root = resp; included = [] }))
      ()
  in
  let zero33 = String.make 33 '\000' in
  let req_exec =
    Wire.make_execute ~request_id:"out-1" ~uri:"system/tree" ~operation:"get"
      ~params:Wire.empty_params ~author:zero33 ~capability:zero33 ()
  in
  let response = Transport.outbound io { Model.root = req_exec; included = [] } in
  check "F2 outbound reentry round-trips the correlated response"
    (match response with
     | Some env ->
         Option.value ~default:"" (Model.text_field env.Model.root "request_id") = "out-1"
         && (match Model.uint_field env.Model.root "status" with Some 200L -> true | _ -> false)
     | None -> false);
  Transport.close_io io;
  (try Unix.close a with _ -> ());
  (try Unix.close b with _ -> ());

  (* ── §7a conformance handlers (the system/validate namespace) — GUIDE-CONFORMANCE §7a ──
     echo (resolve→dispatch, closes A-011) + dispatch-outbound (reentry origination,
     closes A-013). Off by default (only bootstrapped under --validate). *)
  let cpeer = Peer.create ~seed ~open_grants:true ~conformance:true () in
  let plain = Peer.create ~seed ~open_grants:true () in
  let vpath p = "/" ^ p.Peer.local_peer ^ "/system/validate/echo" in
  check "§7a.2 conformance handlers OFF by default (not bootstrapped)"
    (Store.get_at plain.Peer.store ~path:(vpath plain) = None);
  check "§7a conformance handlers bootstrapped under --validate"
    (Store.get_at cpeer.Peer.store ~path:(vpath cpeer) <> None);
  (* echo returns the params entity verbatim *)
  let echo_params = Model.make ~typ:"primitive/any" (Cbor.Map [ (Cbor.Text "value", Cbor.Text "ping-42") ]) in
  let echo_exec =
    Model.make ~typ:"system/protocol/execute"
      (Cbor.Map [ (Cbor.Text "operation", Cbor.Text "echo"); (Cbor.Text "params", Model.to_cbor echo_params) ])
  in
  let e = Peer.echo_handler cpeer echo_exec in
  check "§7a echo returns the params value"
    (e.Peer.status = 200
    && (match Model.field e.Peer.result "value" with Some (Cbor.Text "ping-42") -> true | _ -> false));
  (* dispatch-outbound: a fake reentry conn reflects the inner params back (simulates the
     caller's echo over §6.11 reentry); the handler originates + wraps the response. *)
  let conn = Peer.new_conn () in
  conn.Peer.outbound <-
    Some
      (fun (env : Model.envelope) ->
        let rid = Option.value ~default:"" (Model.text_field env.Model.root "request_id") in
        let inner =
          match Model.field env.Model.root "params" with
          | Some pc -> Model.of_cbor pc
          | None -> Model.make ~typ:"primitive/any" (Cbor.Map [])
        in
        Some { Model.root = Wire.make_response ~request_id:rid ~status:200 ~result:inner; included = [] });
  let cap, capsig = Peer.mint_token cpeer ~grantee_hash:cpeer.Peer.identity.Identity.identity_hash ~grants:[] () in
  let granter = cpeer.Peer.identity.Identity.peer_entity in
  let do_params =
    Model.make ~typ:"primitive/any"
      (Cbor.Map
         [ (Cbor.Text "target", Cbor.Text "system/validate/echo");
           (Cbor.Text "operation", Cbor.Text "echo");
           (Cbor.Text "value", Cbor.Text "round-trip-99");
           (Cbor.Text "reentry_capability", Model.to_cbor cap);
           (Cbor.Text "reentry_granter", Model.to_cbor granter);
           (Cbor.Text "reentry_cap_signature", Model.to_cbor capsig) ])
  in
  let do_exec =
    Model.make ~typ:"system/protocol/execute"
      (Cbor.Map [ (Cbor.Text "operation", Cbor.Text "dispatch"); (Cbor.Text "params", Model.to_cbor do_params) ])
  in
  let dout = Peer.dispatch_outbound_handler cpeer conn do_exec in
  check "§7a dispatch-outbound originates reentry + round-trips the value"
    (dout.Peer.status = 200
    &&
    match Model.field dout.Peer.result "result" with
    | Some rc -> (match Model.field (Model.of_cbor rc) "value" with Some (Cbor.Text "round-trip-99") -> true | _ -> false)
    | None -> false);

  (* ── §3.6 M3 multi-signature K-of-N — ACCEPT path. The validate-peer `multisig`
     category is 100% rejection tests (malformed quorum → 403), which a fail-closed
     peer passes without genuine k-of-n. This is the direction the oracle does NOT
     cover: a real 2-of-3 root (one signer = local peer) with a threshold of valid
     signatures over the cap's content hash MUST be ALLOWed — and each M3/M4/M6
     invariant flip MUST deny. *)
  let ms_store = Store.create () in
  let id1 = Identity.of_seed (String.make 32 '\001') in
  let id2 = Identity.of_seed (String.make 32 '\002') in
  let id3 = Identity.of_seed (String.make 32 '\003') in
  let local = id1.Identity.peer_id in
  let mk_cap ~signers ~threshold ?parent () =
    let granter =
      Cbor.Map
        [ (Cbor.Text "signers", Cbor.Array (List.map (fun s -> Cbor.Bytes s) signers));
          (Cbor.Text "threshold", Cbor.Uint threshold) ]
    in
    let fields =
      [ (Cbor.Text "granter", granter);
        (Cbor.Text "grantee", Cbor.Bytes id1.Identity.identity_hash);
        (Cbor.Text "grants", Cbor.Array []) ]
      @ (match parent with Some p -> [ (Cbor.Text "parent", Cbor.Bytes p) ] | None -> [])
    in
    Model.make ~typ:"system/capability/token" (Cbor.Map fields)
  in
  let peer_inc id = (id.Identity.identity_hash, id.Identity.peer_entity) in
  let sig_inc s = (s.Model.hash, s) in
  let allows local cap inc =
    Capability.verify_capability_chain ~local_peer:local ~store:ms_store cap inc = Capability.Allow
  in
  (* valid 2-of-3, local in quorum, 2 valid sigs → Allow *)
  let signers = [ id1.Identity.identity_hash; id2.Identity.identity_hash; id3.Identity.identity_hash ] in
  let cap = mk_cap ~signers ~threshold:2L () in
  let s1 = Identity.sign_entity id1 cap and s2 = Identity.sign_entity id2 cap in
  let inc3 = [ peer_inc id1; peer_inc id2; peer_inc id3 ] in
  check "multisig 2-of-3 valid quorum → Allow" (allows local cap (inc3 @ [ sig_inc s1; sig_inc s2 ]));
  (* only 1 valid sig (< threshold) → Deny (M4) *)
  check "multisig 1-of-3 below threshold → Deny" (not (allows local cap (inc3 @ [ sig_inc s1 ])));
  (* local peer not among the signers → Deny (M6) *)
  let cap_nl = mk_cap ~signers:[ id2.Identity.identity_hash; id3.Identity.identity_hash ] ~threshold:2L () in
  let n2 = Identity.sign_entity id2 cap_nl and n3 = Identity.sign_entity id3 cap_nl in
  check "multisig local-not-in-signers → Deny"
    (not (allows local cap_nl ([ peer_inc id2; peer_inc id3 ] @ [ sig_inc n2; sig_inc n3 ])));
  (* threshold = 1 (M3 structure) → Deny even with valid sigs (precedence) *)
  let cap_t1 = mk_cap ~signers ~threshold:1L () in
  check "multisig threshold=1 (M3) → Deny" (not (allows local cap_t1 (inc3 @ [ sig_inc s1; sig_inc s2 ])));
  (* duplicate signers (M3 structure) → Deny *)
  let cap_dup = mk_cap ~signers:[ id1.Identity.identity_hash; id1.Identity.identity_hash ] ~threshold:2L () in
  check "multisig duplicate-signers (M3) → Deny"
    (not (allows local cap_dup ([ peer_inc id1 ] @ [ sig_inc (Identity.sign_entity id1 cap_dup) ])));
  (* single-sig strict-superset: a normal single-sig root still verifies identically *)
  let ss_cap =
    Model.make ~typ:"system/capability/token"
      (Cbor.Map
         [ (Cbor.Text "granter", Cbor.Bytes id1.Identity.identity_hash);
           (Cbor.Text "grantee", Cbor.Bytes id1.Identity.identity_hash);
           (Cbor.Text "grants", Cbor.Array []) ])
  in
  let ss_sig = Identity.sign_entity id1 ss_cap in
  check "single-sig root still verifies (strict superset)"
    (allows local ss_cap ([ peer_inc id1; sig_inc ss_sig ]));

  if !fails = 0 then print_endline "selftest: all uncovered-range checks PASS"
  else (Printf.printf "selftest: %d FAILED\n" !fails; exit 1)
