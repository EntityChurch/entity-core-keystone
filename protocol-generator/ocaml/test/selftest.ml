(* Self-tests for surfaces the v1 corpus does NOT exercise but the spec range
   requires (codec-review heuristic: conformance-green ≠ bug-free — probe the
   uncovered ranges). Chiefly the full uint64/nint64 range above i64-max, which
   is where OCaml's 63-bit native int would silently truncate if integers were
   not carried as unsigned Int64. *)

open Entitycore_codec

let fails = ref 0

(* [ran] counts EXECUTED checks. A suite that examined zero things prints exactly
   what one that examined all of them prints, so the count is asserted against a
   floor at the end — the rule this repo has now earned seven times. *)
let ran = ref 0
let check name cond = incr ran; if not cond then (incr fails; Printf.printf "FAIL %s\n" name)

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

  (* decoder rejects a bare CBOR tag (major 6) anywhere — N2.
     The exception is [Tag_rejected] and NOT the generic [Decode_error] since
     0.8.2.25: §4.11 makes the peer answer a different CODE for a tag-policy
     violation (400 non_canonical_ecf, ENTITY-CBOR-ENCODING §5.4) than for every
     other decode fault (400 invalid_request), so the decoder has to distinguish
     them. Asserting the SPECIFIC exception is what keeps the two from being
     re-merged: a [Decode_error] catch here would still pass if the tag arm
     regressed into the structural family. *)
  check "tag-reject bare"
    (try ignore (Cbor.decode (unhex "c100")); false
     with Cbor.Tag_rejected -> true
        (* Named rather than left to escape: an uncaught exception kills the suite
           before it can report WHICH check failed, so a regression here would read
           as a crash instead of as a red test. *)
        | Cbor.Decode_error _ -> false);
  (* And the other direction: a STRUCTURAL fault must NOT come back as
     [Tag_rejected], or the split is one-way and every malformed frame answers
     non_canonical_ecf again. "c1" is a tag head with its argument missing. *)
  check "structural-fault is not tag-reject"
    (try ignore (Cbor.decode (unhex "1b00")); false
     with Cbor.Tag_rejected -> false | Cbor.Decode_error _ -> true);

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
  (* The round-tripped entity's DATA *is* the value — not a {value: …} map.
     §7a.1 passes the `value` field through as the outbound params entity data
     (Peer.dispatch_outbound_handler, `let inner = Model.make ~typ:"primitive/any"
     value`), because re-wrapping it double-wraps and makes the echo's
     result.value come back as a map — keystone §7b t1_2.

     This assertion read `Model.field (Model.of_cbor rc) "value"` — the
     double-wrapped shape — from before that pass-through change, and had been
     FAILING ever since. Nothing caught it because this peer had no run-s2.sh, so
     `selftest.exe` was not on any swept path; the only host-invocable entry
     point was run-agility.sh, which does not build or run it. Traced before
     changing: status is 200 and the value arrives intact as
     `primitive/any` / `Text "round-trip-99"`, so the peer is correct here and
     the expectation was stale. Its S4 row (756 · 0F) agrees. *)
  check "§7a dispatch-outbound originates reentry + round-trips the value"
    (dout.Peer.status = 200
    &&
    match Model.field dout.Peer.result "result" with
    | Some rc -> (
        let inner = Model.of_cbor rc in
        String.equal inner.Model.typ "primitive/any"
        && match inner.Model.data with Cbor.Text "round-trip-99" -> true | _ -> false)
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

  (* ── 0.8.2.20/.21/.24 — §5.2 effective targets, §6.3 check_path_permission,
        the path-scope sentinel, and F50's typing of scope_subset ────────────── *)

  let sid = Identity.of_seed (String.make 32 '\007') in
  let slocal = sid.Identity.peer_id in
  let scope ?(excl = []) incl = Cbor.Map
    ((Cbor.Text "include", Cbor.Array (List.map (fun s -> Cbor.Text s) incl))
     :: (if excl = [] then []
         else [ (Cbor.Text "exclude", Cbor.Array (List.map (fun s -> Cbor.Text s) excl)) ])) in
  let grant ~handlers ~operations ~resources =
    Cbor.Map [ (Cbor.Text "handlers", handlers);
               (Cbor.Text "operations", operations);
               (Cbor.Text "resources", resources) ] in
  let token grants =
    Model.make ~typ:"system/capability/token" (Cbor.Map [ (Cbor.Text "grants", Cbor.Array grants) ]) in
  let exec_with ?targets ?exclude () =
    let resource = match targets with
      | None -> []
      | Some ts ->
          [ (Cbor.Text "resource",
             Cbor.Map ((Cbor.Text "targets", Cbor.Array (List.map (fun s -> Cbor.Text s) ts))
                       :: (match exclude with
                           | None -> []
                           | Some xs -> [ (Cbor.Text "exclude", Cbor.Array (List.map (fun s -> Cbor.Text s) xs)) ]))) ]
    in
    Model.make ~typ:"system/protocol/execute"
      (Cbor.Map ((Cbor.Text "operation", Cbor.Text "get") :: resource)) in
  let eff e = Capability.effective_targets ~local_peer:slocal e in

  (* §5.2 effective targets (0.8.2.20): the caller's own exclude removes entries
     BEFORE anything else looks at the request, and survivors keep the caller's
     RAW spelling (0.8.2.21) rather than a canonical form. *)
  check "eff: caller exclude removes its own target"
    (eff (exec_with ~targets:[ "qA"; "qB" ] ~exclude:[ "qB" ] ()) = ([ "qA" ], true));
  check "eff: survivors are raw, not canonicalized"
    (eff (exec_with ~targets:[ "qA" ] ()) = ([ "qA" ], true));
  (* N11's NON-LOSSY PROJECTION [MUST]: the two empties are DIFFERENT REQUESTS and
     a function returning only a list cannot tell them apart. A resource-OPTIONAL
     operation answers them differently (N7/N10 + EXTENSION-TREE §2.2a: absent ->
     root listing, self-excluded -> 400 path_required), so collapsing them here
     deletes the discriminator before any handler can read it. *)
  check "eff: absent resource is (\\[\\], false)" (eff (exec_with ()) = ([], false));
  check "eff: self-excluded resource is (\\[\\], TRUE) — not the absent case"
    (eff (exec_with ~targets:[ "qA" ] ~exclude:[ "qA" ] ()) = ([], true));
  (* PRESENT-BUT-ILL-TYPED `targets` IS PRESENT — the cell the two vanguards
     disagreed on until 0.8.2.25, corrected toward `go`. Reading it as ABSENT
     would serve a present resource the wider absent-case answer §3.3 forbids
     (on `get`, the root listing instead of 400 path_required). The KEY's
     presence is the discriminator, not the value's type. *)
  check "eff: ill-typed targets is PRESENT with an empty effective list"
    (Capability.effective_targets ~local_peer:slocal
       (Model.make ~typ:"system/protocol/execute"
          (Cbor.Map [ (Cbor.Text "resource", Cbor.Map [ (Cbor.Text "targets", Cbor.Text "qA") ]) ]))
     = ([], true));
  (* ...and a `resource` map with no `targets` KEY at all is absent. *)
  check "eff: a resource with no targets key is absent"
    (Capability.effective_targets ~local_peer:slocal
       (Model.make ~typ:"system/protocol/execute"
          (Cbor.Map [ (Cbor.Text "resource", Cbor.Map [ (Cbor.Text "exclude", Cbor.Array []) ]) ]))
     = ([], false));
  (* §5.4's caller-exclude arm is fail-OPEN on an unmatchable pattern (the grant
     arm is fail-CLOSED): canonicalize answers the sentinel, matches_pattern then
     answers false, and the target simply SURVIVES. *)
  check "eff: unmatchable caller exclude carves out nothing"
    (eff (exec_with ~targets:[ "qA" ] ~exclude:[ "../nope" ] ()) = ([ "qA" ], true));

  (* §6.3 check_path_permission. THE ACCEPT CASE IS WHAT VALIDATES THE FIXTURE —
     a predicate test built only from deny cases is indistinguishable from one
     asserting False == False, and a broken fixture makes every deny pass for
     free. One deny per DIMENSION, because a single deny cannot separate "it
     checks the dimension I care about" from "it denies". *)
  let cpp ?(op = "get") ?(pattern = "system/tree") tok path =
    Capability.check_path_permission ~local_peer:slocal ~operation:op ~path ~token:tok
      ~handler_pattern:pattern in
  let tok_ok = token [ grant ~handlers:(scope [ "system/tree" ])
                         ~operations:(scope [ "get" ]) ~resources:(scope [ "q/*" ]) ] in
  check "cpp: ACCEPT (validates the fixture)" (cpp tok_ok "q/a");
  check "cpp: DENY on the resources dimension" (not (cpp tok_ok "other/a"));
  check "cpp: DENY on the operations dimension" (not (cpp ~op:"put" tok_ok "q/a"));
  check "cpp: DENY on the handlers dimension" (not (cpp ~pattern:"system/other" tok_ok "q/a"));
  (* §5.2's note: an empty resources.include is a legal grant shape (a handler
     that touches no tree paths) and DENIES every path here. *)
  check "cpp: empty resources.include denies every path"
    (not (cpp (token [ grant ~handlers:(scope [ "system/tree" ])
                         ~operations:(scope [ "get" ]) ~resources:(scope []) ]) "q/a"));
  (* A malformed path canonicalizes to the sentinel, which matches no grant
     (§5.4), so it falls through to DENY rather than being matched at all. *)
  check "cpp: a malformed path denies" (not (cpp tok_ok "../nope"));
  (* A grant exclude covering the subject denies: the caller's exclusions were
     already applied in deriving this concrete path, so nothing carves it back. *)
  check "cpp: a grant exclude covering the path denies"
    (not (cpp (token [ grant ~handlers:(scope [ "system/tree" ]) ~operations:(scope [ "get" ])
                         ~resources:(scope ~excl:[ "q/a" ] [ "q/*" ]) ]) "q/a"));

  (* §5.4's unmatchable-pattern rule is SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3):
     "It does NOT reach `operations` or `peers` [MUST]". This is the
     discriminating pair, and the id case cannot be passed by accident —
     "*/apply" is an ordinary namespaced operation name that PATH-canonicalizes
     to the sentinel, so on the pre-.24 unscoped reading it denied the WHOLE
     dimension and `get` included by a bare "*" came back false. *)
  check "sentinel: id-scope operations must NOT consult it"
    (Capability.matches_scope ~local_peer:slocal ~kind:Capability.Id_scope "get"
       { Capability.incl = [ "*" ]; excl = [ "*/apply" ] });
  check "sentinel: id-scope peers must NOT consult it"
    (Capability.matches_scope ~local_peer:slocal ~kind:Capability.Id_scope slocal
       { Capability.incl = [ "*" ]; excl = [ "../nope" ] });
  (* The other half, and it proves this is a scope SPLIT rather than a removal:
     on a path-scope dimension an unmatchable exclude still denies (0.8.2.21),
     because there it would otherwise carve out nothing and leave the grant
     silently wider than its author wrote. *)
  check "sentinel: path-scope still denies on an unmatchable exclude"
    (not (Capability.matches_scope ~local_peer:slocal ~kind:Capability.Path_scope "system/tree"
            { Capability.incl = [ "*" ]; excl = [ "../nope" ] }));
  check "sentinel: path-scope ordinary exclude still carves out only its target"
    (Capability.matches_scope ~local_peer:slocal ~kind:Capability.Path_scope "system/tree"
       { Capability.incl = [ "*" ]; excl = [ "system/secret" ] });

  (* F50 (ruled 0.8.2.16): scope_subset is typed by SCOPE KIND exactly as its
     sibling matches_scope is. The two readings agree on every well-formed grant,
     which is why no hand-tried example found it; these are the two pairs
     `entity-core-formalization` measured as disagreeing, both fail-CLOSED under
     the canonicalizing reading. On the id matcher a literal child include is
     covered by a bare "*" parent. *)
  let ssub ~kind child parent =
    Capability.scope_subset ~child_peer:slocal ~parent_peer:slocal ~kind child parent in
  check "scope_subset id: /tree/get is covered by *"
    (ssub ~kind:Capability.Id_scope
       { Capability.incl = [ "/tree/get" ]; excl = [] } { Capability.incl = [ "*" ]; excl = [] });
  check "scope_subset id: */apply is covered by *"
    (ssub ~kind:Capability.Id_scope
       { Capability.incl = [ "*/apply" ]; excl = [] } { Capability.incl = [ "*" ]; excl = [] });
  (* The id matcher must still REFUSE a genuine widening, or "typed" would just
     mean "always true". *)
  check "scope_subset id: * is NOT covered by a literal"
    (not (ssub ~kind:Capability.Id_scope
            { Capability.incl = [ "*" ]; excl = [] } { Capability.incl = [ "get" ]; excl = [] }));
  (* And the path arm is UNCHANGED — this is a split, not a replacement. *)
  check "scope_subset path: a subtree child is covered by a bare * parent"
    (ssub ~kind:Capability.Path_scope
       { Capability.incl = [ "q/a" ]; excl = [] } { Capability.incl = [ "*" ]; excl = [] });
  check "scope_subset path: an uncovered child is refused"
    (not (ssub ~kind:Capability.Path_scope
            { Capability.incl = [ "q/a" ]; excl = [] } { Capability.incl = [ "r/*" ]; excl = [] }));

  (* §5.2a / §4.11 (0.8.2.24 N4/N5, 0.8.2.25): THE CODE BELONGS TO THE CAUSE. A
     mis-keyed `included` entry is a RESOLUTION-INTEGRITY failure, not a CBOR
     tag-policy violation — its encoding is canonical, and what is false is the
     claim the KEY makes — so it MUST answer 400 hash_mismatch and
     non_canonical_ecf is explicitly non-conformant there. Asserted through the
     peer's own mapping function, not by reading it. *)
  let mis_keyed =
    let e = Model.make ~typ:"primitive/any" (Cbor.Map [ (Cbor.Text "v", Cbor.Text "x") ]) in
    Cbor.Map [ (Cbor.Text "root", Model.to_cbor (Model.make ~typ:"system/protocol/execute" (Cbor.Map [])));
               (Cbor.Text "included", Cbor.Map [ (Cbor.Bytes (String.make 33 '\000'), Model.to_cbor e) ]) ] in
  check "decode: a mis-keyed included entry raises Hash_mismatch"
    (try ignore (Model.envelope_of_cbor mis_keyed); false
     with Model.Hash_mismatch _ -> true
        (* The pre-0.8.2.24 spelling, named so a regression reports as a red check
           rather than as an uncaught exception that ends the run. *)
        | Model.Bad_entity _ -> false);
  check "pre-admission: mis-keyed included maps to 400 hash_mismatch"
    (Wire.pre_admission_refusal (Model.Hash_mismatch "x") = (400, "hash_mismatch"));
  check "pre-admission: a tag-policy violation KEEPS 400 non_canonical_ecf"
    (Wire.pre_admission_refusal Cbor.Tag_rejected = (400, "non_canonical_ecf"));
  check "pre-admission: a structural fault is 400 invalid_request"
    (Wire.pre_admission_refusal (Model.Bad_entity "x") = (400, "invalid_request"));
  check "pre-admission: an oversize frame is 413 payload_too_large"
    (Wire.pre_admission_refusal Wire.Frame_too_large = (413, "payload_too_large"));
  (* §4.11's framing arm is owed a coded frame; an ordinary close is NOT a refusal
     of anything and there is nobody left to answer. *)
  check "framing refusal: oversize is owed a frame" (Wire.is_framing_refusal Wire.Frame_too_large);
  check "framing refusal: truncation is owed a frame" (Wire.is_framing_refusal Wire.Truncated_frame);
  check "framing refusal: a clean close is NOT" (not (Wire.is_framing_refusal Wire.Closed));

  (* ...AND THE CLASSIFICATION HAS TO HAPPEN AT THE READ, WHICH THE THREE CHECKS
     ABOVE CANNOT SEE. They are pure functions of an exception VALUE: they stay
     green while [read_frame] raises the WRONG one. §4.11's whole distinction —
     "a clean close at a frame BOUNDARY is an ordinary hangup and is owed nothing;
     a stream that ends mid-frame is a REFUSAL and is owed a coded frame" — can
     only be made where the frame boundary is known, so it is driven here over a
     real socketpair. A test that never executes the site it is about is the
     never-executed-guard class wearing a green tick. *)
  let read_after ?(shutdown_write = true) (bytes_sent : string) : exn option =
    let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
    if String.length bytes_sent > 0 then
      ignore (Unix.write_substring b bytes_sent 0 (String.length bytes_sent));
    if shutdown_write then Unix.shutdown b Unix.SHUTDOWN_SEND;
    let r = try ignore (Wire.read_frame a); None with e -> Some e in
    (try Unix.close a with _ -> ()); (try Unix.close b with _ -> ());
    r in
  check "read_frame: a clean close AT A BOUNDARY is Closed, not a refusal"
    (read_after "" = Some Wire.Closed);
  check "read_frame: a PARTIAL length prefix is Truncated_frame"
    (read_after "\x00\x00" = Some Wire.Truncated_frame);
  check "read_frame: a prefix declaring more than arrives is Truncated_frame"
    (read_after "\x00\x00\x00\x64ab" = Some Wire.Truncated_frame);
  (* The body arm is the one an [off = 0] inference gets wrong: the prefix has
     been consumed, so ZERO body bytes is still a truncation and not a boundary. *)
  check "read_frame: a prefix with NO body at all is still Truncated_frame"
    (read_after "\x00\x00\x00\x64" = Some Wire.Truncated_frame);
  check "read_frame: an over-max length prefix is Frame_too_large"
    (read_after "\xff\xff\xff\xff" = Some Wire.Frame_too_large);

  (* THE COUNT IS THE ONLY THING THAT SEPARATES "all green" FROM "nothing ran".
     `fails = 0` is the expected output of a passing suite AND of one whose checks
     were dropped — the examined-zero-things class, which this repo has now hit
     seven times. The floor is raised when checks are added; it is deliberately a
     floor rather than an equality so adding one does not fail the gate. *)
  let floor = 68 in
  if !ran < floor then begin
    Printf.printf "selftest: executed %d checks, below the floor of %d — checks were DROPPED\n" !ran floor;
    exit 1
  end;
  if !fails = 0 then Printf.printf "selftest: all %d uncovered-range checks PASS\n" !ran
  else (Printf.printf "selftest: %d of %d FAILED\n" !fails !ran; exit 1)
