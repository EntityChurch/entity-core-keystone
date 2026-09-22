;; dispatch-test.wat — offline KAT for the §5.2 `peers` grant dimension (id-scope: literal
;; match, bare "*" / trailing "/*" / exact, include + exclude), added alongside the fix for
;; peers-grant-dimension-oracle-gap.md ($grant_scope_ok /
;; $op_scope_ok never checked a grant's `peers` scope; the "peers" string constant was parsed
;; into the seed-grant CBOR but never read back at dispatch — the go-oracle has zero test
;; coverage of this dimension, AGENTS.md "conformance-green can be vacuous", so this offline
;; harness is the only regression guard).
;;
;; No live socket / envelope: hand-builds minimal grant-entry CBOR via wire's writer and calls
;; dispatch's exported `peers_scope_ok` / `is_peer_id_seg` directly (the same functions
;; $grant_scope_ok / $op_scope_ok now call at dispatch time), asserting an ACCEPT path and a
;; REJECT path for both the default-peers-scope case (grant omits "peers" -> defaults to
;; {include:[local_peer_id]}, §5.2 line 1040/2378) and an explicit peers.include/exclude case.
;;
;; Exit codes: 0 PASS;
;;   1 default-scope ACCEPT (target == local_peer_id) wrongly denied
;;   2 default-scope REJECT (target == a foreign peer, no explicit peers key) wrongly allowed
;;   3 explicit-include ACCEPT (target in peers.include) wrongly denied
;;   4 explicit-exclude REJECT (target in peers.include AND peers.exclude) wrongly allowed
;;   5 is_peer_id_seg false negative on a real 46-char base58 id
;;   6 is_peer_id_seg false positive on a 32-byte non-base58 segment

(module
  (import "codec" "memory" (memory 17))
  (import "wire" "w_map"   (func $w_map   (param i64)))
  (import "wire" "w_array" (func $w_array (param i64)))
  (import "wire" "w_text"  (func $w_text  (param i32 i32)))
  (import "wire" "g_wp"    (global $g_wp (mut i32)))
  (import "dispatch" "disp_init"       (func $disp_init))
  (import "dispatch" "peers_scope_ok"  (func $peers_scope_ok  (param i32 i32 i32) (result i32)))
  (import "dispatch" "is_peer_id_seg"  (func $is_peer_id_seg  (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))

  ;; two distinct 46-char base58 strings standing in for peer ids.
  (data $peerA "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg")
  (data $peerB "h82pJGF9p7kpzb6eU326EFZf2cDnimbTFVeJtx1qtBmUNJ")

  (func (export "_start")
    ;; 256 pages = 16 MiB. THIS NUMBER IS COUPLED TO dispatch.wat's MEMORY MAP, which is
    ;; why it is not 128 any more: dispatch keeps its store INDEX at 0xA00000 and grows the
    ;; entity ARENA upward from 0xA10000, so at 128 pages (8 MiB) the first store write ran
    ;; off the end -- `out of bounds memory access ... offset 0x00a00000, boundary 0x007fffff`.
    ;; That is not an assert failure and has no code-table entry; it reads as a broken merge.
    ;; The live peer never hit it because host.wat grows to 5632 pages for its per-connection
    ;; buffers; this unit imports the same dispatch.wasm with none of that. 16 MiB leaves the
    ;; arena ~6 MiB, ample for a unit that stores a handful of entities, without reserving the
    ;; peer's full 352 MiB in a test.
    (if (i32.lt_u (memory.size) (i32.const 256))
      (then (drop (memory.grow (i32.sub (i32.const 256) (memory.size))))))
    (call $disp_init)   ;; populates the "peers"/"include"/"exclude" rodata peers_scope_ok reads

    ;; --- is_peer_id_seg sanity ---------------------------------------------------
    (memory.init $peerA (i32.const 0x470000) (i32.const 0) (i32.const 46))
    (if (i32.eqz (call $is_peer_id_seg (i32.const 0x470000) (i32.const 46))) (then (call $exit (i32.const 5))))
    ;; c_respt ("system/protocol/execute/response", 32B, non-base58) — disp_init already placed
    ;; it at 0x460040; too short (<46) alone should already reject.
    (if (call $is_peer_id_seg (i32.const 0x460040) (i32.const 32)) (then (call $exit (i32.const 6))))

    ;; local_peer_id stand-in @ 0x420200 / len @ 0x4202F0 (normally set by host.wat at startup).
    (memory.init $peerA (i32.const 0x420200) (i32.const 0) (i32.const 46))
    (i32.store (i32.const 0x4202F0) (i32.const 46))
    (memory.init $peerB (i32.const 0x470100) (i32.const 0) (i32.const 46))

    ;; --- case 1: grant with NO "peers" key -> defaults to {include:[local_peer_id]} ----------
    (global.set $g_wp (i32.const 0x471000))
    (call $w_map (i64.const 0))                                             ;; {} — no peers key
    ;; ACCEPT: target == local_peer_id (peerA)
    (if (i32.eqz (call $peers_scope_ok (i32.const 0x471000) (i32.const 0x420200) (i32.const 46)))
      (then (call $exit (i32.const 1))))
    ;; REJECT: target == a foreign peer (peerB) — default peers scope is local-only
    (if (call $peers_scope_ok (i32.const 0x471000) (i32.const 0x470100) (i32.const 46))
      (then (call $exit (i32.const 2))))

    ;; --- case 2: grant with explicit peers.include=[peerB], peers.exclude=[peerA] -----------
    (global.set $g_wp (i32.const 0x472000))
    (call $w_map (i64.const 1))
    (call $w_text (i32.const 0x461980) (i32.const 5))                       ;; "peers"
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x4613c0) (i32.const 7))                       ;; "include"
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x470100) (i32.const 46))  ;; [peerB]
    (call $w_text (i32.const 0x4619c0) (i32.const 7))                       ;; "exclude"
    (call $w_array (i64.const 1)) (call $w_text (i32.const 0x420200) (i32.const 46))  ;; [peerA]
    ;; ACCEPT: target == peerB (covered by include, not excluded)
    (if (i32.eqz (call $peers_scope_ok (i32.const 0x472000) (i32.const 0x470100) (i32.const 46)))
      (then (call $exit (i32.const 3))))
    ;; REJECT: target == peerA — present in include's default-local sense AND explicitly
    ;; excluded; exclude MUST win (the genuine MUST-gate, not merely "absent from include")
    (if (call $peers_scope_ok (i32.const 0x472000) (i32.const 0x420200) (i32.const 46))
      (then (call $exit (i32.const 4))))

    (call $exit (i32.const 0)))
)
