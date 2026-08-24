;; wire-test.wat — unit test for the hand-rolled canonical-CBOR primitives (wire.wat).
;; Builds a 2-key canonical map { "status": 200, "request_id": "h-1" } with the writer,
;; then parses it back with the reader and asserts. Result in the exit code:
;;   0 PASS; 10..17 = the specific assertion that failed.
;; Merged (wasm-merge) with wire.wat + codec.wasm (memory provider), run under WasmEdge.

(module
  (import "codec" "memory" (memory 17))
  (import "wire" "rd_head"  (func $rd_head  (param i32) (result i32)))
  (import "wire" "streq"    (func $streq    (param i32 i32 i32 i32) (result i32)))
  (import "wire" "map_find" (func $map_find (param i32 i32 i32) (result i32)))
  (import "wire" "w_uint"   (func $w_uint   (param i64)))
  (import "wire" "w_text"   (func $w_text   (param i32 i32)))
  (import "wire" "w_map"    (func $w_map    (param i64)))
  (import "wire" "g_major"  (global $g_major (mut i32)))
  (import "wire" "g_arg"    (global $g_arg   (mut i64)))
  (import "wire" "g_wp"     (global $g_wp    (mut i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))

  (func $sb (param $p i32) (param $b i32) (i32.store8 (local.get $p) (local.get $b)))

  (func (export "_start")
    (local $vp i32) (local $kb i32)
    ;; cover the high scratch/build addresses (0x200000 / 0x300000)
    (if (i32.lt_u (memory.size) (i32.const 64))
      (then (drop (memory.grow (i32.sub (i32.const 64) (memory.size))))))

    ;; "status" @ 0x200000
    (call $sb (i32.const 0x200000) (i32.const 0x73)) (call $sb (i32.const 0x200001) (i32.const 0x74))
    (call $sb (i32.const 0x200002) (i32.const 0x61)) (call $sb (i32.const 0x200003) (i32.const 0x74))
    (call $sb (i32.const 0x200004) (i32.const 0x75)) (call $sb (i32.const 0x200005) (i32.const 0x73))
    ;; "request_id" @ 0x200010
    (call $sb (i32.const 0x200010) (i32.const 0x72)) (call $sb (i32.const 0x200011) (i32.const 0x65))
    (call $sb (i32.const 0x200012) (i32.const 0x71)) (call $sb (i32.const 0x200013) (i32.const 0x75))
    (call $sb (i32.const 0x200014) (i32.const 0x65)) (call $sb (i32.const 0x200015) (i32.const 0x73))
    (call $sb (i32.const 0x200016) (i32.const 0x74)) (call $sb (i32.const 0x200017) (i32.const 0x5f))
    (call $sb (i32.const 0x200018) (i32.const 0x69)) (call $sb (i32.const 0x200019) (i32.const 0x64))
    ;; "h-1" @ 0x200020
    (call $sb (i32.const 0x200020) (i32.const 0x68)) (call $sb (i32.const 0x200021) (i32.const 0x2d))
    (call $sb (i32.const 0x200022) (i32.const 0x31))
    ;; "missing" @ 0x200030
    (call $sb (i32.const 0x200030) (i32.const 0x6d)) (call $sb (i32.const 0x200031) (i32.const 0x69))
    (call $sb (i32.const 0x200032) (i32.const 0x73)) (call $sb (i32.const 0x200033) (i32.const 0x73))
    (call $sb (i32.const 0x200034) (i32.const 0x69)) (call $sb (i32.const 0x200035) (i32.const 0x6e))
    (call $sb (i32.const 0x200036) (i32.const 0x67))

    ;; build { "status": 200, "request_id": "h-1" } at 0x300000
    (global.set $g_wp (i32.const 0x300000))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x200000) (i32.const 6))   ;; "status"
    (call $w_uint (i64.const 200))
    (call $w_text (i32.const 0x200010) (i32.const 10))  ;; "request_id"
    (call $w_text (i32.const 0x200020) (i32.const 3))   ;; "h-1"

    ;; --- assert: status == uint 200 ---
    (local.set $vp (call $map_find (i32.const 0x300000) (i32.const 0x200000) (i32.const 6)))
    (if (i32.eq (local.get $vp) (i32.const -1)) (then (call $exit (i32.const 10))))
    (drop (call $rd_head (local.get $vp)))
    (if (i32.ne (global.get $g_major) (i32.const 0)) (then (call $exit (i32.const 11))))
    (if (i64.ne (global.get $g_arg) (i64.const 200)) (then (call $exit (i32.const 12))))

    ;; --- assert: request_id == text "h-1" ---
    (local.set $vp (call $map_find (i32.const 0x300000) (i32.const 0x200010) (i32.const 10)))
    (if (i32.eq (local.get $vp) (i32.const -1)) (then (call $exit (i32.const 13))))
    (local.set $kb (call $rd_head (local.get $vp)))
    (if (i32.ne (global.get $g_major) (i32.const 3)) (then (call $exit (i32.const 14))))
    (if (i64.ne (global.get $g_arg) (i64.const 3)) (then (call $exit (i32.const 15))))
    (if (i32.eqz (call $streq (local.get $kb) (i32.const 3) (i32.const 0x200020) (i32.const 3)))
      (then (call $exit (i32.const 16))))

    ;; --- assert: absent key → -1 ---
    (if (i32.ne (call $map_find (i32.const 0x300000) (i32.const 0x200030) (i32.const 7)) (i32.const -1))
      (then (call $exit (i32.const 17))))

    (call $exit (i32.const 0)))
)
