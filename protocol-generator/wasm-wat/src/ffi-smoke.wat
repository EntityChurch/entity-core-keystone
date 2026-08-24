;; ffi-smoke.wat — S1 feasibility SPIKE (increment 2): the codec SEAM.
;;
;; The WASM analog of the asm peer's `make ffi-smoke` (ec_sha256 KAT). Proves the whole
;; codec-seam toolchain composes on a STOCK runtime with NO native host:
;;   hand-authored .wat (imports ec_*) --wat2wasm--> ffismoke.wasm
;;   Rust codec       (exports ec_*)   --cargo wasm32-wasip1--> entitycore_codec.wasm
;;   wasm-merge fuses the two into ONE module over ONE shared memory
;;   wasmedge runs it.
;;
;; The crux it validates: the codec API is pointer-based (ec_sha256(ptr,len,out)), so the
;; codec must read/write the INTERIOR's linear memory. We solve shared memory by having the
;; interior IMPORT the codec's exported memory (the codec owns memory 0); the interior parks
;; its scratch HIGH (0x200000, above the codec's ~1.1 MiB data/stack/heap) after growing, so
;; the two never collide. wasm-merge wires the interior's `codec.*` imports to the codec's
;; exports. If this passes, "hand-authored WAT + compiled codec on stock WasmEdge" is viable.
;;
;; Result is carried in the EXIT CODE (no string handling): 0=PASS, 10=ec_sha256 errored,
;; 20=digest mismatch. KAT: SHA-256("abc") =
;;   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

(module
  ;; the seam: the codec owns memory 0; we import it + the one function under test.
  (import "codec" "memory" (memory 17))
  (import "codec" "ec_sha256" (func $ec_sha256 (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))

  ;; interior scratch (absolute addrs, high above the codec's region):
  ;;   0x200000  input "abc"       (3 bytes)
  ;;   0x200010  digest out        (32 bytes, written by ec_sha256)
  ;;   0x200040  expected KAT      (32 bytes)
  (func (export "_start")
    ;; grow the (imported) memory so 0x200000.. is addressable: ensure >= 48 pages
    (if (i32.lt_u (memory.size) (i32.const 48))
      (then (drop (memory.grow (i32.sub (i32.const 48) (memory.size))))))

    ;; input "abc"
    (i32.store8 (i32.const 0x200000) (i32.const 0x61))
    (i32.store8 (i32.const 0x200001) (i32.const 0x62))
    (i32.store8 (i32.const 0x200002) (i32.const 0x63))

    ;; expected digest (little-endian i64 chunks of the KAT byte sequence)
    (i64.store (i32.const 0x200040) (i64.const 0xeacf018fbf1678ba))
    (i64.store (i32.const 0x200048) (i64.const 0x2322ae5dde404141))
    (i64.store (i32.const 0x200050) (i64.const 0x9c7a1796a36103b0))
    (i64.store (i32.const 0x200058) (i64.const 0xad1500f261ff10b4))

    ;; ec_sha256("abc", 3, &out) — nonzero return => codec error
    (if (call $ec_sha256 (i32.const 0x200000) (i32.const 3) (i32.const 0x200010))
      (then (call $proc_exit (i32.const 10))))

    ;; compare the 32-byte digest as 4 i64 loads
    (if (i64.ne (i64.load (i32.const 0x200010)) (i64.load (i32.const 0x200040)))
      (then (call $proc_exit (i32.const 20))))
    (if (i64.ne (i64.load (i32.const 0x200018)) (i64.load (i32.const 0x200048)))
      (then (call $proc_exit (i32.const 20))))
    (if (i64.ne (i64.load (i32.const 0x200020)) (i64.load (i32.const 0x200050)))
      (then (call $proc_exit (i32.const 20))))
    (if (i64.ne (i64.load (i32.const 0x200028)) (i64.load (i32.const 0x200058)))
      (then (call $proc_exit (i32.const 20))))

    ;; all four chunks matched
    (call $proc_exit (i32.const 0)))
)
