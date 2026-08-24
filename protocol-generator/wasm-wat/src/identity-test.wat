;; identity-test.wat — KAT for identity.wat. The conformance seed (0x11 x 32) must yield the
;; peer_id from run-s4.sh, proving seed_to_pubkey + peerid_format + the system/peer data-map
;; build + ec_content_hash all work on real data over the seam.
;;   0 PASS; 10 seed_to_pubkey err; 11 peerid_format err; 12 len!=46; 13 peer_id mismatch;
;;   14 identity_hash err; 15 identity_hash prefix != 0x00.

(module
  (import "codec" "memory" (memory 17))
  (import "identity" "id_init"        (func $id_init))
  (import "identity" "seed_to_pubkey" (func $seed_to_pubkey (param i32 i32) (result i32)))
  (import "identity" "format_peer_id" (func $format_peer_id (param i32 i32 i32 i32) (result i32)))
  (import "identity" "identity_hash"  (func $identity_hash  (param i32 i32) (result i32)))
  (import "wire" "streq" (func $streq (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))

  (data $seed "\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11")
  (data $exp  "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg")

  (func (export "_start")
    (if (i32.lt_u (memory.size) (i32.const 96))
      (then (drop (memory.grow (i32.sub (i32.const 96) (memory.size))))))
    (call $id_init)

    (memory.init $seed (i32.const 0x420000) (i32.const 0) (i32.const 32))
    (if (call $seed_to_pubkey (i32.const 0x420000) (i32.const 0x420100)) (then (call $exit (i32.const 10))))

    ;; peer_id → 0x420200, len → 0x4202F0
    (if (call $format_peer_id (i32.const 0x420100) (i32.const 0x420200) (i32.const 128) (i32.const 0x4202F0))
      (then (call $exit (i32.const 11))))
    (if (i32.ne (i32.load (i32.const 0x4202F0)) (i32.const 46)) (then (call $exit (i32.const 12))))
    (memory.init $exp (i32.const 0x430000) (i32.const 0) (i32.const 46))
    (if (i32.eqz (call $streq (i32.const 0x420200) (i32.const 46) (i32.const 0x430000) (i32.const 46)))
      (then (call $exit (i32.const 13))))

    ;; identity_hash → 0x440000 (33B, 0x00-prefixed)
    (if (call $identity_hash (i32.const 0x420100) (i32.const 0x440000)) (then (call $exit (i32.const 14))))
    (if (i32.ne (i32.load8_u (i32.const 0x440000)) (i32.const 0)) (then (call $exit (i32.const 15))))

    (call $exit (i32.const 0)))
)
