;; identity.wat — peer identity + the system/peer entity (increment 3).
;; From a 32-byte Ed25519 seed: derive the pubkey, format the §1.5 base58 peer_id, and
;; compute the identity_hash (= 33-byte content_hash of the system/peer entity, used as
;; author/signer/granter/grantee bytes throughout §5/§6). Uses the seam for crypto/hash and
;; wire.wat for the canonical system/peer data map. See WIRE-SURFACE-REFERENCE §7.
;;
;; Constant strings live in a module rodata region (0x400000..) materialized once by
;; $id_init via memory.init from passive data segments (bulk-memory; no instantiation-time
;; address conflict with the codec's low memory).

(module
  (import "codec" "memory" (memory 17))
  (import "codec" "ec_ed25519_seed_to_pubkey" (func $seed_to_pub (param i32 i32) (result i32)))
  (import "codec" "ec_peerid_format" (func $peerid_format (param i64 i64 i32 i32 i32 i32 i32) (result i32)))
  (import "codec" "ec_content_hash" (func $content_hash (param i32 i32 i32 i32 i32) (result i32)))
  (import "wire" "w_map"  (func $w_map  (param i64)))
  (import "wire" "w_text" (func $w_text (param i32 i32)))
  (import "wire" "w_bstr" (func $w_bstr (param i32 i32)))
  (import "wire" "g_wp"   (global $g_wp (mut i32)))

  ;; rodata slots (materialized by $id_init):
  ;;   0x400000 "system/peer"(11)  0x400010 "key_type"(8)
  ;;   0x400020 "ed25519"(7)       0x400030 "public_key"(10)
  (data $s_peer  "system/peer")
  (data $s_ktype "key_type")
  (data $s_ed    "ed25519")
  (data $s_pubk  "public_key")

  (func $id_init (export "id_init")
    (memory.init $s_peer  (i32.const 0x400000) (i32.const 0) (i32.const 11))
    (memory.init $s_ktype (i32.const 0x400010) (i32.const 0) (i32.const 8))
    (memory.init $s_ed    (i32.const 0x400020) (i32.const 0) (i32.const 7))
    (memory.init $s_pubk  (i32.const 0x400030) (i32.const 0) (i32.const 10)))

  ;; build the canonical system/peer DATA map { key_type:"ed25519", public_key:<32> } at
  ;; $dest (keys canonical: key_type(8) < public_key(10)); return byte length.
  (func $build_peer_data (export "build_peer_data") (param $pub i32) (param $dest i32) (result i32)
    (global.set $g_wp (local.get $dest))
    (call $w_map (i64.const 2))
    (call $w_text (i32.const 0x400010) (i32.const 8))    ;; "key_type"
    (call $w_text (i32.const 0x400020) (i32.const 7))    ;; "ed25519"
    (call $w_text (i32.const 0x400030) (i32.const 10))   ;; "public_key"
    (call $w_bstr (local.get $pub) (i32.const 32))
    (i32.sub (global.get $g_wp) (local.get $dest)))

  ;; identity_hash(pub) → out33 = ec_content_hash("system/peer", peer-data). Returns status.
  ;; Uses 0x410000 as the peer-data build scratch.
  (func $identity_hash (export "identity_hash") (param $pub i32) (param $out33 i32) (result i32)
    (local $len i32)
    (local.set $len (call $build_peer_data (local.get $pub) (i32.const 0x410000)))
    (call $content_hash (i32.const 0x400000) (i32.const 11) (i32.const 0x410000) (local.get $len) (local.get $out33)))

  ;; peer_id(pub) → base58 into out_ptr; length into out_len_ptr. Returns status.
  (func $format_peer_id (export "format_peer_id") (param $pub i32) (param $out i32) (param $out_cap i32) (param $out_len_ptr i32) (result i32)
    (call $peerid_format (i64.const 1) (i64.const 0) (local.get $pub) (i32.const 32)
          (local.get $out) (local.get $out_cap) (local.get $out_len_ptr)))

  (func $seed_to_pubkey (export "seed_to_pubkey") (param $seed i32) (param $out i32) (result i32)
    (call $seed_to_pub (local.get $seed) (local.get $out)))
)
