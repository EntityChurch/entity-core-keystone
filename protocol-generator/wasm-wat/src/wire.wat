;; wire.wat — hand-rolled canonical-CBOR reader/writer primitives (increment 3, the
;; envelope/data-map layer). The seam's ec_encode_ecf covers entity-shaped data; the
;; envelope {root,included} + EXECUTE/RESPONSE data maps are bare canonical-CBOR that the
;; peer owns (A-WAT-004, = asm A-ASM-004). These primitives are what every handler uses to
;; parse a request envelope and build a response.
;;
;; Operates on the ONE shared linear memory (imported from the codec — the production model;
;; see PROFILE-RATIONALE). Multi-output is via module globals (the WAT analog of the asm
;; peer parking parser state in registers/scratch), since core-wat multi-value returns aren't
;; assumed. Functions are exported so the test harness (and later the peer modules) bind them
;; through wasm-merge.
;;
;; Canonical CBOR (§1.6/§1.8): map keys ordered (length, then bytewise); shortest head form;
;; uints major 0. The peer builds only small fixed-shape maps, so it emits keys in pre-sorted
;; order — no general sort needed. Reader covers major types 0-6 (no floats in envelope maps).

(module
  (import "codec" "memory" (memory 17))

  ;; parser outputs (set by $rd_head): major type + argument of the last-read head.
  (global $g_major (mut i32) (i32.const 0))
  (global $g_arg   (mut i64) (i64.const 0))
  ;; writer cursor (append position); set by the caller before building.
  (global $g_wp    (mut i32) (i32.const 0))
  (export "g_major" (global $g_major))
  (export "g_arg"   (global $g_arg))
  (export "g_wp"    (global $g_wp))

  ;; --- reader -----------------------------------------------------------------

  ;; read a CBOR head at $p: set g_major = byte>>5, g_arg = argument, return ptr past head.
  (func $rd_head (export "rd_head") (param $p i32) (result i32)
    (local $b i32) (local $ai i32) (local $n i32) (local $i i32) (local $v i64)
    (local.set $b (i32.load8_u (local.get $p)))
    (global.set $g_major (i32.shr_u (local.get $b) (i32.const 5)))
    (local.set $ai (i32.and (local.get $b) (i32.const 0x1f)))
    (local.set $p (i32.add (local.get $p) (i32.const 1)))
    (if (i32.lt_u (local.get $ai) (i32.const 24))
      (then
        (global.set $g_arg (i64.extend_i32_u (local.get $ai)))
        (return (local.get $p))))
    ;; ai in {24,25,26,27} → 1/2/4/8 big-endian argument bytes
    (local.set $n (i32.shl (i32.const 1) (i32.sub (local.get $ai) (i32.const 24))))
    (local.set $v (i64.const 0))
    (local.set $i (i32.const 0))
    (block $done (loop $L
      (br_if $done (i32.eq (local.get $i) (local.get $n)))
      (local.set $v (i64.or (i64.shl (local.get $v) (i64.const 8))
                            (i64.extend_i32_u (i32.load8_u (local.get $p)))))
      (local.set $p (i32.add (local.get $p) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (global.set $g_arg (local.get $v))
    (local.get $p))

  ;; skip one complete CBOR item at $p; return ptr past it. Handles major 0-6.
  (func $skip (export "skip") (param $p i32) (result i32)
    (local $m i32) (local $a i64) (local $i i64) (local $cnt i64)
    (local.set $p (call $rd_head (local.get $p)))
    (local.set $m (global.get $g_major))
    (local.set $a (global.get $g_arg))
    ;; 0,1 uint/nint and 7 simple/float: head already consumed the payload
    (if (i32.or (i32.lt_u (local.get $m) (i32.const 2)) (i32.eq (local.get $m) (i32.const 7)))
      (then (return (local.get $p))))
    ;; 2,3 byte/text string: skip $a content bytes
    (if (i32.or (i32.eq (local.get $m) (i32.const 2)) (i32.eq (local.get $m) (i32.const 3)))
      (then (return (i32.add (local.get $p) (i32.wrap_i64 (local.get $a))))))
    ;; 6 tag: skip one following item
    (if (i32.eq (local.get $m) (i32.const 6))
      (then (return (call $skip (local.get $p)))))
    ;; 4 array: $a items ; 5 map: 2*$a items
    (local.set $cnt (local.get $a))
    (if (i32.eq (local.get $m) (i32.const 5))
      (then (local.set $cnt (i64.mul (local.get $a) (i64.const 2)))))
    (local.set $i (i64.const 0))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $cnt)))
      (local.set $p (call $skip (local.get $p)))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (local.get $p))

  ;; byte-compare [a,alen] vs [b,blen]; return 1 if equal else 0.
  (func $streq (export "streq") (param $a i32) (param $alen i32) (param $b i32) (param $blen i32) (result i32)
    (local $i i32)
    (if (i32.ne (local.get $alen) (local.get $blen)) (then (return (i32.const 0))))
    (local.set $i (i32.const 0))
    (block $done (loop $L
      (br_if $done (i32.eq (local.get $i) (local.get $alen)))
      (if (i32.ne (i32.load8_u (i32.add (local.get $a) (local.get $i)))
                  (i32.load8_u (i32.add (local.get $b) (local.get $i))))
        (then (return (i32.const 0))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L)))
    (i32.const 1))

  ;; find text-key [keyp,keylen] in the map whose head is at $mapp; return ptr to its value,
  ;; or -1 if absent. Assumes canonical map with text keys (the envelope/data-map shape).
  (func $map_find (export "map_find") (param $mapp i32) (param $keyp i32) (param $keylen i32) (result i32)
    (local $n i64) (local $i i64) (local $p i32) (local $kbytes i32) (local $klen i32) (local $valp i32)
    (local.set $p (call $rd_head (local.get $mapp)))     ;; expect g_major==5
    (if (i32.ne (global.get $g_major) (i32.const 5)) (then (return (i32.const -1))))
    (local.set $n (global.get $g_arg))
    (local.set $i (i64.const 0))
    (block $done (loop $L
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      ;; key (text): head then bytes
      (local.set $kbytes (call $rd_head (local.get $p)))
      (local.set $klen (i32.wrap_i64 (global.get $g_arg)))
      (local.set $valp (i32.add (local.get $kbytes) (local.get $klen)))
      (if (call $streq (local.get $kbytes) (local.get $klen) (local.get $keyp) (local.get $keylen))
        (then (return (local.get $valp))))
      (local.set $p (call $skip (local.get $valp)))       ;; skip value → next key
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $L)))
    (i32.const -1))

  ;; --- writer (appends at g_wp) -----------------------------------------------

  (func $w_u8 (export "w_u8") (param $b i32)
    (i32.store8 (global.get $g_wp) (local.get $b))
    (global.set $g_wp (i32.add (global.get $g_wp) (i32.const 1))))

  ;; emit a canonical shortest-form head: (major<<5) | argument.
  (func $w_head (export "w_head") (param $major i32) (param $arg i64)
    (local $hi i32) (local $n i32) (local $i i32)
    (local.set $hi (i32.shl (local.get $major) (i32.const 5)))
    (if (i64.lt_u (local.get $arg) (i64.const 24))
      (then (call $w_u8 (i32.or (local.get $hi) (i32.wrap_i64 (local.get $arg)))) (return)))
    (if (i64.lt_u (local.get $arg) (i64.const 256))       (then (local.set $n (i32.const 1)) (call $w_u8 (i32.or (local.get $hi) (i32.const 24))))
    (else (if (i64.lt_u (local.get $arg) (i64.const 65536)) (then (local.set $n (i32.const 2)) (call $w_u8 (i32.or (local.get $hi) (i32.const 25))))
    (else (if (i64.lt_u (local.get $arg) (i64.const 0x100000000)) (then (local.set $n (i32.const 4)) (call $w_u8 (i32.or (local.get $hi) (i32.const 26))))
    (else (local.set $n (i32.const 8)) (call $w_u8 (i32.or (local.get $hi) (i32.const 27)))))))))
    ;; emit $n big-endian argument bytes
    (local.set $i (local.get $n))
    (block $done (loop $L
      (br_if $done (i32.eqz (local.get $i)))
      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
      (call $w_u8 (i32.wrap_i64 (i64.and (i64.shr_u (local.get $arg)
                    (i64.extend_i32_u (i32.mul (local.get $i) (i32.const 8)))) (i64.const 0xff))))
      (br $L))))

  (func $w_bytes (export "w_bytes") (param $p i32) (param $len i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $done (loop $L
      (br_if $done (i32.eq (local.get $i) (local.get $len)))
      (call $w_u8 (i32.load8_u (i32.add (local.get $p) (local.get $i))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $L))))

  (func $w_uint (export "w_uint") (param $v i64) (call $w_head (i32.const 0) (local.get $v)))
  (func $w_text (export "w_text") (param $p i32) (param $len i32)
    (call $w_head (i32.const 3) (i64.extend_i32_u (local.get $len)))
    (call $w_bytes (local.get $p) (local.get $len)))
  (func $w_bstr (export "w_bstr") (param $p i32) (param $len i32)
    (call $w_head (i32.const 2) (i64.extend_i32_u (local.get $len)))
    (call $w_bytes (local.get $p) (local.get $len)))
  (func $w_map (export "w_map") (param $n i64) (call $w_head (i32.const 5) (local.get $n)))
  (func $w_array (export "w_array") (param $n i64) (call $w_head (i32.const 4) (local.get $n)))
)
