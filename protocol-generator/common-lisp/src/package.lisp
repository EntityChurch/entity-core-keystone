;;;; package.lisp — package definitions for the entity-core codec.
;;;;
;;;; Naming follows the profile [naming]: lisp-case symbols, +earmuffs+ constants,
;;;; *earmuffs* specials, -p predicates. The reader upcases by default; external
;;;; string/byte wire data is kept case-EXACT and is never round-tripped through
;;;; symbols (the case-insensitive-reader footgun — see profile [idiom]).

(defpackage #:entity-core
  (:nicknames #:ec)
  (:use #:cl)
  (:export
   ;; ── conditions (the condition-system error model, profile [error_model]) ──
   #:entity-core-error
   #:non-canonical-ecf
   #:truncated-input
   #:tag-rejected
   #:bad-seed
   #:unsupported-content-hash-format
   #:unsupported-key-type
   #:duplicate-map-key

   ;; ── CBOR / ECF codec ──
   #:cbor-encode
   #:cbor-decode
   #:cbor-decode-safe
   ;; the value sentinels for the float specials + byte-string distinction
   #:+nan+
   #:+inf+
   #:+neg-inf+
   #:+neg-zero+
   #:bytes
   #:bytes-octets
   #:make-bytes
   #:bytes-p
   #:cbor-map
   #:make-cbor-map
   #:cbor-map-pairs
   #:cbor-map-p
   #:map-of

   ;; ── varint (LEB128, N1) ──
   #:varint-encode
   #:varint-decode

   ;; ── base58 ──
   #:base58-encode
   #:base58-decode

   ;; ── content hash ──
   #:content-hash
   #:resolve-content-hash-format

   ;; ── peer id ──
   #:peer-id-format
   #:peer-id-parse
   #:peer-id-from-public-key
   #:key-type-code

   ;; ── signatures ──
   #:ed-sign
   #:ed-verify
   #:ed-public-key))
