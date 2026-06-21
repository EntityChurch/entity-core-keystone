;;;; peer-id.lisp — peer-id formatting/parsing + §1.5 canonical-form derivation.
;;;;
;;;;     peer_id = Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)
;;;;
;;;; key_type and hash_type are multicodec-style LEB128 varints (invariant N1).
;;;;
;;;; A-CL-002 (corroborates A-ZIG-001 / A-OC-007 — THIRD spec-first peer): the
;;;; Ed25519 peer_id is derived from the §1.5 v7.65 CANONICAL-FORM TABLE
;;;; (hash_type=0x00 identity-multihash, digest = RAW public key, NO hash), NOT the
;;;; stale §7.4 / §1.5-line-436 SHA256(pubkey) skeleton.
;;;;
;;;; The §1.5 size-cutoff rule (confirmed by the Elixir peer's agility run): a key
;;;; <= 32 bytes is identity-multihash (hash_type=0x00, digest = key); a larger key
;;;; is SHA-256-form (hash_type=0x01, digest = SHA-256(key)). So Ed25519 (32 B) ->
;;;; (0x01, 0x00, pubkey) and Ed448 (57 B) -> (0x02, 0x01, sha256(pubkey)).

(in-package #:entity-core)

;; key_type codes (V7 §1.5 seed table).
(defparameter +key-type-codes+
  '((:ed25519 . 1) (:ed448 . 2)))

(defun key-type-code (curve)
  "Map a curve keyword (:ed25519 / :ed448) to its key_type code."
  (let ((entry (assoc curve +key-type-codes+)))
    (if entry (cdr entry)
        (error 'unsupported-key-type :detail curve))))

(defun peer-id-format (key-type hash-type digest)
  "Format a peer-id string from its abstract components."
  (base58-encode
   (concatenate 'octet-vector
                (varint-encode key-type)
                (varint-encode hash-type)
                (coerce digest 'octet-vector))))

(defun peer-id-parse (string)
  "Parse a peer-id STRING -> (values key-type hash-type digest-octets)."
  (let ((raw (base58-decode string)))
    (multiple-value-bind (key-type i1) (varint-decode raw)
      (multiple-value-bind (hash-type i2) (varint-decode raw i1)
        (values key-type hash-type (subseq raw i2))))))

(defun peer-id-from-public-key (public-key curve)
  "Derive a peer-id from a raw PUBLIC-KEY (octet-vector) and CURVE keyword, per the
§1.5 canonical-form table + size-cutoff rule (A-CL-002)."
  (let* ((pk (coerce public-key 'octet-vector))
         (key-type (key-type-code curve)))
    (multiple-value-bind (hash-type digest)
        (if (<= (length pk) 32)
            (values 0 pk)                                       ; identity-multihash
            (values 1 (ironclad:digest-sequence :sha256 pk)))  ; SHA-256-form
      (peer-id-format key-type hash-type digest))))
