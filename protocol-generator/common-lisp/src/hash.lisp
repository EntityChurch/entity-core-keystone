;;;; hash.lisp — content_hash construction (ENTITY-CBOR-ENCODING.md §4.2).
;;;;
;;;;     content_hash = varint(format_code) ‖ HASH(ECF({type, data}))
;;;;
;;;; Format code 0x00 = ecfv1-sha256 (the required floor); 0x01 = ecfv1-sha384
;;;; (agility). The format_code is NOT part of the hashed entity — only {type,data}
;;;; is hashed. The varint prefix is multicodec-style LEB128 (invariant N1), so a
;;;; code >= 0x80 extends to multiple bytes.
;;;;
;;;; A-CL-007 (carried from A-OC-004): CONSTRUCT side serialises the caller-supplied
;;;; format_code verbatim (so content_hash.4 with code 128 passes); RECEIVE/verify
;;;; side (resolve-content-hash-format) rejects any unallocated code with
;;;; UNSUPPORTED-CONTENT-HASH-FORMAT.

(in-package #:entity-core)

;; Allocated content-hash format codes (V7 §1.2 / §4.3 registry — active set).
(defparameter +content-hash-formats+
  '((0 . :sha256) (1 . :sha384)))

(defun resolve-content-hash-format (code)
  "Receive-side: resolve an integer format CODE to its ironclad digest keyword.
Signals UNSUPPORTED-CONTENT-HASH-FORMAT for any code outside the allocated set."
  (let ((entry (assoc code +content-hash-formats+)))
    (if entry (cdr entry)
        (error 'unsupported-content-hash-format :detail code))))

(defun %digest-keyword (format-code)
  "Construct-side digest selection: 0x01 -> SHA-384, everything else -> SHA-256.
The corpus exercises only the varint PREFIX for synthetic high codes
(content_hash.4); the peer layer (S3) rejects unallocated codes on receive."
  (if (= format-code 1) :sha384 :sha256))

(defun content-hash (entity &optional (format-code 0))
  "Compute the wire content_hash over ENTITY (a cbor-map carrying \"type\" and
\"data\"). Returns an octet-vector: varint(format-code) ‖ digest(ECF({type,data}))."
  (let* ((type (map-get entity "type"))
         (data (map-get entity "data"))
         (hashed (map-of "type" type "data" data))
         (ecf (cbor-encode hashed))
         (digest (ironclad:digest-sequence (%digest-keyword format-code) ecf)))
    (concatenate 'octet-vector (varint-encode format-code) digest)))

(defun map-get (map key)
  "Fetch KEY (string) from a cbor-map. Signals on absence."
  (let ((entry (assoc key (cbor-map-pairs map) :test #'equal)))
    (if entry (cdr entry)
        (error 'entity-core-error :detail (list :missing-key key)))))
