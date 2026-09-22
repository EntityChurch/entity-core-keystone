;;;; peer-model.lisp — the materialized entity {type,data,content_hash} (§1.1, §3.4)
;;;; and the protocol envelope (§3.1), sitting directly on the S2 codec.
;;;;
;;;; An entity's content_hash covers ONLY {type,data} (§1.1); the wire form carries
;;;; content_hash as a third field so entities are self-describing across
;;;; serialization (§3.1). We keep the two forms distinct: the hash is never
;;;; computed over a map that contains the content_hash field.
;;;;
;;;; data is a cbor-map (the S2 decoded form). The peer reads entity fields out of
;;;; that map; it never round-trips wire strings/bytes through CL symbols.

(in-package #:entity-core/peer)

;; ── entity ───────────────────────────────────────────────────────────────────

(defstruct (entity (:constructor %make-entity (typ data hash)))
  (typ  "" :type string  :read-only t)
  (data nil              :read-only t)   ; a cbor-map
  ;; 33 bytes: format byte 0x00 ‖ 32-byte SHA-256 digest (octet-vector)
  (hash (make-octet-vector 0) :type octet-vector :read-only t))

(defun make-entity (typ data)
  "Construct a materialized entity, computing content_hash under the
ecfv1-sha256 floor (format_code 0). DATA is a cbor-map."
  (let ((m (map-of "type" typ "data" data)))
    (%make-entity typ data (content-hash m 0))))

;; ── cbor-map field helpers (data is a cbor-map) ──────────────────────────────

(defun map-field (map key)
  "Fetch KEY (a string) from a cbor-map, or NIL if absent."
  (when (cbor-map-p map)
    (cdr (assoc key (cbor-map-pairs map) :test #'equal))))

(defun entity-field (e key)
  "Fetch KEY from entity E's data map (the raw decoded value, or NIL)."
  (map-field (entity-data e) key))

(defun entity-text (e key)
  (let ((v (entity-field e key))) (when (stringp v) v)))

(defun entity-bytes (e key)
  "Return KEY's value as an octet-vector if it is a byte string, else NIL."
  (let ((v (entity-field e key)))
    (when (bytes-p v) (bytes-octets v))))

(defun entity-uint (e key)
  (let ((v (entity-field e key))) (when (integerp v) v)))

(defun entity-entity (e key)
  "Decode a nested entity carried at KEY (a cbor-map with type/data/content_hash)."
  (let ((v (entity-field e key)))
    (when (cbor-map-p v) (entity-of-cbor v))))

;; ── wire form: entity carries its content_hash ───────────────────────────────

(defun entity-to-cbor (e)
  "Serialize an entity to its wire cbor-map {type, data, content_hash}."
  (map-of "type" (entity-typ e)
          "data" (entity-data e)
          "content_hash" (make-bytes (entity-hash e))))

(define-condition bad-entity (error)
  ((detail :initarg :detail :reader bad-entity-detail))
  (:documentation "A STRUCTURALLY malformed wire entity or envelope: a missing or
ill-typed TYPE, an absent DATA, a non-map root, an INCLUDED key that is not a byte
string at all.

These are bytes that never become an Envelope, which is §4.11's framing arm:
400 invalid_request. HASH-MISMATCH is the OTHER cause and takes a different code.")
  (:report (lambda (c s) (format s "bad entity: ~a" (bad-entity-detail c)))))

(define-condition hash-mismatch (bad-entity) ()
  (:documentation "A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
CONTENT_HASH is not content_hash({type, data}), or an INCLUDED entry whose MAP KEY does
not bind to the entity filed under it.

§5.2a pins this arm: \"A peer that refuses at the decode boundary MUST answer
400 hash_mismatch [MUST]\" (mood corrected 0.8.2.24), and in the same breath
\"400 non_canonical_ecf is NOT conformant here [MUST]\". That code is
ENTITY-CBOR-ENCODING §6.3's, for a CBOR tag-policy violation, and a mis-keyed INCLUDED
entry carries NO TAG: its encoding is canonical, what is false is the claim the KEY
makes, and the remedy non_canonical_ecf selects (re-encode) sends an honest caller to
the wrong layer. This peer answered non_canonical_ecf for every decode-boundary refusal
until 0.8.2.24 — measured on the wire, arc-probe B1/B2.

A SUBTYPE of BAD-ENTITY rather than a sibling, so every existing HANDLER-CASE on
BAD-ENTITY keeps its behaviour; the classifier that maps a refusal to a code tests this
type FIRST, which is the whole point of the split. The condition system makes that
ordering a TYPECASE rather than a string match — a classifier that recognised the cause
by its report text would be one edit away from silently re-collapsing them.")
  (:report (lambda (c s) (format s "hash mismatch: ~a" (bad-entity-detail c)))))

(defun octets-equal (a b)
  (and (= (length a) (length b))
       (loop for x across a for y across b always (= x y))))

(defun entity-of-cbor (m)
  "Parse a wire entity cbor-map, recompute the hash from {type,data}, and validate
it against the carried content_hash per entity fidelity (§1.8). We trust our
recomputed hash, not the wire bytes (§5.2 validate-before-trust)."
  (let ((typ (map-field m "type"))
        (data (map-field m "data")))
    (unless (stringp typ) (error 'bad-entity :detail "missing/invalid type"))
    (unless data (error 'bad-entity :detail "missing data"))
    (let ((e (make-entity typ data))
          (carried (map-field m "content_hash")))
      (when (and (bytes-p carried)
                 (not (octets-equal (bytes-octets carried) (entity-hash e))))
        ;; §1.8 item 1 — RESOLUTION INTEGRITY, not a structural fault. §5.2a pins the
        ;; decode-boundary code for this cause to 400 hash_mismatch and rules
        ;; 400 non_canonical_ecf non-conformant here (0.8.2.24 N4/N5).
        (error 'hash-mismatch :detail "content_hash mismatch (§1.8 fidelity)"))
      e)))

;; ── envelope (§3.1) ──────────────────────────────────────────────────────────
;;
;; included is an alist (hash-octets . entity); key = the entity content_hash.

(defstruct (envelope (:constructor make-envelope (root &optional included)))
  (root nil :read-only t)            ; an entity
  (included nil :read-only t))       ; alist (octet-vector . entity)

(defun included-get (env h)
  "Find an included entity by its content_hash octet-vector H."
  (cdr (assoc h (envelope-included env) :test #'octets-equal)))

(defun envelope-to-cbor (env)
  (let ((inc (mapcar (lambda (pair)
                       (cons (make-bytes (car pair)) (entity-to-cbor (cdr pair))))
                     (envelope-included env))))
    (map-of "root" (entity-to-cbor (envelope-root env))
            "included" (make-cbor-map inc))))

(defun envelope-of-cbor (m)
  (let ((root-c (map-field m "root"))
        (inc-c (map-field m "included")))
    (unless (cbor-map-p root-c) (error 'bad-entity :detail "envelope: missing root"))
    (let ((root (entity-of-cbor root-c))
          (included
            (when (cbor-map-p inc-c)
              (mapcar
               (lambda (pair)
                 (let ((k (car pair)) (v (cdr pair)))
                   (unless (bytes-p k)
                     (error 'bad-entity :detail "envelope: included key not bytes"))
                   (let ((e (entity-of-cbor v)))
                     ;; §3.1 key != content_hash — §1.8's resolution-integrity
                     ;; obligation, mechanism (a) "bind the key": reject the entry whose
                     ;; key is not content_hash({type, data}) of the entity under it,
                     ;; which fails the envelope closed at ONE site. §5.2a's code for
                     ;; this arm is hash_mismatch, not the structural invalid_request
                     ;; beside it (0.8.2.24 N4/N5).
                     (unless (octets-equal (bytes-octets k) (entity-hash e))
                       (error 'hash-mismatch :detail "included key != content_hash"))
                     (cons (bytes-octets k) e))))
               (cbor-map-pairs inc-c)))))
      (make-envelope root included))))

;; ── hex (for diagnostics + path keys) ────────────────────────────────────────

(defun hex (octets)
  ;; LOWERCASE hex — the address-space convention (matches the Go oracle's
  ;; hex.EncodeToString and the sibling peers' Model.hex `%02x`). Tree paths are
  ;; case-sensitive string keys, so system/signature/{hash} etc. MUST be lower.
  (with-output-to-string (s)
    (loop for b across octets do (format s "~(~2,'0x~)" b))))

(defun unhex (string)
  "Parse a lowercase/uppercase hex STRING back to an octet-vector."
  (let* ((n (floor (length string) 2))
         (out (make-octet-vector n)))
    (dotimes (i n)
      (setf (aref out i) (parse-integer string :start (* i 2) :end (+ (* i 2) 2) :radix 16)))
    out))
