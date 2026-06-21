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
  (:report (lambda (c s) (format s "bad entity: ~a" (bad-entity-detail c)))))

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
        (error 'bad-entity :detail "content_hash mismatch (§1.8 fidelity)"))
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
                     ;; §3.1: included content_hash MUST equal the map key.
                     (unless (octets-equal (bytes-octets k) (entity-hash e))
                       (error 'bad-entity :detail "included key != content_hash"))
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
