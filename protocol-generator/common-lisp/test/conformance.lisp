;;;; conformance.lisp — ECF conformance harness (hand-rolled, no test framework).
;;;;
;;;; Loads the normative fixture (conformance-vectors-v1.cbor), decodes it with THIS
;;;; peer's own decoder (a decoder bug here is itself a conformance failure, per
;;;; ENTITY-CBOR-ENCODING.md §E.3), runs every vector, and byte-compares against the
;;;; cross-blessed `canonical` field. The fixture is the Go wire-conformance oracle's
;;;; output (build-fixture / emit-canonical), so byte-identity to it == oracle PASS.
;;;;
;;;; Vectors dispatch by category (the `id` prefix):
;;;;   content_hash  -> varint(format_code) ‖ SHA-2(ECF({type,data}))
;;;;   peer_id       -> ECF-text(Base58(varint(kt) ‖ varint(ht) ‖ digest))
;;;;   signature     -> Ed25519_sign(seed, ECF({type,data}))
;;;;   everything else (float/int/map_keys/length/primitive/nested/envelope)
;;;;                 -> plain ECF cbor-encode(input)
;;;;   decode_reject -> the decoder MUST reject the `canonical` wire bytes

(defpackage #:entity-core/test
  (:use #:cl #:entity-core)
  (:export #:run-conformance #:run-all #:main))

(in-package #:entity-core/test)

;; ── fixture-map accessors (the fixture decodes to cbor-map / bytes / string) ──
(defun mget (map key &optional default)
  (let ((entry (assoc key (entity-core::cbor-map-pairs map) :test #'equal)))
    (if entry (cdr entry) default)))

(defun mhas (map key)
  (and (assoc key (entity-core::cbor-map-pairs map) :test #'equal) t))

(defun bv (v) (entity-core::bytes-octets v))  ; unwrap a `bytes` value -> octets

(defun hexstr (octets)
  (string-downcase
   (with-output-to-string (s)
     (loop for b across (coerce octets '(simple-array (unsigned-byte 8) (*)))
           do (format s "~2,'0x" b)))))

(defun octets= (a b)
  (let ((a (coerce a '(simple-array (unsigned-byte 8) (*))))
        (b (coerce b '(simple-array (unsigned-byte 8) (*)))))
    (and (= (length a) (length b))
         (loop for x across a for y across b always (= x y)))))

(defun category (id)
  (let ((dot (position #\. id)))
    (if dot (subseq id 0 dot) id)))

;; ── per-vector producer ──────────────────────────────────────────────────────
(defun produce (id input)
  (let ((cat (category id)))
    (cond
      ((string= cat "content_hash")
       (let ((fc (if (mhas input "format_code") (mget input "format_code") 0)))
         ;; rebuild the entity as a cbor-map of {type, data}
         (content-hash (entity-core::map-of "type" (mget input "type")
                                            "data" (mget input "data"))
                       fc)))
      ((string= cat "peer_id")
       (cbor-encode (peer-id-format (mget input "key_type")
                                    (mget input "hash_type")
                                    (bv (mget input "digest")))))
      ((string= cat "signature")
       (let* ((entity (mget input "entity"))
              (ecf (cbor-encode (entity-core::map-of "type" (mget entity "type")
                                                     "data" (mget entity "data")))))
         (ed-sign (bv (mget input "seed")) ecf :ed25519)))
      (t (cbor-encode input)))))

(defun run-vector (vm)
  "Run one vector map. Returns (values id pass-p detail)."
  (let ((id (mget vm "id"))
        (kind (mget vm "kind")))
    (cond
      ((string= kind "decode_reject")
       (let ((wire (bv (mget vm "canonical"))))
         (handler-case
             (progn (cbor-decode wire) (values id nil :accepted-a-reject-vector))
           (entity-core-error () (values id t nil)))))
      ((string= kind "encode_equal")
       (let ((want (bv (mget vm "canonical")))
             (input (mget vm "input")))
         (handler-case
             (let ((got (produce id input)))
               (if (octets= got want)
                   (values id t nil)
                   (values id nil (list :want (hexstr want) :got (hexstr got)))))
           (error (c) (values id nil (list :raised (princ-to-string c)))))))
      (t (values id :skip kind)))))

(defun read-file-octets (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((buf (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence buf in)
      buf)))

(defun default-fixture-path ()
  (or (uiop:getenv "ECF_FIXTURE")
      "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"))

(defun run-conformance (&optional (path (default-fixture-path)))
  "Run the ECF conformance corpus at PATH. Returns (values pass fail total)."
  (let* ((octets (read-file-octets path))
         (vectors (cbor-decode octets))
         (pass 0) (fail 0) (total 0)
         (by-cat (make-hash-table :test 'equal)))
    (format t "~&== ECF conformance: ~a ==~%" path)
    (dolist (v vectors)
      (multiple-value-bind (id ok detail) (run-vector v)
        (cond
          ((eq ok :skip) nil)  ; meta / non-vector entries
          (t
           (incf total)
           (let ((c (category id)))
             (incf (gethash c by-cat 0)))
           (if ok
               (incf pass)
               (progn (incf fail)
                      (format t "  FAIL ~a: ~a~%" id detail)))))))
    (format t "~&Per-category vector counts:~%")
    (let ((cats '()))
      (maphash (lambda (k v) (push (cons k v) cats)) by-cat)
      (dolist (kv (sort cats #'string< :key #'car))
        (format t "  ~12a ~d~%" (car kv) (cdr kv))))
    (format t "~&RESULT: ~d/~d PASS, ~d FAIL~%" pass total fail)
    (values pass fail total)))

(defun run-all ()
  "Run conformance + selftest; exit non-zero on any failure (CI entry point)."
  (multiple-value-bind (pass fail total) (run-conformance)
    (declare (ignore pass total))
    (let ((self-fail (run-selftest)))
      (let ((bad (+ fail self-fail)))
        (when (find-package :uiop)
          (uiop:quit (if (zerop bad) 0 1)))
        (zerop bad)))))
