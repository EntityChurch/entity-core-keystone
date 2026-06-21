;;;; peer-wire.lisp — Wire framing (§1.6) + the two message builders (§3.2 EXECUTE,
;;;; §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]. The payload
;;;; is a CBOR-encoded system/protocol/envelope (§3.1).
;;;;
;;;; Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
;;;; authenticate are OPERATIONS on system/protocol/connect, not message types.

(in-package #:entity-core/peer)

(defconstant +max-frame+ (* 16 1024 1024) "§1.6 SHOULD bound — 16 MiB.")

(define-condition transport-closed (error) ())

;; ── stream read/write of a full frame ─────────────────────────────────────────

(defun read-exact (stream n)
  "Read exactly N octets from STREAM into a fresh octet-vector; signals
TRANSPORT-CLOSED on EOF."
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (when (< got n) (error 'transport-closed))
      buf)))

(defun read-frame (stream)
  "Read one length-prefixed frame; return its CBOR payload octet-vector."
  (let* ((hdr (read-exact stream 4))
         (len (logior (ash (aref hdr 0) 24) (ash (aref hdr 1) 16)
                      (ash (aref hdr 2) 8) (aref hdr 3))))
    (when (or (< len 0) (> len +max-frame+)) (error "frame too large"))
    (read-exact stream len)))

(defun write-frame (stream payload)
  "Write PAYLOAD (octet-vector) as a length-prefixed frame and flush."
  (let* ((len (length payload))
         (hdr (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref hdr 0) (logand (ash len -24) #xff)
          (aref hdr 1) (logand (ash len -16) #xff)
          (aref hdr 2) (logand (ash len -8) #xff)
          (aref hdr 3) (logand len #xff))
    (write-sequence hdr stream)
    (write-sequence payload stream)
    (finish-output stream)))

;; ── envelope <-> frame ─────────────────────────────────────────────────────────

(defun envelope-of-frame (payload) (envelope-of-cbor (cbor-decode payload)))
(defun frame-of-envelope (env) (cbor-encode (envelope-to-cbor env)))

;; ── EXECUTE_RESPONSE builder (§3.3) ────────────────────────────────────────────

(defun make-response (request-id status result)
  (make-entity "system/protocol/execute/response"
               (map-of "request_id" request-id
                       "status" status
                       "result" (entity-to-cbor result))))

;; ── EXECUTE builder (§3.2) ──────────────────────────────────────────────────────

(defun make-execute (request-id uri operation params
                     &key author capability resource)
  (let ((pairs (list (cons "request_id" request-id)
                     (cons "uri" uri)
                     (cons "operation" operation)
                     (cons "params" (entity-to-cbor params)))))
    (when author (setf pairs (append pairs (list (cons "author" (make-bytes author))))))
    (when capability (setf pairs (append pairs (list (cons "capability" (make-bytes capability))))))
    (when resource (setf pairs (append pairs (list (cons "resource" resource)))))
    (make-entity "system/protocol/execute" (make-cbor-map pairs))))

;; ── error result + empty params ─────────────────────────────────────────────────

(defun error-result (code &optional message)
  (make-entity "system/protocol/error"
               (if message
                   (map-of "code" code "message" message)
                   (map-of "code" code))))

(defun empty-params ()
  "Empty-params shape (§3.2): primitive/any whose data is the canonical empty map."
  (make-entity "primitive/any" (make-cbor-map nil)))

(defun resource-target (&rest targets)
  "Build a resource cbor-map {targets: [...]}."
  (map-of "targets" (copy-list targets)))
