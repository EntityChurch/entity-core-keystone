;;;; peer-wire.lisp — Wire framing (§1.6) + the two message builders (§3.2 EXECUTE,
;;;; §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]. The payload
;;;; is a CBOR-encoded system/protocol/envelope (§3.1).
;;;;
;;;; Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
;;;; authenticate are OPERATIONS on system/protocol/connect, not message types.

(in-package #:entity-core/peer)

(defconstant +max-frame+ (* 16 1024 1024) "§1.6 SHOULD bound — 16 MiB.")

(define-condition transport-closed (error) ()
  (:documentation "A clean EOF at a FRAME BOUNDARY: the peer closed and is owed
nothing. NOT a refusal — answering one would put a 400 on the wire for every peer that
simply hangs up."))

(define-condition truncated-frame (error) ()
  (:documentation "A frame that never completed: a prefix declaring N bytes followed by
fewer, or a partial length prefix. §4.11's framing arm names this input outright —
\"un-parseable, truncated or non-canonical CBOR, or a length prefix that never
completes\" -> 400 invalid_request.

A SEPARATE CONDITION FROM TRANSPORT-CLOSED because the two are different events and the
read collapses them; the distinction can only be made here, where the frame boundary is
known."))

(define-condition frame-too-large (error) ()
  (:documentation "A length prefix over +MAX-FRAME+ (§4.10(a)). Distinguished from
TRUNCATED-FRAME because §4.11 gives the two DIFFERENT codes: this one is
413 payload_too_large, and since 0.8.2.25 (N14) emitting it is a MUST rather than a
SHOULD — the condition is detected at the length prefix with the connection intact and
nothing spent, so the permissive mood had nothing to license."))

;; ── stream read/write of a full frame ─────────────────────────────────────────

(defun read-exact (stream n &key (at-boundary nil))
  "Read exactly N octets from STREAM into a fresh octet-vector.

A short read signals TRUNCATED-FRAME — a §4.11 refusal owed a coded frame — EXCEPT when
AT-BOUNDARY is true and NOTHING was read, which is the ordinary close and signals
TRANSPORT-CLOSED. A short read at a boundary (1-3 bytes of a length prefix) is still a
truncation, which is why the test is \"any bytes read\" rather than \"4 or more\"."
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (when (< got n)
        (if (and at-boundary (zerop got))
            (error 'transport-closed)
            (error 'truncated-frame)))
      buf)))

(defun read-frame (stream)
  "Read one length-prefixed frame; return its CBOR payload octet-vector.

Signals TRANSPORT-CLOSED on a clean EOF at a frame boundary (owed nothing),
TRUNCATED-FRAME on a stream that ended mid-frame, and FRAME-TOO-LARGE on an over-limit
length prefix (both §4.11 refusals owed a coded frame; the caller emits it)."
  (let* ((hdr (read-exact stream 4 :at-boundary t))
         (len (logior (ash (aref hdr 0) 24) (ash (aref hdr 1) 16)
                      (ash (aref hdr 2) 8) (aref hdr 3))))
    (when (> len +max-frame+) (error 'frame-too-large))
    ;; A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
    ;; refused there as bytes that never become an Envelope.
    (if (zerop len) (make-array 0 :element-type '(unsigned-byte 8)) (read-exact stream len))))

;; ── §4.11 pre-admission refusal classification (0.8.2.25) ─────────────────────

(defun pre-admission-refusal (c)
  "The (status code message) §4.11 assigns a pre-admission failure's CAUSE.

\"The frame obligation belongs to the class; the CODE belongs to the cause [MUST]\" —
a single code for the class would answer an honest caller under the wrong reason and
send them to the wrong layer.

  connect-auth proof-of-possession      401 authentication_failed  (§4.6/§4.7 — the
                                           connect handler's, not here)
  envelope over the configured maximum  413 payload_too_large      (§4.10(a), N14)
  resolution integrity (mis-keyed inc.) 400 hash_mismatch          (§5.2a, §1.8)
  framing / never becomes an Envelope   400 invalid_request        (§4.7, §4.11)
  root is neither EXECUTE nor E_R       400 invalid_request        (§3.3, §4.11 — in
                                           DISPATCH, not here)

THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. §4.11 rules that code
non-conformant \"on the framing arm\" and gives its reason in the same sentence:
ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE rather
than in conflict. Everything else this decoder calls non-canonical (a non-minimal head,
an indefinite length, mis-ordered keys) is genuinely \"non-canonical CBOR that never
becomes an Envelope\" and takes invalid_request.

ORDER IS LOAD-BEARING: HASH-MISMATCH is a subtype of BAD-ENTITY and TAG-REJECTED a
subtype of NON-CANONICAL-ECF, so each specific arm must be tested before its supertype
or it can never be reached. TYPECASE tests in order, which is why this is a typecase and
not a set of independent predicates.

The messages are a FIXED TABLE, never the condition's own report: a wire-visible string
stays ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte in
an encoded string, on two unrelated compilers), the internal details carry section signs,
and nothing here echoes attacker-supplied bytes back."
  (typecase c
    (frame-too-large
     (list 413 "payload_too_large" "inbound frame exceeds the configured maximum size"))
    (hash-mismatch
     (list 400 "hash_mismatch" "an entity was addressed by a hash that does not bind to it"))
    (entity-core:tag-rejected
     (list 400 "non_canonical_ecf" "CBOR tags are forbidden anywhere in an entity data field"))
    (t
     (list 400 "invalid_request" "frame did not decode into an envelope"))))

(defun framing-refusal-p (c)
  "Whether a READ-FRAME failure is a §4.11 REFUSAL owed a coded frame rather than an
ordinary end of connection. A closed or reset socket is not a refusal of anything and
there is nobody left to answer."
  (or (typep c 'frame-too-large) (typep c 'truncated-frame)))

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
