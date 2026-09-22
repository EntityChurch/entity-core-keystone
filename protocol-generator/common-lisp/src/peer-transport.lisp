;;;; peer-transport.lisp — Transport (L4): TCP listener + per-connection serve loop
;;;; via sb-bsd-sockets + sb-thread (§1.6 framing, §4.8 inbound concurrency, §6.11
;;;; reentry). Plus the CLIENT dialer/handshake used by the two-peer loopback.
;;;;
;;;; CONCURRENCY MODEL (the distant-idiom probe, A-CL-003): native SBCL threads.
;;;; One reader thread per connection demuxes inbound frames (§6.11). An
;;;; EXECUTE_RESPONSE routes to the awaiting outbound caller by request_id; an
;;;; EXECUTE is dispatched on its OWN thread (§4.8) so a handler that originates an
;;;; outbound EXECUTE (§6.13(b)) and awaits its response does NOT block the reader —
;;;; the reader keeps reading and routes the response back. Writes (inbound
;;;; responses + outbound requests share the stream) are serialized by a mutex.
;;;; request_id → (slot . waitqueue) correlation under a mutex is the §6.11 demux —
;;;; the CL analogue of OCaml's Condition+Hashtbl (A-CL-003 validated here).

(in-package #:entity-core/peer)

;; ── per-connection IO (shared by server + client) ──────────────────────────────

(defstruct (io (:constructor %make-io (socket stream)))
  socket stream
  (write-lock (sb-thread:make-mutex :name "write"))
  (pending-lock (sb-thread:make-mutex :name "pending"))
  (pending (make-hash-table :test 'equal))   ; request_id → (cons slot-box waitqueue)
  (closed nil))

(defun make-io (socket stream) (%make-io socket stream))

(defun write-framed (io env)
  (sb-thread:with-mutex ((io-write-lock io))
    (write-frame (io-stream io) (frame-of-envelope env))))

;; Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11 demux).
(defun route-response (io env)
  (let ((request-id (or (entity-text (envelope-root env) "request_id") "")))
    (sb-thread:with-mutex ((io-pending-lock io))
      (let ((cell (gethash request-id (io-pending io))))
        (when cell
          (setf (car cell) (list env))           ; box the value (nil-vs-set distinction)
          (sb-thread:condition-broadcast (cdr cell)))))))

;; §6.13(b) outbound primitive: send a request envelope, await its correlated
;; EXECUTE_RESPONSE. Blocks the calling (dispatch worker) thread; the reader routes
;; the response. Returns NIL if the connection closes first.
(defun io-outbound (io request)
  (let* ((request-id (or (entity-text (envelope-root request) "request_id") ""))
         (wq (sb-thread:make-waitqueue))
         (cell (cons nil wq)))                    ; (car) = NIL until (list env)
    (sb-thread:with-mutex ((io-pending-lock io))
      (setf (gethash request-id (io-pending io)) cell))
    (write-framed io request)
    (sb-thread:with-mutex ((io-pending-lock io))
      (loop while (and (null (car cell)) (not (io-closed io)))
            do (sb-thread:condition-wait wq (io-pending-lock io)))
      (remhash request-id (io-pending io)))
    (when (car cell) (first (car cell)))))

(defun close-io (io)
  (sb-thread:with-mutex ((io-pending-lock io))
    (setf (io-closed io) t)
    (maphash (lambda (k cell) (declare (ignore k))
               (sb-thread:condition-broadcast (cdr cell)))
             (io-pending io))))

;; The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on
;; its own thread (§4.8). ON-EXECUTE dispatches one inbound EXECUTE + writes its
;; response. Returns when the connection closes / a malformed frame ends it.
(defun read-loop (io on-execute)
  (handler-case
      (loop
        (let ((payload
                (handler-case (read-frame (io-stream io))
                  ;; A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed
                  ;; nothing.
                  ((or transport-closed end-of-file) () (return))
                  ;; §4.11: BOTH of these are REFUSALS owed a coded frame, and both used
                  ;; to end the loop in silence — "closing with no coded frame", which is
                  ;; indistinguishable from a network fault and, on a multiplexed
                  ;; connection, destroys unrelated ADMITTED requests. §4.10(a)'s mood was
                  ;; raised SHOULD -> MUST at 0.8.2.25 (N14).
                  ;;
                  ;; The stream is desynchronized on both arms — an oversize body was
                  ;; never drained, a truncated one never arrived — so the coded frame
                  ;; goes out and THEN the loop ends. §4.11 makes the frame mandatory and
                  ;; leaves the close to us; closing is the only sound choice once the
                  ;; framing is lost, and it is a CHOICE rather than an alternative to
                  ;; answering.
                  ;;
                  ;; §4.11's best-effort UNCORRELATED form: no request_id can be recovered
                  ;; from a frame whose body never arrived, and guessing one would
                  ;; correlate the refusal to somebody else's in-flight request.
                  ((or truncated-frame frame-too-large) (c)
                    (refuse-pre-admission io "" (pre-admission-refusal c))
                    (return)))))
          (multiple-value-bind (env cond)
              (handler-case (values (envelope-of-frame payload) nil)
                (error (c) (values nil c)))
            (if (null env)
                ;; A COMPLETE frame the decoder refused. The framing is intact, so we
                ;; answer and KEEP SERVING — and the refusal MUST be a status rather than
                ;; silence (§4.11; §4.9(c) says the same from the other direction).
                ;;
                ;; THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
                ;; non_canonical_ecf for every cause until 0.8.2.24/.25 pinned them
                ;; apart: a mis-keyed included entry is 400 hash_mismatch (its encoding
                ;; is canonical — what is false is the claim the key makes), a tag-policy
                ;; violation keeps non_canonical_ecf, and everything else that never
                ;; becomes an Envelope is 400 invalid_request.
                ;;
                ;; The frame is still REJECTED — only enough is salvaged to correlate the
                ;; response, and an unrecoverable id takes §4.11's uncorrelated
                ;; best-effort form rather than the silence it used to take.
                (refuse-pre-admission io (salvage-request-id payload)
                                      (pre-admission-refusal cond))
                ;; EVERY OTHER ROOT GOES TO DISPATCH, including one that is neither
                ;; EXECUTE nor EXECUTE_RESPONSE. That used to be dropped by DISPATCH
                ;; returning NIL; §6.5's "Other type?" arm now answers 400 invalid_request
                ;; (0.8.2.25 N12/N17) and it does so in ONE place rather than in a second
                ;; copy here where the two could drift.
                (if (string= (entity-typ (envelope-root env)) "system/protocol/execute/response")
                    (route-response io env)
                    (sb-thread:make-thread (lambda () (funcall on-execute env))
                                           :name "exec-dispatch"))))))
    (error () nil)))

(defun salvage-request-id (payload)
  "Recover ONLY the request_id from a frame the strict decoder rejected, so the refusal
can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort frame.
Answers \"\" when nothing is recoverable.

The frame stays rejected: nothing is built from it, nothing is stored, and a tag is never
interpreted — the salvage decode exists solely to read back the correlation key. The
envelope and entity-wrapper shapes are fixed maps with no legal tag position, so a frame
whose ONLY defect is a tag inside some entity's data still has a structurally sound root,
which is exactly the case worth recovering (and the one CAP-6a's >2^64 half arrives as —
a bignum can only reach a peer as a major-type-6 tag)."
  (or (ignore-errors
       (let* ((v (cbor-decode-salvage payload))
              (root (map-field v "root"))
              (data (map-field root "data"))
              (rid (map-field data "request_id")))
         (and (stringp rid) rid)))
      ""))

(defun refuse-pre-admission (io request-id refusal)
  "Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
refused BEFORE it becomes an admitted request.

\"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
wire [MUST] — correlated by request_id where the id is available, and otherwise as a
best-effort coded frame carrying no correlation.\"

§4.9(c)'s deliver-or-signal rule is scoped to \"every request the peer ADMITS\" and
therefore reaches none of these, which is why §4.11 exists. Both of the non-conformant
behaviours it names separately were present on this peer: DROPPING the frame (the
un-salvageable decode arm and the non-EXECUTE root, \"the weaker of the two precisely
because nothing surfaces it\") and CLOSING with no coded frame (the oversize and
truncated arms' silent RETURN).

AN EMPTY REQUEST-ID IS THE BEST-EFFORT FORM, not a bug: it is what the section
prescribes where no id can be recovered."
  (destructuring-bind (status code message) refusal
    ;; A write failure here is a dead socket, not a protocol decision.
    (ignore-errors
     (write-framed io (make-envelope (make-response request-id status
                                                    (error-result code message))
                                     nil)))))

;; ── server: serve one accepted connection ───────────────────────────────────────

(defun serve-connection (peer socket)
  (let* ((stream (sb-bsd-sockets:socket-make-stream
                  socket :input t :output t :element-type '(unsigned-byte 8)))
         (io (make-io socket stream))
         (conn (make-conn)))
    ;; wire the §6.13(b) outbound seam to this connection's io (§6.11 reentry).
    (setf (conn-outbound conn) (lambda (req) (io-outbound io req)))
    (flet ((on-execute (env)
             ;; Per-request isolation: an exception on one adversarial request must
             ;; NOT tear down the connection (§3.3 every EXECUTE receives a response).
             (let ((resp (handler-case (dispatch peer conn env)
                           (error () (internal-error-response env)))))
               (when resp (ignore-errors (write-framed io resp))))))
      (read-loop io #'on-execute)
      (close-io io)
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

;; Listen on 127.0.0.1:PORT (0 = auto). Returns (values socket bound-port).
(defun listen-on (port)
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
    (sb-bsd-sockets:socket-bind sock #(127 0 0 1) port)
    (sb-bsd-sockets:socket-listen sock 64)
    (multiple-value-bind (addr bound) (sb-bsd-sockets:socket-name sock)
      (declare (ignore addr))
      (values sock bound))))

(defun accept-loop (peer sock)
  "Accept connections, serving each on its own thread. Returns when the socket
closes (accept signals)."
  (handler-case
      (loop
        (let ((client (sb-bsd-sockets:socket-accept sock)))
          (when client
            (sb-thread:make-thread (lambda () (serve-connection peer client))
                                   :name "serve-conn"))))
    (error () nil)))

(defun start-listener (peer port)
  "Bind + spawn the accept loop on its own thread. Returns (values socket bound-port thread)."
  (multiple-value-bind (sock bound) (listen-on port)
    (values sock bound
            (sb-thread:make-thread (lambda () (accept-loop peer sock)) :name "accept-loop"))))

;; ══════════════════════════════════════════════════════════════════════════════
;; Client side — the dialer + initiator handshake (drives the two-peer loopback)
;; ══════════════════════════════════════════════════════════════════════════════

(defstruct (client-connection (:constructor %make-client-connection (io)))
  io
  (req-counter 0)
  ;; populated by client-handshake (the authenticated session, §4.4):
  remote-peer-id
  capability            ; the cap token the remote minted for us at connect
  granter-peer          ; remote peer identity (the cap granter)
  cap-signature)        ; signature over the cap

(defun next-request-id (cc)
  (format nil "req-~d" (incf (client-connection-req-counter cc))))

(defun dial (host port)
  "Open a client connection to HOST:PORT and start its reader thread."
  (let* ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
         (addr (if (string= host "127.0.0.1") #(127 0 0 1)
                   (sb-bsd-sockets:host-ent-address
                    (sb-bsd-sockets:get-host-by-name host)))))
    (sb-bsd-sockets:socket-connect sock addr port)
    (let* ((stream (sb-bsd-sockets:socket-make-stream
                    sock :input t :output t :element-type '(unsigned-byte 8)))
           (io (make-io sock stream))
           (cc (%make-client-connection io)))
      ;; client reader: there are no inbound EXECUTEs from a core responder, only
      ;; EXECUTE_RESPONSEs — route them all to the pending table.
      (sb-thread:make-thread
       (lambda () (read-loop io (lambda (env) (declare (ignore env)) nil)))
       :name "client-reader")
      cc)))

(defun client-send (cc request)
  "Send REQUEST envelope and await its correlated EXECUTE_RESPONSE (request_id demux)."
  (io-outbound (client-connection-io cc) request))

;; ── initiator handshake (§4.1 forward leg: hello → authenticate) ────────────────

(defun client-handshake (cc local)
  "Drive the §4.1 forward handshake as initiator: hello then authenticate. On
success, populate CC with the §4.4 capability the responder minted. LOCAL is our
identity. Signals on a non-200 step. Returns CC."
  ;; ── hello ──
  (let* ((hello (make-entity "system/protocol/connect/hello"
                             (map-of "peer_id" (identity-peer-id local)
                                     "nonce" (make-bytes (random-bytes 32))
                                     "protocols" (list "entity-core/1.0")
                                     "timestamp" (now-ms)
                                     "hash_formats" (list "ecfv1-sha256")
                                     "key_types" (list "ed25519"))))
         (r1 (client-send cc (make-envelope
                              (make-execute (next-request-id cc) "system/protocol/connect"
                                            "hello" hello)))))
    (require-ok r1 "hello")
    (let* ((remote-hello (response-result r1))
           (remote-peer-id (entity-text remote-hello "peer_id"))
           (remote-nonce (entity-bytes remote-hello "nonce")))
      (setf (client-connection-remote-peer-id cc) remote-peer-id)
      ;; ── authenticate ──
      (let* ((auth (make-entity "system/protocol/connect/authenticate"
                                (map-of "peer_id" (identity-peer-id local)
                                        "public_key" (make-bytes (identity-public-key local))
                                        "key_type" "ed25519"
                                        "nonce" (make-bytes remote-nonce))))
             (auth-sig (sign-entity local auth))
             (r2 (client-send cc (make-envelope
                                  (make-execute (next-request-id cc) "system/protocol/connect"
                                                "authenticate" auth)
                                  (list (cons (identity-hash local) (identity-peer-entity local))
                                        (cons (entity-hash auth-sig) auth-sig))))))
        (require-ok r2 "authenticate")
        ;; parse the §4.4 initial capability grant
        (let* ((grant (response-result r2))
               (token-h (entity-bytes grant "token"))
               (token (included-get r2 token-h)))
          (unless token (error "authenticate grant omits the capability token"))
          (let* ((granter-h (entity-bytes token "granter"))
                 (granter-peer (included-get r2 granter-h))
                 (cap-sig (find-signature (entity-hash token) (envelope-included r2))))
            (unless granter-peer (error "authenticate grant omits the granter identity"))
            (unless cap-sig (error "authenticate grant omits the capability signature"))
            (setf (client-connection-capability cc) token
                  (client-connection-granter-peer cc) granter-peer
                  (client-connection-cap-signature cc) cap-sig))))
      cc)))

(defun response-result (env)
  "Decode the result entity from an EXECUTE_RESPONSE envelope."
  (let ((rc (entity-field (envelope-root env) "result")))
    (when (cbor-map-p rc) (entity-of-cbor rc))))

(defun response-status (env) (or (entity-uint (envelope-root env) "status") 0))

(defun require-ok (env step)
  (let ((status (response-status env)))
    (unless (= status 200)
      (let* ((r (response-result env))
             (code (and r (entity-text r "code")))
             (msg (and r (entity-text r "message"))))
        (error "~a failed: ~a ~a ~a" step status code (or msg "")))))
  env)

;; ── authenticated EXECUTE (§5.8 full authority chain in `included`) ──────────────

(defun client-execute (cc local uri operation params &optional resource)
  "Build, sign, and send an authenticated EXECUTE; await the correlated
EXECUTE_RESPONSE. The full authority chain travels in `included` (§5.8)."
  (let* ((cap (client-connection-capability cc))
         (exec (make-execute (next-request-id cc) uri operation params
                             :author (identity-hash local)
                             :capability (entity-hash cap)
                             :resource resource))
         (exec-sig (sign-entity local exec))
         (included (list (cons (entity-hash cap) cap)
                         (cons (entity-hash (client-connection-granter-peer cc))
                               (client-connection-granter-peer cc))
                         (cons (identity-hash local) (identity-peer-entity local))
                         (cons (entity-hash (client-connection-cap-signature cc))
                               (client-connection-cap-signature cc))
                         (cons (entity-hash exec-sig) exec-sig))))
    (client-send cc (make-envelope exec included))))

(defun client-close (cc)
  (let ((io (client-connection-io cc)))
    (close-io io)
    (ignore-errors (sb-bsd-sockets:socket-close (io-socket io)))))
