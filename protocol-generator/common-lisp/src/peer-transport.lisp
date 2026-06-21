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
        (let ((payload (handler-case (read-frame (io-stream io))
                         ((or transport-closed end-of-file) () (return)))))
          (let ((env (ignore-errors (envelope-of-frame payload))))
            (when env
              (if (string= (entity-typ (envelope-root env)) "system/protocol/execute/response")
                  (route-response io env)
                  (sb-thread:make-thread (lambda () (funcall on-execute env))
                                         :name "exec-dispatch"))))))
    (error () nil)))

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
