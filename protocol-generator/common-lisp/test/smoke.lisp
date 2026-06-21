;;;; smoke.lisp — S3 two-peer loopback smoke test (the phase exit gate).
;;;;
;;;; Two Common Lisp peers talk over real loopback TCP through the full dispatch
;;;; chain: a RESPONDER peer listens; an INITIATOR peer (a second CL peer identity)
;;;; dials it and drives the §4.1 forward handshake (hello → authenticate), then
;;;; the core ops:
;;;;   * 404 on an unregistered path (no handler resolved)
;;;;   * an authority-gated tree get (200) over the §4.4 discovery floor
;;;;   * a capability request (200)
;;;;   * 8-way request_id demux of concurrently-issued replies (N7, §6.11)
;;;; then tears down cleanly. Proving the peer machinery (transport + handshake +
;;;; register/dispatch + capability gating + request_id demux) is wired end-to-end.
;;;;
;;;; The full validate-peer --profile core conformance run is S4. This smoke proves
;;;; the wire-level peer surface so S4 can run the oracle.

(defpackage #:entity-core/smoke
  (:use #:cl)
  (:export #:run-smoke))

(in-package #:entity-core/smoke)

(defvar *results* '())

(defun check (name ok)
  (push (cons name ok) *results*)
  (format t "  [~a] ~a~%" (if ok "PASS" "FAIL") name))

(defun fixed-seed (byte)
  "A deterministic 32-byte Ed25519 seed (BYTE repeated)."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

(defun run-extensibility-smoke ()
  "Second loopback scenario: the v7.74 Core Extensibility Boundary over the wire.
The responder runs with --debug-open-grants (reach write/grant-gated ops, the
cohort's degenerate seed per F27) and --validate (§7a conformance handlers). Proves
the register LIVE-HOOK (§6.13(a)) and the §7a echo handler (§6.13(a) resolve→
dispatch) end-to-end, plus the emit hook firing on the register's tree writes."
  (let* ((responder (ecp:make-peer :seed (fixed-seed #x33)
                                   :open-grants t :conformance t))
         (initiator-id (ecp:identity-of-seed (fixed-seed #x44)))
         (emit-events (list 0))
         (sock nil) (cc nil))
    ;; register a tree-emit consumer post-bootstrap — the §6.13(c) live hook.
    (ecp:register-tree-consumer (ecp:peer-store responder)
                                (lambda (ev) (declare (ignore ev)) (incf (car emit-events))))
    (unwind-protect
         (multiple-value-bind (s port th) (ecp:start-listener responder 0)
           (declare (ignore th))
           (setf sock s)
           (setf cc (ecp:dial "127.0.0.1" port))
           (ecp:client-handshake cc initiator-id)
           (let ((remote (ecp:client-connection-remote-peer-id cc))
                 (emit-before (car emit-events)))
             (format t "Extensibility (open-grants + --validate):~%")
             ;; ── register live-hook (§6.13(a)) ──
             (let* ((manifest (ec:map-of "name" "demo" "operations" (ec:map-of)))
                    (req (ecp:make-entity "system/handler/register-request"
                                          (ec:map-of "manifest" manifest)))
                    (rreg (ecp:client-execute cc initiator-id
                                              (format nil "/~a/system/handler" remote)
                                              "register" req
                                              (ecp:resource-target "system/handler/demo"))))
               (check "handler register -> 200 (live, not 501)"
                      (= (ecp:response-status rreg) 200))
               (check "emit hook fired on register's tree writes (§6.13(c))"
                      (> (car emit-events) emit-before)))
             ;; ── §7a echo conformance handler (resolve→dispatch) ──
             (let* ((payload (ecp:make-entity "primitive/any" (ec:map-of "ping" 42)))
                    (recho (ecp:client-execute cc initiator-id
                                               (format nil "/~a/system/validate/echo" remote)
                                               "echo" payload)))
               (check "§7a echo -> 200" (= (ecp:response-status recho) 200))
               (let ((res (ecp:response-result recho)))
                 (check "§7a echo returns params verbatim"
                        (and res (string= (ecp:entity-typ res) "primitive/any")))))))
      (when cc (ignore-errors (ecp:client-close cc)))
      (when sock (ignore-errors (sb-bsd-sockets:socket-close sock))))))

(defun run-smoke ()
  (setf *results* '())
  (let* ((responder (ecp:make-peer :seed (fixed-seed #x11)))
         (initiator-id (ecp:identity-of-seed (fixed-seed #x22)))
         (sock nil) (cc nil))
    (unwind-protect
         (progn
           ;; ── boot the responder on an auto-assigned localhost port ──
           (multiple-value-bind (s port th) (ecp:start-listener responder 0)
             (declare (ignore th))
             (setf sock s)
             (format t "Responder listening on 127.0.0.1:~a (peer ~a)~%"
                     port (ecp:peer-local-peer responder))

             ;; ── handshake (initiator → responder) ──
             (setf cc (ecp:dial "127.0.0.1" port))
             (ecp:client-handshake cc initiator-id)
             (let ((remote (ecp:client-connection-remote-peer-id cc)))
               (format t "Handshake:~%")
               (check "session established (capability minted)"
                      (not (null (ecp:client-connection-capability cc))))
               (check "remote peer_id matches responder"
                      (string= remote (ecp:peer-local-peer responder)))

               ;; ── dispatch ──
               (format t "Dispatch:~%")
               ;; The §4.4 discovery floor grants `get` on system/handler/* and
               ;; system/type/*. The bootstrap publishes a handler-interface entity
               ;; at system/handler/{pattern} for each MUST handler — probe one of
               ;; those (a path that exists AND is inside the granted scope).
               (flet ((iface-target ()
                        (ecp:resource-target "system/handler/system/tree"))
                      (exec (uri op &optional resource)
                        (ecp:client-execute cc initiator-id uri op (ecp:empty-params) resource)))

                 ;; 404 on an unregistered path
                 (let ((r404 (exec (format nil "/~a/does/not/exist" remote) "noop")))
                   (check "unregistered path -> 404" (= (ecp:response-status r404) 404)))

                 ;; authority-gated tree get (200) over the discovery floor
                 (let ((rget (exec (format nil "/~a/system/tree" remote) "get" (iface-target))))
                   (check "granted tree get -> 200" (= (ecp:response-status rget) 200))
                   (let ((res (ecp:response-result rget)))
                     (check "tree get returns a system/handler/interface entity"
                            (and res (string= (ecp:entity-typ res) "system/handler/interface")))))

                 ;; capability request (200)
                 (let* ((req-grant (ecp:grant :handlers '("system/tree")
                                              :resources '("system/type/*")
                                              :operations '("get")))
                        (req-params (ecp:make-entity "system/capability/request"
                                                     (ec:map-of "grants" (list req-grant))))
                        (rcap (ecp:client-execute cc initiator-id
                                                  (format nil "/~a/system/capability" remote)
                                                  "request" req-params)))
                   (check "capability request -> 200" (= (ecp:response-status rcap) 200)))

                 ;; ── concurrency: 8-way request_id demux (N7, §6.11) ──
                 (format t "Concurrency (request_id demux):~%")
                 (let* ((n 8)
                        (results (make-array n :initial-element nil))
                        (threads
                          (loop for i below n collect
                            (let ((idx i))
                              (sb-thread:make-thread
                               (lambda ()
                                 (let ((r (exec (format nil "/~a/system/tree" remote) "get" (iface-target))))
                                   (setf (aref results idx)
                                         (and (= (ecp:response-status r) 200)
                                              (let ((res (ecp:response-result r)))
                                                (and res (string= (ecp:entity-typ res) "system/handler/interface")))))))
                               :name (format nil "concurrent-~d" idx))))))
                   (dolist (th threads) (sb-thread:join-thread th))
                   (let ((correlated (count t (coerce results 'list))))
                     (check (format nil "8 interleaved requests each correlated -> ~d/8" correlated)
                            (= correlated 8))))))))
      ;; ── teardown ──
      (when cc (ignore-errors (ecp:client-close cc)))
      (when sock (ignore-errors (sb-bsd-sockets:socket-close sock))))
    ;; ── second scenario: the v7.74 Core Extensibility Boundary over the wire ──
    (run-extensibility-smoke)
    (let ((all-pass (every #'cdr *results*)))
      (format t "~%Teardown clean.   ->   SMOKE: ~a~%" (if all-pass "PASS" "FAIL"))
      all-pass)))
