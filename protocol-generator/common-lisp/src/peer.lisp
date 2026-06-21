;;;; peer.lisp — Peer assembly: bootstrap, the four MUST system handlers (§6.2:
;;;; tree, handler, capability, connect), the §6.5 dispatch chain, §6.6 resolution,
;;;; §6.9 bootstrap, and per-connection state.
;;;;
;;;; THE DISTANT-IDIOM PROBE (profile [idiom].clos_dispatch): operation dispatch is
;;;; a CLOS GENERIC FUNCTION with MULTIPLE DISPATCH on (handler-class × operation).
;;;; A handler is a CLOS object (a subclass of `handler`); each operation is a
;;;; method on HANDLE-OP specialized by the handler's class AND an EQL specializer
;;;; on the operation keyword. The §6.6 backward tree-walk resolves the request URI
;;;; to a bootstrapped handler INSTANCE, then HANDLE-OP dispatches — where every
;;;; single-dispatch peer (C#/TS/OCaml/Elixir) writes a `match op with` ladder, CL
;;;; expresses the same surface as the method table the metaobject system already
;;;; maintains. Unknown (handler, op) pairs fall through to the default method =
;;;; 501, the CLOS analogue of the `| other ->` arm.
;;;;
;;;; Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch chain order
;;;; (verify → resolve → check-permission → handler), and §4.4 initial-grant
;;;; delivery are derived directly from V7. Transport lives in [peer-transport];
;;;; this module is the pure protocol brain (one connection's state + a function
;;;; from inbound envelope to outbound response envelope).

(in-package #:entity-core/peer)

;; ── peer + per-connection state ────────────────────────────────────────────────

(defstruct (peer (:constructor %make-peer))
  (identity nil :read-only t)
  (store nil :read-only t)
  (local-peer "" :type string :read-only t)
  (open-grants nil :read-only t)        ; --debug-open-grants: mint a wide admin cap
  (conformance nil :read-only t)        ; --validate: §7a system/validate/* handlers
  (handlers (make-hash-table :test 'equal) :read-only t)) ; pattern → handler instance

;; Per-connection state (§4.2 connection state is per-connection).
(defstruct conn
  (established nil)
  (issued-nonce nil)        ; nonce we issued in our hello response (octet-vector)
  (hello-peer-id nil)       ; initiator's claimed peer_id from hello
  ;; §6.13(b) handler-facing outbound seam: send an EXECUTE envelope over this
  ;; connection and await its correlated EXECUTE_RESPONSE (§6.11 reentry). Set by
  ;; the transport; NIL when the request did not arrive over a reentrant connection.
  (outbound nil)
  (out-counter 0))

;; A handler outcome: status, result entity, included protocol entities (alist).
(defstruct (outcome (:constructor make-outcome (status result &optional included)))
  status result included)

(defun ok (result &optional included) (make-outcome 200 result included))
(defun err (status code &optional message) (make-outcome status (error-result code message)))

;; ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ────────────────────────────

(defun random-bytes (n) (ironclad:random-data n))

;; ── grant construction (§4.4 / §5.4) ───────────────────────────────────────────

(defun scope-cbor (incl &optional excl)
  (if excl
      (map-of "include" (mapcar #'identity incl) "exclude" (mapcar #'identity excl))
      (map-of "include" (mapcar #'identity incl))))

(defun grant (&key handlers resources operations peers)
  (let ((pairs (list (cons "handlers" (scope-cbor handlers))
                     (cons "resources" (scope-cbor resources))
                     (cons "operations" (scope-cbor operations)))))
    (when peers (setf pairs (append pairs (list (cons "peers" (scope-cbor peers))))))
    (make-cbor-map pairs)))

;; The §4.4 discovery floor: every authenticated identity gets at least this.
(defun discovery-floor ()
  (list (grant :handlers '("system/tree")
               :resources '("system/type/*" "system/handler/*")
               :operations '("get"))
        (grant :handlers '("system/capability") :resources '() :operations '("request"))))

;; Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants).
(defun open-grants-scope ()
  (list (grant :handlers '("*") :resources '("*" "/*/*")
               :operations '("*") :peers '("*"))))

;; Full owner authority over the local namespace /{peer_id}/* (§6.9a).
(defun owner-grants (peer)
  (list (grant :handlers '("*") :resources '("*") :operations '("*")
               :peers (list (peer-local-peer peer)))))

;; ── token mint (§4.4 / §6.9a) ──────────────────────────────────────────────────

(defun mint-token (peer grantee-hash grants &key parent)
  "Mint + sign a capability token granted by us to GRANTEE-HASH. Returns
(values token signature)."
  (let* ((id (peer-identity peer))
         (pairs (list (cons "granter" (make-bytes (identity-hash id)))
                      (cons "grantee" (make-bytes grantee-hash))
                      (cons "grants" grants)
                      (cons "created_at" (now-ms)))))
    (when parent (setf pairs (append pairs (list (cons "parent" (make-bytes parent))))))
    (let ((token (make-entity "system/capability/token" (make-cbor-map pairs))))
      (values token (sign-entity id token)))))

;; ── §6.9a seed policy (authenticate-time grant derivation) ──────────────────────

(defun seed-entry-grants (peer e)
  "Raw grants list from a seed-policy entry, handling both §6.9a.0 shapes: a cap
token (detached-signature — verify the sig at the §3.5 pointer) or a policy-entry."
  (let ((grants-of (lambda () (let ((g (entity-field e "grants"))) (if (listp g) g nil)))))
    (cond
      ((string= (entity-typ e) "system/capability/token")
       (let* ((sig-path (concatenate 'string "/" (peer-local-peer peer)
                                     "/system/signature/" (hex (entity-hash e))))
              (sgn (store-get-at (peer-store peer) sig-path)))
         (if (and sgn (verify-signature sgn (identity-peer-entity (peer-identity peer))))
             (funcall grants-of) nil)))
      ((string= (entity-typ e) "system/capability/policy-entry") (funcall grants-of))
      (t nil))))

(defun derive-seed-grants (peer remote-peer remote-peer-id)
  "§6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
then UNION the matched scope with the §4.4 discovery floor (v7.62 §8)."
  (let* ((store (peer-store peer))
         (base (concatenate 'string "/" (peer-local-peer peer) "/system/capability/policy/"))
         (entry (or (store-get-at store (concatenate 'string base (hex (entity-hash remote-peer))))
                    (store-get-at store (concatenate 'string base remote-peer-id))
                    (store-get-at store (concatenate 'string base "default"))))
         (floor (discovery-floor))
         (policy-grants (if entry (seed-entry-grants peer entry) nil)))
    (if (null policy-grants) floor (append floor policy-grants))))

;; ══════════════════════════════════════════════════════════════════════════════
;; CLOS handler hierarchy — the multiple-dispatch surface (the distant-idiom probe)
;; ══════════════════════════════════════════════════════════════════════════════

(defclass handler ()
  ((peer :initarg :peer :reader handler-peer))
  (:documentation "A core system handler. Subclasses implement HANDLE-OP methods."))

(defclass connect-handler (handler) ())
(defclass tree-handler (handler) ())
(defclass capability-handler (handler) ())
(defclass handlers-handler (handler) ())
(defclass type-handler (handler) ())
(defclass echo-handler (handler) ())                ; §7a conformance
(defclass dispatch-outbound-handler (handler) ())   ; §7a conformance

;; HANDLE-OP is the generic function. It dispatches on (handler-class × operation
;; × ...): the operation rides as an EQL-specialized keyword argument. CTX is a
;; plist carrying (:exec :conn :included :caller-cap) — the §6.6 HandlerContext.
(defgeneric handle-op (handler op ctx)
  (:documentation "Dispatch (handler, operation-keyword) → outcome. The CLOS
method table IS the operation router; unknown pairs fall to the default → 501."))

;; Default method = the `| other ->` arm: unsupported operation for this handler.
(defmethod handle-op ((h handler) op ctx)
  (declare (ignore ctx))
  (err 501 "unsupported_operation" (format nil "~a" op)))

;; ── ctx accessors ──────────────────────────────────────────────────────────────

(defun ctx-exec (ctx) (getf ctx :exec))
(defun ctx-conn (ctx) (getf ctx :conn))
(defun ctx-included (ctx) (getf ctx :included))
(defun ctx-caller-cap (ctx) (getf ctx :caller-cap))
(defun ctx-env (ctx) (getf ctx :env))

;; ── connect handler (§4.1, §4.6) ───────────────────────────────────────────────

(defun str-array (exec key)
  (let ((params (entity-entity exec "params")))
    (when params
      (let ((v (entity-field params key)))
        (when (listp v) (remove-if-not #'stringp v))))))

(defmethod handle-op ((h connect-handler) (op (eql :hello)) ctx)
  (let ((peer (handler-peer h)) (conn (ctx-conn ctx)) (exec (ctx-exec ctx)))
    (if (conn-established conn)
        (err 409 "connection_already_established")
        ;; §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        (let ((hash-ok (let ((f (str-array exec "hash_formats")))
                         (if f (member "ecfv1-sha256" f :test #'string=) t)))
              (key-ok (let ((k (str-array exec "key_types")))
                        (if k (member "ed25519" k :test #'string=) t))))
          (cond
            ((not hash-ok) (err 400 "incompatible_hash_format"))
            ((not key-ok) (err 400 "unsupported_key_type"))
            (t
             (let* ((params (entity-entity exec "params"))
                    (initiator-peer (and params (entity-text params "peer_id")))
                    (nonce (random-bytes 32)))
               (setf (conn-hello-peer-id conn) initiator-peer
                     (conn-issued-nonce conn) nonce)
               (ok (make-entity "system/protocol/connect/hello"
                                (map-of "peer_id" (peer-local-peer peer)
                                        "nonce" (make-bytes nonce)
                                        "protocols" (list "entity-core/1.0")
                                        "timestamp" (now-ms)
                                        "hash_formats" (list "ecfv1-sha256")
                                        "key_types" (list "ed25519")))))))))))

(defmethod handle-op ((h connect-handler) (op (eql :authenticate)) ctx)
  (let ((peer (handler-peer h)) (conn (ctx-conn ctx)) (exec (ctx-exec ctx)))
    (cond
      ((conn-established conn) (err 409 "connection_already_established"))
      ((null (conn-issued-nonce conn)) (err 401 "invalid_nonce")) ; authenticate before hello
      (t
       (let ((auth (entity-entity exec "params")))
         (if (null auth) (err 401 "authentication_failed")
             ;; §4.6 hardening: reject an unsupported key_type riding in the
             ;; key_type field, a non-32-byte public_key, or a non-0x01 peer_id.
             (let ((bad-kt
                     (or (and (entity-text auth "key_type")
                              (not (string= (entity-text auth "key_type") "ed25519")))
                         (let ((p (entity-bytes auth "public_key")))
                           (and p (/= (length p) 32)))
                         (let ((pid (entity-text auth "peer_id")))
                           (and pid (ignore-errors
                                     (multiple-value-bind (kt) (peer-id-parse pid)
                                       (/= kt 1))))))))
               (if bad-kt (err 400 "unsupported_key_type")
                   (let ((pub (entity-bytes auth "public_key"))
                         (echoed (entity-bytes auth "nonce"))
                         (claimed (entity-text auth "peer_id")))
                     (cond
                       ;; step 1: nonce-echo
                       ((not (and echoed (octets-equal echoed (conn-issued-nonce conn))))
                        (err 401 "invalid_nonce"))
                       ((null pub) (err 401 "authentication_failed"))
                       (t
                        ;; step 2: proof of possession
                        (let* ((sgn (find-signature (entity-hash auth) (ctx-included ctx)))
                               (sig-ok (and sgn
                                            (let ((sb (entity-bytes sgn "signature")))
                                              (and sb (ignore-errors
                                                       (ed-verify pub (entity-hash auth) sb :ed25519)))))))
                          (cond
                            ((not sig-ok) (err 401 "authentication_failed"))
                            ;; step 3: identity binding
                            ((not (and claimed (string= claimed (peer-id-of-pubkey pub))))
                             (err 401 "identity_mismatch"))
                            ((and (conn-hello-peer-id conn)
                                  (not (equal (conn-hello-peer-id conn) claimed)))
                             (err 401 "identity_mismatch"))
                            (t
                             ;; success: mint the initial capability for the remote
                             ;; (§4.4 / §6.9a). Scope from the declared seed policy
                             ;; read from the tree, UNION'd with the §4.4 floor.
                             (let* ((remote-peer (peer-entity-of-pubkey pub))
                                    (grants (derive-seed-grants peer remote-peer (or claimed ""))))
                               (multiple-value-bind (token sgn2)
                                   (mint-token peer (entity-hash remote-peer) grants)
                                 (setf (conn-established conn) t)
                                 (ok (make-entity "system/capability/grant"
                                                  (map-of "token" (make-bytes (entity-hash token))))
                                     (list (cons (entity-hash token) token)
                                           (cons (identity-hash (peer-identity peer))
                                                 (identity-peer-entity (peer-identity peer)))
                                           (cons (entity-hash sgn2) sgn2)))))))))))))))))))

;; ── tree handler (§6.3) ─────────────────────────────────────────────────────────

(defun exec-resource-target (exec)
  (let ((r (entity-field exec "resource")))
    (when (cbor-map-p r)
      (let ((targets (map-field r "targets")))
        (when (and (listp targets) targets (stringp (first targets)))
          (first targets))))))

(defun path-flex-ok (target)
  "§1.4 / §5.4: validate a caller-supplied resource target. Reject null byte,
caller leading slash whose first seg is not a peer_id, ./ ../ interior empty."
  (cond
    ((find (code-char 0) target) nil)
    (t
     (let* ((segs0 (uiop:split-string target :separator "/")))
       (multiple-value-bind (abs-ok body)
           (if (starts-with "/" target)
               (if (and (>= (length segs0) 2) (string= (first segs0) ""))
                   (values (is-peer-id (second segs0)) (rest segs0))
                   (values nil segs0))
               (values t segs0))
         (if (not abs-ok) nil
             (let ((body (if (and body (string= (car (last body)) ""))
                             (butlast body) body)))
               (every (lambda (s) (and (not (string= s "")) (not (string= s "."))
                                       (not (string= s "..")))) body))))))))

(defun is-deletion-marker (peer h)
  (let ((e (store-get-by-hash (peer-store peer) h)))
    (and e (string= (entity-typ e) "system/deletion-marker"))))

(defun build-listing (peer path)
  (let* ((store (peer-store peer))
         (entries (remove-if (lambda (row)
                               (destructuring-bind (seg hash deeper) row
                                 (declare (ignore seg))
                                 (and hash (not deeper)
                                      (is-deletion-marker peer (unhex hash)))))
                             (store-listing store path)))
         (entry-map
           (mapcar (lambda (row)
                     (destructuring-bind (seg hash deeper) row
                       (cons seg
                             (entity-to-cbor
                              (make-entity "system/tree/listing-entry"
                                           (if hash
                                               (map-of "has_children" (if deeper :true :false)
                                                       "hash" (make-bytes (unhex hash)))
                                               (map-of "has_children" (if deeper :true :false))))))))
                   entries)))
    (ok (make-entity "system/tree/listing"
                     (map-of "path" path
                             "entries" (make-cbor-map entry-map)
                             "count" (length entries)
                             "offset" 0)))))

(defmethod handle-op ((h tree-handler) (op (eql :get)) ctx)
  (let* ((peer (handler-peer h)) (exec (ctx-exec ctx))
         (target (exec-resource-target exec)))
    (cond
      ((and target (not (path-flex-ok target))) (err 400 "invalid_path" target))
      ((null target) (build-listing peer (concatenate 'string "/" (peer-local-peer peer) "/")))
      ((or (string= target "") (char= (char target (1- (length target))) #\/))
       (build-listing peer (canonicalize (peer-local-peer peer) target)))
      (t
       (let* ((path (canonicalize (peer-local-peer peer) target))
              (e (store-get-at (peer-store peer) path)))
         (if e
             (let ((mode (let ((p (entity-entity exec "params"))) (and p (entity-text p "mode")))))
               (if (string= (or mode "") "hash")
                   (ok (make-entity "system/hash" (map-of "hash" (make-bytes (entity-hash e)))))
                   (ok e)))
             (err 404 "not_found" path)))))))

(defmethod handle-op ((h tree-handler) (op (eql :put)) ctx)
  (let* ((peer (handler-peer h)) (store (peer-store peer)) (exec (ctx-exec ctx))
         (target (exec-resource-target exec)))
    (cond
      ((null target) (err 400 "ambiguous_resource" "tree: missing resource target"))
      ((not (path-flex-ok target)) (err 400 "invalid_path" target))
      (t
       (let* ((path (canonicalize (peer-local-peer peer) target))
              (params (entity-entity exec "params"))
              (entity (and params (entity-entity params "entity")))
              (expected (and params (entity-bytes params "expected_hash")))
              (current (store-hash-at store path))
              (zero33 (make-octet-vector 33))
              (cas-ok (cond ((null expected) t)
                            ((octets-equal expected zero33) (null current))
                            (t (and current (string= current (hex expected)))))))
         (if (not cas-ok) (err 409 "hash_mismatch" path)
             (if entity
                 (progn (store-bind store path entity)
                        (ok (make-entity "system/hash" (map-of "hash" (make-bytes (entity-hash entity))))))
                 (err 400 "unexpected_params" "put: missing entity"))))))))

;; ── capability handler (§6.2) ─────────────────────────────────────────────────

(defun is-zero-hash (h) (every #'zerop h))

(defun req-grants-of (params)
  (let ((g (and params (entity-field params "grants")))) (if (listp g) g nil)))

(defun mint-bounded (peer caller-cap req-grants grantee-hash &key parent)
  "Mint a token bounded as a subset of CALLER-CAP (§6.2 subset-validation)."
  (let* ((local (peer-local-peer peer))
         (bounded
          (and caller-cap
               (let ((parent-grants (grants-of-token caller-cap)))
                 (every (lambda (cg)
                          (let ((c (parse-grant cg)))
                            ;; self-issued mint: granter = local peer → both frames local.
                            (some (lambda (pg) (grant-subset local local local c pg)) parent-grants)))
                        req-grants)))))
    (if (not bounded) (err 403 "scope_exceeds_authority")
        (multiple-value-bind (token sgn) (mint-token peer grantee-hash req-grants :parent parent)
          (ok (make-entity "system/capability/grant"
                           (map-of "token" (make-bytes (entity-hash token))))
              (list (cons (entity-hash token) token)
                    (cons (identity-hash (peer-identity peer))
                          (identity-peer-entity (peer-identity peer)))
                    (cons (entity-hash sgn) sgn)))))))

(defmethod handle-op ((h capability-handler) (op (eql :request)) ctx)
  (let* ((peer (handler-peer h)) (exec (ctx-exec ctx))
         (params (entity-entity exec "params"))
         (author (entity-bytes exec "author")))
    (if (null author) (err 403 "capability_denied")
        (mint-bounded peer (ctx-caller-cap ctx) (req-grants-of params) author))))

(defmethod handle-op ((h capability-handler) (op (eql :delegate)) ctx)
  (let* ((peer (handler-peer h)) (exec (ctx-exec ctx))
         (params (entity-entity exec "params"))
         (author (entity-bytes exec "author"))
         (ph (and params (entity-bytes params "parent"))))
    (cond
      ((null ph) (err 400 "unexpected_params" "delegate: parent required"))
      ((is-zero-hash ph) (err 400 "unexpected_params" "delegate: zero parent"))
      ((not (and author (octets-equal author (identity-hash (peer-identity peer)))))
       (err 501 "unsupported_operation" "delegate: same-peer-only in v1"))
      (t (mint-bounded peer (ctx-caller-cap ctx) (req-grants-of params) author :parent ph)))))

(defmethod handle-op ((h capability-handler) (op (eql :revoke)) ctx)
  (let* ((peer (handler-peer h)) (exec (ctx-exec ctx))
         (params (entity-entity exec "params"))
         (token-h (and params (entity-bytes params "token"))))
    (cond
      ((null token-h) (err 400 "unexpected_params" "revoke: missing token"))
      ((is-zero-hash token-h) (err 400 "unexpected_params" "revoke: zero token"))
      (t (let ((marker (make-entity "system/capability/revocation"
                                    (map-of "token" (make-bytes token-h)
                                            "revoked_at" (now-ms)))))
           (store-bind (peer-store peer)
                       (concatenate 'string "/" (peer-local-peer peer)
                                    "/system/capability/revocations/" (hex token-h))
                       marker)
           (ok (empty-params)))))))

(defmethod handle-op ((h capability-handler) (op (eql :configure)) ctx)
  (let* ((peer (handler-peer h)) (exec (ctx-exec ctx))
         (params (entity-entity exec "params"))
         (pp (and params (entity-text params "peer_pattern"))))
    (if (null pp) (err 400 "unexpected_params" "configure: missing peer_pattern")
        (let ((is-hex (and (= (length pp) 66)
                           (every (lambda (c) (or (char<= #\0 c #\9) (char<= #\a c #\f))) pp))))
          (if (not (or (string= pp "default") is-hex (is-peer-id pp)))
              (err 400 "invalid_peer_pattern" pp)
              (progn
                (store-bind (peer-store peer)
                            (concatenate 'string "/" (peer-local-peer peer)
                                         "/system/capability/policy/" pp)
                            params)
                (ok (empty-params))))))))

;; ── handlers handler (§6.2 / §6.13(a)) — register/unregister ───────────────────

(defun register-pattern (exec)
  "Derive the install pattern from EXECUTE.resource.targets[0]
(system/handler/{pattern}). Returns (values pattern outcome-or-nil)."
  (let ((target (exec-resource-target exec)))
    (if (null target)
        (values nil (err 400 "ambiguous_resource"
                         "register/unregister require exactly one resource target"))
        (let ((prefix "system/handler/"))
          (if (or (not (starts-with prefix target)) (= (length target) (length prefix)))
              (values nil (err 400 "invalid_resource"
                               "resource target MUST be system/handler/{pattern}"))
              (values (subseq target (length prefix)) nil))))))

(defmethod handle-op ((h handlers-handler) (op (eql :register)) ctx)
  (let ((peer (handler-peer h)) (exec (ctx-exec ctx)))
    (multiple-value-bind (pattern bad) (register-pattern exec)
      (if bad bad
          (let ((req (entity-entity exec "params")))
            (cond
              ((null req) (err 400 "unexpected_params" "register: missing params"))
              ((not (string= (entity-typ req) "system/handler/register-request"))
               (err 400 "unexpected_params"
                    (concatenate 'string "register expects register-request, got " (entity-typ req))))
              (t
               (let* ((store (peer-store peer))
                      (manifest (or (entity-field req "manifest") (make-cbor-map nil)))
                      (name (let ((n (map-field manifest "name"))) (if (stringp n) n pattern)))
                      (operations (or (map-field manifest "operations") (make-cbor-map nil)))
                      (expr-path (let ((p (map-field manifest "expression_path"))) (when (stringp p) p)))
                      (internal-scope (map-field manifest "internal_scope"))
                      (grant-scope
                        (let ((rs (entity-field req "requested_scope")))
                          (cond ((listp rs) rs)
                                ((listp internal-scope) internal-scope)
                                (t nil))))
                      (abs (lambda (rel) (concatenate 'string "/" (peer-local-peer peer) "/" rel)))
                      (interface-rel (concatenate 'string "system/handler/" pattern)))
                 ;; (1) handler manifest at the pattern path.
                 (let ((handler-pairs (list (cons "interface" interface-rel))))
                   (when expr-path (setf handler-pairs (append handler-pairs (list (cons "expression_path" expr-path)))))
                   (when internal-scope (setf handler-pairs (append handler-pairs (list (cons "internal_scope" internal-scope)))))
                   (store-bind store (funcall abs pattern)
                               (make-entity "system/handler" (make-cbor-map handler-pairs))))
                 ;; (2) associated types at system/type/{type_name}.
                 (let ((types (entity-field req "types")))
                   (when (cbor-map-p types)
                     (dolist (kv (cbor-map-pairs types))
                       (when (stringp (car kv))
                         (store-bind store (funcall abs (concatenate 'string "system/type/" (car kv)))
                                     (make-entity "system/type" (if (cbor-map-p (cdr kv)) (cdr kv) (map-of "def" (cdr kv)))))))))
                 ;; (3) self-issued signed handler grant + (4) grant-signature at §3.5.
                 (multiple-value-bind (token sgn) (mint-token peer (identity-hash (peer-identity peer)) grant-scope)
                   (store-bind store (funcall abs (concatenate 'string "system/capability/grants/" pattern)) token)
                   (store-bind store (funcall abs (concatenate 'string "system/signature/" (hex (entity-hash token)))) sgn)
                   ;; (5) handler interface entity (discovery index).
                   (store-bind store (funcall abs interface-rel)
                               (make-entity "system/handler/interface"
                                            (map-of "pattern" pattern "name" name "operations" operations)))
                   (ok (make-entity "system/handler/register-result"
                                    (map-of "pattern" pattern "grant" (entity-data token)))))))))))))

(defmethod handle-op ((h handlers-handler) (op (eql :unregister)) ctx)
  (let ((peer (handler-peer h)) (exec (ctx-exec ctx)))
    (multiple-value-bind (pattern bad) (register-pattern exec)
      (if bad bad
          (let* ((store (peer-store peer))
                 (abs (lambda (rel) (concatenate 'string "/" (peer-local-peer peer) "/" rel)))
                 (g (store-get-at store (funcall abs (concatenate 'string "system/capability/grants/" pattern)))))
            (when g
              (store-unbind store (funcall abs (concatenate 'string "system/signature/" (hex (entity-hash g)))))
              (store-unbind store (funcall abs (concatenate 'string "system/capability/grants/" pattern))))
            (store-unbind store (funcall abs pattern))
            (store-unbind store (funcall abs (concatenate 'string "system/handler/" pattern)))
            (ok (empty-params)))))))

;; ── §7a conformance handlers (the system/validate namespace) ────────────────────
;; NOT core protocol — conformance scaffolding (GUIDE-CONFORMANCE §7a), present only
;; under --validate (off by default). echo: the §6.13(a) resolve→dispatch half
;; (closes A-011). dispatch-outbound: the §6.13(b)/§6.11 outbound seam via reentry
;; (closes A-013) — a standing originator that must never ship live in production.

(defmethod handle-op ((h echo-handler) (op (eql :echo)) ctx)
  (let ((p (entity-entity (ctx-exec ctx) "params")))
    (if p (ok p) (err 400 "invalid_params" "echo requires a params entity"))))

(defmethod handle-op ((h dispatch-outbound-handler) (op (eql :dispatch)) ctx)
  (let* ((peer (handler-peer h)) (conn (ctx-conn ctx))
         (p (entity-entity (ctx-exec ctx) "params")))
    (if (null p) (err 400 "invalid_params" "dispatch-outbound requires a params entity")
        (let ((target (or (entity-text p "target") ""))
              (operation (or (entity-text p "operation") ""))
              (value (entity-field p "value"))
              (capability (entity-entity p "reentry_capability"))
              (granter-peer (entity-entity p "reentry_granter"))
              (cap-sig (entity-entity p "reentry_cap_signature")))
          (if (and value capability granter-peer cap-sig)
              ;; §7a.1: the `value' field IS the outbound params entity data — pass it
              ;; through (the reference uses it directly). Re-wrapping as (value . value)
              ;; double-wraps, so the echo's result.value returns a map (keystone §7b t1_2).
              (let* ((inner (make-entity "primitive/any" value))
                     (resource (resource-target (concatenate 'string "system/handler/" target)))
                     (env (outbound-dispatch peer conn target operation inner
                                             capability granter-peer cap-sig :resource resource)))
                (if (null env) (err 503 "no_outbound_seam" "no live §6.11 reentry connection")
                    (let ((status (or (entity-uint (envelope-root env) "status") 0))
                          (result-cbor (or (entity-field (envelope-root env) "result") (make-cbor-map nil))))
                      (ok (make-entity "primitive/any"
                                       (map-of "status" status "result" result-cbor))))))
              (err 400 "invalid_params" "dispatch-outbound requires value + reentry authority"))))))

;; ── §6.13(b) handler-facing outbound dispatch ───────────────────────────────────

(defun outbound-dispatch (peer conn uri operation params capability granter-peer cap-sig &key resource)
  "Build, sign (as the local peer), and send an outbound EXECUTE through the §6.11
reentry seam on the serving connection (conn-outbound, set by the transport),
returning the correlated EXECUTE_RESPONSE envelope, or NIL if no reentrant
connection. Present on every peer even though no CORE handler originates."
  (let ((send (conn-outbound conn)))
    (if (null send) nil
        (let* ((id (peer-identity peer)))
          (incf (conn-out-counter conn))
          (let* ((request-id (format nil "out-~d" (conn-out-counter conn)))
                 (exec (make-execute request-id uri operation params
                                     :author (identity-hash id)
                                     :capability (entity-hash capability)
                                     :resource resource))
                 (exec-sig (sign-entity id exec))
                 (included (list (cons (entity-hash capability) capability)
                                 (cons (entity-hash granter-peer) granter-peer)
                                 (cons (identity-hash id) (identity-peer-entity id))
                                 (cons (entity-hash cap-sig) cap-sig)
                                 (cons (entity-hash exec-sig) exec-sig))))
            (funcall send (make-envelope exec included)))))))

;; ── dispatcher-level signature ingestion (§6.5) ─────────────────────────────────

(defun ingest-signatures (peer env)
  (dolist (pair (envelope-included env))
    (let ((e (cdr pair)))
      (when (string= (entity-typ e) "system/signature")
        (store-put-entity (peer-store peer) e)
        (let ((signer-h (entity-bytes e "signer")))
          (when signer-h
            (let ((signer-peer (included-get env signer-h)))
              (when signer-peer
                (store-put-entity (peer-store peer) signer-peer)
                (let ((target (entity-bytes e "target"))
                      (pk (entity-bytes signer-peer "public_key")))
                  (when (and target pk)
                    (let ((pid (peer-id-of-pubkey pk)))
                      (store-bind (peer-store peer)
                                  (concatenate 'string "/" pid "/system/signature/" (hex target))
                                  e))))))))))))

;; ── handler resolution (§6.6) — backward tree-walk ──────────────────────────────

(defun resolve-handler (peer path)
  "Return (values handler-pattern suffix) for the longest prefix of PATH bound to a
system/handler entity, or NIL."
  (let* ((segs (uiop:split-string path :separator "/"))
         (n (length segs)))
    (loop for i from n downto 1 do
      (let ((prefix (format nil "~{~a~^/~}" (subseq segs 0 i))))
        (let ((e (store-get-at (peer-store peer) prefix)))
          (when (and e (string= (entity-typ e) "system/handler"))
            (return-from resolve-handler
              (values prefix (subseq path (length prefix))))))))
    nil))

(defun strip-local (peer pattern)
  (let ((prefix (concatenate 'string "/" (peer-local-peer peer) "/")))
    (if (starts-with prefix pattern) (subseq pattern (length prefix)) pattern)))

;; Map a stripped handler pattern to its CLOS handler instance (the §6.6 →
;; instance link). Dynamically-registered handlers (no in-process instance) fall
;; through to the entity-native dispatch path.
(defun handler-instance (peer stripped)
  (gethash stripped (peer-handlers peer)))

;; Map a wire operation string to its dispatch keyword (case-EXACT in → keyword).
(defun op-keyword (op)
  (intern (string-upcase op) :keyword))

;; ── entity-native dispatch (v7.74 §6.13(a)) ──────────────────────────────────────
;; A dynamically-registered handler has no in-process body; evaluate the body at its
;; expression_path. The body-binding seam (impl-private §9.4) evaluates the minimal
;; compute/literal shape (§10.1 register round-trip); richer bodies → 501.

(defun entity-native-dispatch (peer handler-path)
  (let ((he (store-get-at (peer-store peer) handler-path)))
    (if (null he) (err 404 "handler_not_found" handler-path)
        (let ((expr-path (entity-text he "expression_path")))
          (if (null expr-path) (err 501 "no_handler_body" handler-path)
              (let* ((abs (canonicalize (peer-local-peer peer) expr-path))
                     (expr (store-get-at (peer-store peer) abs)))
                (cond
                  ((null expr) (err 404 "expression_not_found" abs))
                  ((string= (entity-typ expr) "compute/literal")
                   (let ((value (entity-field expr "value")))
                     (if value
                         (ok (make-entity "compute/result"
                                          (map-of "value" value
                                                  "expression" (make-bytes (entity-hash expr)))))
                         (err 400 "unexpected_params" "compute/literal missing value"))))
                  (t (err 501 "unsupported_expression" (entity-typ expr))))))))))

;; ── dispatch chain (§6.5) ────────────────────────────────────────────────────────

(defun internal-error-response (env)
  (let ((request-id (or (entity-text (envelope-root env) "request_id") "")))
    (make-envelope (make-response request-id 500 (error-result "internal_error")))))

(defun dispatch (peer conn env)
  "The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or NIL for a
non-EXECUTE root (§3.3 server side ignores non-EXECUTE)."
  (let ((exec (envelope-root env)))
    (if (not (string= (entity-typ exec) "system/protocol/execute"))
        nil
        (let* ((request-id (or (entity-text exec "request_id") ""))
               (uri (or (entity-text exec "uri") ""))
               (outcome
                 (handler-case
                     (if (string= uri "system/protocol/connect")
                         (handle-op (handler-instance peer "system/protocol/connect")
                                    (op-keyword (or (entity-text exec "operation") ""))
                                    (list :exec exec :conn conn :included (envelope-included env) :env env))
                         (progn
                           (ingest-signatures peer env)
                           (ecase (verify-request (peer-local-peer peer) (peer-store peer) env)
                             (:authn-fail (err 401 "authentication_failed"))
                             (:authz-deny (err 403 "capability_denied"))
                             (:chain-too-deep (err 400 "chain_depth_exceeded"))
                             (:allow
                              (let ((path (canonicalize (peer-local-peer peer) (normalize-uri uri))))
                                ;; §1.4: inbound dispatch must target the local peer.
                                (if (not (string= (extract-peer (peer-local-peer peer) path) (peer-local-peer peer)))
                                    (err 404 "handler_not_found" "not local peer")
                                    (multiple-value-bind (pattern suffix) (resolve-handler peer path)
                                      (declare (ignore suffix))
                                      (if (null pattern) (err 404 "handler_not_found" path)
                                          (let ((caller-cap (let ((c (entity-bytes exec "capability")))
                                                              (and c (included-get env c)))))
                                            (if (null caller-cap) (err 403 "capability_denied")
                                                (ecase (let* ((resolve-fn (lambda (h) (cap-resolve (envelope-included env) (peer-store peer) h)))
                                                              (granter-peer (or (resolve-granter-peer-id resolve-fn caller-cap)
                                                                                (peer-local-peer peer))))
                                                         (check-permission (peer-local-peer peer) granter-peer exec caller-cap pattern))
                                                  (:deny (err 403 "capability_denied"))
                                                  (:allow
                                                   (let* ((stripped (strip-local peer pattern))
                                                          (inst (handler-instance peer stripped)))
                                                     (if inst
                                                         (handle-op inst (op-keyword (or (entity-text exec "operation") ""))
                                                                    (list :exec exec :conn conn
                                                                          :included (envelope-included env)
                                                                          :caller-cap caller-cap :env env))
                                                         (entity-native-dispatch peer pattern)))))))))))))))
                   (unresolvable-grantee () (err 401 "unresolvable_grantee"))
                   (error () (err 500 "internal_error")))))
          (make-envelope (make-response request-id (outcome-status outcome) (outcome-result outcome))
                         (outcome-included outcome))))))

;; ── bootstrap (§6.9) ──────────────────────────────────────────────────────────

(defun op-spec (input output)
  (let ((pairs '()))
    (when input (push (cons "input_type" input) pairs))
    (when output (push (cons "output_type" output) pairs))
    (make-cbor-map (nreverse pairs))))

(defparameter +bootstrap-handlers+
  ;; (pattern class name ((op input output) ...))
  '(("system/tree" tree-handler "Tree"
     (("get" nil nil) ("put" nil nil)))
    ("system/handler" handlers-handler "Handlers"
     (("register" "system/handler/register-request" "system/handler/register-result")
      ("unregister" "system/handler/unregister-request" nil)))
    ("system/type" type-handler "Types"
     (("validate" "system/type/validate-request" "system/type/validate-result")))
    ("system/capability" capability-handler "Capability"
     (("request" "system/capability/request" "system/capability/grant")
      ("revoke" "system/capability/revoke-request" nil)
      ("configure" "system/capability/policy-entry" nil)
      ("delegate" "system/capability/delegate-request" "system/capability/grant")))
    ("system/protocol/connect" connect-handler "Connect"
     (("hello" nil nil) ("authenticate" nil nil)))))

(defparameter +conformance-handlers+
  '(("system/validate/echo" echo-handler "validate-echo" (("echo" nil nil)))
    ("system/validate/dispatch-outbound" dispatch-outbound-handler "validate-dispatch-outbound"
     (("dispatch" nil nil)))))

(defun %bootstrap-handler-entities (peer pattern name ops)
  "Write the §6.9 tree entities for a handler: handler entity at pattern, interface
at the discovery index, and a bootstrap grant."
  (let* ((store (peer-store peer))
         (local (peer-local-peer peer))
         (operations (make-cbor-map (mapcar (lambda (spec)
                                              (destructuring-bind (o i ou) spec
                                                (cons o (op-spec i ou))))
                                            ops))))
    (store-bind store (concatenate 'string "/" local "/" pattern)
                (make-entity "system/handler"
                             (map-of "interface" (concatenate 'string "system/handler/" pattern))))
    (store-bind store (concatenate 'string "/" local "/system/handler/" pattern)
                (make-entity "system/handler/interface"
                             (map-of "pattern" pattern "name" name "operations" operations)))
    (multiple-value-bind (token) (mint-token peer (identity-hash (peer-identity peer)) nil)
      (store-bind store (concatenate 'string "/" local "/system/capability/grants/" pattern) token))))

(defun make-peer (&key seed open-grants conformance)
  "Construct + bootstrap a peer from a 32-byte Ed25519 SEED."
  (let* ((identity (make-identity seed))
         (store (make-store))
         (local (identity-peer-id identity))
         (peer (%make-peer :identity identity :store store :local-peer local
                           :open-grants open-grants :conformance conformance)))
    ;; local identity entity is in the store (root-granter resolution)
    (store-put-entity store (identity-peer-entity identity))
    ;; publish the 53 core types (§9.5 type-registry floor, render-from-model)
    (publish-core-types store local)
    ;; instantiate + register the CLOS handler instances (the §6.6 → instance map)
    (dolist (spec +bootstrap-handlers+)
      (destructuring-bind (pattern class name ops) spec
        (setf (gethash pattern (peer-handlers peer))
              (make-instance class :peer peer))
        (%bootstrap-handler-entities peer pattern name ops)))
    ;; §6.9a Peer Authority Bootstrap (L0 write-set): the self-owner capability (a
    ;; root cap, full scope over /{peer_id}/*, grantee = own identity; §6.9a.0
    ;; detached-sig shape: cap token at the hex policy path + its self-signature at
    ;; the §3.5 pointer) and the default scope-template entry. Read back by
    ;; authenticate (dual-form lookup). open-grants selects the degenerate
    ;; [default → *] (= --debug-open-grants).
    (let ((policy-base (concatenate 'string "/" local "/system/capability/policy/")))
      (multiple-value-bind (owner-token owner-sig)
          (mint-token peer (identity-hash identity) (owner-grants peer))
        (store-bind store (concatenate 'string policy-base (hex (identity-hash identity))) owner-token)
        (store-bind store (concatenate 'string "/" local "/system/signature/" (hex (entity-hash owner-token))) owner-sig))
      (let* ((default-grants (if open-grants (open-grants-scope) (discovery-floor)))
             (default-entry (make-entity "system/capability/policy-entry"
                                         (map-of "peer_pattern" "default"
                                                 "grants" default-grants))))
        (store-bind store (concatenate 'string policy-base "default") default-entry)))
    ;; §7a conformance handlers — only bootstrapped under --validate.
    (when conformance
      (dolist (spec +conformance-handlers+)
        (destructuring-bind (pattern class name ops) spec
          (setf (gethash pattern (peer-handlers peer))
                (make-instance class :peer peer))
          (%bootstrap-handler-entities peer pattern name ops))))
    peer))

(defun bootstrap (&rest args) (apply #'make-peer args))
