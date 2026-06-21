;;;; peer-store.lisp — Storage (foundation, §1.7): the two layers
;;;;
;;;;   Content Store: hash → entity   (immutable, content-addressed, dedup)
;;;;   Entity Tree:   path → hash     (mutable location index)
;;;;
;;;; In-memory minimal impl. Paths are the canonical absolute form "/{peer_id}/rest"
;;;; (§1.4); the peer canonicalizes before calling in. Path keys are strings; hash
;;;; keys are the 33-byte content_hash rendered as a hex string (so an octet-vector
;;;; works as an EQUAL hash-table key).
;;;;
;;;; EMIT PATHWAY (§6.10 / v7.74 §6.13(c)) — the Core Extensibility Boundary:
;;;; tree/content writes produce events; the bus delivers them to registered
;;;; consumers. The hook is LIVE even with ZERO consumers (events are produced and
;;;; discarded) so a future extension can register a consumer WITHOUT the peer being
;;;; rebuilt — the §6.13(c) MUST. A core-only peer registers zero consumers, but the
;;;; seam is exercised on every bind (the v7.74 "reachable with no consumers"
;;;; requirement). event_type derives from the null-new-hash rule.

(in-package #:entity-core/peer)

(defstruct (store (:constructor %make-store))
  ;; :synchronized — per-request dispatch runs on its own thread (§6.11), so
  ;; concurrent gethash / (setf gethash) on a plain table races its internal
  ;; rehash and corrupts it, surfacing as 500s under sustained load
  ;; (keystone §7b t2_1). SBCL synchronized tables serialize each op; the
  ;; critical section is one table access, so head-of-line (t1_3) holds.
  (content (make-hash-table :test 'equal :synchronized t) :read-only t)   ; hash-hex → entity
  (tree    (make-hash-table :test 'equal :synchronized t) :read-only t)   ; path → hash-hex
  (content-consumers nil)                                  ; list of (event-plist -> *)
  (tree-consumers nil))

(defun make-store () (%make-store))

;; ── emit consumer registration (§6.10 consumer-registration primitive) ───────
;; Reachable any time, including post-bootstrap. Delivery is sync-inline (§9.4).

(defun register-content-consumer (store fn)
  (push fn (store-content-consumers store)))

(defun register-tree-consumer (store fn)
  (push fn (store-tree-consumers store)))

(defun %derive-event-type (previous new)
  (cond ((null previous) "created")
        ((null new) "deleted")
        (t "modified")))

;; ── content store ─────────────────────────────────────────────────────────────
;; §6.10 Store step: a content-store event fires only when the entity is new to the
;; store (a re-put of an existing hash fires nothing).

(defun store-put-entity (store e)
  (let ((k (hex (entity-hash e))))
    (unless (gethash k (store-content store))
      (setf (gethash k (store-content store)) e)
      ;; emit: live even with zero consumers (§6.13(c)).
      (dolist (fn (store-content-consumers store))
        (funcall fn (list :hash (entity-hash e) :entity e))))))

(defun store-get-by-hash (store h)
  (gethash (hex h) (store-content store)))

;; ── entity tree (location index) ──────────────────────────────────────────────
;; §6.10 Bind step: a tree-change event fires when the binding at the path changes.

(defun store-bind (store path e)
  (store-put-entity store e)
  (let* ((prev (gethash path (store-tree store)))
         (new (hex (entity-hash e)))
         (changed (not (and prev (string= prev new)))))
    (setf (gethash path (store-tree store)) new)
    (when changed
      (dolist (fn (store-tree-consumers store))
        (funcall fn (list :event-type (%derive-event-type prev new)
                          :path path :new-hash new :previous-hash prev))))))

(defun store-unbind (store path)
  (let ((prev (gethash path (store-tree store))))
    (remhash path (store-tree store))
    (when prev
      (dolist (fn (store-tree-consumers store))
        (funcall fn (list :event-type "deleted" :path path
                          :new-hash nil :previous-hash prev))))))

(defun store-hash-at (store path)
  "The hex content_hash bound at PATH, or NIL."
  (gethash path (store-tree store)))

(defun store-get-at (store path)
  (let ((h (store-hash-at store path)))
    (when h (gethash h (store-content store)))))

;; One-level listing under PREFIX (a path ending in "/"). Returns a list of
;; (segment hash-hex-or-nil has-children-p) per system/tree/listing-entry (§3.9).
(defun store-listing (store prefix)
  (let* ((prefix (if (and (plusp (length prefix))
                          (char= (char prefix (1- (length prefix))) #\/))
                     prefix (concatenate 'string prefix "/")))
         (plen (length prefix))
         (acc (make-hash-table :test 'equal)))   ; seg → (cons hash-or-nil deeper-p)
    (maphash
     (lambda (path hash)
       (when (and (> (length path) plen)
                  (string= prefix (subseq path 0 plen)))
         (let* ((rest (subseq path plen))
                (slash (position #\/ rest)))
           (if slash
               (let ((seg (subseq rest 0 slash)))
                 (let ((cell (gethash seg acc)))
                   (if cell (setf (cdr cell) t)
                       (setf (gethash seg acc) (cons nil t)))))
               (let ((cell (gethash rest acc)))
                 (if cell (setf (car cell) hash)
                     (setf (gethash rest acc) (cons hash nil))))))))
     (store-tree store))
    (let ((entries '()))
      (maphash (lambda (seg cell) (push (list seg (car cell) (cdr cell)) entries)) acc)
      (sort entries #'string< :key #'first))))
