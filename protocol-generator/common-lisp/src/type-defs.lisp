;;;; type-defs.lisp — Core type floor (V7 §9.5), render-from-model.
;;;;
;;;; The 53 core type *models* live in +core-type-models+ (type-defs-data.lisp, an
;;;; in-code override table generated from the cross-impl Go-rendered type shapes).
;;;; Here we render each to a materialized `system/type' entity and publish it at
;;;; /{peer}/system/type/{name}.
;;;;
;;;; Render-from-model, not ingest-bytes: each entity's content_hash is computed by
;;;; our own S2 codec over the model, then diffed against the canonical
;;;; type-registry vectors (test/type-registry.lisp). A core peer publishes exactly
;;;; these 53 (§9.5) — matched-if-present for anything outside the floor.

(in-package #:entity-core/peer)

;; (type-name . rendered system/type entity) for all 53 core types.
(defun core-type-entities ()
  (mapcar (lambda (pair)
            (cons (car pair) (make-entity "system/type" (cdr pair))))
          +core-type-models+))

;; Publish every core type at its tree path under the local peer's namespace:
;; /{peer}/system/type/{name}. The bytes are also content-addressed in the store.
(defun publish-core-types (store local-peer)
  (dolist (pair (core-type-entities))
    (store-bind store
                (concatenate 'string "/" local-peer "/system/type/" (car pair))
                (cdr pair))))
