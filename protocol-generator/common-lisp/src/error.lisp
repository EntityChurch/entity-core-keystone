;;;; error.lisp — the condition hierarchy (profile [error_model] = conditions).
;;;;
;;;; The most expressive error model of the five peers: the Common Lisp CONDITION
;;;; SYSTEM (a strict superset of exceptions). Public codec entry points SIGNAL
;;;; these conditions; a *-safe convenience surface (ignore-errors-wrapped) is
;;;; provided for value-return callers. Decode-path violations signal with NO
;;;; restart (hard reject per N2/N3).

(in-package #:entity-core)

(define-condition entity-core-error (error)
  ((detail :initarg :detail :initform nil :reader entity-core-error-detail))
  (:documentation "Root of the entity-core codec condition hierarchy.")
  (:report (lambda (c stream)
             (format stream "entity-core error: ~a"
                     (entity-core-error-detail c)))))

(define-condition non-canonical-ecf (entity-core-error) ()
  (:documentation "The wire bytes are not in Entity Canonical Form (ECF §9.1).")
  (:report (lambda (c stream)
             (format stream "non-canonical ECF: ~a"
                     (entity-core-error-detail c)))))

(define-condition truncated-input (entity-core-error) ()
  (:documentation "Input ended before a complete CBOR item was decoded.")
  (:report (lambda (c stream)
             (format stream "truncated input: ~a"
                     (entity-core-error-detail c)))))

(define-condition tag-rejected (non-canonical-ecf) ()
  (:documentation "A CBOR major-type-6 tag was encountered (invariant N2; ECF §6.3 \
MUST reject with 400 non_canonical_ecf).")
  (:report (lambda (c stream)
             (format stream "CBOR tag rejected (N2): ~a"
                     (entity-core-error-detail c)))))

(define-condition duplicate-map-key (non-canonical-ecf) ()
  (:documentation "A map contained a duplicate key on decode.")
  (:report (lambda (c stream)
             (format stream "duplicate map key: ~a"
                     (entity-core-error-detail c)))))

(define-condition bad-seed (entity-core-error) ()
  (:documentation "A signing seed was the wrong length for the key type.")
  (:report (lambda (c stream)
             (format stream "bad seed: ~a"
                     (entity-core-error-detail c)))))

(define-condition unsupported-content-hash-format (entity-core-error) ()
  (:documentation "A content-hash format code is not in the allocated registry \
(receive/verify side rejects; V7 §4.3/§4.7).")
  (:report (lambda (c stream)
             (format stream "unsupported content-hash format: ~a"
                     (entity-core-error-detail c)))))

(define-condition unsupported-key-type (entity-core-error) ()
  (:documentation "A key_type code is not in the allocated registry.")
  (:report (lambda (c stream)
             (format stream "unsupported key type: ~a"
                     (entity-core-error-detail c)))))
