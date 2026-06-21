;;;; sign.lisp — Ed25519 / Ed448 sign/verify/derive via ironclad (pure Lisp).
;;;;
;;;; RFC 8032 deterministic EdDSA: a fixed seed + fixed message yields fixed
;;;; signature bytes. Ed25519 seeds are 32 bytes (64-byte sig); Ed448 seeds are
;;;; 57 bytes (114-byte sig). Both curves are reachable NATIVELY here (no FFI) —
;;;; ironclad implements both in pure Common Lisp (profile [codec]; A-CL-005).
;;;;
;;;; The exact ironclad 0.61 API spellings are confirmed against the in-container
;;;; build at S2 (see status/PHASE-S2.md). ironclad's eddsa private key is created
;;;; from the raw seed via MAKE-PRIVATE-KEY; the public key is derived from it.

(in-package #:entity-core)

(defun %curve-keyword (curve)
  (ecase curve (:ed25519 :ed25519) (:ed448 :ed448)))

(defun ed-sign (seed message &optional (curve :ed25519))
  "Sign raw MESSAGE octets with raw SEED octets under CURVE. Returns the signature
as an octet-vector (64 bytes Ed25519, 114 bytes Ed448)."
  (let* ((kw (%curve-keyword curve))
         (seed* (coerce seed 'octet-vector))
         (msg* (coerce message 'octet-vector))
         (priv (ironclad:make-private-key kw :x seed*)))
    (ironclad:sign-message priv msg*)))

(defun ed-verify (public-key message signature &optional (curve :ed25519))
  "Verify SIGNATURE over MESSAGE octets against raw PUBLIC-KEY octets under CURVE."
  (let* ((kw (%curve-keyword curve))
         (pub (ironclad:make-public-key kw :y (coerce public-key 'octet-vector))))
    (ironclad:verify-signature pub (coerce message 'octet-vector)
                               (coerce signature 'octet-vector))))

(defun ed-public-key (seed &optional (curve :ed25519))
  "Derive the raw public key octets from a raw SEED under CURVE.
ironclad's MAKE-PRIVATE-KEY computes the EdDSA public key Y from the seed X;
DESTRUCTURE-PRIVATE-KEY returns a plist (:x <seed> :y <pubkey>)."
  (let* ((kw (%curve-keyword curve))
         (priv (ironclad:make-private-key kw :x (coerce seed 'octet-vector)))
         (plist (ironclad:destructure-private-key priv)))
    (coerce (getf plist :y) 'octet-vector)))
