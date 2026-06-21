;;;; peer-identity.lisp — Identity (L1): a peer's keypair + derived entities
;;;; (§1.5, §3.5, §7.3). The peer identity is an Ed25519 seed; everything derives:
;;;;
;;;;   public_key    = Ed25519 pub of seed                         (32 bytes)
;;;;   peer_id       = §1.5 canonical-form (identity-multihash; A-CL-002)
;;;;   peer entity   = system/peer {public_key, key_type}          (§3.5; v7.65 —
;;;;                   NO peer_id in the hashable basis)
;;;;   identity_hash = content_hash(peer entity)
;;;;
;;;; Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so
;;;; a signature is bound to the hash format.

(in-package #:entity-core/peer)

;; The struct is named KEYPAIR (the symbol CL:IDENTITY is locked — it is the
;; standard cl:identity function), but its accessors keep the IDENTITY- conc-name
;; (the public surface) via :conc-name. CONSTRUCTOR/predicate are likewise named.
(defstruct (keypair (:conc-name identity-)
                    (:constructor %make-identity)
                    (:predicate identity-p))
  (seed         (make-octet-vector 0) :type octet-vector :read-only t)
  (public-key   (make-octet-vector 0) :type octet-vector :read-only t)
  (peer-id      "" :type string :read-only t)
  (peer-entity  nil :read-only t)                 ; a system/peer entity
  (hash         (make-octet-vector 0) :type octet-vector :read-only t))

(defun peer-entity-of-pubkey (public-key)
  "Build the system/peer entity for a raw PUBLIC-KEY (v7.65: no peer_id field)."
  (make-entity "system/peer"
               (map-of "public_key" (make-bytes public-key)
                       "key_type" "ed25519")))

;; Ed25519 canonical peer_id is the §1.5 identity-multihash form (A-CL-002): the
;; §7.4 NORMATIVE pseudocode (SHA256(pubkey)) is STALE and fails handshake — we
;; follow §1.5. peer-id-from-public-key (S2 codec) already encodes that contract.
(defun peer-id-of-pubkey (public-key)
  (peer-id-from-public-key public-key :ed25519))

(defun make-identity (seed)
  "Construct an identity from a 32-byte Ed25519 SEED octet-vector."
  (let* ((seed* (coerce seed 'octet-vector))
         (public-key (ed-public-key seed* :ed25519))
         (peer-entity (peer-entity-of-pubkey public-key)))
    (%make-identity :seed seed*
                    :public-key public-key
                    :peer-id (peer-id-of-pubkey public-key)
                    :peer-entity peer-entity
                    :hash (entity-hash peer-entity))))

(defun identity-of-seed (seed)
  "Alias for make-identity from a raw seed."
  (make-identity seed))

(defun sign-entity (identity target)
  "Sign TARGET entity's content_hash; produce the system/signature entity (§3.5):
target = signed entity hash, signer = our identity hash."
  (let ((sig-bytes (ed-sign (identity-seed identity) (entity-hash target) :ed25519)))
    (make-entity "system/signature"
                 (map-of "target" (make-bytes (entity-hash target))
                         "signer" (make-bytes (identity-hash identity))
                         "algorithm" "ed25519"
                         "signature" (make-bytes sig-bytes)))))

(defun verify-signature (signature signer-peer)
  "Verify a system/signature entity against the signer's system/peer entity.
Reads public_key from the peer entity; the §5.2 signer-hash check is the caller's
responsibility."
  (let ((target (entity-bytes signature "target"))
        (sig (entity-bytes signature "signature"))
        (pub (entity-bytes signer-peer "public_key")))
    (and target sig pub
         (ignore-errors (ed-verify pub target sig :ed25519)))))
