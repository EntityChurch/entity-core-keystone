;;;; selftest.lisp — uncovered-range probes + the Ed448 RFC-8032 KAT gate.
;;;;
;;;; The codec-review heuristic: a green corpus run proves the math vs the corpus,
;;;; NOT the ranges the corpus doesn't cover. These probes exercise:
;;;;   * uint64 = 2^64-1 and 2^63 (above signed-i64 max — the native-bignum win:
;;;;     no width trap, unlike OCaml int63 / C# ulong / TS bigint)
;;;;   * nint min -2^64
;;;;   * peer-id format->parse round-trip (incl. multi-byte key_type)
;;;;   * base58 decode∘encode with leading-zero preservation
;;;;   * Ed25519 sign/verify + tamper-reject
;;;;   * bare-tag rejection
;;;;
;;;; AND the A-CL-005 acceptance gate: native pure-Lisp Ed448 is trusted ONLY after
;;;; RFC-8032 known-answer-test byte-equality against the locked agility pin (seed
;;;; 0x42×57, the §1.1 fixture message, the 114-byte signature + 57-byte pubkey +
;;;; Base58 peer_id). If this gate fails, Ed448 must NOT be trusted for the agility
;;;; corpus and the documented fallback is the hybrid-FFI route (OCaml A-OC-002).

(in-package #:entity-core/test)

(defvar *self-fail* 0)

(defun check (name ok &optional detail)
  (if ok
      (format t "  ok   ~a~%" name)
      (progn (incf *self-fail*)
             (format t "  FAIL ~a: ~a~%" name detail))))

(defun hex->octets (hex)
  (let* ((n (/ (length hex) 2))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (setf (aref out i)
            (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun rt (value)
  "Encode then decode VALUE; return the decoded round-trip."
  (cbor-decode (cbor-encode value)))

(defun run-selftest ()
  "Run uncovered-range + Ed448-KAT selftests. Returns the failure count."
  (let ((*self-fail* 0))
    (format t "~&== selftest (uncovered ranges + Ed448 KAT gate) ==~%")

    ;; ── native-bignum integer ranges (above signed-i64; no width trap) ──
    (check "uint 2^63" (= (rt (expt 2 63)) (expt 2 63)))
    (check "uint 2^64-1 encodes 1b ff*8"
           (octets= (cbor-encode (1- (expt 2 64)))
                    (hex->octets "1bffffffffffffffff")))
    (check "uint 2^64-1 round-trips" (= (rt (1- (expt 2 64))) (1- (expt 2 64))))
    (check "nint -2^64 encodes 3b ff*8"
           (octets= (cbor-encode (- (expt 2 64)))
                    (hex->octets "3bffffffffffffffff")))
    (check "nint -2^64 round-trips" (= (rt (- (expt 2 64))) (- (expt 2 64))))

    ;; ── float specials + ladder round-trips ──
    (check "nan sentinel rt"      (eq (rt +nan+) +nan+))
    (check "+inf sentinel rt"     (eq (rt +inf+) +inf+))
    (check "-inf sentinel rt"     (eq (rt +neg-inf+) +neg-inf+))
    (check "-0.0 sentinel rt"     (eq (rt +neg-zero+) +neg-zero+))
    (check "1.5 -> f16 3 bytes"   (= (length (cbor-encode 1.5d0)) 3))
    (check "1.1 -> f64 9 bytes"   (= (length (cbor-encode 1.1d0)) 9))
    (check "65503.0 -> f32"       (= (length (cbor-encode 65503.0d0)) 5))
    (check "f16 rt 65504"         (= (rt 65504.0d0) 65504.0d0))

    ;; ── peer-id format->parse round-trip (incl. multi-byte key_type) ──
    (let ((digest (hex->octets "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")))
      (multiple-value-bind (kt ht dg) (peer-id-parse (peer-id-format 1 0 digest))
        (check "peer-id rt (kt=1)" (and (= kt 1) (= ht 0) (octets= dg digest))))
      (multiple-value-bind (kt ht dg) (peer-id-parse (peer-id-format 128 1 digest))
        (check "peer-id rt multibyte kt=128"
               (and (= kt 128) (= ht 1) (octets= dg digest)))))

    ;; ── base58 leading-zero preservation ──
    (let ((b (hex->octets "0000deadbeef")))
      (check "base58 leading-zero rt" (octets= (base58-decode (base58-encode b)) b)))

    ;; ── Ed25519 sign/verify + tamper-reject (deterministic over a message) ──
    (let* ((seed (hex->octets "0000000000000000000000000000000000000000000000000000000000000000"))
           (msg  (entity-core::string-to-utf8 "selftest"))
           (sig  (ed-sign seed msg :ed25519))
           (pub  (ed-public-key seed :ed25519)))
      (check "ed25519 sig 64 B" (= (length sig) 64))
      (check "ed25519 verify"   (ed-verify pub msg sig :ed25519))
      (check "ed25519 tamper-reject"
             (not (ed-verify pub (entity-core::string-to-utf8 "selftesu") sig :ed25519))))

    ;; ── N2: bare-tag rejection (tag 55799 self-describe wrapper) ──
    (check "bare tag 55799 rejected"
           (handler-case (progn (cbor-decode (hex->octets "d9d9f7a0")) nil)
             (tag-rejected () t)))

    ;; ── A-CL-005 GATE: native Ed448 RFC-8032 byte-equality KAT ──
    (run-ed448-kat)

    ;; ── §3.6 M3 multi-signature K-of-N — ACCEPT path (oracle-omitted direction) ──
    (run-multisig-accept)

    *self-fail*))

(defun run-multisig-accept ()
  "§3.6 M3 multi-signature K-of-N ACCEPT-path coverage. The validate-peer `multisig`
category is 100% REJECTION tests (each builds a MALFORMED quorum and asserts 403),
which a fail-closed peer passes 10/10 WITHOUT genuine k-of-n. This exercises the
direction the oracle cannot: a real 2-of-3 root (one signer = the local peer) with a
threshold of valid signatures over the cap's content hash MUST be ALLOWed — and each
M3/M4/M6 invariant flip MUST deny. Single-sig stays a strict superset."
  (let* ((store (ecp:make-store))
         (id1 (ecp:make-identity (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))
         (id2 (ecp:make-identity (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
         (id3 (ecp:make-identity (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
         (local (ecp:identity-peer-id id1))
         (h1 (ecp:identity-hash id1)) (h2 (ecp:identity-hash id2)) (h3 (ecp:identity-hash id3)))
    (labels ((mk-cap (signers threshold &optional parent)
               ;; Build a multi-sig token: granter = {signers:[hash], threshold:uint}.
               (let* ((granter (make-cbor-map
                                (list (cons "signers" (mapcar #'make-bytes signers))
                                      (cons "threshold" threshold))))
                      (fields (append
                               (list (cons "granter" granter)
                                     (cons "grantee" (make-bytes h1))
                                     (cons "grants" '()))
                               (when parent (list (cons "parent" (make-bytes parent)))))))
                 (ecp:make-entity "system/capability/token" (make-cbor-map fields))))
             (peer-inc (id) (cons (ecp:identity-hash id) (ecp:identity-peer-entity id)))
             (sig-inc (s) (cons (ecp:entity-hash s) s))
             (allowed (cap inc)
               (eq (ecp::verify-capability-chain local store cap inc) :allow)))
      (let* ((signers (list h1 h2 h3))
             (cap (mk-cap signers 2))
             (s1 (ecp:sign-entity id1 cap))
             (s2 (ecp:sign-entity id2 cap))
             (s3 (ecp:sign-entity id3 cap))
             (inc3 (list (peer-inc id1) (peer-inc id2) (peer-inc id3))))
        ;; valid 2-of-3, local in quorum, 2 valid sigs → Allow
        (check "multisig 2-of-3 valid quorum -> Allow"
               (allowed cap (append inc3 (list (sig-inc s1) (sig-inc s2)))))
        ;; 3-of-3 worth of sigs but only threshold-2 needed → still Allow (≥ threshold)
        (check "multisig 2-of-3 with all 3 sigs -> Allow"
               (allowed cap (append inc3 (list (sig-inc s1) (sig-inc s2) (sig-inc s3)))))
        ;; only 1 valid sig (< threshold) → Deny (M4)
        (check "multisig 1-of-3 below threshold -> Deny"
               (not (allowed cap (append inc3 (list (sig-inc s1))))))
        ;; duplicate signature from one signer does NOT inflate the count (distinct
        ;; signers only): id1 signing twice is still 1 distinct signer → Deny (M4)
        (check "multisig duplicate-sig same-signer does not inflate count -> Deny"
               (not (allowed cap (append inc3 (list (sig-inc s1) (sig-inc s1))))))
        ;; threshold = 1 (M3 structure) → Deny even with valid sigs (precedence 25)
        (let ((cap-t1 (mk-cap signers 1)))
          (check "multisig threshold=1 (M3) -> Deny"
                 (not (allowed cap-t1 (append inc3 (list (sig-inc (ecp:sign-entity id1 cap-t1))
                                                         (sig-inc (ecp:sign-entity id2 cap-t1))))))))
        ;; local peer not among the signers → Deny (M6)
        (let* ((cap-nl (mk-cap (list h2 h3) 2))
               (n2 (ecp:sign-entity id2 cap-nl))
               (n3 (ecp:sign-entity id3 cap-nl)))
          (check "multisig local-not-in-signers (M6) -> Deny"
                 (not (allowed cap-nl (list (peer-inc id2) (peer-inc id3)
                                            (sig-inc n2) (sig-inc n3))))))
        ;; duplicate signers (M3 structure) → Deny
        (let* ((cap-dup (mk-cap (list h1 h1) 2)))
          (check "multisig duplicate-signers (M3) -> Deny"
                 (not (allowed cap-dup (list (peer-inc id1)
                                             (sig-inc (ecp:sign-entity id1 cap-dup)))))))
        ;; multi-sig is ROOT-ONLY: a multi-sig token with a parent → Deny (M3)
        (let* ((cap-child (mk-cap signers 2 h1)))
          (check "multisig with parent (root-only, M3) -> Deny"
                 (not (allowed cap-child (append inc3 (list (sig-inc (ecp:sign-entity id1 cap-child))
                                                            (sig-inc (ecp:sign-entity id2 cap-child)))))))))
      ;; single-sig strict-superset: a normal single-sig root still verifies
      (let* ((ss-cap (ecp:make-entity
                      "system/capability/token"
                      (make-cbor-map (list (cons "granter" (make-bytes h1))
                                           (cons "grantee" (make-bytes h1))
                                           (cons "grants" '())))))
             (ss-sig (ecp:sign-entity id1 ss-cap)))
        (check "single-sig root still verifies (strict superset)"
               (allowed ss-cap (list (peer-inc id1) (sig-inc ss-sig))))))))

(defun run-ed448-kat ()
  "Ed448 RFC-8032 KAT byte-equality gate (A-CL-005). Pins from v7.71
agility-SEEDS.md §1.1 (KEY-TYPE-ED448-1)."
  (let* ((seed (make-array 57 :element-type '(unsigned-byte 8) :initial-element #x42))
         (msg-hex "76372e3637205068617365203120636f686f72742063726f73732d696d706c2045643434382066697874757265")
         (msg (hex->octets msg-hex))
         (want-pub-hex "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00")
         (want-sig-hex "0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400")
         (want-peer-id "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4"))
    (handler-case
        (let* ((pub (ed-public-key seed :ed448))
               (sig (ed-sign seed msg :ed448))
               (peer-id (peer-id-from-public-key pub :ed448)))
          (check "ED448 KAT pubkey (57 B, byte-equal)"
                 (octets= pub (hex->octets want-pub-hex)))
          (check "ED448 KAT signature (114 B, byte-equal RFC-8032)"
                 (octets= sig (hex->octets want-sig-hex)))
          (check "ED448 KAT verify" (ed-verify pub msg sig :ed448))
          (check "ED448 KAT peer_id (§1.5 SHA-256-form)"
                 (string= peer-id want-peer-id)))
      (error (c)
        (check "ED448 KAT (native pure-Lisp)" nil
               (format nil "ironclad Ed448 raised: ~a — fallback = hybrid-FFI (A-OC-002)" c))))))
