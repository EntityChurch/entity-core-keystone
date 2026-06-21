;;;; entity-core.asd — ASDF system definitions for entity-core-protocol-common-lisp
;;;;
;;;; Peer #5 (Common Lisp). Three systems, layered so the codec stays a clean,
;;;; dependency-light island and the peer machinery is its own namespace above it:
;;;;
;;;;   entity-core         — the S2 codec island: ECF (canonical-CBOR) encode/decode,
;;;;                         content-hash, peer-id, Ed25519/Ed448 sign/verify, varint,
;;;;                         base58. Public package ENTITY-CORE (nickname EC). The only
;;;;                         third-party runtime dependency is ironclad (crypto); CBOR,
;;;;                         base58, and varint are hand-rolled in-repo — no CL CBOR
;;;;                         library gives ECF's canonical guarantees (see profile [codec]).
;;;;   entity-core/peer    — the full V7 Layers 1–4 + foundation peer (handshake,
;;;;                         §6.5/§6.6 CLOS multiple-dispatch handlers, capability
;;;;                         authorization, in-memory store, §9.5 type registry,
;;;;                         native sb-thread transport). Public package ENTITY-CORE/PEER
;;;;                         (nickname ECP).
;;;;   entity-core/test    — the hand-rolled S2 codec conformance harness (run by
;;;;                         ASDF test-op). Test-only; not a public surface.
;;;;
;;;; Conformance: validate-peer --profile core PASS (568 · 284P/195W/0F/89S). The host
;;;; executable (../host.lisp, ENTITY-CORE/HOST) is the S4 conformance driver — it is
;;;; test/conformance only and is intentionally NOT a component of any installed system.
;;;;
;;;; Version: the release LINE is 0.1.0-pre — parked pre-release pending arch v0.1
;;;; sign-off + a first external Common Lisp consumer (the S5 promotion gate). ASDF's
;;;; :version field is dotted-integer ONLY (it rejects a SemVer "-pre" suffix and falls
;;;; back to NIL with a warning), so the :version slots carry the parseable "0.1.0" and
;;;; the "-pre" pre-release marker lives in CHANGELOG.md / README.md / status/PHASE-S5.md.
;;;; (A-CL-010 — ASDF has no SemVer pre-release channel; recorded, resolved locally.)

(asdf:defsystem "entity-core"
  :description "Entity Core Protocol (V7) — Common Lisp codec island: canonical-CBOR (ECF) encode/decode, content-hash, peer-id, Ed25519/Ed448."
  :author "Entity Core Protocol contributors"
  :license "Apache-2.0"
  :version "0.1.0"        ;; ASDF version field is dotted-integer only — pre-release "-pre" line carried in CHANGELOG/README (S5)
  :homepage "https://github.com/entity-systems/entity-core-keystone"
  :depends-on ("ironclad")
  :pathname "src/"
  :serial t
  :components ((:file "package")
               (:file "error")
               (:file "varint")
               (:file "base58")
               (:file "cbor")
               (:file "hash")
               (:file "peer-id")
               (:file "sign"))
  :in-order-to ((test-op (test-op "entity-core/test"))))

(asdf:defsystem "entity-core/peer"
  :description "Entity Core Protocol (V7) — Common Lisp peer machinery: V7 Layers 1–4 + foundation on native sb-thread concurrency + CLOS multiple-dispatch handlers."
  :author "Entity Core Protocol contributors"
  :license "Apache-2.0"
  :version "0.1.0"        ;; ASDF version field is dotted-integer only — pre-release "-pre" line carried in CHANGELOG/README (S5)
  :homepage "https://github.com/entity-systems/entity-core-keystone"
  :depends-on ("entity-core" "ironclad" "sb-bsd-sockets")
  :pathname "src/"
  :serial t
  :components ((:file "peer-package")
               (:file "peer-model")
               (:file "peer-identity")
               (:file "peer-store")
               (:file "type-defs-data")
               (:file "type-defs")
               (:file "peer-capability")
               (:file "peer-wire")
               (:file "peer")
               (:file "peer-transport")))

(asdf:defsystem "entity-core/test"
  :description "Hand-rolled conformance harness for the entity-core codec (test-op; not a public surface)."
  :author "Entity Core Protocol contributors"
  :license "Apache-2.0"
  :version "0.1.0"        ;; ASDF version field is dotted-integer only — pre-release "-pre" line carried in CHANGELOG/README (S5)
  ;; entity-core/peer is pulled in for the §3.6 multi-sig ACCEPT-path selftest
  ;; (verify-capability-chain + identity/sign helpers): the validate-peer multisig
  ;; category is 100% rejection tests, so the ALLOW direction lives only here.
  :depends-on ("entity-core" "entity-core/peer")
  :pathname "test/"
  :serial t
  :components ((:file "conformance")
               (:file "selftest"))
  :perform (test-op (op c)
             (uiop:symbol-call :entity-core/test :run-all)))
