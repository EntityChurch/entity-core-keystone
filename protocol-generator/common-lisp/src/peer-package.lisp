;;;; peer-package.lisp — package for the S3 peer machinery (V7 Layers 1–4 + foundation).
;;;;
;;;; The codec package (entity-core / EC) is the pure S2 layer. The peer machinery
;;;; lives in its OWN package (entity-core/peer, nickname ECP) layered above it, so
;;;; the codec stays a clean, dependency-light unit and the peer surface is the new
;;;; S3 namespace. Naming follows the profile [naming]: lisp-case symbols,
;;;; +earmuffs+ constants, *earmuffs* specials, -p predicates. CLOS class names are
;;;; lisp-case (profile [naming].class_names).
;;;;
;;;; The distant-idiom probe (profile [idiom].clos_dispatch): handler resolution +
;;;; operation dispatch are CLOS GENERIC FUNCTIONS specialized on (handler-class ×
;;;; operation), i.e. real multiple dispatch — the seam every single-dispatch peer
;;;; (C#/TS/OCaml/Elixir) expresses as an if/match ladder. Concurrency is native
;;;; SBCL threads (sb-thread): one reader thread per connection + dispatch on its
;;;; own thread (§4.8/§6.11), a request_id→waitqueue correlation table under a mutex.

(defpackage #:entity-core/peer
  (:nicknames #:ecp)
  (:use #:cl)
  ;; Pull the codec value model + primitives in by their EC: names where used.
  (:import-from #:entity-core
                #:cbor-encode #:cbor-decode
                #:bytes #:make-bytes #:bytes-octets #:bytes-p
                #:cbor-map #:make-cbor-map #:cbor-map-pairs #:cbor-map-p #:map-of
                #:content-hash
                #:peer-id-from-public-key #:peer-id-parse
                #:ed-sign #:ed-verify #:ed-public-key
                #:octet-vector #:make-octet-vector)
  ;; ── Public surface, tiered (the S5 "settle the surface" decision) ──────────
  ;; CL has no module-private keyword; package exports ARE the surface. We can't
  ;; prune the test-client helpers wholesale (the in-repo test execs — smoke.lisp,
  ;; type-registry.lisp — are separate library clients that use them by name), so
  ;; the stable contract is DOCUMENTED by tier here, the OCaml-`.mli`-deferral
  ;; analogue. Tier 1/2 is the public surface; the last block is test-client +
  ;; address-space helpers that may churn without a semver bump (NOT stable API).
  (:export
   ;; ── Tier 1 — model + identity (codec-island consumers, the §1.x value layer) ──
   #:entity #:make-entity #:entity-of-cbor #:entity-typ #:entity-data #:entity-hash
   #:entity-to-cbor #:entity-field #:entity-text #:entity-bytes #:entity-uint
   #:envelope #:make-envelope #:envelope-root #:envelope-included #:included-get
   ;; identity (the struct type is KEYPAIR; accessors keep the IDENTITY- conc-name)
   #:keypair #:make-identity #:identity-of-seed #:identity-peer-id
   #:identity-peer-entity #:identity-hash #:identity-public-key
   #:identity-seed #:sign-entity #:verify-signature

   ;; ── Tier 2 — full peer (handshake / dispatch / store / transport) ──
   ;; peer
   #:peer #:make-peer #:peer-identity #:peer-store #:peer-local-peer #:dispatch
   #:bootstrap
   ;; store
   #:store #:make-store #:store-bind #:store-get-at #:store-get-by-hash
   #:store-put-entity #:store-hash-at #:store-listing
   #:register-content-consumer #:register-tree-consumer
   ;; type-registry (§9.5 core type floor, render-from-model)
   #:core-type-entities #:publish-core-types
   ;; transport (server + client)
   #:listen-on #:accept-loop #:serve-connection #:start-listener
   #:dial #:client-connection #:client-handshake #:client-execute #:client-close
   #:client-connection-remote-peer-id #:client-connection-capability
   #:response-status #:response-result

   ;; ── Test-client + address-space helpers (NOT stable API; used by the in-repo
   ;;    smoke/type-registry execs; may churn without a semver bump) ──
   #:empty-params #:resource-target          ; wire builders (smoke)
   #:grant #:scope #:scope-cbor              ; capability request builders (smoke)
   #:hex))                                    ; lowercase-hex helper (type-registry; A-CL-009)
