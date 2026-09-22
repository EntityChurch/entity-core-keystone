;;;; spec-0825.lisp — the 0.8.2.20 .. 0.8.2.25 surfaces this harness owns.
;;;;
;;;; FOUR RULES, ONE FILE, because they share a fixture vocabulary:
;;;;
;;;;   RULE A — §3.3's effective-targets ladder, §6.3's CHECK-PATH-PERMISSION, and
;;;;            the §6.3 listing filter (0.8.2.20/.21/.22 + N7/N10/N11 at .24/.25).
;;;;   RULE B — the §5.4 sentinel scoped to PATH-SCOPE (0.8.2.24, N2/N3).
;;;;   RULE C — the decode-boundary code belongs to the CAUSE (0.8.2.24, N4/N5).
;;;;   RULE E — SCOPE-SUBSET typed by scope kind (F50, ruled at 0.8.2.16).
;;;;   RULE F — the sentinel guard sits on every path to the decision (K-6).
;;;;   RULE D — §4.11's pre-admission refusal table (0.8.2.25).
;;;;
;;;; EVERY PREDICATE HERE CARRIES BOTH DIRECTIONS. A deny-only test of an
;;;; authorization predicate is indistinguishable from one asserting NIL == NIL: a
;;;; broken fixture denies everything and every deny case passes. The accept case is
;;;; what validates the FIXTURE, and one deny case PER DIMENSION is what says the
;;;; predicate checks the dimension under test rather than merely being able to say no.
;;;;
;;;; The tree ladder is driven through the REAL HANDLE-OP with a real store, because
;;;; the defect RULE A closes is a handler that implements §3.3's ARITHMETIC completely
;;;; and then indexes targets[0] anyway — EFFECTIVE-TARGETS alone cannot show that.

(in-package #:entity-core/test)

(defvar *spec-fail* 0)

(defun s-check (name ok &optional detail)
  (if ok
      (format t "  ok   ~a~%" name)
      (progn (incf *spec-fail*) (format t "  FAIL ~a: ~a~%" name detail))))

(defvar +local+ "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA")
(defvar +remote+ "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB")

;; ── fixture builders ───────────────────────────────────────────────────────────

(defun sc (incl &optional excl)
  (ecp::make-scope incl excl))

(defun scope-cbor* (incl &optional excl)
  (if excl
      (entity-core:map-of "include" incl "exclude" excl)
      (entity-core:map-of "include" incl)))

(defun grant* (&key (handlers '()) (resources '()) (operations '())
                    handlers-excl resources-excl operations-excl peers)
  (let ((pairs (list (cons "handlers" (scope-cbor* handlers handlers-excl))
                     (cons "resources" (scope-cbor* resources resources-excl))
                     (cons "operations" (scope-cbor* operations operations-excl)))))
    (when peers (setf pairs (append pairs (list (cons "peers" (scope-cbor* peers))))))
    (entity-core:make-cbor-map pairs)))

(defun token* (&rest grants)
  (ecp:make-entity "system/capability/token" (entity-core:map-of "grants" grants)))

(defun grant-rec* (&rest args)
  (ecp::parse-grant (apply #'grant* args)))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE B — §5.4's sentinel is PATH-SCOPE only (0.8.2.24, N2/N3)
;; ═══════════════════════════════════════════════════════════════════════════════
;;
;; "A capability carrying an unmatchable PATH-SCOPE pattern is INVALID [MUST] ... It
;; does NOT reach operations or peers [MUST]."
;;
;; The id-scope case cannot be passed by accident: "*/apply" is an ordinary namespaced
;; operation name that PATH-canonicalizes to the sentinel, so on the pre-.24 unscoped
;; reading it DENIED THE WHOLE DIMENSION — "get", included by a bare "*", came back
;; NIL. The path-scope half is the other side and proves this is a scope SPLIT rather
;; than a removal: the sentinel still bites where the dimension is a path.
(defun test-sentinel-scoping ()
  (s-check "B: id-scope exclude */apply carves out nothing"
           (ecp::matches-scope +local+ "get" (sc '("*") '("*/apply")) :id))
  (s-check "B: id-scope peers exclude ../nope carves out nothing"
           (ecp::matches-scope +local+ +local+ (sc '("*") '("../nope")) :id))
  (s-check "B: path-scope unmatchable exclude STILL denies"
           (not (ecp::matches-scope +local+ "system/tree" (sc '("*") '("../nope")) :path)))
  (s-check "B: path-scope matchable exclude carves out only its own target"
           (and (ecp::matches-scope +local+ "system/tree" (sc '("*") '("system/secret")) :path)
                (not (ecp::matches-scope +local+ "system/secret"
                                         (sc '("*") '("system/secret")) :path)))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE E — SCOPE-SUBSET is typed by scope kind (F50, ruled YES at 0.8.2.16)
;; ═══════════════════════════════════════════════════════════════════════════════
;;
;; §3.6's grammar binds the scope TYPE, not one function: "An implementation on the
;; canonicalizing reading is non-conformant and MUST adopt the literal matcher."
;; entity-core-formalization (K-7) measured the divergence on lean at 2 of 64 include
;; pairs and 2 of 64 exclude pairs, fail-CLOSED, with a 16-pair control alphabet
;; reporting 0 — which is why every hand-tried example missed it.
(defun subset* (child parent)
  (ecp::grant-subset +local+ +local+ +local+ child parent))

(defun test-scope-subset-typing ()
  ;; THE DISCRIMINATING PAIR (K-7's own witness). "*/apply" PATH-canonicalizes to the
  ;; §5.4 sentinel, which MATCHES-PATTERN then refuses in EITHER operand — the
  ;; fail-CLOSED direction K-7 measured. Under the conformant literal matcher a bare
  ;; "*" covers it.
  (s-check "E: an ordinary namespaced operation name is a LITERAL, covered by *"
           (subset* (grant-rec* :operations '("*/apply"))
                    (grant-rec* :operations '("*"))))
  (s-check "E: the exclude arm takes the literal matcher too"
           (subset* (grant-rec* :operations '("*") :operations-excl '("*/apply"))
                    (grant-rec* :operations '("*") :operations-excl '("*/apply"))))
  ;; CONTROLS — without these the typing change would be satisfied by a function that
  ;; returns T unconditionally.
  (s-check "E: CONTROL a child include the parent does not cover is NOT a subset"
           (not (subset* (grant-rec* :operations '("get"))
                         (grant-rec* :operations '("put")))))
  (s-check "E: CONTROL a dropped parent exclude is NOT a subset"
           (not (subset* (grant-rec* :operations '("*"))
                         (grant-rec* :operations '("*") :operations-excl '("put")))))
  ;; The PATH dimensions are unchanged by F50 — the frames still do the work.
  (s-check "E: handlers is path-scope and still canonicalizes"
           (and (subset* (grant-rec* :handlers '("system/tree"))
                         (grant-rec* :handlers (list (format nil "/~a/system/tree" +local+))))
                (not (subset* (grant-rec* :handlers '("system/tree"))
                              (grant-rec* :handlers (list (format nil "/~a/system/tree" +remote+)))))))
  (s-check "E: peers is the second id-scope dimension"
           (and (subset* (grant-rec* :operations '("*") :peers (list +local+))
                         (grant-rec* :operations '("*") :peers '("*")))
                (not (subset* (grant-rec* :operations '("*") :peers (list +remote+))
                              (grant-rec* :operations '("*") :peers (list +local+)))))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE F — the sentinel guard sits on every path that reaches the decision (K-6)
;; ═══════════════════════════════════════════════════════════════════════════════
;;
;; 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the guard
;; MUST sit on every path that reaches the decision it protects."
;;
;; THIS PEER SATISFIES IT BY CONSTRUCTION AND THAT IS THE POINT OF THIS TEST: the guard
;; is the FIRST COND CLAUSE OF MATCHES-PATTERN itself, not a wrapper beside it, so
;; there is no unguarded twin a call site could reach instead. lean's defect was two
;; functions — matchesSeg raw and matchesSegNM guarded — with scopeSubset calling the
;; raw one. This peer has ONE function, and every matcher call site (COVERED,
;; COVERED-LOCAL/COVERED-GRANT in CHECK-RESOURCE-SCOPE, SCOPE-SUBSET,
;; CHECK-PATH-PERMISSION, EFFECTIVE-TARGETS) routes through it.
(defun test-never-match-guard ()
  (let ((nm ecp::+never-match+))
    (s-check "F: sentinel as the VALUE never matches"
             (not (ecp::matches-pattern nm "*")))
    (s-check "F: sentinel as the PATTERN never matches"
             (not (ecp::matches-pattern (format nil "/~a/x" +local+) nm)))
    (s-check "F: sentinel against ITSELF never matches"
             (not (ecp::matches-pattern nm nm)))
    ;; CONTROL: the bare-star clause sits directly below the guard and returns T for
    ;; everything else, which is exactly why the guard has to be first.
    (s-check "F: CONTROL a bare * still matches an ordinary path"
             (ecp::matches-pattern (format nil "/~a/x" +local+) "*")))
  (s-check "F: a sentinel INCLUDE covers nothing (fail-CLOSED) through matches-scope"
           (not (ecp::matches-scope +local+ "../nope" (sc '("*")) :path)))
  (s-check "F: a sentinel INCLUDE covers nothing through scope-subset"
           (not (subset* (grant-rec* :handlers '("../nope"))
                         (grant-rec* :handlers '("*")))))
  (s-check "F: a sentinel INCLUDE covers nothing through check-path-permission"
           (not (ecp::check-path-permission
                 +local+ "get" (format nil "/~a/app/x" +local+)
                 (token* (grant* :handlers '("*") :operations '("*") :resources '("../nope")))
                 "system/tree"))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE A (part 1) — §6.3 CHECK-PATH-PERMISSION (0.8.2.20/.21/.22)
;; ═══════════════════════════════════════════════════════════════════════════════
(defun test-check-path-permission ()
  (let ((tok (token* (grant* :handlers '("system/tree") :operations '("get")
                             :resources '("app/*"))))
        (path (format nil "/~a/app/x" +local+)))
    ;; THE ACCEPT CASE IS THE FIXTURE'S OWN TEST. Without it a grant map this function
    ;; cannot parse would deny everything and all three deny cases below would pass.
    (s-check "A: check-path-permission ACCEPTS when all three dimensions line up"
             (ecp::check-path-permission +local+ "get" path tok "system/tree"))
    ;; ONE DENY PER DIMENSION, because a single deny cannot distinguish "the predicate
    ;; checks the dimension I care about" from "the predicate denies".
    (s-check "A: denies on the handlers dimension (path-scope)"
             (not (ecp::check-path-permission +local+ "get" path tok "system/other")))
    (s-check "A: denies on the operations dimension (id-scope)"
             (not (ecp::check-path-permission +local+ "put" path tok "system/tree")))
    (s-check "A: denies on the resources dimension (path-scope)"
             (not (ecp::check-path-permission +local+ "get" (format nil "/~a/other/x" +local+)
                                              tok "system/tree"))))
  ;; §6.3's signature names handlers, operations and resources. PEERS is NOT consulted:
  ;; the path is local by construction here (§1.4's inbound rule refuses a foreign
  ;; namespace at §6.5 step 3, before any handler runs).
  (s-check "A: three dimensions, not four — an empty peers scope does not deny"
           (ecp::check-path-permission
            +local+ "get" (format nil "/~a/app/x" +local+)
            (token* (grant* :handlers '("system/tree") :operations '("get")
                            :resources '("app/*") :peers '()))
            "system/tree"))
  ;; §5.2's note: an empty RESOURCES.INCLUDE is a LEGAL grant shape (a handler that
  ;; touches no tree paths) and coverage over an empty include list is NIL, so it denies
  ;; every path. Not a parse failure — the accept control above proves the parser works.
  (s-check "A: an empty resources.include denies every path"
           (not (ecp::check-path-permission
                 +local+ "get" (format nil "/~a/app/x" +local+)
                 (token* (grant* :handlers '("*") :operations '("*") :resources '()))
                 "system/tree")))
  ;; A malformed path canonicalizes to +NEVER-MATCH+, which matches no grant, so it
  ;; falls through to DENY rather than being matched against anything — and rather than
  ;; escaping as a condition the §6.5 frame would answer 500 (0.8.2.20 made CANONICALIZE
  ;; total for exactly this reason).
  (let ((wide (token* (grant* :handlers '("*") :operations '("*") :resources '("*")))))
    (s-check "A: CONTROL the same token authorizes a well-formed local path"
             (ecp::check-path-permission +local+ "get" (format nil "/~a/app/x" +local+)
                                         wide "system/tree"))
    (s-check "A: a malformed path falls through to DENY"
             (not (ecp::check-path-permission +local+ "get" "../escape" wide "system/tree")))
    ;; §6.3's block reads matches_scope(canonical_path, grant.resources, "path-scope",
    ;; local_peer_id) — there is NO granter parameter to pass. A bare "*" in RESOURCES
    ;; therefore canonicalizes to /{local}/* here whoever granted the capability.
    (s-check "A: the frame is the LOCAL peer, not the granter"
             (not (ecp::check-path-permission +local+ "get" (format nil "/~a/app/x" +remote+)
                                              wide "system/tree")))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE A (part 2) — EFFECTIVE-TARGETS: the TWO-EMPTIES DISCRIMINATOR (N11)
;; ═══════════════════════════════════════════════════════════════════════════════
;;
;; N11 makes the discriminator a [MUST]: "where an implementation projects
;; resource.targets onto the effective set ahead of the handler, that projection MUST
;; NOT be lossy about its own emptiness — narrow when narrowing leaves something, and
;; retain the raw pair when narrowing would empty it." This peer carries the
;; discriminator as a SECOND RETURN VALUE, because CL's NIL is both "absent" and "the
;; empty list" and a single-value return therefore CANNOT express it.
(defun eff* (resource)
  (let ((exec (ecp::make-execute "r1" "system/tree" "get" (ecp:empty-params)
                                 :resource resource)))
    (ecp::effective-targets +local+ exec)))

(defun eff-present-p (resource)
  (nth-value 1 (eff* resource)))

(defun test-effective-targets ()
  (s-check "A: an absent resource reports ABSENT"
           (not (eff-present-p nil)))
  ;; PINS THE SHIPPED ANSWER TO AN OPEN QUESTION rather than endorsing it. §3.2 says
  ;; TARGETS "MUST contain at least one entry", which makes a resource map with no
  ;; TARGETS key MALFORMED rather than absent — and N10's point is that a PRESENT
  ;; resource must not be served the wider absent-case answer. Nothing in the 778-check
  ;; set drives it and no disposition is pinned, so the behaviour is HELD rather than
  ;; changed; this case exists so that changing it is a DECISION and not a drift.
  (s-check "A: a resource map with no targets key reports ABSENT (open question, held)"
           (and (not (eff-present-p (entity-core:make-cbor-map nil)))
                (not (eff-present-p (entity-core:map-of "exclude" '("a"))))))
  ;; THE DISCRIMINATOR, in the direction N11 protects.
  (s-check "A: present-but-self-excluded reports PRESENT with no survivors"
           (multiple-value-bind (eff had)
               (eff* (entity-core:map-of "targets" '("a") "exclude" '("a")))
             (and had (null eff))))
  (s-check "A: an explicitly empty targets array reports PRESENT"
           (multiple-value-bind (eff had) (eff* (entity-core:map-of "targets" '()))
             (and had (null eff))))
  ;; An ill-typed TARGETS is PRESENT. Reporting it absent gives GET the root listing for
  ;; a request that named something — N11's own defect one field over, and the cell on
  ;; which the two 0.8.2.25 vanguards diverged before being corrected toward go.
  (s-check "A: an ill-typed targets is PRESENT, not absent"
           (multiple-value-bind (eff had) (eff* (entity-core:map-of "targets" 42))
             (and had (null eff))))
  ;; 0.8.2.21: EFFECTIVE-TARGETS yields RAW survivors, not canonical forms — the value
  ;; flows on to the store lookup, which canonicalizes for itself.
  (s-check "A: survivors keep the caller's own spelling"
           (equal (eff* (entity-core:map-of "targets" '("app/x" "app/y") "exclude" '("app/y")))
                  '("app/x"))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE A (part 3) + RULE G — the ladder in the REAL tree handler
;; ═══════════════════════════════════════════════════════════════════════════════
(defvar *lp* nil)

(defun mk-peer ()
  (let ((p (ecp:make-peer :seed (make-array 32 :element-type '(unsigned-byte 8)
                                               :initial-element #x5a))))
    (setf *lp* (ecp:peer-local-peer p))
    (ecp:store-bind (ecp:peer-store p) (format nil "/~a/app/a" *lp*)
                    (ecp:make-entity "primitive/any" (entity-core:map-of "v" 1)))
    (ecp:store-bind (ecp:peer-store p) (format nil "/~a/app/b" *lp*)
                    (ecp:make-entity "primitive/any" (entity-core:map-of "v" 2)))
    p))

(defun cap* (&key (resources '("*")) resources-excl)
  (token* (grant* :handlers '("*") :operations '("*")
                  :resources resources :resources-excl resources-excl)))

(defun ctx* (resource &key (operation "get") (cap (cap*)) params (pattern "system/tree"))
  (let ((exec (ecp::make-execute "r1" "system/tree" operation (or params (ecp:empty-params))
                                 :resource resource)))
    (list :exec exec :conn nil :included nil :caller-cap cap
          :env (ecp:make-envelope exec) :handler-pattern pattern)))

(defun outcome-code (o)
  (ecp:entity-text (ecp::outcome-result o) "code"))

(defun run-op (peer op ctx)
  (ecp::handle-op (ecp::handler-instance peer "system/tree") op ctx))

(defun test-tree-ladder ()
  (let ((p (mk-peer)))
    ;; ── RULE G: resolve the OPERATION first; only then run the §3.3 ladder ──
    ;;
    ;; A peer that validates the resource first answers the wrong fault for every
    ;; unknown operation (entity-system-conformance X9 / F52). The control WITH a
    ;; resource is what makes it an ORDERING claim rather than a missing-501 claim.
    ;; On this substrate the ordering is STRUCTURAL: HANDLE-OP is a CLOS generic
    ;; specialized on the operation keyword, so an unknown operation reaches the
    ;; default (handler, op) method and never enters a resource ladder at all.
    (s-check "G: an unknown operation with NO resource is 501"
             (let ((o (run-op p :bogusop (ctx* nil))))
               (and (= (ecp::outcome-status o) 501)
                    (string= (outcome-code o) "unsupported_operation"))))
    (s-check "G: CONTROL the same unknown operation WITH a resource is also 501"
             (let ((o (run-op p :bogusop (ctx* (entity-core:map-of "targets" '("app/a"))))))
               (and (= (ecp::outcome-status o) 501)
                    (string= (outcome-code o) "unsupported_operation"))))

    ;; ── the ladder, GET (resource-OPTIONAL, BROAD-RESULT per EXTENSION-TREE §2.2a) ──
    (s-check "A: an absent resource is the root listing"
             (let ((o (run-op p :get (ctx* nil))))
               (and (= (ecp::outcome-status o) 200)
                    (string= (ecp:entity-typ (ecp::outcome-result o)) "system/tree/listing"))))
    ;; THE TWO EMPTIES ARE DISTINCT. Collapsing them would serve the ROOT LISTING to a
    ;; request that named one excluded path — the wider-than-the-request answer §3.3
    ;; forbids and the live disclosure the 0.8.2.25 vanguard work surfaced.
    (s-check "A: present-but-self-excluded is 400 path_required"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a")
                                                               "exclude" '("app/a"))))))
               (and (= (ecp::outcome-status o) 400)
                    (string= (outcome-code o) "path_required"))))
    (s-check "A: two effective targets is 400 ambiguous_resource"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a" "app/b"))))))
               (and (= (ecp::outcome-status o) 400)
                    (string= (outcome-code o) "ambiguous_resource"))))
    ;; THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then
    ;; indexes targets[0] has implemented the arithmetic completely and is still reading
    ;; a path no authorization covered. Here targets[0] is EXCLUDED and the single
    ;; survivor is targets[1], so the two readings return different entities.
    (s-check "A: the selection is the SURVIVOR, never targets[0]"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a" "app/b")
                                                               "exclude" '("app/a"))))))
               (and (= (ecp::outcome-status o) 200)
                    (eql (ecp:entity-field (ecp::outcome-result o) "v") 2))))
    ;; 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing "/" is
    ;; a listing request and is NOT a pattern — only a * makes it one.
    (s-check "A: a pattern target is 400 malformed_resource"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/*"))))))
               (and (= (ecp::outcome-status o) 400)
                    (string= (outcome-code o) "malformed_resource"))))
    (s-check "A: CONTROL a trailing-slash target is a LISTING, not a pattern"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/"))))))
               (and (= (ecp::outcome-status o) 200)
                    (string= (ecp:entity-typ (ecp::outcome-result o)) "system/tree/listing"))))
    ;; §5.4 rules the caller-exclude arm separately from the GRANT arm: CANONICALIZE
    ;; answers the sentinel, MATCHES-PATTERN then answers NIL, and the target simply
    ;; SURVIVES. The matchable control beside it is what says the exclude works at all.
    (s-check "A: the caller-exclude arm is fail-OPEN on an unmatchable pattern"
             (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a")
                                                               "exclude" '("../nope"))))))
               (and (= (ecp::outcome-status o) 200)
                    (eql (ecp:entity-field (ecp::outcome-result o) "v") 1))))

    ;; ── the ladder, PUT (resource-REQUIRED) ──
    ;;
    ;; THE CODE CHANGE 0.8.2.20 FORCED: this branch answered ambiguous_resource for a
    ;; MISSING target, which 0.8.2.20 names as the exact inversion it forbids — the
    ;; remedies differ (supply a resource is not disambiguate your request) and the code
    ;; is what selects the remedy.
    (s-check "A: put answers path_required for a MISSING target"
             (string= (outcome-code (run-op p :put (ctx* nil :operation "put")))
                      "path_required"))
    (s-check "A: put collapses BOTH empties to path_required"
             (string= (outcome-code
                       (run-op p :put (ctx* (entity-core:map-of "targets" '("app/a")
                                                                "exclude" '("app/a"))
                                            :operation "put")))
                      "path_required"))
    (s-check "A: put still answers ambiguous_resource for TWO survivors"
             (string= (outcome-code
                       (run-op p :put (ctx* (entity-core:map-of "targets" '("app/a" "app/b"))
                                            :operation "put")))
                      "ambiguous_resource"))

    ;; ── §6.3: the handler-level path check ──
    ;;
    ;; THE F84 DEFECT. The caller's own EXCLUDE removes app/b from the DISPATCH check's
    ;; view entirely, so CHECK-PERMISSION never sees it; without §6.3's own check the
    ;; handler then serves it. §6.3: "not a secondary check ... the sole enforcement
    ;; wherever the subject is derived after dispatch."
    (let ((narrow (cap* :resources '("*") :resources-excl '("app/b"))))
      (s-check "A: get DENIES a path the caller's own capability excludes"
               (let ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/b"))
                                             :cap narrow))))
                 (and (= (ecp::outcome-status o) 403)
                      (string= (outcome-code o) "capability_denied"))))
      (s-check "A: CONTROL the SAME capability still serves a path it covers"
               (= (ecp::outcome-status
                   (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a"))
                                        :cap narrow)))
                  200))
      (s-check "A: put DENIES, and nothing is written"
               (let* ((e (ecp:make-entity "primitive/any" (entity-core:map-of "v" 9)))
                      (params (ecp:make-entity "primitive/any"
                                               (entity-core:map-of "entity" (ecp:entity-to-cbor e))))
                      (o (run-op p :put (ctx* (entity-core:map-of "targets" '("app/b"))
                                              :operation "put" :cap narrow :params params))))
                 (and (= (ecp::outcome-status o) 403)
                      ;; A 403 whose refusal arrives AFTER the store write would satisfy
                      ;; the status assertion alone, so the store is read back.
                      (eql (ecp:entity-field
                            (ecp:store-get-at (ecp:peer-store p) (format nil "/~a/app/b" *lp*))
                            "v")
                           2))))
      ;; The bootstrap/internal path. The filter's subject is "the caller's verified
      ;; capability", and where there is none there is no caller to narrow.
      (s-check "A: an unauthenticated context is NOT path-checked"
               (= (ecp::outcome-status
                   (run-op p :get (ctx* (entity-core:map-of "targets" '("app/a")) :cap nil)))
                  200))

      ;; ── §6.3: the listing filter (0.8.2.21/.22) ──
      ;;
      ;; "Entries for which check_path_permission returns DENY MUST be omitted. The
      ;; result's COUNT field MUST reflect the FILTERED entry count, not the source
      ;; tree's total count." A count that still reports the source total IS the
      ;; disclosure the rule exists to prevent, so it is asserted separately.
      (s-check "A: the listing OMITS an entry the caller's capability excludes"
               (let* ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/"))
                                              :cap narrow)))
                      (r (ecp::outcome-result o))
                      (entries (ecp:entity-field r "entries")))
                 (and (= (ecp::outcome-status o) 200)
                      (equal (sort (mapcar #'car (entity-core:cbor-map-pairs entries)) #'string<)
                             '("a"))
                      (eql (ecp:entity-field r "count") 1))))
      (s-check "A: CONTROL a capability covering both names both, count 2"
               (let* ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/")))))
                      (r (ecp::outcome-result o))
                      (entries (ecp:entity-field r "entries")))
                 (and (equal (sort (mapcar #'car (entity-core:cbor-map-pairs entries)) #'string<)
                             '("a" "b"))
                      (eql (ecp:entity-field r "count") 2))))
      ;; §6.3 makes each ENTRY the subject. Testing the PREFIX would deny a listing to a
      ;; caller whose grant covers children but not the node above them, which is the
      ;; ordinary shape of a narrowed grant.
      (s-check "A: the DIRECTORY itself is deliberately not checked"
               (let* ((o (run-op p :get (ctx* (entity-core:map-of "targets" '("app/"))
                                              :cap (cap* :resources '("app/*")))))
                      (entries (ecp:entity-field (ecp::outcome-result o) "entries")))
                 (and (= (ecp::outcome-status o) 200)
                      (equal (sort (mapcar #'car (entity-core:cbor-map-pairs entries)) #'string<)
                             '("a" "b"))))))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE C + RULE D — the decode boundary and §4.11's refusal table
;; ═══════════════════════════════════════════════════════════════════════════════
(defun refusal-of (c) (ecp::pre-admission-refusal c))

(defun test-pre-admission-mapping ()
  ;; "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]"
  ;; — a single code for the class would answer an honest caller under the wrong reason
  ;; and send them to the wrong layer.
  (let ((rows
          (list
           ;; §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14).
           (list (make-condition 'ecp::frame-too-large) 413 "payload_too_large")
           ;; §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
           ;; non_canonical_ecf NON-CONFORMANT here.
           (list (make-condition 'ecp::hash-mismatch :detail "x") 400 "hash_mismatch")
           ;; ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
           (list (make-condition 'entity-core:tag-rejected :detail "x") 400 "non_canonical_ecf")
           ;; §4.7 / §4.11 framing arm: bytes that never become an Envelope.
           (list (make-condition 'ecp::truncated-frame) 400 "invalid_request")
           (list (make-condition 'entity-core:truncated-input :detail "x") 400 "invalid_request")
           (list (make-condition 'ecp::bad-entity :detail "x") 400 "invalid_request")
           ;; The one that makes the SUBTYPE ORDERING load-bearing: a non-minimal head
           ;; is "non-canonical CBOR" by name and is NOT the tag-policy arm.
           (list (make-condition 'entity-core:non-canonical-ecf :detail "x") 400 "invalid_request"))))
    (s-check "D: examined-N, not merely `no failures`" (= (length rows) 7) (length rows))
    (dolist (row rows)
      (destructuring-bind (c status code) row
        (destructuring-bind (got-status got-code message) (refusal-of c)
          (s-check (format nil "D: ~a -> ~a ~a" (type-of c) status code)
                   (and (= got-status status) (string= got-code code)
                        ;; A wire-visible string stays ASCII: two peers in this cohort
                        ;; have been killed at runtime by a non-ASCII byte in an encoded
                        ;; string, on two unrelated compilers.
                        (every (lambda (ch) (< (char-code ch) 128)) message))
                   (list got-status got-code))))))
  ;; Which read failures are owed a frame at all. A closed or reset socket is not a
  ;; refusal of anything and there is nobody left to answer.
  (s-check "D: framing-refusal-p separates OWED from ENDED"
           (and (ecp::framing-refusal-p (make-condition 'ecp::frame-too-large))
                (ecp::framing-refusal-p (make-condition 'ecp::truncated-frame))
                (not (ecp::framing-refusal-p (make-condition 'ecp::transport-closed))))))

(defun test-decode-boundary-split ()
  ;; Before 0.8.2.24 this peer answered 400 non_canonical_ecf for every one of these,
  ;; which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed INCLUDED
  ;; entry carries NO TAG, its encoding is canonical, and re-encode is not the caller's
  ;; remedy.
  (let* ((good (ecp:make-entity "primitive/any" (entity-core:map-of "x" 1)))
         (root (ecp::make-execute "t1" "system/tree" "get" (ecp:empty-params))))
    ;; (a) MIS-KEYED included entry -> resolution integrity.
    (s-check "C: a mis-keyed included entry signals HASH-MISMATCH"
             (typep (nth-value 1 (ignore-errors
                                  (ecp::envelope-of-cbor
                                   (entity-core:map-of
                                    "root" (ecp:entity-to-cbor root)
                                    "included" (entity-core:make-cbor-map
                                                (list (cons (entity-core:make-bytes
                                                             (make-array 33 :element-type '(unsigned-byte 8)
                                                                            :initial-element #x11))
                                                            (ecp:entity-to-cbor good))))))))
                    'ecp::hash-mismatch))
    ;; (b) A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
    ;; class (§1.8 item 1) and takes the same code.
    (s-check "C: a carried content_hash mismatch signals HASH-MISMATCH"
             (typep (nth-value 1 (ignore-errors
                                  (ecp:entity-of-cbor
                                   (entity-core:map-of
                                    "type" (ecp:entity-typ good)
                                    "data" (ecp:entity-data good)
                                    "content_hash" (entity-core:make-bytes
                                                    (make-array 33 :element-type '(unsigned-byte 8)
                                                                   :initial-element #x22))))))
                    'ecp::hash-mismatch))
    ;; (c) STRUCTURAL faults stay a bare BAD-ENTITY -> invalid_request. THIS IS THE
    ;; DISCRIMINATOR: HASH-MISMATCH is a SUBTYPE of BAD-ENTITY, so if both causes
    ;; collapsed into one condition the split above would pass vacuously — the negative
    ;; direction has to be asserted too.
    (s-check "C: a structural fault is BAD-ENTITY and NOT hash-mismatch"
             (let ((c (nth-value 1 (ignore-errors
                                    (ecp:entity-of-cbor (entity-core:map-of "data" 1))))))
               (and (typep c 'ecp::bad-entity) (not (typep c 'ecp::hash-mismatch)))))
    (s-check "C: a missing envelope root is BAD-ENTITY and NOT hash-mismatch"
             (let ((c (nth-value 1 (ignore-errors
                                    (ecp::envelope-of-cbor (entity-core:map-of "nope" 1))))))
               (and (typep c 'ecp::bad-entity) (not (typep c 'ecp::hash-mismatch)))))
    ;; (d) And the WELL-FORMED envelope must still decode, or every case above is
    ;; satisfied by a decoder that refuses everything.
    (s-check "C: CONTROL a well-formed envelope still decodes"
             (let ((env (ecp::envelope-of-cbor
                         (entity-core:map-of
                          "root" (ecp:entity-to-cbor root)
                          "included" (entity-core:make-cbor-map
                                      (list (cons (entity-core:make-bytes (ecp:entity-hash good))
                                                  (ecp:entity-to-cbor good))))))))
               (and env (ecp:included-get env (ecp:entity-hash good))))))
  ;; ENTITY-CBOR-ENCODING §6.3 is the sole definition of that code in the corpus and
  ;; assigns it to a major-type-6 item in a data-field position. Everything else this
  ;; decoder calls non-canonical is §4.11's framing arm.
  (s-check "C: a CBOR tag signals TAG-REJECTED"
           (typep (nth-value 1 (ignore-errors
                                (entity-core:cbor-decode
                                 (make-array 2 :element-type '(unsigned-byte 8)
                                               :initial-contents '(#xc1 #x00)))))
                  'entity-core:tag-rejected))
  ;; An INDEFINITE-LENGTH array head: a NON-CANONICAL-ECF that is NOT the tag arm, which
  ;; is what makes the SUBTYPE ordering in PRE-ADMISSION-REFUSAL load-bearing rather than
  ;; decorative.
  (s-check "C: an indefinite length is non-canonical but NOT the tag arm"
           (let ((c (nth-value 1 (ignore-errors
                                  (entity-core:cbor-decode
                                   (make-array 1 :element-type '(unsigned-byte 8)
                                                 :initial-contents '(#x9f)))))))
             (and (typep c 'entity-core:non-canonical-ecf)
                  (not (typep c 'entity-core:tag-rejected))
                  (string= (second (refusal-of c)) "invalid_request"))))
  ;; OUT OF SCOPE, RECORDED RATHER THAN FIXED, AND REPORTED AS AN OBSERVATION SO IT
  ;; CANNOT PASS FOR A GREEN.
  ;;
  ;; #x18 #x01 is a uint8-argument head carrying the value 1, which the canonical form
  ;; encodes in the head byte itself. %DEC-ARG accepts every well-formed head width
  ;; without comparing the decoded value to the minimal one, so this peer's strict decoder
  ;; answers 1 where the sibling ruby, python and go peers refuse. The elixir peer has the
  ;; SAME gap, found the same way on the same day — two peers, one shape.
  ;;
  ;; It is a CODEC change, outside RULES A-G's scope, with an unmeasured blast radius on
  ;; the S2 corpus (71/71 today) and on S4; smoothing it into a §4.11 sweep would bury it.
  ;; Printed, not counted: a FAIL here would hold this gate red on a pre-existing gap the
  ;; sweep did not create, which is the "teaches people to skip it" failure mode.
  (format t "  note NON-MINIMAL ARGUMENT HEAD ACCEPTED ON DECODE (pre-existing, out of ~
scope, reported not fixed): (cbor-decode #(#x18 #x01)) = ~s~%"
          (ignore-errors (entity-core:cbor-decode
                          (make-array 2 :element-type '(unsigned-byte 8)
                                        :initial-contents '(#x18 #x01))))))

;; ═══════════════════════════════════════════════════════════════════════════════
;; RULE D — §4.11 over a real socket
;; ═══════════════════════════════════════════════════════════════════════════════
;;
;; A green mapping over a transport that never calls it is the CHECK-PATH-PERMISSION
;; shape all over again, so the emission is driven end to end.
;;
;; EVERY SOCKET CASE CARRIES A POSITIVE CONTROL in the same run. A probe fails in the
;; direction of the answer it is looking for: a malformed frame that is malformed in a
;; SECOND way answers the code under measurement for the wrong reason, and without the
;; control that publishes as a peer finding.
(defun framed (payload)
  (let* ((n (length payload))
         (out (make-array (+ 4 n) :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (ldb (byte 8 24) n) (aref out 1) (ldb (byte 8 16) n)
          (aref out 2) (ldb (byte 8 8) n)  (aref out 3) (ldb (byte 8 0) n))
    (replace out payload :start1 4)
    out))

(defun hello-frame ()
  "A well-formed EXECUTE the peer MUST answer 200 — the positive control."
  (let* ((id (ecp:identity-of-seed (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element #x2a)))
         (hello (ecp:make-entity
                 "system/protocol/connect/hello"
                 (entity-core:map-of
                  "peer_id" (ecp:identity-peer-id id)
                  "nonce" (entity-core:make-bytes
                           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
                  "protocols" '("entity-core/1.0")
                  "timestamp" 1
                  "hash_formats" '("ecfv1-sha256")
                  "key_types" '("ed25519")))))
    (framed (ecp::frame-of-envelope
             (ecp:make-envelope
              (ecp::make-execute "ctl-1" "system/protocol/connect" "hello" hello))))))

(defvar +read-deadline-seconds+ 5
  "THE DEADLINE IS THE ASSERTION, not a convenience. §4.11's silent drop produces NO
response, and READ-FRAME parks in a blocking READ-SEQUENCE — so without a timeout a
dropped frame HANGS the harness instead of failing it, and a hung test is strictly worse
than a red one: it reports nothing and blocks everything behind it. Measured the hard way
while planting, twice in one session (the ruby peer's socket driver had the identical
hole).")

(defun read-response (stream)
  "One framed response, or NIL if the peer DROPPED the frame / closed with nothing."
  (handler-case
      (sb-ext:with-timeout +read-deadline-seconds+
      (let* ((payload (ecp::read-frame stream))
             (env (ecp::envelope-of-frame payload))
             (root (ecp:envelope-root env))
             (res (ecp:entity-field root "result")))
        (list (ecp:entity-uint root "status")
              (or (entity-core::cdr (assoc "code" (entity-core:cbor-map-pairs
                                                   (ecp::map-field res "data"))
                                           :test #'equal))
                  "")
              (or (ecp:entity-text root "request_id") ""))))
    (error () nil)
    (sb-ext:timeout () nil)))

(defmacro with-live-peer ((port-var) &body body)
  "Start a listener on an ephemeral port, run BODY, stop it."
  `(let ((peer (ecp:make-peer :seed (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element #x7b))))
     (multiple-value-bind (sock ,port-var) (ecp:listen-on 0)
       (let ((accept (sb-thread:make-thread
                      (lambda () (ignore-errors (ecp:accept-loop peer sock)))
                      :name "spec-accept")))
         (unwind-protect (progn ,@body)
           (ignore-errors (sb-bsd-sockets:socket-close sock))
           (ignore-errors (sb-thread:terminate-thread accept)))))))

(defun connect-stream (port)
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect s #(127 0 0 1) port)
    (values s (sb-bsd-sockets:socket-make-stream
               s :input t :output t :element-type '(unsigned-byte 8)))))

(defun drive (frames n port)
  "Send FRAMES on one connection and read N responses, keyed by request_id.

KEYED BY request_id, NOT BY ARRIVAL ORDER, and the reason is a real property of this
substrate rather than test hygiene: §4.8 dispatches an inbound EXECUTE on its OWN thread
while the framing refusals are written from the reader, so a spawned answer can
legitimately land after a later one. §6.11 correlates by request_id for exactly that
reason; asserting on position would be asserting something the protocol does not promise."
  (multiple-value-bind (sock stream) (connect-stream port)
    (unwind-protect
         (progn
           (dolist (f frames) (write-sequence f stream))
           (finish-output stream)
           (let ((out '()))
             (dotimes (i n (nreverse out))
               (let ((r (read-response stream)))
                 (push r out)))))
      (ignore-errors (sb-bsd-sockets:socket-close sock)))))

(defun by-id (responses)
  (let ((h (make-hash-table :test #'equal)))
    (dolist (r responses h)
      (when r (setf (gethash (third r) h) (list (first r) (second r)))))))

(defun test-pre-admission-wire ()
  (let ((good (ecp:make-entity "primitive/any" (entity-core:map-of "x" 1)))
        (root (ecp::make-execute "t1" "system/tree" "get" (ecp:empty-params))))
    (with-live-peer (port)
      ;; The control on its own, first. If this fails, nothing below is a reading about
      ;; the peer — it is a reading about this file.
      (s-check "D: the positive control answers 200"
               (equal (gethash "ctl-1" (by-id (drive (list (hello-frame)) 1 port)))
                      '(200 "")))

      ;; A COMPLETE frame the decoder refused: the framing is intact, so the peer answers
      ;; and KEEPS SERVING. The control on the SAME connection is the differential that
      ;; says the answer was a refusal of the FRAME and not the connection collapsing.
      (let* ((mis-keyed
               (framed (entity-core:cbor-encode
                        (entity-core:map-of
                         "root" (ecp:entity-to-cbor root)
                         "included" (entity-core:make-cbor-map
                                     (list (cons (entity-core:make-bytes
                                                  (make-array 33 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x11))
                                                 (ecp:entity-to-cbor good))))))))
             ;; A root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400
             ;; invalid_request (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and
             ;; NOT the silent drop this peer used to answer it with.
             (other-root
               (framed (ecp::frame-of-envelope
                        (ecp:make-envelope
                         (ecp:make-entity "primitive/any"
                                          (entity-core:map-of "request_id" "x-1"))))))
             (h (by-id (drive (list mis-keyed other-root (hello-frame)) 3 port))))
        (s-check "D+C: a mis-keyed included entry answers 400 hash_mismatch, CORRELATED"
                 (equal (gethash "t1" h) '(400 "hash_mismatch")) (gethash "t1" h))
        (s-check "D: a non-EXECUTE root answers 400 invalid_request, not silence"
                 (equal (gethash "x-1" h) '(400 "invalid_request")) (gethash "x-1" h))
        (s-check "D: the connection is STILL SERVING after both refusals"
                 (equal (gethash "ctl-1" h) '(200 ""))))

      ;; Where no request_id can be recovered, §4.11 prescribes "a best-effort coded
      ;; frame carrying no correlation" — an empty request_id IS that form. Guessing one
      ;; would correlate the refusal to somebody else's in-flight request.
      (let ((h (by-id (drive (list (framed (entity-core:cbor-encode
                                            (entity-core:map-of "nope" 1)))
                                   (framed (make-array 4 :element-type '(unsigned-byte 8)
                                                         :initial-element #xff))
                                   (hello-frame))
                             3 port))))
        (s-check "D: an unattributable refusal is an UNCORRELATED coded frame"
                 (equal (gethash "" h) '(400 "invalid_request")) (gethash "" h))
        (s-check "D: the connection is still serving after two uncorrelated refusals"
                 (equal (gethash "ctl-1" h) '(200 ""))))

      ;; §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the length
      ;; prefix with the connection intact and nothing spent, so the 413 goes out FIRST
      ;; and the close comes after — the close is now IN ADDITION to the frame, not
      ;; instead of it.
      (multiple-value-bind (sock stream) (connect-stream port)
        (unwind-protect
             (let ((n (1+ ecp::+max-frame+)))
               (write-sequence (make-array 4 :element-type '(unsigned-byte 8)
                                             :initial-contents
                                             (list (ldb (byte 8 24) n) (ldb (byte 8 16) n)
                                                   (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
                               stream)
               (finish-output stream)
               (let ((r (read-response stream)))
                 (s-check "D: an oversize frame is ANSWERED 413 before the close"
                          (equal r '(413 "payload_too_large" "")) r)))
          (ignore-errors (sb-bsd-sockets:socket-close sock))))
      (s-check "D: the listener survived the oversize refusal"
               (equal (gethash "ctl-1" (by-id (drive (list (hello-frame)) 1 port)))
                      '(200 "")))

      ;; A length prefix that never completes — §4.11's framing arm names this input
      ;; outright. The write side is shut down so the peer sees EOF mid-frame rather than
      ;; an idle connection.
      (multiple-value-bind (sock stream) (connect-stream port)
        (unwind-protect
             (progn
               (write-sequence (make-array 5 :element-type '(unsigned-byte 8)
                                             :initial-contents '(#x00 #x00 #x10 #x00 #xa1))
                               stream)
               (finish-output stream)
               (sb-bsd-sockets:socket-shutdown sock :direction :output)
               (let ((r (read-response stream)))
                 (s-check "D: a truncated frame is ANSWERED 400 invalid_request"
                          (equal r '(400 "invalid_request" "")) r)))
          (ignore-errors (sb-bsd-sockets:socket-close sock)))))))

;; ═══════════════════════════════════════════════════════════════════════════════

(defun run-spec-0825 ()
  "Run the 0.8.2.20..25 surface gate. Returns the failure count."
  (let ((*spec-fail* 0))
    (format t "~&== spec 0.8.2.25 (RULES A/B/C/D/E/F/G) ==~%")
    (test-sentinel-scoping)
    (test-scope-subset-typing)
    (test-never-match-guard)
    (test-check-path-permission)
    (test-effective-targets)
    (test-tree-ladder)
    (test-pre-admission-mapping)
    (test-decode-boundary-split)
    (test-pre-admission-wire)
    (format t "~&  spec 0.8.2.25: ~[all green~:;~:*~d FAIL~]~%" *spec-fail*)
    *spec-fail*))
