;;;; peer-capability.lisp — Capability system (L3): the §5 verification core.
;;;;
;;;; Pattern matching (§5.4), request verification (§5.2 verify-request /
;;;; check-permission), delegation-chain verification (§5.5), attenuation (§5.6).
;;;; Derived from the §5 pseudocode directly (spec-first). The verdict is a bare
;;;; :allow / :deny (§5.10 Layer-1 determinism); the dispatcher maps :deny → 403,
;;;; with the unresolvable-grantee → 401 carve-out signalled as a condition.
;;;;
;;;; Scopes/grants are parsed out of the token entity's data on demand. The §PR-8
;;;; granter-frame refinement is carried on the LOCAL frame for the self-issued
;;;; dominant path (granter = local), which is byte-identical to the pre-fix
;;;; behavior — the cross-peer V2(a) flip is exercised at S4 against the oracle.

(in-package #:entity-core/peer)

(defconstant +uint64-max+ (1- (ash 1 64))
  "Inclusive maximum of primitive/uint — the §5.6 rule-3 representability bound.")

(defun temporal-fields-representable-p (cap)
  "§6.2 CAP-6a (INGEST): every temporal field on a RECEIVED token must be either
ABSENT (legal — \"no bound\") or representable as primitive/uint. A bignum, a
negative integer, or any non-integer is MALFORMED, and the verifier MUST refuse it
rather than read the unrepresentable field as absent — absent means *no expiry*, so
the fail-open reading grants an immortal capability to whoever sent the bad value.

The mechanism here is arithmetic rather than a null: ENTITY-UINT returns the value
of ANY integer, including a negative one, so the range checks did not skip — they
ran and returned the wrong answer. For a negative not_before, (>= tnow nb) is true,
so the cap passed.

Common Lisp integers are unbounded, so the >2^64 half is a DELIBERATE range check —
there is no overflow to trip over.

MUST run BEFORE the range checks it protects."
  (every (lambda (key)
           (let ((v (entity-field cap key)))
             (or (null v)
                 (and (integerp v) (<= 0 v +uint64-max+)))))
         '("expires_at" "not_before" "created_at")))


(define-condition unresolvable-grantee (error) ()
  (:documentation "§5.5 carve-out: a grantee that cannot be resolved → 401, not 403."))

;; ── grant / scope parse ───────────────────────────────────────────────────────

(defun text-list (v)
  (when (listp v) (remove-if-not #'stringp v)))

(defstruct (scope (:constructor make-scope (incl excl)))
  (incl nil) (excl nil))

(defun parse-scope (m)
  (if (cbor-map-p m)
      (make-scope (text-list (map-field m "include"))
                  (text-list (map-field m "exclude")))
      (make-scope nil nil)))

(defstruct (grant-rec (:constructor make-grant-rec (handlers resources operations peers)))
  handlers resources operations peers)

(defun parse-grant (m)
  (flet ((sc (k) (parse-scope (map-field m k))))
    (make-grant-rec (sc "handlers") (sc "resources") (sc "operations")
                    (when (map-field m "peers") (parse-scope (map-field m "peers"))))))

(defun grants-of-token (token)
  (let ((g (entity-field token "grants")))
    (when (listp g) (mapcar #'parse-grant g))))

;; ── §5.4 pattern matching ─────────────────────────────────────────────────────

(defun starts-with (prefix s)
  (and (>= (length s) (length prefix))
       (string= prefix (subseq s 0 (length prefix)))))

(defun normalize-uri (uri)
  "§1.4: strip the entity:// scheme to an absolute path."
  (if (starts-with "entity://" uri)
      (concatenate 'string "/" (subseq uri 9))
      uri))

(defparameter +never-match+ "/never-match"
  "The unmatchable value (0.8.2.20). Unreachable as a canonical path by
CONSTRUCTION: its first segment cannot be a peer_id, since PEER-ID-P requires >= 46
Base58 characters and #\- is outside the Base58 alphabet.")

(defun canonicalize (local-peer path)
  "Resolve peer-relative paths to absolute /{local}/... form.

TOTAL (0.8.2.20): the return domain is \"a canonical path OR +NEVER-MATCH+\". This
used to signal, and the signal was reachable from the wire — every normative call
site is a matcher with no error channel to consume one, so the condition escaped the
matcher, the resilience frame caught it, and \"../x\" in a resource exclude answered
500 (measured 2026-09-14). The diagnostic belongs at admission (§6.5), which has a
caller to answer."
  (cond ((or (starts-with "./" path) (starts-with "../" path)) +never-match+)
        ((starts-with "*/" path) +never-match+)
        ((starts-with "/" path) path)
        (t (concatenate 'string "/" local-peer "/" path))))

(defun matches-pattern (path pattern)
  "PATH and PATTERN both already canonical (absolute)."
  (cond
    ;; +NEVER-MATCH+ never matches, in EITHER operand (0.8.2.20). FIRST, and a
    ;; matcher rule rather than a property of the string: the clause below returns T
    ;; for a bare "*", so safety must not rest on a value merely looking unmatchable.
    ((or (string= path +never-match+) (string= pattern +never-match+)) nil)
    ((string= pattern "*") t)
    ((starts-with "/*/" pattern)
     (let ((remainder (subseq pattern 3)))
       (if (< (length path) 1) nil
           (let ((i (position #\/ path :start 1)))
             (if i (matches-pattern (subseq path (1+ i)) remainder) nil)))))
    ((and (>= (length pattern) 2)
          (string= (subseq pattern (- (length pattern) 2)) "/*"))
     (starts-with (subseq pattern 0 (1- (length pattern))) path))
    (t (string= path pattern))))

;; §5.2 id-scope match (0.8.1, F40) — operations and peers. Literal comparison with
;; exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix. None
;; of the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
;; literal string: a non-match, never a fault.
(defun matches-id-pattern (value pattern)
  (cond ((string= pattern "*") t)
        ((and (>= (length pattern) 2)
              (string= (subseq pattern (- (length pattern) 2)) "/*"))
         (let ((prefix (subseq pattern 0 (1- (length pattern)))))
           (and (>= (length value) (length prefix))
                (string= (subseq value 0 (length prefix)) prefix))))
        (t (string= value pattern))))

;; §5.2 typed scope match. KIND is :ID (operations, peers) or :PATH (handlers,
;; resources) and has no default — every call site names its dimension, so a new one
;; cannot silently inherit the wrong matcher, which is exactly the F40 defect.
(defun exclude-unmatchable-p (frame excl)
  "AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
fail-CLOSED in an include (covers nothing -> the grant grants nothing) and fail-OPEN
in an exclude (carves out nothing -> the grant is SILENTLY WIDER than its author
wrote): same value, same matcher, opposite safety direction, so the reading is chosen
where the POSITION is known and MATCHES-PATTERN stays uniform over its operands.

ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). +NEVER-MATCH+ is a §5.4
PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that §5.2's
own id-scope arm forbids putting through the §5.4 transforms. This guard used to sit
OUTSIDE the type dispatch, transcribing §5.2's loop as it read before that loop grew one
— which ran an id pattern through those transforms purely to classify it and then DENIED
THE WHOLE DIMENSION on a property unrelated to whether the exclude carves anything out.
An OPERATIONS exclude of \"*/apply\" — an ordinary namespaced operation name, and a
literal that matches nothing under the id-scope grammar — canonicalized to the sentinel
and denied every operation. Over-denial, and invisible on any well-formed grant.

§5.4 says outright that the rule \"does NOT reach operations or peers [MUST]\", and it
does NOT leave the id-scope dimensions unprotected by oversight: under the id-scope
grammar every non-* pattern is a literal and a literal is never structurally unmatchable,
so there is nothing here for this sentinel to detect. A scope boundary, not an omission."
  (some (lambda (p) (string= (canonicalize frame p) +never-match+)) excl))

(defun matches-scope (local-peer value s kind)
  ;; SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
  ;; `if dimension_type == "system/capability/path-scope"`, and §5.4 scopes its own
  ;; invalid-capability rule the same way. KIND already names the dimension here, so the
  ;; scoping costs one term and cannot be got wrong by a new call site.
  (if (and (eq kind :path) (exclude-unmatchable-p local-peer (scope-excl s)))
      nil                                      ; 0.8.2.21 — deny
  (if (eq kind :id)
      (flet ((covered-id (pats) (some (lambda (p) (matches-id-pattern value p)) pats)))
        (and (covered-id (scope-incl s)) (not (covered-id (scope-excl s)))))
      (let ((cv (canonicalize local-peer value)))
        (flet ((covered (pats) (some (lambda (p) (matches-pattern cv (canonicalize local-peer p))) pats)))
          (and (covered (scope-incl s)) (not (covered (scope-excl s)))))))))

;; ── §5.2 check-permission ──────────────────────────────────────────────────────

(defun first-segment (uri)
  (let ((uri (if (starts-with "/" uri) (subseq uri 1) uri)))
    (let ((i (position #\/ uri))) (if i (subseq uri 0 i) uri))))

(defun is-peer-id (seg)
  (and (>= (length seg) 46)
       (every (lambda (c) (find c entity-core::+base58-alphabet+)) seg)))

(defun extract-peer (local-peer uri)
  (let ((first (first-segment (normalize-uri uri))))
    (if (is-peer-id first) first local-peer)))

(defun check-resource-scope (local-peer granter-peer resource s)
  "Concrete-target subset (the core surface the oracle exercises). The grant's own
resource patterns canonicalize against the GRANTER's peer_id (§PR-8 / V2(a)), NOT
the verifier's: a bare \"*\" on a foreign-granted cap means \"/{granter}/*\" — the
granter's own namespace — so it does NOT admit the verifier's namespace. The
caller-supplied targets/exclude stay on the LOCAL frame (§5.4). For the self-issued
dominant path granter = local, so this is byte-identical to the pre-fix behavior;
only the foreign-granter cross-peer case flips from admit to deny."
  (let ((targets (text-list (map-field resource "targets")))
        (caller-excl (text-list (map-field resource "exclude"))))
    (flet ((covered-local (pats v) (some (lambda (p) (matches-pattern v (canonicalize local-peer p))) pats))
           ;; granter frame: the grant's own resource include/exclude patterns.
           (covered-grant (pats v) (some (lambda (p) (matches-pattern v (canonicalize granter-peer p))) pats)))
      (and targets
           ;; An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST,
           ;; before any target: the coverage test below is correct in isolation and
           ;; is simply never reached on a sentinel, because MATCHES-PATTERN says NIL.
           ;;
           ;; UNGUARDED ON PURPOSE, unlike MATCHES-SCOPE's (0.8.2.24): S here is ALWAYS
           ;; the RESOURCES dimension, which §5.2 fixes as path-scope, so the type test
           ;; that call site performs would be a constant here. The single-dimension
           ;; signature is what makes that checkable — a granter frame reaching an
           ;; id-scope call site is the defect, and this function cannot be one.
           (not (exclude-unmatchable-p granter-peer (scope-excl s)))
           (every (lambda (tgt)
                    (let ((ct (canonicalize local-peer tgt)))
                      (cond ((covered-local caller-excl ct) t)
                            ((not (covered-grant (scope-incl s) ct)) nil)
                            (t (not (covered-grant (scope-excl s) ct))))))
                  targets)))))

(defun resolve-granter-peer-id (resolve-fn cap)
  "§PR-8 — the frame for canonicalizing CAP's grant resource patterns is the
GRANTER's peer_id. Single-sig granter → derive peer_id from its public_key;
multi-sig / unresolvable granter → NIL (caller falls back to the local peer, the M3
root-only frame). RESOLVE-FN is the included-then-store lookup the chain walk uses."
  (let ((gh (entity-bytes cap "granter")))
    (when gh
      (let ((g (funcall resolve-fn gh)))
        (when g
          (let ((pk (entity-bytes g "public_key")))
            (when pk (peer-id-of-pubkey pk))))))))

(defun check-permission (local-peer granter-peer exec token handler-pattern)
  "Gate the wire request at the dispatch authorization boundary (§3.2.3 / v7.73).
GRANTER-PEER is the §PR-8 canonicalization frame for the cap's grant resource
patterns (resolved at the dispatch site); every other dimension stays on the local
frame."
  (let* ((operation (or (entity-text exec "operation") ""))
         (uri (or (entity-text exec "uri") ""))
         (target-peer (extract-peer local-peer uri))
         (resource (entity-field exec "resource")))
    (flet ((grant-ok (g)
             (and (matches-scope local-peer operation (grant-rec-operations g) :id)
                  (matches-scope local-peer handler-pattern (grant-rec-handlers g) :path)
                  (let ((peers (or (grant-rec-peers g) (make-scope (list local-peer) nil))))
                    (matches-scope local-peer target-peer peers :id))
                  (if (cbor-map-p resource)
                      (check-resource-scope local-peer granter-peer resource (grant-rec-resources g))
                      t))))
      (if (some #'grant-ok (grants-of-token token)) :allow :deny))))

;; ── §3.3 effective targets + §6.3 handler-level path check ─────────────────────

(defun effective-targets (local-peer exec)
  "§5.2's effective target list (0.8.2.20): the caller's own RESOURCE.EXCLUDE removes
entries from RESOURCE.TARGETS BEFORE anything else looks at the request.

Returns two values: the surviving targets, and whether the EXECUTE carried a RESOURCE at
all. The survivors are in the caller's OWN SPELLING, not canonicalized — 0.8.2.21 is
explicit that effective_targets yields raw survivors, and the distinction is load-bearing
because the value flows on to the tree lookup, which canonicalizes for itself.

THE SECOND VALUE IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
\"where an implementation projects resource.targets onto the effective set ahead of the
handler, that projection MUST NOT be lossy about its own emptiness — narrow when
narrowing leaves something, and retain the raw pair when narrowing would empty it.\" A
function returning only a list cannot satisfy that: collapsing [qA] exclude [qA] to NIL
would delete the two-empties discriminator before any handler could read it, and the
handler's refusal arm becomes dead code that only a WIRE drive can detect. Common Lisp
carries the discriminator as a SECOND RETURN VALUE — the same property, spelled the way
this substrate spells it, and better than a NIL-vs-empty-list distinction that CL does
not have (NIL is both).

\"Every seam that narrows is exempted alike, inbound-wire and in-process sub-dispatch,
or one request receives two different answers according to which door it arrived
through.\" This peer has exactly ONE narrowing seam — this function, called by the tree
handler — and §6.5's dispatch chain does not project: DISPATCH passes EXEC through
untouched and CHECK-PERMISSION reads RESOURCE for itself. So there is no second door to
keep in step, and adding a projection at dispatch would create one.

A PRESENT-BUT-ILL-TYPED TARGETS IS **PRESENT**, with an empty survivor list. Reporting it
absent would serve the WIDER absent-case answer to a request that named a resource, which
is N11's own defect one field over.

The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it separately
from the grant arm) and that is INHERITED here rather than restated: CANONICALIZE answers
the sentinel, MATCHES-PATTERN then answers NIL, and the target simply survives."
  (let ((r (entity-field exec "resource")))
    (if (not (cbor-map-p r))
        (values nil nil)
        ;; PRESENCE, not truthiness: a RESOURCE map with an explicit empty TARGETS array
        ;; is PRESENT. ASSOC answers the pair itself, which is the only way to tell an
        ;; absent key from a key bound to NIL on this substrate.
        (let ((pair (assoc "targets" (cbor-map-pairs r) :test #'equal)))
          (if (null pair)
              (values nil nil)
              (let ((targets (let ((v (cdr pair))) (if (listp v) v nil)))
                    (excl (text-list (map-field r "exclude"))))
                (values
                 (remove-if-not
                  (lambda (tgt)
                    (and (stringp tgt)
                         (let ((ct (canonicalize local-peer tgt)))
                           (notany (lambda (x) (matches-pattern ct (canonicalize local-peer x)))
                                   excl))))
                  targets)
                 t)))))))

(defun check-path-permission (local-peer operation path token handler-pattern)
  "§6.3's handler-level path check: may the caller access PATH AS A TREE PATH, under
HANDLER-PATTERN, with TOKEN?

IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the subject
is derived after dispatch, and the dispatch-level check can be made VACUOUS by
caller-controlled input: a caller who excludes the one target its capability does not
cover removes that target from CHECK-PERMISSION's view entirely, and a handler that then
acts on it has authorized nothing.

THREE DIMENSIONS, NOT FOUR. PEERS is not consulted — the path is local by construction at
this point (§1.4's inbound rule refuses a foreign namespace at §6.5 step 3, before any
handler runs), and §6.3's signature names only handlers, operations and resources.

THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature rather
than a choice: §6.3's block reads
matches_scope(canonical_path, grant.resources, \"path-scope\", local_peer_id) — there is
no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is a
pattern compared against a parent's pattern; this call site compares a CONCRETE local path
the handler is about to touch.

Scope types: HANDLERS -> path-scope, OPERATIONS -> id-scope, RESOURCES -> path-scope. An
empty RESOURCES.INCLUDE is a legal grant shape (§5.2: handlers that touch no tree paths)
and DENIES every path here, which is what that note says it should. A malformed path
canonicalizes to +NEVER-MATCH+, which matches no grant, so it falls through to DENY rather
than being matched against anything."
  (and (some (lambda (g)
               (and (matches-scope local-peer handler-pattern (grant-rec-handlers g) :path)
                    (matches-scope local-peer operation (grant-rec-operations g) :id)
                    (matches-scope local-peer path (grant-rec-resources g) :path)))
             (grants-of-token token))
       t))

;; ── §5.5 / §5.6 chain verification + attenuation ───────────────────────────────

(defun now-ms ()
  (multiple-value-bind (s us) (sb-ext:get-time-of-day)
    (+ (* s 1000) (floor us 1000))))

(defun find-signature (target included)
  "Find a system/signature in INCLUDED (alist) whose target == TARGET octets."
  (cdr (find-if (lambda (pair)
                  (let ((e (cdr pair)))
                    (and (string= (entity-typ e) "system/signature")
                         (let ((tg (entity-bytes e "target")))
                           (and tg (octets-equal tg target))))))
                included)))

(defun cap-resolve (included store h)
  "Resolve a hash H to an entity: included first, then the store."
  (or (included-get-alist included h)
      (store-get-by-hash store h)))

(defun included-get-alist (included h)
  (cdr (assoc h included :test #'octets-equal)))

;; §PR-8 / §5.5a (Amendment 1): each side's patterns canonicalize against THAT
;; side's granter peer_id — CHILD-PEER for the child grant's patterns, PARENT-PEER
;; for the parent's. For the resource dimension these are the per-link granter
;; frames; for handler/operation/peer dimensions both are the local frame (no §PR-8
;; there). When the two frames are equal (same-peer chain) this is byte-identical
;; to the pre-Amendment behavior.
(defun scope-subset (child-peer parent-peer child parent kind)
  "§5.5a/§5.6 subset check: every child include must be covered by some parent include,
and every parent exclude must be inherited by some child exclude.

TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization K-7). §3.6's
id-scope grammar binds the scope TYPE, not one function — \"An implementation on the
canonicalizing reading is non-conformant and MUST adopt the literal matcher\" — so the
rule F40 landed on MATCHES-SCOPE reaches here too, with delegation-chain WIDENING named
as the reason: on the canonicalizing reading a bare id include reads as covered by a
path-form parent pattern it does not literally match, and a child grant comes out wider
than its parent. lean's differential put it at 2 of 64 include pairs and 2 of 64 exclude
pairs, fail-closed, with a 16-pair control alphabet reporting 0 — which is why every
hand-tried example missed it.

KIND has NO DEFAULT and is named at every call site, because a default is how the next
dimension inherits the wrong matcher silently — the original F40 defect. The per-link
granter frames are meaningless on the id arm (an id pattern is never canonicalized) and
are simply unread there."
  (flet ((frame (pattern peer) (if (eq kind :path) (canonicalize peer pattern) pattern))
         (covers (pattern value) (if (eq kind :path)
                                     (matches-pattern value pattern)
                                     (matches-id-pattern value pattern))))
    (and (every (lambda (cp)
                  (let ((cc (frame cp child-peer)))
                    (some (lambda (pp) (covers (frame pp parent-peer) cc))
                          (scope-incl parent))))
                (scope-incl child))
         (every (lambda (pe)
                  (let ((cpe (frame pe parent-peer)))
                    (some (lambda (ce) (covers (frame ce child-peer) cpe))
                          (scope-excl child))))
                (scope-excl parent)))))

;; CHILD-PEER/PARENT-PEER are the §5.5a per-link granter frames applied to the
;; RESOURCE dimension only; handlers/operations/peers stay on LOCAL-PEER. The scope
;; KIND is a property of the DIMENSION and is named at every call site, never defaulted
;; (F50 / 0.8.2.16).
(defun grant-subset (local-peer child-peer parent-peer child parent)
  (and (scope-subset local-peer local-peer (grant-rec-handlers child) (grant-rec-handlers parent) :path)
       (scope-subset local-peer local-peer (grant-rec-operations child) (grant-rec-operations parent) :id)
       (scope-subset child-peer parent-peer (grant-rec-resources child) (grant-rec-resources parent) :path)
       (let ((cp (or (grant-rec-peers child) (make-scope (list local-peer) nil)))
             (pp (or (grant-rec-peers parent) (make-scope (list local-peer) nil))))
         (scope-subset local-peer local-peer cp pp :id))))

(defun is-attenuated (local-peer child-peer parent-peer child parent)
  (let ((cg (grants-of-token child)) (pg (grants-of-token parent)))
    (and (every (lambda (c) (some (lambda (p) (grant-subset local-peer child-peer parent-peer c p)) pg)) cg)
         (let ((pe (entity-uint parent "expires_at"))
               (ce (entity-uint child "expires_at")))
           (cond ((and pe (null ce)) nil)       ; child infinite, parent finite
                 ((and pe ce) (<= ce pe))
                 (t t))))))

(defun cbor-true-p (v) (eq v :true))

(defun check-delegation-caveats (parent child depth)
  "§5.7 — PARENT's delegation_caveats constrain its direct CHILD. Returns T if the
child is admissible under the parent's caveats (no_delegation / max_delegation_depth
/ max_delegation_ttl), NIL to deny."
  (let ((caveats (entity-field parent "delegation_caveats")))
    (if (not (cbor-map-p caveats)) t
        (let ((no-deleg (cbor-true-p (map-field caveats "no_delegation"))))
          (if no-deleg nil
              (let ((depth-ok
                      (let ((m (map-field caveats "max_delegation_depth")))
                        (if (integerp m) (< depth m) t)))
                    (ttl-ok
                      (let ((maxttl (map-field caveats "max_delegation_ttl")))
                        (if (integerp maxttl)
                            (let ((ex (entity-uint child "expires_at"))
                                  (cr (entity-uint child "created_at")))
                              (cond ((and ex cr) (<= (- ex cr) maxttl))
                                    (ex t)            ; created_at absent — can't bound, admit
                                    (t nil)))         ; infinite child lifetime exceeds any limit
                            t))))
                (and depth-ok ttl-ok)))))))

(defun link-granter-peer (resolve-fn local-peer cap)
  "§5.5a per-link canonicalization frame for CAP's resource patterns = its granter's
peer_id. Multi-sig root (no granter hash) → LOCAL-PEER. Single-sig: derive peer_id
from the resolved granter's public_key. PREFERRED HARD-FAIL: an unresolvable granter
identity, or a resolved entity yielding no public_key, returns NIL → the caller
DENIES the chain walk (never a silent fallback to the local frame)."
  (let ((gh (entity-bytes cap "granter")))
    (if (null gh) local-peer            ; multi-sig root (M3) → local frame
        (let ((g (funcall resolve-fn gh)))
          (when g
            (let ((pk (entity-bytes g "public_key")))
              (when pk (peer-id-of-pubkey pk))))))))

(defun collect-chain (cap resolve-fn)
  "Walk to root via parent hashes. Returns (values chain ok)."
  (let ((acc '()) (current cap) (depth 0))
    (loop
      (when (> depth 64) (return (values nil nil)))
      (push current acc)
      (let ((ph (entity-bytes current "parent")))
        (if (null ph)
            (return (values (nreverse acc) t))
            (let ((parent (funcall resolve-fn ph)))
              (if parent (setf current parent depth (1+ depth))
                  (return (values nil nil)))))))))

(defun chain-exceeds-depth-p (store capability included)
  "§4.10(b) structural-bound pre-check: true if the authority chain rooted at
CAPABILITY exceeds the max depth (64). Walks parent pointers without verifying
signatures — depth is a purely structural property, gated BEFORE the per-link
authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
(structural excess), distinct from a 403 capability_denied authz failure (arch
ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
returns NIL here and is left for VERIFY-CAPABILITY-CHAIN to deny (403)."
  (let ((resolve-fn (lambda (h) (cap-resolve included store h)))
        (current capability) (depth 0))
    (loop
      (when (> depth 64) (return t))
      (let ((ph (entity-bytes current "parent")))
        (if (null ph)
            (return nil)                ; root reached within bound
            (let ((parent (funcall resolve-fn ph)))
              (if parent (setf current parent depth (1+ depth))
                  (return nil))))))))   ; unreachable — not a depth problem

;; ── §3.6 M3 multi-signature granter ──────────────────────────────────────────
;;
;; The capability `granter` field is a union (§3.6): a single system/hash
;; (single-sig, byte string) or a {signers: [system/hash], threshold: uint}
;; descriptor (multi-sig, ROOT-ONLY). A multi-sig root is verified by
;; VERIFY-MULTISIG-ROOT — M3 structure first, then §5.5 M6 root-at-local + M4
;; k-of-n quorum.

(defstruct (multi-granter (:constructor make-multi-granter (signers threshold)))
  signers threshold)

(defun multi-granter-of-entity (cap)
  "Parse CAP's granter field as a §3.6 multi-granter descriptor, or NIL if it is a
single-sig granter (a byte string) / absent. SIGNERS is a list of hash octet-vectors;
THRESHOLD is the parsed uint (0 if absent — a structurally-invalid quorum that M3
will deny)."
  (let ((g (entity-field cap "granter")))
    (when (cbor-map-p g)
      (let ((signers (let ((xs (map-field g "signers")))
                       (when (listp xs)
                         (loop for x in xs when (bytes-p x) collect (bytes-octets x)))))
            (threshold (let ((tv (map-field g "threshold")))
                         (if (integerp tv) tv 0))))
        (make-multi-granter signers threshold)))))

(defun is-multisig (cap)
  "T if CAP's granter is a §3.6 multi-granter descriptor (map, not a byte string)."
  (cbor-map-p (entity-field cap "granter")))

(defun has-duplicate-signers-p (signers)
  "T if SIGNERS (a list of octet-vectors) contains a duplicate."
  (loop for (s . rest) on signers
        thereis (member s rest :test #'octets-equal)))

(defun find-signatures-targeting (target included)
  "All system/signature entities in INCLUDED (alist) whose target == TARGET octets."
  (loop for (nil . e) in included
        when (and (string= (entity-typ e) "system/signature")
                  (let ((tg (entity-bytes e "target")))
                    (and tg (octets-equal tg target))))
          collect e))

(defun verify-multisig-root (local-peer resolve-fn cap mg included)
  "§3.6 M3 / §5.5 M4·M6. Returns T (ALLOW) only if the quorum is well-formed AND a
threshold of DISTINCT signers signed CAP's content hash. Structural validation (M3)
precedes signature counting (§3.6 precedence 25): a malformed quorum is denied on its
structure, not on its signatures. Every path returns a boolean → the dispatcher maps
NIL to 403 capability_denied; never errors or hangs."
  (let* ((signers (multi-granter-signers mg))
         (threshold (multi-granter-threshold mg))
         (n (length signers)))
    (flet ((peer-id-of (h)
             (let ((p (funcall resolve-fn h)))
               (when p
                 (let ((pk (entity-bytes p "public_key")))
                   (when pk (peer-id-of-pubkey pk)))))))
      (and
       ;; §3.6 M3 structure — root-only; real quorum (n ≥ 2); usable threshold
       ;; (2 ≤ threshold ≤ n); distinct signers.
       (null (entity-bytes cap "parent"))
       (>= n 2)
       (>= threshold 2)
       (<= threshold n)
       (not (has-duplicate-signers-p signers))
       ;; §5.5 M6 root-at-local — the local peer MUST be a quorum member.
       (some (lambda (s) (let ((pid (peer-id-of s))) (and pid (string= pid local-peer))))
             signers)
       ;; §6.2 CAP-6a (INGEST) — BEFORE the range checks below, which the
       ;; absent-vs-unrepresentable ambiguity is exactly what defeats.
       (temporal-fields-representable-p cap)
       ;; temporal validity + grantee resolution (as for any root).
       (let ((tnow (now-ms)))
         (and (let ((nb (entity-uint cap "not_before"))) (or (null nb) (>= tnow nb)))
              (let ((ex (entity-uint cap "expires_at"))) (or (null ex) (>= ex tnow)))))
       (let ((gh (entity-bytes cap "grantee")))
         (and gh (funcall resolve-fn gh) t))
       ;; §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over CAP's
       ;; content hash; ≥ threshold ⇒ quorum. A duplicate signature from the same
       ;; signer does NOT inflate the count (we count distinct signer hashes).
       (let ((sigs (find-signatures-targeting (entity-hash cap) included))
             (valid '()))
         (dolist (s signers)
           (unless (member s valid :test #'octets-equal)
             (let ((signer-peer (funcall resolve-fn s)))
               (when (and signer-peer
                          (some (lambda (sgn)
                                  (let ((sg (entity-bytes sgn "signer")))
                                    (and sg (octets-equal sg s)
                                         (verify-signature sgn signer-peer))))
                                sigs))
                 (push s valid)))))
         (>= (length valid) threshold))))))

(defun verify-capability-chain (local-peer store capability included)
  "§5.5. A single-sig root must root at the LOCAL peer; a §3.6 M3 multi-sig root
(root-only) must pass k-of-n quorum via VERIFY-MULTISIG-ROOT. A multi-sig token
anywhere but the chain root is rejected. Returns :allow / :deny; signals
UNRESOLVABLE-GRANTEE for the §5.5 401 carve-out."
  (let ((resolve-fn (lambda (h) (cap-resolve included store h))))
    (multiple-value-bind (chain ok) (collect-chain capability resolve-fn)
      (if (not ok) :deny
          (let* ((root (car (last chain)))
                 (root-ok
                   (let ((mg (multi-granter-of-entity root)))
                     (if mg
                         ;; §3.6 M3 multi-sig root — k-of-n quorum (structure + sigs
                         ;; + temporal + grantee all handled here).
                         (verify-multisig-root local-peer resolve-fn root mg included)
                         ;; single-sig root: granter identity's peer_id == local peer.
                         (let ((gh (entity-bytes root "granter")))
                           (and gh
                                (let ((g (funcall resolve-fn gh)))
                                  (and g
                                       (let ((pk (entity-bytes g "public_key")))
                                         (and pk (string= (peer-id-of-pubkey pk) local-peer)))))))))))
            (if (not root-ok) :deny
                (let ((good t) (n (length chain)))
                  (loop for i from 0 for current in chain while good do
                    (if (is-multisig current)
                        ;; §3.6 M3 multi-sig is ROOT-ONLY and is fully verified above
                        ;; (structure, quorum signatures, temporal, grantee). A
                        ;; multi-sig token anywhere but the chain root is rejected;
                        ;; at the root the single-sig per-link checks are skipped.
                        (when (< i (1- n)) (setf good nil))
                        (progn
                    ;; signature: signer == granter, verify against granter identity
                    (let ((gh (entity-bytes current "granter")))
                      (if gh
                          (let ((sgn (find-signature (entity-hash current) included))
                                (granter (funcall resolve-fn gh)))
                            (if (and sgn granter)
                                (let ((signer (entity-bytes sgn "signer")))
                                  (unless (and signer (octets-equal signer gh)
                                               (verify-signature sgn granter))
                                    (setf good nil)))
                                (setf good nil)))
                          (setf good nil)))
                    ;; grantee resolution → 401 carve-out
                    (let ((gh (entity-bytes current "grantee")))
                      (if gh
                          (unless (funcall resolve-fn gh) (error 'unresolvable-grantee))
                          (error 'unresolvable-grantee)))
                    ;; §6.2 CAP-6a (INGEST) — before the range checks, same reason
                    ;; as the root path.
                    (unless (temporal-fields-representable-p current) (setf good nil))
                    ;; temporal validity
                    (let ((tnow (now-ms)))
                      (let ((nb (entity-uint current "not_before")))
                        (when (and nb (< tnow nb)) (setf good nil)))
                      (let ((ex (entity-uint current "expires_at")))
                        (when (and ex (< ex tnow)) (setf good nil))))
                    ;; delegation link: parent.grantee == current.granter,
                    ;; attenuation, and §5.7 delegation caveats (per-link, depth = i).
                    (when (< i (1- n))
                      (let* ((parent (nth (1+ i) chain))
                             ;; §5.5a: resolve each link's granter peer_id as the
                             ;; per-link frame. Hard-fail (deny) on an unresolvable
                             ;; granter rather than fall back to the local frame.
                             (child-peer (link-granter-peer resolve-fn local-peer current))
                             (parent-peer (link-granter-peer resolve-fn local-peer parent)))
                        (if (or (null child-peer) (null parent-peer))
                            (setf good nil)         ; unresolvable link granter → deny
                            (let ((pg (entity-bytes parent "grantee"))
                                  (cg (entity-bytes current "granter")))
                              (unless (and pg cg (octets-equal pg cg)
                                           (is-attenuated local-peer child-peer parent-peer current parent)
                                           (check-delegation-caveats parent current i))
                                (setf good nil))))))))) ; close progn + (if is-multisig)
                  (if good :allow :deny))))))))

(defun is-revoked (local-peer store capability included)
  (let* ((resolve-fn (lambda (h) (cap-resolve included store h)))
         (root-hash (multiple-value-bind (chain ok) (collect-chain capability resolve-fn)
                      (if ok (entity-hash (car (last chain))) (entity-hash capability)))))
    (flet ((check (h)
             (store-get-at store (concatenate 'string "/" local-peer
                                              "/system/capability/revocations/" (hex h)))))
      (or (check (entity-hash capability)) (check root-hash)))))

;; ── §5.2 verify-request (3-way verdict: :allow / :authn-fail / :authz-deny) ─────

(defun verify-request (local-peer store env)
  "Returns :allow, :authn-fail (→401), or :authz-deny (→403). Signals
UNRESOLVABLE-GRANTEE (→401) through chain verification."
  (let* ((exec (envelope-root env))
         (included (envelope-included env)))
    (let ((sgn (find-signature (entity-hash exec) included)))
      (if (null sgn) :authn-fail
          (let ((author-h (entity-bytes exec "author")))
            (let ((signer (entity-bytes sgn "signer")))
              (if (not (and signer author-h (octets-equal signer author-h)))
                  :authn-fail
                  (let ((author (and author-h (included-get env author-h))))
                    (if (null author) :authn-fail
                        (if (not (verify-signature sgn author)) :authn-fail
                            (let ((cap (let ((ch (entity-bytes exec "capability")))
                                         (and ch (included-get env ch)))))
                              (if (null cap) :authz-deny
                                  ;; §4.10(b) resource bound: a chain exceeding max depth is
                                  ;; rejected as 400 chain_depth_exceeded (structural excess)
                                  ;; BEFORE the per-link authz walk — distinct from 403
                                  ;; capability_denied. Arch v7.75 ruling: 400 lets the caller
                                  ;; distinguish "shorten your chain" from "you lack the cap".
                                  (if (chain-exceeds-depth-p store cap included) :chain-too-deep
                                  (ecase (verify-capability-chain local-peer store cap included)
                                    (:deny :authz-deny)
                                    (:allow
                                     (let ((grantee (entity-bytes cap "grantee")))
                                       (cond ((not (and grantee author-h (octets-equal grantee author-h)))
                                              :authz-deny)
                                             ((is-revoked local-peer store cap included) :authz-deny)
                                             (t :allow))))))))))))))))))
