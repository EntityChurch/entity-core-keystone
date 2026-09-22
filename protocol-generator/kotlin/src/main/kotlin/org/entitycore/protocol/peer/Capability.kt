package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue
import java.math.BigInteger

/**
 * Capability system (L3): the §5 verification core — pattern matching (§5.4), request
 * verification (§5.2 [verifyRequest] / [checkPermission]), delegation-chain verification
 * (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1), and genuine §3.6 M3
 * multi-signature K-of-N ([verifyMultiSigRoot]).
 *
 * Derived from the §5 pseudocode directly. The verdict is a Kotlin `enum class`
 * ([Verdict] ALLOW/DENY — §5.10 Layer-1 determinism) matched exhaustively by `when` at
 * the dispatch site; the dispatcher maps DENY → 403, with the §5.5 unresolvable-grantee
 * → 401 carve-out carried as [UnresolvableGrantee]. The three-way request verdict
 * ([RequestVerdict]) folds in the §4.10(b) `CHAIN_TOO_DEEP` (→ 400) structural case.
 *
 * The §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension's patterns
 * canonicalize against the GRANTER's peer_id; handlers/operations/peers stay on the
 * local frame. For the self-issued dominant path (granter = local) this is
 * byte-identical to the pre-fix behavior; only the foreign-granter cross-peer case
 * flips (exercised at S4 against the oracle).
 */
internal object Capability {

    /** §5.10 Layer-1 verdict. */
    enum class Verdict { ALLOW, DENY }

    /** §5.2 three-way request verdict (+ §4.10(b) structural chain-depth case). */
    enum class RequestVerdict { ALLOW, AUTHN_FAIL, AUTHZ_DENY, CHAIN_TOO_DEEP }

    /** §5.5 carve-out: a grantee that cannot be resolved → 401, not 403. */
    class UnresolvableGrantee : RuntimeException("unresolvable grantee")

    // ── grant / scope parse ──────────────────────────────────────────────────────

    data class Scope(val incl: List<String>, val excl: List<String>)

    data class GrantRec(
        val handlers: Scope,
        val resources: Scope,
        val operations: Scope,
        val peers: Scope?,
    )

    fun parseScope(m: EcfValue.MapVal?): Scope {
        if (m == null) return Scope(emptyList(), emptyList())
        return Scope(Cbor.textList(m, "include") ?: emptyList(), Cbor.textList(m, "exclude") ?: emptyList())
    }

    fun parseGrant(m: EcfValue.MapVal?): GrantRec {
        val peers = if (m?.get("peers") != null) parseScope(Cbor.asMap(m["peers"])) else null
        return GrantRec(
            parseScope(Cbor.asMap(m?.get("handlers"))),
            parseScope(Cbor.asMap(m?.get("resources"))),
            parseScope(Cbor.asMap(m?.get("operations"))),
            peers,
        )
    }

    fun grantsOfToken(token: Entity): List<GrantRec> =
        (Cbor.mapList(token.data(), "grants") ?: emptyList()).map { parseGrant(it) }

    // ── §5.4 pattern matching ─────────────────────────────────────────────────────

    fun startsWith(prefix: String, s: String): Boolean = s.length >= prefix.length && s.startsWith(prefix)

    fun normalizeUri(uri: String): String =
        if (startsWith("entity://", uri)) "/" + uri.substring(9) else uri

    /**
     * The unmatchable value (0.8.2.20). Unreachable as a canonical path by CONSTRUCTION:
     * its first segment cannot be a peer_id, since [isPeerId] requires >= 46 Base58
     * characters and `-` is outside the Base58 alphabet.
     */
    const val NEVER_MATCH = "/never-match"

    /**
     * Resolve peer-relative paths to absolute /{local}/... form.
     *
     * TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". This used
     * to THROW, and the throw was reachable from the wire — every normative call site is a
     * matcher with no error channel to consume one, so the exception escaped the matcher,
     * the resilience frame caught it, and `../x` in a resource exclude answered 500
     * (measured 2026-09-14). The diagnostic belongs at admission (§6.5), which has a
     * caller to answer.
     */
    fun canonicalize(localPeer: String, path: String): String {
        if (startsWith("./", path) || startsWith("../", path)) return NEVER_MATCH
        if (startsWith("*/", path)) return NEVER_MATCH
        if (startsWith("/", path)) return path
        return "/$localPeer/$path"
    }

    fun matchesPattern(path: String, pattern: String): Boolean {
        // NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
        // rule rather than a property of the string: the arm below returns true for a
        // bare "*", so safety must not rest on a value merely looking unmatchable.
        if (path == NEVER_MATCH || pattern == NEVER_MATCH) return false
        if (pattern == "*") return true
        if (startsWith("/*/", pattern)) {
            val remainder = pattern.substring(3)
            if (path.isEmpty()) return false
            val i = path.indexOf('/', 1)
            return i >= 0 && matchesPattern(path.substring(i + 1), remainder)
        }
        if (pattern.length >= 2 && pattern.endsWith("/*")) {
            return startsWith(pattern.substring(0, pattern.length - 1), path)
        }
        return path == pattern
    }

    /**
     * Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
     * call site — no default — so a new one cannot inherit the wrong matcher silently,
     * which is exactly the F40 defect.
     */
    enum class ScopeKind { ID, PATH }

    /**
     * §5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal comparison
     * with exactly two wildcard forms: bare `*` and a trailing slash-star segment-prefix.
     * None of the §5.4 path transforms apply, so a pattern carrying path syntax is
     * matched as a literal string: a non-match, never a fault.
     */
    fun matchesIdPattern(value: String, pattern: String): Boolean {
        if (pattern == "*") return true
        if (pattern.length >= 2 && pattern.endsWith("/*")) {
            return value.startsWith(pattern.substring(0, pattern.length - 1))
        }
        return value == pattern
    }

    /**
     * AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
     * in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
     * exclude (carves out nothing -> the grant is SILENTLY WIDER than its author wrote):
     * same value, same matcher, opposite safety direction, so the reading is chosen where
     * the POSITION is known and [matchesPattern] stays uniform over its operands. The
     * guard is SCOPED TO PATH-SCOPE by its caller (0.8.2.24 N2/N3); see [matchesScope].
     */
    private fun excludeIsUnmatchable(frame: String, excl: List<String>): Boolean =
        excl.any { canonicalize(frame, it) == NEVER_MATCH }

    fun matchesScope(localPeer: String, value: String, s: Scope, kind: ScopeKind): Boolean {
        // SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). §5.2's exclude loop tests the sentinel
        // INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4's rule is
        // likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID …
        // It does NOT reach `operations` or `peers` [MUST]".
        //
        // This guard used to sit OUTSIDE the type dispatch, transcribing §5.2's loop
        // before that loop grew its type test — which ran an id pattern through the §5.4
        // transforms purely to classify it and then DENIED THE WHOLE DIMENSION on a
        // property unrelated to whether the exclude carves anything out: an `operations`
        // exclude of `*/apply`, an ordinary namespaced operation name, path-canonicalizes
        // to the sentinel and denied every operation. Over-denial, invisible on any
        // well-formed grant.
        //
        // The id arm below reaches the literal matcher unguarded, which is correct: under
        // the id-scope grammar every non-`*` pattern is a literal, and a literal is never
        // structurally unmatchable, so there is nothing here for the sentinel to detect.
        if (kind == ScopeKind.PATH && excludeIsUnmatchable(localPeer, s.excl)) return false
        if (kind == ScopeKind.ID) {
            return coveredId(s.incl, value) && !coveredId(s.excl, value)
        }
        val cv = canonicalize(localPeer, value)
        return covered(localPeer, s.incl, cv) && !covered(localPeer, s.excl, cv)
    }

    private fun coveredId(pats: List<String>, value: String): Boolean =
        pats.any { matchesIdPattern(value, it) }

    private fun covered(frame: String, pats: List<String>, cv: String): Boolean =
        pats.any { matchesPattern(cv, canonicalize(frame, it)) }

    // ── §5.2 check-permission ──────────────────────────────────────────────────────

    fun firstSegment(uri: String): String {
        val u = if (startsWith("/", uri)) uri.substring(1) else uri
        val i = u.indexOf('/')
        return if (i >= 0) u.substring(0, i) else u
    }

    private const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    fun isPeerId(seg: String): Boolean =
        seg.length >= 46 && seg.all { BASE58_ALPHABET.indexOf(it) >= 0 }

    fun extractPeer(localPeer: String, uri: String): String {
        val first = firstSegment(normalizeUri(uri))
        return if (isPeerId(first)) first else localPeer
    }

    /**
     * Concrete-target subset (the core surface the oracle exercises). The grant's own
     * resource patterns canonicalize against the GRANTER's peer_id (§PR-8 / V2(a)); the
     * caller-supplied targets/exclude stay on the LOCAL frame (§5.4).
     */
    fun checkResourceScope(localPeer: String, granterPeer: String, resource: EcfValue.MapVal, s: Scope): Boolean {
        val targets = Cbor.textList(resource, "targets")
        val callerExcl = Cbor.textList(resource, "exclude")
        if (targets.isNullOrEmpty()) return false
        // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
        // target: the coverage test below is correct in isolation and is simply never
        // reached on a sentinel, because matchesPattern answers false.
        if (excludeIsUnmatchable(granterPeer, s.excl)) return false
        for (tgt in targets) {
            val ct = canonicalize(localPeer, tgt)
            if (callerExcl != null && coveredFrame(localPeer, callerExcl, ct)) continue // caller excluded → ok
            if (!coveredFrame(granterPeer, s.incl, ct)) return false
            if (coveredFrame(granterPeer, s.excl, ct)) return false
        }
        return true
    }

    private fun coveredFrame(frame: String, pats: List<String>, v: String): Boolean =
        pats.any { matchesPattern(v, canonicalize(frame, it)) }

    /** §PR-8 — the frame for canonicalizing CAP's grant resource patterns is the
     *  GRANTER's peer_id. Single-sig granter → derive peer_id from its public_key;
     *  unresolvable → null (caller falls back to local). */
    fun resolveGranterPeerId(resolve: (ByteArray) -> Entity?, cap: Entity): String? {
        val gh = cap.bytes("granter") ?: return null
        val g = resolve(gh) ?: return null
        val pk = g.bytes("public_key") ?: return null
        return Identity.peerIdOfPublicKey(pk)
    }

    /**
     * Gate the wire request at the dispatch authorization boundary (§3.2.3 / v7.73).
     * [granterPeer] is the §PR-8 canonicalization frame for the cap's grant resource
     * patterns; every other dimension stays on the local frame.
     */
    fun checkPermission(
        localPeer: String,
        granterPeer: String,
        exec: Entity,
        token: Entity,
        handlerPattern: String,
    ): Verdict {
        val operation = exec.text("operation") ?: ""
        val uri = exec.text("uri") ?: ""
        val targetPeer = extractPeer(localPeer, uri)
        val resource = exec.mapField("resource")
        for (g in grantsOfToken(token)) {
            var ok = matchesScope(localPeer, operation, g.operations, ScopeKind.ID) &&
                matchesScope(localPeer, handlerPattern, g.handlers, ScopeKind.PATH)
            if (ok) {
                val peers = g.peers ?: Scope(listOf(localPeer), emptyList())
                ok = matchesScope(localPeer, targetPeer, peers, ScopeKind.ID)
            }
            if (ok && resource != null) {
                ok = checkResourceScope(localPeer, granterPeer, resource, g.resources)
            }
            if (ok) return Verdict.ALLOW
        }
        return Verdict.DENY
    }

    // ── §5.2 effective targets and §6.3 check_path_permission ───────────────────────

    /**
     * The result of [effectiveTargets]: the surviving targets and whether the EXECUTE
     * carried a `resource` AT ALL.
     *
     * THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES `[MUST]` (0.8.2.25, N11):
     * *"where an implementation projects `resource.targets` onto the effective set ahead
     * of the handler, that projection MUST NOT be lossy about its own emptiness — narrow
     * when narrowing leaves something, and retain the raw pair when narrowing would empty
     * it."* A function returning only a list cannot satisfy that: collapsing
     * `[qA] exclude [qA]` to `[]` deletes the two-empties discriminator before any handler
     * can read it, and the handler's refusal arm becomes dead code that only a WIRE drive
     * can detect.
     */
    data class EffectiveTargets(val survivors: List<String>, val hasResource: Boolean)

    /**
     * §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
     * entries from `resource.targets` BEFORE anything else looks at the request.
     *
     * The survivors are returned in the caller's OWN SPELLING, not canonicalized —
     * 0.8.2.21 is explicit that `effective_targets` yields raw survivors, and the
     * distinction is load-bearing because the value flows on to `store.getAt`, which
     * canonicalizes for itself.
     *
     * A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
     * Reporting it absent would serve the WIDER absent-case answer to a request that named
     * a resource, which is N11's own defect one field over.
     *
     * The caller-exclude arm is fail-OPEN on an unmatchable pattern — §5.4 rules it
     * separately from the grant arm — and that is INHERITED here rather than restated: the
     * pattern canonicalizes to [NEVER_MATCH], [matchesPattern] then answers false, and the
     * target simply survives.
     *
     * *"Every seam that narrows is exempted alike."* This peer has exactly ONE narrowing
     * seam — this function, called by the tree handler — and §6.5's dispatch chain does not
     * project: `dispatchInner` passes the EXECUTE through untouched and [checkPermission]
     * reads `resource` for itself. There is no second door to keep in step, and adding a
     * projection at dispatch would create one.
     */
    fun effectiveTargets(localPeer: String, exec: Entity): EffectiveTargets {
        val r = exec.mapField("resource")
        if (r == null || r.get("targets") == null) return EffectiveTargets(emptyList(), false)
        val targets = Cbor.textList(r, "targets") ?: emptyList()
        val callerExcl = Cbor.textList(r, "exclude") ?: emptyList()
        val survivors = targets.filter { t ->
            val ct = canonicalize(localPeer, t)
            callerExcl.none { matchesPattern(ct, canonicalize(localPeer, it)) }
        }
        return EffectiveTargets(survivors, true)
    }

    /**
     * §6.3's handler-level path check.
     *
     * IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
     * subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
     * by caller-controlled input: a caller who excludes the one target its capability does
     * not cover removes that target from [checkPermission]'s view entirely, and a handler
     * that then acts on it has authorized nothing.
     *
     * THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
     * construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
     * step 3, before any handler runs), and §6.3's signature names only handlers,
     * operations and resources.
     *
     * THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
     * rather than a choice: §6.3's block reads
     * `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` — there
     * is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject
     * is a pattern compared against a parent's pattern; this call site compares a CONCRETE
     * local path the handler is about to touch.
     *
     * Canonicalization is total (0.8.2.20), so a malformed path answers the sentinel, which
     * matches no grant (§5.4) and falls through to DENY rather than being matched against
     * anything.
     *
     * An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
     * tree paths) and DENIES every path here, which is what that note says it should.
     */
    fun checkPathPermission(
        localPeer: String,
        operation: String,
        path: String,
        token: Entity,
        handlerPattern: String,
    ): Boolean {
        val cp = canonicalize(localPeer, path)
        return grantsOfToken(token).any { g ->
            matchesScope(localPeer, handlerPattern, g.handlers, ScopeKind.PATH) &&
                matchesScope(localPeer, operation, g.operations, ScopeKind.ID) &&
                matchesScope(localPeer, cp, g.resources, ScopeKind.PATH)
        }
    }

    // ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────────

    /** Inclusive maximum of `primitive/uint` — the representability bound. */
    private val UINT64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

    /**
     * §6.2 CAP-6a (INGEST): every temporal field on a RECEIVED token must be either
     * ABSENT (legal — "no bound") or representable as `primitive/uint`. A bignum, a
     * negative integer, or any non-integer is **malformed**, and the verifier MUST refuse
     * it rather than read the unrepresentable field as absent — absent means *no expiry*,
     * so the fail-open reading grants an immortal capability.
     *
     * The mechanism here is arithmetic rather than a null: `Cbor.uint` returns the
     * `BigInteger` of ANY `IntVal`, including a negative one, so the range checks did not
     * skip — they ran and returned the wrong answer. For a negative `not_before`,
     * `now < not_before` is false, so the cap passed.
     *
     * MUST run BEFORE the range checks it protects.
     */
    fun temporalFieldsRepresentable(cap: Entity): Boolean {
        for (key in listOf("expires_at", "not_before", "created_at")) {
            val v = cap.field(key) ?: continue          // absent is legal — no bound
            if (v is EcfValue.Null) continue
            val i = (v as? EcfValue.IntVal) ?: return false
            if (i.value.signum() < 0 || i.value > UINT64_MAX) return false
        }
        return true
    }

    fun nowMs(): Long = System.currentTimeMillis()

    fun findSignature(target: ByteArray, included: List<Envelope.Included>): Entity? =
        included.map { it.entity }.firstOrNull { e ->
            e.type == "system/signature" && Identity.octetsEqual(e.bytes("target"), target)
        }

    // ── §3.6 M3 multi-signature granter ──────────────────────────────────────────
    // The capability `granter` field is a union (§3.6): a single system/hash (bytes,
    // single-sig) OR a {signers: [system/hash], threshold: uint} map (multi-sig,
    // ROOT-ONLY). A multi-sig root is verified by [verifyMultiSigRoot] — §3.6 M3
    // structure first, then §5.5 M6 root-at-local + M4 k-of-n quorum.

    /** A parsed multi-sig granter descriptor: the signer identity hashes + the k threshold. */
    data class MultiGranter(val signers: List<ByteArray>, val threshold: BigInteger)

    /**
     * Parse the `granter` union as a multi-sig descriptor, or null if it is a single
     * `system/hash` (bytes) or absent. Detection: granter is a CBOR map (not bytes).
     */
    fun multiGranterOf(cap: Entity): MultiGranter? {
        val m = cap.field("granter") as? EcfValue.MapVal ?: return null
        val signers = ((m["signers"] as? EcfValue.Arr)?.items ?: emptyList())
            .mapNotNull { (it as? EcfValue.Bytes)?.octets() }
        val threshold = Cbor.uint(m, "threshold") ?: BigInteger.ZERO
        return MultiGranter(signers, threshold)
    }

    fun isMultiSig(cap: Entity): Boolean = cap.field("granter") is EcfValue.MapVal

    private fun hasDuplicateSigners(signers: List<ByteArray>): Boolean {
        for (i in signers.indices) {
            for (j in i + 1 until signers.size) {
                if (Identity.octetsEqual(signers[i], signers[j])) return true
            }
        }
        return false
    }

    private fun signaturesTargeting(target: ByteArray, included: List<Envelope.Included>): List<Entity> =
        included.map { it.entity }.filter { e ->
            e.type == "system/signature" && Identity.octetsEqual(e.bytes("target"), target)
        }

    /**
     * Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4·M6). Returns true
     * (ALLOW) only if the quorum is well-formed AND a threshold of DISTINCT signers
     * signed the cap's content hash. Structural validation (M3) precedes signature
     * counting (§3.6 precedence 25): a malformed quorum is denied on its structure, not
     * on missing/invalid sigs. Every failure path returns false → the dispatcher maps it
     * to 403 capability_denied (never a throw, never a hang).
     */
    private fun verifyMultiSigRoot(
        localPeer: String,
        resolve: (ByteArray) -> Entity?,
        cap: Entity,
        mg: MultiGranter,
        included: List<Envelope.Included>,
    ): Boolean {
        val n = mg.signers.size
        // §3.6 M3 structure — root-only (parent null); a real quorum (n ≥ 2); a usable
        // threshold (2 ≤ threshold ≤ n); distinct signers. BEFORE any signature work
        // (precedence 25).
        if (cap.bytes("parent") != null) return false
        if (n < 2) return false
        if (mg.threshold < BigInteger.TWO || mg.threshold > BigInteger.valueOf(n.toLong())) return false
        if (hasDuplicateSigners(mg.signers)) return false

        // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
        val localInSigners = mg.signers.any { peerIdOfSigner(resolve, it) == localPeer }
        if (!localInSigners) return false

        // §6.2 CAP-6a (INGEST) — MUST run BEFORE the range checks below, because the
        // range checks are exactly what the unrepresentable value defeats.
        if (!temporalFieldsRepresentable(cap)) return false

        // Temporal validity + grantee resolution (as for any root).
        val now = nowMs()
        val nb = cap.uint("not_before")
        if (nb != null && BigInteger.valueOf(now) < nb) return false
        val ex = cap.uint("expires_at")
        if (ex != null && ex < BigInteger.valueOf(now)) return false
        val grantee = cap.bytes("grantee")
        if (grantee == null || resolve(grantee) == null) return false

        // §5.5 M4 k-of-n: at least `threshold` DISTINCT quorum members produced a valid
        // signature over the cap's content hash. A duplicate signature from one signer
        // does NOT inflate the count (we count distinct signer hashes).
        val sigs = signaturesTargeting(cap.rawHash(), included)
        val validSigners = ArrayList<ByteArray>()
        for (signerHash in mg.signers) {
            if (validSigners.any { Identity.octetsEqual(it, signerHash) }) continue
            val signerPeer = resolve(signerHash) ?: continue
            val hasValid = sigs.any { sgn ->
                Identity.octetsEqual(sgn.bytes("signer"), signerHash) &&
                    Identity.verifySignature(sgn, signerPeer)
            }
            if (hasValid) validSigners.add(signerHash)
        }
        return BigInteger.valueOf(validSigners.size.toLong()) >= mg.threshold
    }

    private fun peerIdOfSigner(resolve: (ByteArray) -> Entity?, signerHash: ByteArray): String? {
        val p = resolve(signerHash) ?: return null
        val pk = p.bytes("public_key") ?: return null
        return Identity.peerIdOfPublicKey(pk)
    }

    fun capResolve(included: List<Envelope.Included>, store: Store, h: ByteArray): Entity? =
        includedGet(included, h) ?: store.getByHash(h)

    fun includedGet(included: List<Envelope.Included>, h: ByteArray): Entity? =
        included.firstOrNull { Identity.octetsEqual(it.hash, h) }?.entity

    /** §PR-8 / §5.5a per-link canonicalization frame for CAP's resource patterns = its
     *  granter's peer_id. Multi-sig root (no granter hash) → localPeer. Single-sig:
     *  derive from the resolved granter's public_key; unresolvable → null (caller denies). */
    private fun linkGranterPeer(resolve: (ByteArray) -> Entity?, localPeer: String, cap: Entity): String? {
        val gh = cap.bytes("granter") ?: return localPeer
        val g = resolve(gh) ?: return null
        val pk = g.bytes("public_key") ?: return null
        return Identity.peerIdOfPublicKey(pk)
    }

    /**
     * §5.5a subset check: every child include must be covered by some parent include, and
     * every parent exclude must be inherited by some child exclude.
     *
     * TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
     * §3.6's id-scope grammar binds the scope TYPE, not one function — *"An implementation
     * on the canonicalizing reading is non-conformant and MUST adopt the literal matcher"*
     * — so the rule F40 landed on [matchesScope] reaches here too, with delegation-chain
     * WIDENING named as the reason: on the canonicalizing reading a bare id include reads
     * as covered by a path-form parent pattern it does not literally match, and a child
     * grant comes out wider than its parent. `lean`'s differential put it at 2 of 64
     * include pairs and 2 of 64 exclude pairs, fail-closed, with a 16-pair control alphabet
     * reporting 0 — which is why every hand-tried example missed it.
     *
     * [kind] has NO DEFAULT and is named at every call site, because a default is how the
     * next dimension inherits the wrong matcher silently — the original F40 defect. The
     * per-link granter frames are meaningless on the id arm (an id pattern is never
     * canonicalized) and are simply unread there.
     */
    private fun scopeSubset(
        childPeer: String,
        parentPeer: String,
        child: Scope,
        parent: Scope,
        kind: ScopeKind,
    ): Boolean {
        // An id pattern is never canonicalized; a path pattern always is (§3.6 / §5.4).
        fun frame(peer: String, pattern: String): String =
            if (kind == ScopeKind.PATH) canonicalize(peer, pattern) else pattern
        // The matcher §3.6 binds to the scope TYPE — literal for id, §5.4 for path.
        fun covers(pattern: String, value: String): Boolean =
            if (kind == ScopeKind.PATH) matchesPattern(value, pattern) else matchesIdPattern(value, pattern)

        for (cp in child.incl) {
            val cc = frame(childPeer, cp)
            if (parent.incl.none { covers(frame(parentPeer, it), cc) }) return false
        }
        for (pe in parent.excl) {
            val cpe = frame(parentPeer, pe)
            if (child.excl.none { covers(frame(childPeer, it), cpe) }) return false
        }
        return true
    }

    fun grantSubset(localPeer: String, childPeer: String, parentPeer: String, child: GrantRec, parent: GrantRec): Boolean {
        // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
        // dimensions stay on the local frame. The scope KIND is a property of the
        // DIMENSION and is named at every call site, never defaulted (F50 / 0.8.2.16).
        if (!scopeSubset(localPeer, localPeer, child.handlers, parent.handlers, ScopeKind.PATH)) return false
        if (!scopeSubset(localPeer, localPeer, child.operations, parent.operations, ScopeKind.ID)) return false
        if (!scopeSubset(childPeer, parentPeer, child.resources, parent.resources, ScopeKind.PATH)) return false
        val cp = child.peers ?: Scope(listOf(localPeer), emptyList())
        val pp = parent.peers ?: Scope(listOf(localPeer), emptyList())
        return scopeSubset(localPeer, localPeer, cp, pp, ScopeKind.ID)
    }

    private fun isAttenuated(localPeer: String, childPeer: String, parentPeer: String, child: Entity, parent: Entity): Boolean {
        val cg = grantsOfToken(child)
        val pg = grantsOfToken(parent)
        for (c in cg) {
            if (pg.none { grantSubset(localPeer, childPeer, parentPeer, c, it) }) return false
        }
        val pe = parent.uint("expires_at")
        val ce = child.uint("expires_at")
        if (pe != null && ce == null) return false // child infinite, parent finite
        if (pe != null) return ce!! <= pe
        return true
    }

    private fun checkDelegationCaveats(parent: Entity, child: Entity, depth: Int): Boolean {
        val caveats = parent.mapField("delegation_caveats") ?: return true
        if (Cbor.isTrue(caveats["no_delegation"])) return false
        var depthOk = true
        val m = Cbor.uint(caveats, "max_delegation_depth")
        if (m != null) depthOk = BigInteger.valueOf(depth.toLong()) < m
        var ttlOk = true
        val maxTtl = Cbor.uint(caveats, "max_delegation_ttl")
        if (maxTtl != null) {
            val ex = child.uint("expires_at")
            val cr = child.uint("created_at")
            ttlOk = when {
                ex != null && cr != null -> ex.subtract(cr) <= maxTtl
                ex != null -> true             // created_at absent — can't bound, admit
                else -> false                  // infinite child lifetime exceeds any limit
            }
        }
        return depthOk && ttlOk
    }

    private data class Chain(val chain: List<Entity>?, val ok: Boolean)

    private fun collectChain(cap: Entity, resolve: (ByteArray) -> Entity?): Chain {
        val acc = ArrayList<Entity>()
        var current = cap
        var depth = 0
        while (true) {
            if (depth > 64) return Chain(null, false)
            acc.add(current)
            val ph = current.bytes("parent") ?: return Chain(acc, true)
            val parent = resolve(ph) ?: return Chain(null, false)
            current = parent
            depth++
        }
    }

    /**
     * §4.10(b) structural-bound pre-check: true if the authority chain rooted at [capability]
     * exceeds the max depth (64). Walks parent pointers without verifying signatures —
     * depth is a purely structural property, gated BEFORE the per-link authz walk so an
     * over-deep chain is reported as 400 chain_depth_exceeded (structural excess),
     * distinct from a 403 capability_denied authz failure (arch ruling, v7.75 §4.10(b)).
     * An unreachable parent is NOT a depth problem — it returns false here and is left
     * for verifyCapabilityChain to deny (403).
     */
    fun chainExceedsDepth(store: Store, capability: Entity, included: List<Envelope.Included>): Boolean {
        val resolve = { h: ByteArray -> capResolve(included, store, h) }
        var current = capability
        var depth = 0
        while (true) {
            if (depth > 64) return true
            val ph = current.bytes("parent") ?: return false // root reached within bound
            val parent = resolve(ph) ?: return false          // unreachable — not a depth problem
            current = parent
            depth++
        }
    }

    fun verifyCapabilityChain(localPeer: String, store: Store, capability: Entity, included: List<Envelope.Included>): Verdict =
        verifyCapabilityChainRootedAt(localPeer, localPeer, store, capability, included)

    /**
     * [verifyCapabilityChain] with the expected ROOT granter named separately from the
     * verifying peer.
     *
     * §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
     * minted by the TARGET peer, so root-trust is relaxed away from the local peer — and
     * every other clause (per-link signatures, grantee resolution, temporal validity,
     * attenuation, caveats) is unchanged. Parameterized rather than forked because a
     * second copy of a chain walk is a second copy that drifts.
     *
     * A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
     * `rootPeer != localPeer` the quorum arm is REFUSED outright rather than verified:
     * *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
     * GROUP's authority — its co-signers authorized it too. Verifying the quorum here and
     * accepting it would let any one signer's target confer the whole group's grant,
     * which is E3/F66's over-acceptance. §5.5's M6 also requires the LOCAL peer in the
     * signer set, so the quorum arm has no meaning in a foreign frame even on its own
     * terms.
     */
    fun verifyCapabilityChainRootedAt(
        localPeer: String,
        rootPeer: String,
        store: Store,
        capability: Entity,
        included: List<Envelope.Included>,
    ): Verdict {
        val resolve = { h: ByteArray -> capResolve(included, store, h) }
        val c = collectChain(capability, resolve)
        if (!c.ok) return Verdict.DENY
        val chain = c.chain!!
        val root = chain.last()
        // Root authority: a single-sig root must root at `rootPeer`; a §3.6 M3 multi-sig
        // root (root-only) must pass k-of-n quorum validation, and only in the LOCAL frame.
        val rootMg = multiGranterOf(root)
        val rootOk = if (rootMg != null) {
            rootPeer == localPeer && verifyMultiSigRoot(localPeer, resolve, root, rootMg, included)
        } else {
            val rgh = root.bytes("granter")
            val g = rgh?.let { resolve(it) }
            val pk = g?.bytes("public_key")
            pk != null && Identity.peerIdOfPublicKey(pk) == rootPeer
        }
        if (!rootOk) return Verdict.DENY

        var good = true
        val n = chain.size
        var i = 0
        while (i < n && good) {
            val current = chain[i]
            // A §3.6 M3 multi-sig token is root-only and fully verified above. A multi-sig
            // token anywhere but the chain root is rejected; otherwise it is skipped here.
            if (isMultiSig(current)) {
                if (i != n - 1) good = false
                i++
                continue
            }
            // signature: signer == granter, verify against granter identity
            val gh = current.bytes("granter")
            if (gh != null) {
                val sgn = findSignature(current.rawHash(), included)
                val granter = resolve(gh)
                if (sgn != null && granter != null) {
                    val signer = sgn.bytes("signer")
                    if (!(signer != null && Identity.octetsEqual(signer, gh) &&
                            Identity.verifySignature(sgn, granter))) {
                        good = false
                    }
                } else {
                    good = false
                }
            } else {
                good = false
            }
            // grantee resolution → 401 carve-out
            val geh = current.bytes("grantee")
            if (geh != null) {
                if (resolve(geh) == null) throw UnresolvableGrantee()
            } else {
                throw UnresolvableGrantee()
            }
            // §6.2 CAP-6a (INGEST) — before the range checks, same reason as the root path.
            if (!temporalFieldsRepresentable(current)) good = false
            // temporal validity
            val tnow = nowMs()
            val nb = current.uint("not_before")
            if (nb != null && BigInteger.valueOf(tnow) < nb) good = false
            val ex = current.uint("expires_at")
            if (ex != null && ex < BigInteger.valueOf(tnow)) good = false
            // delegation link
            if (i < n - 1) {
                val parent = chain[i + 1]
                val childPeer = linkGranterPeer(resolve, localPeer, current)
                val parentPeer = linkGranterPeer(resolve, localPeer, parent)
                if (childPeer == null || parentPeer == null) {
                    good = false
                } else {
                    val pg = parent.bytes("grantee")
                    val cg = current.bytes("granter")
                    if (!(pg != null && cg != null && Identity.octetsEqual(pg, cg) &&
                            isAttenuated(localPeer, childPeer, parentPeer, current, parent) &&
                            checkDelegationCaveats(parent, current, i))) {
                        good = false
                    }
                }
            }
            i++
        }
        return if (good) Verdict.ALLOW else Verdict.DENY
    }

    fun isRevoked(localPeer: String, store: Store, capability: Entity, included: List<Envelope.Included>): Boolean {
        val resolve = { h: ByteArray -> capResolve(included, store, h) }
        val c = collectChain(capability, resolve)
        val rootHash = if (c.ok) c.chain!!.last().rawHash() else capability.rawHash()
        return revokeMarker(localPeer, store, capability.rawHash()) != null ||
            revokeMarker(localPeer, store, rootHash) != null
    }

    private fun revokeMarker(localPeer: String, store: Store, h: ByteArray): Entity? =
        store.getAt("/$localPeer/system/capability/revocations/${Cbor.hex(h)}")

    // ── §5.2 verify-request (3-way verdict) ─────────────────────────────────────────

    fun verifyRequest(localPeer: String, store: Store, env: Envelope): RequestVerdict {
        val exec = env.root
        val included = env.included
        val sgn = findSignature(exec.rawHash(), included) ?: return RequestVerdict.AUTHN_FAIL
        val authorH = exec.bytes("author")
        val signer = sgn.bytes("signer")
        if (!(signer != null && authorH != null && Identity.octetsEqual(signer, authorH))) {
            return RequestVerdict.AUTHN_FAIL
        }
        val author = includedGet(included, authorH) ?: return RequestVerdict.AUTHN_FAIL
        if (!Identity.verifySignature(sgn, author)) return RequestVerdict.AUTHN_FAIL
        val ch = exec.bytes("capability")
        val cap = ch?.let { includedGet(included, it) } ?: return RequestVerdict.AUTHZ_DENY
        // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
        // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk.
        if (chainExceedsDepth(store, cap, included)) return RequestVerdict.CHAIN_TOO_DEEP
        if (verifyCapabilityChain(localPeer, store, cap, included) == Verdict.DENY) {
            return RequestVerdict.AUTHZ_DENY
        }
        val grantee = cap.bytes("grantee")
        if (!(grantee != null && Identity.octetsEqual(grantee, authorH))) return RequestVerdict.AUTHZ_DENY
        if (isRevoked(localPeer, store, cap, included)) return RequestVerdict.AUTHZ_DENY
        return RequestVerdict.ALLOW
    }

    // ── §1.4 PD-2: outbound sub-dispatch authorization ────────────────────────────

    /**
     * Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
     *
     * §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree`
     * and `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's
     * handler pattern to be the target uri's peer-relative path, because a grant names
     * HANDLERS and a handler pattern never carries a peer segment. Matching a grant
     * against the absolute or schemed form matches nothing, silently, which reads at the
     * wire as an authority refusal.
     *
     * The first segment is dropped ONLY when it is a peer_id. A peer-relative
     * `system/protocol/connect` must not lose `system` — the standing defect on
     * `smalltalk` and `forth`, where an unconditional strip made every self-minted grant
     * unusable while the handshake stayed green.
     */
    fun peerRelativeOf(uri: String): String {
        val p = normalizeUri(uri)
        if (!p.startsWith("/")) return p
        val body = p.substring(1)
        val slash = body.indexOf('/')
        val first = if (slash < 0) body else body.substring(0, slash)
        return if (isPeerId(first)) {
            if (slash < 0) "" else body.substring(slash + 1)
        } else {
            body
        }
    }

    /**
     * Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
     * tolerant of the pattern arriving absolute or peer-relative.
     *
     * §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
     * the grant path is built from the PEER-RELATIVE one. The two are one segment apart
     * and concatenating the wrong one yields a doubled peer segment whose lookup misses —
     * which fails closed as "no handler grant" and is indistinguishable, at the wire, from
     * a genuine authority refusal.
     */
    fun grantPathFor(localPeer: String, pattern: String): String {
        val prefix = "/$localPeer/"
        val rel = if (pattern.startsWith(prefix)) pattern.substring(prefix.length) else pattern
        return "/$localPeer/system/capability/grants/$rel"
    }

    /**
     * Verify a presented reentry credential against §1.4's clauses and, where they all
     * hold, answer the `peers` scope Dimension 4 relaxes to. `null` relaxes nothing.
     *
     * Every clause is required and failing any relaxes nothing: the chain ROOT granter
     * resolves to the TARGET peer and is NOT a multi-signature root (a K-of-N root is a
     * GROUP's authority and never relaxes Dimension 4 — [verifyCapabilityChainRootedAt]
     * refuses the quorum arm in a foreign frame, which is where that rule lands); the LEAF
     * grantee is the local peer; the chain is valid and not revoked.
     */
    fun targetMintedPeersRelaxation(
        localPeer: String,
        targetPeer: String,
        store: Store,
        cred: Entity,
        included: List<Envelope.Included>,
    ): Scope? {
        // Nothing to relax — the default already covers this peer. Treating a
        // self-targeted credential as a relaxation would make the exemption reachable with
        // no foreign mint at all.
        if (targetPeer == localPeer) return null
        if (verifyCapabilityChainRootedAt(localPeer, targetPeer, store, cred, included) != Verdict.ALLOW) return null
        if (isRevoked(localPeer, store, cred, included)) return null
        val gh = cred.bytes("grantee") ?: return null
        val ge = capResolve(included, store, gh) ?: return null
        val pk = ge.bytes("public_key") ?: return null
        if (Identity.peerIdOfPublicKey(pk) != localPeer) return null
        // The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent means
        // the granter — the target peer — which is the ordinary reentry shape: "you may
        // dispatch back to me."
        val g = grantsOfToken(cred).firstOrNull() ?: return null
        return g.peers ?: Scope(listOf(targetPeer), emptyList())
    }

    /**
     * §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
     * LEAVES the peer, with all four dimensions applied.
     *
     * ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
     * decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's
     * pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE
     * TARGET PEER naming this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY
     * DIMENSION 4, to the peers that capability covers.
     *
     * *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT
     * a grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
     * sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
     * BYPASS it is distinguished from is a peer that treats the credential as a standalone
     * authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
     * obvious vectors agree under either reading (sources agree -> allow, no source ->
     * refuse), so the only input that separates them is a VALID credential presented to a
     * handler whose own grant does NOT cover the request, which MUST refuse.
     *
     * A credential failing any verification clause relaxes NOTHING and the handler grant
     * gates unrelaxed — it does not turn the verdict into an error.
     *
     * `targetPeer` is supplied by the caller rather than derived here: on the §6.11 reentry
     * seam the uri may be PEER-RELATIVE and the destination is the connection's remote, so
     * `extractPeer(uri, local)` would answer the LOCAL peer and Dimension 4 would pass
     * vacuously on the default `{include: [local]}` — the exemption would then never be
     * exercised and a bypass would read as a compose.
     *
     * `cred == null` is the ambient arm: Dimension 4 is decided by the handler's grant
     * alone.
     */
    fun checkOutboundSubDispatch(
        localPeer: String,
        targetPeer: String,
        handlerPattern: String,
        operation: String,
        store: Store,
        handlerGrant: Entity,
        resource: EcfValue.MapVal,
        cred: Entity?,
        included: List<Envelope.Included>,
    ): Boolean {
        // Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
        val relaxTo = cred?.let { targetMintedPeersRelaxation(localPeer, targetPeer, store, it, included) }
        for (g in grantsOfToken(handlerGrant)) {
            if (!matchesScope(localPeer, handlerPattern, g.handlers, ScopeKind.PATH)) continue
            if (!matchesScope(localPeer, operation, g.operations, ScopeKind.ID)) continue
            if (!checkResourceScope(localPeer, localPeer, resource, g.resources)) continue
            // Dimension 4. §5.2's default for an absent `peers` scope is
            // {include: [local_peer_id]}, so a foreign target fails unless this grant names
            // it or a target-minted credential relaxes it.
            val peers = g.peers ?: Scope(listOf(localPeer), emptyList())
            if (matchesScope(localPeer, targetPeer, peers, ScopeKind.ID)) return true
            if (relaxTo != null && matchesScope(localPeer, targetPeer, relaxTo, ScopeKind.ID)) return true
        }
        return false
    }
}
