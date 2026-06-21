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

    /** Resolve peer-relative paths to absolute /{local}/... form. */
    fun canonicalize(localPeer: String, path: String): String {
        if (startsWith("./", path) || startsWith("../", path)) {
            throw IllegalArgumentException("canonicalize: reserved directory-relative path")
        }
        if (startsWith("*/", path)) {
            throw IllegalArgumentException("canonicalize: ambiguous bare peer wildcard")
        }
        if (startsWith("/", path)) return path
        return "/$localPeer/$path"
    }

    fun matchesPattern(path: String, pattern: String): Boolean {
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

    fun matchesScope(localPeer: String, value: String, s: Scope): Boolean {
        val cv = canonicalize(localPeer, value)
        return covered(localPeer, s.incl, cv) && !covered(localPeer, s.excl, cv)
    }

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
            var ok = matchesScope(localPeer, operation, g.operations) &&
                matchesScope(localPeer, handlerPattern, g.handlers)
            if (ok) {
                val peers = g.peers ?: Scope(listOf(localPeer), emptyList())
                ok = matchesScope(localPeer, targetPeer, peers)
            }
            if (ok && resource != null) {
                ok = checkResourceScope(localPeer, granterPeer, resource, g.resources)
            }
            if (ok) return Verdict.ALLOW
        }
        return Verdict.DENY
    }

    // ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────────

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

    private fun scopeSubset(childPeer: String, parentPeer: String, child: Scope, parent: Scope): Boolean {
        for (cp in child.incl) {
            val cc = canonicalize(childPeer, cp)
            if (parent.incl.none { matchesPattern(cc, canonicalize(parentPeer, it)) }) return false
        }
        for (pe in parent.excl) {
            val cpe = canonicalize(parentPeer, pe)
            if (child.excl.none { matchesPattern(cpe, canonicalize(childPeer, it)) }) return false
        }
        return true
    }

    fun grantSubset(localPeer: String, childPeer: String, parentPeer: String, child: GrantRec, parent: GrantRec): Boolean {
        if (!scopeSubset(localPeer, localPeer, child.handlers, parent.handlers)) return false
        if (!scopeSubset(localPeer, localPeer, child.operations, parent.operations)) return false
        if (!scopeSubset(childPeer, parentPeer, child.resources, parent.resources)) return false
        val cp = child.peers ?: Scope(listOf(localPeer), emptyList())
        val pp = parent.peers ?: Scope(listOf(localPeer), emptyList())
        return scopeSubset(localPeer, localPeer, cp, pp)
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

    fun verifyCapabilityChain(localPeer: String, store: Store, capability: Entity, included: List<Envelope.Included>): Verdict {
        val resolve = { h: ByteArray -> capResolve(included, store, h) }
        val c = collectChain(capability, resolve)
        if (!c.ok) return Verdict.DENY
        val chain = c.chain!!
        val root = chain.last()
        // Root authority: a single-sig root must root at the local peer; a §3.6 M3
        // multi-sig root (root-only) must pass k-of-n quorum validation.
        val rootMg = multiGranterOf(root)
        val rootOk = if (rootMg != null) {
            verifyMultiSigRoot(localPeer, resolve, root, rootMg, included)
        } else {
            val rgh = root.bytes("granter")
            val g = rgh?.let { resolve(it) }
            val pk = g?.bytes("public_key")
            pk != null && Identity.peerIdOfPublicKey(pk) == localPeer
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
}
