package org.entitycore.protocol.peer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.entitycore.protocol.codec.EcfValue;

/**
 * Capability system (L3): the §5 verification core — pattern matching (§5.4), request
 * verification (§5.2 {@link #verifyRequest} / {@link #checkPermission}), delegation-chain
 * verification (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1).
 *
 * <p>Derived from the §5 pseudocode directly (spec-first). The verdict is a bare
 * {@link Verdict#ALLOW}/{@link Verdict#DENY} (§5.10 Layer-1 determinism); the
 * dispatcher maps DENY → 403, with the §5.5 unresolvable-grantee → 401 carve-out
 * thrown as {@link UnresolvableGrantee}.
 *
 * <p>The §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension's patterns
 * canonicalize against the GRANTER's peer_id; handlers/operations/peers stay on the
 * local frame. For the self-issued dominant path (granter = local) this is
 * byte-identical to the pre-fix behavior; only the foreign-granter cross-peer case
 * flips. The cross-peer V2(a) flip is exercised at S4 against the oracle.
 */
final class Capability {
    private Capability() { }

    enum Verdict { ALLOW, DENY }

    /** §5.2 three-way request verdict. */
    enum RequestVerdict { ALLOW, AUTHN_FAIL, AUTHZ_DENY, CHAIN_TOO_DEEP }

    /** §5.5 carve-out: a grantee that cannot be resolved → 401, not 403. */
    static final class UnresolvableGrantee extends RuntimeException {
        private static final long serialVersionUID = 1L;
        UnresolvableGrantee() {
            super("unresolvable grantee");
        }
    }

    // ── grant / scope parse ──────────────────────────────────────────────────────

    record Scope(List<String> incl, List<String> excl) { }

    record GrantRec(Scope handlers, Scope resources, Scope operations, Scope peers) { }

    static Scope parseScope(EcfValue.Map m) {
        if (m == null) {
            return new Scope(List.of(), List.of());
        }
        List<String> incl = Cbor.textList(m, "include");
        List<String> excl = Cbor.textList(m, "exclude");
        return new Scope(incl != null ? incl : List.of(), excl != null ? excl : List.of());
    }

    static GrantRec parseGrant(EcfValue.Map m) {
        Scope peers = (m != null && m.get("peers") != null) ? parseScope(Cbor.asMap(m.get("peers"))) : null;
        return new GrantRec(
                parseScope(Cbor.asMap(m == null ? null : m.get("handlers"))),
                parseScope(Cbor.asMap(m == null ? null : m.get("resources"))),
                parseScope(Cbor.asMap(m == null ? null : m.get("operations"))),
                peers);
    }

    static List<GrantRec> grantsOfToken(Entity token) {
        List<EcfValue.Map> raw = Cbor.mapList(token.data(), "grants");
        if (raw == null) {
            return List.of();
        }
        List<GrantRec> out = new ArrayList<>(raw.size());
        for (EcfValue.Map g : raw) {
            out.add(parseGrant(g));
        }
        return out;
    }

    // ── §5.4 pattern matching ─────────────────────────────────────────────────────

    static boolean startsWith(String prefix, String s) {
        return s.length() >= prefix.length() && s.startsWith(prefix);
    }

    static String normalizeUri(String uri) {
        return startsWith("entity://", uri) ? "/" + uri.substring(9) : uri;
    }

    /**
     * The unmatchable value (0.8.2.20). A single-segment absolute path whose first
     * segment cannot be a peer_id — {@code isPeerId} requires >= 46 Base58 characters and
     * {@code -} is outside the Base58 alphabet — so it is unreachable as a canonical path
     * by construction rather than by prohibition.
     */
    static final String NEVER_MATCH = "/never-match";

    /**
     * Resolve peer-relative paths to absolute /{local}/... form.
     *
     * TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH", and
     * malformed input yields the sentinel rather than an exception. THIS USED TO THROW,
     * and the throw was reachable from the wire: every normative call site is a matcher
     * with no error channel to consume one, so the exception escaped the matcher, was
     * caught by the peer's resilience frame, and any caller who put {@code ../x} in a
     * resource exclude got a 500 — measured on the wire 2026-09-14, on this peer and
     * twelve others generated from the same shape. The diagnostic belongs at admission
     * (§6.5), which has a caller to answer.
     */
    static String canonicalize(String localPeer, String path) {
        if (startsWith("./", path) || startsWith("../", path)) {
            return NEVER_MATCH;                 // reserved: directory-relative (§1.4)
        }
        if (startsWith("*/", path)) {
            return NEVER_MATCH;                 // ambiguous bare peer wildcard: use /*/rest
        }
        if (startsWith("/", path)) {
            return path;
        }
        return "/" + localPeer + "/" + path;
    }

    static boolean matchesPattern(String path, String pattern) {
        // NEVER_MATCH never matches, in EITHER operand (0.8.2.20). This arm is FIRST and
        // is a matcher rule, not a property of the string: the arm below returns true for
        // a bare "*" operand, so safety MUST NOT rest on a value merely looking
        // unmatchable.
        if (path.equals(NEVER_MATCH) || pattern.equals(NEVER_MATCH)) {
            return false;
        }
        if (pattern.equals("*")) {
            return true;
        }
        if (startsWith("/*/", pattern)) {
            String remainder = pattern.substring(3);
            if (path.length() < 1) {
                return false;
            }
            int i = path.indexOf('/', 1);
            return (i >= 0) && matchesPattern(path.substring(i + 1), remainder);
        }
        if (pattern.length() >= 2 && pattern.endsWith("/*")) {
            return startsWith(pattern.substring(0, pattern.length() - 1), path);
        }
        return path.equals(pattern);
    }

    /**
     * Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
     * call site — no default — so a new one cannot inherit the wrong matcher silently,
     * which is exactly the F40 defect.
     */
    enum ScopeKind { ID, PATH }

    /**
     * §5.2 id-scope match (0.8.1, F40) — {@code operations} and {@code peers}. Literal
     * comparison with exactly two wildcard forms: bare {@code *} and a trailing
     * {@code /*} segment-prefix. None of the §5.4 path transforms apply, so a pattern
     * carrying path syntax is matched as a literal string: a non-match, never a fault.
     */
    static boolean matchesIdPattern(String value, String pattern) {
        if (pattern.equals("*")) {
            return true;
        }
        if (pattern.length() >= 2 && pattern.endsWith("/*")) {
            return startsWith(pattern.substring(0, pattern.length() - 1), value);
        }
        return value.equals(pattern);
    }

    private static boolean coveredId(List<String> pats, String value) {
        for (String p : pats) {
            if (matchesIdPattern(value, p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel's "matches
     * nothing" is fail-CLOSED in an include (covers nothing -> the grant grants nothing)
     * and fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
     * its author wrote). Same value, same matcher, opposite safety direction — so the
     * reading is chosen HERE, where the position is known, and {@link #matchesPattern}
     * stays uniform over its operands.
     *
     * <p>The guard is SCOPED TO PATH-SCOPE by its callers (0.8.2.24 N2/N3); see
     * {@link #matchesScope}. A capability carrying such a pattern is invalid at §5.4 and
     * should never reach that loop at all, so this arm is a net rather than the only gate.
     */
    private static boolean excludeIsUnmatchable(String frame, List<String> excl) {
        for (String p : excl) {
            if (canonicalize(frame, p).equals(NEVER_MATCH)) {
                return true;
            }
        }
        return false;
    }

    static boolean matchesScope(String localPeer, String value, Scope s, ScopeKind kind) {
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
        if (kind == ScopeKind.PATH && excludeIsUnmatchable(localPeer, s.excl())) {
            return false;                       // 0.8.2.21 — deny, do not carve out nothing
        }
        if (kind == ScopeKind.ID) {
            return coveredId(s.incl(), value) && !coveredId(s.excl(), value);
        }
        String cv = canonicalize(localPeer, value);
        return covered(localPeer, s.incl(), cv) && !covered(localPeer, s.excl(), cv);
    }

    private static boolean covered(String frame, List<String> pats, String cv) {
        for (String p : pats) {
            if (matchesPattern(cv, canonicalize(frame, p))) {
                return true;
            }
        }
        return false;
    }

    // ── §5.2 check-permission ──────────────────────────────────────────────────────

    static String firstSegment(String uri) {
        String u = startsWith("/", uri) ? uri.substring(1) : uri;
        int i = u.indexOf('/');
        return (i >= 0) ? u.substring(0, i) : u;
    }

    static boolean isPeerId(String seg) {
        if (seg.length() < 46) {
            return false;
        }
        for (int i = 0; i < seg.length(); i++) {
            if (Base58Alphabet.indexOf(seg.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    private static final String Base58Alphabet =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static String extractPeer(String localPeer, String uri) {
        String first = firstSegment(normalizeUri(uri));
        return isPeerId(first) ? first : localPeer;
    }

    /**
     * Concrete-target subset (the core surface the oracle exercises). The grant's own
     * resource patterns canonicalize against the GRANTER's peer_id (§PR-8 / V2(a)); the
     * caller-supplied targets/exclude stay on the LOCAL frame (§5.4). For the
     * self-issued dominant path granter = local, byte-identical to the pre-fix behavior.
     */
    static boolean checkResourceScope(String localPeer, String granterPeer, EcfValue.Map resource, Scope s) {
        List<String> targets = Cbor.textList(resource, "targets");
        List<String> callerExcl = Cbor.textList(resource, "exclude");
        if (targets == null || targets.isEmpty()) {
            return false;
        }
        // An unmatchable GRANT exclude excludes everything (0.8.2.21). THIS IS FIRST,
        // before any target is considered: the coverage test below is correct in
        // isolation and is simply never reached on a sentinel, because matchesPattern
        // answers false and the grant reads as having carved out nothing.
        if (excludeIsUnmatchable(granterPeer, s.excl())) {
            return false;
        }
        for (String tgt : targets) {
            String ct = canonicalize(localPeer, tgt);
            // NEVER_MATCH is NOT skipped by the caller-exclude arm — it cannot be covered
            // by any exclude (§5.4 matcher rule), so it stays in the list and is refused
            // by the include test below.
            if (callerExcl != null && coveredFrame(localPeer, callerExcl, ct)) {
                continue;                                  // caller excluded → vacuously ok
            }
            if (!coveredFrame(granterPeer, s.incl(), ct)) {
                return false;
            }
            if (coveredFrame(granterPeer, s.excl(), ct)) {
                return false;
            }
        }
        return true;
    }

    private static boolean coveredFrame(String frame, List<String> pats, String v) {
        for (String p : pats) {
            if (matchesPattern(v, canonicalize(frame, p))) {
                return true;
            }
        }
        return false;
    }

    /** §PR-8 — the frame for canonicalizing CAP's grant resource patterns is the
     *  GRANTER's peer_id. Single-sig granter → derive peer_id from its public_key;
     *  unresolvable → null (caller falls back to local). */
    static String resolveGranterPeerId(Function<byte[], Entity> resolve, Entity cap) {
        byte[] gh = cap.bytes("granter");
        if (gh == null) {
            return null;
        }
        Entity g = resolve.apply(gh);
        if (g == null) {
            return null;
        }
        byte[] pk = g.bytes("public_key");
        return (pk != null) ? Identity.peerIdOfPublicKey(pk) : null;
    }

    /**
     * Gate the wire request at the dispatch authorization boundary (§3.2.3 / v7.73).
     * {@code granterPeer} is the §PR-8 canonicalization frame for the cap's grant
     * resource patterns; every other dimension stays on the local frame.
     */
    static Verdict checkPermission(String localPeer, String granterPeer, Entity exec, Entity token,
                                   String handlerPattern) {
        String operation = orEmpty(exec.text("operation"));
        String uri = orEmpty(exec.text("uri"));
        String targetPeer = extractPeer(localPeer, uri);
        EcfValue.Map resource = exec.mapField("resource");
        for (GrantRec g : grantsOfToken(token)) {
            boolean ok = matchesScope(localPeer, operation, g.operations(), ScopeKind.ID)
                    && matchesScope(localPeer, handlerPattern, g.handlers(), ScopeKind.PATH);
            if (ok) {
                Scope peers = (g.peers() != null) ? g.peers() : new Scope(List.of(localPeer), List.of());
                ok = matchesScope(localPeer, targetPeer, peers, ScopeKind.ID);
            }
            if (ok && resource != null) {
                ok = checkResourceScope(localPeer, granterPeer, resource, g.resources());
            }
            if (ok) {
                return Verdict.ALLOW;
            }
        }
        return Verdict.DENY;
    }

    // ── §5.2 effective targets and §6.3 check_path_permission ───────────────────────

    /**
     * The result of {@link #effectiveTargets}: the surviving targets and whether the
     * EXECUTE carried a {@code resource} AT ALL.
     *
     * <p>THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES {@code [MUST]} (0.8.2.25,
     * N11): <em>"where an implementation projects {@code resource.targets} onto the
     * effective set ahead of the handler, that projection MUST NOT be lossy about its own
     * emptiness — narrow when narrowing leaves something, and retain the raw pair when
     * narrowing would empty it."</em> A function returning only a list cannot satisfy
     * that: collapsing {@code [qA] exclude [qA]} to {@code []} deletes the two-empties
     * discriminator before any handler can read it, and the handler's refusal arm becomes
     * dead code that only a WIRE drive can detect.
     */
    record EffectiveTargets(List<String> survivors, boolean hasResource) { }

    /**
     * §5.2's effective target list (0.8.2.20): the caller's own {@code resource.exclude}
     * removes entries from {@code resource.targets} BEFORE anything else looks at the
     * request.
     *
     * <p>The survivors are returned in the caller's OWN SPELLING, not canonicalized —
     * 0.8.2.21 is explicit that {@code effective_targets} yields raw survivors, and the
     * distinction is load-bearing because the value flows on to {@code store.getAt}, which
     * canonicalizes for itself.
     *
     * <p>A PRESENT-BUT-ILL-TYPED {@code targets} IS <b>PRESENT</b>, with an empty survivor
     * list. Reporting it absent would serve the WIDER absent-case answer to a request that
     * named a resource, which is N11's own defect one field over.
     *
     * <p>The caller-exclude arm is fail-OPEN on an unmatchable pattern — §5.4 rules it
     * separately from the grant arm — and that is INHERITED here rather than restated: the
     * pattern canonicalizes to {@link #NEVER_MATCH}, {@link #matchesPattern} then answers
     * false, and the target simply survives.
     *
     * <p><em>"Every seam that narrows is exempted alike."</em> This peer has exactly ONE
     * narrowing seam — this function, called by the tree handler — and §6.5's dispatch
     * chain does not project: {@code dispatchInner} passes the EXECUTE through untouched
     * and {@link #checkPermission} reads {@code resource} for itself. There is no second
     * door to keep in step, and adding a projection at dispatch would create one.
     */
    static EffectiveTargets effectiveTargets(String localPeer, Entity exec) {
        EcfValue.Map r = exec.mapField("resource");
        if (r == null || r.get("targets") == null) {
            return new EffectiveTargets(List.of(), false);
        }
        List<String> targets = Cbor.textList(r, "targets");
        if (targets == null) {
            targets = List.of();                // present but ill-typed: PRESENT, no survivors
        }
        List<String> callerExcl = Cbor.textList(r, "exclude");
        if (callerExcl == null) {
            callerExcl = List.of();
        }
        List<String> out = new ArrayList<>(targets.size());
        for (String t : targets) {
            String ct = canonicalize(localPeer, t);
            boolean dropped = false;
            for (String x : callerExcl) {
                if (matchesPattern(ct, canonicalize(localPeer, x))) {
                    dropped = true;
                    break;
                }
            }
            if (!dropped) {
                out.add(t);
            }
        }
        return new EffectiveTargets(out, true);
    }

    /**
     * §6.3's handler-level path check.
     *
     * <p>IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
     * subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
     * by caller-controlled input: a caller who excludes the one target its capability does
     * not cover removes that target from {@link #checkPermission}'s view entirely, and a
     * handler that then acts on it has authorized nothing.
     *
     * <p>THREE DIMENSIONS, NOT FOUR. {@code peers} is not consulted — the path is local by
     * construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
     * step 3, before any handler runs), and §6.3's signature names only handlers,
     * operations and resources.
     *
     * <p>THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
     * rather than a choice: §6.3's block reads
     * {@code matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)} —
     * there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the
     * subject is a pattern compared against a parent's pattern; this call site compares a
     * CONCRETE local path the handler is about to touch.
     *
     * <p>Canonicalization is total (0.8.2.20), so a malformed path answers the sentinel,
     * which matches no grant (§5.4) and falls through to DENY rather than being matched
     * against anything.
     *
     * <p>An empty {@code resources.include} is a legal grant shape (§5.2: handlers that
     * touch no tree paths) and DENIES every path here, which is what that note says it
     * should.
     */
    static boolean checkPathPermission(String localPeer, String operation, String path,
                                       Entity token, String handlerPattern) {
        String cp = canonicalize(localPeer, path);
        for (GrantRec g : grantsOfToken(token)) {
            if (!matchesScope(localPeer, handlerPattern, g.handlers(), ScopeKind.PATH)) {
                continue;
            }
            if (!matchesScope(localPeer, operation, g.operations(), ScopeKind.ID)) {
                continue;
            }
            if (!matchesScope(localPeer, cp, g.resources(), ScopeKind.PATH)) {
                continue;
            }
            return true;
        }
        return false;
    }

    // ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────────

    /** Inclusive maximum of {@code primitive/uint} — the representability bound. */
    private static final BigInteger UINT64_MAX =
            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    /**
     * §6.2 CAP-6a (INGEST): every temporal field on a RECEIVED token must be either
     * ABSENT (legal — "no bound") or representable as {@code primitive/uint}. A bignum,
     * a negative integer, or any non-integer is <b>malformed</b>, and the verifier MUST
     * refuse it rather than read the unrepresentable field as absent — absent means
     * <i>no expiry</i>, so the fail-open reading grants an immortal capability.
     *
     * <p>The mechanism here differs from the null-collapsing peers and is worth naming:
     * {@code Cbor.uint} returns the {@code BigInteger} of ANY {@code EcfValue.Int},
     * including a negative one. So the range checks did not skip — they ran and simply
     * returned the wrong answer: for a negative {@code not_before},
     * {@code now < not_before} is false, so the cap passed. Same fail-open, reached by
     * arithmetic rather than by a null.
     *
     * <p>MUST run BEFORE the range checks it protects.
     */
    static boolean temporalFieldsRepresentable(Entity cap) {
        for (String key : new String[] {"expires_at", "not_before", "created_at"}) {
            EcfValue v = cap.field(key);
            if (v == null || v instanceof EcfValue.Null) {
                continue; // absent/null is legal — no bound
            }
            if (!(v instanceof EcfValue.Int i)) {
                return false;
            }
            if (i.value().signum() < 0 || i.value().compareTo(UINT64_MAX) > 0) {
                return false;
            }
        }
        return true;
    }

    static long nowMs() {
        return System.currentTimeMillis();
    }

    static Entity findSignature(byte[] target, List<Envelope.Included> included) {
        for (Envelope.Included in : included) {
            Entity e = in.entity();
            if (e.type().equals("system/signature")) {
                byte[] tg = e.bytes("target");
                if (tg != null && Identity.octetsEqual(tg, target)) {
                    return e;
                }
            }
        }
        return null;
    }

    // ── §3.6 M3 multi-signature granter ──────────────────────────────────────────
    // The capability `granter` field is a union (§3.6): a single system/hash (bytes,
    // single-sig) OR a {signers: [system/hash], threshold: uint} map (multi-sig,
    // ROOT-ONLY). A multi-sig root is verified by {@link #verifyMultiSigRoot} — §3.6 M3
    // structure first, then §5.5 M6 root-at-local + M4 k-of-n quorum.

    /** A parsed multi-sig granter descriptor: the signer identity hashes + the k threshold. */
    record MultiGranter(List<byte[]> signers, BigInteger threshold) { }

    /**
     * Parse the {@code granter} union as a multi-sig descriptor, or null if it is a
     * single {@code system/hash} (bytes) or absent. Detection: granter is a CBOR map
     * (not bytes). {@code signers} = the array of hash byte-strings; {@code threshold}
     * = the uint (0 when absent/non-uint, which M3 then rejects as < 2).
     */
    static MultiGranter multiGranterOf(Entity cap) {
        EcfValue g = cap.field("granter");
        if (!(g instanceof EcfValue.Map m)) {
            return null;
        }
        List<byte[]> signers = new ArrayList<>();
        EcfValue sv = m.get("signers");
        if (sv instanceof EcfValue.Array a) {
            for (EcfValue item : a.items()) {
                if (item instanceof EcfValue.Bytes b) {
                    signers.add(b.octets());
                }
            }
        }
        BigInteger threshold = Cbor.uint(m, "threshold");
        return new MultiGranter(signers, threshold != null ? threshold : BigInteger.ZERO);
    }

    static boolean isMultiSig(Entity cap) {
        return cap.field("granter") instanceof EcfValue.Map;
    }

    private static boolean hasDuplicateSigners(List<byte[]> signers) {
        for (int i = 0; i < signers.size(); i++) {
            for (int j = i + 1; j < signers.size(); j++) {
                if (Identity.octetsEqual(signers.get(i), signers.get(j))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** All {@code system/signature} entities in {@code included} that target {@code target}. */
    private static List<Entity> signaturesTargeting(byte[] target, List<Envelope.Included> included) {
        List<Entity> out = new ArrayList<>();
        for (Envelope.Included in : included) {
            Entity e = in.entity();
            if (e.type().equals("system/signature")) {
                byte[] tg = e.bytes("target");
                if (tg != null && Identity.octetsEqual(tg, target)) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    /**
     * Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4·M6). Returns
     * true (ALLOW) only if the quorum is well-formed AND a threshold of DISTINCT signers
     * signed the cap's content hash. Structural validation (M3) precedes signature
     * counting (§3.6 precedence 25): a malformed quorum is denied on its structure, not
     * on missing/invalid sigs. Every failure path returns false → the dispatcher maps it
     * to 403 capability_denied (never a throw, never a hang).
     */
    private static boolean verifyMultiSigRoot(String localPeer, Function<byte[], Entity> resolve,
                                              Entity cap, MultiGranter mg,
                                              List<Envelope.Included> included) {
        int n = mg.signers().size();
        // §3.6 M3 structure — root-only; a real quorum (n ≥ 2); a usable threshold
        // (2 ≤ threshold ≤ n, so neither degenerate-single nor unsatisfiable); distinct
        // signers. BEFORE any signature work (precedence 25).
        if (cap.bytes("parent") != null) {
            return false;
        }
        if (n < 2) {
            return false;
        }
        if (mg.threshold().compareTo(BigInteger.TWO) < 0
                || mg.threshold().compareTo(BigInteger.valueOf(n)) > 0) {
            return false;
        }
        if (hasDuplicateSigners(mg.signers())) {
            return false;
        }

        // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
        boolean localInSigners = false;
        for (byte[] s : mg.signers()) {
            String pid = peerIdOfSigner(resolve, s);
            if (pid != null && pid.equals(localPeer)) {
                localInSigners = true;
                break;
            }
        }
        if (!localInSigners) {
            return false;
        }

        // §6.2 CAP-6a (INGEST) — MUST run BEFORE the range checks below, because the
        // range checks are exactly what the unrepresentable value defeats.
        if (!temporalFieldsRepresentable(cap)) {
            return false;
        }

        // Temporal validity + grantee resolution (as for any root).
        long now = nowMs();
        BigInteger nb = cap.uint("not_before");
        if (nb != null && BigInteger.valueOf(now).compareTo(nb) < 0) {
            return false;
        }
        BigInteger ex = cap.uint("expires_at");
        if (ex != null && ex.compareTo(BigInteger.valueOf(now)) < 0) {
            return false;
        }
        byte[] grantee = cap.bytes("grantee");
        if (grantee == null || resolve.apply(grantee) == null) {
            return false;
        }

        // §5.5 M4 k-of-n: at least `threshold` DISTINCT quorum members produced a valid
        // signature over the cap's content hash. A duplicate signature from one signer
        // does NOT inflate the count (we count distinct signer hashes).
        List<Entity> sigs = signaturesTargeting(cap.rawHash(), included);
        List<byte[]> validSigners = new ArrayList<>();
        for (byte[] signerHash : mg.signers()) {
            boolean alreadyCounted = false;
            for (byte[] v : validSigners) {
                if (Identity.octetsEqual(v, signerHash)) {
                    alreadyCounted = true;
                    break;
                }
            }
            if (alreadyCounted) {
                continue;
            }
            Entity signerPeer = resolve.apply(signerHash);
            if (signerPeer == null) {
                continue;
            }
            for (Entity sgn : sigs) {
                byte[] sg = sgn.bytes("signer");
                if (sg != null && Identity.octetsEqual(sg, signerHash)
                        && Identity.verifySignature(sgn, signerPeer)) {
                    validSigners.add(signerHash);
                    break;
                }
            }
        }
        return BigInteger.valueOf(validSigners.size()).compareTo(mg.threshold()) >= 0;
    }

    /** Derive a signer's peer_id from its resolved system/peer identity, or null. */
    private static String peerIdOfSigner(Function<byte[], Entity> resolve, byte[] signerHash) {
        Entity p = resolve.apply(signerHash);
        if (p == null) {
            return null;
        }
        byte[] pk = p.bytes("public_key");
        return (pk != null) ? Identity.peerIdOfPublicKey(pk) : null;
    }

    static Entity capResolve(List<Envelope.Included> included, Store store, byte[] h) {
        Entity e = includedGet(included, h);
        return (e != null) ? e : store.getByHash(h);
    }

    static Entity includedGet(List<Envelope.Included> included, byte[] h) {
        for (Envelope.Included in : included) {
            if (Identity.octetsEqual(in.hash(), h)) {
                return in.entity();
            }
        }
        return null;
    }

    /** §PR-8 / §5.5a per-link canonicalization frame for CAP's resource patterns =
     *  its granter's peer_id. Multi-sig root (no granter hash) → localPeer. Single-sig:
     *  derive from the resolved granter's public_key; unresolvable → null (caller denies). */
    static String linkGranterPeer(Function<byte[], Entity> resolve, String localPeer, Entity cap) {
        byte[] gh = cap.bytes("granter");
        if (gh == null) {
            return localPeer;
        }
        Entity g = resolve.apply(gh);
        if (g == null) {
            return null;
        }
        byte[] pk = g.bytes("public_key");
        return (pk != null) ? Identity.peerIdOfPublicKey(pk) : null;
    }

    /**
     * §5.5a subset check: every child include must be covered by some parent include, and
     * every parent exclude must be inherited by some child exclude.
     *
     * <p>TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; {@code entity-core-formalization}
     * K-7). §3.6's id-scope grammar binds the scope TYPE, not one function — <em>"An
     * implementation on the canonicalizing reading is non-conformant and MUST adopt the
     * literal matcher"</em> — so the rule F40 landed on {@link #matchesScope} reaches here
     * too, with delegation-chain WIDENING named as the reason: on the canonicalizing
     * reading a bare id include reads as covered by a path-form parent pattern it does not
     * literally match, and a child grant comes out wider than its parent. {@code lean}'s
     * differential put it at 2 of 64 include pairs and 2 of 64 exclude pairs, fail-closed,
     * with a 16-pair control alphabet reporting 0 — which is why every hand-tried example
     * missed it.
     *
     * <p>{@code kind} has NO DEFAULT and is named at every call site, because a default is
     * how the next dimension inherits the wrong matcher silently — the original F40 defect.
     * The per-link granter frames are meaningless on the id arm (an id pattern is never
     * canonicalized) and are simply unread there.
     */
    private static boolean scopeSubset(String childPeer, String parentPeer,
                                       Scope child, Scope parent, ScopeKind kind) {
        for (String cp : child.incl()) {
            String cc = frameFor(kind, childPeer, cp);
            boolean some = false;
            for (String pp : parent.incl()) {
                if (coversFor(kind, frameFor(kind, parentPeer, pp), cc)) {
                    some = true;
                    break;
                }
            }
            if (!some) {
                return false;
            }
        }
        for (String pe : parent.excl()) {
            String cpe = frameFor(kind, parentPeer, pe);
            boolean some = false;
            for (String ce : child.excl()) {
                if (coversFor(kind, frameFor(kind, childPeer, ce), cpe)) {
                    some = true;
                    break;
                }
            }
            if (!some) {
                return false;
            }
        }
        return true;
    }

    /** An id pattern is never canonicalized; a path pattern always is (§3.6 / §5.4). */
    private static String frameFor(ScopeKind kind, String peer, String pattern) {
        return (kind == ScopeKind.PATH) ? canonicalize(peer, pattern) : pattern;
    }

    /** The matcher §3.6 binds to the scope TYPE — literal for id, §5.4 for path. */
    private static boolean coversFor(ScopeKind kind, String pattern, String value) {
        return (kind == ScopeKind.PATH) ? matchesPattern(value, pattern) : matchesIdPattern(value, pattern);
    }

    static boolean grantSubset(String localPeer, String childPeer, String parentPeer,
                               GrantRec child, GrantRec parent) {
        // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
        // dimensions stay on the local frame. The scope KIND is a property of the
        // DIMENSION and is named at every call site, never defaulted (F50 / 0.8.2.16).
        if (!scopeSubset(localPeer, localPeer, child.handlers(), parent.handlers(), ScopeKind.PATH)) {
            return false;
        }
        if (!scopeSubset(localPeer, localPeer, child.operations(), parent.operations(), ScopeKind.ID)) {
            return false;
        }
        if (!scopeSubset(childPeer, parentPeer, child.resources(), parent.resources(), ScopeKind.PATH)) {
            return false;
        }
        Scope cp = (child.peers() != null) ? child.peers() : new Scope(List.of(localPeer), List.of());
        Scope pp = (parent.peers() != null) ? parent.peers() : new Scope(List.of(localPeer), List.of());
        return scopeSubset(localPeer, localPeer, cp, pp, ScopeKind.ID);
    }

    private static boolean isAttenuated(String localPeer, String childPeer, String parentPeer,
                                        Entity child, Entity parent) {
        List<GrantRec> cg = grantsOfToken(child);
        List<GrantRec> pg = grantsOfToken(parent);
        for (GrantRec c : cg) {
            boolean some = false;
            for (GrantRec p : pg) {
                if (grantSubset(localPeer, childPeer, parentPeer, c, p)) {
                    some = true;
                    break;
                }
            }
            if (!some) {
                return false;
            }
        }
        BigInteger pe = parent.uint("expires_at");
        BigInteger ce = child.uint("expires_at");
        if (pe != null && ce == null) {
            return false;                              // child infinite, parent finite
        }
        if (pe != null) {
            return ce.compareTo(pe) <= 0;
        }
        return true;
    }

    private static boolean checkDelegationCaveats(Entity parent, Entity child, int depth) {
        EcfValue.Map caveats = parent.mapField("delegation_caveats");
        if (caveats == null) {
            return true;
        }
        if (Cbor.isTrue(caveats.get("no_delegation"))) {
            return false;
        }
        boolean depthOk = true;
        BigInteger m = Cbor.uint(caveats, "max_delegation_depth");
        if (m != null) {
            depthOk = BigInteger.valueOf(depth).compareTo(m) < 0;
        }
        boolean ttlOk = true;
        BigInteger maxTtl = Cbor.uint(caveats, "max_delegation_ttl");
        if (maxTtl != null) {
            BigInteger ex = child.uint("expires_at");
            BigInteger cr = child.uint("created_at");
            if (ex != null && cr != null) {
                ttlOk = ex.subtract(cr).compareTo(maxTtl) <= 0;
            } else if (ex != null) {
                ttlOk = true;                          // created_at absent — can't bound, admit
            } else {
                ttlOk = false;                         // infinite child lifetime exceeds any limit
            }
        }
        return depthOk && ttlOk;
    }

    private record Chain(List<Entity> chain, boolean ok) { }

    private static Chain collectChain(Entity cap, Function<byte[], Entity> resolve) {
        List<Entity> acc = new ArrayList<>();
        Entity current = cap;
        int depth = 0;
        while (true) {
            if (depth > 64) {
                return new Chain(null, false);
            }
            acc.add(current);
            byte[] ph = current.bytes("parent");
            if (ph == null) {
                return new Chain(acc, true);
            }
            Entity parent = resolve.apply(ph);
            if (parent == null) {
                return new Chain(null, false);
            }
            current = parent;
            depth++;
        }
    }

    /**
     * §4.10(b) structural-bound pre-check: true if the authority chain rooted at
     * {@code capability} exceeds the max depth (64). Walks parent pointers without
     * verifying signatures — depth is a purely structural property, gated BEFORE the
     * per-link authz walk so an over-deep chain is reported as 400
     * chain_depth_exceeded (structural excess), distinct from a 403 capability_denied
     * authz failure (arch ruling, v7.75 §4.10(b)). An unreachable parent is NOT a
     * depth problem — it returns false here and is left for verifyCapabilityChain to
     * deny (403).
     */
    static boolean chainExceedsDepth(Store store, Entity capability,
                                     List<Envelope.Included> included) {
        Function<byte[], Entity> resolve = h -> capResolve(included, store, h);
        Entity current = capability;
        int depth = 0;
        while (true) {
            if (depth > 64) {
                return true;
            }
            byte[] ph = current.bytes("parent");
            if (ph == null) {
                return false; // root reached within bound
            }
            Entity parent = resolve.apply(ph);
            if (parent == null) {
                return false; // unreachable — not a depth problem
            }
            current = parent;
            depth++;
        }
    }

    static Verdict verifyCapabilityChain(String localPeer, Store store, Entity capability,
                                         List<Envelope.Included> included) {
        return verifyCapabilityChainRootedAt(localPeer, localPeer, store, capability, included);
    }

    /**
     * {@link #verifyCapabilityChain} with the expected ROOT granter named separately from
     * the verifying peer.
     *
     * <p>§1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
     * minted by the TARGET peer, so root-trust is relaxed away from the local peer — and
     * every other clause (per-link signatures, grantee resolution, temporal validity,
     * attenuation, caveats) is unchanged. Parameterized rather than forked because a
     * second copy of a chain walk is a second copy that drifts.
     *
     * <p>A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
     * {@code rootPeer != localPeer} the quorum arm is REFUSED outright rather than
     * verified: <i>minted by the target</i> means the target SOLELY minted it, and a
     * K-of-N root is a GROUP's authority — its co-signers authorized it too. Verifying the
     * quorum here and accepting it would let any one signer's target confer the whole
     * group's grant, which is E3/F66's over-acceptance. §5.5's M6 also requires the LOCAL
     * peer in the signer set, so the quorum arm has no meaning in a foreign frame even on
     * its own terms.
     */
    static Verdict verifyCapabilityChainRootedAt(String localPeer, String rootPeer, Store store,
                                                 Entity capability,
                                                 List<Envelope.Included> included) {
        Function<byte[], Entity> resolve = h -> capResolve(included, store, h);
        Chain c = collectChain(capability, resolve);
        if (!c.ok()) {
            return Verdict.DENY;
        }
        List<Entity> chain = c.chain();
        Entity root = chain.get(chain.size() - 1);
        // Root authority: a single-sig root must root at `rootPeer`; a §3.6 M3 multi-sig
        // root (root-only) must pass k-of-n quorum validation, and only in the LOCAL frame.
        boolean rootOk;
        MultiGranter rootMg = multiGranterOf(root);
        if (rootMg != null) {
            rootOk = rootPeer.equals(localPeer)
                    && verifyMultiSigRoot(localPeer, resolve, root, rootMg, included);
        } else {
            rootOk = false;
            byte[] rgh = root.bytes("granter");
            if (rgh != null) {
                Entity g = resolve.apply(rgh);
                if (g != null) {
                    byte[] pk = g.bytes("public_key");
                    rootOk = pk != null && Identity.peerIdOfPublicKey(pk).equals(rootPeer);
                }
            }
        }
        if (!rootOk) {
            return Verdict.DENY;
        }
        boolean good = true;
        int n = chain.size();
        for (int i = 0; i < n && good; i++) {
            Entity current = chain.get(i);
            // A §3.6 M3 multi-sig token is root-only and fully verified above (structure,
            // quorum signatures, temporal, grantee). A multi-sig token anywhere but the
            // chain root is rejected; otherwise it is skipped here (no single-sig per-link
            // signature/temporal/delegation work applies to it).
            if (isMultiSig(current)) {
                if (i != n - 1) {
                    good = false;
                }
                continue;
            }
            // signature: signer == granter, verify against granter identity
            byte[] gh = current.bytes("granter");
            if (gh != null) {
                Entity sgn = findSignature(current.rawHash(), included);
                Entity granter = resolve.apply(gh);
                if (sgn != null && granter != null) {
                    byte[] signer = sgn.bytes("signer");
                    if (!(signer != null && Identity.octetsEqual(signer, gh)
                            && Identity.verifySignature(sgn, granter))) {
                        good = false;
                    }
                } else {
                    good = false;
                }
            } else {
                good = false;
            }
            // grantee resolution → 401 carve-out
            byte[] geh = current.bytes("grantee");
            if (geh != null) {
                if (resolve.apply(geh) == null) {
                    throw new UnresolvableGrantee();
                }
            } else {
                throw new UnresolvableGrantee();
            }
            // §6.2 CAP-6a (INGEST) — before the range checks, same reason as the root path.
            if (!temporalFieldsRepresentable(current)) {
                good = false;
            }
            // temporal validity
            long tnow = nowMs();
            BigInteger nb = current.uint("not_before");
            if (nb != null && BigInteger.valueOf(tnow).compareTo(nb) < 0) {
                good = false;
            }
            BigInteger ex = current.uint("expires_at");
            if (ex != null && ex.compareTo(BigInteger.valueOf(tnow)) < 0) {
                good = false;
            }
            // delegation link
            if (i < n - 1) {
                Entity parent = chain.get(i + 1);
                String childPeer = linkGranterPeer(resolve, localPeer, current);
                String parentPeer = linkGranterPeer(resolve, localPeer, parent);
                if (childPeer == null || parentPeer == null) {
                    good = false;
                } else {
                    byte[] pg = parent.bytes("grantee");
                    byte[] cg = current.bytes("granter");
                    if (!(pg != null && cg != null && Identity.octetsEqual(pg, cg)
                            && isAttenuated(localPeer, childPeer, parentPeer, current, parent)
                            && checkDelegationCaveats(parent, current, i))) {
                        good = false;
                    }
                }
            }
        }
        return good ? Verdict.ALLOW : Verdict.DENY;
    }

    static boolean isRevoked(String localPeer, Store store, Entity capability,
                             List<Envelope.Included> included) {
        Function<byte[], Entity> resolve = h -> capResolve(included, store, h);
        Chain c = collectChain(capability, resolve);
        byte[] rootHash = c.ok() ? c.chain().get(c.chain().size() - 1).rawHash() : capability.rawHash();
        return revokeMarker(localPeer, store, capability.rawHash()) != null
                || revokeMarker(localPeer, store, rootHash) != null;
    }

    private static Entity revokeMarker(String localPeer, Store store, byte[] h) {
        return store.getAt("/" + localPeer + "/system/capability/revocations/" + Cbor.hex(h));
    }

    // ── §5.2 verify-request (3-way verdict) ─────────────────────────────────────────

    static RequestVerdict verifyRequest(String localPeer, Store store, Envelope env) {
        Entity exec = env.root();
        List<Envelope.Included> included = env.included();
        Entity sgn = findSignature(exec.rawHash(), included);
        if (sgn == null) {
            return RequestVerdict.AUTHN_FAIL;
        }
        byte[] authorH = exec.bytes("author");
        byte[] signer = sgn.bytes("signer");
        if (!(signer != null && authorH != null && Identity.octetsEqual(signer, authorH))) {
            return RequestVerdict.AUTHN_FAIL;
        }
        Entity author = includedGet(included, authorH);
        if (author == null) {
            return RequestVerdict.AUTHN_FAIL;
        }
        if (!Identity.verifySignature(sgn, author)) {
            return RequestVerdict.AUTHN_FAIL;
        }
        byte[] ch = exec.bytes("capability");
        Entity cap = (ch != null) ? includedGet(included, ch) : null;
        if (cap == null) {
            return RequestVerdict.AUTHZ_DENY;
        }
        // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
        // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
        // distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the caller
        // distinguish "shorten your chain" from "you lack the capability".
        if (chainExceedsDepth(store, cap, included)) {
            return RequestVerdict.CHAIN_TOO_DEEP;
        }
        Verdict chainVerdict = verifyCapabilityChain(localPeer, store, cap, included);
        if (chainVerdict == Verdict.DENY) {
            return RequestVerdict.AUTHZ_DENY;
        }
        byte[] grantee = cap.bytes("grantee");
        if (!(grantee != null && authorH != null && Identity.octetsEqual(grantee, authorH))) {
            return RequestVerdict.AUTHZ_DENY;
        }
        if (isRevoked(localPeer, store, cap, included)) {
            return RequestVerdict.AUTHZ_DENY;
        }
        return RequestVerdict.ALLOW;
    }

    private static String orEmpty(String s) {
        return (s != null) ? s : "";
    }

    // ── §1.4 PD-2: outbound sub-dispatch authorization ────────────────────────────

    /**
     * Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
     *
     * <p>§1.4 admits three spellings of one address — {@code system/tree},
     * {@code /{peer}/system/tree} and {@code entity://{peer}/system/tree} — and §1.4's
     * PD-2 block requires Dimension 1's handler pattern to be the target uri's
     * peer-relative path, because a grant names HANDLERS and a handler pattern never
     * carries a peer segment. Matching a grant against the absolute or schemed form
     * matches nothing, silently, which reads at the wire as an authority refusal.
     *
     * <p>The first segment is dropped ONLY when it is a peer_id. A peer-relative
     * {@code system/protocol/connect} must not lose {@code system} — the standing defect
     * on {@code smalltalk} and {@code forth}, where an unconditional strip made every
     * self-minted grant unusable while the handshake stayed green.
     */
    static String peerRelativeOf(String uri) {
        String p = normalizeUri(uri);
        if (!p.startsWith("/")) {
            return p;
        }
        String body = p.substring(1);
        int slash = body.indexOf('/');
        String first = (slash < 0) ? body : body.substring(0, slash);
        if (isPeerId(first)) {
            return (slash < 0) ? "" : body.substring(slash + 1);
        }
        return body;
    }

    /**
     * Store key of a handler's OWN grant (§6.8:
     * {@code system/capability/grants/{pattern}}), tolerant of the pattern arriving
     * absolute or peer-relative.
     *
     * <p>§6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute,
     * while the grant path is built from the PEER-RELATIVE one. The two are one segment
     * apart and concatenating the wrong one yields a doubled peer segment whose lookup
     * misses — which fails closed as "no handler grant" and is indistinguishable, at the
     * wire, from a genuine authority refusal.
     */
    static String grantPathFor(String localPeer, String pattern) {
        String prefix = "/" + localPeer + "/";
        String rel = pattern.startsWith(prefix) ? pattern.substring(prefix.length()) : pattern;
        return "/" + localPeer + "/system/capability/grants/" + rel;
    }

    /**
     * Verify a presented reentry credential against §1.4's clauses and, where they all
     * hold, answer the {@code peers} scope Dimension 4 relaxes to. {@code null} relaxes
     * nothing.
     *
     * <p>Every clause is required and failing any relaxes nothing: the chain ROOT granter
     * resolves to the TARGET peer and is NOT a multi-signature root (a K-of-N root is a
     * GROUP's authority and never relaxes Dimension 4 —
     * {@link #verifyCapabilityChainRootedAt} refuses the quorum arm in a foreign frame,
     * which is where that rule lands); the LEAF grantee is the local peer; the chain is
     * valid and not revoked.
     */
    static Scope targetMintedPeersRelaxation(String localPeer, String targetPeer, Store store,
                                             Entity cred, List<Envelope.Included> included) {
        // Nothing to relax — the default already covers this peer. Treating a
        // self-targeted credential as a relaxation would make the exemption reachable with
        // no foreign mint at all.
        if (targetPeer.equals(localPeer)) {
            return null;
        }
        if (verifyCapabilityChainRootedAt(localPeer, targetPeer, store, cred, included) != Verdict.ALLOW) {
            return null;
        }
        if (isRevoked(localPeer, store, cred, included)) {
            return null;
        }
        byte[] gh = cred.bytes("grantee");
        if (gh == null) {
            return null;
        }
        Entity ge = capResolve(included, store, gh);
        if (ge == null) {
            return null;
        }
        byte[] pk = ge.bytes("public_key");
        if (pk == null || !Identity.peerIdOfPublicKey(pk).equals(localPeer)) {
            return null;
        }
        // The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent means
        // the granter — the target peer — which is the ordinary reentry shape: "you may
        // dispatch back to me."
        for (GrantRec g : grantsOfToken(cred)) {
            return (g.peers() != null) ? g.peers() : new Scope(List.of(targetPeer), List.of());
        }
        return null;
    }

    /**
     * §1.4's PD-2 gate: {@code check_permission} run before a locally-originated
     * sub-dispatch LEAVES the peer, with all four dimensions applied.
     *
     * <p>ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
     * decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's
     * pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE
     * TARGET PEER naming this peer as {@code grantee} relaxes Dimension 4 ({@code peers})
     * AND ONLY DIMENSION 4, to the peers that capability covers.
     *
     * <p><i>"The target answers WHERE; the handler's grant answers WHAT."</i> A credential
     * is NOT a grant: with no handler grant there is nothing to supply Dimensions 1-3, so
     * the sub-dispatch is refused however good the credential is. That is the COMPOSE, and
     * the BYPASS it is distinguished from is a peer that treats the credential as a
     * standalone authorizer and steers past its own grant — §6.8's confused-deputy
     * substitution. Both obvious vectors agree under either reading (sources agree ->
     * allow, no source -> refuse), so the only input that separates them is a VALID
     * credential presented to a handler whose own grant does NOT cover the request, which
     * MUST refuse.
     *
     * <p>A credential failing any verification clause relaxes NOTHING and the handler grant
     * gates unrelaxed — it does not turn the verdict into an error.
     *
     * <p>{@code targetPeer} is supplied by the caller rather than derived here: on the
     * §6.11 reentry seam the uri may be PEER-RELATIVE and the destination is the
     * connection's remote, so {@code extractPeer(uri, local)} would answer the LOCAL peer
     * and Dimension 4 would pass vacuously on the default {@code {include: [local]}} — the
     * exemption would then never be exercised and a bypass would read as a compose.
     *
     * <p>{@code cred == null} is the ambient arm: Dimension 4 is decided by the handler's
     * grant alone.
     */
    static boolean checkOutboundSubDispatch(String localPeer, String targetPeer,
                                            String handlerPattern, String operation, Store store,
                                            Entity handlerGrant, EcfValue.Map resource,
                                            Entity cred, List<Envelope.Included> included) {
        // Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
        Scope relaxTo = (cred == null) ? null
                : targetMintedPeersRelaxation(localPeer, targetPeer, store, cred, included);
        for (GrantRec g : grantsOfToken(handlerGrant)) {
            if (!matchesScope(localPeer, handlerPattern, g.handlers(), ScopeKind.PATH)) {
                continue;
            }
            if (!matchesScope(localPeer, operation, g.operations(), ScopeKind.ID)) {
                continue;
            }
            if (!checkResourceScope(localPeer, localPeer, resource, g.resources())) {
                continue;
            }
            // Dimension 4. §5.2's default for an absent `peers` scope is
            // {include: [local_peer_id]}, so a foreign target fails unless this grant names
            // it or a target-minted credential relaxes it.
            Scope peers = (g.peers() != null) ? g.peers() : new Scope(List.of(localPeer), List.of());
            if (matchesScope(localPeer, targetPeer, peers, ScopeKind.ID)) {
                return true;
            }
            if (relaxTo != null && matchesScope(localPeer, targetPeer, relaxTo, ScopeKind.ID)) {
                return true;
            }
        }
        return false;
    }
}
