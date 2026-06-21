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

    /** Resolve peer-relative paths to absolute /{local}/... form. */
    static String canonicalize(String localPeer, String path) {
        if (startsWith("./", path) || startsWith("../", path)) {
            throw new IllegalArgumentException("canonicalize: reserved directory-relative path");
        }
        if (startsWith("*/", path)) {
            throw new IllegalArgumentException("canonicalize: ambiguous bare peer wildcard");
        }
        if (startsWith("/", path)) {
            return path;
        }
        return "/" + localPeer + "/" + path;
    }

    static boolean matchesPattern(String path, String pattern) {
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

    static boolean matchesScope(String localPeer, String value, Scope s) {
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
        for (String tgt : targets) {
            String ct = canonicalize(localPeer, tgt);
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
            boolean ok = matchesScope(localPeer, operation, g.operations())
                    && matchesScope(localPeer, handlerPattern, g.handlers());
            if (ok) {
                Scope peers = (g.peers() != null) ? g.peers() : new Scope(List.of(localPeer), List.of());
                ok = matchesScope(localPeer, targetPeer, peers);
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

    // ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────────

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

    private static boolean scopeSubset(String childPeer, String parentPeer, Scope child, Scope parent) {
        for (String cp : child.incl()) {
            String cc = canonicalize(childPeer, cp);
            boolean some = false;
            for (String pp : parent.incl()) {
                if (matchesPattern(cc, canonicalize(parentPeer, pp))) {
                    some = true;
                    break;
                }
            }
            if (!some) {
                return false;
            }
        }
        for (String pe : parent.excl()) {
            String cpe = canonicalize(parentPeer, pe);
            boolean some = false;
            for (String ce : child.excl()) {
                if (matchesPattern(cpe, canonicalize(childPeer, ce))) {
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

    static boolean grantSubset(String localPeer, String childPeer, String parentPeer,
                               GrantRec child, GrantRec parent) {
        if (!scopeSubset(localPeer, localPeer, child.handlers(), parent.handlers())) {
            return false;
        }
        if (!scopeSubset(localPeer, localPeer, child.operations(), parent.operations())) {
            return false;
        }
        if (!scopeSubset(childPeer, parentPeer, child.resources(), parent.resources())) {
            return false;
        }
        Scope cp = (child.peers() != null) ? child.peers() : new Scope(List.of(localPeer), List.of());
        Scope pp = (parent.peers() != null) ? parent.peers() : new Scope(List.of(localPeer), List.of());
        return scopeSubset(localPeer, localPeer, cp, pp);
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
        Function<byte[], Entity> resolve = h -> capResolve(included, store, h);
        Chain c = collectChain(capability, resolve);
        if (!c.ok()) {
            return Verdict.DENY;
        }
        List<Entity> chain = c.chain();
        Entity root = chain.get(chain.size() - 1);
        // Root authority: a single-sig root must root at the local peer; a §3.6 M3
        // multi-sig root (root-only) must pass k-of-n quorum validation.
        boolean rootOk;
        MultiGranter rootMg = multiGranterOf(root);
        if (rootMg != null) {
            rootOk = verifyMultiSigRoot(localPeer, resolve, root, rootMg, included);
        } else {
            rootOk = false;
            byte[] rgh = root.bytes("granter");
            if (rgh != null) {
                Entity g = resolve.apply(rgh);
                if (g != null) {
                    byte[] pk = g.bytes("public_key");
                    rootOk = pk != null && Identity.peerIdOfPublicKey(pk).equals(localPeer);
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
}
