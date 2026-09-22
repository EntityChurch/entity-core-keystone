package org.entitycore.protocol.peer;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.crypto.EntityCryptoException;

/**
 * Peer assembly: bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2: connect,
 * tree, handler, capability), the §6.5 dispatch chain, §6.6 resolution, and per-connection
 * state. The pure protocol brain — a function from inbound envelope to outbound response
 * envelope. Transport lives in {@link Transport}.
 *
 * <p>Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch chain order
 * (verify → resolve → check-permission → handler), and §4.4 initial-grant delivery are
 * derived directly from V7.
 *
 * <p>Idiom (the static-OO single-dispatch axis): each handler is a {@link Handler} whose
 * {@code handle(operation, ctx)} switches over the operation string — the mainstream
 * `match op` ladder, the contrast with the Common Lisp peer's CLOS multiple dispatch.
 */
public final class Peer {

    private final Identity identity;
    private final Store store;
    private final String localPeer;
    private final boolean openGrants;       // --debug-open-grants: degenerate wide admin cap
    private final boolean conformance;      // --validate: §7a system/validate/* handlers
    private final Map<String, Handler> handlers = new HashMap<>();  // pattern → handler
    private final SecureRandom rng = new SecureRandom();

    private Peer(Identity identity, Store store, String localPeer,
                 boolean openGrants, boolean conformance) {
        this.identity = identity;
        this.store = store;
        this.localPeer = localPeer;
        this.openGrants = openGrants;
        this.conformance = conformance;
    }

    public Store store() {
        return store;
    }

    public String localPeer() {
        return localPeer;
    }

    /**
     * The handler registered at a peer-relative pattern, or null.
     *
     * <p>Package-private: it exists so a gate can drive ONE handler with a hand-built
     * {@link HandlerContext}, which is how §6.3's listing filter is measured — the narrow
     * grant is the whole input there, and minting one over the wire would put three more
     * moving parts between the assertion and the thing asserted.
     */
    Handler handlerFor(String pattern) {
        return handlers.get(pattern);
    }

    public Identity identity() {
        return identity;
    }

    // ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ───────────────────────────

    byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        rng.nextBytes(b);
        return b;
    }

    // ── grant construction (§4.4 / §5.4) ───────────────────────────────────────────

    static EcfValue.Map scopeCbor(List<String> incl, List<String> excl) {
        if (excl != null) {
            return Cbor.map("include", arr(incl), "exclude", arr(excl));
        }
        return Cbor.map("include", arr(incl));
    }

    private static EcfValue.Array arr(List<String> ss) {
        List<EcfValue> items = new ArrayList<>(ss.size());
        for (String s : ss) {
            items.add(new EcfValue.Text(s));
        }
        return new EcfValue.Array(items);
    }

    /** Build a grant cbor-map. {@code peers} null → omit (defaults to local at check time). */
    public static EcfValue.Map grant(List<String> handlers, List<String> resources,
                                     List<String> operations, List<String> peers) {
        List<EcfValue.Map.Entry> pairs = new ArrayList<>();
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("handlers"), scopeCbor(handlers, null)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("resources"), scopeCbor(resources, null)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("operations"), scopeCbor(operations, null)));
        if (peers != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("peers"), scopeCbor(peers, null)));
        }
        return new EcfValue.Map(pairs);
    }

    /** The §4.4 discovery floor: every authenticated identity gets at least this. */
    private List<EcfValue.Map> discoveryFloor() {
        List<EcfValue.Map> out = new ArrayList<>();
        out.add(grant(List.of("system/tree"), List.of("system/type/*", "system/handler/*"),
                List.of("get"), null));
        out.add(grant(List.of("system/capability"), List.of(), List.of("request"), null));
        return out;
    }

    /** Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants). */
    private List<EcfValue.Map> openGrantsScope() {
        List<EcfValue.Map> out = new ArrayList<>();
        out.add(grant(List.of("*"), List.of("*", "/*/*"), List.of("*"), List.of("*")));
        return out;
    }

    /** Full owner authority over the local namespace /{peer_id}/* (§6.9a). */
    private List<EcfValue.Map> ownerGrants() {
        List<EcfValue.Map> out = new ArrayList<>();
        out.add(grant(List.of("*"), List.of("*"), List.of("*"), List.of(localPeer)));
        return out;
    }

    // ── token mint (§4.4 / §6.9a) ───────────────────────────────────────────────────

    /** A minted token + its signature. */
    record Minted(Entity token, Entity signature) { }

    private Minted mintToken(byte[] granteeHash, List<EcfValue.Map> grants, byte[] parent)
            throws EntityCryptoException {
        return mintTokenAt(granteeHash, grants, parent, Capability.nowMs(), null);
    }

    /**
     * {@link #mintToken} with an explicit {@code created_at} and §5.6 {@code expires_at}.
     *
     * <p>The two are passed together on purpose: the §5.6 duration terms are relative to
     * {@code createdAt}, so sampling the clock twice would let the emitted
     * {@code created_at} and the expiry derived from it skew apart. Callers computing a
     * ceiling sample once and thread it through.
     */
    private Minted mintTokenAt(byte[] granteeHash, List<EcfValue.Map> grants, byte[] parent,
            long createdAt, BigInteger expiresAt) throws EntityCryptoException {
        List<EcfValue.Map.Entry> pairs = new ArrayList<>();
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("granter"),
                new EcfValue.Bytes(identity.identityHash())));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("grantee"),
                new EcfValue.Bytes(granteeHash)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("grants"), grantsArray(grants)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("created_at"),
                EcfValue.Int.of(createdAt)));
        if (expiresAt != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("expires_at"),
                    new EcfValue.Int(expiresAt)));
        }
        if (parent != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("parent"), new EcfValue.Bytes(parent)));
        }
        Entity token = Entity.make("system/capability/token", new EcfValue.Map(pairs));
        return new Minted(token, identity.sign(token));
    }

    /**
     * Convert a DURATION term ({@code ttl_ms}) to an absolute timestamp, reporting
     * whether it contributes a ceiling at all (§5.6 MIN_DEFINED rule 1 + rule 3).
     *
     * <p>Overflow DROPS the term — treated as absent, exactly as a null term is. It MUST
     * NOT wrap and MUST NOT saturate: saturation encodes differently from absence and
     * manufactures {@code expires_at == 2^64-1}, a finite bound no reader can distinguish
     * from a deliberate one. {@code BigInteger} does not overflow, so this is a
     * DELIBERATE range check — a bignum type that "just does the arithmetic" silently
     * never fires rule 3.
     *
     * <p>{@code ttl == 0} is NOT special-cased, deliberately: rule 2 makes 0 a DEFINED
     * value yielding {@code createdAt} (expire immediately). Letting it fall out of the
     * arithmetic is what keeps it from collapsing into the absent/null "no bound"
     * spelling — the collapse {@code ttl_zero_and_overflow} caught here.
     */
    private static BigInteger durationTerm(long createdAt, BigInteger ttl) {
        if (ttl == null || ttl.signum() < 0) {
            return null;
        }
        BigInteger sum = BigInteger.valueOf(createdAt).add(ttl);
        return sum.compareTo(UINT64_MAX_J) > 0 ? null : sum;
    }

    /** §5.6 MIN_DEFINED: the minimum over the DEFINED terms only; null when none is. */
    private static BigInteger minDefined(BigInteger... terms) {
        BigInteger out = null;
        for (BigInteger t : terms) {
            if (t != null && (out == null || t.compareTo(out) < 0)) {
                out = t;
            }
        }
        return out;
    }

    private static final BigInteger UINT64_MAX_J =
            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    /**
     * The {@code ttl_ms} of the policy entry that ceilings THIS caller (§6.2 CAP-5), via
     * the same dual-form lookup the §4.4 authenticate path uses
     * (hex → Base58 → {@code default}).
     *
     * <p>This is the term that makes policy withdrawal bounded on the {@code request}
     * path: the entry's {@code ttl_ms} is the withdrawal latency for tokens already issued.
     */
    private BigInteger policyTtlMs(byte[] granteeHash) {
        String base = "/" + localPeer + "/system/capability/policy/";
        Entity entry = store.getAt(base + Cbor.hex(granteeHash));
        if (entry == null) {
            Entity peerE = store.getByHash(granteeHash);
            byte[] pub = (peerE != null) ? peerE.bytes("public_key") : null;
            if (pub != null) {
                entry = store.getAt(base + Identity.peerIdOfPublicKey(pub));
            }
        }
        if (entry == null) {
            entry = store.getAt(base + "default");
        }
        return (entry != null) ? entry.uint("ttl_ms") : null;
    }

    private static EcfValue grantsArray(List<EcfValue.Map> grants) {
        List<EcfValue> items = new ArrayList<>(grants.size());
        items.addAll(grants);
        return new EcfValue.Array(items);
    }

    private List<Envelope.Included> capIncluded(Minted m) {
        List<Envelope.Included> inc = new ArrayList<>();
        inc.add(new Envelope.Included(m.token().hash(), m.token()));
        inc.add(new Envelope.Included(identity.identityHash(), identity.peerEntity()));
        inc.add(new Envelope.Included(m.signature().hash(), m.signature()));
        return inc;
    }

    // ── §6.9a seed policy (authenticate-time grant derivation) ────────────────────────

    private List<EcfValue.Map> seedEntryGrants(Entity e) {
        if (e.type().equals("system/capability/token")) {
            String sigPath = "/" + localPeer + "/system/signature/" + Cbor.hex(e.rawHash());
            Entity sgn = store.getAt(sigPath);
            if (sgn != null && Identity.verifySignature(sgn, identity.peerEntity())) {
                List<EcfValue.Map> g = Cbor.mapList(e.data(), "grants");
                return (g != null) ? g : List.of();
            }
            return List.of();
        }
        if (e.type().equals("system/capability/policy-entry")) {
            List<EcfValue.Map> g = Cbor.mapList(e.data(), "grants");
            return (g != null) ? g : List.of();
        }
        return List.of();
    }

    /** §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
     *  then UNION the matched scope with the §4.4 discovery floor. */
    private List<EcfValue.Map> deriveSeedGrants(Entity remotePeer, String remotePeerId) {
        String base = "/" + localPeer + "/system/capability/policy/";
        Entity entry = store.getAt(base + Cbor.hex(remotePeer.rawHash()));
        if (entry == null) {
            entry = store.getAt(base + remotePeerId);
        }
        if (entry == null) {
            entry = store.getAt(base + "default");
        }
        List<EcfValue.Map> floor = discoveryFloor();
        if (entry == null) {
            return floor;
        }
        List<EcfValue.Map> policy = seedEntryGrants(entry);
        if (policy.isEmpty()) {
            return floor;
        }
        List<EcfValue.Map> out = new ArrayList<>(floor);
        out.addAll(policy);
        return out;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Handlers (single-dispatch operation ladders — the static-OO idiom axis)
    // ══════════════════════════════════════════════════════════════════════════════

    private static List<String> strArray(Entity exec, String key) {
        Entity params = exec.entityField("params");
        return (params != null) ? Cbor.textList(params.data(), key) : null;
    }

    /** §4.1 / §4.6 — the connect handler (hello / authenticate). */
    private final class ConnectHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) throws EntityCryptoException {
            return switch (op) {
                case "hello" -> hello(ctx);
                case "authenticate" -> authenticate(ctx);
                // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
                // 400 invalid_request, not the 501 every other handler answers. The table
                // separates a STATE conflict from an UNKNOWN operation because they select
                // different remedies — "an unknown connect operation is not out of order at
                // all; it exists in no state", so connection_sequence_error would point the
                // caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
                // scoped "in any state", so this arm covers pre-handshake AND established;
                // the genuine sequence cases are refused inside hello/authenticate, with 409.
                //
                // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
                // (§3.3's 501 row, §6.2) is a different contract and is separately gated;
                // moving the shared 501 would trade one green check for another.
                default -> Outcome.err(400, "invalid_request", "connect: unknown operation " + op);
            };
        }

        private Outcome hello(HandlerContext ctx) {
            Conn conn = ctx.conn();
            Entity exec = ctx.exec();
            if (conn.established) {
                return Outcome.err(409, "connection_already_established");
            }
            // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
            // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
            // implement arriving in a state that forbids it — the same class as
            // connection_already_established above, taking the same 409. A half-open
            // connection is NOT established, so the guard above cannot reach it; §4.7
            // names this gap explicitly because two adjacent rules each look like they
            // cover it and neither does.
            if (conn.issuedNonce != null) {
                return Outcome.err(409, "connection_sequence_error");
            }
            // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
            List<String> hf = strArray(exec, "hash_formats");
            boolean hashOk = (hf == null) || hf.contains("ecfv1-sha256");
            List<String> kt = strArray(exec, "key_types");
            boolean keyOk = (kt == null) || kt.contains("ed25519");
            if (!hashOk) {
                return Outcome.err(400, "incompatible_hash_format");
            }
            if (!keyOk) {
                return Outcome.err(400, "unsupported_key_type");
            }
            Entity params = exec.entityField("params");
            String initiator = (params != null) ? params.text("peer_id") : null;
            // §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
            // is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
            // its `peer_id` — so a hello may advertise a perfectly good accept-set and
            // still name an identity we cannot verify. Checking only the array leaves
            // that MUST unenforced at hello, which is where §4.5 wants it; authenticate
            // catches it one leg later, which is conformant but non-canonical.
            //
            // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
            // field, not a key_type we lack, and authenticate already refuses it.
            if (initiator != null) {
                try {
                    if (org.entitycore.protocol.crypto.PeerId.parse(initiator).keyType()
                            != org.entitycore.protocol.crypto.PeerId.KEY_TYPE_ED25519) {
                        return Outcome.err(400, "unsupported_key_type");
                    }
                } catch (Exception ignore) {
                    // unparseable peer_id → not our question; authenticate refuses it
                }
            }
            // §4.5 `protocols` — the one negotiated field Required with NO default, so
            // there is no floor to fall back to, and its two failure modes carry
            // different codes on purpose (§4.5 table row / §4.7 row 1):
            //
            //   absent or empty     -> 400 invalid_request       (a malformed hello)
            //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
            //
            // "a caller that named no version cannot be told the comparison failed" —
            // the remedies differ (send the field vs change the version) and §4.7 exists
            // so the code selects the remedy. The vocabulary is §8.4's protocol version
            // identifiers, today the single entity-core/1.0.
            //
            // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
            // precedence between the three, so a hello disjoint in more than one
            // dimension may be refused on any of them — but the choice is OBSERVABLE, and
            // the reference peer refuses key_types first. Checking protocols first is
            // equally spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
            // because that probe's own hello carries protocols ["entity-core/v7"] — a
            // spec-line name, not a §8.4 identifier (F56).
            List<String> protos = strArray(exec, "protocols");
            if (protos == null || protos.isEmpty()) {
                return Outcome.err(400, "invalid_request", "hello: protocols absent or empty");
            }
            if (!protos.contains("entity-core/1.0")) {
                return Outcome.err(400, "incompatible_protocol");
            }
            byte[] nonce = randomBytes(32);
            conn.helloPeerId = initiator;
            conn.issuedNonce = nonce;
            return Outcome.ok(Entity.make("system/protocol/connect/hello",
                    Cbor.map(
                            "peer_id", localPeer,
                            "nonce", Cbor.bytes(nonce),
                            "protocols", Cbor.textArray("entity-core/1.0"),
                            "timestamp", EcfValue.Int.of(Capability.nowMs()),
                            "hash_formats", Cbor.textArray("ecfv1-sha256"),
                            "key_types", Cbor.textArray("ed25519"))));
        }

        private Outcome authenticate(HandlerContext ctx) throws EntityCryptoException {
            Conn conn = ctx.conn();
            Entity exec = ctx.exec();
            if (conn.established) {
                // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
                // single-use nonce. The anti-replay property is the MUST and the mechanism
                // (established-state tracking) is impl-defined, but the STATUS is pinned to
                // 401 invalid_nonce — a 409 state-conflict under-signals the replay.
                return Outcome.err(401, "invalid_nonce");
            }
            if (conn.issuedNonce == null) {
                return Outcome.err(401, "invalid_nonce");          // authenticate before hello
            }
            Entity auth = exec.entityField("params");
            if (auth == null) {
                return Outcome.err(401, "authentication_failed");
            }
            // §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-0x01 peer_id.
            String ktField = auth.text("key_type");
            boolean badKt = (ktField != null && !ktField.equals("ed25519"));
            byte[] pub = auth.bytes("public_key");
            if (!badKt && pub != null && pub.length != 32) {
                badKt = true;
            }
            String claimed = auth.text("peer_id");
            if (!badKt && claimed != null) {
                try {
                    if (org.entitycore.protocol.crypto.PeerId.parse(claimed).keyType()
                            != org.entitycore.protocol.crypto.PeerId.KEY_TYPE_ED25519) {
                        badKt = true;
                    }
                } catch (Exception ignore) {
                    // unparseable peer_id → fall through to the step checks below
                }
            }
            if (badKt) {
                return Outcome.err(400, "unsupported_key_type");
            }
            byte[] echoed = auth.bytes("nonce");
            // step 1: nonce-echo
            if (!(echoed != null && Identity.octetsEqual(echoed, conn.issuedNonce))) {
                return Outcome.err(401, "invalid_nonce");
            }
            if (pub == null) {
                return Outcome.err(401, "authentication_failed");
            }
            // step 2: proof of possession
            Entity sgn = Capability.findSignature(auth.rawHash(), ctx.included());
            boolean sigOk = false;
            if (sgn != null) {
                byte[] sb = sgn.bytes("signature");
                if (sb != null) {
                    sigOk = org.entitycore.protocol.crypto.Ed.verify(
                            pub, auth.rawHash(), sb, org.entitycore.protocol.crypto.PeerId.Curve.ED25519);
                }
            }
            if (!sigOk) {
                return Outcome.err(401, "authentication_failed");
            }
            // step 3: identity binding
            if (!(claimed != null && claimed.equals(Identity.peerIdOfPublicKey(pub)))) {
                return Outcome.err(401, "identity_mismatch");
            }
            if (conn.helloPeerId != null && !conn.helloPeerId.equals(claimed)) {
                return Outcome.err(401, "identity_mismatch");
            }
            // success: mint the initial capability for the remote (§4.4 / §6.9a)
            Entity remotePeer = Identity.peerEntityOfPublicKey(pub);
            List<EcfValue.Map> grants = deriveSeedGrants(remotePeer, claimed);
            Minted m = mintToken(remotePeer.hash(), grants, null);
            conn.established = true;
            return Outcome.ok(
                    Entity.make("system/capability/grant", Cbor.map("token", Cbor.bytes(m.token().hash()))),
                    capIncluded(m));
        }
    }

    /** §6.3 — the tree handler (get / put). */
    private final class TreeHandler implements Handler {
        /**
         * RESOLVE THE OPERATION FIRST; only then run the §3.3 resource ladder. This switch
         * is what makes that true: a handler that validates the resource first answers a
         * RESOURCE fault for an unknown-OPERATION request, so {@code system/tree:bogusop}
         * with no {@code resource} reports {@code ambiguous_resource} where §3.3 pins
         * {@code 501 unsupported_operation}.
         */
        @Override
        public Outcome handle(String op, HandlerContext ctx) {
            return switch (op) {
                case "get" -> get(ctx);
                case "put" -> put(ctx);
                default -> Outcome.err(501, "unsupported_operation", op);
            };
        }

        private Outcome get(HandlerContext ctx) {
            Entity exec = ctx.exec();
            // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
            // `resource.targets`: a handler that counts the effective list and then
            // indexes `targets[0]` has implemented the arithmetic completely and is still
            // reading a path no authorization covered. This peer read `targets.get(0)`
            // with no count at all, so `targets:[a,b] exclude:[a]` served `a`.
            Capability.EffectiveTargets eff = Capability.effectiveTargets(localPeer, exec);
            if (!eff.hasResource()) {
                // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
                // IS WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is
                // scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get`
                // does not. For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
                // present-but-empty case by whether the absent case is WIDER than the
                // request — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty.
                //
                // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
                // resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
                // listing", self-excluded case "400 path_required". Both arms are pinned
                // by text and neither is this peer's choice.
                return buildListing(ctx, "/" + localPeer + "/");
            }
            if (eff.survivors().isEmpty()) {
                // `resource` PRESENT, every target carved out by the caller's own exclude.
                // Serving it the absent case "answers a request for one excluded path with
                // a listing of the tree" (EXTENSION-TREE §2.2a).
                return Outcome.err(400, "path_required", "tree: effective target list is empty");
            }
            if (eff.survivors().size() > 1) {
                return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target");
            }
            String target = eff.survivors().get(0);
            if (!pathFlexOk(target)) {
                return Outcome.err(400, "invalid_path", target);
            }
            if (target.isEmpty() || target.charAt(target.length() - 1) == '/') {
                return buildListing(ctx, Capability.canonicalize(localPeer, target));
            }
            // A resource-requiring operation takes a CONCRETE path (0.8.2.20). Without
            // this the pattern is looked up as a literal and answers `404 not_found`,
            // which names the wrong fault: the request is malformed, the tree is fine.
            if (isPatternPath(target)) {
                return Outcome.err(400, "malformed_resource", target);
            }
            String path = Capability.canonicalize(localPeer, target);
            // §6.3: the handler MUST verify the CALLER's capability covers the path it is
            // about to read. NOT a secondary check — the dispatch-level check never saw
            // this path if the caller excluded it.
            if (!authorizePath(ctx, "get", path)) {
                return Outcome.err(403, "capability_denied", "capability does not cover path");
            }
            Entity e = store.getAt(path);
            if (e == null) {
                return Outcome.err(404, "not_found", path);
            }
            Entity params = exec.entityField("params");
            String mode = (params != null) ? params.text("mode") : null;
            if ("hash".equals(mode)) {
                return Outcome.ok(Entity.make("system/hash", Cbor.map("hash", Cbor.bytes(e.hash()))));
            }
            return Outcome.ok(e);
        }

        /**
         * §6.3's per-path authorization, against the CALLER's verified capability and the
         * OWNING handler's pattern — both carried on the context by the dispatcher, which
         * already computed them.
         *
         * <p>An UNAUTHENTICATED context (no capability) is NOT filtered: the filter's
         * subject is "the caller's verified capability", and where there is none there is
         * no caller to narrow. That is the bootstrap path, and it matches both vanguard
         * peers. On this peer every reachable tree dispatch carries a capability —
         * {@code dispatchInner} refuses a missing one with 403 before any handler runs, and
         * the connect handler is the sole null case — so the branch is unreachable today
         * and is written for the rule rather than for a caller.
         */
        private boolean authorizePath(HandlerContext ctx, String operation, String path) {
            if (ctx.callerCap() == null) {
                return true;
            }
            return Capability.checkPathPermission(localPeer, operation, path, ctx.callerCap(), ctx.pattern());
        }

        /**
         * A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes
         * a CONCRETE path (0.8.2.20), and a trailing {@code /} is a listing request rather
         * than a pattern — only a {@code *} makes it one.
         */
        private boolean isPatternPath(String target) {
            return target.indexOf('*') >= 0;
        }

        /**
         * Digest byte length for a {@code content_hash_format} code per the §1.2 seed
         * table, or -1 when this peer cannot VERIFY that code. The total wire length is
         * this plus the varint prefix, which is not a constant of the code (§7.3):
         * codes &ge; 0x80 occupy more than one byte.
         */
        private int hashDigestLen(long formatCode) {
            if (formatCode == 0x00L) {
                return 32;
            }
            if (formatCode == 0x01L) {
                return 48;
            }
            return -1;
        }

        /**
         * §6.3's {@code put} admission ladder (normative, 0.8.2.11).
         *
         * <p>{@code put} is a RECEIPT path: the submitter authors the entity, the peer
         * validates what it received (§1.8 item 1) and MUST NOT author a submitted
         * entity's {@code content_hash} on the submitter's behalf. Two ordered steps:
         *
         * <ol>
         * <li>STRUCTURE — a map carrying a non-empty text {@code type}, a PRESENT
         * {@code data} (any CBOR value; null is a legal payload), and a
         * {@code content_hash} that is a well-formed {@code system/hash} whose total
         * byte length matches its format code (§1.2). Any failure &rarr; 400
         * {@code invalid_request}. A well-formed hash naming a format code this peer
         * cannot verify is the separate §1.2 ingest-dispatch case &rarr; 400
         * {@code unsupported_content_hash_format}.</li>
         * <li>HASH — carried {@code content_hash} vs {@code content_hash({type, data})}.
         * Disagreement &rarr; 400 {@code hash_mismatch}.</li>
         * </ol>
         *
         * <p>Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
         * 2's inputs are exactly what step 1 establishes, so a submission that is both
         * malformed and mis-hashed is step 1's and answers {@code invalid_request}.
         *
         * <p>Structural admission is not semantic validation: {@code data} is never
         * checked against the type named by {@code type}.
         *
         * <p>Returns the admitted entity in {@code entity}, or the refusal in
         * {@code refusal} — exactly one is non-null.
         */
        private record PutAdmission(Entity entity, Outcome refusal) { }

        private PutAdmission admitPut(EcfValue v) {
            if (!(v instanceof EcfValue.Map m)) {
                return refusePut("invalid_request", "put: entity is not a map");
            }
            if (!(m.get("type") instanceof EcfValue.Text t) || t.value().isEmpty()) {
                return refusePut("invalid_request",
                        "put: entity.type absent, empty or not a text string");
            }
            EcfValue data = m.get("data");
            if (data == null) {
                return refusePut("invalid_request", "put: entity.data absent");
            }
            if (!(m.get("content_hash") instanceof EcfValue.Bytes chb)
                    || chb.octets().length == 0) {
                return refusePut("invalid_request",
                        "put: entity.content_hash absent or not a byte string");
            }
            byte[] carried = chb.octets();
            org.entitycore.protocol.codec.Varint.Decoded decoded;
            try {
                decoded = org.entitycore.protocol.codec.Varint.decode(carried, 0);
            } catch (org.entitycore.protocol.codec.EntityCodecException e) {
                return refusePut("invalid_request",
                        "put: entity.content_hash is not a well-formed system/hash");
            }
            int digestLen = hashDigestLen(decoded.value());
            if (digestLen < 0) {
                // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it.
                // NOT invalid_request: the shape is fine, the algorithm is what we lack.
                return refusePut("unsupported_content_hash_format",
                        "put: unsupported content_hash_format");
            }
            if (carried.length != decoded.next() + digestLen) {
                return refusePut("invalid_request",
                        "put: content_hash length does not match its format code");
            }
            byte[] computed;
            try {
                computed = org.entitycore.protocol.crypto.ContentHash.compute(
                        EcfValue.Map.of("type", t, "data", data), (int) decoded.value());
            } catch (org.entitycore.protocol.codec.EntityCodecException e) {
                return refusePut("hash_mismatch",
                        "put: content_hash does not match content_hash({type, data})");
            }
            if (!java.util.Arrays.equals(computed, carried)) {
                return refusePut("hash_mismatch",
                        "put: content_hash does not match content_hash({type, data})");
            }
            // The carried hash IS the entity's address; recomputing it into the store
            // would be the authoring arm §6.3 forbids.
            return new PutAdmission(Entity.admitted(t.value(), data, carried), null);
        }

        private PutAdmission refusePut(String code, String message) {
            return new PutAdmission(null, Outcome.err(400, code, message));
        }

        private Outcome put(HandlerContext ctx) {
            Entity exec = ctx.exec();
            // Same ladder as `get`, with the two empties COLLAPSED rather than split:
            // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an
            // empty effective list IS the absent case" applies in its unscoped form and
            // both empties answer `path_required`. That is the same table `get`'s branch
            // cites, one row down.
            //
            // Note the code 0.8.2.20 forces: a MISSING target is `path_required`, never
            // `ambiguous_resource` — 0.8.2.20 names that inversion outright, because
            // *supply a resource* is not *disambiguate your request* and the code is what
            // selects the remedy. This peer answered `ambiguous_resource` for both.
            Capability.EffectiveTargets eff = Capability.effectiveTargets(localPeer, exec);
            if (!eff.hasResource() || eff.survivors().isEmpty()) {
                return Outcome.err(400, "path_required", "tree: put requires a resource target");
            }
            if (eff.survivors().size() > 1) {
                return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target");
            }
            String target = eff.survivors().get(0);
            if (!pathFlexOk(target)) {
                return Outcome.err(400, "invalid_path", target);
            }
            if (isPatternPath(target)) {
                return Outcome.err(400, "malformed_resource", target);
            }
            String path = Capability.canonicalize(localPeer, target);
            // §6.3 / §6.8: the caller's capability MUST cover the path it names.
            if (!authorizePath(ctx, "put", path)) {
                return Outcome.err(403, "capability_denied", "capability does not cover path");
            }
            Entity params = exec.entityField("params");
            EcfValue rawEntity = (params != null) ? params.field("entity") : null;
            byte[] expected = (params != null) ? params.bytes("expected_hash") : null;
            String current = store.hashAt(path);
            boolean casOk;
            if (expected == null) {
                casOk = true;
            } else if (isZeroHash(expected)) {
                casOk = (current == null);
            } else {
                casOk = current != null && current.equals(Cbor.hex(expected));
            }
            if (!casOk) {
                return Outcome.err(409, "hash_mismatch", path);
            }
            if (rawEntity == null) {
                return Outcome.err(400, "unexpected_params", "put: missing entity");
            }
            PutAdmission admission = admitPut(rawEntity);
            if (admission.refusal() != null) {
                return admission.refusal();
            }
            Entity entity = admission.entity();
            store.bind(path, entity);
            return Outcome.ok(Entity.make("system/hash", Cbor.map("hash", Cbor.bytes(entity.hash()))));
        }

        /**
         * Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
         *
         * <p><em>"When any handler returns a multi-entry result whose entries are tree
         * paths, each entry MUST be individually checked using
         * {@code check_path_permission}. Entries for which {@code check_path_permission}
         * returns DENY MUST be omitted. The result's {@code count} field MUST reflect the
         * filtered entry count, not the source tree's total count."</em>
         *
         * <p>This is the read path at its highest volume and it is the reason 0.8.2.21
         * refused to carve reads out of the caller-specified-path rule: an unfiltered
         * listing discloses the EXISTENCE of every binding under a prefix to a caller whose
         * capability covers none of them.
         *
         * <p>The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the
         * subject, and testing the prefix would deny a listing to a caller whose grant
         * covers children but not the node above them, which is the ordinary shape of a
         * narrowed grant.
         */
        private Outcome buildListing(HandlerContext ctx, String path) {
            List<Store.ListEntry> entries = new ArrayList<>();
            for (Store.ListEntry row : store.listing(path)) {
                // §6.3's per-entry check (0.8.2.21/.22). The peer-root prefix ends in "/";
                // guard against an empty segment when joining the entry name.
                String entryPath = (path.endsWith("/") ? path : path + "/") + row.segment();
                if (!authorizePath(ctx, "get", entryPath)) {
                    continue;
                }
                if (row.hashHex() != null && !row.hasChildren()
                        && isDeletionMarker(Cbor.unhex(row.hashHex()))) {
                    continue;
                }
                entries.add(row);
            }
            List<EcfValue.Map.Entry> entryPairs = new ArrayList<>(entries.size());
            for (Store.ListEntry row : entries) {
                EcfValue.Map data = (row.hashHex() != null)
                        ? Cbor.map("has_children", row.hasChildren(),
                                   "hash", Cbor.bytes(Cbor.unhex(row.hashHex())))
                        : Cbor.map("has_children", row.hasChildren());
                Entity le = Entity.make("system/tree/listing-entry", data);
                entryPairs.add(new EcfValue.Map.Entry(new EcfValue.Text(row.segment()), le.toCbor()));
            }
            return Outcome.ok(Entity.make("system/tree/listing",
                    Cbor.map(
                            "path", path,
                            "entries", new EcfValue.Map(entryPairs),
                            // `count` follows the FILTERED total. A count that still
                            // reports the source total is the disclosure the rule exists
                            // to prevent.
                            "count", EcfValue.Int.of(entries.size()),
                            "offset", EcfValue.Int.of(0))));
        }

        private boolean isDeletionMarker(byte[] h) {
            Entity e = store.getByHash(h);
            return e != null && e.type().equals("system/deletion-marker");
        }
    }

    /**
     * EXTENSION-TYPE — the system/type:validate handler (a real body, replacing the S3
     * placeholder echo). Validates an entity against a registered §2 type definition:
     * checks every required (non-optional) field of the type is present in the entity's
     * data and reports any unevaluated (extra) fields. Returns a
     * {@code system/type/validate-result} {@code {valid, violations?, unevaluated_fields?}}.
     *
     * <p>Scope note: the {@code type} category is an EXTENSION category (auto-skipped under
     * {@code --profile core}), so this is not on the core gate — but it is a genuine,
     * cohort-parity peer surface (the deeper type-constraint analysis — byte_size, union_of
     * membership, nested map_of/array_of recursion — is EXTENSION-TYPE v1.1 and intentionally
     * out of this core body's scope; structural required/unevaluated checks are the floor).
     */
    private final class TypeHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) {
            if (!op.equals("validate")) {
                return Outcome.err(501, "unsupported_operation", op);
            }
            Entity req = ctx.params();
            if (req == null) {
                return Outcome.err(400, "invalid_params", "validate requires a params entity");
            }
            Entity subject = req.entityField("entity");
            if (subject == null) {
                return Outcome.err(400, "unexpected_params", "validate-request missing entity");
            }
            // Resolve the type definition: explicit type_path wins, else the subject's own type.
            String typePath = req.text("type_path");
            String typeName = (typePath != null) ? typePath : subject.type();
            Entity typeDef = store.getAt(abs("system/type/" + typeName));
            if (typeDef == null) {
                // Unknown type → cannot evaluate; report a single violation (not a 4xx —
                // the request itself is well-formed; the verdict is "not valid").
                List<EcfValue> vs = new ArrayList<>();
                vs.add(Cbor.map(
                        "kind", "unknown_type",
                        "field", typeName,
                        "message", "no registered type definition for " + typeName));
                return Outcome.ok(Entity.make("system/type/validate-result",
                        Cbor.map("valid", false, "violations", Cbor.array(vs))));
            }
            EcfValue.Map fields = typeDef.mapField("fields");
            EcfValue.Map subjData = Cbor.asMap(subject.rawData());
            List<EcfValue> violations = new ArrayList<>();
            List<String> unevaluated = new ArrayList<>();
            java.util.Set<String> declared = new java.util.HashSet<>();
            if (fields != null) {
                for (EcfValue.Map.Entry fe : fields.entries()) {
                    if (!(fe.key() instanceof EcfValue.Text fk)) {
                        continue;
                    }
                    declared.add(fk.value());
                    EcfValue.Map spec = Cbor.asMap(fe.value());
                    boolean optional = spec != null && Cbor.isTrue(spec.get("optional"));
                    boolean present = subjData != null && subjData.get(fk.value()) != null;
                    if (!optional && !present) {
                        violations.add(Cbor.map(
                                "kind", "missing_required_field",
                                "field", fk.value(),
                                "message", "required field absent"));
                    }
                }
            }
            // Unevaluated (extra) fields not declared by the type — §2 reporting, not a hard fail.
            if (subjData != null) {
                for (EcfValue.Map.Entry se : subjData.entries()) {
                    if (se.key() instanceof EcfValue.Text sk && !declared.contains(sk.value())) {
                        unevaluated.add(sk.value());
                    }
                }
            }
            boolean valid = violations.isEmpty();
            List<EcfValue.Map.Entry> result = new ArrayList<>();
            result.add(new EcfValue.Map.Entry(new EcfValue.Text("valid"),
                    valid ? EcfValue.Bool.TRUE : EcfValue.Bool.FALSE));
            if (!violations.isEmpty()) {
                result.add(new EcfValue.Map.Entry(new EcfValue.Text("violations"),
                        Cbor.array(violations)));
            }
            if (!unevaluated.isEmpty()) {
                result.add(new EcfValue.Map.Entry(new EcfValue.Text("unevaluated_fields"),
                        Cbor.textArray(unevaluated.toArray(new String[0]))));
            }
            return Outcome.ok(Entity.make("system/type/validate-result", new EcfValue.Map(result)));
        }
    }

    /** §6.2 — the capability handler (request / delegate / revoke / configure). */
    private final class CapabilityHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) throws EntityCryptoException {
            return switch (op) {
                case "request" -> request(ctx);
                case "delegate" -> delegate(ctx);
                case "revoke" -> revoke(ctx);
                case "configure" -> configure(ctx);
                default -> Outcome.err(501, "unsupported_operation", op);
            };
        }

        private Outcome request(HandlerContext ctx) throws EntityCryptoException {
            Entity exec = ctx.exec();
            Entity params = exec.entityField("params");
            byte[] author = exec.bytes("author");
            if (author == null) {
                return Outcome.err(403, "capability_denied");
            }
            return mintBounded(ctx.callerCap(), reqGrants(params), author, null, params);
        }

        private Outcome delegate(HandlerContext ctx) throws EntityCryptoException {
            Entity exec = ctx.exec();
            Entity params = exec.entityField("params");
            byte[] author = exec.bytes("author");
            byte[] ph = (params != null) ? params.bytes("parent") : null;
            if (ph == null) {
                return Outcome.err(400, "unexpected_params", "delegate: parent required");
            }
            if (isZeroHash(ph)) {
                return Outcome.err(400, "unexpected_params", "delegate: zero parent");
            }
            if (!(author != null && Identity.octetsEqual(author, identity.identityHash()))) {
                return Outcome.err(501, "unsupported_operation", "delegate: same-peer-only in v1");
            }
            return mintBounded(ctx.callerCap(), reqGrants(params), author, ph, params);
        }

        private Outcome revoke(HandlerContext ctx) {
            Entity exec = ctx.exec();
            Entity params = exec.entityField("params");
            byte[] tokenH = (params != null) ? params.bytes("token") : null;
            if (tokenH == null) {
                return Outcome.err(400, "unexpected_params", "revoke: missing token");
            }
            if (isZeroHash(tokenH)) {
                return Outcome.err(400, "unexpected_params", "revoke: zero token");
            }
            Entity marker = Entity.make("system/capability/revocation",
                    Cbor.map("token", Cbor.bytes(tokenH), "revoked_at", EcfValue.Int.of(Capability.nowMs())));
            store.bind("/" + localPeer + "/system/capability/revocations/" + Cbor.hex(tokenH), marker);
            return Outcome.ok(Wire.emptyParams());
        }

        private Outcome configure(HandlerContext ctx) {
            Entity exec = ctx.exec();
            Entity params = exec.entityField("params");
            String pp = (params != null) ? params.text("peer_pattern") : null;
            if (pp == null) {
                return Outcome.err(400, "unexpected_params", "configure: missing peer_pattern");
            }
            boolean isHex = pp.length() == 66 && pp.chars().allMatch(
                    c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
            if (!(pp.equals("default") || isHex || Capability.isPeerId(pp))) {
                return Outcome.err(400, "invalid_peer_pattern", pp);
            }
            store.bind("/" + localPeer + "/system/capability/policy/" + pp, params);
            return Outcome.ok(Wire.emptyParams());
        }

        private Outcome mintBounded(Entity callerCap, List<EcfValue.Map> reqGrants,
                                    byte[] granteeHash, byte[] parent, Entity params)
                throws EntityCryptoException {
            boolean bounded = false;
            if (callerCap != null) {
                List<Capability.GrantRec> parentGrants = Capability.grantsOfToken(callerCap);
                bounded = true;
                for (EcfValue.Map cgRaw : reqGrants) {
                    Capability.GrantRec c = Capability.parseGrant(cgRaw);
                    boolean some = false;
                    for (Capability.GrantRec pg : parentGrants) {
                        // self-issued mint: granter = local → both frames local.
                        if (Capability.grantSubset(localPeer, localPeer, localPeer, c, pg)) {
                            some = true;
                            break;
                        }
                    }
                    if (!some) {
                        bounded = false;
                        break;
                    }
                }
            }
            if (!bounded) {
                return Outcome.err(403, "scope_exceeds_authority");
            }
            // §6.2 CAP-5 / §5.6 MIN_DEFINED. `request` mints a ROOT token (parent: null),
            // so §5.6's parent-child attenuation rule never reaches it — without this
            // bound, temporal attenuation is the one dimension a requester can escape.
            //
            //   expires_at = MIN_DEFINED(
            //       caller_capability.expires_at,      // ABSOLUTE — enters directly
            //       created_at + policy_entry.ttl_ms,  // DURATION — converted first
            //       created_at + request.ttl_ms)       // DURATION — converted first
            //
            // Term SHAPE is the trap: mixing a duration in unconverted yields a timestamp
            // near the epoch and clamps every token to already-expired. The disposition is
            // a CLAMP, never a rejection — an over-long request from a bounded caller
            // mints at 200 with the clamped value; rejecting it is non-conformant.
            long createdAt = Capability.nowMs();
            BigInteger expiresAt = minDefined(
                    (callerCap != null) ? callerCap.uint("expires_at") : null,
                    durationTerm(createdAt, policyTtlMs(granteeHash)),
                    durationTerm(createdAt, (params != null) ? params.uint("ttl_ms") : null));
            Minted m = mintTokenAt(granteeHash, reqGrants, parent, createdAt, expiresAt);
            return Outcome.ok(
                    Entity.make("system/capability/grant", Cbor.map("token", Cbor.bytes(m.token().hash()))),
                    capIncluded(m));
        }
    }

    /** §6.2 / §6.13(a) — the handlers handler (register / unregister). */
    private final class HandlersHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) throws EntityCryptoException {
            return switch (op) {
                case "register" -> register(ctx);
                case "unregister" -> unregister(ctx);
                default -> Outcome.err(501, "unsupported_operation", op);
            };
        }

        private Outcome register(HandlerContext ctx) throws EntityCryptoException {
            Entity exec = ctx.exec();
            String pattern = registerPattern(exec);
            if (pattern == null) {
                return registerPatternError(exec);
            }
            if (isReservedSystemPattern(pattern)) {
                return Outcome.err(403, "forbidden_pattern",
                        "section 6.2: user-installed handlers MUST NOT register at system/* paths: " + pattern);
            }
            Entity req = exec.entityField("params");
            if (req == null) {
                return Outcome.err(400, "unexpected_params", "register: missing params");
            }
            if (!req.type().equals("system/handler/register-request")) {
                return Outcome.err(400, "unexpected_params",
                        "register expects register-request, got " + req.type());
            }
            EcfValue.Map manifest = req.mapField("manifest");
            if (manifest == null) {
                manifest = Cbor.emptyMap();
            }
            String name = Cbor.text(manifest, "name");
            if (name == null) {
                name = pattern;
            }
            EcfValue.Map operations = Cbor.asMap(manifest.get("operations"));
            if (operations == null) {
                operations = Cbor.emptyMap();
            }
            String exprPath = Cbor.text(manifest, "expression_path");
            EcfValue internalScope = manifest.get("internal_scope");
            List<EcfValue.Map> grantScope = Cbor.mapList(req.data(), "requested_scope");
            if (grantScope == null) {
                grantScope = (internalScope instanceof EcfValue.Array)
                        ? Cbor.mapList(req.data(), "internal_scope") : null;
            }
            if (grantScope == null) {
                grantScope = List.of();
            }
            String interfaceRel = "system/handler/" + pattern;
            // (1) handler manifest at the pattern path
            List<EcfValue.Map.Entry> hp = new ArrayList<>();
            hp.add(new EcfValue.Map.Entry(new EcfValue.Text("interface"), new EcfValue.Text(interfaceRel)));
            if (exprPath != null) {
                hp.add(new EcfValue.Map.Entry(new EcfValue.Text("expression_path"), new EcfValue.Text(exprPath)));
            }
            if (internalScope != null) {
                hp.add(new EcfValue.Map.Entry(new EcfValue.Text("internal_scope"), internalScope));
            }
            store.bind(abs(pattern), Entity.make("system/handler", new EcfValue.Map(hp)));
            // (2) associated types at system/type/{type_name}
            EcfValue.Map types = req.mapField("types");
            if (types != null) {
                for (EcfValue.Map.Entry kv : types.entries()) {
                    if (kv.key() instanceof EcfValue.Text tk) {
                        EcfValue.Map td = (kv.value() instanceof EcfValue.Map m) ? m
                                : Cbor.map("def", kv.value());
                        store.bind(abs("system/type/" + tk.value()), Entity.make("system/type", td));
                    }
                }
            }
            // (3) self-issued signed handler grant + (4) grant-signature at §3.5
            Minted m = mintToken(identity.identityHash(), grantScope, null);
            store.bind(abs("system/capability/grants/" + pattern), m.token());
            store.bind(abs("system/signature/" + Cbor.hex(m.token().rawHash())), m.signature());
            // (5) handler interface entity (discovery index)
            store.bind(abs(interfaceRel), Entity.make("system/handler/interface",
                    Cbor.map("pattern", pattern, "name", name, "operations", operations)));
            return Outcome.ok(Entity.make("system/handler/register-result",
                    Cbor.map("pattern", pattern, "grant", m.token().data())));
        }

        private Outcome unregister(HandlerContext ctx) {
            Entity exec = ctx.exec();
            String pattern = registerPattern(exec);
            if (pattern == null) {
                return registerPatternError(exec);
            }
            Entity g = store.getAt(abs("system/capability/grants/" + pattern));
            if (g != null) {
                store.unbind(abs("system/signature/" + Cbor.hex(g.rawHash())));
                store.unbind(abs("system/capability/grants/" + pattern));
            }
            store.unbind(abs(pattern));
            store.unbind(abs("system/handler/" + pattern));
            return Outcome.ok(Wire.emptyParams());
        }
    }

    /** §7a conformance handler: echo (the §6.13(a) resolve→dispatch half). */
    private static final class EchoHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) {
            if (!op.equals("echo")) {
                return Outcome.err(501, "unsupported_operation", op);
            }
            Entity p = ctx.params();
            return (p != null) ? Outcome.ok(p)
                    : Outcome.err(400, "invalid_params", "echo requires a params entity");
        }
    }

    /** §7a conformance handler: dispatch-outbound (the §6.13(b)/§6.11 outbound seam). */
    private final class DispatchOutboundHandler implements Handler {
        @Override
        public Outcome handle(String op, HandlerContext ctx) throws EntityCryptoException {
            if (!op.equals("dispatch")) {
                return Outcome.err(501, "unsupported_operation", op);
            }
            Entity p = ctx.params();
            if (p == null) {
                return Outcome.err(400, "invalid_params", "dispatch-outbound requires a params entity");
            }
            String target = orEmpty(p.text("target"));
            String operation = orEmpty(p.text("operation"));
            EcfValue value = p.field("value");
            // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
            // single-granter case is an array of ONE. They were singular, which made
            // §1.4's multi-signature-root rule ungateable on the wire: driving it needs
            // two granter identities and two signatures, and a single-credential carrier
            // cannot express that input.
            //
            // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
            // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle
            // is what all 46 tracked reports are measured against and it sends the
            // SINGULAR names; a plural-only peer reads the triple as absent there, takes
            // the ambient arm and refuses — measured on the `go` vanguard as 2 of 778
            // severities moving PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at
            // BOTH check sets. REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before:
            // the exit condition is that `tools/oracle-pin.env`'s `ref` names an oracle
            // whose dispatch-outbound probe sends the plural carriers.
            Entity capability = p.entityField("reentry_capability");
            List<Entity> granterPeers = entityListField(p, "reentry_granters");
            if (granterPeers == null) {
                Entity one = p.entityField("reentry_granter");
                granterPeers = (one != null) ? List.of(one) : null;
            }
            List<Entity> capSigs = entityListField(p, "reentry_cap_signatures");
            if (capSigs == null) {
                Entity one = p.entityField("reentry_cap_signature");
                capSigs = (one != null) ? List.of(one) : null;
            }
            if (value == null) {
                return Outcome.err(400, "invalid_params", "dispatch-outbound requires value");
            }
            // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED
            // arm, all three absent selects the AMBIENT arm, and a PARTIAL set is 400
            // invalid_params — a partial credential is malformed, not ambient. An empty
            // array is partial, not present: it carries no credential.
            int nPresent = (capability != null ? 1 : 0)
                    + ((granterPeers != null && !granterPeers.isEmpty()) ? 1 : 0)
                    + ((capSigs != null && !capSigs.isEmpty()) ? 1 : 0);
            if (nPresent != 0 && nPresent != 3) {
                return Outcome.err(400, "invalid_params",
                        "dispatch-outbound reentry authority is all-or-none");
            }
            boolean hasCred = nPresent == 3;
            Entity cred = hasCred ? capability : null;
            List<Entity> granters = hasCred ? granterPeers : List.of();
            List<Entity> sigs = hasCred ? capSigs : List.of();
            // §7a.1 generic relay (RULINGS-CONCURRENCY-GATE-7b-MATRIX-2026-06-13 #2):
            // dispatch-outbound is a *generic relay* — the `value` field is the bytes
            // of the downstream's params entity data and MUST be forwarded verbatim,
            // never re-wrapped/inspected. The validator already shaped it as echo's
            // {value: X} params; re-wrapping it (the earlier shipped code did
            // {value: value}) double-nests and makes echoed.value a MAP, which is the
            // non-conformant party the keystone matrix caught. A faithful relay just
            // passes the map through as the outbound EXECUTE's params data.
            EcfValue.Map valueMap = Cbor.asMap(value);
            EcfValue.Map innerData = (valueMap != null) ? valueMap : Cbor.map("value", value);
            Entity inner = Entity.make("primitive/any", innerData);
            // `target` arrives as any of §1.4's three spellings and the validator sends
            // the SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the
            // resource target want the PEER-RELATIVE path — §1.4's PD-2 block says so for
            // Dimension 1, and a resource target carrying a scheme is not a path at all.
            String relTarget = Capability.peerRelativeOf(target);
            EcfValue.Map resource = Wire.resourceTarget("system/handler/" + relTarget);

            // §7a.2a: the presented arm verifies against a BUNDLE MERGED FROM THE PARENT
            // ENVELOPE'S `included`. The credential, its granters and its signatures
            // arrive NESTED IN PARAMS (ratified shape (a), in-band), so they are not in
            // ctx.included() and a verifier handed that alone cannot resolve a single link
            // — every credential then reads as invalid and the legitimate reentry is
            // refused.
            List<Envelope.Included> bundle = new ArrayList<>(ctx.included());
            if (hasCred) {
                bundle.add(new Envelope.Included(cred.hash(), cred));
                for (Entity g : granters) {
                    bundle.add(new Envelope.Included(g.hash(), g));
                }
                for (Entity sg : sigs) {
                    bundle.add(new Envelope.Included(sg.hash(), sg));
                }
            }
            // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends
            // the absolute form, so the URI names the target. Where the uri is
            // PEER-RELATIVE there is no peer in it and the §6.11 seam's destination is the
            // connection's remote, so that is the fallback — without it Dimension 4 passes
            // vacuously.
            String uriPeer = Capability.extractPeer(localPeer, target);
            String targetPeer = uriPeer.equals(localPeer) && ctx.conn().helloPeerId != null
                    ? ctx.conn().helloPeerId : uriPeer;

            // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer,
            // all four dimensions, on THIS handler's own grant — with a target-minted
            // credential relaxing Dimension 4 and nothing else. Consulting only the
            // presented credential here is the §6.8 confused-deputy bypass.
            Entity ownGrant = store.getAt(Capability.grantPathFor(localPeer, ctx.pattern()));
            if (ownGrant == null) {
                // §6.8: a handler with no valid grant does not run. Fail closed rather
                // than falling back to the credential, which is the substitution §6.8
                // forbids.
                return Outcome.err(403, "capability_denied", "no handler grant for " + ctx.pattern());
            }
            if (!Capability.checkOutboundSubDispatch(localPeer, targetPeer, relTarget, operation,
                    store, ownGrant, resource, cred, bundle)) {
                // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
                // transport- or gateway-class code would launder an authorization verdict
                // into a route fault, and the ambient and presented branches would then
                // disagree about what the same gate decided.
                return Outcome.err(403, "capability_denied",
                        "outbound sub-dispatch not authorized by the handler grant");
            }
            Envelope env = outboundDispatch(ctx.conn(), target, operation, inner,
                    cred, granters, sigs, resource);
            if (env == null) {
                return Outcome.err(503, "no_outbound_seam", "no live section 6.11 reentry connection");
            }
            BigInteger status = env.root().uint("status");
            EcfValue resultCbor = env.root().field("result");
            if (resultCbor == null) {
                resultCbor = Cbor.emptyMap();
            }
            return Outcome.ok(Entity.make("primitive/any",
                    Cbor.map("status", (status != null) ? status : BigInteger.ZERO, "result", resultCbor)));
        }
    }

    // ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────────

    /**
     * Send an outbound EXECUTE through the §6.11 reentry seam.
     *
     * <p>{@code granterPeers} and {@code capSigs} are PLURAL (GUIDE-CONFORMANCE §7a.1,
     * 0.8.2.19) so a K-of-N root can present every granter identity and every link
     * signature. Every member goes into {@code included} because §5.5's chain walk
     * resolves granters and signers BY HASH out of that map — a granter left out is a link
     * the verifier cannot reach, which fails closed and reads as the peer refusing the
     * credential form rather than as a carrier we truncated.
     *
     * <p>{@code capability == null} is the AMBIENT arm: the EXECUTE carries no
     * {@code capability} field at all. An empty hash would NOT do — that is a present
     * field resolving to nothing, which §5.2 reads as an unresolvable capability rather
     * than as its absence.
     */
    Envelope outboundDispatch(Conn conn, String uri, String operation, Entity params,
                              Entity capability, List<Entity> granterPeers, List<Entity> capSigs,
                              EcfValue.Map resource) throws EntityCryptoException {
        Function<Envelope, Envelope> send = conn.outbound;
        if (send == null) {
            return null;
        }
        String requestId = "out-" + conn.nextOutCounter();
        Entity exec = Wire.makeExecute(requestId, uri, operation, params,
                identity.identityHash(), (capability != null) ? capability.hash() : null, resource);
        Entity execSig = identity.sign(exec);
        List<Envelope.Included> included = new ArrayList<>();
        if (capability != null) {
            included.add(new Envelope.Included(capability.hash(), capability));
            for (Entity g : granterPeers) {
                included.add(new Envelope.Included(g.hash(), g));
            }
            for (Entity sg : capSigs) {
                included.add(new Envelope.Included(sg.hash(), sg));
            }
        }
        included.add(new Envelope.Included(identity.identityHash(), identity.peerEntity()));
        included.add(new Envelope.Included(execSig.hash(), execSig));
        return send.apply(new Envelope(exec, included));
    }

    /**
     * Decode an ARRAY of nested entities at {@code key} (the §7a.1 plural carriers).
     *
     * <p>{@code null} means the key is absent or is not a list; an array whose members do
     * not all decode is a MALFORMED carrier and is also {@code null}, never a silently
     * shorter list, because the caller's all-or-none test would then read a partial
     * credential as a complete one.
     */
    private static List<Entity> entityListField(Entity e, String key) {
        EcfValue v = e.field(key);
        if (!(v instanceof EcfValue.Array arr)) {
            return null;
        }
        List<Entity> out = new ArrayList<>(arr.items().size());
        for (EcfValue item : arr.items()) {
            if (!(item instanceof EcfValue.Map m)) {
                return null;
            }
            try {
                out.add(Entity.ofCbor(m));
            } catch (RuntimeException ex) {
                return null;
            }
        }
        return out;
    }

    // ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────────

    private void ingestSignatures(Envelope env) {
        for (Envelope.Included pair : env.included()) {
            Entity e = pair.entity();
            if (e.type().equals("system/signature")) {
                store.putEntity(e);
                byte[] signerH = e.bytes("signer");
                if (signerH != null) {
                    Entity signerPeer = env.includedGet(signerH);
                    if (signerPeer != null) {
                        store.putEntity(signerPeer);
                        byte[] target = e.bytes("target");
                        byte[] pk = signerPeer.bytes("public_key");
                        if (target != null && pk != null) {
                            String pid = Identity.peerIdOfPublicKey(pk);
                            store.bind("/" + pid + "/system/signature/" + Cbor.hex(target), e);
                        }
                    }
                }
            }
        }
    }

    // ── handler resolution (§6.6) — backward tree-walk ─────────────────────────────────

    /** Return the longest prefix of {@code path} bound to a system/handler entity, or null. */
    private String resolveHandler(String path) {
        String[] segs = path.split("/", -1);
        for (int i = segs.length; i >= 1; i--) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < i; j++) {
                if (j > 0) {
                    sb.append('/');
                }
                sb.append(segs[j]);
            }
            String prefix = sb.toString();
            Entity e = store.getAt(prefix);
            if (e != null && e.type().equals("system/handler")) {
                return prefix;
            }
        }
        return null;
    }

    private String stripLocal(String pattern) {
        String prefix = "/" + localPeer + "/";
        return Capability.startsWith(prefix, pattern) ? pattern.substring(prefix.length()) : pattern;
    }

    // ── entity-native dispatch (v7.74 §6.13(a)) ─────────────────────────────────────────

    private Outcome entityNativeDispatch(String handlerPath) {
        Entity he = store.getAt(handlerPath);
        if (he == null) {
            return Outcome.err(404, "handler_not_found", handlerPath);
        }
        String exprPath = he.text("expression_path");
        if (exprPath == null) {
            return Outcome.err(501, "no_handler_body", handlerPath);
        }
        String abs = Capability.canonicalize(localPeer, exprPath);
        Entity expr = store.getAt(abs);
        if (expr == null) {
            return Outcome.err(404, "expression_not_found", abs);
        }
        if (expr.type().equals("compute/literal")) {
            EcfValue value = expr.field("value");
            if (value == null) {
                return Outcome.err(400, "unexpected_params", "compute/literal missing value");
            }
            return Outcome.ok(Entity.make("compute/result",
                    Cbor.map("value", value, "expression", Cbor.bytes(expr.hash()))));
        }
        return Outcome.err(501, "unsupported_expression", expr.type());
    }

    // ── dispatch chain (§6.5) ──────────────────────────────────────────────────────────

    /**
     * The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or null for a
     * non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
     */
    public Envelope dispatch(Conn conn, Envelope env) {
        Entity exec = env.root();
        if (!exec.type().equals("system/protocol/execute")) {
            return null;
        }
        String requestId = orEmpty(exec.text("request_id"));
        Outcome outcome;
        try {
            outcome = dispatchInner(conn, env, exec);
        } catch (Capability.UnresolvableGrantee g) {
            outcome = Outcome.err(401, "unresolvable_grantee");
        } catch (RuntimeException | EntityCryptoException e) {
            if (System.getenv("PEER_DEBUG_500") != null) {
                e.printStackTrace();
            }
            outcome = Outcome.err(500, "internal_error");
        }
        return new Envelope(Wire.makeResponse(requestId, outcome.status(), outcome.result()),
                outcome.included());
    }

    private Outcome dispatchInner(Conn conn, Envelope env, Entity exec) throws EntityCryptoException {
        String uri = orEmpty(exec.text("uri"));
        String operation = orEmpty(exec.text("operation"));
        if (uri.equals("system/protocol/connect")) {
            return handlers.get("system/protocol/connect").handle(operation,
                    new HandlerContext(exec, conn, env.included(), null, env, "system/protocol/connect"));
        }
        ingestSignatures(env);
        // §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
        // sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace
        // took the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs
        // the caller to authenticate and retry, and for a foreign-namespace address that
        // retry cannot succeed at any authentication state — so the 401 names a remedy that
        // does not exist." §6.5 step 3 calls it "a gate, not an ordering preference" and
        // §1.4 makes the downstream permission check unreachable here.
        String path = Capability.canonicalize(localPeer, Capability.normalizeUri(uri));
        if (!Capability.extractPeer(localPeer, path).equals(localPeer)) {
            return Outcome.err(400, "invalid_request", "not local peer");
        }
        Capability.RequestVerdict v = Capability.verifyRequest(localPeer, store, env);
        switch (v) {
            case AUTHN_FAIL:
                return Outcome.err(401, "authentication_failed");
            case AUTHZ_DENY:
                return Outcome.err(403, "capability_denied");
            case CHAIN_TOO_DEEP:
                return Outcome.err(400, "chain_depth_exceeded");
            default:
                break;
        }
        // (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
        // 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
        String pattern = resolveHandler(path);
        if (pattern == null) {
            return Outcome.err(404, "handler_not_found", path);
        }
        byte[] capH = exec.bytes("capability");
        Entity callerCap = (capH != null) ? env.includedGet(capH) : null;
        if (callerCap == null) {
            return Outcome.err(403, "capability_denied");
        }
        Function<byte[], Entity> resolveFn = h -> Capability.capResolve(env.included(), store, h);
        String granterPeer = Capability.resolveGranterPeerId(resolveFn, callerCap);
        if (granterPeer == null) {
            granterPeer = localPeer;
        }
        if (Capability.checkPermission(localPeer, granterPeer, exec, callerCap, pattern)
                == Capability.Verdict.DENY) {
            return Outcome.err(403, "capability_denied");
        }
        String stripped = stripLocal(pattern);
        Handler inst = handlers.get(stripped);
        if (inst != null) {
            return inst.handle(operation,
                    new HandlerContext(exec, conn, env.included(), callerCap, env, pattern));
        }
        return entityNativeDispatch(pattern);
    }

    // ── bootstrap (§6.9) ──────────────────────────────────────────────────────────────

    private static EcfValue.Map opSpec(String input, String output) {
        List<EcfValue.Map.Entry> pairs = new ArrayList<>();
        if (input != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("input_type"), new EcfValue.Text(input)));
        }
        if (output != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("output_type"), new EcfValue.Text(output)));
        }
        return new EcfValue.Map(pairs);
    }

    /** A bootstrap handler spec: pattern, the handler instance factory, display name, ops. */
    private record HandlerSpec(String pattern, Handler handler, String name, String[][] ops) { }

    private void bootstrapHandlerEntities(String pattern, String name, String[][] ops)
            throws EntityCryptoException {
        List<EcfValue.Map.Entry> opPairs = new ArrayList<>(ops.length);
        for (String[] spec : ops) {
            opPairs.add(new EcfValue.Map.Entry(new EcfValue.Text(spec[0]), opSpec(spec[1], spec[2])));
        }
        EcfValue.Map operations = new EcfValue.Map(opPairs);
        store.bind("/" + localPeer + "/" + pattern, Entity.make("system/handler",
                Cbor.map("interface", "system/handler/" + pattern)));
        store.bind("/" + localPeer + "/system/handler/" + pattern,
                Entity.make("system/handler/interface",
                        Cbor.map("pattern", pattern, "name", name, "operations", operations)));
        // §6.8: the grant MUST exist at `system/capability/grants/{pattern}` and a handler
        // with no valid grant does not run — so this bind is the ceiling row 1 intersects
        // against, not bookkeeping. An empty grants list is the right default for a
        // handler that never dispatches onward and the WRONG one for a handler that does,
        // which is why dispatch-outbound gets a NARROW one: with a wide grant, consulting
        // it and skipping it give the same answer on every input, so the confused-deputy
        // discriminator cannot fire and a bypass reads as conformant (GUIDE-CONFORMANCE
        // §7a.1 makes the narrowness a scaffold-contract requirement).
        Minted m = mintToken(identity.identityHash(), ownGrantsFor(pattern), null);
        store.bind("/" + localPeer + "/system/capability/grants/" + pattern, m.token());
    }

    /**
     * A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward, as
     * distinct from any capability a caller presents. §6.8 row 1: an access in service of a
     * caller's request needs the caller's verified capability AND this grant, and BOTH must
     * pass. Narrow for {@code dispatch-outbound}; empty for everything else.
     */
    private static List<EcfValue.Map> ownGrantsFor(String pattern) {
        if (!pattern.equals("system/validate/dispatch-outbound")) {
            return List.of();
        }
        return List.of(Cbor.map(
                "handlers", Cbor.map("include", new EcfValue.Array(List.of(new EcfValue.Text("system/validate/echo")))),
                "operations", Cbor.map("include", new EcfValue.Array(List.of(new EcfValue.Text("echo")))),
                "resources", Cbor.map("include",
                        new EcfValue.Array(List.of(new EcfValue.Text("system/handler/system/validate/echo"))))));
    }

    /** Construct + bootstrap a peer from a 32-byte Ed25519 seed. */
    public static Peer create(byte[] seed, boolean openGrants, boolean conformance)
            throws EntityCryptoException {
        Identity identity = Identity.ofSeed(seed);
        Store store = new Store();
        String local = identity.peerId();
        Peer peer = new Peer(identity, store, local, openGrants, conformance);

        // local identity entity in the store (root-granter resolution)
        store.putEntity(identity.peerEntity());
        // publish the core type floor (S3 minimal subset; full 53 at S4)
        CoreTypes.publish(store, local);

        // instantiate + register the MUST handler instances (the §6.6 → instance map)
        List<HandlerSpec> bootstrap = List.of(
                new HandlerSpec("system/tree", peer.new TreeHandler(), "Tree",
                        new String[][] {{"get", null, null}, {"put", null, null}}),
                new HandlerSpec("system/handler", peer.new HandlersHandler(), "Handlers",
                        new String[][] {
                                {"register", "system/handler/register-request", "system/handler/register-result"},
                                {"unregister", "system/handler/unregister-request", null}}),
                new HandlerSpec("system/type", peer.new TypeHandler(), "Types",  // real type-validate body (S4, A-JAVA-008)
                        new String[][] {{"validate", "system/type/validate-request", "system/type/validate-result"}}),
                new HandlerSpec("system/capability", peer.new CapabilityHandler(), "Capability",
                        new String[][] {
                                {"request", "system/capability/request", "system/capability/grant"},
                                {"revoke", "system/capability/revoke-request", null},
                                {"configure", "system/capability/policy-entry", null},
                                {"delegate", "system/capability/delegate-request", "system/capability/grant"}}),
                new HandlerSpec("system/protocol/connect", peer.new ConnectHandler(), "Connect",
                        new String[][] {{"hello", null, null}, {"authenticate", null, null}}));
        for (HandlerSpec spec : bootstrap) {
            peer.handlers.put(spec.pattern(), spec.handler());
            peer.bootstrapHandlerEntities(spec.pattern(), spec.name(), spec.ops());
        }

        // §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap (root, full scope
        // over /{peer}/*, grantee = own identity; §6.9a.0 detached-sig shape) + default
        // scope-template entry. Read back by authenticate (dual-form lookup). open-grants
        // selects the degenerate [default → *].
        String policyBase = "/" + local + "/system/capability/policy/";
        Minted owner = peer.mintToken(identity.identityHash(), peer.ownerGrants(), null);
        store.bind(policyBase + Cbor.hex(identity.identityHash()), owner.token());
        store.bind("/" + local + "/system/signature/" + Cbor.hex(owner.token().rawHash()),
                owner.signature());
        List<EcfValue.Map> defaultGrants = openGrants ? peer.openGrantsScope() : peer.discoveryFloor();
        Entity defaultEntry = Entity.make("system/capability/policy-entry",
                Cbor.map("peer_pattern", "default", "grants", grantsArray(defaultGrants)));
        store.bind(policyBase + "default", defaultEntry);

        // §7a conformance handlers — only bootstrapped under --validate
        if (conformance) {
            List<HandlerSpec> conf = List.of(
                    new HandlerSpec("system/validate/echo", new EchoHandler(), "validate-echo",
                            new String[][] {{"echo", null, null}}),
                    new HandlerSpec("system/validate/dispatch-outbound",
                            peer.new DispatchOutboundHandler(), "validate-dispatch-outbound",
                            new String[][] {{"dispatch", null, null}}));
            for (HandlerSpec spec : conf) {
                peer.handlers.put(spec.pattern(), spec.handler());
                peer.bootstrapHandlerEntities(spec.pattern(), spec.name(), spec.ops());
            }
        }
        return peer;
    }

    // ── small helpers ────────────────────────────────────────────────────────────────

    private String abs(String rel) {
        return "/" + localPeer + "/" + rel;
    }

    private static String execResourceTarget(Entity exec) {
        EcfValue.Map r = exec.mapField("resource");
        if (r == null) {
            return null;
        }
        List<String> targets = Cbor.textList(r, "targets");
        return (targets != null && !targets.isEmpty()) ? targets.get(0) : null;
    }

    private static boolean pathFlexOk(String target) {
        if (target.indexOf('\0') >= 0) {
            return false;
        }
        String[] segs0 = target.split("/", -1);
        boolean absOk;
        List<String> body;
        if (Capability.startsWith("/", target)) {
            if (segs0.length >= 2 && segs0[0].isEmpty()) {
                absOk = Capability.isPeerId(segs0[1]);
                body = new ArrayList<>(List.of(segs0).subList(1, segs0.length));
            } else {
                absOk = false;
                body = List.of(segs0);
            }
        } else {
            absOk = true;
            body = List.of(segs0);
        }
        if (!absOk) {
            return false;
        }
        if (!body.isEmpty() && body.get(body.size() - 1).isEmpty()) {
            body = body.subList(0, body.size() - 1);
        }
        for (String s : body) {
            if (s.isEmpty() || s.equals(".") || s.equals("..")) {
                return false;
            }
        }
        return true;
    }

    private static boolean isZeroHash(byte[] h) {
        for (byte b : h) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static List<EcfValue.Map> reqGrants(Entity params) {
        if (params == null) {
            return List.of();
        }
        List<EcfValue.Map> g = Cbor.mapList(params.data(), "grants");
        return (g != null) ? g : List.of();
    }

    private static String registerPattern(Entity exec) {
        String target = execResourceTarget(exec);
        if (target == null) {
            return null;
        }
        String prefix = "system/handler/";
        if (!Capability.startsWith(prefix, target) || target.length() == prefix.length()) {
            return null;
        }
        return target.substring(prefix.length());
    }

    /** §6.2: user-installed handlers MUST NOT register at reserved {@code system/*} paths. */
    private static boolean isReservedSystemPattern(String pattern) {
        return pattern.equals("system") || Capability.startsWith("system/", pattern);
    }

    private static Outcome registerPatternError(Entity exec) {
        String target = execResourceTarget(exec);
        if (target == null) {
            return Outcome.err(400, "ambiguous_resource",
                    "register/unregister require exactly one resource target");
        }
        return Outcome.err(400, "invalid_resource",
                "resource target MUST be system/handler/{pattern}");
    }

    private static String orEmpty(String s) {
        return (s != null) ? s : "";
    }
}
