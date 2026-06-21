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
        List<EcfValue.Map.Entry> pairs = new ArrayList<>();
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("granter"),
                new EcfValue.Bytes(identity.identityHash())));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("grantee"),
                new EcfValue.Bytes(granteeHash)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("grants"), grantsArray(grants)));
        pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("created_at"),
                EcfValue.Int.of(Capability.nowMs())));
        if (parent != null) {
            pairs.add(new EcfValue.Map.Entry(new EcfValue.Text("parent"), new EcfValue.Bytes(parent)));
        }
        Entity token = Entity.make("system/capability/token", new EcfValue.Map(pairs));
        return new Minted(token, identity.sign(token));
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
                default -> Outcome.err(501, "unsupported_operation", op);
            };
        }

        private Outcome hello(HandlerContext ctx) {
            Conn conn = ctx.conn();
            Entity exec = ctx.exec();
            if (conn.established) {
                return Outcome.err(409, "connection_already_established");
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
                return Outcome.err(409, "connection_already_established");
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
            String target = execResourceTarget(exec);
            if (target != null && !pathFlexOk(target)) {
                return Outcome.err(400, "invalid_path", target);
            }
            if (target == null) {
                return buildListing("/" + localPeer + "/");
            }
            if (target.isEmpty() || target.charAt(target.length() - 1) == '/') {
                return buildListing(Capability.canonicalize(localPeer, target));
            }
            String path = Capability.canonicalize(localPeer, target);
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

        private Outcome put(HandlerContext ctx) {
            Entity exec = ctx.exec();
            String target = execResourceTarget(exec);
            if (target == null) {
                return Outcome.err(400, "ambiguous_resource", "tree: missing resource target");
            }
            if (!pathFlexOk(target)) {
                return Outcome.err(400, "invalid_path", target);
            }
            String path = Capability.canonicalize(localPeer, target);
            Entity params = exec.entityField("params");
            Entity entity = (params != null) ? params.entityField("entity") : null;
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
            if (entity == null) {
                return Outcome.err(400, "unexpected_params", "put: missing entity");
            }
            store.bind(path, entity);
            return Outcome.ok(Entity.make("system/hash", Cbor.map("hash", Cbor.bytes(entity.hash()))));
        }

        private Outcome buildListing(String path) {
            List<Store.ListEntry> entries = new ArrayList<>();
            for (Store.ListEntry row : store.listing(path)) {
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
            return mintBounded(ctx.callerCap(), reqGrants(params), author, null);
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
            return mintBounded(ctx.callerCap(), reqGrants(params), author, ph);
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
                                    byte[] granteeHash, byte[] parent) throws EntityCryptoException {
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
            Minted m = mintToken(granteeHash, reqGrants, parent);
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
            Entity capability = p.entityField("reentry_capability");
            Entity granterPeer = p.entityField("reentry_granter");
            Entity capSig = p.entityField("reentry_cap_signature");
            if (!(value != null && capability != null && granterPeer != null && capSig != null)) {
                return Outcome.err(400, "invalid_params",
                        "dispatch-outbound requires value + reentry authority");
            }
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
            EcfValue.Map resource = Wire.resourceTarget("system/handler/" + target);
            Envelope env = outboundDispatch(ctx.conn(), target, operation, inner,
                    capability, granterPeer, capSig, resource);
            if (env == null) {
                return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection");
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

    Envelope outboundDispatch(Conn conn, String uri, String operation, Entity params,
                              Entity capability, Entity granterPeer, Entity capSig,
                              EcfValue.Map resource) throws EntityCryptoException {
        Function<Envelope, Envelope> send = conn.outbound;
        if (send == null) {
            return null;
        }
        String requestId = "out-" + conn.nextOutCounter();
        Entity exec = Wire.makeExecute(requestId, uri, operation, params,
                identity.identityHash(), capability.hash(), resource);
        Entity execSig = identity.sign(exec);
        List<Envelope.Included> included = new ArrayList<>();
        included.add(new Envelope.Included(capability.hash(), capability));
        included.add(new Envelope.Included(granterPeer.hash(), granterPeer));
        included.add(new Envelope.Included(identity.identityHash(), identity.peerEntity()));
        included.add(new Envelope.Included(capSig.hash(), capSig));
        included.add(new Envelope.Included(execSig.hash(), execSig));
        return send.apply(new Envelope(exec, included));
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
                    new HandlerContext(exec, conn, env.included(), null, env));
        }
        ingestSignatures(env);
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
        String path = Capability.canonicalize(localPeer, Capability.normalizeUri(uri));
        // §1.4: inbound dispatch must target the local peer.
        if (!Capability.extractPeer(localPeer, path).equals(localPeer)) {
            return Outcome.err(404, "handler_not_found", "not local peer");
        }
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
                    new HandlerContext(exec, conn, env.included(), callerCap, env));
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
        Minted m = mintToken(identity.identityHash(), List.of(), null);
        store.bind("/" + localPeer + "/system/capability/grants/" + pattern, m.token());
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
