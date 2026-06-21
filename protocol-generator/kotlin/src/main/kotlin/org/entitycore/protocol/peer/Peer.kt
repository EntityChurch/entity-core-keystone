package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue
import org.entitycore.protocol.crypto.PeerId
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Peer assembly: bootstrap (§6.9 / §6.9a), the MUST system handlers (§6.2: connect, tree,
 * handler, capability, type), the §6.5 dispatch chain, §6.6 resolution, and per-connection
 * state. The pure protocol brain — a `suspend` function from inbound envelope to outbound
 * response envelope. Transport lives in [Transport].
 *
 * Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch chain order (verify
 * → resolve → check-permission → handler), and §4.4 initial-grant delivery are derived
 * from V7.
 *
 * **Idiom (the verdict/dispatch axis).** Each handler is a [Handler] whose `handle(op,
 * ctx)` is a `when` over the operation string — the mainstream `match op` ladder with the
 * "unknown operation → 501" arm as `else`. The §5.2/§5.10 verdicts are Kotlin `enum`s
 * matched EXHAUSTIVELY by `when` at the dispatch site (profile `exhaustive_when`). Handlers
 * are `suspend` (a handler that originates an outbound EXECUTE — §6.13(b)/§6.11 reentry —
 * awaits the response via the coroutine seam, never blocking a thread).
 */
class Peer private constructor(
    val identity: Identity,
    val store: Store,
    val localPeer: String,
    private val openGrants: Boolean,   // --debug-open-grants: degenerate wide admin cap
    private val conformance: Boolean,  // --validate: §7a system/validate/(star) handlers
) {
    private val handlers = HashMap<String, Handler>() // pattern → handler
    private val rng = SecureRandom()

    // ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ───────────────────────────

    private fun randomBytes(n: Int): ByteArray {
        val b = ByteArray(n)
        rng.nextBytes(b)
        return b
    }

    // ── grant construction (§4.4 / §5.4) ───────────────────────────────────────────

    /** The §4.4 discovery floor: every authenticated identity gets at least this. */
    private fun discoveryFloor(): List<EcfValue.MapVal> = listOf(
        grant(listOf("system/tree"), listOf("system/type/*", "system/handler/*"), listOf("get"), null),
        grant(listOf("system/capability"), emptyList(), listOf("request"), null),
    )

    /** Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants). */
    private fun openGrantsScope(): List<EcfValue.MapVal> =
        listOf(grant(listOf("*"), listOf("*", "/*/*"), listOf("*"), listOf("*")))

    /** Full owner authority over the local namespace /{peer_id}/(star) (§6.9a). */
    private fun ownerGrants(): List<EcfValue.MapVal> =
        listOf(grant(listOf("*"), listOf("*"), listOf("*"), listOf(localPeer)))

    // ── token mint (§4.4 / §6.9a) ───────────────────────────────────────────────────

    /** A minted token + its signature. */
    private data class Minted(val token: Entity, val signature: Entity)

    private fun mintToken(granteeHash: ByteArray, grants: List<EcfValue.MapVal>, parent: ByteArray?): Minted {
        val pairs = ArrayList<EcfValue.Entry>()
        pairs.add(EcfValue.Entry(EcfValue.Text("granter"), EcfValue.Bytes(identity.identityHash())))
        pairs.add(EcfValue.Entry(EcfValue.Text("grantee"), EcfValue.Bytes(granteeHash)))
        pairs.add(EcfValue.Entry(EcfValue.Text("grants"), grantsArray(grants)))
        pairs.add(EcfValue.Entry(EcfValue.Text("created_at"), EcfValue.IntVal.of(Capability.nowMs())))
        if (parent != null) pairs.add(EcfValue.Entry(EcfValue.Text("parent"), EcfValue.Bytes(parent)))
        val token = Entity.make("system/capability/token", EcfValue.MapVal(pairs))
        return Minted(token, identity.sign(token))
    }

    private fun capIncluded(m: Minted): List<Envelope.Included> = listOf(
        Envelope.Included(m.token.hash(), m.token),
        Envelope.Included(identity.identityHash(), identity.peerEntity),
        Envelope.Included(m.signature.hash(), m.signature),
    )

    // ── §6.9a seed policy (authenticate-time grant derivation) ────────────────────────

    private fun seedEntryGrants(e: Entity): List<EcfValue.MapVal> = when (e.type) {
        "system/capability/token" -> {
            val sigPath = "/$localPeer/system/signature/${Cbor.hex(e.rawHash())}"
            val sgn = store.getAt(sigPath)
            if (sgn != null && Identity.verifySignature(sgn, identity.peerEntity)) {
                Cbor.mapList(e.data(), "grants") ?: emptyList()
            } else emptyList()
        }
        "system/capability/policy-entry" -> Cbor.mapList(e.data(), "grants") ?: emptyList()
        else -> emptyList()
    }

    /** §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
     *  then UNION the matched scope with the §4.4 discovery floor. */
    private fun deriveSeedGrants(remotePeer: Entity, remotePeerId: String): List<EcfValue.MapVal> {
        val base = "/$localPeer/system/capability/policy/"
        val entry = store.getAt(base + Cbor.hex(remotePeer.rawHash()))
            ?: store.getAt(base + remotePeerId)
            ?: store.getAt(base + "default")
        val floor = discoveryFloor()
        if (entry == null) return floor
        val policy = seedEntryGrants(entry)
        if (policy.isEmpty()) return floor
        return floor + policy
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Handlers (single-dispatch operation `when` ladders)
    // ══════════════════════════════════════════════════════════════════════════════

    private fun strArray(exec: Entity, key: String): List<String>? =
        exec.entityField("params")?.let { Cbor.textList(it.data(), key) }

    /** §4.1 / §4.6 — the connect handler (hello / authenticate). */
    private inner class ConnectHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome = when (operation) {
            "hello" -> hello(ctx)
            "authenticate" -> authenticate(ctx)
            else -> Outcome.err(501, "unsupported_operation", operation)
        }

        private fun hello(ctx: HandlerContext): Outcome {
            val conn = ctx.conn
            val exec = ctx.exec
            if (conn.established) return Outcome.err(409, "connection_already_established")
            // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
            val hf = strArray(exec, "hash_formats")
            val kt = strArray(exec, "key_types")
            if (hf != null && !hf.contains("ecfv1-sha256")) return Outcome.err(400, "incompatible_hash_format")
            if (kt != null && !kt.contains("ed25519")) return Outcome.err(400, "unsupported_key_type")
            val params = exec.entityField("params")
            conn.helloPeerId = params?.text("peer_id")
            val nonce = randomBytes(32)
            conn.issuedNonce = nonce
            return Outcome.ok(
                Entity.make(
                    "system/protocol/connect/hello",
                    Cbor.map(
                        "peer_id", localPeer,
                        "nonce", Cbor.bytes(nonce),
                        "protocols", Cbor.textArray("entity-core/1.0"),
                        "timestamp", EcfValue.IntVal.of(Capability.nowMs()),
                        "hash_formats", Cbor.textArray("ecfv1-sha256"),
                        "key_types", Cbor.textArray("ed25519"),
                    ),
                ),
            )
        }

        private fun authenticate(ctx: HandlerContext): Outcome {
            val conn = ctx.conn
            val exec = ctx.exec
            if (conn.established) return Outcome.err(409, "connection_already_established")
            val issuedNonce = conn.issuedNonce ?: return Outcome.err(401, "invalid_nonce") // before hello
            val auth = exec.entityField("params") ?: return Outcome.err(401, "authentication_failed")
            // §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-0x01 peer_id.
            var badKt = auth.text("key_type")?.let { it != "ed25519" } ?: false
            val pub = auth.bytes("public_key")
            if (!badKt && pub != null && pub.size != 32) badKt = true
            val claimed = auth.text("peer_id")
            if (!badKt && claimed != null) {
                try {
                    if (PeerId.parse(claimed).keyType != PeerId.KEY_TYPE_ED25519) badKt = true
                } catch (ignore: Exception) {
                    // unparseable peer_id → fall through to the step checks below
                }
            }
            if (badKt) return Outcome.err(400, "unsupported_key_type")
            // step 1: nonce-echo
            val echoed = auth.bytes("nonce")
            if (!(echoed != null && Identity.octetsEqual(echoed, issuedNonce))) {
                return Outcome.err(401, "invalid_nonce")
            }
            if (pub == null) return Outcome.err(401, "authentication_failed")
            // step 2: proof of possession
            val sgn = Capability.findSignature(auth.rawHash(), ctx.included)
            val sigOk = sgn?.bytes("signature")?.let { sb ->
                org.entitycore.protocol.crypto.Ed.verify(
                    pub, auth.rawHash(), sb, org.entitycore.protocol.crypto.Curve.ED25519)
            } ?: false
            if (!sigOk) return Outcome.err(401, "authentication_failed")
            // step 3: identity binding
            if (claimed != Identity.peerIdOfPublicKey(pub)) return Outcome.err(401, "identity_mismatch")
            if (conn.helloPeerId != null && conn.helloPeerId != claimed) {
                return Outcome.err(401, "identity_mismatch")
            }
            // success: mint the initial capability for the remote (§4.4 / §6.9a)
            val remotePeer = Identity.peerEntityOfPublicKey(pub)
            val grants = deriveSeedGrants(remotePeer, claimed)
            val m = mintToken(remotePeer.hash(), grants, null)
            conn.established = true
            return Outcome.ok(
                Entity.make("system/capability/grant", Cbor.map("token", Cbor.bytes(m.token.hash()))),
                capIncluded(m),
            )
        }
    }

    /** §6.3 — the tree handler (get / put). */
    private inner class TreeHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome = when (operation) {
            "get" -> get(ctx)
            "put" -> put(ctx)
            else -> Outcome.err(501, "unsupported_operation", operation)
        }

        private fun get(ctx: HandlerContext): Outcome {
            val exec = ctx.exec
            val target = execResourceTarget(exec)
            if (target != null && !pathFlexOk(target)) return Outcome.err(400, "invalid_path", target)
            if (target == null) return buildListing("/$localPeer/")
            if (target.isEmpty() || target.last() == '/') {
                return buildListing(Capability.canonicalize(localPeer, target))
            }
            val path = Capability.canonicalize(localPeer, target)
            val e = store.getAt(path) ?: return Outcome.err(404, "not_found", path)
            val mode = exec.entityField("params")?.text("mode")
            if (mode == "hash") {
                return Outcome.ok(Entity.make("system/hash", Cbor.map("hash", Cbor.bytes(e.hash()))))
            }
            return Outcome.ok(e)
        }

        private fun put(ctx: HandlerContext): Outcome {
            val exec = ctx.exec
            val target = execResourceTarget(exec)
                ?: return Outcome.err(400, "ambiguous_resource", "tree: missing resource target")
            if (!pathFlexOk(target)) return Outcome.err(400, "invalid_path", target)
            val path = Capability.canonicalize(localPeer, target)
            val params = exec.entityField("params")
            val entity = params?.entityField("entity")
            val expected = params?.bytes("expected_hash")
            val current = store.hashAt(path)
            val casOk = when {
                expected == null -> true
                isZeroHash(expected) -> current == null
                else -> current != null && current == Cbor.hex(expected)
            }
            if (!casOk) return Outcome.err(409, "hash_mismatch", path)
            if (entity == null) return Outcome.err(400, "unexpected_params", "put: missing entity")
            store.bind(path, entity)
            return Outcome.ok(Entity.make("system/hash", Cbor.map("hash", Cbor.bytes(entity.hash()))))
        }

        private fun buildListing(path: String): Outcome {
            val entries = store.listing(path).filterNot { row ->
                row.hashHex != null && !row.hasChildren && isDeletionMarker(Cbor.unhex(row.hashHex))
            }
            val entryPairs = entries.map { row ->
                val data = if (row.hashHex != null) {
                    Cbor.map("has_children", row.hasChildren, "hash", Cbor.bytes(Cbor.unhex(row.hashHex)))
                } else {
                    Cbor.map("has_children", row.hasChildren)
                }
                val le = Entity.make("system/tree/listing-entry", data)
                EcfValue.Entry(EcfValue.Text(row.segment), le.toCbor())
            }
            return Outcome.ok(
                Entity.make(
                    "system/tree/listing",
                    Cbor.map(
                        "path", path,
                        "entries", EcfValue.MapVal(entryPairs),
                        "count", EcfValue.IntVal.of(entries.size.toLong()),
                        "offset", EcfValue.IntVal.of(0L),
                    ),
                ),
            )
        }

        private fun isDeletionMarker(h: ByteArray): Boolean =
            store.getByHash(h)?.type == "system/deletion-marker"
    }

    /**
     * EXTENSION-TYPE — the system/type:validate handler. Validates an entity against a
     * registered §2 type definition: every required (non-optional) field present, and any
     * unevaluated (extra) fields reported. Returns a `system/type/validate-result`
     * `{valid, violations?, unevaluated_fields?}`. The `type` category is EXTENSION (auto-
     * skipped under --profile core); structural required/unevaluated checks are the floor.
     */
    private inner class TypeHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome {
            if (operation != "validate") return Outcome.err(501, "unsupported_operation", operation)
            val req = ctx.params() ?: return Outcome.err(400, "invalid_params", "validate requires a params entity")
            val subject = req.entityField("entity")
                ?: return Outcome.err(400, "unexpected_params", "validate-request missing entity")
            val typeName = req.text("type_path") ?: subject.type
            val typeDef = store.getAt(abs("system/type/$typeName"))
            if (typeDef == null) {
                val vs = listOf<EcfValue>(
                    Cbor.map("kind", "unknown_type", "field", typeName,
                        "message", "no registered type definition for $typeName"),
                )
                return Outcome.ok(Entity.make("system/type/validate-result",
                    Cbor.map("valid", false, "violations", Cbor.array(vs))))
            }
            val fields = typeDef.mapField("fields")
            val subjData = Cbor.asMap(subject.rawData())
            val violations = ArrayList<EcfValue>()
            val unevaluated = ArrayList<String>()
            val declared = HashSet<String>()
            if (fields != null) {
                for (fe in fields.entries) {
                    val fk = (fe.key as? EcfValue.Text)?.value ?: continue
                    declared.add(fk)
                    val spec = Cbor.asMap(fe.value)
                    val optional = spec != null && Cbor.isTrue(spec["optional"])
                    val present = subjData != null && subjData[fk] != null
                    if (!optional && !present) {
                        violations.add(Cbor.map("kind", "missing_required_field", "field", fk,
                            "message", "required field absent"))
                    }
                }
            }
            if (subjData != null) {
                for (se in subjData.entries) {
                    val sk = (se.key as? EcfValue.Text)?.value
                    if (sk != null && !declared.contains(sk)) unevaluated.add(sk)
                }
            }
            val valid = violations.isEmpty()
            val result = ArrayList<EcfValue.Entry>()
            result.add(EcfValue.Entry(EcfValue.Text("valid"),
                if (valid) EcfValue.Bool.TRUE else EcfValue.Bool.FALSE))
            if (violations.isNotEmpty()) {
                result.add(EcfValue.Entry(EcfValue.Text("violations"), Cbor.array(violations)))
            }
            if (unevaluated.isNotEmpty()) {
                result.add(EcfValue.Entry(EcfValue.Text("unevaluated_fields"), Cbor.textArray(unevaluated)))
            }
            return Outcome.ok(Entity.make("system/type/validate-result", EcfValue.MapVal(result)))
        }
    }

    /** §6.2 — the capability handler (request / delegate / revoke / configure). */
    private inner class CapabilityHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome = when (operation) {
            "request" -> request(ctx)
            "delegate" -> delegate(ctx)
            "revoke" -> revoke(ctx)
            "configure" -> configure(ctx)
            else -> Outcome.err(501, "unsupported_operation", operation)
        }

        private fun request(ctx: HandlerContext): Outcome {
            val params = ctx.exec.entityField("params")
            val author = ctx.exec.bytes("author") ?: return Outcome.err(403, "capability_denied")
            return mintBounded(ctx.callerCap, reqGrants(params), author, null)
        }

        private fun delegate(ctx: HandlerContext): Outcome {
            val params = ctx.exec.entityField("params")
            val author = ctx.exec.bytes("author")
            val ph = params?.bytes("parent") ?: return Outcome.err(400, "unexpected_params", "delegate: parent required")
            if (isZeroHash(ph)) return Outcome.err(400, "unexpected_params", "delegate: zero parent")
            if (!(author != null && Identity.octetsEqual(author, identity.identityHash()))) {
                return Outcome.err(501, "unsupported_operation", "delegate: same-peer-only in v1")
            }
            return mintBounded(ctx.callerCap, reqGrants(params), author, ph)
        }

        private fun revoke(ctx: HandlerContext): Outcome {
            val params = ctx.exec.entityField("params")
            val tokenH = params?.bytes("token") ?: return Outcome.err(400, "unexpected_params", "revoke: missing token")
            if (isZeroHash(tokenH)) return Outcome.err(400, "unexpected_params", "revoke: zero token")
            val marker = Entity.make("system/capability/revocation",
                Cbor.map("token", Cbor.bytes(tokenH), "revoked_at", EcfValue.IntVal.of(Capability.nowMs())))
            store.bind("/$localPeer/system/capability/revocations/${Cbor.hex(tokenH)}", marker)
            return Outcome.ok(Wire.emptyParams())
        }

        private fun configure(ctx: HandlerContext): Outcome {
            val params = ctx.exec.entityField("params")
            val pp = params?.text("peer_pattern") ?: return Outcome.err(400, "unexpected_params", "configure: missing peer_pattern")
            val isHex = pp.length == 66 && pp.all { (it in '0'..'9') || (it in 'a'..'f') }
            if (!(pp == "default" || isHex || Capability.isPeerId(pp))) {
                return Outcome.err(400, "invalid_peer_pattern", pp)
            }
            store.bind("/$localPeer/system/capability/policy/$pp", params)
            return Outcome.ok(Wire.emptyParams())
        }

        private fun mintBounded(callerCap: Entity?, reqGrants: List<EcfValue.MapVal>, granteeHash: ByteArray, parent: ByteArray?): Outcome {
            var bounded = false
            if (callerCap != null) {
                val parentGrants = Capability.grantsOfToken(callerCap)
                bounded = true
                for (cgRaw in reqGrants) {
                    val c = Capability.parseGrant(cgRaw)
                    // self-issued mint: granter = local → both frames local.
                    if (parentGrants.none { Capability.grantSubset(localPeer, localPeer, localPeer, c, it) }) {
                        bounded = false
                        break
                    }
                }
            }
            if (!bounded) return Outcome.err(403, "scope_exceeds_authority")
            val m = mintToken(granteeHash, reqGrants, parent)
            return Outcome.ok(
                Entity.make("system/capability/grant", Cbor.map("token", Cbor.bytes(m.token.hash()))),
                capIncluded(m),
            )
        }
    }

    /** §6.2 / §6.13(a) — the handlers handler (register / unregister). */
    private inner class HandlersHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome = when (operation) {
            "register" -> register(ctx)
            "unregister" -> unregister(ctx)
            else -> Outcome.err(501, "unsupported_operation", operation)
        }

        private fun register(ctx: HandlerContext): Outcome {
            val exec = ctx.exec
            val pattern = registerPattern(exec) ?: return registerPatternError(exec)
            val req = exec.entityField("params") ?: return Outcome.err(400, "unexpected_params", "register: missing params")
            if (req.type != "system/handler/register-request") {
                return Outcome.err(400, "unexpected_params", "register expects register-request, got ${req.type}")
            }
            val manifest = req.mapField("manifest") ?: Cbor.emptyMap()
            val name = Cbor.text(manifest, "name") ?: pattern
            val operations = Cbor.asMap(manifest["operations"]) ?: Cbor.emptyMap()
            val exprPath = Cbor.text(manifest, "expression_path")
            val internalScope = manifest["internal_scope"]
            var grantScope = Cbor.mapList(req.data(), "requested_scope")
            if (grantScope == null && internalScope is EcfValue.Arr) {
                grantScope = Cbor.mapList(req.data(), "internal_scope")
            }
            if (grantScope == null) grantScope = emptyList()
            val interfaceRel = "system/handler/$pattern"
            // (1) handler manifest at the pattern path
            val hp = ArrayList<EcfValue.Entry>()
            hp.add(EcfValue.Entry(EcfValue.Text("interface"), EcfValue.Text(interfaceRel)))
            if (exprPath != null) hp.add(EcfValue.Entry(EcfValue.Text("expression_path"), EcfValue.Text(exprPath)))
            if (internalScope != null) hp.add(EcfValue.Entry(EcfValue.Text("internal_scope"), internalScope))
            store.bind(abs(pattern), Entity.make("system/handler", EcfValue.MapVal(hp)))
            // (2) associated types at system/type/{type_name}
            val types = req.mapField("types")
            if (types != null) {
                for (kv in types.entries) {
                    val tk = (kv.key as? EcfValue.Text)?.value ?: continue
                    val td = (kv.value as? EcfValue.MapVal) ?: Cbor.map("def", kv.value)
                    store.bind(abs("system/type/$tk"), Entity.make("system/type", td))
                }
            }
            // (3) self-issued signed handler grant + (4) grant-signature at §3.5
            val m = mintToken(identity.identityHash(), grantScope, null)
            store.bind(abs("system/capability/grants/$pattern"), m.token)
            store.bind(abs("system/signature/${Cbor.hex(m.token.rawHash())}"), m.signature)
            // (5) handler interface entity (discovery index)
            store.bind(abs(interfaceRel), Entity.make("system/handler/interface",
                Cbor.map("pattern", pattern, "name", name, "operations", operations)))
            return Outcome.ok(Entity.make("system/handler/register-result",
                Cbor.map("pattern", pattern, "grant", m.token.data())))
        }

        private fun unregister(ctx: HandlerContext): Outcome {
            val exec = ctx.exec
            val pattern = registerPattern(exec) ?: return registerPatternError(exec)
            val g = store.getAt(abs("system/capability/grants/$pattern"))
            if (g != null) {
                store.unbind(abs("system/signature/${Cbor.hex(g.rawHash())}"))
                store.unbind(abs("system/capability/grants/$pattern"))
            }
            store.unbind(abs(pattern))
            store.unbind(abs("system/handler/$pattern"))
            return Outcome.ok(Wire.emptyParams())
        }
    }

    /** §7a conformance handler: echo (the §6.13(a) resolve→dispatch half). */
    private class EchoHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome {
            if (operation != "echo") return Outcome.err(501, "unsupported_operation", operation)
            return ctx.params()?.let { Outcome.ok(it) }
                ?: Outcome.err(400, "invalid_params", "echo requires a params entity")
        }
    }

    /** §7a conformance handler: dispatch-outbound (the §6.13(b)/§6.11 outbound seam). */
    private inner class DispatchOutboundHandler : Handler {
        override suspend fun handle(operation: String, ctx: HandlerContext): Outcome {
            if (operation != "dispatch") return Outcome.err(501, "unsupported_operation", operation)
            val p = ctx.params() ?: return Outcome.err(400, "invalid_params", "dispatch-outbound requires a params entity")
            val target = p.text("target") ?: ""
            val operationField = p.text("operation") ?: ""
            val value = p.field("value")
            val capability = p.entityField("reentry_capability")
            val granterPeer = p.entityField("reentry_granter")
            val capSig = p.entityField("reentry_cap_signature")
            if (!(value != null && capability != null && granterPeer != null && capSig != null)) {
                return Outcome.err(400, "invalid_params", "dispatch-outbound requires value + reentry authority")
            }
            // §7a.1 generic relay: the `value` field is the bytes of the downstream's
            // params entity data and MUST be forwarded verbatim, never re-wrapped. The
            // validator already shaped it as echo's {value: X} params; a faithful relay
            // passes the map through as the outbound EXECUTE's params data (re-wrapping
            // double-nests — the non-conformant party the keystone matrix caught).
            val valueMap = Cbor.asMap(value)
            val innerData = valueMap ?: Cbor.map("value", value)
            val inner = Entity.make("primitive/any", innerData)
            val resource = Wire.resourceTarget("system/handler/$target")
            val env = outboundDispatch(ctx.conn, target, operationField, inner, capability, granterPeer, capSig, resource)
                ?: return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection")
            val status = env.root.uint("status") ?: BigInteger.ZERO
            val resultCbor = env.root.field("result") ?: Cbor.emptyMap()
            return Outcome.ok(Entity.make("primitive/any", Cbor.map("status", status, "result", resultCbor)))
        }
    }

    // ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────────

    private suspend fun outboundDispatch(
        conn: Conn,
        uri: String,
        operation: String,
        params: Entity,
        capability: Entity,
        granterPeer: Entity,
        capSig: Entity,
        resource: EcfValue.MapVal,
    ): Envelope? {
        val send = conn.outbound ?: return null
        val requestId = "out-${conn.nextOutCounter()}"
        val exec = Wire.makeExecute(requestId, uri, operation, params,
            identity.identityHash(), capability.hash(), resource)
        val execSig = identity.sign(exec)
        val included = listOf(
            Envelope.Included(capability.hash(), capability),
            Envelope.Included(granterPeer.hash(), granterPeer),
            Envelope.Included(identity.identityHash(), identity.peerEntity),
            Envelope.Included(capSig.hash(), capSig),
            Envelope.Included(execSig.hash(), execSig),
        )
        return send(Envelope(exec, included))
    }

    // ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────────

    private fun ingestSignatures(env: Envelope) {
        for (pair in env.included) {
            val e = pair.entity
            if (e.type != "system/signature") continue
            store.putEntity(e)
            val signerH = e.bytes("signer") ?: continue
            val signerPeer = env.includedGet(signerH) ?: continue
            store.putEntity(signerPeer)
            val target = e.bytes("target")
            val pk = signerPeer.bytes("public_key")
            if (target != null && pk != null) {
                val pid = Identity.peerIdOfPublicKey(pk)
                store.bind("/$pid/system/signature/${Cbor.hex(target)}", e)
            }
        }
    }

    // ── handler resolution (§6.6) — backward tree-walk ─────────────────────────────────

    /** Return the longest prefix of [path] bound to a system/handler entity, or null. */
    private fun resolveHandler(path: String): String? {
        val segs = path.split("/")
        for (i in segs.size downTo 1) {
            val prefix = segs.subList(0, i).joinToString("/")
            val e = store.getAt(prefix)
            if (e != null && e.type == "system/handler") return prefix
        }
        return null
    }

    private fun stripLocal(pattern: String): String {
        val prefix = "/$localPeer/"
        return if (Capability.startsWith(prefix, pattern)) pattern.substring(prefix.length) else pattern
    }

    // ── entity-native dispatch (v7.74 §6.13(a)) ─────────────────────────────────────────

    private fun entityNativeDispatch(handlerPath: String): Outcome {
        val he = store.getAt(handlerPath) ?: return Outcome.err(404, "handler_not_found", handlerPath)
        val exprPath = he.text("expression_path") ?: return Outcome.err(501, "no_handler_body", handlerPath)
        val abs = Capability.canonicalize(localPeer, exprPath)
        val expr = store.getAt(abs) ?: return Outcome.err(404, "expression_not_found", abs)
        if (expr.type == "compute/literal") {
            val value = expr.field("value") ?: return Outcome.err(400, "unexpected_params", "compute/literal missing value")
            return Outcome.ok(Entity.make("compute/result",
                Cbor.map("value", value, "expression", Cbor.bytes(expr.hash()))))
        }
        return Outcome.err(501, "unsupported_expression", expr.type)
    }

    // ── dispatch chain (§6.5) ──────────────────────────────────────────────────────────

    /**
     * The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or null for a
     * non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
     */
    suspend fun dispatch(conn: Conn, env: Envelope): Envelope? {
        val exec = env.root
        if (exec.type != "system/protocol/execute") return null
        val requestId = exec.text("request_id") ?: ""
        val outcome = try {
            dispatchInner(conn, env, exec)
        } catch (g: Capability.UnresolvableGrantee) {
            Outcome.err(401, "unresolvable_grantee")
        } catch (e: RuntimeException) {
            if (System.getenv("PEER_DEBUG_500") != null) e.printStackTrace()
            Outcome.err(500, "internal_error")
        }
        return Envelope(Wire.makeResponse(requestId, outcome.status, outcome.result), outcome.included)
    }

    private suspend fun dispatchInner(conn: Conn, env: Envelope, exec: Entity): Outcome {
        val uri = exec.text("uri") ?: ""
        val operation = exec.text("operation") ?: ""
        if (uri == "system/protocol/connect") {
            return handlers.getValue("system/protocol/connect")
                .handle(operation, HandlerContext(exec, conn, env.included, null, env))
        }
        ingestSignatures(env)
        // §5.2 three-way request verdict (+ §4.10(b) chain-depth) — exhaustive `when`.
        when (Capability.verifyRequest(localPeer, store, env)) {
            Capability.RequestVerdict.AUTHN_FAIL -> return Outcome.err(401, "authentication_failed")
            Capability.RequestVerdict.AUTHZ_DENY -> return Outcome.err(403, "capability_denied")
            Capability.RequestVerdict.CHAIN_TOO_DEEP -> return Outcome.err(400, "chain_depth_exceeded")
            Capability.RequestVerdict.ALLOW -> {} // fall through
        }
        val path = Capability.canonicalize(localPeer, Capability.normalizeUri(uri))
        // §1.4: inbound dispatch must target the local peer.
        if (Capability.extractPeer(localPeer, path) != localPeer) {
            return Outcome.err(404, "handler_not_found", "not local peer")
        }
        val pattern = resolveHandler(path) ?: return Outcome.err(404, "handler_not_found", path)
        val capH = exec.bytes("capability")
        val callerCap = capH?.let { env.includedGet(it) } ?: return Outcome.err(403, "capability_denied")
        val resolveFn = { h: ByteArray -> Capability.capResolve(env.included, store, h) }
        val granterPeer = Capability.resolveGranterPeerId(resolveFn, callerCap) ?: localPeer
        if (Capability.checkPermission(localPeer, granterPeer, exec, callerCap, pattern) == Capability.Verdict.DENY) {
            return Outcome.err(403, "capability_denied")
        }
        val stripped = stripLocal(pattern)
        val inst = handlers[stripped]
        return inst?.handle(operation, HandlerContext(exec, conn, env.included, callerCap, env))
            ?: entityNativeDispatch(pattern)
    }

    // ── bootstrap (§6.9) ──────────────────────────────────────────────────────────────

    private fun opSpec(input: String?, output: String?): EcfValue.MapVal {
        val pairs = ArrayList<EcfValue.Entry>()
        if (input != null) pairs.add(EcfValue.Entry(EcfValue.Text("input_type"), EcfValue.Text(input)))
        if (output != null) pairs.add(EcfValue.Entry(EcfValue.Text("output_type"), EcfValue.Text(output)))
        return EcfValue.MapVal(pairs)
    }

    private fun bootstrapHandlerEntities(pattern: String, name: String, ops: List<Triple<String, String?, String?>>) {
        val opPairs = ops.map { (op, input, output) ->
            EcfValue.Entry(EcfValue.Text(op), opSpec(input, output))
        }
        val operations = EcfValue.MapVal(opPairs)
        store.bind("/$localPeer/$pattern", Entity.make("system/handler",
            Cbor.map("interface", "system/handler/$pattern")))
        store.bind("/$localPeer/system/handler/$pattern", Entity.make("system/handler/interface",
            Cbor.map("pattern", pattern, "name", name, "operations", operations)))
        val m = mintToken(identity.identityHash(), emptyList(), null)
        store.bind("/$localPeer/system/capability/grants/$pattern", m.token)
    }

    /** A bootstrap handler spec: pattern, instance, display name, ops (op→input?,output?). */
    private data class HandlerSpec(
        val pattern: String,
        val handler: Handler,
        val name: String,
        val ops: List<Triple<String, String?, String?>>,
    )

    private fun bootstrap() {
        // local identity entity in the store (root-granter resolution)
        store.putEntity(identity.peerEntity)
        // publish the §9.5 core type floor
        CoreTypes.publish(store, localPeer)

        // instantiate + register the MUST handler instances (the §6.6 → instance map)
        val bootstrap = listOf(
            HandlerSpec("system/tree", TreeHandler(), "Tree",
                listOf(Triple("get", null, null), Triple("put", null, null))),
            HandlerSpec("system/handler", HandlersHandler(), "Handlers", listOf(
                Triple("register", "system/handler/register-request", "system/handler/register-result"),
                Triple("unregister", "system/handler/unregister-request", null))),
            HandlerSpec("system/type", TypeHandler(), "Types",
                listOf(Triple("validate", "system/type/validate-request", "system/type/validate-result"))),
            HandlerSpec("system/capability", CapabilityHandler(), "Capability", listOf(
                Triple("request", "system/capability/request", "system/capability/grant"),
                Triple("revoke", "system/capability/revoke-request", null),
                Triple("configure", "system/capability/policy-entry", null),
                Triple("delegate", "system/capability/delegate-request", "system/capability/grant"))),
            HandlerSpec("system/protocol/connect", ConnectHandler(), "Connect",
                listOf(Triple("hello", null, null), Triple("authenticate", null, null))),
        )
        for (spec in bootstrap) {
            handlers[spec.pattern] = spec.handler
            bootstrapHandlerEntities(spec.pattern, spec.name, spec.ops)
        }

        // §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap (root, full scope
        // over /{peer}/(star), grantee = own identity; §6.9a.0 detached-sig shape) + default
        // scope-template entry. Read back by authenticate (dual-form lookup).
        val policyBase = "/$localPeer/system/capability/policy/"
        val owner = mintToken(identity.identityHash(), ownerGrants(), null)
        store.bind(policyBase + Cbor.hex(identity.identityHash()), owner.token)
        store.bind("/$localPeer/system/signature/${Cbor.hex(owner.token.rawHash())}", owner.signature)
        val defaultGrants = if (openGrants) openGrantsScope() else discoveryFloor()
        val defaultEntry = Entity.make("system/capability/policy-entry",
            Cbor.map("peer_pattern", "default", "grants", grantsArray(defaultGrants)))
        store.bind(policyBase + "default", defaultEntry)

        // §7a conformance handlers — only bootstrapped under --validate
        if (conformance) {
            val conf = listOf(
                HandlerSpec("system/validate/echo", EchoHandler(), "validate-echo",
                    listOf(Triple("echo", null, null))),
                HandlerSpec("system/validate/dispatch-outbound", DispatchOutboundHandler(),
                    "validate-dispatch-outbound", listOf(Triple("dispatch", null, null))),
            )
            for (spec in conf) {
                handlers[spec.pattern] = spec.handler
                bootstrapHandlerEntities(spec.pattern, spec.name, spec.ops)
            }
        }
    }

    // ── small helpers ────────────────────────────────────────────────────────────────

    private fun abs(rel: String): String = "/$localPeer/$rel"

    companion object {
        /** Build a grant cbor-map. [peers] null → omit (defaults to local at check time). */
        fun grant(handlers: List<String>, resources: List<String>, operations: List<String>, peers: List<String>?): EcfValue.MapVal {
            val pairs = ArrayList<EcfValue.Entry>()
            pairs.add(EcfValue.Entry(EcfValue.Text("handlers"), scopeCbor(handlers, null)))
            pairs.add(EcfValue.Entry(EcfValue.Text("resources"), scopeCbor(resources, null)))
            pairs.add(EcfValue.Entry(EcfValue.Text("operations"), scopeCbor(operations, null)))
            if (peers != null) pairs.add(EcfValue.Entry(EcfValue.Text("peers"), scopeCbor(peers, null)))
            return EcfValue.MapVal(pairs)
        }

        private fun scopeCbor(incl: List<String>, excl: List<String>?): EcfValue.MapVal =
            if (excl != null) Cbor.map("include", Cbor.textArray(incl), "exclude", Cbor.textArray(excl))
            else Cbor.map("include", Cbor.textArray(incl))

        private fun grantsArray(grants: List<EcfValue.MapVal>): EcfValue =
            EcfValue.Arr(grants.toList())

        /** Construct + bootstrap a peer from a 32-byte Ed25519 seed. */
        fun create(seed: ByteArray, openGrants: Boolean = false, conformance: Boolean = false): Peer {
            val identity = Identity.ofSeed(seed)
            val peer = Peer(identity, Store(), identity.peerId, openGrants, conformance)
            peer.bootstrap()
            return peer
        }

        private fun execResourceTarget(exec: Entity): String? {
            val r = exec.mapField("resource") ?: return null
            val targets = Cbor.textList(r, "targets")
            return targets?.firstOrNull()
        }

        private fun pathFlexOk(target: String): Boolean {
            if (target.indexOf('\u0000') >= 0) return false
            val segs0 = target.split("/")
            val absOk: Boolean
            var body: List<String>
            if (Capability.startsWith("/", target)) {
                if (segs0.size >= 2 && segs0[0].isEmpty()) {
                    absOk = Capability.isPeerId(segs0[1])
                    body = segs0.subList(1, segs0.size)
                } else {
                    absOk = false
                    body = segs0
                }
            } else {
                absOk = true
                body = segs0
            }
            if (!absOk) return false
            if (body.isNotEmpty() && body.last().isEmpty()) body = body.subList(0, body.size - 1)
            return body.none { it.isEmpty() || it == "." || it == ".." }
        }

        private fun isZeroHash(h: ByteArray): Boolean = h.all { it.toInt() == 0 }

        private fun reqGrants(params: Entity?): List<EcfValue.MapVal> =
            params?.let { Cbor.mapList(it.data(), "grants") } ?: emptyList()

        private fun registerPattern(exec: Entity): String? {
            val target = execResourceTarget(exec) ?: return null
            val prefix = "system/handler/"
            if (!Capability.startsWith(prefix, target) || target.length == prefix.length) return null
            return target.substring(prefix.length)
        }

        private fun registerPatternError(exec: Entity): Outcome {
            execResourceTarget(exec)
                ?: return Outcome.err(400, "ambiguous_resource", "register/unregister require exactly one resource target")
            return Outcome.err(400, "invalid_resource", "resource target MUST be system/handler/{pattern}")
        }
    }
}
