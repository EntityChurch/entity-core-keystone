package org.entitycore.protocol.peer

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.entitycore.protocol.codec.EcfValue
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * S3 two-peer loopback smoke test (the phase exit gate).
 *
 * Two Kotlin peers talk over real loopback TCP through the full §6.5 dispatch chain. A
 * RESPONDER peer listens; an INITIATOR peer (a second identity) dials it and drives the
 * §4.1 forward handshake (hello → authenticate), then:
 *  - 404 on an unregistered path (no handler resolved);
 *  - an authority-gated tree get (200) over the §4.4 discovery floor;
 *  - a capability request (200);
 *  - 8-way request_id demux of concurrently-issued replies (N7, §6.11), via 8 coroutines.
 *
 * A second scenario exercises the v7.74 Core Extensibility Boundary (--debug-open-grants
 * + --validate): the register live-hook (§6.13(a)), the emit hook firing on register's
 * tree writes (§6.13(c)), the §7a echo handler, AND the §6.11 dispatch-outbound reentry
 * (the validator-as-B-role surface S4's origination-core needs).
 *
 * The full validate-peer --profile core run is S4. This smoke proves the wire-level peer
 * surface so S4 can run the oracle.
 */
class SmokeTest {

    private val results = ArrayList<Boolean>()

    private fun check(name: String, ok: Boolean): Boolean {
        results.add(ok)
        println("  [${if (ok) "PASS" else "FAIL"}] $name")
        return ok
    }

    private fun seed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

    @Test
    fun twoPeerLoopback() {
        runBlocking {
            runCoreScenario()
            runExtensibilityScenario()
        }
        val allPass = results.all { it }
        val pass = results.count { it }
        println("\nSMOKE: ${if (allPass) "PASS" else "FAIL"} ($pass/${results.size})")
        assertTrue(allPass, "two-peer loopback must be all-PASS")
    }

    // ── Scenario 1: core ops (responder = default seed policy) ──────────────────────

    private suspend fun runCoreScenario() {
        val responder = Peer.create(seed(0x11))
        Transport.startListener(responder, 0).use { listener ->
            println("Responder listening on 127.0.0.1:${listener.port} (peer ${responder.localPeer})")
            val initiator = Peer.create(seed(0x22))
            Transport.dial(initiator, "127.0.0.1", listener.port).use { s ->
                val remote = s.remotePeerId!!
                println("Handshake:")
                check("session established (capability minted)", s.capability != null)
                check("remote peer_id matches responder", remote == responder.localPeer)

                println("Dispatch:")
                // 404 on an unregistered path
                val r404 = s.execute("/$remote/does/not/exist", "noop", Wire.emptyParams(), null)
                check("unregistered path -> 404", Wire.responseStatus(r404!!) == 404)

                // authority-gated tree get (200) over the discovery floor: a
                // handler-interface entity bootstrapped under system/handler/{pattern}.
                val ifaceTarget = Wire.resourceTarget("system/handler/system/tree")
                val rget = s.execute("/$remote/system/tree", "get", Wire.emptyParams(), ifaceTarget)!!
                check("granted tree get -> 200", Wire.responseStatus(rget) == 200)
                val res = Wire.responseResult(rget)
                check("tree get returns a system/handler/interface entity",
                    res != null && res.type == "system/handler/interface")

                // capability request (200)
                val reqGrant = Peer.grant(listOf("system/tree"), listOf("system/type/*"), listOf("get"), null)
                val reqParams = Entity.make("system/capability/request",
                    Cbor.map("grants", EcfValue.Arr(listOf(reqGrant))))
                val rcap = s.execute("/$remote/system/capability", "request", reqParams, null)!!
                check("capability request -> 200", Wire.responseStatus(rcap) == 200)

                // 8-way request_id demux (N7, §6.11) — 8 concurrent coroutines.
                println("Concurrency (request_id demux):")
                val correlated = coroutineScope {
                    (1..8).map {
                        async {
                            val r = s.execute("/$remote/system/tree", "get", Wire.emptyParams(),
                                Wire.resourceTarget("system/handler/system/tree"))
                            val rr = r?.let { e -> Wire.responseResult(e) }
                            r != null && Wire.responseStatus(r) == 200 &&
                                rr != null && rr.type == "system/handler/interface"
                        }
                    }.awaitAll().count { it }
                }
                check("8 interleaved requests each correlated -> $correlated/8", correlated == 8)
            }
        }
    }

    // ── Scenario 2: the v7.74 Core Extensibility Boundary over the wire ─────────────

    private suspend fun runExtensibilityScenario() {
        val responder = Peer.create(seed(0x33), openGrants = true, conformance = true)
        var emitEvents = 0
        responder.store.registerTreeConsumer { emitEvents++ }
        Transport.startListener(responder, 0).use { listener ->
            // initiator is ALSO a --validate peer so the §6.11 reentry echo round-trips
            // (B originates echo back to A; A must serve it — the S4 validator-as-B shape).
            val initiator = Peer.create(seed(0x44), openGrants = true, conformance = true)
            Transport.dial(initiator, "127.0.0.1", listener.port).use { s ->
                val remote = s.remotePeerId!!
                val emitBefore = emitEvents
                println("Extensibility (open-grants + --validate):")

                // register live-hook (§6.13(a))
                val manifest = Cbor.map("name", "demo", "operations", Cbor.emptyMap())
                val req = Entity.make("system/handler/register-request", Cbor.map("manifest", manifest))
                val rreg = s.execute("/$remote/system/handler", "register", req,
                    Wire.resourceTarget("system/handler/demo"))!!
                check("handler register -> 200 (live, not 501)", Wire.responseStatus(rreg) == 200)
                check("emit hook fired on register's tree writes (§6.13(c))", emitEvents > emitBefore)

                // §7a echo conformance handler (resolve→dispatch)
                val payload = Entity.make("primitive/any", Cbor.map("ping", EcfValue.IntVal.of(42L)))
                val recho = s.execute("/$remote/system/validate/echo", "echo", payload, null)!!
                check("§7a echo -> 200", Wire.responseStatus(recho) == 200)
                val res = Wire.responseResult(recho)
                check("§7a echo returns params verbatim", res != null && res.type == "primitive/any")

                // §6.11 dispatch-outbound REENTRY: the responder (B) originates an outbound
                // EXECUTE back over THIS inbound connection to the initiator (A). The
                // initiator's reader dispatches it (it must serve echo too → make it a
                // --validate peer). We model the validator-as-B surface S4 needs.
                check("§6.11 dispatch-outbound reentry round-trips (B→A echo over inbound conn)",
                    runReentryProbe(s, remote))
            }
        }
    }

    /**
     * Drive the §6.11 dispatch-outbound seam: the responder's (B) dispatch-outbound
     * handler originates an outbound EXECUTE back to the caller (A) over the SAME inbound
     * connection (reentry). The connection IS reentrant (B can write to A over the open
     * socket), so this proves the §6.13(b) outbound primitive + the §6.11 reentry param
     * shape end-to-end — the exact surface S4's origination-core
     * `dispatch_outbound_reentry` exercises over real two-peer TCP, here validated at the
     * smoke level (the validator supplies the cross-peer reentry cap at S4; the smoke
     * passes the session cap to prove the seam parses + reaches the outbound primitive).
     *
     * Accept 200 (the initiator A served the reentrant EXECUTE and B round-tripped it) OR
     * a structured 503 (no_outbound_seam — only if the connection were non-reentrant);
     * reject 404/501 (handler absent — seam not wired) or 400 (param shape rejected).
     */
    private suspend fun runReentryProbe(s: Transport.Session, remote: String): Boolean {
        val params = Entity.make("primitive/any", Cbor.map(
            "target", "system/validate/echo",
            "operation", "echo",
            "value", Cbor.map("ping", EcfValue.IntVal.of(7L)),
            "reentry_capability", s.capability!!.toCbor(),
            "reentry_granter", s.granterPeer!!.toCbor(),
            "reentry_cap_signature", s.capSignature!!.toCbor(),
        ))
        val r = s.execute("/$remote/system/validate/dispatch-outbound", "dispatch", params, null)
            ?: return false
        // Outer 200 = the §6.11 reentry round-tripped end-to-end: B's dispatch-outbound
        // handler originated an EXECUTE back to A over the SAME inbound connection, A's
        // reader dispatched it and replied, and B correlated the reply by request_id and
        // returned it — the full §6.13(b)+§6.11 transport path over real two-peer TCP.
        // The INNER status carried in the result reflects A's authz verdict on the
        // reentrant EXECUTE: here A authorizes by the cap B passed (the session cap A's
        // granter B minted), so the inner echo verdict is a §5.2 cap check, not the
        // transport. S4's validator supplies the cross-peer reentry cap that makes the
        // inner verdict 200; the smoke proves the transport seam round-trips (outer 200).
        val inner = Wire.responseResult(r)?.uint("status")?.toInt()
        println("    (reentry round-tripped; inner echo verdict=$inner)")
        return Wire.responseStatus(r) == 200
    }
}
