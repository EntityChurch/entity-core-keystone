package org.entitycore.protocol.peer

import kotlinx.coroutines.runBlocking
import org.entitycore.protocol.codec.EcfValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * §3.3's effective-targets ladder (0.8.2.20, refined at .24/.25) and §6.3's listing filter,
 * driven end-to-end over real loopback.
 *
 * The ladder runs on the EFFECTIVE list, never on `resource.targets`: a handler that counts
 * the effective list and then indexes `targets[0]` has implemented the arithmetic
 * completely and is still reading a path no authorization covered. This peer did not even
 * count — it read `targets[0]` and answered 200 — so `targets:[a,b] exclude:[a]` served `a`.
 */
class TreeLadderTest {

    private fun seed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

    private fun codeOf(env: Envelope?): String = Wire.responseResult(env!!)?.text("code") ?: ""

    private fun resource(targets: List<String>, exclude: List<String>?): EcfValue.MapVal =
        if (exclude == null) {
            Cbor.map("targets", Cbor.textArray(targets))
        } else {
            Cbor.map("targets", Cbor.textArray(targets), "exclude", Cbor.textArray(exclude))
        }

    /** §3.3's rows, one code each. */
    @Test
    fun ladderAnswersEachRowWithItsOwnCode() = runBlocking {
        // The responder runs the degenerate default->* seed policy so the caller's grant
        // covers every path: these rows are about the LADDER's arithmetic, not about
        // authorization, and a narrow grant would answer 403 before the ladder is reached.
        val responder = Peer.create(seed(0x51), openGrants = true)
        Transport.startListener(responder, 0).use { listener ->
            val initiator = Peer.create(seed(0x52))
            Transport.dial(initiator, "127.0.0.1", listener.port).use { s ->
                val tree = "/${s.remotePeerId!!}/system/tree"

                // ABSENT resource -> the root listing. EXTENSION-TREE §2.2a (v4.11) declares
                // `get` resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
                // listing".
                val absent = s.execute(tree, "get", Wire.emptyParams(), null)
                assertEquals(200, Wire.responseStatus(absent!!))
                assertEquals("system/tree/listing", Wire.responseResult(absent!!)?.type)

                // PRESENT and self-excluded -> 400 path_required. THE TWO EMPTIES ARE
                // DISTINCT for a resource-OPTIONAL operation (0.8.2.24 N7 / 0.8.2.25 N10):
                // serving this the absent case "answers a request for one excluded path with
                // a listing of the tree".
                val self = s.execute(tree, "get", Wire.emptyParams(), resource(listOf("app/a"), listOf("app/a")))
                assertEquals(400, Wire.responseStatus(self!!))
                assertEquals("path_required", codeOf(self))

                // Two survivors -> 400 ambiguous_resource. A peer indexing targets[0] answers
                // 200 and cannot tell the caller it ignored the second.
                val amb = s.execute(tree, "get", Wire.emptyParams(), resource(listOf("app/a", "app/b"), null))
                assertEquals(400, Wire.responseStatus(amb!!))
                assertEquals("ambiguous_resource", codeOf(amb))

                // A PATTERN subject -> 400 malformed_resource. A resource-requiring operation
                // takes a CONCRETE path; without this the pattern is looked up as a literal
                // and answers 404, which names the wrong fault.
                val pat = s.execute(tree, "get", Wire.emptyParams(), resource(listOf("system/type/*"), null))
                assertEquals(400, Wire.responseStatus(pat!!))
                assertEquals("malformed_resource", codeOf(pat))

                // An unmatchable CALLER exclude carves out NOTHING — the fail-OPEN direction
                // of §5.4's sentinel, and the correct one here.
                val unmatchable =
                    s.execute(tree, "get", Wire.emptyParams(), resource(listOf("system/type/"), listOf("../nope")))
                assertEquals(200, Wire.responseStatus(unmatchable!!))

                // `put` collapses the two empties: §2.2a declares it resource-REQUIRED. Note
                // the code 0.8.2.20 forces — a MISSING target is NOT `ambiguous_resource`;
                // *supply a resource* is not *disambiguate your request*, and this peer
                // answered `ambiguous_resource` for both.
                assertEquals("path_required", codeOf(s.execute(tree, "put", Wire.emptyParams(), null)))
                assertEquals(
                    "path_required",
                    codeOf(s.execute(tree, "put", Wire.emptyParams(), resource(listOf("app/a"), listOf("app/a")))),
                )
                assertEquals(
                    "ambiguous_resource",
                    codeOf(s.execute(tree, "put", Wire.emptyParams(), resource(listOf("app/a", "app/b"), null))),
                )

                // RULE G control: the OPERATION resolves FIRST. An unknown op with no resource
                // answers the OPERATION fault, never the resource one — a handler that
                // validates the resource first names the wrong fault for every unknown
                // operation.
                val bogus = s.execute(tree, "bogusop", Wire.emptyParams(), null)
                assertEquals(501, Wire.responseStatus(bogus!!))
                assertEquals("unsupported_operation", codeOf(bogus))
            }
        }
    }

    /**
     * `targets:[a,b] exclude:[a]`. The effective set is `{b}`, size 1, so the COUNT rule
     * says proceed — and a raw `targets[0]` selector proceeds on `a`. Both are bound, so a
     * 200 naming `a` is a selection defect and nothing else.
     */
    @Test
    fun ladderSelectsTheSubjectFromTheEffectiveSet() = runBlocking {
        val responder = Peer.create(seed(0x53), openGrants = true)
        Transport.startListener(responder, 0).use { listener ->
            val initiator = Peer.create(seed(0x54))
            Transport.dial(initiator, "127.0.0.1", listener.port).use { s ->
                val remote = s.remotePeerId!!
                responder.store.bind("/$remote/app/sel/a", Entity.make("test/a", Cbor.emptyMap()))
                responder.store.bind("/$remote/app/sel/b", Entity.make("test/b", Cbor.emptyMap()))

                val r = s.execute(
                    "/$remote/system/tree", "get", Wire.emptyParams(),
                    resource(listOf("app/sel/a", "app/sel/b"), listOf("app/sel/a")),
                )
                assertEquals(200, Wire.responseStatus(r!!))
                assertNotNull(Wire.responseResult(r!!))
                assertEquals("test/b", Wire.responseResult(r!!)?.type, "targets[0] would have answered test/a")
            }
        }
    }

    /**
     * §6.3's listing filter (0.8.2.21/.22) — *"each entry MUST be individually checked using
     * `check_path_permission`. Entries for which `check_path_permission` returns DENY MUST
     * be omitted. The result's `count` field MUST reflect the filtered entry count, not the
     * source tree's total count."*
     *
     * Driven through a hand-built [HandlerContext] rather than a session, because the NARROW
     * GRANT is the whole input and minting one over the wire would put three more moving
     * parts between the assertion and the thing asserted. The wire half is
     * `tools/arc-probe` G4.
     */
    @Test
    fun listingOmitsEntriesTheCallersCapabilityExcludes() = runBlocking {
        val peer = Peer.create(seed(0x55), openGrants = true)
        val base = "/${peer.localPeer}/app/list"
        peer.store.bind("$base/a", Entity.make("test/leaf", Cbor.emptyMap()))
        peer.store.bind("$base/b", Entity.make("test/leaf", Cbor.emptyMap()))

        // THE CONTROL, and it is what makes the assertion below falsifiable: with a grant
        // covering BOTH, the listing names both. "b is absent" under a narrower grant is the
        // trivial truth if the directory read does not work at all.
        val wide = listUnder(peer, narrowToken("app/list/*"))
        assertEquals(listOf("a", "b"), wide.first)
        assertEquals(2, wide.second)

        val narrow = listUnder(peer, narrowToken("app/list/a"))
        assertEquals(listOf("a"), narrow.first, "an excluded entry MUST be omitted")
        assertEquals(1, narrow.second, "`count` MUST follow the FILTERED total")

        // An UNAUTHENTICATED context is not filtered — the filter's subject is "the caller's
        // verified capability", and where there is none there is no caller to narrow. This
        // is the bootstrap path, and it matches both vanguard peers.
        assertEquals(listOf("a", "b"), listUnder(peer, null).first)
    }

    private suspend fun listUnder(peer: Peer, cap: Entity?): Pair<List<String>, Int> {
        val exec = Wire.makeExecute(
            "l1", "system/tree", "get", Wire.emptyParams(),
            resource = resource(listOf("app/list/"), null),
        )
        val env = Envelope(exec)
        val out = peer.handlerFor("system/tree")!!
            .handle("get", HandlerContext(exec, Conn(), env.included, cap, env, "system/tree"))
        assertEquals(200, out.status)
        val entries = out.result.mapField("entries")!!
        val names = entries.entries.map { (it.key as EcfValue.Text).value }.sorted()
        return Pair(names, out.result.uint("count")!!.toInt())
    }

    /**
     * A token whose single grant covers `system/tree`, `get`, and exactly `resources`.
     * `granter`/`grantee`/`created_at` are not read by `check_path_permission`, which
     * answers about the token's GRANTS only.
     */
    private fun narrowToken(vararg resources: String): Entity = Entity.make(
        "system/capability/token",
        Cbor.map(
            "grants", EcfValue.Arr(
                listOf(Peer.grant(listOf("system/tree"), resources.toList(), listOf("get"), null)),
            ),
            "granter", Cbor.bytes(ByteArray(33)),
            "grantee", Cbor.bytes(ByteArray(33)),
            "created_at", EcfValue.IntVal.of(1_700_000_000_000L),
        ),
    )
}
