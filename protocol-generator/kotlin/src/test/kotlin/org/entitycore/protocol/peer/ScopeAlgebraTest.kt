package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The §5 scope algebra at the unit level: §5.2's effective-target projection (0.8.2.20,
 * N11), §6.3's `check_path_permission`, the §5.4 sentinel's scoping to PATH-SCOPE
 * (0.8.2.24 N2/N3) and §5.5a's `scope_subset` typed by scope kind (F50, ruled at
 * 0.8.2.16).
 *
 * AUTHORED HERE BECAUSE THE PINNED CHECK SET HAS NO VECTOR ON THIS SURFACE. Every one of
 * these behaviours is measurable on the wire by `tools/arc-probe` and by nothing in the
 * 778-check core gate, so a unit that regresses silently is exactly what `run-s2.sh` is
 * for.
 */
class ScopeAlgebraTest {

    private val local = "z6MkLocalPeerIdentityBase58PlaceholderAAAAAAAAAAA"

    // ── §5.2 effective targets (0.8.2.20 / N11) ────────────────────────────────────

    /**
     * The pair — survivors AND "was there a resource at all" — is §3.3's NON-LOSSY
     * PROJECTION `[MUST]` (0.8.2.25, N11). A function returning only a list collapses
     * `[qA] exclude [qA]` to `[]` and deletes the two-empties discriminator before any
     * handler can read it.
     */
    @Test
    fun effectiveTargetsSeparatesTheTwoEmpties() {
        val absent = Capability.effectiveTargets(local, execWith(null))
        assertFalse(absent.hasResource)
        assertTrue(absent.survivors.isEmpty())

        val self = Capability.effectiveTargets(local, execWith(resource(listOf("qA"), listOf("qA"))))
        assertTrue(self.hasResource, "the discriminator N11 requires")
        assertTrue(self.survivors.isEmpty())
    }

    /**
     * The caller's own exclude removes entries BEFORE anything else looks at the request,
     * and survivors come back in the caller's OWN SPELLING — 0.8.2.21 is explicit that
     * `effective_targets` yields raw survivors, and the value flows on to a tree lookup
     * that canonicalizes for itself.
     */
    @Test
    fun effectiveTargetsNarrowsAndKeepsTheCallersSpelling() {
        assertEquals(
            listOf("qB"),
            Capability.effectiveTargets(local, execWith(resource(listOf("qA", "qB"), listOf("qA")))).survivors,
        )
        assertEquals(
            listOf("qA", "qB"),
            Capability.effectiveTargets(local, execWith(resource(listOf("qA", "qB"), null))).survivors,
        )
    }

    /**
     * The caller-exclude arm is fail-OPEN on an unmatchable pattern; §5.4 rules it
     * separately from the grant arm, where the same value is fail-CLOSED. INHERITED from
     * the primitives rather than restated: the pattern canonicalizes to the sentinel and
     * `matchesPattern` then answers false, so the target survives.
     */
    @Test
    fun effectiveTargetsUnmatchableCallerExcludeCarvesOutNothing() {
        assertEquals(
            listOf("qA"),
            Capability.effectiveTargets(local, execWith(resource(listOf("qA"), listOf("../nope")))).survivors,
        )
    }

    /**
     * A PRESENT-BUT-ILL-TYPED `targets` is PRESENT, with an empty survivor list. Reporting
     * it absent would serve the WIDER absent-case answer to a request that named a
     * resource — N11's own defect one field over, and the cell the two vanguard peers
     * initially disagreed on.
     */
    @Test
    fun effectiveTargetsIllTypedTargetsAreStillPresent() {
        val ill = Capability.effectiveTargets(local, execWith(Cbor.map("targets", "not-an-array")))
        assertTrue(ill.hasResource)
        assertTrue(ill.survivors.isEmpty())

        // A resource map with no `targets` key at all is ABSENT, not present-and-empty:
        // there is no target list to have been emptied.
        assertFalse(
            Capability.effectiveTargets(local, execWith(Cbor.map("exclude", Cbor.textArray("x")))).hasResource,
        )
    }

    // ── §6.3 check_path_permission ─────────────────────────────────────────────────

    /**
     * ONE ACCEPT AND ONE DENY PER DIMENSION. The accept case is what validates the FIXTURE:
     * a predicate test built only from deny cases is indistinguishable from one asserting
     * `false == false`, because a broken fixture denies everything for free. One deny per
     * dimension is what says the predicate checks the dimension rather than merely being
     * able to say no.
     */
    @Test
    fun checkPathPermissionAcceptsInGrantAndDeniesPerDimension() {
        val cap = token(Peer.grant(listOf("system/tree"), listOf("q/*"), listOf("get"), null))

        assertTrue(Capability.checkPathPermission(local, "get", "q/a", cap, "system/tree"))
        assertFalse(Capability.checkPathPermission(local, "get", "other/a", cap, "system/tree"), "resources")
        assertFalse(Capability.checkPathPermission(local, "put", "q/a", cap, "system/tree"), "operations")
        assertFalse(Capability.checkPathPermission(local, "get", "q/a", cap, "system/capability"), "handlers")
    }

    /**
     * An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
     * tree paths) and DENIES every path — `covered` over an empty include list is false,
     * which is what that note says it should be.
     */
    @Test
    fun checkPathPermissionEmptyResourceIncludeDeniesEveryPath() {
        val cap = token(Peer.grant(listOf("system/tree"), emptyList(), listOf("get"), null))
        assertFalse(Capability.checkPathPermission(local, "get", "q/a", cap, "system/tree"))
    }

    /**
     * Canonicalization is TOTAL (0.8.2.20): a malformed path answers the sentinel, which
     * matches no grant, so it falls through to DENY rather than escaping as an exception
     * the §6.5 frame would answer with a 500.
     */
    @Test
    fun checkPathPermissionMalformedPathDenies() {
        val cap = token(Peer.grant(listOf("system/tree"), listOf("*"), listOf("get"), null))
        // The wide-open control first, or "false everywhere" would satisfy this vacuously.
        assertTrue(Capability.checkPathPermission(local, "get", "q/a", cap, "system/tree"))
        assertFalse(Capability.checkPathPermission(local, "get", "../escape", cap, "system/tree"))
    }

    // ── §5.4 sentinel, SCOPED TO PATH-SCOPE (0.8.2.24 N2/N3) ───────────────────────

    /**
     * *"a capability carrying an unmatchable PATH-SCOPE pattern is INVALID … It does NOT
     * reach `operations` or `peers` `[MUST]`"*.
     *
     * The unscoped guard ran an id pattern through the §5.4 transforms purely to classify
     * it and then denied the WHOLE dimension on a property unrelated to whether the exclude
     * carves anything out: a bare-star-slash operation name path-canonicalizes to the
     * sentinel. Over-denial, invisible on any well-formed grant.
     */
    @Test
    fun sentinelDeniesOnPathScopeOnly() {
        val idScope = Capability.Scope(listOf("*"), listOf("*/apply"))
        // The ID arm: the exclude is a literal that simply does not equal `compute`, so the
        // include still carries and the dimension is NOT denied.
        assertTrue(Capability.matchesScope(local, "compute", idScope, Capability.ScopeKind.ID))
        // …and it still EXCLUDES what it literally names, or the guard has merely been
        // deleted rather than scoped.
        assertFalse(Capability.matchesScope(local, "*/apply", idScope, Capability.ScopeKind.ID))

        // The PATH arm keeps 0.8.2.21's rule: an unmatchable exclude DENIES rather than
        // carving out nothing.
        assertFalse(
            Capability.matchesScope(
                local, "q/a", Capability.Scope(listOf("*"), listOf("../nope")), Capability.ScopeKind.PATH,
            ),
        )
        // Control: the identical include with no unmatchable exclude allows.
        assertTrue(
            Capability.matchesScope(
                local, "q/a", Capability.Scope(listOf("*"), emptyList()), Capability.ScopeKind.PATH,
            ),
        )
    }

    // ── §5.5a scope_subset typed by scope kind (F50 / 0.8.2.16) ────────────────────

    /**
     * §3.6's id-scope grammar binds the scope TYPE, not one function — *"An implementation
     * on the canonicalizing reading is non-conformant and MUST adopt the literal matcher"*
     * — so the rule F40 landed on `matchesScope` reaches `scope_subset` too.
     *
     * A namespaced operation name is the witness and it is fail-CLOSED: under the
     * canonicalizing reading it becomes the §5.4 sentinel, which matches nothing in either
     * operand, so a legitimate child `operations` include was refused against a parent of
     * `*`. The literal matcher covers it.
     */
    @Test
    fun scopeSubsetOperationsUseTheLiteralMatcher() {
        val wideOpen = grantRec(scope("*"), scope("*"), scope("*"))

        assertTrue(
            Capability.grantSubset(
                local, local, local,
                grantRec(scope("system/tree"), scope("q/*"), scope("*/apply")), wideOpen,
            ),
        )

        // The EXCLUDE arm of the same pair: a parent exclude the child repeats verbatim is
        // inherited under the literal matcher and was not under the canonicalizing one.
        assertTrue(
            Capability.grantSubset(
                local, local, local,
                grantRec(scope("system/tree"), scope("q/*"), Capability.Scope(listOf("*"), listOf("*/apply"))),
                grantRec(scope("*"), scope("*"), Capability.Scope(listOf("*"), listOf("*/apply"))),
            ),
        )

        // THE MATCHER HALF, and it is here because its plant RAN GREEN without it on the
        // sibling peers. The cases above are decided by the FRAME (the sentinel), so
        // replacing only `covers` with the path matcher left every assertion passing — an
        // inert control. This pair separates the two matchers on strings the frame leaves
        // alone: §5.4's peer-wildcard walk makes `matchesPattern("/x/get", "/*/get")` TRUE
        // while §3.6's literal matcher answers FALSE. Under the canonicalizing reading the
        // child therefore reads as covered by a parent it does not literally match, and the
        // child grant comes out WIDER than its parent — the widening F50 names.
        assertFalse(
            Capability.grantSubset(
                local, local, local,
                grantRec(scope("system/tree"), scope("q/*"), scope("/x/get")),
                grantRec(scope("*"), scope("*"), scope("/*/get")),
            ),
            "operations must use the LITERAL matcher, not the peer-wildcard walk",
        )

        // CONTROL — the typing must not turn scope_subset into a rubber stamp: an
        // operations include the parent does not literally cover is still refused.
        assertFalse(
            Capability.grantSubset(
                local, local, local,
                grantRec(scope("system/tree"), scope("q/*"), scope("put")),
                grantRec(scope("*"), scope("*"), scope("get")),
            ),
        )

        // CONTROL — the PATH dimensions keep the canonicalizing matcher: a resources
        // include outside the parent's subtree is refused.
        assertFalse(
            Capability.grantSubset(
                local, local, local,
                grantRec(scope("system/tree"), scope("other/*"), scope("get")),
                grantRec(scope("*"), scope("q/*"), scope("*")),
            ),
        )
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────

    private fun scope(vararg incl: String) = Capability.Scope(incl.toList(), emptyList())

    private fun grantRec(handlers: Capability.Scope, resources: Capability.Scope, operations: Capability.Scope) =
        Capability.GrantRec(handlers, resources, operations, null)

    /**
     * A token entity carrying `grants`. `granter`/`grantee`/`created_at` are not read by
     * `check_path_permission`, which answers about the token's GRANTS only — the chain,
     * signature, temporal bounds and revocation are `verifyRequest`'s and must already have
     * held.
     */
    private fun token(vararg grants: EcfValue.MapVal): Entity = Entity.make(
        "system/capability/token",
        Cbor.map(
            "grants", EcfValue.Arr(grants.toList()),
            "granter", Cbor.bytes(ByteArray(33)),
            "grantee", Cbor.bytes(ByteArray(33)),
            "created_at", EcfValue.IntVal.of(1_700_000_000_000L),
        ),
    )

    private fun resource(targets: List<String>, exclude: List<String>?): EcfValue.MapVal =
        if (exclude == null) {
            Cbor.map("targets", Cbor.textArray(targets))
        } else {
            Cbor.map(
                "targets", Cbor.textArray(targets),
                "exclude", Cbor.textArray(exclude),
            )
        }

    /**
     * An EXECUTE carrying `resource` VERBATIM — the §3.3 ladder has to tell "no resource"
     * from "a resource whose every target was excluded" and answer each with its own
     * disposition, so the shapes here deliberately include ones no admission parser would
     * accept.
     */
    private fun execWith(resource: EcfValue?): Entity =
        if (resource == null) {
            Entity.make(
                "system/protocol/execute",
                Cbor.map("request_id", "t", "uri", "system/tree", "operation", "get"),
            )
        } else {
            Entity.make(
                "system/protocol/execute",
                Cbor.map("request_id", "t", "uri", "system/tree", "operation", "get", "resource", resource),
            )
        }
}
