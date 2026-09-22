package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.entitycore.protocol.codec.EcfValue;
import org.junit.jupiter.api.Test;

/**
 * The §5 scope algebra at the unit level: §5.2's effective-target projection (0.8.2.20,
 * N11), §6.3's {@code check_path_permission}, the §5.4 sentinel's scoping to PATH-SCOPE
 * (0.8.2.24 N2/N3) and §5.5a's {@code scope_subset} typed by scope kind (F50, ruled at
 * 0.8.2.16).
 *
 * <p>AUTHORED HERE BECAUSE THE PINNED CHECK SET HAS NO VECTOR ON THIS SURFACE. Every one of
 * these behaviours is measurable on the wire by {@code tools/arc-probe} and by nothing in
 * the 778-check core gate, so a unit that regresses silently is exactly what
 * {@code run-s2.sh} is for.
 */
final class ScopeAlgebraTest {

    private static final String LOCAL = "z6MkLocalPeerIdentityBase58PlaceholderAAAAAAAAAAA";

    // ── §5.2 effective targets (0.8.2.20 / N11) ────────────────────────────────────

    /**
     * The pair — survivors AND "was there a resource at all" — is §3.3's NON-LOSSY
     * PROJECTION {@code [MUST]} (0.8.2.25, N11). A function returning only a list collapses
     * {@code [qA] exclude [qA]} to {@code []} and deletes the two-empties discriminator
     * before any handler can read it.
     */
    @Test
    void effectiveTargetsSeparatesTheTwoEmpties() {
        Capability.EffectiveTargets absent = Capability.effectiveTargets(LOCAL, execWith(null));
        assertFalse(absent.hasResource());
        assertTrue(absent.survivors().isEmpty());

        Capability.EffectiveTargets self = Capability.effectiveTargets(
                LOCAL, execWith(resource(List.of("qA"), List.of("qA"))));
        assertTrue(self.hasResource(), "the discriminator N11 requires");
        assertTrue(self.survivors().isEmpty());
    }

    /**
     * The caller's own exclude removes entries BEFORE anything else looks at the request,
     * and survivors come back in the caller's OWN SPELLING — 0.8.2.21 is explicit that
     * {@code effective_targets} yields raw survivors, and the value flows on to a tree
     * lookup that canonicalizes for itself.
     */
    @Test
    void effectiveTargetsNarrowsAndKeepsTheCallersSpelling() {
        assertEquals(List.of("qB"), Capability.effectiveTargets(
                LOCAL, execWith(resource(List.of("qA", "qB"), List.of("qA")))).survivors());
        assertEquals(List.of("qA", "qB"), Capability.effectiveTargets(
                LOCAL, execWith(resource(List.of("qA", "qB"), null))).survivors());
    }

    /**
     * The caller-exclude arm is fail-OPEN on an unmatchable pattern; §5.4 rules it
     * separately from the grant arm, where the same value is fail-CLOSED. INHERITED from
     * the primitives rather than restated: the pattern canonicalizes to the sentinel and
     * {@code matchesPattern} then answers false, so the target survives.
     */
    @Test
    void effectiveTargetsUnmatchableCallerExcludeCarvesOutNothing() {
        assertEquals(List.of("qA"), Capability.effectiveTargets(
                LOCAL, execWith(resource(List.of("qA"), List.of("../nope")))).survivors());
    }

    /**
     * A PRESENT-BUT-ILL-TYPED {@code targets} is PRESENT, with an empty survivor list.
     * Reporting it absent would serve the WIDER absent-case answer to a request that named
     * a resource — N11's own defect one field over, and the cell the two vanguard peers
     * initially disagreed on.
     */
    @Test
    void effectiveTargetsIllTypedTargetsAreStillPresent() {
        Capability.EffectiveTargets ill = Capability.effectiveTargets(
                LOCAL, execWith(Cbor.map("targets", "not-an-array")));
        assertTrue(ill.hasResource());
        assertTrue(ill.survivors().isEmpty());

        // A resource map with no `targets` key at all is ABSENT, not present-and-empty:
        // there is no target list to have been emptied.
        assertFalse(Capability.effectiveTargets(
                LOCAL, execWith(Cbor.map("exclude", Cbor.textArray("x")))).hasResource());
    }

    // ── §6.3 check_path_permission ─────────────────────────────────────────────────

    /**
     * ONE ACCEPT AND ONE DENY PER DIMENSION. The accept case is what validates the FIXTURE:
     * a predicate test built only from deny cases is indistinguishable from one asserting
     * {@code false == false}, because a broken fixture denies everything for free. One deny
     * per dimension is what says the predicate checks the dimension rather than merely
     * being able to say no.
     */
    @Test
    void checkPathPermissionAcceptsInGrantAndDeniesPerDimension() {
        Entity cap = token(Peer.grant(List.of("system/tree"), List.of("q/*"), List.of("get"), null));

        assertTrue(Capability.checkPathPermission(LOCAL, "get", "q/a", cap, "system/tree"));
        assertFalse(Capability.checkPathPermission(LOCAL, "get", "other/a", cap, "system/tree"),
                "resources");
        assertFalse(Capability.checkPathPermission(LOCAL, "put", "q/a", cap, "system/tree"),
                "operations");
        assertFalse(Capability.checkPathPermission(LOCAL, "get", "q/a", cap, "system/capability"),
                "handlers");
    }

    /**
     * An empty {@code resources.include} is a legal grant shape (§5.2: handlers that touch
     * no tree paths) and DENIES every path — {@code covered} over an empty include list is
     * false, which is what that note says it should be.
     */
    @Test
    void checkPathPermissionEmptyResourceIncludeDeniesEveryPath() {
        Entity cap = token(Peer.grant(List.of("system/tree"), List.of(), List.of("get"), null));
        assertFalse(Capability.checkPathPermission(LOCAL, "get", "q/a", cap, "system/tree"));
    }

    /**
     * Canonicalization is TOTAL (0.8.2.20): a malformed path answers the sentinel, which
     * matches no grant, so it falls through to DENY rather than escaping as an exception
     * the §6.5 frame would answer with a 500.
     */
    @Test
    void checkPathPermissionMalformedPathDenies() {
        Entity cap = token(Peer.grant(List.of("system/tree"), List.of("*"), List.of("get"), null));
        // The wide-open control first, or "false everywhere" would satisfy this vacuously.
        assertTrue(Capability.checkPathPermission(LOCAL, "get", "q/a", cap, "system/tree"));
        assertFalse(Capability.checkPathPermission(LOCAL, "get", "../escape", cap, "system/tree"));
    }

    // ── §5.4 sentinel, SCOPED TO PATH-SCOPE (0.8.2.24 N2/N3) ───────────────────────

    /**
     * <em>"a capability carrying an unmatchable PATH-SCOPE pattern is INVALID … It does NOT
     * reach {@code operations} or {@code peers} {@code [MUST]}"</em>.
     *
     * <p>The unscoped guard ran an id pattern through the §5.4 transforms purely to classify
     * it and then denied the WHOLE dimension on a property unrelated to whether the exclude
     * carves anything out: {@code * /apply}, an ordinary namespaced operation name,
     * path-canonicalizes to the sentinel. Over-denial, invisible on any well-formed grant.
     */
    @Test
    void sentinelDeniesOnPathScopeOnly() {
        Capability.Scope idScope = new Capability.Scope(List.of("*"), List.of("*/apply"));
        // The ID arm: the exclude is a literal that simply does not equal `compute`, so the
        // include still carries and the dimension is NOT denied.
        assertTrue(Capability.matchesScope(LOCAL, "compute", idScope, Capability.ScopeKind.ID));
        // …and it still EXCLUDES what it literally names, or the guard has merely been
        // deleted rather than scoped.
        assertFalse(Capability.matchesScope(LOCAL, "*/apply", idScope, Capability.ScopeKind.ID));

        // The PATH arm keeps 0.8.2.21's rule: an unmatchable exclude DENIES rather than
        // carving out nothing.
        Capability.Scope pathScope = new Capability.Scope(List.of("*"), List.of("../nope"));
        assertFalse(Capability.matchesScope(LOCAL, "q/a", pathScope, Capability.ScopeKind.PATH));
        // Control: the identical include with no unmatchable exclude allows.
        assertTrue(Capability.matchesScope(LOCAL, "q/a",
                new Capability.Scope(List.of("*"), List.of()), Capability.ScopeKind.PATH));
    }

    // ── §5.5a scope_subset typed by scope kind (F50 / 0.8.2.16) ────────────────────

    /**
     * §3.6's id-scope grammar binds the scope TYPE, not one function — <em>"An
     * implementation on the canonicalizing reading is non-conformant and MUST adopt the
     * literal matcher"</em> — so the rule F40 landed on {@code matchesScope} reaches
     * {@code scope_subset} too.
     *
     * <p>{@code * /apply} is the witness and it is fail-CLOSED: under the canonicalizing
     * reading it becomes the §5.4 sentinel, which matches nothing in either operand, so a
     * legitimate child {@code operations} include was refused against a parent of
     * {@code *}. The literal matcher covers it.
     */
    @Test
    void scopeSubsetOperationsUseTheLiteralMatcher() {
        Capability.GrantRec wideOpen = grantRec(scope("*"), scope("*"), scope("*"));

        assertTrue(Capability.grantSubset(LOCAL, LOCAL, LOCAL,
                grantRec(scope("system/tree"), scope("q/*"), scope("*/apply")), wideOpen));

        // The EXCLUDE arm of the same pair: a parent exclude the child repeats verbatim is
        // inherited under the literal matcher and was not under the canonicalizing one.
        Capability.GrantRec parentEx = grantRec(scope("*"), scope("*"),
                new Capability.Scope(List.of("*"), List.of("*/apply")));
        Capability.GrantRec childEx = grantRec(scope("system/tree"), scope("q/*"),
                new Capability.Scope(List.of("*"), List.of("*/apply")));
        assertTrue(Capability.grantSubset(LOCAL, LOCAL, LOCAL, childEx, parentEx));

        // THE MATCHER HALF, and it is here because its plant RAN GREEN without it. The
        // `*/apply` cases above are decided by the FRAME (the sentinel), so replacing only
        // `coversFor` with the path matcher left every assertion passing — an inert
        // control. This pair separates the two matchers on strings the frame leaves alone:
        // §5.4's peer-wildcard walk makes `matchesPattern("/x/get", "/*/get")` TRUE while
        // §3.6's literal matcher answers FALSE. Under the canonicalizing reading the child
        // therefore reads as covered by a parent it does not literally match, and the child
        // grant comes out WIDER than its parent — the delegation-chain widening F50 names.
        assertFalse(Capability.grantSubset(LOCAL, LOCAL, LOCAL,
                grantRec(scope("system/tree"), scope("q/*"), scope("/x/get")),
                grantRec(scope("*"), scope("*"), scope("/*/get"))),
                "operations must use the LITERAL matcher, not the peer-wildcard walk");

        // CONTROL — the typing must not turn scope_subset into a rubber stamp: an
        // operations include the parent does not literally cover is still refused.
        assertFalse(Capability.grantSubset(LOCAL, LOCAL, LOCAL,
                grantRec(scope("system/tree"), scope("q/*"), scope("put")),
                grantRec(scope("*"), scope("*"), scope("get"))));

        // CONTROL — the PATH dimensions keep the canonicalizing matcher: a resources
        // include outside the parent's subtree is refused.
        assertFalse(Capability.grantSubset(LOCAL, LOCAL, LOCAL,
                grantRec(scope("system/tree"), scope("other/*"), scope("get")),
                grantRec(scope("*"), scope("q/*"), scope("*"))));
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────

    private static Capability.Scope scope(String... incl) {
        return new Capability.Scope(List.of(incl), List.of());
    }

    private static Capability.GrantRec grantRec(Capability.Scope handlers,
                                                Capability.Scope resources,
                                                Capability.Scope operations) {
        return new Capability.GrantRec(handlers, resources, operations, null);
    }

    /**
     * A token entity carrying {@code grants}. {@code granter}/{@code grantee}/
     * {@code created_at} are not read by {@code check_path_permission}, which answers about
     * the token's GRANTS only — the chain, signature, temporal bounds and revocation are
     * {@code verifyRequest}'s and must already have held.
     */
    private static Entity token(EcfValue.Map... grants) {
        return Entity.make("system/capability/token", Cbor.map(
                "grants", new EcfValue.Array(List.of((EcfValue[]) grants)),
                "granter", Cbor.bytes(new byte[33]),
                "grantee", Cbor.bytes(new byte[33]),
                "created_at", EcfValue.Int.of(1_700_000_000_000L)));
    }

    private static EcfValue.Map resource(List<String> targets, List<String> exclude) {
        if (exclude == null) {
            return Cbor.map("targets", Cbor.textArray(targets.toArray(new String[0])));
        }
        return Cbor.map("targets", Cbor.textArray(targets.toArray(new String[0])),
                "exclude", Cbor.textArray(exclude.toArray(new String[0])));
    }

    /**
     * An EXECUTE carrying {@code resource} VERBATIM — the §3.3 ladder has to tell "no
     * resource" from "a resource whose every target was excluded" and answer each with its
     * own disposition, so the shapes here deliberately include ones no admission parser
     * would accept.
     */
    private static Entity execWith(EcfValue resource) {
        if (resource == null) {
            return Entity.make("system/protocol/execute", Cbor.map(
                    "request_id", "t", "uri", "system/tree", "operation", "get"));
        }
        return Entity.make("system/protocol/execute", Cbor.map(
                "request_id", "t", "uri", "system/tree", "operation", "get",
                "resource", resource));
    }
}
