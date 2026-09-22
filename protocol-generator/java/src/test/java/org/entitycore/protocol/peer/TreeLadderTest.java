package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.entitycore.protocol.codec.EcfValue;
import org.junit.jupiter.api.Test;

/**
 * §3.3's effective-targets ladder (0.8.2.20, refined at .24/.25) and §6.3's listing filter,
 * driven end-to-end over real loopback.
 *
 * <p>The ladder runs on the EFFECTIVE list, never on {@code resource.targets}: a handler
 * that counts the effective list and then indexes {@code targets[0]} has implemented the
 * arithmetic completely and is still reading a path no authorization covered. This peer did
 * not even count — it read {@code targets.get(0)} and answered 200 — so
 * {@code targets:[a,b] exclude:[a]} served {@code a}.
 */
final class TreeLadderTest {

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static String codeOf(Envelope env) {
        Entity res = Wire.responseResult(env);
        return (res != null && res.text("code") != null) ? res.text("code") : "";
    }

    private static EcfValue.Map resource(List<String> targets, List<String> exclude) {
        if (exclude == null) {
            return Cbor.map("targets", Cbor.textArray(targets.toArray(new String[0])));
        }
        return Cbor.map("targets", Cbor.textArray(targets.toArray(new String[0])),
                "exclude", Cbor.textArray(exclude.toArray(new String[0])));
    }

    /** §3.3's rows, one code each. */
    @Test
    void ladderAnswersEachRowWithItsOwnCode() throws Exception {
        // The responder runs the degenerate default->* seed policy so the caller's grant
        // covers every path: these rows are about the LADDER's arithmetic, not about
        // authorization, and a narrow grant would answer 403 before the ladder is reached.
        Peer responder = Peer.create(seed(0x51), true, false);
        try (Transport.Listener listener = Transport.startListener(responder, 0)) {
            Peer initiator = Peer.create(seed(0x52), false, false);
            try (Transport.Session s = Transport.dial(initiator, "127.0.0.1", listener.port())) {
                String tree = "/" + s.remotePeerId() + "/system/tree";

                // ABSENT resource -> the root listing. EXTENSION-TREE §2.2a (v4.11) declares
                // `get` resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
                // listing".
                Envelope absent = s.execute(tree, "get", Wire.emptyParams(), null);
                assertEquals(200, Wire.responseStatus(absent));
                assertEquals("system/tree/listing", Wire.responseResult(absent).type());

                // PRESENT and self-excluded -> 400 path_required. THE TWO EMPTIES ARE
                // DISTINCT for a resource-OPTIONAL operation (0.8.2.24 N7 / 0.8.2.25 N10):
                // serving this the absent case "answers a request for one excluded path
                // with a listing of the tree".
                Envelope self = s.execute(tree, "get", Wire.emptyParams(),
                        resource(List.of("app/a"), List.of("app/a")));
                assertEquals(400, Wire.responseStatus(self));
                assertEquals("path_required", codeOf(self));

                // Two survivors -> 400 ambiguous_resource. A peer indexing targets[0]
                // answers 200 and cannot tell the caller it ignored the second.
                Envelope amb = s.execute(tree, "get", Wire.emptyParams(),
                        resource(List.of("app/a", "app/b"), null));
                assertEquals(400, Wire.responseStatus(amb));
                assertEquals("ambiguous_resource", codeOf(amb));

                // A PATTERN subject -> 400 malformed_resource. A resource-requiring
                // operation takes a CONCRETE path; without this the pattern is looked up as
                // a literal and answers 404, which names the wrong fault.
                Envelope pat = s.execute(tree, "get", Wire.emptyParams(),
                        resource(List.of("system/type/*"), null));
                assertEquals(400, Wire.responseStatus(pat));
                assertEquals("malformed_resource", codeOf(pat));

                // An unmatchable CALLER exclude carves out NOTHING — the fail-OPEN
                // direction of §5.4's sentinel, and the correct one here.
                Envelope unmatchable = s.execute(tree, "get", Wire.emptyParams(),
                        resource(List.of("system/type/"), List.of("../nope")));
                assertEquals(200, Wire.responseStatus(unmatchable));

                // `put` collapses the two empties: §2.2a declares it resource-REQUIRED.
                // Note the code 0.8.2.20 forces — a MISSING target is NOT
                // `ambiguous_resource`; *supply a resource* is not *disambiguate your
                // request*, and this peer answered `ambiguous_resource` for both.
                Envelope putAbsent = s.execute(tree, "put", Wire.emptyParams(), null);
                assertEquals("path_required", codeOf(putAbsent));
                Envelope putSelf = s.execute(tree, "put", Wire.emptyParams(),
                        resource(List.of("app/a"), List.of("app/a")));
                assertEquals("path_required", codeOf(putSelf));
                Envelope putAmb = s.execute(tree, "put", Wire.emptyParams(),
                        resource(List.of("app/a", "app/b"), null));
                assertEquals("ambiguous_resource", codeOf(putAmb));

                // RULE G control: the OPERATION resolves FIRST. An unknown op with no
                // resource answers the OPERATION fault, never the resource one — a handler
                // that validates the resource first names the wrong fault for every unknown
                // operation.
                Envelope bogus = s.execute(tree, "bogusop", Wire.emptyParams(), null);
                assertEquals(501, Wire.responseStatus(bogus));
                assertEquals("unsupported_operation", codeOf(bogus));
            }
        }
    }

    /**
     * {@code targets:[a,b] exclude:[a]}. The effective set is {@code {b}}, size 1, so the
     * COUNT rule says proceed — and a raw {@code targets[0]} selector proceeds on
     * {@code a}. Both are bound, so a 200 naming {@code a} is a selection defect and
     * nothing else.
     */
    @Test
    void ladderSelectsTheSubjectFromTheEffectiveSet() throws Exception {
        Peer responder = Peer.create(seed(0x53), true, false);
        try (Transport.Listener listener = Transport.startListener(responder, 0)) {
            Peer initiator = Peer.create(seed(0x54), false, false);
            try (Transport.Session s = Transport.dial(initiator, "127.0.0.1", listener.port())) {
                String remote = s.remotePeerId();
                responder.store().bind("/" + remote + "/app/sel/a",
                        Entity.make("test/a", Cbor.map()));
                responder.store().bind("/" + remote + "/app/sel/b",
                        Entity.make("test/b", Cbor.map()));

                Envelope r = s.execute("/" + remote + "/system/tree", "get", Wire.emptyParams(),
                        resource(List.of("app/sel/a", "app/sel/b"), List.of("app/sel/a")));
                assertEquals(200, Wire.responseStatus(r));
                assertNotNull(Wire.responseResult(r));
                assertEquals("test/b", Wire.responseResult(r).type(),
                        "targets[0] would have answered test/a");
            }
        }
    }

    /**
     * §6.3's listing filter (0.8.2.21/.22) — <em>"each entry MUST be individually checked
     * using {@code check_path_permission}. Entries for which {@code check_path_permission}
     * returns DENY MUST be omitted. The result's {@code count} field MUST reflect the
     * filtered entry count, not the source tree's total count."</em>
     *
     * <p>Driven through a hand-built {@link HandlerContext} rather than a session, because
     * the NARROW GRANT is the whole input and minting one over the wire would put three
     * more moving parts between the assertion and the thing asserted. The wire half is
     * {@code tools/arc-probe} G4.
     */
    @Test
    void listingOmitsEntriesTheCallersCapabilityExcludes() throws Exception {
        Peer peer = Peer.create(seed(0x55), true, false);
        String base = "/" + peer.localPeer() + "/app/list";
        peer.store().bind(base + "/a", Entity.make("test/leaf", Cbor.map()));
        peer.store().bind(base + "/b", Entity.make("test/leaf", Cbor.map()));

        // THE CONTROL, and it is what makes the assertion below falsifiable: with a grant
        // covering BOTH, the listing names both. "b is absent" under a narrower grant is
        // the trivial truth if the directory read does not work at all.
        Listing wide = listUnder(peer, narrowToken("app/list/*"));
        assertEquals(List.of("a", "b"), wide.names);
        assertEquals(2, wide.count);

        Listing narrow = listUnder(peer, narrowToken("app/list/a"));
        assertEquals(List.of("a"), narrow.names, "an excluded entry MUST be omitted");
        assertEquals(1, narrow.count, "`count` MUST follow the FILTERED total");

        // An UNAUTHENTICATED context is not filtered — the filter's subject is "the
        // caller's verified capability", and where there is none there is no caller to
        // narrow. This is the bootstrap path, and it matches both vanguard peers.
        assertEquals(List.of("a", "b"), listUnder(peer, null).names);
    }

    private record Listing(List<String> names, int count) { }

    private Listing listUnder(Peer peer, Entity cap) throws Exception {
        Entity exec = Wire.makeExecute("l1", "system/tree", "get", Wire.emptyParams(),
                null, null, resource(List.of("app/list/"), null));
        Envelope env = new Envelope(exec);
        Outcome out = peer.handlerFor("system/tree").handle("get",
                new HandlerContext(exec, null, env.included(), cap, env, "system/tree"));
        assertEquals(200, out.status());
        EcfValue.Map entries = out.result().mapField("entries");
        List<String> names = new ArrayList<>();
        for (EcfValue.Map.Entry e : entries.entries()) {
            names.add(((EcfValue.Text) e.key()).value());
        }
        java.util.Collections.sort(names);
        return new Listing(names, out.result().uint("count").intValue());
    }

    /**
     * A token whose single grant covers {@code system/tree}, {@code get}, and exactly
     * {@code resources}. {@code granter}/{@code grantee}/{@code created_at} are not read by
     * {@code check_path_permission}, which answers about the token's GRANTS only.
     */
    private static Entity narrowToken(String... resources) {
        return Entity.make("system/capability/token", Cbor.map(
                "grants", new EcfValue.Array(List.of(
                        Peer.grant(List.of("system/tree"), List.of(resources), List.of("get"), null))),
                "granter", Cbor.bytes(new byte[33]),
                "grantee", Cbor.bytes(new byte[33]),
                "created_at", EcfValue.Int.of(1_700_000_000_000L)));
    }
}
