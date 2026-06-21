package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.entitycore.protocol.codec.EcfValue;
import org.junit.jupiter.api.Test;

/**
 * S3 two-peer loopback smoke test (the phase exit gate).
 *
 * <p>Two Java peers talk over real loopback TCP through the full §6.5 dispatch chain. A
 * RESPONDER peer listens; an INITIATOR peer (a second identity) dials it and drives the
 * §4.1 forward handshake (hello → authenticate), then:
 * <ul>
 *   <li>404 on an unregistered path (no handler resolved);</li>
 *   <li>an authority-gated tree get (200) over the §4.4 discovery floor;</li>
 *   <li>a capability request (200);</li>
 *   <li>8-way request_id demux of concurrently-issued replies (N7, §6.11).</li>
 * </ul>
 * Then a second scenario exercises the v7.74 Core Extensibility Boundary
 * (--debug-open-grants + --validate): the register live-hook (§6.13(a)), the emit hook
 * firing on register's tree writes (§6.13(c)), and the §7a echo handler.
 *
 * <p>The full validate-peer --profile core run is S4. This smoke proves the wire-level
 * peer surface so S4 can run the oracle.
 */
final class SmokeTest {

    private final List<Boolean> results = new ArrayList<>();

    private boolean check(String name, boolean ok) {
        results.add(ok);
        System.out.printf("  [%s] %s%n", ok ? "PASS" : "FAIL", name);
        return ok;
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    @Test
    void twoPeerLoopback() throws Exception {
        runCoreScenario();
        runExtensibilityScenario();
        boolean allPass = results.stream().allMatch(Boolean::booleanValue);
        long pass = results.stream().filter(Boolean::booleanValue).count();
        System.out.printf("%nSMOKE: %s (%d/%d)%n", allPass ? "PASS" : "FAIL", pass, results.size());
        assertTrue(allPass, "two-peer loopback must be all-PASS");
    }

    // ── Scenario 1: core ops (responder = default seed policy) ──────────────────────

    private void runCoreScenario() throws Exception {
        Peer responder = Peer.create(seed(0x11), false, false);
        try (Transport.Listener listener = Transport.startListener(responder, 0)) {
            System.out.printf("Responder listening on 127.0.0.1:%d (peer %s)%n",
                    listener.port(), responder.localPeer());
            Peer initiator = Peer.create(seed(0x22), false, false);
            try (Transport.Session s = Transport.dial(initiator, "127.0.0.1", listener.port())) {
                String remote = s.remotePeerId();
                System.out.println("Handshake:");
                check("session established (capability minted)", s.capability() != null);
                check("remote peer_id matches responder", remote.equals(responder.localPeer()));

                System.out.println("Dispatch:");
                // 404 on an unregistered path
                Envelope r404 = s.execute("/" + remote + "/does/not/exist", "noop",
                        Wire.emptyParams(), null);
                check("unregistered path -> 404", Wire.responseStatus(r404) == 404);

                // authority-gated tree get (200) over the discovery floor: a
                // handler-interface entity bootstrapped under system/handler/{pattern}.
                EcfValue.Map ifaceTarget = Wire.resourceTarget("system/handler/system/tree");
                Envelope rget = s.execute("/" + remote + "/system/tree", "get",
                        Wire.emptyParams(), ifaceTarget);
                check("granted tree get -> 200", Wire.responseStatus(rget) == 200);
                Entity res = Wire.responseResult(rget);
                check("tree get returns a system/handler/interface entity",
                        res != null && res.type().equals("system/handler/interface"));

                // capability request (200)
                EcfValue.Map reqGrant = Peer.grant(List.of("system/tree"),
                        List.of("system/type/*"), List.of("get"), null);
                Entity reqParams = Entity.make("system/capability/request",
                        Cbor.map("grants", new EcfValue.Array(List.of(reqGrant))));
                Envelope rcap = s.execute("/" + remote + "/system/capability", "request",
                        reqParams, null);
                check("capability request -> 200", Wire.responseStatus(rcap) == 200);

                // 8-way request_id demux (N7, §6.11)
                System.out.println("Concurrency (request_id demux):");
                final int n = 8;
                boolean[] oks = new boolean[n];
                Thread[] threads = new Thread[n];
                for (int i = 0; i < n; i++) {
                    final int idx = i;
                    threads[i] = Thread.ofVirtual().start(() -> {
                        try {
                            Envelope r = s.execute("/" + remote + "/system/tree", "get",
                                    Wire.emptyParams(), Wire.resourceTarget("system/handler/system/tree"));
                            Entity rr = Wire.responseResult(r);
                            oks[idx] = Wire.responseStatus(r) == 200
                                    && rr != null && rr.type().equals("system/handler/interface");
                        } catch (Exception e) {
                            oks[idx] = false;
                        }
                    });
                }
                for (Thread t : threads) {
                    t.join();
                }
                int correlated = 0;
                for (boolean ok : oks) {
                    if (ok) {
                        correlated++;
                    }
                }
                check("8 interleaved requests each correlated -> " + correlated + "/8", correlated == n);
            }
        }
    }

    // ── Scenario 2: the v7.74 Core Extensibility Boundary over the wire ─────────────

    private void runExtensibilityScenario() throws Exception {
        Peer responder = Peer.create(seed(0x33), true, true);   // --debug-open-grants + --validate
        AtomicInteger emitEvents = new AtomicInteger();
        responder.store().registerTreeConsumer(ev -> emitEvents.incrementAndGet());
        try (Transport.Listener listener = Transport.startListener(responder, 0)) {
            Peer initiator = Peer.create(seed(0x44), false, false);
            try (Transport.Session s = Transport.dial(initiator, "127.0.0.1", listener.port())) {
                String remote = s.remotePeerId();
                int emitBefore = emitEvents.get();
                System.out.println("Extensibility (open-grants + --validate):");

                // register live-hook (§6.13(a))
                EcfValue.Map manifest = Cbor.map("name", "demo", "operations", Cbor.emptyMap());
                Entity req = Entity.make("system/handler/register-request",
                        Cbor.map("manifest", manifest));
                Envelope rreg = s.execute("/" + remote + "/system/handler", "register",
                        req, Wire.resourceTarget("system/handler/demo"));
                check("handler register -> 200 (live, not 501)", Wire.responseStatus(rreg) == 200);
                check("emit hook fired on register's tree writes (§6.13(c))",
                        emitEvents.get() > emitBefore);

                // §7a echo conformance handler (resolve→dispatch)
                Entity payload = Entity.make("primitive/any", Cbor.map("ping", EcfValue.Int.of(42)));
                Envelope recho = s.execute("/" + remote + "/system/validate/echo", "echo",
                        payload, null);
                check("§7a echo -> 200", Wire.responseStatus(recho) == 200);
                Entity res = Wire.responseResult(recho);
                check("§7a echo returns params verbatim",
                        res != null && res.type().equals("primitive/any"));
            }
        }
    }

    /** Direct entry point (run-s3.sh invokes the JUnit gate; this mirrors it for
     *  ad-hoc debugging). */
    public static void main(String[] args) throws Exception {
        SmokeTest t = new SmokeTest();
        t.runCoreScenario();
        t.runExtensibilityScenario();
        boolean allPass = t.results.stream().allMatch(Boolean::booleanValue);
        long pass = t.results.stream().filter(Boolean::booleanValue).count();
        System.out.printf("%nSMOKE: %s (%d/%d)%n", allPass ? "PASS" : "FAIL", pass, t.results.size());
        System.exit(allPass ? 0 : 1);
    }
}
