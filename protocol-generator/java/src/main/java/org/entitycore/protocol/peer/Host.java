package org.entitycore.protocol.peer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/**
 * Standalone S4-ready host: boots a peer on a localhost port and prints a
 * {@code LISTENING <port>} line so a harness can scrape the bound port. Flags:
 *
 * <pre>
 *   --port N               bind port (0 = auto, the default)
 *   --seed B               seed byte (repeated 32×) for a deterministic identity
 *   --name NAME            load a persistent Ed25519 identity from the standard
 *                          on-disk location ~/.entity/peers/NAME/keypair (the
 *                          entity-core PEM keypair: base64 of a 32-byte seed between
 *                          BEGIN/END ENTITY PRIVATE KEY lines — the same convention
 *                          the Go entity-peer --name and peer-manager use). Lets the
 *                          validator's multisig accept-path probe co-sign AS the peer
 *                          (crypto.LookupKeypairByPeerID finds the keypair).
 *   --debug-open-grants    degenerate [default → *] admin seed (non-conformant, F27)
 *   --validate             bootstrap the §7a system/validate/* conformance handlers
 * </pre>
 *
 * <p>The §7a handlers are OFF by default (a standing dispatch-outbound originator must
 * never ship live); {@code --validate} opts in (the keystone cohort mechanism).
 */
public final class Host {
    private Host() { }

    public static void main(String[] args) throws Exception {
        int port = 0;
        int seedByte = 1;
        String name = null;
        boolean openGrants = false;
        boolean validate = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> port = Integer.parseInt(args[++i]);
                case "--seed" -> seedByte = Integer.parseInt(args[++i]);
                case "--name" -> name = args[++i];
                case "--debug-open-grants" -> openGrants = true;
                case "--validate" -> validate = true;
                default -> { /* ignore unknown flags for forward-compat */ }
            }
        }
        byte[] seed;
        if (name != null) {
            seed = loadSeedFromName(name);
        } else {
            seed = new byte[32];
            Arrays.fill(seed, (byte) seedByte);
        }
        Peer peer = Peer.create(seed, openGrants, validate);
        Transport.Listener listener = Transport.startListener(peer, port);
        System.out.println("LISTENING " + listener.port());
        System.out.println("PEER " + peer.localPeer());
        System.out.flush();
        // park forever (the harness kills the process)
        Thread.currentThread().join();
    }

    /**
     * Load the 32-byte Ed25519 seed from the standard on-disk keypair at
     * {@code ~/.entity/peers/NAME/keypair} — an entity-core PEM whose body is
     * base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines (the Go entity-peer
     * {@code --name} / peer-manager convention). Missing or malformed → exit 2.
     */
    private static byte[] loadSeedFromName(String name) {
        String home = System.getProperty("user.home");
        if (home == null || home.isEmpty()) {
            home = System.getenv("HOME");
        }
        if (home == null || home.isEmpty()) {
            home = "/root";
        }
        Path path = Path.of(home, ".entity", "peers", name, "keypair");
        try {
            StringBuilder body = new StringBuilder();
            for (String line : Files.readAllLines(path)) {
                if (!line.startsWith("-")) {
                    body.append(line.trim());
                }
            }
            byte[] seed = Base64.getDecoder().decode(body.toString());
            if (seed.length != 32) {
                System.err.println("error: --name " + name + ": expected a 32-byte seed, got "
                        + seed.length + " bytes");
                System.exit(2);
            }
            return seed;
        } catch (Exception e) {
            System.err.println("error: --name " + name + ": " + e.getMessage());
            System.exit(2);
            throw new IllegalStateException("unreachable");
        }
    }
}
