package org.entitycore.protocol.peer

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.system.exitProcess

/**
 * Standalone S4-ready host: boots a peer on a localhost port and prints a
 * `LISTENING <port>` line so a harness can scrape the bound port. Flags:
 *
 * ```
 *   --port N               bind port (0 = auto, the default)
 *   --seed B               seed byte (repeated 32×) for a deterministic identity
 *   --name NAME            load a persistent Ed25519 identity from the standard on-disk
 *                          location ~/.entity/peers/NAME/keypair (the entity-core PEM
 *                          keypair: base64 of a 32-byte seed between BEGIN/END ENTITY
 *                          PRIVATE KEY lines — the Go entity-peer --name / peer-manager
 *                          convention). Lets the validator's multisig accept-path probe
 *                          co-sign AS the peer (crypto.LookupKeypairByPeerID).
 *   --debug-open-grants    degenerate [default → *] admin seed (non-conformant, F27)
 *   --validate             bootstrap the §7a system/validate/(star) conformance handlers
 * ```
 *
 * The §7a handlers are OFF by default (a standing dispatch-outbound originator must never
 * ship live); `--validate` opts in (the keystone cohort mechanism).
 */
object Host {
    @JvmStatic
    fun main(args: Array<String>) {
        var port = 0
        var seedByte = 1
        var name: String? = null
        var openGrants = false
        var validate = false
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--port" -> port = args[++i].toInt()
                "--seed" -> seedByte = args[++i].toInt()
                "--name" -> name = args[++i]
                "--debug-open-grants" -> openGrants = true
                "--validate" -> validate = true
                else -> { /* ignore unknown flags for forward-compat */ }
            }
            i++
        }
        val seed = if (name != null) loadSeedFromName(name) else ByteArray(32) { seedByte.toByte() }
        val peer = Peer.create(seed, openGrants, validate)
        Transport.startListener(peer, port).let { listener ->
            println("LISTENING ${listener.port}")
            println("PEER ${peer.localPeer}")
            System.out.flush()
            // park forever (the harness kills the process)
            Thread.currentThread().join()
        }
    }

    /**
     * Load the 32-byte Ed25519 seed from the standard on-disk keypair at
     * `~/.entity/peers/NAME/keypair` — an entity-core PEM whose body is base64(seed)
     * between BEGIN/END ENTITY PRIVATE KEY lines. Missing or malformed → exit 2.
     */
    private fun loadSeedFromName(name: String): ByteArray {
        val home = System.getProperty("user.home")?.takeIf { it.isNotEmpty() }
            ?: System.getenv("HOME")?.takeIf { it.isNotEmpty() }
            ?: "/root"
        val path = Path.of(home, ".entity", "peers", name, "keypair")
        return try {
            val body = Files.readAllLines(path).filterNot { it.startsWith("-") }
                .joinToString("") { it.trim() }
            val seed = Base64.getDecoder().decode(body)
            if (seed.size != 32) {
                System.err.println("error: --name $name: expected a 32-byte seed, got ${seed.size} bytes")
                exitProcess(2)
            }
            seed
        } catch (e: Exception) {
            System.err.println("error: --name $name: ${e.message}")
            exitProcess(2)
        }
    }
}
