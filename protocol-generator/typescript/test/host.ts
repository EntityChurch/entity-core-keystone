/**
 * entity-core-protocol-typescript — standalone peer host.
 *
 * The runnable target for S4 conformance: boots a single {@link Peer} listener on a
 * TCP port and blocks until signalled, so an external oracle (entity-core-go
 * `validate-peer`) can drive the live wire surface against it. Twin of the C#
 * `EntityCore.Protocol.Host` Program.
 *
 *   --port N               listen port (default 7777; 0 = auto-assign)
 *   --debug-open-grants    mint a wide-open admin capability on authenticate
 *                          instead of the §4.4 restricted standard grant. Debug
 *                          only — lets validate-peer reach grant-gated paths.
 *   --name NAME            load a persistent Ed25519 identity from the standard
 *                          on-disk location ~/.entity/peers/NAME/keypair (the
 *                          entity-core PEM keypair: a base64-encoded 32-byte seed
 *                          between BEGIN/END ENTITY PRIVATE KEY lines — the same
 *                          convention the Go entity-peer --name and peer-manager use).
 *                          Without --name a fixed test seed is used (stable peer_id).
 *
 * The peer binds loopback (127.0.0.1); run the validator in the same network
 * namespace (same container / pod). A single `LISTENING …` line goes to stdout once
 * bound — a run script waits for it before pointing the validator at the port.
 *
 * Run (in-container, after tsc): `node dist/test/host.js --port 7777 [--name NAME] [--debug-open-grants]`.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { Peer, PeerIdentity } from "../src/index.js";

/** Fixed 32-byte Ed25519 seed → stable peer identity across runs (no --name). */
const DEFAULT_SEED = new Uint8Array(32).fill(0x11);

/**
 * Load the 32-byte Ed25519 seed from the standard on-disk keypair (Go entity-peer
 * --name / peer-manager convention): ~/.entity/peers/NAME/keypair, a PEM whose body is
 * base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
 */
function loadSeedFromName(name: string): Uint8Array {
  const path = join(homedir(), ".entity", "peers", name, "keypair");
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: --name ${name}: ${msg}\n`);
    process.exit(2);
  }
  const body = text
    .split(/\r?\n/)
    .filter((line) => line.length > 0 && !line.startsWith("-"))
    .join("");
  const seed = new Uint8Array(Buffer.from(body, "base64"));
  if (seed.length !== 32) {
    process.stderr.write(`error: --name ${name}: expected a 32-byte seed, got ${seed.length} bytes\n`);
    process.exit(2);
  }
  return seed;
}

async function main(): Promise<number> {
  let port = 7777;
  let openGrants = false;
  let validate = false;
  let seed = DEFAULT_SEED;

  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--port": {
        const next = argv[++i];
        const parsed = next === undefined ? NaN : Number(next);
        if (!Number.isInteger(parsed)) {
          process.stderr.write("error: --port requires an integer argument\n");
          return 2;
        }
        port = parsed;
        break;
      }
      case "--name": {
        const next = argv[++i];
        if (next === undefined) {
          process.stderr.write("error: --name requires a NAME argument\n");
          return 2;
        }
        seed = loadSeedFromName(next);
        break;
      }
      case "--debug-open-grants":
        openGrants = true;
        process.stderr.write(
          "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — " +
            "it now selects the degenerate `default → *` seed policy. Prefer --seed-policy.\n",
        );
        break;
      case "--validate":
        validate = true;
        break;
      case "-h":
      case "--help":
        process.stdout.write("usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]\n");
        return 0;
      default:
        process.stderr.write(`error: unknown argument '${arg}'\n`);
        return 2;
    }
  }

  const peer = new Peer({
    identity: PeerIdentity.fromSeed(seed),
    debugOpenGrants: openGrants,
    conformanceHandlers: validate,
  });
  const bound = await peer.listen(port);

  // Single readiness line on stdout (matches the C# host's contract).
  process.stdout.write(
    `LISTENING 127.0.0.1:${bound} peer_id=${peer.localPeerId} open_grants=${openGrants} validate=${validate}\n`,
  );

  // Block until SIGINT (Ctrl+C) or SIGTERM (podman stop / kill).
  await new Promise<void>((resolve) => {
    const shutdown = (): void => resolve();
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });

  await peer.dispose();
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  },
);
