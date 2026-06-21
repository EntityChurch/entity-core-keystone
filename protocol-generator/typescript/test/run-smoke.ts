/**
 * S3 smoke runner — the phase exit gate. Two TypeScript peers talk over real
 * loopback TCP through the full dispatch chain: the §4.1 handshake (both
 * directions), 404 on an unregistered path, an authority-gated tree get (200), a
 * capability request (200), and 8-way `request_id` demux of interleaved replies.
 *
 * Run (in-container, after tsc): `node dist/test/run-smoke.js`.
 */

import { Ecf, Entity, Peer, PeerSession, ResourceTarget } from "../src/index.js";
import { GrantEntry, Scope } from "../src/index.js";

const results: [string, boolean][] = [];

function check(name: string, ok: boolean): void {
  results.push([name, ok]);
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}`);
}

async function main(): Promise<void> {
  const responder = new Peer();
  const initiator = new Peer();
  const port = await responder.listen(0);

  try {
    // ── Handshake ──────────────────────────────────────────────────────
    const session = await initiator.connect("127.0.0.1", port);
    console.log("Handshake:");
    check("session established", session.capability !== undefined);
    check("remote peer_id matches responder", session.remotePeerId === responder.localPeerId);

    const remote = session.remotePeerId;
    const typeTarget = (): ResourceTarget => new ResourceTarget(["system/type/system/peer"], null);

    // ── Dispatch ───────────────────────────────────────────────────────
    console.log("Dispatch:");
    const r404 = await session.execute(`/${remote}/does/not/exist`, "noop", PeerSession.emptyParams());
    check("unregistered path -> 404", r404.statusCode === 404);

    const rGet = await session.execute(`/${remote}/system/tree`, "get", PeerSession.emptyParams(), typeTarget());
    check("granted tree get -> 200", rGet.statusCode === 200);
    check("tree get returns a system/type entity", rGet.result.type === "system/type");

    const requestGrant = new GrantEntry(
      new Scope(["system/tree"], null),
      new Scope(["system/type/*"], null),
      new Scope(["get"], null),
      null,
      null,
      null,
    );
    const requestParams = Entity.create(
      "system/capability/request",
      Ecf.map(["grants", Ecf.array([requestGrant.toEcf()])]),
    );
    const rCap = await session.execute(`/${remote}/system/capability`, "request", requestParams);
    check("capability request -> 200", rCap.statusCode === 200);

    // ── Concurrency: request_id demux (N7) ─────────────────────────────
    console.log("Concurrency (request_id demux):");
    const concurrent = await Promise.all(
      Array.from({ length: 8 }, () =>
        session.execute(`/${remote}/system/tree`, "get", PeerSession.emptyParams(), typeTarget()),
      ),
    );
    const correlated = concurrent.filter((r) => r.statusCode === 200 && r.result.type === "system/type").length;
    check(`8 interleaved requests each correlated to its own response -> ${correlated}/8`, correlated === 8);
  } finally {
    await initiator.dispose();
    await responder.dispose();
  }

  const allPass = results.every(([, ok]) => ok);
  console.log(`\nTeardown clean.   ->   SMOKE: ${allPass ? "PASS" : "FAIL"}`);
  process.exit(allPass ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error("SMOKE: FAIL (uncaught)");
  console.error(e);
  process.exit(1);
});
