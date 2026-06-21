import { test } from "node:test";
import assert from "node:assert/strict";
import { ecfPreEncoded } from "../src/codec/ecf-value.js";
import {
  CapabilityToken,
  Ecf,
  Entity,
  Peer,
  PeerSession,
  ResourceTarget,
  SeedPolicy,
  Status,
  TypeNames,
} from "../src/index.js";

/**
 * GUIDE-CONFORMANCE §7a — the `system/validate/*` conformance test-handlers, driven
 * black-box over the wire exactly as `validate-peer` would. `echo` proves the §6.13(a)
 * resolve→dispatch half (closes A-011); `dispatch-outbound` proves the §6.13(b)/§6.11
 * outbound seam via reentry (closes A-013). Also pins the §7a.2 "off by default" lifecycle.
 */

const TIMEOUT = 10000;

test("§7a echo returns the params value over the wire", async () => {
  const peer = new Peer({ seedPolicy: SeedPolicy.debugOpen(), conformanceHandlers: true });
  const client = new Peer();
  try {
    const port = await peer.listen(0);
    const session = await client.connect("127.0.0.1", port, TIMEOUT);
    const prm = Entity.create(TypeNames.PrimitiveAny, Ecf.map(["value", Ecf.text("ping-42")]));
    const resp = await session.execute(
      "system/validate/echo",
      "echo",
      prm,
      new ResourceTarget(["system/handler/system/validate/echo"], null),
      TIMEOUT,
    );
    assert.equal(resp.statusCode, Status.Ok);
    assert.equal(Ecf.asText(Ecf.require(resp.result.data, "value")), "ping-42");
  } finally {
    await client.dispose();
    await peer.dispose();
  }
});

test("§7a dispatch-outbound originates a reentry EXECUTE back to the caller", async () => {
  // target = the peer under validation (A-role originator). caller = the validator, in
  // conformance mode so it can SERVE the target's reentry echo (B-role on the same conn).
  const target = new Peer({ seedPolicy: SeedPolicy.debugOpen(), conformanceHandlers: true });
  const caller = new Peer({ seedPolicy: SeedPolicy.debugOpen(), conformanceHandlers: true });
  try {
    const port = await target.listen(0);
    const session = await caller.connect("127.0.0.1", port, TIMEOUT);

    // Only the caller can authorize the reentry direction (target → caller): it mints a cap
    // granting the TARGET authority to execute back at the caller, carried in-band in params.
    const { token: cap, signature: capSig } = CapabilityToken.createRoot(
      caller.localIdentity,
      target.localIdentity.identityHash,
      SeedPolicy.openGrants(),
      1000n,
    );

    const prm = Entity.create(
      TypeNames.PrimitiveAny,
      Ecf.map(
        ["target", Ecf.text("system/validate/echo")],
        ["operation", Ecf.text("echo")],
        ["value", Ecf.text("round-trip-99")],
        ["reentry_capability", ecfPreEncoded(cap.entity.wireBytes)],
        ["reentry_granter", ecfPreEncoded(caller.localIdentity.peerEntity.wireBytes)],
        ["reentry_cap_signature", ecfPreEncoded(capSig.wireBytes)],
      ),
    );

    const resp = await session.execute(
      "system/validate/dispatch-outbound",
      "dispatch",
      prm,
      new ResourceTarget(["system/handler/system/validate/dispatch-outbound"], null),
      TIMEOUT,
    );

    assert.equal(resp.statusCode, Status.Ok);
    assert.equal(Ecf.asUint(Ecf.require(resp.result.data, "status")), 200n);
    const downstream = Entity.fromDecoded(Ecf.require(resp.result.data, "result"));
    assert.equal(Ecf.asText(Ecf.require(downstream.data, "value")), "round-trip-99");
  } finally {
    await caller.dispose();
    await target.dispose();
  }
});

test("§7a.2 conformance handlers are off by default (404)", async () => {
  const peer = new Peer({ seedPolicy: SeedPolicy.debugOpen() }); // no conformanceHandlers
  const client = new Peer();
  try {
    const port = await peer.listen(0);
    const session = await client.connect("127.0.0.1", port, TIMEOUT);
    const resp = await session.execute(
      "system/validate/echo",
      "echo",
      Entity.create(TypeNames.PrimitiveAny, Ecf.map(["value", Ecf.text("x")])),
      new ResourceTarget(["system/handler/system/validate/echo"], null),
      TIMEOUT,
    );
    assert.equal(resp.statusCode, Status.NotFound);
  } finally {
    await client.dispose();
    await peer.dispose();
  }
});
