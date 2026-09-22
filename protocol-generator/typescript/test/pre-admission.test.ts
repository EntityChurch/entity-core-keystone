import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import {
  Ecf,
  Entity,
  Envelope,
  ExecuteResponse,
  HashMismatchError,
  Peer,
  SeedPolicy,
  TagRejectedError,
} from "../src/index.js";
import { encode } from "../src/codec/canonical-cbor.js";
import { ecfBytes, ecfMap, ecfPreEncoded, ecfText } from "../src/codec/ecf-value.js";
import {
  FrameTooLargeError,
  framingRefusal,
  preAdmissionRefusal,
  TruncatedFrameError,
  writeFrame,
} from "../src/transport/frame-codec.js";

/**
 * §4.11 pre-admission refusals (0.8.2.25).
 *
 * §4.11's rule has two parts and they fail differently. *"A peer that refuses a frame
 * pre-admission MUST put a coded EXECUTE_RESPONSE on the wire [MUST]"* is the OBLIGATION,
 * wire-visible, and it is the half that was broken here — this peer had BOTH of the
 * behaviours §4.11 names separately as non-conformant: DROPPING the frame (a partial
 * trailing frame and an un-salvageable decode) and CLOSING with no coded frame (an
 * oversize prefix, and the non-EXECUTE root's bare `break`). *"The CODE belongs to the
 * cause [MUST]"* is a MAPPING, and a mapping is exactly the thing that regresses silently
 * when a new failure joins an existing branch.
 *
 * §4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"* and
 * reaches none of these, which is why §4.11 exists. The pinned check set (778) has no
 * vector on this surface, so the coverage is authored here rather than inherited.
 */

const TIMEOUT = 10_000;

/** Start a peer on an ephemeral port and return it with a raw client socket. */
async function connectRaw(): Promise<{ peer: Peer; sock: net.Socket }> {
  const peer = new Peer({ seedPolicy: SeedPolicy.debugOpen() });
  const port = await peer.listen(0);
  const sock = await new Promise<net.Socket>((resolve, reject) => {
    const s = net.createConnection({ host: "127.0.0.1", port }, () => resolve(s));
    s.once("error", reject);
  });
  return { peer, sock };
}

/** Read the next complete frame off a raw socket and decode it as a coded refusal. */
function readRefusal(sock: net.Socket): Promise<{ status: number; code: string; requestId: string }> {
  return new Promise((resolve, reject) => {
    let buf = new Uint8Array(0);
    const timer = setTimeout(
      () => reject(new Error("no coded EXECUTE_RESPONSE arrived: the peer answered with silence or a bare close")),
      TIMEOUT,
    );
    const done = (v: { status: number; code: string; requestId: string }): void => {
      clearTimeout(timer);
      sock.removeListener("data", onData);
      resolve(v);
    };
    const onData = (chunk: Buffer): void => {
      const next = new Uint8Array(buf.length + chunk.length);
      next.set(buf);
      next.set(chunk, buf.length);
      buf = next;
      if (buf.length < 4) return;
      const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
      if (buf.length < 4 + len) return;
      try {
        const env = Envelope.decode(buf.slice(4, 4 + len));
        assert.equal(
          env.root.type,
          "system/protocol/execute/response",
          "§4.11 requires a coded EXECUTE_RESPONSE",
        );
        const response = new ExecuteResponse(env.root);
        done({
          status: response.statusCode,
          code: Ecf.optText(response.result.data, "code") ?? "",
          requestId: response.requestId,
        });
      } catch (e) {
        clearTimeout(timer);
        reject(e);
      }
    };
    sock.on("data", onData);
    sock.once("close", () => {
      if (buf.length === 0) {
        clearTimeout(timer);
        reject(new Error("the peer closed with no coded frame — §4.11's second non-conformant behaviour"));
      }
    });
  });
}

/** A well-formed frame whose `included` entry is filed under a hash that is not its own. */
function misKeyedFrame(requestId: string): Uint8Array {
  const good = Entity.create("primitive/any", Ecf.map(["x", Ecf.uint(1n)]));
  const root = Entity.create(
    "system/protocol/execute",
    Ecf.map(["request_id", Ecf.text(requestId)], ["uri", Ecf.text("system/tree")], ["operation", Ecf.text("get")]),
  );
  return encode(
    ecfMap([
      [ecfText("root"), ecfPreEncoded(root.wireBytes)],
      [ecfText("included"), ecfMap([[ecfBytes(new Uint8Array(33).fill(0x11)), ecfPreEncoded(good.wireBytes)]])],
    ]),
  );
}

// ── the CLASSIFICATION half ──────────────────────────────────────────────────

// §4.11's table, one row at a time. "A single code for the class would answer an honest
// caller under the wrong reason and send them to the wrong layer."
test("§4.11 — the refusal CODE is the cause's, not the class's", () => {
  // §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
  assert.deepEqual(preAdmissionRefusal(new FrameTooLargeError("x")).status, 413);
  assert.equal(preAdmissionRefusal(new FrameTooLargeError("x")).code, "payload_too_large");
  // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules non_canonical_ecf
  // NON-CONFORMANT here.
  assert.equal(preAdmissionRefusal(new HashMismatchError("x")).code, "hash_mismatch");
  assert.equal(preAdmissionRefusal(new HashMismatchError("x")).status, 400);
  // ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
  assert.equal(preAdmissionRefusal(new TagRejectedError("x")).code, "non_canonical_ecf");
  // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
  assert.equal(preAdmissionRefusal(new TruncatedFrameError("x")).code, "invalid_request");
  assert.equal(preAdmissionRefusal(new Error("anything else")).code, "invalid_request");
  // Every message is ASCII (RULE H: a wire-visible string is CBOR-text-encoded).
  for (const e of [new FrameTooLargeError("x"), new HashMismatchError("x"), new TagRejectedError("x"), new Error("x")]) {
    const { message } = preAdmissionRefusal(e);
    assert.ok([...message].every((c) => c.charCodeAt(0) < 128), `non-ASCII in a wire message: ${message}`);
  }

  // framingRefusal separates "owed a frame" from "the connection simply ended".
  assert.equal(framingRefusal(new FrameTooLargeError("x")), true);
  assert.equal(framingRefusal(new TruncatedFrameError("x")), true);
  assert.equal(framingRefusal(new Error("socket hung up")), false);
  assert.equal(framingRefusal(new HashMismatchError("x")), false);
});

// The two decode-boundary CAUSES must reach the classifier as DIFFERENT error types.
// Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of them, which
// is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed `included` entry
// carries no tag, its encoding is canonical, and *re-encode* is not the caller's remedy.
test("§5.2a — the decode boundary distinguishes resolution integrity from structure", () => {
  assert.throws(
    () => Envelope.decode(misKeyedFrame("t1")),
    HashMismatchError,
    "a mis-keyed included entry is a RESOLUTION-INTEGRITY fault",
  );
  // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same class
  // (§1.8 item 1) and takes the same code.
  const tampered = encode(
    ecfMap([
      [ecfText("type"), ecfText("primitive/any")],
      [ecfText("data"), ecfPreEncoded(encode(Ecf.map(["x", Ecf.uint(1n)])))],
      // 0x00 = the ecfv1-sha256 format byte, then 32 wrong digest bytes. The format code
      // must be SUPPORTED or the decode fails one rung earlier on
      // `unsupported_content_hash_format`, which is a different cause and a different
      // code — the first cut of this fixture used 0xf2 throughout and measured that
      // instead, which is the "a probe fails in the direction of the answer it is looking
      // for" trap in a fixture.
      [ecfText("content_hash"), ecfBytes(Uint8Array.from([0x00, ...new Uint8Array(32).fill(0x22)]))],
    ]),
  );
  assert.throws(() => Entity.decode(tampered), HashMismatchError);

  // STRUCTURAL faults are NOT HashMismatchError. THIS IS THE DISCRIMINATOR: if both
  // causes collapsed into one type the assertions above would pass vacuously.
  const noType = encode(ecfMap([[ecfText("data"), ecfPreEncoded(encode(Ecf.uint(1n)))]]));
  assert.throws(() => Entity.decode(noType), (e: unknown) => !(e instanceof HashMismatchError));

  // And the WELL-FORMED envelope must still decode, or every case above is satisfied by a
  // decoder that refuses everything.
  const good = Entity.create("primitive/any", Ecf.map(["x", Ecf.uint(1n)]));
  const root = Entity.create("system/protocol/execute", Ecf.map(["request_id", Ecf.text("t1")]));
  const wellFormed = encode(
    ecfMap([
      [ecfText("root"), ecfPreEncoded(root.wireBytes)],
      [ecfText("included"), ecfMap([[ecfBytes(good.contentHash), ecfPreEncoded(good.wireBytes)]])],
    ]),
  );
  const env = Envelope.decode(wellFormed);
  assert.equal(env.find(good.contentHash) !== undefined, true, "the included entity did not survive decode");
});

// ── the OBLIGATION half, over a real socket ──────────────────────────────────

// An oversize length prefix — §4.10(a), mood raised to MUST at 0.8.2.25 (N14). The body is
// never drained, so the framing is lost and the peer closes afterwards; the close is now
// IN ADDITION TO the frame rather than instead of it.
test("§4.11 — an oversize length prefix is answered 413 before the close", async () => {
  const { peer, sock } = await connectRaw();
  try {
    // 32 MiB declared, nothing sent. The bound is read from the PREFIX, so no body needs
    // to exist for the refusal to fire — that is the whole point of checking it there.
    const prefix = new Uint8Array(4);
    new DataView(prefix.buffer).setUint32(0, 0x0200_0000, false);
    sock.write(prefix);
    const { status, code, requestId } = await readRefusal(sock);
    assert.equal(status, 413);
    assert.equal(code, "payload_too_large");
    // §4.11's best-effort UNCORRELATED form: there is no request_id to recover from a
    // frame whose body never arrived, and guessing one would correlate the refusal to
    // somebody else's in-flight request.
    assert.equal(requestId, "");
  } finally {
    sock.destroy();
    await peer.dispose();
  }
});

// A length prefix that declares more than is sent — §4.11's framing arm, "a length prefix
// that never completes" -> 400 invalid_request. The CONTROL is the next test: both end the
// stream, and only one is owed a frame.
test("§4.11 — a truncated frame is answered 400 invalid_request", async () => {
  const { peer, sock } = await connectRaw();
  try {
    sock.write(Buffer.from([0x00, 0x00, 0x10, 0x00, 0xa1]));
    sock.end();
    const { status, code } = await readRefusal(sock);
    assert.equal(status, 400);
    assert.equal(code, "invalid_request");
  } finally {
    sock.destroy();
    await peer.dispose();
  }
});

// THE CONTROL. A clean EOF at a frame boundary is an ordinary hangup, NOT a refusal, and
// is owed nothing. Without this row every assertion above is satisfied by a peer that
// answers 400 to everyone who hangs up, which would be a new defect rather than a fix.
test("§4.11 control — a clean close at a frame boundary is not a refusal", async () => {
  const { peer, sock } = await connectRaw();
  try {
    const bytes: number[] = [];
    sock.on("data", (c: Buffer) => bytes.push(...c));
    sock.end();
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(bytes.length, 0, "a clean close was answered with bytes; it is not a refusal");
  } finally {
    sock.destroy();
    await peer.dispose();
  }
});

// A mis-keyed `included` entry — §5.2a (0.8.2.24 N4/N5) pins 400 hash_mismatch here and
// rules 400 non_canonical_ecf NON-CONFORMANT. The frame is COMPLETE, so the peer answers
// and KEEPS SERVING; the correlated id proves the salvage path ran.
test("§5.2a — a mis-keyed included entry is 400 hash_mismatch and the connection survives", async () => {
  const { peer, sock } = await connectRaw();
  try {
    const frame = misKeyedFrame("mk-1");
    await writeFrame(sock, frame);
    const first = await readRefusal(sock);
    assert.equal(first.status, 400);
    assert.equal(first.code, "hash_mismatch");
    assert.equal(first.requestId, "mk-1", "a complete frame's request_id is recoverable, so the refusal correlates");

    // AND THE CONNECTION KEEPS SERVING. A decode refusal on a complete frame does not
    // desynchronize the stream, so answering it and closing would be the cascade this
    // peer already paid 81 FAILs for. Send it again and expect a second answer.
    await writeFrame(sock, frame);
    const second = await readRefusal(sock);
    assert.equal(second.code, "hash_mismatch");
  } finally {
    sock.destroy();
    await peer.dispose();
  }
});

// §6.5's "Other type?" arm as rewritten at 0.8.2.25 (N12/N17): "400 invalid_request, coded
// frame; MAY then close. NOT a bare close." §3.3 previously read "the connection MUST be
// closed", assigning no code and requiring no frame, and this reader did exactly that — a
// bare `break`. §9.1's floor row that mandated it was REPLACED at the same revision (N18).
test("§4.11 — a non-EXECUTE root is answered 400 invalid_request, not closed on", async () => {
  const { peer, sock } = await connectRaw();
  try {
    const root = Entity.create("primitive/any", Ecf.map(["request_id", Ecf.text("x-1")]));
    await writeFrame(sock, new Envelope(root, []).encode());
    const { status, code, requestId } = await readRefusal(sock);
    assert.equal(status, 400);
    assert.equal(code, "invalid_request");
    // Correlated where the id is recoverable; the uncorrelated frame is the FALLBACK.
    assert.equal(requestId, "x-1");
  } finally {
    sock.destroy();
    await peer.dispose();
  }
});
