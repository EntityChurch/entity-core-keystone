"use strict";
/**
 * session — a per-connection handle the AUTHORED flow drives. Because Node-RED
 * deep-CLONES msg between nodes (flattening class instances + dropping functions),
 * two rules shape this design:
 *   1. every wire carries CBOR *bytes* (Buffers survive cloning) — exactly what the
 *      real TCP wire carries; envelopes are reconstructed inside each node.
 *   2. the session (with its closures + the §6.11 correlation Map) lives in a
 *      module-level REGISTRY keyed by connection id; nodes look it up by msg.conn
 *      (a string), never carry it on msg.
 *
 * §6.5 dispatch is AUTHORED here as GRANULAR STEPS, one per visible flow node
 * (decode → target → connect-preauth → author → capability → verify → resolve →
 * permission → handler). Each step advances a per-dispatch scratch context — the
 * intermediate class instances (Execute, Envelope, capability token, resolution)
 * live in that context, keyed by a dispatch id, never on the cloned msg. Only the
 * DELEGATED leaf math is called out to (kernel.prim: Ed25519 verify, the
 * capability-chain verdict, the permission verdict, the model/path helpers); the
 * §6.5/§5.2 SEQUENCE is the authored graph. This is a faithful port of the TS
 * peer's Dispatcher#dispatchCore/#verifyRequest/#runHandler (ADR-0012: still
 * cohort-consistent — the leaf crypto is shared substrate).
 *
 * It also implements the §6.11 ReentrantSender (nextRequestId + sendRequest) so the
 * delegated respond()/dispatch-outbound can originate over the flow-owned socket.
 */

const path = require("node:path");
const ec = require(path.join(__dirname, "codec-bridge.js"));

/** connId -> session. Shared with the flow via bridge.sessions (settings.js). */
const sessions = new Map();

function newSession(kernel, connId, sendFrame) {
  const P = kernel.prim; // delegated leaf primitives (crypto/verdict/model/path)
  const peer = kernel.services; // localPeerId / localIdentity / tree / contentStore / nowMs
  const registry = kernel.registry;
  const connState = new kernel.ConnectionState();
  const pending = new Map(); // request_id -> { resolve, reject } (§6.11 reentry)
  const dispatches = new Map(); // dispatch id -> scratch ctx (authored §6.5 chain)
  let counter = 0;
  let dcounter = 0;

  const localPeerId = peer.localPeerId;

  // ---- small local mirrors of the dispatcher's plain-function helpers ----
  const isProto = (e) => e instanceof P.EntityProtocolError;
  const msgOf = (e) => (e instanceof Error ? e.message : String(e));
  /** An error Envelope (bytes), mirroring Dispatcher.errorEnvelope. */
  const errBytes = (requestId, status, code, message) =>
    Buffer.from(new ec.Envelope(ec.ExecuteResponse.error(requestId, status, code, message).entity, []).encode());
  /** An error Envelope (object), for the handler-run path. */
  const errEnv = (requestId, status, code, message) =>
    new ec.Envelope(ec.ExecuteResponse.error(requestId, status, code, message).entity, []);
  /** The §6.5 outer-wrapper fault mapping: EntityProtocolError → request_error, else internal_error. */
  const faultErr = (e) =>
    isProto(e)
      ? { status: e.status, code: "request_error", message: e.message }
      : { status: ec.Status.InternalError, code: "internal_error", message: msgOf(e) };

  const session = {
    connId,
    connState,

    // ---- §6.11 ReentrantSender (used in-process by the delegated respond() + handlers) ----
    nextRequestId() {
      return "nr-" + connId + "-" + ++counter;
    },
    async sendRequest(envelope, timeoutMs) {
      const reqId = new ec.Execute(envelope.root).requestId;
      if (pending.has(reqId)) throw new Error("duplicate in-flight request_id '" + reqId + "'");
      let resolve, reject;
      const p = new Promise((res, rej) => { resolve = res; reject = rej; });
      pending.set(reqId, { resolve, reject });
      const timer = setTimeout(() => {
        if (pending.delete(reqId)) reject(new Error("no response for '" + reqId + "' within " + timeoutMs + "ms"));
      }, timeoutMs);
      try {
        sendFrame(envelope.encode()); // authored transport egress (direct origination)
      } catch (e) {
        clearTimeout(timer);
        pending.delete(reqId);
        throw e;
      }
      try {
        return await p;
      } finally {
        clearTimeout(timer);
        pending.delete(reqId);
      }
    },

    // ---- §6.11 demux (n-decode) + reentry routing (n-reentry) ----

    /**
     * §6.11 demux discriminant from raw frame bytes.
     *
     * "undecodable" and "invalid" ARE DIFFERENT ANSWERS AND THIS USED TO COLLAPSE THEM.
     * A frame the strict decoder rejects is the decode-boundary case and takes the code
     * its CAUSE is assigned (§4.11, §5.2a); a frame that decodes cleanly but whose root is
     * neither EXECUTE nor EXECUTE_RESPONSE is §3.3's case and takes `400 invalid_request`.
     * Returning "invalid" for both sent the first one to a node whose whole body was
     * `return null`, so this peer answered a mis-keyed `included` entry with silence —
     * measured on the wire 2026-09-14, status 0 on both B-family cases.
     *
     * BOTH ARMS NOW ANSWER, which is the .25 change: §4.9(c)'s deliver-or-signal rule is
     * scoped to requests the peer ADMITS and reaches NEITHER of these, and §4.11 is the
     * rule that does. See `refusePreAdmissionBytes` and `refuseNonExecuteRootBytes`.
     */
    classifyBytes(bytes) {
      let env;
      try {
        env = ec.decodeEnvelope(bytes);
      } catch (_) {
        return "undecodable"; // refused — and the refusal is a STATUS (refusePreAdmissionBytes)
      }
      const t = env.root.type;
      if (t === ec.TypeNames.Execute) return "execute";
      if (t === ec.TypeNames.ExecuteResponse) return "response";
      return "invalid";
    },

    /**
     * Build the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires for a frame the strict
     * decoder rejected — CORRELATED where a request_id is recoverable, best-effort
     * uncorrelated where it is not. Returns the encoded response bytes.
     *
     * TWO THINGS CHANGED AT .25 AND THEY FAIL DIFFERENTLY.
     *
     * THE CODE IS THE CAUSE'S. This answered `non_canonical_ecf` for every decode
     * failure. §5.2a (N4/N5) makes a mis-keyed `included` entry `400 hash_mismatch` and
     * rules `non_canonical_ecf` NOT conformant there: the bytes ARE canonical, and what is
     * false is the claim the KEY makes, so `non_canonical_ecf`'s remedy (re-encode) sends
     * an honest caller to the wrong layer. The tag-policy arm keeps its own code, because
     * ENTITY-CBOR-ENCODING defines that code for that violation specifically. The table is
     * DELEGATED (`ec.preAdmissionRefusal`) rather than restated here — a second reading of
     * which error means which code drifts on the first revision that adds a cause.
     *
     * AND AN UNRECOVERABLE request_id IS NO LONGER SILENCE. This returned null on the
     * reading that "there is nobody to answer". §4.11 rules otherwise and is right to: an
     * uncorrelated coded frame still tells the sender its frame was REFUSED rather than
     * lost, which is exactly the distinction a silent drop destroys.
     *
     * The frame stays rejected either way: nothing is built from it and nothing is stored
     * — the salvage decode exists solely to read back the correlation key.
     */
    refusePreAdmissionBytes(bytes) {
      let err;
      try {
        ec.decodeEnvelope(bytes);
        return null; // it decodes \u2014 not this node's case
      } catch (e) {
        err = e;
      }
      const { status, code, message } = ec.preAdmissionRefusal(err);
      let requestId = "";
      try {
        const salvaged = ec.decodeSalvage(bytes);
        const root = ec.Ecf.require(salvaged, "root");
        requestId = ec.Ecf.requireText(ec.Ecf.require(root, "data"), "request_id");
      } catch (_) {
        requestId = ""; // \u00a74.11's best-effort form, prescribed rather than tolerated
      }
      try {
        const response = ec.ExecuteResponse.error(requestId, status, code, message);
        return ec.encodeEnvelope(new ec.Envelope(response.entity, []));
      } catch (_) {
        return null;
      }
    },

    /**
     * Build the `400 invalid_request` answer for a frame that DECODED cleanly and whose
     * root is neither EXECUTE nor EXECUTE_RESPONSE (\u00a73.3, \u00a74.11).
     *
     * ITS PREDECESSOR DROPPED THE FRAME, and that is one of the two behaviours \u00a74.11
     * names separately as non-conformant. It is also the easiest one to leave in place,
     * because the input reads as an unroutable message rather than as a refusal \u2014 and the
     * caller IS correlatable: the request_id is right there in a root that decoded. A drop
     * bills them their full \u00a76.11(c) deadline for a frame we read successfully and chose
     * not to answer.
     */
    refuseNonExecuteRootBytes(bytes) {
      let requestId = "";
      try {
        const env = ec.decodeEnvelope(bytes);
        requestId = ec.Ecf.optText(env.root.data, "request_id") || "";
      } catch (_) {
        return null; // undecodable is the other node's case
      }
      try {
        const response = ec.ExecuteResponse.error(
          requestId,
          400,
          "invalid_request",
          "root is neither an EXECUTE nor an EXECUTE_RESPONSE",
        );
        return ec.encodeEnvelope(new ec.Envelope(response.entity, []));
      } catch (_) {
        return null;
      }
    },

    /**
     * Build the coded frame for a FRAMING refusal the authored transport node detected
     * itself \u2014 an over-limit length prefix, or a stream that ended mid-frame. There is no
     * request_id by construction (no frame ever arrived), so this is \u00a74.11's best-effort
     * uncorrelated form, which the section prescribes rather than tolerates.
     */
    refuseFramingBytes(err) {
      const { status, code, message } = ec.preAdmissionRefusal(err);
      try {
        const response = ec.ExecuteResponse.error("", status, code, message);
        return ec.encodeEnvelope(new ec.Envelope(response.entity, []));
      } catch (_) {
        return null;
      }
    },

    /** Route an inbound EXECUTE_RESPONSE frame to its parked origination (N7). */
    routeResponseBytes(bytes) {
      let env;
      try {
        env = ec.decodeEnvelope(bytes);
      } catch (_) {
        return;
      }
      try {
        const reqId = new ec.ExecuteResponse(env.root).requestId;
        const d = pending.get(reqId);
        if (d) d.resolve(env);
      } catch (_) {
        // malformed response root — no id to route to; drop (mirrors #routeResponse)
      }
    },

    // ================= AUTHORED §6.5 dispatch chain (one step per visible node) =================
    // Each dpXxx(did) reads/advances the scratch ctx and returns a route string; the
    // flow node maps the route to an output wire. dispatchScratch lives here, never on msg.

    /**
     * Begin dispatch of an inbound EXECUTE frame: decode → construct Execute →
     * request_id → dispatch path → target-is-local (§1.4). Mints the dispatch id.
     * Mirrors Dispatcher.dispatch()'s prelude + #dispatchCore's path/target checks.
     * @returns {{did:string, route:'ok'|'err'}}
     */
    dpBegin(bytes) {
      const did = "d" + connId + "-" + ++dcounter;
      const ctx = { requestId: "", establishedBefore: connState.established };
      dispatches.set(did, ctx);

      let env;
      try {
        env = ec.decodeEnvelope(bytes);
      } catch (e) {
        // A frame that classified as EXECUTE but fails full decode here → 400.
        ctx.err = { status: ec.Status.BadRequest, code: "invalid_request", message: msgOf(e) };
        return { did, route: "err" };
      }
      ctx.env = env;

      // new Execute / requestId: EntityProtocolError → 400 invalid_request (requestId ""),
      // anything else rethrows (mirrors dispatch(); an inbound EXECUTE never silently 500s here).
      try {
        ctx.execute = new ec.Execute(env.root);
      } catch (e) {
        if (isProto(e)) { ctx.err = { status: ec.Status.BadRequest, code: "invalid_request", message: e.message }; return { did, route: "err" }; }
        throw e;
      }
      try {
        ctx.requestId = ctx.execute.requestId;
      } catch (e) {
        if (isProto(e)) { ctx.err = { status: ec.Status.BadRequest, code: "invalid_request", message: e.message }; return { did, route: "err" }; }
        throw e;
      }

      // From here, faults follow the §6.5 outer wrapper (request_error / internal_error).
      try {
        let dpath;
        try {
          dpath = P.Paths.dispatchPath(ctx.execute.uri, localPeerId);
        } catch (e) {
          if (isProto(e)) { ctx.err = { status: ec.Status.BadRequest, code: "invalid_request", message: e.message }; return { did, route: "err" }; }
          throw e;
        }
        ctx.path = dpath;
        // Inbound dispatch MUST target the local peer (§1.4).
        if (P.Paths.extractPeer(dpath, localPeerId) !== localPeerId) {
          ctx.err = { status: ec.Status.BadRequest, code: "invalid_request", message: "request does not target local peer" };
          return { did, route: "err" };
        }
        return { did, route: "ok" };
      } catch (e) {
        ctx.err = faultErr(e);
        return { did, route: "err" };
      }
    },

    /**
     * Connection pre-authorization (§4.2, §6.5) — the sole no-auth special case.
     * @returns {'connect'|'auth'|'err'}
     */
    dpConnectPreauth(did) {
      const ctx = dispatches.get(did);
      try {
        // RT-6 (§4.6, 0.8.1): route ALL connect-path traffic to the connect handler,
        // established or not. A replayed authenticate on an established connection
        // carries no author/capability (same pre-auth shape as leg 1) and MUST reach
        // ConnectHandler's own 401 invalid_nonce check, not fall through to the
        // generic authenticated-dispatch 401 missing_author below.
        const connectPath = "/" + localPeerId + "/" + ec.Protocols.ConnectPath;
        if (ctx.path === connectPath) {
          const connect = registry.get(ec.Protocols.ConnectPath);
          if (connect === null) {
            ctx.err = { status: ec.Status.InternalError, code: "no_connect_handler", message: "connect handler missing" };
            return "err";
          }
          ctx.connectHandler = connect;
          return "connect";
        }
        return "auth";
      } catch (e) {
        ctx.err = faultErr(e);
        return "err";
      }
    },

    /** Every authenticated EXECUTE MUST carry author (§5.1). Missing → 401 (§3.3). */
    dpAuthorPresent(did) {
      const ctx = dispatches.get(did);
      // §4.7: a non-connect EXECUTE arriving BEFORE the handshake completes is refused
      // 401 authentication_failed. `missing_author` is the right code for an ESTABLISHED
      // connection that omits `author`, and the wrong one here: the caller's remedy is to
      // finish the handshake, not to sign this frame.
      if (!connState.established) {
        ctx.err = { status: ec.Status.Unauthorized, code: "authentication_failed", message: "connection not established" };
        return "err";
      }
      if (ctx.execute.author === null) {
        ctx.err = { status: ec.Status.Unauthorized, code: "missing_author", message: "author required" };
        return "err";
      }
      return "ok";
    },

    /** Every authenticated EXECUTE MUST carry capability (§5.1). Missing → 403 (§3.3). */
    dpCapPresent(did) {
      const ctx = dispatches.get(did);
      if (ctx.execute.capability === null) {
        ctx.err = { status: ec.Status.Forbidden, code: "missing_authorization", message: "capability required" };
        return "err";
      }
      return "ok";
    },

    /**
     * Ingest envelope signatures (§6.5) + integrity/capability verification (§5.2).
     * Delegates the leaf crypto (Ed25519 verify, capability-chain verdict) to prim;
     * AUTHORS the §5.2 sequence + the single-401 / chain-depth / revocation ordering.
     * @returns {'ok'|'err'}
     */
    dpVerify(did) {
      const ctx = dispatches.get(did);
      try {
        this._ingestSignatures(ctx.env);
        const verify = this._verifyRequest(ctx.execute, ctx.env);
        if (verify.status !== ec.Status.Ok) {
          ctx.err = { status: verify.status, code: verify.code, message: verify.message };
          return "err";
        }
        ctx.capability = verify.capability;
        return "ok";
      } catch (e) {
        ctx.err = faultErr(e);
        return "err";
      }
    },

    /** Resolve handler by tree walk (§6.6). No match → 404. */
    dpResolve(did) {
      const ctx = dispatches.get(did);
      try {
        const res = registry.resolve(ctx.path);
        if (res === null) {
          // §3.3's 404 row (0.8.2.7) names the code `handler_not_found`. `not_found` is
          // the code for a bound-path miss INSIDE a handler (tree get); this is the
          // resolution step failing, a different row and a different remedy.
          ctx.err = { status: ec.Status.NotFound, code: "handler_not_found", message: "no handler resolves " + ctx.path };
          return "err";
        }
        ctx.res = res;
        return "ok";
      } catch (e) {
        ctx.err = faultErr(e);
        return "err";
      }
    },

    /**
     * Dispatch permission check (§5.2 check_permission, §PR-8) + dispatch-time
     * handler-grant validation (§6.8). Delegates the permission verdict to prim.
     * @returns {'ok'|'err'}
     */
    dpPermission(did) {
      const ctx = dispatches.get(did);
      try {
        const capability = ctx.capability;
        const granterPeerId = P.Permissions.resolveGranterPeerId(capability, ctx.env, localPeerId);
        if (!P.Permissions.checkPermission(ctx.execute, capability, ctx.res.pattern, localPeerId, granterPeerId)) {
          ctx.err = { status: ec.Status.Forbidden, code: "capability_denied", message: "capability does not grant the operation" };
          return "err";
        }
        const handlerGrant = registry.resolveGrant(ctx.res.pattern);
        if (handlerGrant === null || !this._validateHandlerGrant(handlerGrant)) {
          ctx.err = { status: ec.Status.Forbidden, code: "permission_denied", message: "handler grant missing or invalid" };
          return "err";
        }
        ctx.handlerGrant = handlerGrant;
        return "ok";
      } catch (e) {
        ctx.err = faultErr(e);
        return "err";
      }
    },

    /** Run the resolved connect handler (connection pre-auth branch). Terminal. */
    async dpRunConnect(did) {
      const ctx = dispatches.get(did);
      try {
        const env = await this._runHandler(
          ctx.connectHandler, ctx.execute, ctx.env, connState, null, null, ec.Protocols.ConnectPath, "", session,
        );
        return this._finish(did, env);
      } catch (e) {
        const f = faultErr(e);
        return this._finishBytes(did, errBytes(ctx.requestId, f.status, f.code, f.message));
      }
    },

    /**
     * Run the resolved handler (§6.13): native in-process body, or the entity-native
     * seam (v7.74 §6.13(a)). Terminal.
     */
    async dpRunHandler(did) {
      const ctx = dispatches.get(did);
      try {
        const res = ctx.res;
        const env = res.native !== null
          ? await this._runHandler(res.native, ctx.execute, ctx.env, connState, ctx.capability, ctx.handlerGrant, res.pattern, res.suffix, session)
          : this._runEntityNative(res.handlerEntity, ctx.execute);
        return this._finish(did, env);
      } catch (e) {
        const f = faultErr(e);
        return this._finishBytes(did, errBytes(ctx.requestId, f.status, f.code, f.message));
      }
    },

    /** Build the error EXECUTE_RESPONSE for a short-circuited dispatch. Terminal. */
    dpBuildError(did) {
      const ctx = dispatches.get(did);
      const e = ctx.err;
      return this._finishBytes(did, errBytes(ctx.requestId, e.status, e.code, e.message));
    },

    // ---- terminal helpers: compute §4.1 flipped, encode, free the scratch ----
    _finish(did, envelope) {
      return this._finishBytes(did, Buffer.from(envelope.encode()));
    },
    _finishBytes(did, payload) {
      const ctx = dispatches.get(did);
      const flipped = !ctx.establishedBefore && connState.established; // §4.1: did this dispatch establish?
      dispatches.delete(did);
      return { payload, flipped };
    },

    // ---- ported private dispatcher helpers (delegate leaf crypto, author the logic) ----

    /**
     * §5.2 verify_request: request integrity + capability verification. Faithful port
     * of Dispatcher#verifyRequest (revocation skipped when supports_revocation=false is
     * NOT the case here — we mirror the TS peer which DOES walk revocations).
     */
    _verifyRequest(execute, envelope) {
      const authorHash = execute.author;
      const capabilityHash = execute.capability;
      const deny = (status, code, message) => ({ status, code, message, capability: null });

      // Signature (target-matching) over the EXECUTE.
      const signature = P.ChainVerifier.findSignature(envelope, execute.entity.contentHash);
      if (signature === null) return deny(ec.Status.Unauthorized, "invalid_signature", "no signature for EXECUTE");
      if (!P.hashEqual(P.signatureSigner(signature), authorHash)) {
        return deny(ec.Status.Unauthorized, "invalid_signature", "signature signer is not the author");
      }
      const author = envelope.find(authorHash);
      if (author === undefined) return deny(ec.Status.Unauthorized, "unresolvable_author", "author identity not in included");
      if (!P.verifySignature(signature, author)) {
        return deny(ec.Status.Unauthorized, "invalid_signature", "EXECUTE signature does not verify");
      }

      // Capability integrity.
      const capabilityEntity = envelope.find(capabilityHash);
      if (capabilityEntity === undefined) return deny(ec.Status.Forbidden, "capability_denied", "capability not in included");
      const capability = new P.CapabilityToken(capabilityEntity);

      // §5.2 / §3.6 PR-3 single-401 carve-out: the leaf cap's grantee MUST resolve to a
      // present system/peer entity — fired BEFORE the structural grantee==author check.
      const granteeEntity = envelope.find(capability.grantee);
      if (granteeEntity === undefined || granteeEntity.type !== ec.TypeNames.Peer) {
        return deny(ec.Status.Unauthorized, "unresolvable_grantee", "leaf cap grantee does not resolve to a system/peer entity");
      }
      if (!P.hashEqual(capability.grantee, authorHash)) {
        return deny(ec.Status.Forbidden, "capability_denied", "capability grantee is not the author");
      }
      // §4.10(b): a chain exceeding max depth is 400 chain_depth_exceeded (structural),
      // BEFORE the per-link authz walk — distinct from 403 capability_denied.
      if (P.ChainVerifier.exceedsMaxDepth(capability, envelope)) {
        return deny(ec.Status.BadRequest, "chain_depth_exceeded", "capability chain exceeds max depth (§4.10b)");
      }
      if (!P.ChainVerifier.verifyCapabilityChain(capability, envelope, localPeerId, peer.nowMs)) {
        return deny(ec.Status.Forbidden, "capability_denied", "capability chain verification failed");
      }
      // §5.2 step 4: revocation. A revoked link → 403 capability_revoked.
      if (this._isChainRevoked(capability, envelope)) {
        return deny(ec.Status.Forbidden, "capability_revoked", "capability is revoked (§5.1)");
      }
      return { status: ec.Status.Ok, code: null, message: null, capability };
    },

    /** §5.1 is_revoked over the full authority chain. Port of Dispatcher#isChainRevoked. */
    _isChainRevoked(leaf, envelope) {
      let current = leaf;
      let depth = 0;
      while (current !== null && depth <= 64) {
        const p = "/" + localPeerId + "/system/capability/revocations/" + current.contentHashHex;
        if (peer.tree.get(p) !== undefined) return true;
        if (current.parent === null) break;
        const parent = envelope.find(current.parent);
        if (parent === undefined) break;
        current = new P.CapabilityToken(parent);
        depth++;
      }
      return false;
    },

    /** §6.8 dispatch-time handler-grant validation. Port of Dispatcher#validateHandlerGrant. */
    _validateHandlerGrant(grant) {
      if (grant.granter === null || !P.hashEqual(grant.granter, peer.localIdentity.identityHash)) return false;
      const sig = peer.tree.get("/" + localPeerId + "/system/signature/" + grant.contentHashHex);
      if (sig === undefined || !P.verifySignature(sig, peer.localIdentity.peerEntity)) return false;
      if (grant.notBefore !== null && peer.nowMs < grant.notBefore) return false;
      if (grant.expiresAt !== null && grant.expiresAt < peer.nowMs) return false;
      return true;
    },

    /** §6.5 ingest_envelope_signatures. Port of Dispatcher#ingestSignatures. */
    _ingestSignatures(envelope) {
      for (const entity of envelope.included.values()) {
        if (entity.type !== ec.TypeNames.Signature) continue;
        peer.contentStore.put(entity);
        const signerHash = P.signatureSigner(entity);
        const signerPeer = envelope.find(signerHash) ?? peer.contentStore.get(signerHash);
        if (signerPeer === undefined) continue;
        peer.contentStore.put(signerPeer);
        const p = "/" + P.peerEntityId(signerPeer) + "/system/signature/" + P.hashHex(P.signatureTarget(entity));
        if (peer.tree.get(p) === undefined) peer.tree.put(p, entity);
      }
    },

    /** Run a handler with a §6.13 HandlerContext. Port of Dispatcher#runHandler. */
    async _runHandler(handler, execute, request, conn, callerCapability, handlerGrant, pattern, suffix, sender) {
      const context = new P.HandlerContext({
        peer,
        execute,
        envelope: request,
        pattern,
        suffix,
        callerCapability,
        handlerGrant,
        author: execute.author,
        connection: conn,
        // §6.13(b) handler-facing outbound seam — routes through §6.11 reentry.
        outbound: sender === null ? null : new P.OutboundDispatchImpl(peer.localIdentity, sender),
      });
      try {
        const result = await handler.handle(context);
        const response = ec.ExecuteResponse.build(execute.requestId, result.status, result.result);
        return new ec.Envelope(response.entity, result.included);
      } catch (e) {
        if (isProto(e)) return errEnv(execute.requestId, e.status, "handler_error", e.message);
        return errEnv(execute.requestId, ec.Status.InternalError, "internal_error", msgOf(e));
      }
    },

    /** Entity-native handler seam (v7.74 §6.13(a)). Port of Dispatcher#runEntityNative. */
    _runEntityNative(handlerEntity, execute) {
      const exprPath = ec.Ecf.optText(handlerEntity.data, "expression_path");
      if (exprPath === null) {
        return errEnv(execute.requestId, ec.Status.NotSupported, "no_handler_body", "registered handler has neither a native body nor an expression_path");
      }
      const absExpr = P.Paths.canonicalize(exprPath, localPeerId);
      const expr = peer.tree.get(absExpr);
      if (expr === undefined) {
        return errEnv(execute.requestId, ec.Status.NotFound, "expression_not_found", "no entity bound at the handler's expression_path " + absExpr);
      }
      if (expr.type === ec.TypeNames.ComputeLiteral) {
        const value = ec.Ecf.require(expr.data, "value");
        const result = ec.Entity.create(ec.TypeNames.ComputeResult, ec.Ecf.map(["value", value], ["expression", ec.Ecf.bytes(expr.contentHash)]));
        const response = ec.ExecuteResponse.build(execute.requestId, ec.Status.Ok, result);
        return new ec.Envelope(response.entity, []);
      }
      return errEnv(execute.requestId, ec.Status.NotSupported, "unsupported_expression", "core peer evaluates only compute/literal bodies (the entity-native seam); richer bodies need the compute extension");
    },

    // ---- §4.1 handshake ordering + lifecycle ----

    /** §4.1 ordering latch: resolve authResponseSent only after leg-2's response is written. */
    afterResponseWritten(flipped) {
      if (flipped) connState.authResponseSent.resolve();
    },

    /** Kick the delegated responder handshake driver (leg-3 reverse-authenticate). */
    start() {
      if (process.env.EC_NO_REVERSE_AUTH === "1") return; // diagnostic toggle
      Promise.resolve()
        .then(() => kernel.respond(session, kernel.identity, connState, kernel.HANDSHAKE_TIMEOUT_MS))
        .catch(() => { /* best-effort; a failed reverse handshake doesn't affect the initiator's session */ });
    },

    dispose() {
      for (const d of pending.values()) d.reject(new Error("connection closed"));
      pending.clear();
      dispatches.clear();
      // Unwind the delegated responder handshake driver promptly: a half-open probe
      // connection would otherwise leave respond() awaiting inboundHello for the full
      // 10s handshake timeout, leaking a session + timers per probe connection —
      // which saturates the event loop across a long conformance run (the t2_1/t2_2
      // §6.11-robustness failure). Rejecting the handshake Deferreds is idempotent
      // (no-op once settled) and best-effort-caught inside respond().
      connState.inboundHello.reject(new Error("connection closed"));
      connState.authResponseSent.reject(new Error("connection closed"));
      sessions.delete(connId);
    },
  };

  sessions.set(connId, session);
  return session;
}

module.exports = { newSession, sessions };
