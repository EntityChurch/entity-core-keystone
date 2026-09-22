/**
 * `kpc-host` — the keystone peer contract host for the typescript peer.
 *
 * `runHost(argv, installFixtures)`. Every fixture below is specified byte-for-byte in
 * `protocol-generator/shared/peer-contract/FIXTURE-HOST.md`, and the section numbers in
 * the comments are that document's. The shared driver (`tools/peer-contract/driver`)
 * measures what these fixtures do; nothing here decides a verdict.
 *
 * It imports ONLY `entity-core-protocol-typescript`, through that package's `exports`
 * map (run-contract.sh links it into this package's node_modules). If a fixture needs
 * something the package does not expose, that is a contract finding about the peer, and
 * the fix belongs in the peer, not here.
 */

import { readFileSync } from "node:fs";

import {
  type ConsumerId,
  type DispatchContext,
  Ecf,
  Entity,
  type ExpressionRequest,
  GrantEntry,
  type HandlerHandle,
  HandlerResult,
  Permissions,
  type Peer,
  RegisterError,
  ResourceTarget,
  Scope,
  hashHex,
  runHost,
} from "entity-core-protocol-typescript";

type EcfValue = ReturnType<typeof Ecf.text>;

function any(...pairs: (readonly [string, EcfValue])[]): Entity {
  return Entity.create("primitive/any", Ecf.map(...pairs));
}

function paramText(ctx: DispatchContext, key: string): string {
  try {
    return Ecf.optText(ctx.params.data, key) ?? "";
  } catch {
    return "";
  }
}

/** Lowercase hex text → bytes (the fixture's own parsing of a driver param). Empty for bad hex. */
function unhex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

const uint = (n: number): EcfValue => Ecf.uint(BigInt(n));

function statusCode(r: HandlerResult): Entity {
  let code = "";
  try {
    code = Ecf.optText(r.result.data, "code") ?? "";
  } catch {
    code = "";
  }
  return any(["status", uint(r.status)], ["code", Ecf.text(code)]);
}

/** A `system/tree` put request for `entity` (§6.3: the submitter supplies the content hash). */
function putRequest(entity: Entity): Entity {
  return Entity.create(
    "system/tree/put-request",
    Ecf.map([
      "entity",
      Ecf.map(["type", Ecf.text(entity.type)], ["data", entity.data], ["content_hash", Ecf.bytes(entity.contentHash)]),
    ]),
  );
}

/** Attempt an install that MUST be refused; report what the surface said. */
function refusal(attempt: () => HandlerHandle): { status: number; code: string } {
  try {
    // Installed when it must not have been: leave it installed (so the driver sees it)
    // and report success, which the driver scores as a failure.
    attempt();
    return { status: 200, code: "" };
  } catch (e) {
    if (e instanceof RegisterError) {
      return { status: e.status, code: e.code };
    }
    throw e;
  }
}

function packageAnnouncement(): { package: string; depends_on: string } {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    name: string;
    dependencies?: Record<string, string>;
  };
  const deps = Object.keys(pkg.dependencies ?? {});
  return { package: pkg.name, depends_on: deps.length === 1 ? deps[0]! : deps.join(",") };
}

function installFixtures(peer: Peer): void {
  const nonce = process.env["KPC_NONCE"];
  if (nonce === undefined) {
    throw new Error("KPC_NONCE is not set — the contract host is started by the contract driver");
  }
  const L = peer.localPeerId;
  const noop = (): HandlerResult => HandlerResult.ok(any());

  // §2.1 witness.
  const captured = `${nonce}:app/contract/witness`;
  peer.registerHandler(
    {
      pattern: "app/contract/witness",
      name: "witness",
      operations: { echo: { inputType: "primitive/any", outputType: "contract/witness-result" } },
      internalScope: null,
      types: { "contract/witness-result": Ecf.map(["name", Ecf.text("contract/witness-result")]) },
    },
    (ctx) => HandlerResult.ok(any(["witness", Ecf.text(`${captured}:${paramText(ctx, "echo")}`)])),
  );
  const collision = refusal(() => peer.registerHandler({ pattern: "app/contract/witness", name: "again", operations: ["echo"] }, noop));
  const builtin = refusal(() => peer.registerHandler({ pattern: "system/tree", name: "shadow", operations: ["get"] }, noop));
  const invalid = refusal(() => peer.registerHandler({ pattern: "app//bad", name: "bad", operations: ["echo"] }, noop));

  // §2.2 removable — the handle is kept.
  const removable = peer.registerHandler(
    {
      pattern: "app/contract/removable",
      name: "removable",
      operations: ["echo"],
      types: { "contract/removable-type": Ecf.map(["name", Ecf.text("contract/removable-type")]) },
    },
    () => HandlerResult.ok(any(["witness", Ecf.text("removable")])),
  );

  // §2.4 consumers, in order A, B (tree) then C (content). One ordered log; JS delivery is
  // single-threaded, so ordering is the delivery order.
  const log: string[] = [];
  const eventsPrefix = `/${L}/app/contract/events/`;
  const treeConsumer = (tag: string) => (ev: { path: string; context: { author?: Uint8Array } | null }) => {
    if (ev.path.startsWith(eventsPrefix)) {
      const author = ev.context?.author;
      log.push(`${tag}|tree|${ev.path}|${author === undefined ? "" : hashHex(author)}`);
    }
  };
  peer.emit.registerTreeConsumer(treeConsumer("A"));
  const b: ConsumerId = peer.emit.registerTreeConsumer(treeConsumer("B"));
  peer.emit.registerContentConsumer((ev) => {
    if (ev.entity.type === "contract/event-marker") {
      log.push(`C|content|${hashHex(ev.hash)}|`);
    }
  });

  // §2.3 probe.
  peer.registerHandler(
    { pattern: "app/contract/probe", name: "probe", operations: ["install_report", "close_removable", "events", "unregister_b"] },
    (ctx) => {
      switch (ctx.operation) {
        case "install_report":
          return HandlerResult.ok(
            any(
              ["collision_status", uint(collision.status)],
              ["collision_code", Ecf.text(collision.code)],
              ["builtin_collision_status", uint(builtin.status)],
              ["builtin_collision_code", Ecf.text(builtin.code)],
              ["invalid_status", uint(invalid.status)],
              ["invalid_code", Ecf.text(invalid.code)],
            ),
          );
        case "close_removable": {
          const first = removable.close();
          const second = removable.close();
          return HandlerResult.ok(any(["first", Ecf.bool(first)], ["second", Ecf.bool(second)]));
        }
        case "events":
          return HandlerResult.ok(any(["log", Ecf.array(log.map((e) => Ecf.text(e)))]));
        case "unregister_b":
          return HandlerResult.ok(any(["removed", Ecf.bool(peer.emit.unregisterConsumer(b))]));
        default:
          return HandlerResult.of(501, Entity.create("system/protocol/error", Ecf.map(["code", Ecf.text("unsupported_operation")])));
      }
    },
  );

  // §2.5 granted / ungranted.
  const putUnderHandlerGrant = async (ctx: DispatchContext, target: string): Promise<HandlerResult> => {
    const grant = ctx.handlerGrant;
    if (grant === null) {
      return HandlerResult.ok(any(["status", uint(403)], ["code", Ecf.text("capability_denied")]));
    }
    const r = await ctx.dispatchExecute({
      uri: "system/tree",
      operation: "put",
      params: putRequest(any(["v", uint(1)])),
      resource: new ResourceTarget([target], null),
      capability: grant,
    });
    return HandlerResult.ok(statusCode(r));
  };
  const scratchScope = [
    new GrantEntry(
      new Scope(["system/tree"], null),
      new Scope([`/${L}/app/contract/scratch/*`], null),
      new Scope(["put"], null),
      null,
      null,
      null,
    ),
  ];
  peer.registerHandler(
    { pattern: "app/contract/granted", name: "granted", operations: ["put_inside", "put_outside"], internalScope: scratchScope },
    (ctx) => putUnderHandlerGrant(ctx, ctx.operation === "put_inside" ? "app/contract/scratch/inside" : "app/contract/other/outside"),
  );
  peer.registerHandler(
    { pattern: "app/contract/ungranted", name: "ungranted", operations: ["put_inside"], internalScope: null },
    (ctx) => putUnderHandlerGrant(ctx, "app/contract/scratch/inside"),
  );

  // §2.6 context.
  peer.registerHandler({ pattern: "app/contract/context", name: "context", operations: ["echo", "budget"] }, (ctx) => {
    if (ctx.operation === "budget") {
      return HandlerResult.ok(any(["frame_budget", uint(ctx.frameBudget())]));
    }
    return HandlerResult.ok(
      any(
        ["operation", Ecf.text(ctx.operation)],
        ["pattern", Ecf.text(ctx.pattern)],
        ["suffix", Ecf.text(ctx.suffix)],
        ["author", Ecf.text(ctx.author === null ? "" : hashHex(ctx.author))],
        ["caller_capability", Ecf.text(ctx.callerCapability === null ? "" : ctx.callerCapability.contentHashHex)],
        ["handler_grant", Ecf.text(ctx.handlerGrant === null ? "" : ctx.handlerGrant.contentHashHex)],
        ["marker", Ecf.text(paramText(ctx, "marker"))],
      ),
    );
  });

  // §2.7 dispatch — under the caller's capability (the default).
  peer.registerHandler({ pattern: "app/contract/dispatch", name: "dispatch", operations: ["put_as_caller"] }, async (ctx) => {
    const n = Ecf.field(ctx.params.data, "n") ?? uint(0);
    const marker = Entity.create("contract/event-marker", Ecf.map(["n", n]));
    const r = await ctx.dispatchExecute({
      uri: "system/tree",
      operation: "put",
      params: putRequest(marker),
      resource: new ResourceTarget(["app/contract/events/sub"], null),
    });
    return HandlerResult.ok(statusCode(r));
  });

  // §2.8 authz.
  peer.registerHandler({ pattern: "app/contract/authz", name: "authz", operations: ["check"] }, (ctx) => {
    const token = ctx.callerCapability;
    const allowed =
      token !== null &&
      Permissions.checkPathPermission(
        paramText(ctx, "operation"),
        paramText(ctx, "path"),
        token,
        paramText(ctx, "handler_pattern"),
        ctx.localPeerId,
      );
    return HandlerResult.ok(any(["allowed", Ecf.bool(allowed)]));
  });

  // §2.10 data — the in-process data surface, which is the peer's own store.
  const abs = (p: string): string => `/${L}/${p}`;
  const item = (marker: string): Entity => Entity.create("contract/data-item", Ecf.map(["marker", Ecf.text(marker)]));
  const found = (e: Entity | undefined): Entity => {
    let marker = "";
    if (e !== undefined) {
      try {
        marker = Ecf.optText(e.data, "marker") ?? "";
      } catch {
        marker = "";
      }
    }
    return any(
      ["found", Ecf.bool(e !== undefined)],
      ["type", Ecf.text(e?.type ?? "")],
      ["marker", Ecf.text(marker)],
      ["hash", Ecf.text(e?.contentHashHex ?? "")],
    );
  };
  peer.registerHandler(
    { pattern: "app/contract/data", name: "data", operations: ["put", "get", "bind", "get_at", "unbind", "forge"] },
    (ctx) => {
      switch (ctx.operation) {
        case "put": {
          const e = item(paramText(ctx, "marker"));
          const accepted = peer.contentStore.put(e);
          return HandlerResult.ok(any(["hash", Ecf.text(e.contentHashHex)], ["accepted", Ecf.bool(accepted)]));
        }
        case "get":
          return HandlerResult.ok(found(peer.contentStore.get(unhex(paramText(ctx, "hash")))));
        case "bind": {
          const e = item(paramText(ctx, "marker"));
          const accepted = peer.tree.put(abs(paramText(ctx, "path")), e, ctx.emitContext());
          return HandlerResult.ok(any(["hash", Ecf.text(e.contentHashHex)], ["accepted", Ecf.bool(accepted)]));
        }
        case "get_at":
          return HandlerResult.ok(found(peer.tree.get(abs(paramText(ctx, "path")))));
        case "unbind":
          peer.tree.remove(abs(paramText(ctx, "path")), ctx.emitContext());
          return HandlerResult.ok(any());
        case "forge": {
          // TypeScript's `private constructor` is compile-time only, so the forgery IS
          // constructible from outside the package: the forger's data under the victim's
          // content hash. What the contract asks is that the store refuses it.
          const forger = item(paramText(ctx, "marker"));
          const victim = item(paramText(ctx, "victim_marker"));
          const Ctor = Entity as unknown as new (type: string, data: EcfValue, hash: Uint8Array, wire: Uint8Array) => Entity;
          const forged = new Ctor(forger.type, forger.data, victim.contentHash, forger.wireBytes);
          const putAccepted = peer.contentStore.put(forged);
          const bindAccepted = peer.tree.put(abs(paramText(ctx, "path")), forged);
          return HandlerResult.ok(
            any(["constructible", Ecf.bool(true)], ["put_accepted", Ecf.bool(putAccepted)], ["bind_accepted", Ecf.bool(bindAccepted)]),
          );
        }
        default:
          return HandlerResult.of(501, Entity.create("system/protocol/error", Ecf.map(["code", Ecf.text("unsupported_operation")])));
      }
    },
  );

  // §2.9 evaluator (MODULE) — claims `compute/literal` too, so a peer that asked it
  // before its own literal floor would be visible.
  peer.setExpressionEvaluator({
    evaluate(req: ExpressionRequest): HandlerResult | null {
      if (req.expression.type !== "contract/echo-expression" && req.expression.type !== "compute/literal") {
        return null;
      }
      const value = Ecf.field(req.expression.data, "value") ?? Ecf.nullValue;
      return HandlerResult.ok(any(["evaluated_by", Ecf.text("contract-evaluator")], ["value", value]));
    },
  });
}

runHost(process.argv.slice(2), installFixtures, { recordFields: { contract_host: packageAnnouncement() } }).then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exit(1);
  },
);
