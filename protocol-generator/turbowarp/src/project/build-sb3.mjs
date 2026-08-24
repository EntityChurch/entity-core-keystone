// build-sb3.mjs — generate `entity-core-peer.sb3`, the TurboWarp/Scratch project in which
// the entity-core §6.5 DISPATCH LOGIC IS AUTHORED AS SCRATCH BLOCKS. The only things that
// leave the canvas are the crypto/codec/socket "tricky bits", exposed by the `ecutils`
// custom extension (see ../extension/ec-utils-extension.js). Everything you see on the
// stage's script — the classify, the 401/403/404 guard ladder, handler routing — is the
// protocol, in the language.
//
// The dispatch is authored as a GUARD LADDER under a `when execute arrives` hat: a flat
// chain of `if <deny-condition> { send <error>; stop this script }` guards, then the
// handler send on fall-through. That maps 1:1 to Dispatcher#dispatchCore and reads top to
// bottom. A .sb3 is a ZIP of project.json + assets; this file compiles the block tree and
// writes it with a tiny store-only ZIP writer. See ../BLOCK-DESIGN.md.

import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "dist");
mkdirSync(OUT, { recursive: true });
const md5 = (buf) => createHash("md5").update(buf).digest("hex");

// ============================ block compiler (a small DSL) ============================
// Produces valid sb3 blocks. Input encodings (Scratch VM serialization):
//   reporter in a shadowed slot : [3, <blockId>, [10, ""]]
//   variable in a shadowed slot : [3, [12, name, varId], [10, ""]]
//   boolean operand / condition : [2, <blockId>]         (no shadow)
//   literal text                : [1, [10, "s"]]
//   literal number              : [1, [4, "n"]]
let seq = 0;
const B = {};
const mk = (op, { inputs = {}, fields = {}, top = false, x = 0, y = 0, mutation } = {}) => {
  const id = "b" + ++seq;
  B[id] = { opcode: op, next: null, parent: null, inputs, fields, shadow: false, topLevel: top, ...(top ? { x, y } : {}) };
  if (mutation) B[id].mutation = mutation;
  return id;
};
const rep = (blockId) => [3, blockId, [10, ""]];               // reporter block as input
const vvar = (v) => [3, [12, v.name, v.id], [10, ""]];         // variable as reporter input
const cond = (blockId) => [2, blockId];                        // boolean block as condition/operand
const txt = (s) => [1, [10, String(s)]];
const num = (n) => [1, [4, String(n)]];

// operators
const notB = (b) => mk("operator_not", { inputs: { OPERAND: cond(b) } });
const andB = (a, b) => mk("operator_and", { inputs: { OPERAND1: cond(a), OPERAND2: cond(b) } });
const orB = (a, b) => mk("operator_or", { inputs: { OPERAND1: cond(a), OPERAND2: cond(b) } });
const eqVal = (a, b) => mk("operator_equals", { inputs: { OPERAND1: a, OPERAND2: b } });
const eqEmpty = (v) => eqVal(vvar(v), txt(""));
const eqStr = (v, s) => eqVal(vvar(v), txt(s));
const eqRepStr = (block, s) => eqVal(rep(block), txt(s)); // compare a reporter's value to a literal

// extension blocks
const ext = (op, inputs) => mk("ecutils_" + op, { inputs });

// statements
const setVar = (v, valueInput) => mk("data_setvariableto", { inputs: { VALUE: valueInput }, fields: { VARIABLE: [v.name, v.id] } });
const changeVar = (v, n) => mk("data_changevariableby", { inputs: { VALUE: num(n) }, fields: { VARIABLE: [v.name, v.id] } });
const stopScript = () => mk("control_stop", { fields: { STOP_OPTION: ["this script", null] }, mutation: { tagName: "mutation", children: [], hasnext: "false" } });
const send = (respBlock, connVar) => ext("sendResponse", { RESP: rep(respBlock), CONN: vvar(connVar) });

// link a list of statement ids into a stack; return the first id
const stack = (ids) => {
  for (let i = 0; i < ids.length; i++) {
    B[ids[i]].parent = i === 0 ? null : ids[i - 1];
    B[ids[i]].next = i + 1 < ids.length ? ids[i + 1] : null;
  }
  return ids[0];
};
// an `if <cond> { body... }` guard; body is a list of statement ids
const guard = (condBlock, bodyIds) => {
  const first = stack(bodyIds);
  return mk("control_if", { inputs: { CONDITION: cond(condBlock), SUBSTACK: [2, first] } });
};
// an `if <cond> { then } else { else }`
const ifElse = (condBlock, thenIds, elseIds) => {
  const t = stack(thenIds), e = stack(elseIds);
  return mk("control_if_else", { inputs: { CONDITION: cond(condBlock), SUBSTACK: [2, t], SUBSTACK2: [2, e] } });
};
// a `repeat until <cond> { body }` loop
const repeatUntil = (condBlock, bodyIds) => {
  const first = stack(bodyIds);
  return mk("control_repeat_until", { inputs: { CONDITION: cond(condBlock), SUBSTACK: [2, first] } });
};

// ---- custom blocks (procedures) — each handler becomes its OWN labeled `define` stack, so the
// canvas reads as a short dispatch spine + one legible procedure per handler, not one 400-block
// tower. No-argument procedures (handlers read the shared working vars); `warp` = run atomically.
// `stop this script` inside a procedure stops the PROCEDURE (early-return within the handler); the
// caller then `stop`s the main script, so a matched handler always terminates dispatch. ----
const PROC_MUT = (proccode, extra = {}) => ({ tagName: "mutation", children: [], proccode, argumentids: "[]", warp: "true", ...extra });
// define a no-arg procedure with body `bodyIds`, placed at (x,y); returns its proccode.
const procDef = (proccode, bodyIds, x, y) => {
  const protoId = "b" + ++seq;
  const defId = "b" + ++seq;
  B[protoId] = {
    opcode: "procedures_prototype", next: null, parent: defId, inputs: {}, fields: {}, shadow: true, topLevel: false,
    mutation: PROC_MUT(proccode, { argumentnames: "[]", argumentdefaults: "[]" }),
  };
  const first = bodyIds.length ? stack(bodyIds) : null;
  B[defId] = {
    opcode: "procedures_definition", next: first, parent: null, inputs: { custom_block: [1, protoId] },
    fields: {}, shadow: false, topLevel: true, x, y,
  };
  if (first) B[first].parent = defId;
  return proccode;
};
// call a no-arg procedure by proccode
const procCall = (proccode) => mk("procedures_call", { mutation: PROC_MUT(proccode) });
// route to a handler procedure and terminate the main dispatch script on match.
const route = (patternValue, proccode) => guard(eqStr(V.pattern, patternValue), [procCall(proccode), stopScript()]);

// ============================ variables ============================
const V = {
  // dashboard (Stage-global → shown as monitors)
  pid: { id: "VID_PID", name: "peer id" },
  lastPath: { id: "VID_PATH", name: "last dispatched path" },
  lastStat: { id: "VID_STAT", name: "last status" },
  count: { id: "VID_CNT", name: "dispatch count" },
  // working (sprite-local)
  conn: { id: "VW_CONN", name: "conn" },
  exec: { id: "VW_EXEC", name: "exec" },
  path: { id: "VW_PATH", name: "path" },
  pattern: { id: "VW_PAT", name: "pattern" },
  rpath: { id: "VW_RPATH", name: "resolve path" }, // §6.6 walk cursor (longest-prefix down to root)
  // tree-handler working vars
  op: { id: "VT_OP", name: "op" },
  target: { id: "VT_TGT", name: "target" },
  tpath: { id: "VT_PATH", name: "tree path" },
  writeResult: { id: "VT_WR", name: "write result" },
  hpattern: { id: "VH_PAT", name: "handler pattern" },
};
const stageVars = {};
for (const k of ["pid", "lastPath", "lastStat", "count"]) stageVars[V[k].id] = [V[k].name, ""];
const spriteVars = {};
for (const k of ["conn", "exec", "path", "pattern", "rpath", "op", "target", "tpath", "writeResult", "hpattern"]) spriteVars[V[k].id] = [V[k].name, ""];

// ============================ THE DISPATCH SCRIPT (§6.5, as blocks) ============================
// error terminal: [ send(error response ... ), stop this script ]
const errTerminal = (status, code, message) => {
  const errResp = ext("errorResponse", { H: vvar(V.exec), S: num(status), C: txt(code), M: txt(message) });
  return [setVar(V.lastStat, num(status)), send(errResp, V.conn), stopScript()];
};
// ok terminal: [ set last status = 200, send(ok response … result …), stop this script ]
const okSend = (resultBlock) => [
  setVar(V.lastStat, rep(ext("statusOk", {}))),
  send(ext("okResponse", { H: vvar(V.exec), RESULT: rep(resultBlock) }), V.conn),
  stopScript(),
];

// preamble: read the inbound EXECUTE + its dispatch path
const preamble = [
  setVar(V.conn, rep(ext("inboundConn", {}))),
  setVar(V.exec, rep(ext("inboundExec", {}))),
  setVar(V.path, rep(ext("dispatchPathOf", { H: vvar(V.exec) }))),
  setVar(V.lastPath, vvar(V.path)),
];

// guard ladder (top → bottom, mirrors Dispatcher#dispatchCore)
// connect pre-authorization (§4.2) — the SOLE no-auth special case, fired when the path is the
// connect path AND the connection is not yet established (== Dispatcher's gate). The hello /
// authenticate handshake is AUTHORED IN SCRATCH: the operation switch + each leg's negotiation /
// PoP guard ladder with its pinned status code. The per-conn state, nonce/PoP crypto, key
// derivation, and seed-cap minting are `ecutils` seam blocks.
const connectHelloBody = [
  guard(notB(ext("isHelloParams", { H: vvar(V.exec) })), errTerminal(400, "connection_sequence_error", "expected a hello entity")),
  // §4.7 / v7.66: reject an unnegotiable peer_id key family at the earliest boundary.
  guard(notB(ext("helloKeyTypeSupported", { H: vvar(V.exec) })), errTerminal(400, "unsupported_key_type", "unsupported peer_id key_type; this peer signs/verifies Ed25519 (0x01) and Ed448 (0x02) only")),
  // §4.5 negotiation: protocol / hash_format / key_type intersections must be non-empty.
  guard(notB(ext("protocolCompatible", { H: vvar(V.exec) })), errTerminal(400, "incompatible_protocol", "no common protocol version")),
  guard(notB(ext("hashFormatCompatible", { H: vvar(V.exec) })), errTerminal(400, "incompatible_hash_format", "no common content_hash_format")),
  guard(notB(ext("keyTypesCompatible", { H: vvar(V.exec) })), errTerminal(400, "unsupported_key_type", "key_types accept-set excludes responder key_type")),
  ...okSend(ext("helloResponse", { H: vvar(V.exec), CONN: vvar(V.conn) })),
];
const connectAuthenticateBody = [
  // §4.6 sequence: already-established (409, defensive — the pre-auth gate excludes it) → hello-first.
  guard(ext("established", { CONN: vvar(V.conn) }), errTerminal(409, "connection_already_established", "connection already established")),
  guard(notB(ext("helloReceivedOn", { CONN: vvar(V.conn) })), errTerminal(400, "connection_sequence_error", "authenticate before hello")),
  guard(notB(ext("isAuthenticateParams", { H: vvar(V.exec) })), errTerminal(400, "connection_sequence_error", "expected an authenticate entity")),
  // §4.6 PoP: echo the challenge nonce (401) → key family (400) → id-vs-key (401) → signature (401).
  guard(notB(ext("authNonceEchoes", { H: vvar(V.exec), CONN: vvar(V.conn) })), errTerminal(401, "invalid_nonce", "authenticate nonce does not echo the challenge")),
  guard(notB(ext("authKeyTypeSupported", { H: vvar(V.exec) })), errTerminal(400, "unsupported_key_type", "unsupported key_type")),
  guard(notB(ext("authIdentityMatches", { H: vvar(V.exec) })), errTerminal(401, "identity_mismatch", "public key does not match peer_id")),
  guard(notB(ext("authSignatureValid", { H: vvar(V.exec) })), errTerminal(401, "invalid_signature", "authenticate signature invalid")),
  // §4.4 / §6.9a: mint the initial capability + mark established; the 200 grant carries its included set.
  setVar(V.lastStat, rep(ext("statusOk", {}))),
  send(ext("authenticateResponse", { H: vvar(V.exec), CONN: vvar(V.conn) }), V.conn),
  stopScript(),
];
// `dispatch connect` — its own labeled procedure; the pre-auth guard in the spine calls it.
const p_connect = procDef("dispatch connect", [
  setVar(V.op, rep(ext("operationOf", { H: vvar(V.exec) }))),
  guard(eqStr(V.op, "hello"), connectHelloBody),
  guard(eqStr(V.op, "authenticate"), connectAuthenticateBody),
  ...errTerminal(400, "connection_sequence_error", "unknown connect operation"),
], 520, 40);
const g_connect = guard(
  andB(ext("isConnectPath", { PATH: vvar(V.path) }), notB(ext("established", { CONN: vvar(V.conn) }))),
  [procCall(p_connect), stopScript()],
);
const g_author = guard(notB(ext("hasAuthor", { H: vvar(V.exec) })), errTerminal(401, "missing_author", "author required"));
const g_cap = guard(notB(ext("hasCapability", { H: vvar(V.exec) })), errTerminal(403, "missing_authorization", "capability required"));
// §5.2 verify_request, authored as the exact spec sequence (each guard → its pinned code):
const g_sig = guard(notB(ext("signatureValid", { H: vvar(V.exec) })), errTerminal(401, "invalid_signature", "EXECUTE signature does not verify"));
const g_capres = guard(notB(ext("capabilityResolves", { H: vvar(V.exec) })), errTerminal(403, "capability_denied", "capability not in included"));
const g_grantee = guard(notB(ext("granteeResolves", { H: vvar(V.exec) })), errTerminal(401, "unresolvable_grantee", "leaf cap grantee does not resolve to a system/peer entity")); // §3.6 PR-3 single-401 carve-out
const g_grIsAuthor = guard(notB(ext("granteeIsAuthor", { H: vvar(V.exec) })), errTerminal(403, "capability_denied", "capability grantee is not the author"));
const g_depth = guard(notB(ext("chainWithinDepth", { H: vvar(V.exec) })), errTerminal(400, "chain_depth_exceeded", "capability chain exceeds max depth (§4.10b)"));
const g_chain = guard(notB(ext("chainVerifies", { H: vvar(V.exec) })), errTerminal(403, "capability_denied", "capability chain verification failed"));
const g_revoked = guard(ext("capabilityRevoked", { H: vvar(V.exec) }), errTerminal(403, "capability_revoked", "capability is revoked (§5.1)"));
// §6.6 handler resolution — AUTHORED AS THE TREE WALK, not a hardcoded pattern list. Start at the
// full dispatch path and walk backward one segment at a time (longest prefix first); the handler is
// whichever registered `system/handler` prefix matches first (== HandlerRegistry#resolve). `pattern`
// is the *product of the walk*, not a constant. The store lookup + path slice are the only seam bits.
const p_resolve = procDef("resolve handler §6.6", [
  setVar(V.pattern, txt("")),
  setVar(V.rpath, vvar(V.path)),
  repeatUntil(orB(notB(eqEmpty(V.pattern)), eqEmpty(V.rpath)), [
    ifElse(ext("handlerRegisteredAt", { P: vvar(V.rpath) }),
      [setVar(V.pattern, rep(ext("patternAt", { P: vvar(V.rpath) })))],           // matched → the pattern is this prefix
      [setVar(V.rpath, rep(ext("parentPrefix", { P: vvar(V.rpath) })))]),          // else → drop a segment, keep walking
  ]),
], 1000, 620);
const s_resolve = procCall(p_resolve);
const g_404 = guard(eqEmpty(V.pattern), errTerminal(404, "not_found", "no handler resolves the path"));
const g_perm = guard(
  notB(ext("capabilityPermits", { PATTERN: vvar(V.pattern), H: vvar(V.exec) })),
  errTerminal(403, "capability_denied", "capability does not grant the operation"),
);
// echo handler (§7a system/validate/echo) — AUTHORED IN SCRATCH: the response result IS the
// request params. The canonical example that the handler bodies CAN live on the canvas too.
const p_echo = procDef("dispatch echo", [
  changeVar(V.count, 1),
  setVar(V.lastStat, rep(ext("statusOk", {}))),
  send(ext("okResponse", { H: vvar(V.exec), RESULT: rep(ext("paramsOf", { H: vvar(V.exec) })) }), V.conn),
  stopScript(),
], 520, 320);
// tree handler (§6.3 system/tree) — AUTHORED IN SCRATCH: operation switch + get/put branching +
// the 400/403/404/409/501 decisions. The store/path/CAS mechanics are `ecutils` seam blocks.
const treeGetBody = [
  guard(notB(ext("hasSingleTarget", { H: vvar(V.exec) })), errTerminal(400, "invalid_request", "tree operation requires exactly one resource target")),
  setVar(V.target, rep(ext("singleTarget", { H: vvar(V.exec) }))),
  guard(notB(ext("validTarget", { T: vvar(V.target) })), errTerminal(400, "invalid_path", "invalid target path")),
  guard(ext("isListing", { T: vvar(V.target) }), okSend(ext("treeListingResult", { T: vvar(V.target), PAT: vvar(V.pattern), H: vvar(V.exec) }))),
  setVar(V.tpath, rep(ext("canonicalize", { T: vvar(V.target) }))),
  guard(notB(ext("pathPermits", { OP: txt("get"), PATH: vvar(V.tpath), PAT: vvar(V.pattern), H: vvar(V.exec) })), errTerminal(403, "capability_denied", "capability does not cover path")),
  guard(notB(ext("treeHas", { PATH: vvar(V.tpath) })), errTerminal(404, "not_found", "no entity bound at path")),
  guard(eqRepStr(ext("modeOf", { H: vvar(V.exec) }), "hash"), okSend(ext("treeHashResult", { PATH: vvar(V.tpath) }))),
  ...okSend(ext("treeEntityResult", { PATH: vvar(V.tpath) })),
];
const treePutBody = [
  guard(notB(ext("hasSingleTarget", { H: vvar(V.exec) })), errTerminal(400, "invalid_request", "tree operation requires exactly one resource target")),
  setVar(V.target, rep(ext("singleTarget", { H: vvar(V.exec) }))),
  guard(notB(ext("validTarget", { T: vvar(V.target) })), errTerminal(400, "invalid_path", "invalid target path")),
  setVar(V.tpath, rep(ext("canonicalize", { T: vvar(V.target) }))),
  guard(notB(ext("pathPermits", { OP: txt("put"), PATH: vvar(V.tpath), PAT: vvar(V.pattern), H: vvar(V.exec) })), errTerminal(403, "capability_denied", "capability does not cover path")),
  setVar(V.writeResult, rep(ext("treeWrite", { PATH: vvar(V.tpath), H: vvar(V.exec) }))),
  guard(eqStr(V.writeResult, "conflict"), errTerminal(409, "hash_mismatch", "conditional write failed")),
  ...okSend(ext("emptyAck", {})),
];
const p_tree = procDef("dispatch tree", [
  setVar(V.op, rep(ext("operationOf", { H: vvar(V.exec) }))),
  guard(eqStr(V.op, "get"), treeGetBody),
  guard(eqStr(V.op, "put"), treePutBody),
  ...errTerminal(501, "operation_not_supported", "tree handler has no such operation"),
], 1000, 40);

// handlers handler (§6.2 system/handler) — AUTHORED IN SCRATCH: operation switch + resource
// validation + status codes. The five normative register writes / their reversal are seam blocks.
// factory (fresh blocks per call — reusing block ids across two branches would corrupt the tree)
const handlerResourceGuards = () => [
  guard(notB(ext("hasSingleTarget", { H: vvar(V.exec) })), errTerminal(400, "ambiguous_resource", "register/unregister require exactly one resource target (system/handler/{pattern})")),
  guard(notB(ext("handlerResourceValid", { H: vvar(V.exec) })), errTerminal(400, "invalid_resource", "resource target MUST be system/handler/{pattern}")),
  setVar(V.hpattern, rep(ext("handlerPatternOf", { H: vvar(V.exec) }))),
];
const p_handlers = procDef("dispatch handlers", [
  setVar(V.op, rep(ext("operationOf", { H: vvar(V.exec) }))),
  guard(eqStr(V.op, "register"), [
    ...handlerResourceGuards(),
    guard(notB(ext("isRegisterRequest", { H: vvar(V.exec) })), errTerminal(400, "invalid_params", "register expects a handler register-request")),
    ...okSend(ext("registerHandler", { PATTERN: vvar(V.hpattern), H: vvar(V.exec) })),
  ]),
  guard(eqStr(V.op, "unregister"), [
    ...handlerResourceGuards(),
    ...okSend(ext("unregisterHandler", { PATTERN: vvar(V.hpattern) })),
  ]),
  ...errTerminal(501, "unsupported_operation", "unknown handlers-handler operation"),
], 1500, 40);

// capability handler (§6.2 system/capability) — AUTHORED IN SCRATCH: operation switch
// (request / configure / revoke / delegate) + the per-op guard ladders and their pinned
// status codes. Token minting/signing, scope-attenuation math, and the policy/revocation
// store writes are `ecutils` seam blocks (the crypto/CBOR "tricky bits").
const capRequestBody = [
  // author is guaranteed present by the §6.5 g_author guard; the handler's own 403 stays
  // authored for faithfulness to CapabilityHandler#request (its self-contained contract).
  guard(notB(ext("hasAuthor", { H: vvar(V.exec) })), errTerminal(403, "missing_authorization", "capability request requires an author")),
  guard(notB(ext("authorInIncluded", { H: vvar(V.exec) })), errTerminal(400, "unresolvable_grantee", "author identity not in included")),
  guard(notB(ext("requestScopeWithinAuthority", { H: vvar(V.exec) })), errTerminal(403, "scope_exceeds_authority", "requested grant exceeds the caller's presented authority (§6.2 / §5.6)")),
  setVar(V.lastStat, rep(ext("statusOk", {}))),
  send(ext("capabilityRequestResponse", { H: vvar(V.exec) }), V.conn),
  stopScript(),
];
const capConfigureBody = [
  guard(notB(ext("isPolicyEntryParams", { H: vvar(V.exec) })), errTerminal(400, "invalid_params", "configure expects a system/capability/policy-entry")),
  guard(notB(ext("validPolicyPattern", { H: vvar(V.exec) })), errTerminal(400, "invalid_params", 'peer_pattern MUST be "default", a 66/98-char hex content hash, or a Base58 peer_id (v7.62 §4)')),
  guard(notB(ext("policyHasGrants", { H: vvar(V.exec) })), errTerminal(400, "invalid_params", "policy-entry MUST specify at least one grant (v7.62 §4)")),
  ...okSend(ext("configurePolicy", { H: vvar(V.exec) })),
];
const capRevokeBody = [
  guard(notB(ext("revokeTokenValid", { H: vvar(V.exec) })), errTerminal(400, "invalid_params", "revoke-request.token must be non-zero (v7.62 §10)")),
  ...okSend(ext("writeRevocation", { H: vvar(V.exec) })),
];
const p_capability = procDef("dispatch capability", [
  setVar(V.op, rep(ext("operationOf", { H: vvar(V.exec) }))),
  guard(eqStr(V.op, "request"), capRequestBody),
  guard(eqStr(V.op, "configure"), capConfigureBody),
  guard(eqStr(V.op, "revoke"), capRevokeBody),
  // §6.2 closeout F1: delegate is same-peer-only in v1 → a remote caller receives 501.
  guard(eqStr(V.op, "delegate"), errTerminal(501, "unsupported_operation", "delegate is same-peer-only in v1 (closeout F1); input shape under-specified (F13)")),
  ...errTerminal(501, "unsupported_operation", "unknown capability operation"),
], 1500, 400);

// Body-selection (NOT resolution): the walk above already found the handler (`pattern`). This just
// runs the authored body for it — a match against the patterns we hand-authored, because Scratch
// can't call a procedure by a dynamic name. Any handler the walk resolves that ISN'T hand-authored
// (e.g. a dynamically-registered entity-native handler) falls through to the delegated catch-all.
const s_count = changeVar(V.count, 1);
const s_ok = setVar(V.lastStat, rep(ext("statusOk", {})));
const s_run = send(ext("runHandlerBody", { PATTERN: vvar(V.pattern), H: vvar(V.exec), CONN: vvar(V.conn) }), V.conn);

// THE DISPATCH SPINE (`when execute arrives`) — a short, readable top-to-bottom sequence: the §6.5
// pre-auth + §5.2 verify ladder → the §6.6 `resolve handler` tree WALK → 404/permission → run the
// resolved handler's authored `define dispatch <handler>` body (or the catch-all if not authored).
const hat = mk("ecutils_whenExecute", { top: true, x: 40, y: 40 });
const body = stack([...preamble, g_connect, g_author, g_cap,
  g_sig, g_capres, g_grantee, g_grIsAuthor, g_depth, g_chain, g_revoked, // §5.2 verify sequence
  s_resolve, g_404, g_perm,                                             // §6.6 walk → 404 → permission
  route("system/validate/echo", p_echo), route("system/tree", p_tree),
  route("system/handler", p_handlers), route("system/capability", p_capability),
  s_count, s_ok, s_run]);
B[hat].next = body;
B[body].parent = hat;

// ============================ dashboard script (green flag → connect → mirror peer id) ============================
const flag = mk("event_whenflagclicked", { top: true, x: 40, y: 380 });
const connectCmd = ext("connect", { URL: txt("ws://localhost:7802") });
const setPid = setVar(V.pid, rep(ext("peerId", {})));
const forever = mk("control_forever", { inputs: { SUBSTACK: [2, setPid] } });
B[setPid].parent = forever;
stack([connectCmd, forever]);
B[flag].next = connectCmd; B[connectCmd].parent = flag;

// ============================ structural validation ============================
(function validate() {
  const ids = new Set(Object.keys(B));
  const bad = [];
  for (const [id, b] of Object.entries(B)) {
    if (b.next && !ids.has(b.next)) bad.push(`${id}.next → missing ${b.next}`);
    if (b.parent && !ids.has(b.parent)) bad.push(`${id}.parent → missing ${b.parent}`);
    for (const [k, v] of Object.entries(b.inputs)) {
      const refs = [];
      if (v[0] === 2 && typeof v[1] === "string") refs.push(v[1]);
      if (v[0] === 3 && typeof v[1] === "string") refs.push(v[1]);
      for (const r of refs) if (!ids.has(r)) bad.push(`${id}.inputs.${k} → missing ${r}`);
    }
  }
  if (bad.length) { console.error("SB3 VALIDATION FAILED:\n  " + bad.join("\n  ")); process.exit(1); }
})();

// ============================ assets + targets ============================
const backdrop = Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="360">' +
  '<rect width="480" height="360" fill="#0b1e24"/>' +
  '<text x="24" y="44" fill="#7fd4c1" font-family="sans-serif" font-size="22">entity-core peer — dispatch authored in Scratch</text>' +
  "</svg>",
);
const aBack = md5(backdrop);
const dot = (fill) => Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><circle cx="40" cy="40" r="30" fill="' + fill + '"/></svg>');
const c0 = dot("#5bb8a3"), c1 = dot("#eaeaea");
const a0 = md5(c0), a1 = md5(c1);

const stage = {
  isStage: true, name: "Stage", variables: stageVars, lists: {}, broadcasts: {}, blocks: {}, comments: {},
  currentCostume: 0,
  costumes: [{ assetId: aBack, name: "backdrop1", md5ext: aBack + ".svg", dataFormat: "svg", rotationCenterX: 240, rotationCenterY: 180 }],
  sounds: [], volume: 100, layerOrder: 0, tempo: 60, videoTransparency: 50, videoState: "on", textToSpeechLanguage: null,
};
const sprite = {
  isStage: false, name: "peer", variables: spriteVars, lists: {}, broadcasts: {}, blocks: B, comments: {},
  currentCostume: 0,
  costumes: [
    { assetId: a0, name: "on", md5ext: a0 + ".svg", dataFormat: "svg", rotationCenterX: 40, rotationCenterY: 40 },
    { assetId: a1, name: "off", md5ext: a1 + ".svg", dataFormat: "svg", rotationCenterX: 40, rotationCenterY: 40 },
  ],
  sounds: [], volume: 100, layerOrder: 1, visible: true, x: 180, y: -110, size: 100, direction: 90, draggable: false, rotationStyle: "all around",
};
const monitors = ["pid", "lastPath", "lastStat", "count"].map((k, i) => ({
  id: V[k].id, mode: "default", opcode: "data_variable", params: { VARIABLE: V[k].name }, spriteName: null,
  value: "", width: 0, height: 0, x: 5, y: 5 + i * 30, visible: true, sliderMin: 0, sliderMax: 100, isDiscrete: true,
}));

const project = {
  targets: [stage, sprite], monitors, extensions: ["ecutils"],
  meta: { semver: "3.0.0", vm: "0.2.0", agent: "entity-core-keystone build-sb3 (dispatch-in-scratch)" },
};

// ============================ store-only .sb3 (zip) ============================
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (buf) => { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function zip(entries) {
  const chunks = [], central = []; let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name), crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nameBuf.length, 26);
    chunks.push(lh, nameBuf, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf); offset += lh.length + nameBuf.length + data.length;
  }
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, centralBuf, eocd]);
}

const projectJson = Buffer.from(JSON.stringify(project));
const sb3 = zip([
  { name: "project.json", data: projectJson },
  { name: aBack + ".svg", data: backdrop },
  { name: a0 + ".svg", data: c0 },
  { name: a1 + ".svg", data: c1 },
]);
writeFileSync(join(__dirname, "entity-core-peer.sb3"), sb3);
writeFileSync(join(OUT, "project.json"), projectJson);
console.log("wrote project/entity-core-peer.sb3 (" + sb3.length + " bytes), " + Object.keys(B).length + " blocks, extensions=[ecutils]");
