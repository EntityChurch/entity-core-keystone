// run-blocks.mjs — a HEADLESS conformance harness that runs the REAL authored Scratch
// program. It loads the actual `dist/project.json` block tree and executes it with a
// faithful interpreter over the same `ecutils` extension the TurboWarp editor loads:
// every `when execute arrives` frame walks the genuine block graph (control_if /
// control_stop / operator_* / data_* / ecutils_*). This is not a re-implementation of the
// peer — it is the block program itself, interpreted, so the oracle measures what the
// canvas actually does. (The one thing it can't cover is the TurboWarp VM's own runtime;
// a manual editor run does that.)
//
// Pipeline: bridge (TCP 7801 ↔ WS 7802) ← this harness connects out as the peer ← the Go
// validate-peer oracle dials TCP 7801.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket } from "ws";

globalThis.WebSocket = WebSocket; // the extension's connect() uses the global
const __dirname = dirname(fileURLToPath(import.meta.url));
const TW = join(__dirname, "..");

await import(join(TW, "extension/ec-utils-extension.js")); // side-effect: globalThis.EntityCoreUtils
const EntityCoreUtils = globalThis.EntityCoreUtils;

const project = JSON.parse(readFileSync(join(TW, "dist/project.json"), "utf8"));
const peerSprite = project.targets.find((t) => !t.isStage);
const blocks = peerSprite.blocks;
const hatId = Object.keys(blocks).find((id) => blocks[id].opcode === "ecutils_whenExecute");
if (!hatId) { console.error("no `when execute arrives` hat in project.json"); process.exit(1); }

// ---------------- the faithful block interpreter ----------------
const STOP = Symbol("stop-this-script");
const vars = {}; // variable id -> value

// custom-block (procedure) table: proccode -> first body block id. Each `dispatch <handler>` is a
// `procedures_definition` hat whose `custom_block` input points at a `procedures_prototype` shadow
// carrying the proccode; the definition's `.next` is the body. (No-arg procedures in this project.)
const procDefs = {};
for (const [id, b] of Object.entries(blocks)) {
  if (b.opcode !== "procedures_definition") continue;
  const proto = blocks[b.inputs.custom_block[1]];
  procDefs[proto.mutation.proccode] = b.next;
}

const primVal = (p) => {
  // p is a primitive array: [10,text] [4..8,number] [12,name,id]=variable
  if (p[0] === 12) return vars[p[2]] ?? "";
  return p[1];
};
async function resolveInput(v) {
  if (!Array.isArray(v)) return v;
  const inner = v[1];
  if (v[0] === 1) return primVal(inner);           // shadow literal
  if (typeof inner === "string") return evalBlock(inner); // block covers the slot
  return primVal(inner);                            // variable/literal in a [2]/[3] slot
}
const truthy = (x) => x === true || x === "true" || (typeof x === "number" && x !== 0);
const extArgs = async (b) => {
  const a = {};
  for (const k of Object.keys(b.inputs)) a[k] = await resolveInput(b.inputs[k]);
  return a;
};
async function evalBlock(id) {
  const b = blocks[id];
  switch (b.opcode) {
    case "operator_not": return !truthy(await resolveInput(b.inputs.OPERAND));
    case "operator_and": return truthy(await resolveInput(b.inputs.OPERAND1)) && truthy(await resolveInput(b.inputs.OPERAND2));
    case "operator_or": return truthy(await resolveInput(b.inputs.OPERAND1)) || truthy(await resolveInput(b.inputs.OPERAND2));
    case "operator_equals": {
      const x = await resolveInput(b.inputs.OPERAND1), y = await resolveInput(b.inputs.OPERAND2);
      return String(x).toLowerCase() === String(y).toLowerCase(); // Scratch equality
    }
    default:
      if (b.opcode.startsWith("ecutils_")) return await ext[b.opcode.slice("ecutils_".length)](await extArgs(b));
      throw new Error("unhandled reporter opcode " + b.opcode);
  }
}
const substackFirst = (input) => (input && input[0] === 2 ? input[1] : null);
async function runStack(firstId) {
  let id = firstId;
  while (id) {
    const b = blocks[id];
    switch (b.opcode) {
      case "data_setvariableto": vars[b.fields.VARIABLE[1]] = await resolveInput(b.inputs.VALUE); break;
      case "data_changevariableby": {
        const vid = b.fields.VARIABLE[1];
        vars[vid] = (Number(vars[vid]) || 0) + Number(await resolveInput(b.inputs.VALUE)); break;
      }
      case "control_if":
        if (truthy(await resolveInput(b.inputs.CONDITION))) await runStack(substackFirst(b.inputs.SUBSTACK));
        break;
      case "control_if_else":
        if (truthy(await resolveInput(b.inputs.CONDITION))) await runStack(substackFirst(b.inputs.SUBSTACK));
        else await runStack(substackFirst(b.inputs.SUBSTACK2));
        break;
      case "control_repeat_until": {
        // `repeat until <cond>` — run the substack while the condition is false. Bounded defensively
        // (the §6.6 walk shrinks its path each pass, so it always terminates well under the cap).
        let guardN = 0;
        while (!truthy(await resolveInput(b.inputs.CONDITION))) {
          await runStack(substackFirst(b.inputs.SUBSTACK));
          if (++guardN > 100000) throw new Error("control_repeat_until exceeded iteration cap");
        }
        break;
      }
      case "control_stop":
        if (b.fields.STOP_OPTION && b.fields.STOP_OPTION[0] === "this script") throw STOP;
        break;
      case "procedures_call": {
        // Run the called procedure's body. `stop this script` inside it stops the PROCEDURE
        // (Scratch semantics) — caught here — so the caller's own `stop` still terminates dispatch.
        try { await runStack(procDefs[b.mutation.proccode]); } catch (e) { if (e !== STOP) throw e; }
        break;
      }
      default:
        if (b.opcode.startsWith("ecutils_")) await ext[b.opcode.slice("ecutils_".length)](await extArgs(b));
        else throw new Error("unhandled statement opcode " + b.opcode);
    }
    id = b.next;
  }
}
async function runWhenExecute() {
  try { await runStack(blocks[hatId].next); } catch (e) { if (e !== STOP) throw e; }
}

// ---------------- wire the extension to the interpreter ----------------
const runtimeShim = { startHats: () => {} }; // we drive the hat ourselves via the queue
const ext = new EntityCoreUtils(runtimeShim);
// Replace the extension's tick pump with sequential interpretation of the real blocks. Yield to the
// event loop between hats (real Scratch schedules scripts cooperatively, one step per tick) so the
// socket layer can FLUSH each response and accept/close connections between requests instead of
// starving behind a serial drain — the difference that decides §6.11 connection-churn (t2_2).
ext._pump = async function () {
  if (this._busy || this.queue.length === 0) return;
  this._busy = true;
  try {
    while (this.queue.length) {
      this.inbound = this.queue.shift();
      await runWhenExecute();
      await new Promise((r) => setImmediate(r));
    }
  } finally { this._busy = false; }
};

const WS_URL = process.env.WS_URL || "ws://127.0.0.1:7802";
ext.connect({ URL: WS_URL });
process.stdout.write("BLOCKS-PEER-READY " + WS_URL + " (peer " + (ext.peerId() || "?") + ")\n");

// keep alive
setInterval(() => {}, 1 << 30);
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
