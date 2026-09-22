import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Ecf,
  Entity,
  type ExecuteResponse,
  type GrantEntry,
  Peer,
  PeerIdentity,
  PeerSession,
  ResourceTarget,
  SeedPolicy,
  SeedPolicyError,
  Status,
  TypeNames,
  hashHex,
  withSeedPolicyFromFile,
} from "../src/index.js";

/**
 * §6.9a seed policy as a DECLARED VALUE — the keystone file format
 * (`protocol-generator/shared/seed-policy/`), `SeedPolicy.fromJson`,
 * `withSeedPolicyFromFile`, and the host's `--seed-policy PATH` flag.
 *
 * The refusal set mirrors the rust peer's reader so the cohort's hosts refuse the same
 * files. The enforcement tests are the half a parser test cannot supply: a narrow named
 * grant must be ENFORCED for the identity it names and NOT for another identity, over a
 * real loopback, because a policy that parses and is never consulted passes every
 * parse assertion.
 */

const TIMEOUT = 10_000;
const HERE = dirname(fileURLToPath(import.meta.url));

function locateExamples(): string {
  let dir = HERE;
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, "protocol-generator/shared/seed-policy/examples");
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  throw new Error(`could not locate protocol-generator/shared/seed-policy/examples above ${HERE}`);
}

const EXAMPLES = locateExamples();

function ecfOf(grants: readonly GrantEntry[]): string {
  // Structural comparison via the canonical ECF bytes — the form the policy entry is bound in.
  return Buffer.from(Ecf.encodeEcf(Ecf.array(grants.map((g) => g.toEcf())))).toString("hex");
}

// ----- the shipped examples ---------------------------------------------------------

test("seed-policy: default-floor.json parses to exactly the §4.4 discovery floor", () => {
  const { seedPolicy } = withSeedPolicyFromFile(join(EXAMPLES, "default-floor.json"));
  assert.equal(seedPolicy.defaultGrants.length, 2);
  assert.equal(ecfOf(seedPolicy.defaultGrants), ecfOf(SeedPolicy.discoveryFloor()));
  assert.equal(seedPolicy.namedEntries.length, 0);
});

test("seed-policy: debug-open.json parses (one wide-open default grant, `_comment` skipped)", () => {
  const { seedPolicy } = withSeedPolicyFromFile(join(EXAMPLES, "debug-open.json"));
  assert.equal(seedPolicy.defaultGrants.length, 1);
  assert.deepEqual(seedPolicy.defaultGrants[0]!.resources.include, ["*", "/*/*"]);
  assert.equal(seedPolicy.namedEntries.length, 0);
});

test("seed-policy: operator-admin.json parses to one named entry + the floor default", () => {
  const { seedPolicy } = withSeedPolicyFromFile(join(EXAMPLES, "operator-admin.json"));
  assert.equal(seedPolicy.namedEntries.length, 1);
  assert.equal(seedPolicy.namedEntries[0]!.key, "0000000000000000000000000000000000000000000000000000000000000000ab");
  assert.deepEqual(seedPolicy.namedEntries[0]!.grants[0]!.peers?.include, ["self"]);
  assert.equal(ecfOf(seedPolicy.defaultGrants), ecfOf(SeedPolicy.discoveryFloor()));
});

test("seed-policy: a file with no default entry gets the discovery floor as default", () => {
  const p = SeedPolicy.fromJson('{"version":1,"entries":[]}');
  assert.equal(ecfOf(p.defaultGrants), ecfOf(SeedPolicy.discoveryFloor()));
});

test("seed-policy: an exclude survives, and constraints/allowances carry integers verbatim", () => {
  // Raw text, not JSON.stringify: 2^64-1 is not representable as a JS number, which is
  // exactly why the reader refuses to go through one.
  const p = SeedPolicy.fromJson(
    '{"version":1,"entries":[{"grantee":"default","grants":[{"handlers":{"include":["app/x"]},' +
      '"resources":{"include":["app/x/*"],"exclude":["app/x/secret"]},"operations":{"include":["get"]},' +
      '"constraints":{"max":18446744073709551615,"min":-5,"tag":"t","nested":{"ok":true,"none":null}}}]}]}',
  );
  const g = p.defaultGrants[0]!;
  assert.deepEqual(g.resources.exclude, ["app/x/secret"]);
  assert.notEqual(g.constraints, null);
  assert.equal(Ecf.requireUint(g.constraints!, "max"), (1n << 64n) - 1n);
});

test("seed-policy: an empty exclude list is preserved as present", () => {
  const p = SeedPolicy.fromJson(
    '{"version":1,"entries":[{"grantee":"default","grants":[{"handlers":{"include":["a"]},"resources":{"include":["b"],"exclude":[]},"operations":{"include":["get"]}}]}]}',
  );
  assert.deepEqual(p.defaultGrants[0]!.resources.exclude, []);
});

test("seed-policy: an empty grants list is legal (CAP-2 withdrawal form)", () => {
  const p = SeedPolicy.fromJson('{"version":1,"entries":[{"grantee":"default","grants":[]}]}');
  assert.equal(p.defaultGrants.length, 0);
});

test("seed-policy: a Base58 peer id and a 98-char identity hex are accepted as named grantees", () => {
  const peerId = PeerIdentity.fromSeed(new Uint8Array(32).fill(0x42)).peerId;
  const hex98 = "01" + "ab".repeat(48);
  const p = SeedPolicy.fromJson(
    JSON.stringify({ version: 1, entries: [{ grantee: peerId, grants: [] }, { grantee: hex98, grants: [] }] }),
  );
  assert.deepEqual(
    p.namedEntries.map((e) => e.key),
    [peerId, hex98],
  );
});

// ----- refusals ---------------------------------------------------------------------

const G = '"grants":[]';
const wrap = (entry: string): string => `{"version":1,"entries":[${entry}]}`;
const SCOPE = '{"include":["x"]}';
const grantWith = (extra: string): string =>
  wrap(`{"grantee":"default","grants":[{"handlers":${SCOPE},"resources":${SCOPE},"operations":${SCOPE}${extra}}]}`);

const REFUSALS: readonly (readonly [string, string])[] = [
  ["version 2", '{"version":2,"entries":[]}'],
  ["version missing", '{"entries":[]}'],
  ["version as float 1.0", '{"version":1.0,"entries":[]}'],
  ["entries missing", '{"version":1}'],
  ["entries not an array", '{"version":1,"entries":{}}'],
  ["unknown root key", '{"version":1,"entries":[],"extra":1}'],
  ["root not an object", "[]"],
  ["grantee self", wrap(`{"grantee":"self",${G}}`)],
  ["bounds", wrap(`{"grantee":"default",${G},"bounds":{"expires_at":1}}`)],
  ["bad grantee *", wrap(`{"grantee":"*",${G}}`)],
  ["hex grantee of the wrong length", wrap(`{"grantee":"${"ab".repeat(20)}",${G}}`)],
  ["empty grantee", wrap(`{"grantee":"",${G}}`)],
  ["unknown entry key", wrap(`{"grantee":"default",${G},"ttl":1}`)],
  ["second default", wrap(`{"grantee":"default",${G}},{"grantee":"default",${G}}`)],
  ["duplicate named grantee", wrap(`{"grantee":"${"ab".repeat(33)}",${G}},{"grantee":"${"ab".repeat(33)}",${G}}`)],
  ["grants not an array", wrap('{"grantee":"default","grants":{}}')],
  ["grant missing operations", wrap(`{"grantee":"default","grants":[{"handlers":${SCOPE},"resources":${SCOPE}}]}`)],
  ["unknown grant key", grantWith(',"ttl_ms":5')],
  ["unknown scope key", wrap(`{"grantee":"default","grants":[{"handlers":{"include":[],"only":[]},"resources":${SCOPE},"operations":${SCOPE}}]}`)],
  ["scope missing include", wrap(`{"grantee":"default","grants":[{"handlers":{"exclude":[]},"resources":${SCOPE},"operations":${SCOPE}}]}`)],
  ["non-string include entry", wrap(`{"grantee":"default","grants":[{"handlers":{"include":[1]},"resources":${SCOPE},"operations":${SCOPE}}]}`)],
  ["constraints not an object", grantWith(',"constraints":[]')],
  ["float inside constraints", grantWith(',"constraints":{"max":1.5}')],
  ["exponent inside allowances", grantWith(',"allowances":{"n":1e3}')],
  ["duplicate JSON key", '{"version":1,"version":1,"entries":[]}'],
  ["trailing content", '{"version":1,"entries":[]} x'],
  ["trailing comma", '{"version":1,"entries":[],}'],
  ["unpaired surrogate", wrap(`{"grantee":"default","_c":"\\ud800",${G}}`)],
  ["integer out of range", grantWith(',"constraints":{"n":18446744073709551616}')],
];

for (const [why, text] of REFUSALS) {
  test(`seed-policy: refuses ${why}`, () => {
    assert.throws(() => SeedPolicy.fromJson(text), SeedPolicyError);
  });
}

test("seed-policy: `_`-prefixed keys are comments at every level", () => {
  const p = SeedPolicy.fromJson(
    '{"_a":1,"version":1,"entries":[{"_b":[],"grantee":"default","grants":[{"_c":{},"handlers":{"_d":0,"include":["x"]},"resources":{"include":["y"]},"operations":{"include":["get"]}}]}]}',
  );
  assert.equal(p.defaultGrants.length, 1);
});

// ----- enforcement: a narrow named grant binds its identity and nobody else ----------

function treeGet(session: PeerSession, path: string): Promise<ExecuteResponse> {
  return session.execute("system/tree", "get", PeerSession.emptyParams(), new ResourceTarget([path], null), TIMEOUT);
}

async function narrowPolicyStatuses(namedKey: (a: PeerIdentity) => string): Promise<{
  aData: number;
  aSecret: number;
  bData: number;
}> {
  const a = PeerIdentity.fromSeed(new Uint8Array(32).fill(0x51));
  const b = PeerIdentity.fromSeed(new Uint8Array(32).fill(0x52));
  const policy = SeedPolicy.fromJson(
    JSON.stringify({
      version: 1,
      entries: [
        {
          grantee: namedKey(a),
          grants: [
            {
              handlers: { include: ["system/tree"] },
              resources: { include: ["app/*"], exclude: ["app/secret"] },
              operations: { include: ["get"] },
            },
          ],
        },
      ],
    }),
  );
  const responder = new Peer({ seedPolicy: policy });
  const payload = Entity.create(TypeNames.PrimitiveAny, Ecf.map(["v", Ecf.text("x")]));
  responder.tree.put("/" + responder.localPeerId + "/app/data", payload);
  responder.tree.put("/" + responder.localPeerId + "/app/secret", payload);
  const initA = new Peer({ identity: a });
  const initB = new Peer({ identity: b });
  try {
    const port = await responder.listen(0);
    const sa = await initA.connect("127.0.0.1", port, TIMEOUT);
    const sb = await initB.connect("127.0.0.1", port, TIMEOUT);
    return {
      aData: (await treeGet(sa, "app/data")).statusCode,
      aSecret: (await treeGet(sa, "app/secret")).statusCode,
      bData: (await treeGet(sb, "app/data")).statusCode,
    };
  } finally {
    await initA.dispose();
    await initB.dispose();
    await responder.dispose();
  }
}

test("seed-policy: a narrow grant named by identity hex is enforced for that identity only", async () => {
  const s = await narrowPolicyStatuses((a) => hashHex(a.identityHash));
  // ACCEPT first: it is the assertion that validates the fixture (a policy that never
  // matched would deny all three and pass every deny assertion below for free).
  assert.equal(s.aData, Status.Ok, "named identity reads inside its grant");
  assert.equal(s.aSecret, Status.Forbidden, "named identity refused on its excluded path");
  assert.equal(s.bData, Status.Forbidden, "another identity falls to the discovery floor");
});

test("seed-policy: a narrow grant named by Base58 peer id is enforced for that identity only", async () => {
  const s = await narrowPolicyStatuses((a) => a.peerId);
  assert.equal(s.aData, Status.Ok);
  assert.equal(s.aSecret, Status.Forbidden);
  assert.equal(s.bData, Status.Forbidden);
});

// ----- the host binary --------------------------------------------------------------

const HOST_JS = join(HERE, "host.js");

interface HostRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * The host's one readiness line, `LISTENING <json>` (keystone peer contract `run.ready`,
 * record `keystone-peer-ready/1`), parsed. Throws if stdout does not START with exactly that.
 */
function readiness(stdout: string): Record<string, unknown> {
  const m = /^LISTENING (\{.*\})\n/.exec(stdout);
  assert.ok(m, `no readiness line in ${JSON.stringify(stdout)}`);
  const rec = JSON.parse(m[1]!) as Record<string, unknown>;
  assert.equal(rec["record"], "keystone-peer-ready/1");
  return rec;
}

/** Run the host; resolve once it exits or once it prints LISTENING (then SIGTERM it). */
function runHost(args: readonly string[]): Promise<HostRun> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOST_JS, "--port", "0", ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), TIMEOUT);
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
      if (stdout.includes("LISTENING")) {
        child.kill("SIGTERM");
      }
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test("host: --seed-policy with an invalid file prints to stderr and exits 2 without listening", async () => {
  const dir = mkdtempSync(join(tmpdir(), "seedpol-"));
  const bad = join(dir, "bad.json");
  writeFileSync(bad, wrap(`{"grantee":"self",${G}}`));
  const r = await runHost(["--seed-policy", bad]);
  assert.equal(r.code, 2);
  assert.equal(r.stdout.includes("LISTENING"), false);
  assert.match(r.stderr, /--seed-policy: .*self/);
});

test("host: --seed-policy loads, reports its counts, and wins over --debug-open-grants", async () => {
  const r = await runHost(["--seed-policy", join(EXAMPLES, "operator-admin.json"), "--debug-open-grants"]);
  const rec = readiness(r.stdout);
  assert.match(String(rec["addr"]), /^127\.0\.0\.1:\d+$/);
  assert.equal(rec["posture"], "file", "a declared policy wins over --debug-open-grants");
  assert.equal(rec["validate"], false);
  assert.match(r.stderr, /--debug-open-grants is DEPRECATED and is IGNORED because --seed-policy was given/);
  assert.match(r.stderr, /seed-policy: \S+operator-admin\.json \(default entry: 2 grant\(s\), 1 named entr\(ies\)\)/);
});

test("host: --debug-open-grants alone still works and still warns", async () => {
  const r = await runHost(["--debug-open-grants"]);
  const rec = readiness(r.stdout);
  assert.match(String(rec["addr"]), /^127\.0\.0\.1:\d+$/);
  assert.equal(rec["posture"], "debug-open");
  assert.equal(rec["posture_digest"], "debug-open");
  assert.equal(rec["validate"], false);
  assert.match(r.stderr, /--debug-open-grants is DEPRECATED \(v7\.74/);
  assert.equal(r.stderr.includes("seed-policy:"), false);
});
