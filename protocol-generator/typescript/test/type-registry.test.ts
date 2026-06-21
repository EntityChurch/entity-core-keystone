/**
 * A-006 — type-registry byte-diff (the top S4 precursor).
 *
 * The peer renders its 53 core `system/type/<name>` entities natively
 * (CoreTypeRegistry, single source of truth in code) and this test diffs each
 * one's `content_hash` against the Go-rendered vector set
 * (`type-registry-vectors-v1.cbor`, the S8 drift target). The C# reference peer
 * proved its 53 byte-identical; TS must too before the `type_system` validate-peer
 * category can be trusted. A byte-identical content_hash is a hard equality — it
 * means the TS render of the type's ECF data is byte-for-byte the Go render.
 *
 * The vector `content_hash` is `ecf-sha256:<64 hex>` (the 32-byte digest only);
 * the peer's `contentHashHex` is `00<64 hex>` (the §1.2 one-byte format code `0x00`
 * followed by the digest). We compare the digest halves.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { decode } from "../src/codec/canonical-cbor.js";
import { ALL_CORE_TYPES } from "../src/types/index.js";

const VECTOR_RELATIVE = "protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor";

function locateVectors(): string {
  const fromEnv = process.env["TYPE_REGISTRY_VECTORS"];
  if (fromEnv) {
    return fromEnv;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, VECTOR_RELATIVE);
    if (existsSync(candidate)) {
      return candidate;
    }
    dir = dirname(dir);
  }
  throw new Error(`could not locate ${VECTOR_RELATIVE}; set TYPE_REGISTRY_VECTORS`);
}

/** name -> digest hex (the 64-char half after the `ecf-sha256:` prefix). */
function loadVectorHashes(): Map<string, string> {
  const bytes = new Uint8Array(readFileSync(locateVectors()));
  const value = decode(bytes);
  assert.equal(value.kind, "array", "vector file root must be an array");
  const map = new Map<string, string>();
  if (value.kind !== "array") return map;
  for (const item of value.items) {
    assert.equal(item.kind, "map");
    if (item.kind !== "map") continue;
    let name: string | undefined;
    let hash: string | undefined;
    for (const [k, v] of item.pairs) {
      if (k.kind !== "text") continue;
      if (k.value === "name" && v.kind === "text") name = v.value;
      if (k.value === "content_hash" && v.kind === "text") hash = v.value;
    }
    if (name !== undefined && hash !== undefined) {
      const prefix = "ecf-sha256:";
      assert.ok(hash.startsWith(prefix), `unexpected content_hash form: ${hash}`);
      map.set(name, hash.slice(prefix.length));
    }
  }
  return map;
}

test("A-006: every core type content_hash is byte-identical to the Go vector set", () => {
  const vectors = loadVectorHashes();
  assert.ok(vectors.size >= ALL_CORE_TYPES.length, `vector set has ${vectors.size} types`);

  const mismatches: string[] = [];
  const missing: string[] = [];
  let matched = 0;

  for (const def of ALL_CORE_TYPES) {
    const expected = vectors.get(def.name);
    if (expected === undefined) {
      missing.push(def.name);
      continue;
    }
    const full = def.toEntity().contentHashHex; // "00" + 64 hex digest
    assert.ok(full.startsWith("00"), `${def.name}: expected 0x00 format code, got ${full.slice(0, 2)}`);
    const digest = full.slice(2);
    if (digest !== expected) {
      mismatches.push(`${def.name}\n    want ${expected}\n    got  ${digest}`);
    } else {
      matched++;
    }
  }

  const report = [
    `core types rendered: ${ALL_CORE_TYPES.length}`,
    `byte-identical:      ${matched}`,
    missing.length ? `MISSING from vectors: ${missing.join(", ")}` : "",
    mismatches.length ? `MISMATCH:\n  ${mismatches.join("\n  ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  assert.equal(missing.length, 0, `core types absent from the vector set:\n${report}`);
  assert.equal(mismatches.length, 0, `content_hash mismatches:\n${report}`);
  assert.equal(matched, ALL_CORE_TYPES.length, report);
});
