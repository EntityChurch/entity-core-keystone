import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Locates the vendored conformance fixture relative to the build output (the
 * keystone repo layout). Twin of the C# `Corpus.Locate`. `ECF_VECTORS` overrides.
 */
const RELATIVE_PATH = "protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor";

export function locateCorpus(): string {
  const fromEnv = process.env["ECF_VECTORS"];
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  // Walk up to the repo root looking for the vendored fixture.
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, RELATIVE_PATH);
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  throw new Error(`could not locate ${RELATIVE_PATH} above ${fileURLToPath(import.meta.url)}; set ECF_VECTORS`);
}

export function loadCorpusBytes(): Uint8Array {
  return new Uint8Array(readFileSync(locateCorpus()));
}
