import { test } from "node:test";
import assert from "node:assert/strict";
import { loadCorpusBytes } from "./corpus.js";
import { runConformance } from "./conformance-runner.js";

/**
 * The S2 gate (node:test form). The standalone `run-conformance.ts` prints the
 * category table; this asserts byte-identity to the cross-blessed corpus inside
 * the `node --test` run.
 */
test("ECF conformance corpus — every vector byte-identical to the cross-blessed fixture", () => {
  const report = runConformance(loadCorpusBytes());
  const failures = report.results.filter((r) => !r.pass).map((r) => `${r.id} [${r.kind}]: ${r.message}`);
  assert.deepEqual(failures, [], `\nfailing vectors:\n${failures.join("\n")}\n`);
  assert.ok(report.results.length >= 69, `expected ≥69 vectors, ran ${report.results.length}`);
});
