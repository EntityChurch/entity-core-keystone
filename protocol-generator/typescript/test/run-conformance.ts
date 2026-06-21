import { loadCorpusBytes } from "./corpus.js";
import { runConformance, type ConformanceReport } from "./conformance-runner.js";

/**
 * Standalone conformance harness: prints the per-category table and exits
 * non-zero on any failure (the S2 gate). Twin of the C# `Conformance` console.
 *
 *   node dist/test/run-conformance.js
 */

function byCategory(report: ConformanceReport): Array<[string, number, number]> {
  const order: string[] = [];
  const pass = new Map<string, number>();
  const total = new Map<string, number>();
  for (const r of report.results) {
    if (!total.has(r.category)) {
      order.push(r.category);
      pass.set(r.category, 0);
      total.set(r.category, 0);
    }
    total.set(r.category, total.get(r.category)! + 1);
    if (r.pass) {
      pass.set(r.category, pass.get(r.category)! + 1);
    }
  }
  return order.map((c) => [c, pass.get(c)!, total.get(c)!]);
}

const report = runConformance(loadCorpusBytes());

console.log("category        pass total");
console.log("--------------------------");
let passSum = 0;
let totalSum = 0;
for (const [category, pass, total] of byCategory(report)) {
  passSum += pass;
  totalSum += total;
  const ok = pass === total ? "ok" : "FAIL";
  console.log(`${category.padEnd(15)} ${String(pass).padStart(3)}  ${String(total).padStart(3)}  ${ok}`);
}
console.log("--------------------------");
console.log(`TOTAL           ${String(passSum).padStart(3)}  ${String(totalSum).padStart(3)}`);

if (!report.allPass) {
  console.log(`# RESULT: FAIL (${passSum}/${totalSum})`);
  for (const r of report.results) {
    if (!r.pass) {
      console.log(`  FAIL ${r.id} [${r.kind}] ${r.message ?? ""}`);
    }
  }
  process.exit(1);
}
console.log(`# RESULT: PASS (${passSum}/${totalSum})`);
