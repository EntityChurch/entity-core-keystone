// node:test TAP (stdin) → libtest-format lines (stdout), for tools/peer-contract/report.py.
//
//   ok 3 - context_unforgeable__x            → test context_unforgeable__x ... ok
//   not ok 4 - context_unforgeable__y        → test context_unforgeable__y ... FAILED
//   ok 5 - z # SKIP reason                   → test z ... ignored
//
// Every TAP result line is converted (subtests included, at any indentation), so a renamed or
// failing test is visible rather than dropped. The TAP itself is appended after the converted
// lines, each prefixed with `# `, so a reader can see what the conversion was made from
// without it matching report.py's `test … ... ok` pattern.
import { readFileSync } from "node:fs";

const tap = readFileSync(0, "utf8");
const out = [];
let results = 0;
for (const raw of tap.split(/\r?\n/)) {
  const m = /^\s*(not ok|ok) \d+ - (.*?)(?:\s+#\s+(SKIP|TODO)\b.*)?$/i.exec(raw);
  if (!m) continue;
  results++;
  // TAP escapes `#` and `\` in names.
  const name = m[2].replace(/\\#/g, "#").replace(/\\\\/g, "\\");
  const outcome = m[3] ? "ignored" : m[1] === "ok" ? "ok" : "FAILED";
  out.push(`test ${name} ... ${outcome}`);
}
out.push(`# ${results} TAP result line(s) converted`);
for (const raw of tap.split(/\r?\n/)) out.push(`# ${raw}`);
process.stdout.write(out.join("\n") + "\n");
