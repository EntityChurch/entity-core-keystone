/**
 * entity-core-protocol-typescript — the bare peer host.
 *
 * `runHost(argv, () => {})` and nothing else: the runnable target for S4 conformance
 * (`run-s4.sh`) and the keystone peer contract's BARE HOST. Every flag, the readiness
 * record and the stop behaviour are {@link runHost}'s — see `src/host.ts`:
 *
 *   --port N  --bind ADDR  --name NAME  --validate  --seed-policy PATH
 *   --max-frame-bytes N  --ready-file PATH  --debug-open-grants (deprecated)  --help
 *
 * Without `--name` a fixed test seed (0x11 × 32) is used, so the peer id is stable.
 * One `LISTENING {"record":"keystone-peer-ready/1",…}` line goes to stdout once the
 * peer is listening; a harness waits for it.
 *
 * Run (in-container, after tsc): `node dist/test/host.js --port 7777 [--name NAME] [--seed-policy PATH] [--validate]`.
 */

import { runHost } from "../src/index.js";

runHost(process.argv.slice(2), () => {}).then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exit(1);
  },
);
