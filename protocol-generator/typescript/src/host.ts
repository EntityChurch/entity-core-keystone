import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ChainVerifier, SeedPolicy } from "./capability/index.js";
import { PeerIdentity } from "./identity/index.js";
import { Peer } from "./peer.js";

/**
 * The peer's own host, as a library function (keystone peer contract `embed.host_main`,
 * `run.cli`, `run.identity`, `run.ready`, `run.serve`, `run.posture`, `run.limits`,
 * `run.stop`). The bare host is `runHost(argv, () => {})`; a composed host is the same
 * call with a `configure` that installs its extensions. Node layer — like `peer.ts`, it
 * is not part of the browser-portable core.
 */

/** The readiness record's `record` value (`run.ready`). */
export const READY_RECORD = "keystone-peer-ready/1";

/** The flag set both hosts accept, and nothing else (`run.cli`). */
export const HOST_USAGE =
  "usage: host [--port N] [--bind ADDR] [--name NAME] [--validate] [--seed-policy PATH] " +
  "[--max-frame-bytes N] [--ready-file PATH] [--debug-open-grants] [--help]";

/** Fixed 32-byte Ed25519 seed used when no `--name` is given → a stable peer id across runs. */
export const DEFAULT_HOST_SEED: Uint8Array = new Uint8Array(32).fill(0x11);

/** Parsed host arguments. */
export interface HostArgs {
  readonly port: number;
  readonly bind: string;
  readonly name: string | null;
  readonly validate: boolean;
  readonly seedPolicyPath: string | null;
  readonly maxFrameBytes: number | null;
  readonly readyFile: string | null;
  readonly debugOpenGrants: boolean;
  readonly help: boolean;
}

/** A refused argument list: the message a host prints before exiting non-zero. */
export class HostArgsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HostArgsError";
    Object.setPrototypeOf(this, HostArgsError.prototype);
  }
}

/**
 * Parse `run.cli`'s flags. Any other argument, or a flag missing (or with an unusable)
 * value, throws {@link HostArgsError}.
 */
export function parseHostArgs(argv: readonly string[]): HostArgs {
  let port = 7777;
  let bind = "127.0.0.1";
  let name: string | null = null;
  let validate = false;
  let seedPolicyPath: string | null = null;
  let maxFrameBytes: number | null = null;
  let readyFile: string | null = null;
  let debugOpenGrants = false;
  let help = false;

  const value = (i: number, flag: string): string => {
    const v = argv[i];
    if (v === undefined) {
      throw new HostArgsError(`${flag} requires a value`);
    }
    return v;
  };
  const integer = (text: string, flag: string, min: number, max: number): number => {
    if (!/^[0-9]+$/.test(text)) {
      throw new HostArgsError(`${flag} requires a non-negative integer, got '${text}'`);
    }
    const n = Number(text);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
      throw new HostArgsError(`${flag} must be in [${min}, ${max}], got '${text}'`);
    }
    return n;
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case "--port":
        port = integer(value(++i, arg), arg, 0, 65535);
        break;
      case "--bind":
        bind = value(++i, arg);
        break;
      case "--name":
        name = value(++i, arg);
        break;
      case "--validate":
        validate = true;
        break;
      case "--seed-policy":
        seedPolicyPath = value(++i, arg);
        break;
      case "--max-frame-bytes":
        maxFrameBytes = integer(value(++i, arg), arg, 1, 0xffffffff);
        break;
      case "--ready-file":
        readyFile = value(++i, arg);
        break;
      case "--debug-open-grants":
        debugOpenGrants = true;
        break;
      case "--help":
        help = true;
        break;
      default:
        throw new HostArgsError(`unknown argument '${arg}'`);
    }
  }
  return { port, bind, name, validate, seedPolicyPath, maxFrameBytes, readyFile, debugOpenGrants, help };
}

/**
 * `run.identity` — the 32-byte Ed25519 seed from `$HOME/.entity/peers/NAME/keypair`: a PEM
 * whose body is base64 of the seed between `-----BEGIN ENTITY PRIVATE KEY-----` and
 * `-----END ENTITY PRIVATE KEY-----` (the Go entity-peer `--name` / peer-manager
 * convention). Throws with the reason on a missing file or a wrong-length seed.
 */
export function loadNamedSeed(name: string, home: string = homedir()): Uint8Array {
  const path = join(home, ".entity", "peers", name, "keypair");
  const text = readFileSync(path, "utf8");
  const body = text
    .split(/\r?\n/)
    .filter((line) => line.length > 0 && !line.startsWith("-"))
    .join("");
  const seed = new Uint8Array(Buffer.from(body, "base64"));
  if (seed.length !== 32) {
    throw new Error(`${path}: expected a 32-byte seed, got ${seed.length} bytes`);
  }
  return seed;
}

/** Called with the constructed peer before it listens. May be async; a throw stops the host (no readiness record). */
export type HostConfigure = (peer: Peer) => void | Promise<void>;

/** Options for {@link runHost}. */
export interface RunHostOptions {
  /**
   * Extra top-level fields for the readiness record — a contract host announces
   * `contract_host` here. They cannot replace a field the record defines.
   */
  readonly recordFields?: Readonly<Record<string, unknown>>;
  /** Where the readiness line and usage go (default `process.stdout`). */
  readonly stdout?: { write(text: string): unknown };
  /** Where diagnostics go (default `process.stderr`). */
  readonly stderr?: { write(text: string): unknown };
}

/**
 * `run_host(argv, configure)`: parse `run.cli`, load `run.identity`, apply `run.posture`,
 * construct the peer with the `run.limits` frame budget, call `configure` BEFORE
 * listening, listen where `--bind` says, write `--ready-file` and print exactly one
 * `LISTENING <json>` line (`run.ready`), then serve until SIGTERM / SIGINT, on which the
 * listener is released and the returned promise resolves (`run.stop`).
 *
 * Resolves with the process exit code: `0` after a signalled stop or `--help`; `2` for a
 * refused argument list, identity or policy; `1` when `configure` or listening failed.
 * Nothing is printed on stdout in any failure case.
 */
export async function runHost(
  argv: readonly string[],
  configure: HostConfigure,
  options: RunHostOptions = {},
): Promise<number> {
  const out = options.stdout ?? process.stdout;
  const err = options.stderr ?? process.stderr;

  let args: HostArgs;
  try {
    args = parseHostArgs(argv);
  } catch (e) {
    err.write(`error: ${e instanceof Error ? e.message : String(e)}\n${HOST_USAGE}\n`);
    return 2;
  }
  if (args.help) {
    out.write(HOST_USAGE + "\n");
    return 0;
  }

  let seed = DEFAULT_HOST_SEED;
  if (args.name !== null) {
    try {
      seed = loadNamedSeed(args.name);
    } catch (e) {
      err.write(`error: --name ${args.name}: ${e instanceof Error ? e.message : String(e)}\n`);
      return 2;
    }
  }

  let seedPolicy: SeedPolicy | null = null;
  let posture: "standard" | "debug-open" | "file" = args.debugOpenGrants ? "debug-open" : "standard";
  let postureDigest: string = posture;
  if (args.seedPolicyPath !== null) {
    try {
      // One read: the digest is of exactly the bytes that were parsed. Fatal decode —
      // invalid UTF-8 is refused, not replaced.
      const bytes = readFileSync(args.seedPolicyPath);
      seedPolicy = SeedPolicy.fromJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      posture = "file";
      postureDigest = createHash("sha256").update(bytes).digest("hex");
    } catch (e) {
      // Refuse before binding anything: a policy that cannot be materialized as written
      // must not fall back to some other policy and listen anyway.
      err.write(`error: --seed-policy: ${args.seedPolicyPath}: ${e instanceof Error ? e.message : String(e)}\n`);
      return 2;
    }
    if (args.debugOpenGrants) {
      err.write("warning: --debug-open-grants is DEPRECATED and is IGNORED because --seed-policy was given (a declared policy wins)\n");
    }
    err.write(
      `seed-policy: ${args.seedPolicyPath} (default entry: ${seedPolicy.defaultGrants.length} grant(s), ` +
        `${seedPolicy.namedEntries.length} named entr(ies))\n`,
    );
  } else if (args.debugOpenGrants) {
    err.write(
      "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — it now selects the degenerate " +
        "`default → *` seed policy. Prefer --seed-policy PATH " +
        "(protocol-generator/shared/seed-policy/examples/debug-open.json is the file form).\n",
    );
  }

  const peer = new Peer({
    identity: PeerIdentity.fromSeed(seed),
    ...(seedPolicy !== null ? { seedPolicy } : { debugOpenGrants: args.debugOpenGrants }),
    conformanceHandlers: args.validate,
    ...(args.maxFrameBytes !== null ? { maxFrameBytes: args.maxFrameBytes } : {}),
  });

  try {
    await configure(peer);
  } catch (e) {
    err.write(`error: configure: ${e instanceof Error ? e.message : String(e)}\n`);
    await peer.dispose();
    return 1;
  }

  // Install the stop handlers before listening, so a SIGTERM that arrives the instant the
  // port is open still releases it instead of taking Node's default path mid-setup.
  let stop!: () => void;
  const stopped = new Promise<void>((resolve) => {
    stop = resolve;
  });
  const onSignal = (): void => stop();
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);

  let bound: number;
  try {
    bound = await peer.listen(args.port, args.bind);
  } catch (e) {
    err.write(`error: listen ${args.bind}:${args.port}: ${e instanceof Error ? e.message : String(e)}\n`);
    process.removeListener("SIGTERM", onSignal);
    process.removeListener("SIGINT", onSignal);
    await peer.dispose();
    return 1;
  }

  const record = readyRecord(peer, args, bound, posture, postureDigest, options.recordFields ?? {});
  const json = JSON.stringify(record);
  if (args.readyFile !== null) {
    try {
      writeFileSync(args.readyFile, json + "\n");
    } catch (e) {
      err.write(`error: --ready-file ${args.readyFile}: ${e instanceof Error ? e.message : String(e)}\n`);
      await peer.dispose();
      return 1;
    }
  }
  out.write(`LISTENING ${json}\n`);

  await stopped;
  process.removeListener("SIGTERM", onSignal);
  process.removeListener("SIGINT", onSignal);
  // Bounded: the listener is released synchronously inside dispose(); a connection that
  // will not close must not keep the process alive past the stop budget.
  await Promise.race([peer.dispose(), new Promise<void>((resolve) => setTimeout(resolve, 2000).unref())]);
  return 0;
}

/** `run.ready`'s record for a listening peer. `extra` fields never replace a defined one. */
export function readyRecord(
  peer: Peer,
  args: HostArgs,
  boundPort: number,
  posture: string,
  postureDigest: string,
  extra: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  const host = args.bind.includes(":") ? `[${args.bind}]` : args.bind;
  return {
    ...extra,
    record: READY_RECORD,
    transport: "tcp",
    addr: `${host}:${boundPort}`,
    peer_id: peer.localPeerId,
    posture,
    posture_digest: postureDigest,
    limits: { max_frame_bytes: peer.maxFrameBytes, max_chain_depth: ChainVerifier.MAX_CHAIN_DEPTH },
    validate: args.validate,
  };
}
