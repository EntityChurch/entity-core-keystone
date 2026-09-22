import { type EcfValue, ecfArray, ecfBool, ecfInt, ecfMap, ecfNull, ecfText } from "../codec/ecf-value.js";
import { GrantEntry } from "./grant-entry.js";
import { isPeerId } from "./paths.js";
import { Scope } from "./scope.js";
import { type Json, jsonGet, parseStrictJson } from "./strict-json.js";

/** A seed-policy file that cannot be materialized as written (§6.9a; keystone seed-policy convention). */
export class SeedPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SeedPolicyError";
  }
}

/** A named seed-policy entry (§6.9a.1): a grantee key (identity-hash hex or Base58 peer-id) and its scope. */
export interface SeedPolicyEntry {
  readonly key: string;
  readonly grants: readonly GrantEntry[];
}

/**
 * The declared identity → capability seed policy (V7 §6.9a Peer Authority
 * Bootstrap). Materialized into the tree under `system/capability/policy/{key}` at
 * peer-init (the §6.9a Bootstrap L0 write-set); §4.6 authenticate reads it back via
 * the v7.64 dual-form lookup (hex → Base58 → `default`) and UNIONs the matched scope
 * with the §4.4 discovery floor.
 *
 * Replaces the hardcoded `initialGrants()` / `openGrants()` fork §6.9a declares
 * non-conformant. The peer-owner authority is the always-present `self` entry
 * (materialized by {@link Peer}, since it is a real owner capability, not a template).
 * The degenerate `default → *` policy ({@link SeedPolicy.debugOpen}) is the retired
 * `--debug-open-grants` behaviour — deprecated in v7.74, removed in v7.75.
 */
export class SeedPolicy {
  private constructor(
    readonly defaultGrants: readonly GrantEntry[],
    readonly namedEntries: readonly SeedPolicyEntry[],
  ) {}

  /**
   * The §4.4 discovery floor: every authenticated identity gets at least this — read
   * `system/type/*` + `system/handler/*`; invoke `system/capability:request`. UNION'd
   * into every derived grant (§6.9a).
   */
  static discoveryFloor(): GrantEntry[] {
    return [
      new GrantEntry(
        new Scope(["system/tree"], null),
        new Scope(["system/type/*", "system/handler/*"], null),
        new Scope(["get"], null),
        null,
        null,
        null,
      ),
      new GrantEntry(
        new Scope(["system/capability"], null),
        Scope.empty,
        new Scope(["request"], null),
        null,
        null,
        null,
      ),
    ];
  }

  /**
   * A wide-open admin scope (every handler, resource, operation; both peer-local `*`
   * and cross-peer `/*​/*` resource forms). The degenerate `default → *` policy
   * corresponds to the retired `--debug-open-grants`.
   */
  static openGrants(): GrantEntry[] {
    return [
      new GrantEntry(
        new Scope(["*"], null),
        new Scope(["*", "/*/*"], null),
        new Scope(["*"], null),
        null,
        null,
        null,
      ),
    ];
  }

  /**
   * Full owner authority over the local namespace `/{peer_id}/*` (§6.9a) — the scope
   * of the `self`-owner capability the peer mints for its own identity. Local namespace
   * only (no cross-peer `/*​/*`): bare `*` canonicalizes to `/{peer_id}/*` on the
   * granter (= local) frame.
   */
  static ownerGrants(localPeerId: string): GrantEntry[] {
    return [
      new GrantEntry(
        new Scope(["*"], null),
        new Scope(["*"], null),
        new Scope(["*"], null),
        new Scope([localPeerId], null),
        null,
        null,
      ),
    ];
  }

  /** The conformant default seed policy: `default` = the §4.4 discovery floor. */
  static standard(): SeedPolicy {
    return new SeedPolicy(SeedPolicy.discoveryFloor(), []);
  }

  /**
   * The degenerate debug seed policy: `default → *` — the retired `--debug-open-grants`
   * behaviour (every authenticating identity gets the wide-open admin grant), now routed
   * through the real §6.9a mechanism. Deprecated in v7.74, removed in v7.75.
   */
  static debugOpen(): SeedPolicy {
    return new SeedPolicy(SeedPolicy.openGrants(), []);
  }

  /** Build a custom seed policy (the `withSeedPolicy` builder affordance, §6.9a(e)). */
  static of(defaultGrants: readonly GrantEntry[], named: readonly SeedPolicyEntry[] = []): SeedPolicy {
    return new SeedPolicy(defaultGrants, named);
  }

  /**
   * Parse the keystone seed-policy JSON format
   * (`protocol-generator/shared/seed-policy/` — README §3, `seed-policy.schema.json`).
   * Portable: no filesystem access (see `withSeedPolicyFromFile` in the Node layer).
   *
   * Refuses rather than approximates on each of the following, because every one of them
   * would otherwise be an authorization decision nobody wrote down. The rules are the rust
   * peer's, so the cohort's hosts refuse the same files:
   *
   * - an unknown key at root / entry / grant / scope level (the schema is
   *   `additionalProperties: false`). Keys beginning with `_` are comments and are skipped
   *   — the shipped `examples/` carry `_comment`, which the schema as written does not admit;
   * - `version` other than the integer 1;
   * - `grantee: "self"` — the owner capability lives at the self key and is minted by the
   *   peer; a policy entry there would overwrite it;
   * - `bounds` — `system/capability/policy-entry` (§6.2) carries `peer_pattern`, `grants`
   *   and `ttl_ms` only, so there is nowhere to materialize a `not_before`/`expires_at` and
   *   dropping it would widen the policy silently;
   * - a grantee that is not `default`, a 66/98-char lowercase identity-hash hex, or a
   *   Base58 peer id; the same grantee twice; a second `default`;
   * - a float, a duplicate object key, or trailing content anywhere in the document.
   *
   * A file with no `default` entry gets the §4.4 discovery floor as `default`. An empty
   * `grants: []` is legal (the CAP-2 withdrawal form).
   */
  static fromJson(text: string): SeedPolicy {
    let root: Json;
    try {
      root = parseStrictJson(text);
    } catch (err) {
      throw new SeedPolicyError(err instanceof Error ? err.message : String(err));
    }
    checkKeys(root, ["version", "entries"], "seed policy");
    const version = jsonGet(root, "version");
    if (version === undefined) {
      throw new SeedPolicyError("seed policy: missing version");
    }
    if (version.kind !== "int" || version.value !== 1n) {
      throw new SeedPolicyError("seed policy: version must be 1");
    }
    const entries = jsonGet(root, "entries");
    if (entries === undefined) {
      throw new SeedPolicyError("seed policy: missing entries");
    }
    if (entries.kind !== "array") {
      throw new SeedPolicyError("seed policy: entries must be an array");
    }

    let defaultGrants: GrantEntry[] | null = null;
    const named: SeedPolicyEntry[] = [];
    entries.items.forEach((entry, i) => {
      const what = `entries[${i}]`;
      checkKeys(entry, ["grantee", "grants", "bounds"], what);
      if (jsonGet(entry, "bounds") !== undefined) {
        throw new SeedPolicyError(
          `${what}: bounds is not supported — system/capability/policy-entry (section 6.2) ` +
            "carries peer_pattern, grants and ttl_ms only, so a not_before/expires_at here would be dropped",
        );
      }
      const granteeJson = jsonGet(entry, "grantee");
      if (granteeJson === undefined || granteeJson.kind !== "string" || granteeJson.value.length === 0) {
        throw new SeedPolicyError(`${what}: grantee must be a non-empty string`);
      }
      const grantee = granteeJson.value;
      const grantsJson = jsonGet(entry, "grants");
      if (grantsJson === undefined || grantsJson.kind !== "array") {
        throw new SeedPolicyError(`${what}: grants must be an array`);
      }
      const grants = grantsJson.items.map((g, j) => grantFromJson(g, `${what}.grants[${j}]`));

      if (grantee === "default") {
        if (defaultGrants !== null) {
          throw new SeedPolicyError(`${what}: a second default entry`);
        }
        defaultGrants = grants;
      } else if (grantee === "self") {
        throw new SeedPolicyError(
          `${what}: grantee "self" is materialized by the peer as its owner capability; ` +
            "a policy entry at that key would overwrite it",
        );
      } else if (isIdentityHex(grantee) || isPeerId(grantee)) {
        if (named.some((e) => e.key === grantee)) {
          throw new SeedPolicyError(`${what}: grantee ${grantee} appears twice`);
        }
        named.push({ key: grantee, grants });
      } else {
        throw new SeedPolicyError(
          `${what}: grantee "${grantee}" is not default, an identity-hash hex, or a Base58 peer id`,
        );
      }
    });
    return new SeedPolicy(defaultGrants ?? SeedPolicy.discoveryFloor(), named);
  }
}

function isIdentityHex(s: string): boolean {
  return (s.length === 66 || s.length === 98) && /^[0-9a-f]+$/.test(s);
}

function checkKeys(value: Json, allowed: readonly string[], what: string): void {
  if (value.kind !== "object") {
    throw new SeedPolicyError(`${what}: must be an object`);
  }
  for (const [k] of value.entries) {
    if (!k.startsWith("_") && !allowed.includes(k)) {
      throw new SeedPolicyError(`${what}: unknown key "${k}"`);
    }
  }
}

function stringList(value: Json, what: string): string[] {
  if (value.kind !== "array") {
    throw new SeedPolicyError(`${what}: must be an array`);
  }
  return value.items.map((item) => {
    if (item.kind !== "string") {
      throw new SeedPolicyError(`${what}: entries must be strings`);
    }
    return item.value;
  });
}

function scopeFromJson(value: Json, what: string): Scope {
  checkKeys(value, ["include", "exclude"], what);
  const include = jsonGet(value, "include");
  if (include === undefined) {
    throw new SeedPolicyError(`${what}: missing include`);
  }
  const includeList = stringList(include, `${what}.include`);
  const exclude = jsonGet(value, "exclude");
  // `exclude` is preserved whenever it is present — including as an empty list.
  return new Scope(includeList, exclude === undefined ? null : stringList(exclude, `${what}.exclude`));
}

function grantFromJson(value: Json, what: string): GrantEntry {
  checkKeys(value, ["handlers", "resources", "operations", "peers", "constraints", "allowances"], what);
  const dim = (name: string): Scope => {
    const v = jsonGet(value, name);
    if (v === undefined) {
      throw new SeedPolicyError(`${what}: missing ${name}`);
    }
    return scopeFromJson(v, `${what}.${name}`);
  };
  const handlers = dim("handlers");
  const resources = dim("resources");
  const operations = dim("operations");
  const peersJson = jsonGet(value, "peers");
  const peers = peersJson === undefined ? null : scopeFromJson(peersJson, `${what}.peers`);
  const extra = (name: string): EcfValue | null => {
    const v = jsonGet(value, name);
    if (v === undefined) {
      return null;
    }
    if (v.kind !== "object") {
      throw new SeedPolicyError(`${what}.${name}: must be an object`);
    }
    return jsonToEcf(v);
  };
  return new GrantEntry(handlers, resources, operations, peers, extra("constraints"), extra("allowances"));
}

/** Carry a JSON value into ECF verbatim (integers as `bigint`; floats never reach here). */
function jsonToEcf(value: Json): EcfValue {
  switch (value.kind) {
    case "null":
      return ecfNull();
    case "bool":
      return ecfBool(value.value);
    case "int":
      return ecfInt(value.value);
    case "string":
      return ecfText(value.value);
    case "array":
      return ecfArray(value.items.map(jsonToEcf));
    case "object":
      return ecfMap(value.entries.map(([k, v]) => [ecfText(k), jsonToEcf(v)] as const));
  }
}
