import { GrantEntry } from "./grant-entry.js";
import { Scope } from "./scope.js";

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
}
