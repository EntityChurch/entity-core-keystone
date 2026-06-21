import { type EcfValue } from "../codec/ecf-value.js";
import { Ecf } from "../model/index.js";
import { Scope } from "./scope.js";

/**
 * A `system/capability/grant-entry` (V7 §3.6): one self-describing authorization —
 * which `handlers` may be called, which `resources` (data paths) may be accessed,
 * which `operations` are allowed, which `peers` are in scope, plus domain-specific
 * narrowing `constraints` and expanding `allowances`.
 */
export class GrantEntry {
  constructor(
    readonly handlers: Scope,
    readonly resources: Scope,
    readonly operations: Scope,
    readonly peers: Scope | null,
    readonly constraints: EcfValue | null,
    readonly allowances: EcfValue | null,
  ) {}

  /** Peer scope, defaulting to the local peer only when absent (§3.6). */
  effectivePeers(localPeerId: string): Scope {
    return this.peers ?? new Scope([localPeerId], null);
  }

  toEcf(): EcfValue {
    return Ecf.map(
      ["handlers", this.handlers.toEcf()],
      ["resources", this.resources.toEcf()],
      ["operations", this.operations.toEcf()],
      ["peers", this.peers === null ? null : this.peers.toEcf()],
      ["constraints", this.constraints],
      ["allowances", this.allowances],
    );
  }

  static fromEcf(value: EcfValue): GrantEntry {
    const handlers = Scope.fromEcf(Ecf.require(value, "handlers"));
    const resources = Scope.fromEcf(Ecf.require(value, "resources"));
    const operations = Scope.fromEcf(Ecf.require(value, "operations"));
    const peersField = Ecf.field(value, "peers");
    return new GrantEntry(
      handlers,
      resources,
      operations,
      peersField === null ? null : Scope.fromEcf(peersField),
      Ecf.field(value, "constraints"),
      Ecf.field(value, "allowances"),
    );
  }
}
