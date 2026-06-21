import { type EcfValue } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import { Entity, Ecf, TypeNames } from "../model/index.js";
import { type PeerIdentity, signEntity } from "../identity/index.js";
import { GrantEntry } from "./grant-entry.js";

/**
 * A multi-signature granter (V7 §3.6 M3): `{signers, threshold}`. A capability
 * whose `granter` is this shape (rather than a single `system/hash`) is authorized
 * by a k-of-n quorum and is root-only (`parent: null`). Parsing is total — a
 * malformed shape yields an empty/zero structure that fails validation, never a
 * throw (so an inbound multi-sig EXECUTE rejects, never hangs).
 */
export class MultiSigGranter {
  constructor(
    readonly signers: readonly Uint8Array[],
    readonly threshold: bigint,
  ) {}

  static fromEcf(value: EcfValue): MultiSigGranter {
    const signers: Uint8Array[] = [];
    let threshold = 0n;
    if (value.kind === "map") {
      const signersField = Ecf.field(value, "signers");
      if (signersField !== null && signersField.kind === "array") {
        for (const item of signersField.items) {
          if (item.kind === "bytes") {
            signers.push(item.value);
          }
        }
      }
      const thresholdField = Ecf.field(value, "threshold");
      if (thresholdField !== null && thresholdField.kind === "int" && !thresholdField.negative) {
        threshold = thresholdField.argument;
      }
    }
    return new MultiSigGranter(signers, threshold);
  }
}

/** Delegation caveats on a token (V7 §3.6, §5.7). */
export class DelegationCaveats {
  constructor(
    readonly noDelegation: boolean | null,
    readonly maxDelegationDepth: bigint | null,
    readonly maxDelegationTtl: bigint | null,
  ) {}

  static fromEcf(value: EcfValue | null): DelegationCaveats | null {
    if (value === null) {
      return null;
    }
    return new DelegationCaveats(
      Ecf.optBool(value, "no_delegation"),
      Ecf.optUint(value, "max_delegation_depth"),
      Ecf.optUint(value, "max_delegation_ttl"),
    );
  }
}

/**
 * A typed view over a `system/capability/token` entity (V7 §3.6). Carries the
 * grant list, the `granter` / `grantee` identity hashes, an optional delegation
 * `parent`, temporal bounds, and delegation caveats. The token is signed by the
 * granter; the signature is found by target-matching in the envelope (§3.6).
 */
export class CapabilityToken {
  readonly entity: Entity;
  readonly grants: readonly GrantEntry[];
  /** The single-sig granter identity hash, or null when {@link multiGranter} is set. */
  readonly granter: Uint8Array | null;
  /** The multi-sig granter (§3.6 M3), or null for a single-sig token. */
  readonly multiGranter: MultiSigGranter | null;
  readonly grantee: Uint8Array;
  readonly parent: Uint8Array | null;
  readonly createdAt: bigint;
  readonly expiresAt: bigint | null;
  readonly notBefore: bigint | null;
  readonly caveats: DelegationCaveats | null;

  constructor(entity: Entity) {
    if (entity.type !== TypeNames.CapabilityToken) {
      throw new EntityProtocolError(`expected ${TypeNames.CapabilityToken}, got '${entity.type}'`);
    }
    this.entity = entity;
    this.grants = Ecf.asArray(Ecf.require(entity.data, "grants")).map((g) => GrantEntry.fromEcf(g));

    // The granter is a union (§3.6): a single system/hash (single-sig) or a
    // {signers, threshold} multi-granter (multi-sig, root-only). Parse totally —
    // never throw on the multi-sig shape (that would swallow the response).
    const granterField = Ecf.require(entity.data, "granter");
    if (granterField.kind === "bytes") {
      this.granter = granterField.value;
      this.multiGranter = null;
    } else {
      this.granter = null;
      this.multiGranter = MultiSigGranter.fromEcf(granterField);
    }

    this.grantee = Ecf.requireBytes(entity.data, "grantee");
    this.parent = Ecf.optBytes(entity.data, "parent");
    this.createdAt = Ecf.requireUint(entity.data, "created_at");
    this.expiresAt = Ecf.optUint(entity.data, "expires_at");
    this.notBefore = Ecf.optUint(entity.data, "not_before");
    this.caveats = DelegationCaveats.fromEcf(Ecf.field(entity.data, "delegation_caveats"));
  }

  /** True when this token is granted by a k-of-n quorum (root-only, §3.6 M3). */
  get isMultiSig(): boolean {
    return this.multiGranter !== null;
  }

  get contentHash(): Uint8Array {
    return this.entity.contentHash;
  }

  get contentHashHex(): string {
    return this.entity.contentHashHex;
  }

  /**
   * Build and self-sign a root capability token granted by `granter` to
   * `granteeHash`. Returns the token plus its signature entity (the granter signs
   * the token's content hash, §3.6).
   */
  static createRoot(
    granter: PeerIdentity,
    granteeHash: Uint8Array,
    grants: readonly GrantEntry[],
    createdAt: bigint,
    expiresAt: bigint | null = null,
  ): { token: CapabilityToken; signature: Entity } {
    const data = Ecf.map(
      ["grants", Ecf.array(grants.map((g) => g.toEcf()))],
      ["granter", Ecf.bytes(granter.identityHash)],
      ["grantee", Ecf.bytes(granteeHash)],
      ["created_at", Ecf.uint(createdAt)],
      ["expires_at", expiresAt === null ? null : Ecf.uint(expiresAt)],
    );
    const entity = Entity.create(TypeNames.CapabilityToken, data);
    const signature = signEntity(entity, granter);
    return { token: new CapabilityToken(entity), signature };
  }
}
