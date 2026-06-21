import { type EcfValue } from "../codec/ecf-value.js";
import { Ecf } from "../model/index.js";
import * as Paths from "./paths.js";

/**
 * A grant scope dimension (V7 §3.6): `{include, exclude?}`. Both
 * `system/capability/path-scope` (handlers, resources) and
 * `system/capability/id-scope` (operations, peers) share this shape, and
 * {@link Scope.matches} works uniformly across both (§5.2 `matches_scope`).
 */
export class Scope {
  constructor(
    readonly include: readonly string[],
    readonly exclude: readonly string[] | null,
  ) {}

  static readonly empty = new Scope([], null);

  toEcf(): EcfValue {
    return Ecf.map(
      ["include", Ecf.array(this.include.map((p) => Ecf.text(p)))],
      ["exclude", this.exclude === null ? null : Ecf.array(this.exclude.map((p) => Ecf.text(p)))],
    );
  }

  static fromEcf(value: EcfValue): Scope {
    const include = Ecf.asArray(Ecf.require(value, "include")).map((v) => Ecf.asText(v));
    const excludeField = Ecf.field(value, "exclude");
    const exclude = excludeField === null ? null : Ecf.asArray(excludeField).map((v) => Ecf.asText(v));
    return new Scope(include, exclude);
  }

  /**
   * True if `value` is included and not excluded by this scope (§5.2
   * `matches_scope`). Value and patterns are canonicalized uniformly, so the same
   * routine serves both path and identifier dimensions.
   */
  matches(value: string, localPeerId: string): boolean {
    const canonicalValue = Paths.canonicalize(value, localPeerId);

    let matched = false;
    for (const pattern of this.include) {
      if (Paths.matchesPattern(canonicalValue, Paths.canonicalize(pattern, localPeerId))) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return false;
    }

    if (this.exclude !== null) {
      for (const pattern of this.exclude) {
        if (Paths.matchesPattern(canonicalValue, Paths.canonicalize(pattern, localPeerId))) {
          return false;
        }
      }
    }
    return true;
  }
}
