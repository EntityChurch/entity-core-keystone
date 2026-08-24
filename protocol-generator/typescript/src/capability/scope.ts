import { type EcfValue } from "../codec/ecf-value.js";
import { Ecf } from "../model/index.js";
import * as Paths from "./paths.js";

/**
 * Which §5.2 matcher a grant dimension uses (0.8.1, F40). {@link Scope.matches}
 * takes it as a required argument — no default — so a new call site cannot silently
 * inherit the wrong matcher, which is exactly the F40 defect.
 */
export type ScopeKind = "id" | "path";

/**
 * §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
 * forms — bare `*` and a trailing `/*` segment-prefix. None of the §5.4 path
 * transforms apply — no leading-slash universal reading, no interior peer-wildcard, no
 * peer-relative qualification — so a pattern carrying path syntax is matched as a
 * literal string: a non-match, never a fault.
 */
export function matchesIdPattern(value: string, pattern: string): boolean {
  if (pattern === "*") {
    return true;
  }
  if (pattern.endsWith("/*")) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return value === pattern;
}

/**
 * A grant scope dimension (V7 §3.6): `{include, exclude?}`. Both
 * `system/capability/path-scope` (handlers, resources) and
 * `system/capability/id-scope` (operations, peers) share this shape, but §5.2
 * matches each **by its scope type** (0.8.1, F40) — see {@link Scope.matches}.
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
   * `matches_scope`). `kind` selects the matcher by scope type: `"path"`
   * (handlers, resources) canonicalizes both sides; `"id"` (operations, peers)
   * compares literally per the 0.8.1 id-scope grammar. The two MUST NOT be
   * interchanged.
   */
  matches(value: string, localPeerId: string, kind: ScopeKind): boolean {
    const canonicalValue = kind === "path" ? Paths.canonicalize(value, localPeerId) : value;
    const covers = (pattern: string): boolean =>
      kind === "id"
        ? matchesIdPattern(value, pattern)
        : Paths.matchesPattern(canonicalValue, Paths.canonicalize(pattern, localPeerId));

    let matched = false;
    for (const pattern of this.include) {
      if (covers(pattern)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return false;
    }

    if (this.exclude !== null) {
      for (const pattern of this.exclude) {
        if (covers(pattern)) {
          return false;
        }
      }
    }
    return true;
  }
}
