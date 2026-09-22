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
    // 0.8.2.21 — an unmatchable exclude DENIES rather than carving out nothing, and
    // SCOPED TO PATH-SCOPE at 0.8.2.24 (N2/N3). §5.2's exclude loop tests the sentinel
    // INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4's rule is
    // likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID … It
    // does NOT reach `operations` or `peers` [MUST]".
    //
    // This guard used to sit OUTSIDE the type dispatch, transcribing §5.2's loop before
    // that loop grew its type test — which ran an id pattern through the §5.4 transforms
    // purely to classify it and then DENIED THE WHOLE DIMENSION on a property unrelated
    // to whether the exclude carves anything out: an `operations` exclude of `*/apply`,
    // an ordinary namespaced operation name, path-canonicalizes to the sentinel and
    // denied every operation. Over-denial, invisible on any well-formed grant.
    //
    // The id arm reaches the literal matcher below unguarded, which is correct: under the
    // id-scope grammar every non-`*` pattern is a literal, and a literal is never
    // structurally unmatchable, so there is nothing here for the sentinel to detect.
    if (kind === "path" && this.exclude !== null && Paths.excludeIsUnmatchable(this.exclude, localPeerId)) {
      return false;
    }
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
