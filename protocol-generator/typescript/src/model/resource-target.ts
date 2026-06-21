import { type EcfValue } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";

/**
 * A `system/protocol/resource-target` (V7 §3.2): the data paths an operation
 * accesses (`targets`, at least one) plus optional `exclude` paths. The
 * dispatcher checks this against `grant.resources` before handler dispatch.
 */
export class ResourceTarget {
  constructor(
    readonly targets: readonly string[],
    readonly exclude: readonly string[] | null,
  ) {}

  toEcf(): EcfValue {
    return Ecf.map(
      ["targets", Ecf.array(this.targets.map((t) => Ecf.text(t)))],
      ["exclude", this.exclude === null ? null : Ecf.array(this.exclude.map((e) => Ecf.text(e)))],
    );
  }

  static fromEcf(value: EcfValue): ResourceTarget {
    const targets = Ecf.asArray(Ecf.require(value, "targets")).map((t) => Ecf.asText(t));
    if (targets.length === 0) {
      throw new EntityProtocolError("resource-target.targets MUST contain at least one entry (§3.2)");
    }
    const excludeField = Ecf.field(value, "exclude");
    const exclude = excludeField === null ? null : Ecf.asArray(excludeField).map((e) => Ecf.asText(e));
    return new ResourceTarget(targets, exclude);
  }
}
