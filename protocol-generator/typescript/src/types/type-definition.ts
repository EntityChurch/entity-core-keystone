import { type EcfValue, ecfMap, ecfText } from "../codec/ecf-value.js";
import { Entity, Ecf } from "../model/index.js";

/**
 * A field spec inside a {@link TypeDef} — the model of the reference
 * `system/type/field-spec` shape (TYPE-SYSTEM §4.2). Exactly one structural
 * carrier is set: a {@link typeRef}, an {@link arrayOf}, a {@link mapOf}, or a
 * {@link unionOf}. Every field is encoded with omit-empty semantics (an
 * absent/false/zero value drops the key) so the rendered CBOR is byte-identical to
 * the Go reference encoder (ECF canonical form).
 */
interface FSpecFields {
  readonly typeRef: string | undefined;
  readonly optional: boolean;
  readonly arrayOf: FSpec | undefined;
  readonly mapOf: FSpec | undefined;
  readonly unionOf: readonly FSpec[] | undefined;
  readonly keyType: string | undefined;
  readonly byteSize: bigint | undefined;
}

const EMPTY_FSPEC: FSpecFields = {
  typeRef: undefined,
  optional: false,
  arrayOf: undefined,
  mapOf: undefined,
  unionOf: undefined,
  keyType: undefined,
  byteSize: undefined,
};

export class FSpec {
  readonly typeRef: string | undefined;
  readonly optional: boolean;
  readonly arrayOf: FSpec | undefined;
  readonly mapOf: FSpec | undefined;
  readonly unionOf: readonly FSpec[] | undefined;
  readonly keyType: string | undefined;
  readonly byteSize: bigint | undefined;

  private constructor(init: FSpecFields) {
    this.typeRef = init.typeRef;
    this.optional = init.optional;
    this.arrayOf = init.arrayOf;
    this.mapOf = init.mapOf;
    this.unionOf = init.unionOf;
    this.keyType = init.keyType;
    this.byteSize = init.byteSize;
  }

  /** This spec marked optional (the §1.3 absent-key convention at validate time). */
  opt(): FSpec {
    return new FSpec({ ...this, optional: true });
  }

  /** This spec with a fixed encoded byte width (e.g. `format_code` = 1 byte). */
  size(bytes: bigint): FSpec {
    return new FSpec({ ...this, byteSize: bytes });
  }

  /** Render to the ECF data map (omit-empty; key order applied at encode time). */
  toData(): EcfValue {
    return Ecf.map(
      ["type_ref", this.typeRef === undefined ? null : Ecf.text(this.typeRef)],
      ["optional", this.optional ? Ecf.bool(true) : null],
      ["array_of", this.arrayOf === undefined ? null : this.arrayOf.toData()],
      ["map_of", this.mapOf === undefined ? null : this.mapOf.toData()],
      ["union_of", this.unionOf === undefined ? null : Ecf.array(this.unionOf.map((u) => u.toData()))],
      ["key_type", this.keyType === undefined ? null : Ecf.text(this.keyType)],
      ["byte_size", this.byteSize === undefined ? null : Ecf.uint(this.byteSize)],
    );
  }

  static ref(typeRef: string): FSpec {
    return new FSpec({ ...EMPTY_FSPEC, typeRef });
  }

  static array(element: FSpec): FSpec {
    return new FSpec({ ...EMPTY_FSPEC, arrayOf: element });
  }

  static map(value: FSpec, keyType?: string): FSpec {
    return new FSpec({ ...EMPTY_FSPEC, mapOf: value, keyType });
  }

  static union(...variants: FSpec[]): FSpec {
    return new FSpec({ ...EMPTY_FSPEC, unionOf: variants });
  }
}

/**
 * A core type definition — the model of a `system/type` entity's data payload
 * (TYPE-SYSTEM §4.1). Rendered natively via {@link toEntity} through the byte-green
 * codec; the resulting `content_hash` is diffed against the Go-rendered vector set
 * (S8 drift target). This is the peer's single source of truth for its published
 * types (memory: type-registry-render-design). A mutable fluent builder, frozen by
 * convention once pushed into the registry.
 */
export class TypeDef {
  #extends: string | undefined;
  readonly #fields: [string, FSpec][] = [];
  #layout: string[] | undefined;

  constructor(readonly name: string) {}

  ext(extendsName: string): this {
    this.#extends = extendsName;
    return this;
  }

  f(key: string, spec: FSpec): this {
    this.#fields.push([key, spec]);
    return this;
  }

  lay(...layout: string[]): this {
    this.#layout = layout;
    return this;
  }

  /** Location-index path: `system/type/<name>`. */
  get treePath(): string {
    return "system/type/" + this.name;
  }

  toData(): EcfValue {
    const fields =
      this.#fields.length > 0
        ? ecfMap(this.#fields.map(([k, spec]) => [ecfText(k), spec.toData()] as const))
        : null;
    const layout = this.#layout && this.#layout.length > 0 ? Ecf.array(this.#layout.map((s) => Ecf.text(s))) : null;
    return Ecf.map(
      ["name", Ecf.text(this.name)],
      ["extends", this.#extends === undefined ? null : Ecf.text(this.#extends)],
      ["fields", fields],
      ["layout", layout],
    );
  }

  toEntity(): Entity {
    return Entity.create("system/type", this.toData());
  }
}
