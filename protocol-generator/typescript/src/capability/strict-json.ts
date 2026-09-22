/**
 * A strict JSON reader for authorization input (the §6.9a seed-policy file).
 *
 * `JSON.parse` is the wrong tool for a file whose every byte is an authorization
 * decision, for two reasons it does not report:
 *
 * - **numbers are IEEE-754 doubles.** `1.5` and `1.0` both parse, and an integer above
 *   2⁵³ silently rounds. A seed policy has no use for a float, and rounding one into a
 *   grant would be a policy nobody wrote — so a fraction or exponent is refused, and an
 *   integer is carried as a `bigint` in the u64 / i64 range (the range the rust peer's
 *   reader accepts, so the cohort refuses the same inputs);
 * - **duplicate object keys are last-one-wins.** RFC 8259 leaves them undefined, and
 *   "last one wins" in a policy file is an authorization decision made by accident —
 *   refused.
 *
 * Also refused: trailing content, trailing commas, raw control characters in strings,
 * and unpaired UTF-16 surrogate escapes. No `node:*` import: this module sits under
 * `capability/`, which a browser bundle loads.
 */

export type Json =
  | { readonly kind: "null" }
  | { readonly kind: "bool"; readonly value: boolean }
  | { readonly kind: "int"; readonly value: bigint }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "array"; readonly items: readonly Json[] }
  | { readonly kind: "object"; readonly entries: readonly (readonly [string, Json])[] };

const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);

/** Look up a key in a JSON object (`undefined` when absent or not an object). */
export function jsonGet(value: Json, key: string): Json | undefined {
  if (value.kind !== "object") {
    return undefined;
  }
  for (const [k, v] of value.entries) {
    if (k === key) {
      return v;
    }
  }
  return undefined;
}

/** Parse `text` as strict JSON. Throws `Error` with a positioned message on refusal. */
export function parseStrictJson(text: string): Json {
  const p = new Parser(text);
  p.ws();
  const v = p.value();
  p.ws();
  if (p.pos !== text.length) {
    p.fail("trailing content after the JSON value");
  }
  return v;
}

class Parser {
  pos = 0;
  constructor(private readonly s: string) {}

  fail(msg: string): never {
    throw new Error(`json: ${msg} at offset ${this.pos}`);
  }

  ws(): void {
    while (this.pos < this.s.length) {
      const c = this.s[this.pos];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") {
        this.pos++;
      } else {
        break;
      }
    }
  }

  value(): Json {
    const c = this.s[this.pos];
    switch (c) {
      case "{":
        return this.object();
      case "[":
        return this.array();
      case '"':
        return { kind: "string", value: this.string() };
      case "t":
        this.literal("true");
        return { kind: "bool", value: true };
      case "f":
        this.literal("false");
        return { kind: "bool", value: false };
      case "n":
        this.literal("null");
        return { kind: "null" };
      default:
        if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) {
          return this.number();
        }
        return this.fail(c === undefined ? "unexpected end of input" : `unexpected character '${c}'`);
    }
  }

  literal(word: string): void {
    if (this.s.startsWith(word, this.pos)) {
      this.pos += word.length;
      return;
    }
    this.fail(`invalid literal (expected ${word})`);
  }

  number(): Json {
    const start = this.pos;
    if (this.s[this.pos] === "-") {
      this.pos++;
    }
    const d = this.s[this.pos];
    if (d === "0") {
      this.pos++;
    } else if (d !== undefined && d >= "1" && d <= "9") {
      while (this.pos < this.s.length && this.s[this.pos]! >= "0" && this.s[this.pos]! <= "9") {
        this.pos++;
      }
    } else {
      this.fail("invalid number");
    }
    const next = this.s[this.pos];
    if (next === "." || next === "e" || next === "E") {
      this.fail("numbers must be integers (a fraction or exponent is refused, never approximated)");
    }
    if (next !== undefined && next >= "0" && next <= "9") {
      this.fail("invalid number (leading zero)");
    }
    const value = BigInt(this.s.slice(start, this.pos));
    if (value > U64_MAX || value < I64_MIN) {
      this.fail("integer out of range (must fit u64 or i64)");
    }
    return { kind: "int", value };
  }

  hex4(): number {
    const h = this.s.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) {
      this.fail("invalid \\u escape");
    }
    this.pos += 4;
    return parseInt(h, 16);
  }

  string(): string {
    this.pos++; // opening quote
    let out = "";
    for (;;) {
      if (this.pos >= this.s.length) {
        this.fail("unterminated string");
      }
      const c = this.s[this.pos]!;
      const code = c.charCodeAt(0);
      if (c === '"') {
        this.pos++;
        return out;
      }
      if (code < 0x20) {
        this.fail("raw control character in string");
      }
      if (code >= 0xd800 && code <= 0xdfff) {
        // A raw surrogate in the decoded text: accept only a well-formed pair.
        const lo = this.s.charCodeAt(this.pos + 1);
        if (code <= 0xdbff && lo >= 0xdc00 && lo <= 0xdfff) {
          out += this.s.slice(this.pos, this.pos + 2);
          this.pos += 2;
          continue;
        }
        this.fail("unpaired surrogate in string");
      }
      if (c !== "\\") {
        out += c;
        this.pos++;
        continue;
      }
      this.pos++;
      const e = this.s[this.pos];
      this.pos++;
      switch (e) {
        case '"':
          out += '"';
          break;
        case "\\":
          out += "\\";
          break;
        case "/":
          out += "/";
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const u = this.hex4();
          if (u >= 0xdc00 && u <= 0xdfff) {
            this.fail("unpaired surrogate escape");
          }
          if (u >= 0xd800 && u <= 0xdbff) {
            if (this.s[this.pos] !== "\\" || this.s[this.pos + 1] !== "u") {
              this.fail("unpaired surrogate escape");
            }
            this.pos += 2;
            const lo = this.hex4();
            if (lo < 0xdc00 || lo > 0xdfff) {
              this.fail("unpaired surrogate escape");
            }
            out += String.fromCharCode(u, lo);
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          this.fail("invalid escape");
      }
    }
  }

  array(): Json {
    this.pos++;
    const items: Json[] = [];
    this.ws();
    if (this.s[this.pos] === "]") {
      this.pos++;
      return { kind: "array", items };
    }
    for (;;) {
      this.ws();
      items.push(this.value());
      this.ws();
      const c = this.s[this.pos];
      if (c === ",") {
        this.pos++;
        this.ws();
        if (this.s[this.pos] === "]") {
          this.fail("trailing comma");
        }
        continue;
      }
      if (c === "]") {
        this.pos++;
        return { kind: "array", items };
      }
      this.fail("expected ',' or ']'");
    }
  }

  object(): Json {
    this.pos++;
    const entries: [string, Json][] = [];
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.pos] === "}") {
      this.pos++;
      return { kind: "object", entries };
    }
    for (;;) {
      this.ws();
      if (this.s[this.pos] !== '"') {
        this.fail(this.s[this.pos] === "}" ? "trailing comma" : "expected a string key");
      }
      const key = this.string();
      if (seen.has(key)) {
        this.fail(`duplicate key "${key}"`);
      }
      seen.add(key);
      this.ws();
      if (this.s[this.pos] !== ":") {
        this.fail("expected ':'");
      }
      this.pos++;
      this.ws();
      entries.push([key, this.value()]);
      this.ws();
      const c = this.s[this.pos];
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "}") {
        this.pos++;
        return { kind: "object", entries };
      }
      this.fail("expected ',' or '}'");
    }
  }
}
