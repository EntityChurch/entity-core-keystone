/**
 * Byte-buffer primitives for the codec core. Pure-JS and browser-safe: everything
 * is `Uint8Array` (never Node `Buffer`), so this module — and everything that
 * builds on it — lifts into a browser/Deno/Bun bundle untouched (profile
 * `[interop]`, the consumable-data-library use case).
 */

/** A growable big-endian byte writer. Backs the canonical CBOR encoder. */
export class ByteWriter {
  #buf: Uint8Array;
  #len = 0;

  constructor(initialCapacity = 64) {
    this.#buf = new Uint8Array(initialCapacity);
  }

  get length(): number {
    return this.#len;
  }

  #ensure(extra: number): void {
    const need = this.#len + extra;
    if (need <= this.#buf.length) {
      return;
    }
    let cap = this.#buf.length * 2;
    while (cap < need) {
      cap *= 2;
    }
    const grown = new Uint8Array(cap);
    grown.set(this.#buf.subarray(0, this.#len));
    this.#buf = grown;
  }

  pushByte(b: number): void {
    this.#ensure(1);
    this.#buf[this.#len++] = b & 0xff;
  }

  pushBytes(bytes: Uint8Array): void {
    this.#ensure(bytes.length);
    this.#buf.set(bytes, this.#len);
    this.#len += bytes.length;
  }

  /** Snapshot the written bytes as a freshly allocated `Uint8Array`. */
  toBytes(): Uint8Array {
    return this.#buf.slice(0, this.#len);
  }
}

const HEX = "0123456789abcdef";

/** Lowercase hex encode (for hash-string display and test assertions). */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  }
  return out;
}

/** Decode a lowercase/uppercase hex string to bytes. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex string has odd length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

/** Concatenate byte chunks into one `Uint8Array`. */
export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) {
    total += c.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/** Constant-shape byte equality. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
