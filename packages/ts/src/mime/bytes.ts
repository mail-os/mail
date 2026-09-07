/**
 * Byte plumbing shared by the decoders.
 *
 * Every decoder in this parser writes into a `ByteWriter` and hands back a single
 * exact sized ArrayBuffer at the end. Collecting chunks in a Blob and awaiting
 * `blob.arrayBuffer()` instead, which is the obvious portable way to join them, costs
 * an extra copy of the whole body plus a trip through the microtask queue for every
 * part of the message.
 */

const INITIAL_CAPACITY = 1024

// A part with an empty body never grows past this, and a multipart message has one
// decoder per part, so the buffer is shared until something is actually written.
const EMPTY = new Uint8Array(0)

/** Growable byte sink. Doubles, so appending n bytes stays amortized O(n). */
export class ByteWriter {
  bytes: Uint8Array
  length: number
  private initialCapacity: number

  constructor(capacity: number = INITIAL_CAPACITY) {
    this.bytes = EMPTY
    this.length = 0
    this.initialCapacity = capacity > 0 ? capacity : INITIAL_CAPACITY
  }

  private grow(needed: number): void {
    let capacity = this.bytes.length ? this.bytes.length * 2 : this.initialCapacity
    while (capacity < needed)
      capacity *= 2

    const next = new Uint8Array(capacity)
    if (this.length)
      next.set(this.bytes.subarray(0, this.length))
    this.bytes = next
  }

  ensure(extra: number): void {
    const needed = this.length + extra
    if (needed > this.bytes.length)
      this.grow(needed)
  }

  writeByte(byte: number): void {
    if (this.length >= this.bytes.length)
      this.grow(this.length + 1)
    this.bytes[this.length++] = byte
  }

  write(chunk: Uint8Array, start = 0, end = chunk.length): void {
    const count = end - start
    if (count <= 0)
      return
    this.ensure(count)
    this.bytes.set(chunk.subarray(start, end), this.length)
    this.length += count
  }

  /** Exact sized copy of everything written so far. */
  toArrayBuffer(): ArrayBuffer {
    return this.bytes.buffer.slice(0, this.length) as ArrayBuffer
  }

  toUint8Array(): Uint8Array {
    return this.bytes.slice(0, this.length)
  }
}

export const textEncoder: TextEncoder = new TextEncoder()

// ignoreBOM so that a U+FEFF at the start of a line is kept as a character instead of
// being swallowed. A stripped BOM turns a line a strict parser skips into a genuine
// header, which is how a second `From:` gets smuggled past anything that inspects the
// raw message.
const utf8Decoder = new TextDecoder('utf-8', { ignoreBOM: true })

/**
 * Decodes a header line.
 *
 * Straight to TextDecoder, even for the short ASCII lines that make up most headers.
 * Building the string from char codes instead, which avoids the decoder's fixed per
 * call cost, measures an order of magnitude slower on Bun: the native decode is hard to
 * beat from JavaScript at any length.
 */
export function decodeHeaderLine(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes)
}
