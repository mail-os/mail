/**
 * Quoted-printable decoding.
 */

import { ByteWriter } from './bytes'

const CHR_EQUALS = 0x3D
const CHR_LF = 0x0A

/**
 * Numeric value of an ASCII hex digit, or -1 when the byte is not one.
 */
export function hexNibble(c: number): number {
  if (c >= 0x30 /* 0 */ && c <= 0x39 /* 9 */)
    return c - 0x30
  if (c >= 0x61 /* a */ && c <= 0x66 /* f */)
    return c - 0x61 + 10
  if (c >= 0x41 /* A */ && c <= 0x46 /* F */)
    return c - 0x41 + 10
  return -1
}

export class QPDecoder {
  private out: ByteWriter

  constructor(sizeHint?: number) {
    this.out = new ByteWriter(sizeHint)
  }

  /**
   * Copies a run of literal bytes.
   *
   * `TypedArray.set` needs a view of the source range, and allocating that view costs
   * more than the copy itself for the short runs between two escape sequences. Encoded
   * text is mostly short runs, so anything under a cache line is copied by hand.
   */
  private copyRun(dest: Uint8Array, line: Uint8Array, start: number, end: number, at: number): number {
    const length = end - start
    if (length <= 0)
      return at

    if (length < 64) {
      for (let i = start; i < end; i++)
        dest[at++] = line[i]
      return at
    }

    dest.set(line.subarray(start, end), at)
    return at + length
  }

  /**
   * Quoted-printable source is 7 bit by definition, so it is decoded byte by byte and
   * the result is handed on as bytes. Running the body charset over the encoded source
   * instead corrupts every part whose charset is not ASCII compatible: the same content
   * that decodes correctly in base64 comes out as mojibake in quoted-printable.
   */
  update(line: Uint8Array): void {
    let len = line.length

    // a line ending in '=' is a soft line break, the newline is not part of the content
    const softBreak = len > 0 && line[len - 1] === CHR_EQUALS
    if (softBreak)
      len--

    const out = this.out
    out.ensure(len + 1)
    const dest = out.bytes
    let p = out.length

    let literalStart = 0
    for (let i = 0; i < len; i++) {
      if (line[i] !== CHR_EQUALS || i + 2 >= len)
        continue

      const high = hexNibble(line[i + 1])
      const low = hexNibble(line[i + 2])
      if (high < 0 || low < 0) {
        // not a valid escape sequence, keep it as literal text
        continue
      }

      p = this.copyRun(dest, line, literalStart, i, p)
      dest[p++] = (high << 4) | low
      i += 2
      literalStart = i + 1
    }

    p = this.copyRun(dest, line, literalStart, len, p)

    if (!softBreak)
      dest[p++] = CHR_LF

    out.length = p
  }

  finalize(): ArrayBuffer {
    return this.out.toArrayBuffer()
  }
}

/** Body decoder for parts that carry no transfer encoding. */
export class PassThroughDecoder {
  private out: ByteWriter

  constructor(sizeHint?: number) {
    this.out = new ByteWriter(sizeHint)
  }

  update(line: Uint8Array): void {
    const out = this.out
    out.ensure(line.length + 1)
    out.bytes.set(line, out.length)
    out.length += line.length
    out.bytes[out.length++] = CHR_LF
  }

  finalize(): ArrayBuffer {
    return this.out.toArrayBuffer()
  }
}

export interface ContentDecoder {
  update: (line: Uint8Array) => void
  finalize: () => ArrayBuffer
}
