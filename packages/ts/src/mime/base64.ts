/**
 * Base64 decoding and encoding.
 *
 * The streaming decoder reads the encoded body as bytes. Decoding each line to a
 * string, stripping the non alphabet characters with a regex and carrying the
 * remainder as a string, which is the usual shape, allocates two strings per line and
 * copies the whole payload several times over before a single byte is produced.
 */

import { ByteWriter } from './bytes'

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const INVALID = 0xFF
const PADDING = 0xFE

// Byte -> 6 bit value, with everything outside the alphabet marked so the stream
// decoder can skip line breaks and stray characters without a regex pass.
const byteLookup = new Uint8Array(256).fill(INVALID)
for (let i = 0; i < BASE64_CHARS.length; i++)
  byteLookup[BASE64_CHARS.charCodeAt(i)] = i
byteLookup[0x3D /* = */] = PADDING

// Character -> 6 bit value for whole-string decoding, where anything unknown reads as
// zero. Encoded words are stripped of non alphabet characters before they get here, so
// the only way to land on an unknown character is a stray '=' inside the payload, and
// treating it as a zero bit group keeps the surrounding text decodable.
const charLookup = new Uint8Array(256)
for (let i = 0; i < BASE64_CHARS.length; i++)
  charLookup[BASE64_CHARS.charCodeAt(i)] = i

/**
 * Decodes a complete base64 string.
 *
 * @param base64 Base64 payload, already stripped of characters outside the alphabet
 */
export function decodeBase64(base64: string): ArrayBuffer {
  // Padding carries no data, so the byte count comes from the payload alone. Sizing the
  // buffer from the raw length instead treats '=' as a data character and leaves the
  // output padded with NUL bytes, which then travel into subjects and filenames.
  let len = base64.length
  while (len > 0 && base64.charCodeAt(len - 1) === 0x3D)
    len--

  // A remainder of one character cannot encode a byte, it is a truncated group
  if (len % 4 === 1)
    len--

  const remainder = len % 4
  const bufferLength = Math.floor(len / 4) * 3 + (remainder ? remainder - 1 : 0)

  const arrayBuffer = new ArrayBuffer(bufferLength)
  const bytes = new Uint8Array(arrayBuffer)

  let p = 0
  for (let i = 0; i < len; i += 4) {
    const encoded1 = charLookup[base64.charCodeAt(i) & 0xFF]
    const encoded2 = charLookup[base64.charCodeAt(i + 1) & 0xFF]
    const encoded3 = charLookup[base64.charCodeAt(i + 2) & 0xFF]
    const encoded4 = charLookup[base64.charCodeAt(i + 3) & 0xFF]

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4)
    if (p < bufferLength)
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2)
    if (p < bufferLength)
      bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63)
  }

  return arrayBuffer
}

/**
 * Streaming base64 body decoder.
 *
 * Fed one body line at a time, it keeps at most three 6 bit values of carry between
 * lines and writes decoded bytes straight into the output buffer.
 */
export class Base64Decoder {
  private out: ByteWriter
  private c0 = 0
  private c1 = 0
  private c2 = 0
  private carry = 0

  constructor(sizeHint?: number) {
    this.out = new ByteWriter(sizeHint)
  }

  /**
   * '=' terminates a base64 unit. Some mailers pad every line, and treating the padding
   * as a character to skip concatenates the units, which knocks everything after the
   * first embedded pad out of 4 character alignment and decodes it to garbage.
   */
  private flushCarry(dest: Uint8Array, p: number): number {
    switch (this.carry) {
      // A single leftover 6 bit value is a truncated group and encodes no byte
      case 2:
        dest[p++] = (this.c0 << 2) | (this.c1 >> 4)
        break
      case 3:
        dest[p++] = (this.c0 << 2) | (this.c1 >> 4)
        dest[p++] = ((this.c1 & 15) << 4) | (this.c2 >> 2)
        break
    }
    this.carry = 0
    return p
  }

  update(line: Uint8Array): void {
    const len = line.length
    const out = this.out
    // Worst case every byte in the line is a base64 character and the carry is full
    out.ensure((((len + 3) * 3) >> 2) + 3)

    const dest = out.bytes
    let p = out.length

    let c0 = this.c0
    let c1 = this.c1
    let c2 = this.c2
    let carry = this.carry

    for (let i = 0; i < len; i++) {
      const value = byteLookup[line[i]]

      if (value === INVALID)
        continue

      if (value === PADDING) {
        this.c0 = c0
        this.c1 = c1
        this.c2 = c2
        this.carry = carry
        p = this.flushCarry(dest, p)
        carry = 0
        continue
      }

      switch (carry) {
        case 0:
          c0 = value
          carry = 1
          break
        case 1:
          c1 = value
          carry = 2
          break
        case 2:
          c2 = value
          carry = 3
          break
        default:
          dest[p++] = (c0 << 2) | (c1 >> 4)
          dest[p++] = ((c1 & 15) << 4) | (c2 >> 2)
          dest[p++] = ((c2 & 3) << 6) | value
          carry = 0
          break
      }
    }

    this.c0 = c0
    this.c1 = c1
    this.c2 = c2
    this.carry = carry
    out.length = p
  }

  finalize(): ArrayBuffer {
    const out = this.out
    out.ensure(2)
    out.length = this.flushCarry(out.bytes, out.length)
    return out.toArrayBuffer()
  }
}

// Encoding 3 bytes at a time into a string with `+=` reallocates the string on every
// group. Collecting char codes and converting a chunk at a time keeps it linear.
const ENCODE_CHUNK = 3 * 4096

function encodeBase64Portable(bytes: Uint8Array): string {
  let result = ''
  const codes: number[] = []

  for (let offset = 0; offset < bytes.length; offset += ENCODE_CHUNK) {
    const end = Math.min(offset + ENCODE_CHUNK, bytes.length)
    codes.length = 0

    let i = offset
    for (; i + 2 < end; i += 3) {
      const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
      codes.push(
        BASE64_CHARS.charCodeAt((chunk >> 18) & 63),
        BASE64_CHARS.charCodeAt((chunk >> 12) & 63),
        BASE64_CHARS.charCodeAt((chunk >> 6) & 63),
        BASE64_CHARS.charCodeAt(chunk & 63),
      )
    }

    // The tail is only padded on the final chunk, every other chunk is a multiple of 3
    const remaining = end - i
    if (remaining === 1) {
      const chunk = bytes[i]
      codes.push(
        BASE64_CHARS.charCodeAt(chunk >> 2),
        BASE64_CHARS.charCodeAt((chunk & 3) << 4),
        0x3D,
        0x3D,
      )
    }
    else if (remaining === 2) {
      const chunk = (bytes[i] << 8) | bytes[i + 1]
      codes.push(
        BASE64_CHARS.charCodeAt(chunk >> 10),
        BASE64_CHARS.charCodeAt((chunk >> 4) & 63),
        BASE64_CHARS.charCodeAt((chunk & 15) << 2),
        0x3D,
      )
    }

    result += String.fromCharCode.apply(null, codes)
  }

  return result
}

// Buffer's base64 encoder is native, so it is used where it exists (Bun, Node) and the
// portable encoder covers browsers and workers.
const nodeBuffer = (globalThis as { Buffer?: { from: (input: Uint8Array) => { toString: (encoding: string) => string } } }).Buffer

/** Encodes a buffer as standard, padded base64. */
export function encodeBase64(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input)

  if (nodeBuffer)
    return nodeBuffer.from(bytes).toString('base64')

  return encodeBase64Portable(bytes)
}
