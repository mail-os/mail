/**
 * RFC 2047 encoded words and RFC 2231 parameter value continuations.
 */

import { ByteWriter, textEncoder } from './bytes'
import { decodeBase64 } from './base64'
import { getDecoder } from './charsets'
import { hexNibble } from './qp'

const NEEDS_Q_NORMALIZATION = /[\s_]/
const IS_CLEAN_BASE64 = /^[a-z0-9+/=]*$/i

/**
 * Decodes a single encoded word payload.
 *
 * @param charset Charset label, possibly carrying an RFC 2231 language tag
 * @param encoding `Q` or `B`
 * @param str Encoded payload
 */
export function decodeWord(charset: string, encoding: string, str: string): string {
  // RFC2231 added a language tag to the encoding
  // see: https://tools.ietf.org/html/rfc2231#section-5
  // this implementation silently ignores this tag
  const splitPos = charset.indexOf('*')
  if (splitPos >= 0)
    charset = charset.slice(0, splitPos)

  const upperEncoding = encoding.toUpperCase()

  let bytes: Uint8Array

  if (upperEncoding === 'Q') {
    // Neither rewrite can change a payload that carries no whitespace and no underscore,
    // and the test is a single scan against two passes that each build a new string
    const normalized = NEEDS_Q_NORMALIZATION.test(str)
      ? str
        // remove spaces between = and hex char, this might indicate invalidly applied
        // line splitting
          .replace(/=\s+([0-9a-f])/gi, '=$1')
        // convert all underscores to spaces
          .replace(/[\s_]/g, ' ')
      : str

    const buf = textEncoder.encode(normalized)
    const len = buf.length
    const decoded = new Uint8Array(len)
    let p = 0

    for (let i = 0; i < len; i++) {
      const c = buf[i]
      if (i + 2 < len && c === 0x3D /* = */) {
        const high = hexNibble(buf[i + 1])
        const low = hexNibble(buf[i + 2])
        if (high >= 0 && low >= 0) {
          decoded[p++] = (high << 4) | low
          i += 2
          continue
        }
      }
      decoded[p++] = c
    }

    bytes = decoded.subarray(0, p)
  }
  else if (upperEncoding === 'B') {
    // Most payloads are already clean, and testing for a stray character costs one scan
    // against a scan plus a copy of the whole payload
    const clean = IS_CLEAN_BASE64.test(str) ? str : str.replace(/[^a-z0-9+/=]+/gi, '')
    bytes = new Uint8Array(decodeBase64(clean))
  }
  else {
    // keep as is, assume utf8
    bytes = textEncoder.encode(str)
  }

  return getDecoder(charset).decode(bytes)
}

// A charset label runs to the next '?' so that labels containing punctuation, eg.
// ISO_8859-1:1987, are recognised. Whitespace is excluded so a stray '=?' in running text
// can not swallow the rest of the line.
const ENCODED_WORD_PATTERN = '=\\?([^?\\s]+)\\?([QqBb])\\?([^?]*)\\?='
const ENCODED_WORD_REGEX = new RegExp(ENCODED_WORD_PATTERN, 'g')

// Only linear whitespace separates encoded words, the rest is content
const WORD_SEPARATOR_REGEX = /^[ \t\r\n]+$/

const ENCODED_WORDS_ONLY_REGEX = new RegExp(`^(?:${ENCODED_WORD_PATTERN}\\s*)+$`)

/**
 * Checks whether a string is nothing but RFC 2047 encoded words. Kept next to the
 * grammar it depends on, so the pattern has a single definition.
 */
export function isEncodedWordsOnly(str: string): boolean {
  return ENCODED_WORDS_ONLY_REGEX.test(str)
}

interface TextToken {
  text: string
  charset?: undefined
}

interface WordToken {
  text?: undefined
  charset: string
  encoding: string
  encodedText: string
}

type EncodedWordToken = TextToken | WordToken

/**
 * Splits a string into encoded words and the literal text around them.
 *
 * Working on a token list rather than marking joinable words with an in band sentinel
 * means the input can not contain the marker, which would otherwise let a sender delete
 * text from a subject or a display name by writing the marker into the header.
 */
function splitEncodedWords(str: string): EncodedWordToken[] {
  const tokens: EncodedWordToken[] = []

  ENCODED_WORD_REGEX.lastIndex = 0

  let pos = 0
  let match = ENCODED_WORD_REGEX.exec(str)

  while (match) {
    if (match.index > pos)
      tokens.push({ text: str.slice(pos, match.index) })

    tokens.push({ charset: match[1], encoding: match[2], encodedText: match[3] })
    pos = match.index + match[0].length
    match = ENCODED_WORD_REGEX.exec(str)
  }

  if (pos < str.length)
    tokens.push({ text: str.slice(pos) })

  return tokens
}

/**
 * Checks if two adjacent encoded words may be decoded as a single unit. A multi byte
 * character is often split across two words, so the bytes have to be concatenated before
 * they are decoded. Base64 additionally needs the left chunk to end on a group boundary,
 * otherwise the concatenation shifts every byte that follows.
 */
function canJoinWords(left: WordToken, right: WordToken): boolean {
  const encoding = left.encoding.toUpperCase()

  if (left.charset !== right.charset || encoding !== right.encoding.toUpperCase())
    return false

  if (encoding === 'B')
    return left.encodedText.length % 4 === 0 && !left.encodedText.endsWith('=')

  return true
}

/**
 * Decodes a token list into a string, optionally merging adjacent encoded words.
 */
function renderTokens(tokens: EncodedWordToken[], joinWords: boolean): string {
  let result = ''
  let pending: WordToken | null = null

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]

    if (token.text !== undefined) {
      // whitespace between two encoded words is a folding artifact, not content
      const nextToken = tokens[i + 1]
      if (pending && nextToken && nextToken.text === undefined && WORD_SEPARATOR_REGEX.test(token.text))
        continue

      if (pending) {
        result += decodeWord(pending.charset, pending.encoding, pending.encodedText)
        pending = null
      }
      result += token.text
      continue
    }

    if (pending && joinWords && canJoinWords(pending, token)) {
      pending.encodedText += token.encodedText
      continue
    }

    if (pending)
      result += decodeWord(pending.charset, pending.encoding, pending.encodedText)

    pending = { charset: token.charset, encoding: token.encoding, encodedText: token.encodedText }
  }

  if (pending)
    result += decodeWord(pending.charset, pending.encoding, pending.encodedText)

  return result
}

/**
 * Decodes every RFC 2047 encoded word in a header value.
 */
export function decodeWords(str: string | null | undefined): string {
  const value = (str || '').toString()

  // Most header values carry no encoded word at all, and the scan for the opening
  // delimiter is far cheaper than tokenizing the value
  if (value.indexOf('=?') < 0)
    return value

  const tokens = splitEncodedWords(value)

  const result = renderTokens(tokens, true)

  // A replacement character means the bytes did not decode, which happens when two
  // words were joined that should have stayed apart. Retry keeping them separate.
  return result.indexOf('�') < 0 ? result : renderTokens(tokens, false)
}

/**
 * Percent decodes an RFC 2231 parameter section using the charset it declares.
 */
export function decodeURIComponentWithCharset(encodedStr: string, charset?: string | false): string {
  const writer = new ByteWriter(encodedStr.length)

  for (let i = 0; i < encodedStr.length; i++) {
    const code = encodedStr.charCodeAt(i)

    if (code === 0x25 /* % */ && i + 2 < encodedStr.length) {
      const high = hexNibble(encodedStr.charCodeAt(i + 1))
      const low = hexNibble(encodedStr.charCodeAt(i + 2))
      if (high >= 0 && low >= 0) {
        writer.writeByte((high << 4) | low)
        i += 2
        continue
      }
    }

    if (code > 126)
      writer.write(textEncoder.encode(encodedStr.charAt(i)))
    else
      writer.writeByte(code)
  }

  return getDecoder(charset || 'utf-8').decode(writer.bytes.subarray(0, writer.length))
}

export interface StructuredHeader {
  value: string | false
  params: Record<string, string>
}

interface ContinuationSection {
  nr: number
  value: string
  encoded: boolean
}

interface ContinuationParam {
  charset: string | false
  values: ContinuationSection[]
}

/**
 * Converts RFC 2231 parameter value continuations into single parameter values.
 * https://tools.ietf.org/html/rfc2231#section-3
 */
export function decodeParameterValueContinuations(header: StructuredHeader): void {
  let paramKeys: Map<string, ContinuationParam> | null = null

  for (const key of Object.keys(header.params)) {
    const match = key.match(/\*((\d+)\*?)?$/)
    if (!match) {
      // nothing to do here, does not seem like a continuation param
      continue
    }

    if (!paramKeys)
      paramKeys = new Map()

    const actualKey = key.slice(0, match.index).toLowerCase()
    const nr = Number(match[2]) || 0

    let paramVal = paramKeys.get(actualKey)
    if (!paramVal) {
      paramVal = { charset: false, values: [] }
      paramKeys.set(actualKey, paramVal)
    }

    let value = header.params[key]
    // RFC 2231 section 4.1: only a section whose name ends in '*' is percent encoded.
    // A plain `name*0=` section is literal text, so decoding it invents characters
    // that never appeared on the wire, turning `a%2F..%2Fetc` into a path traversal.
    const encoded = match[0].charAt(match[0].length - 1) === '*'

    if (nr === 0 && encoded) {
      const charsetMatch = value.match(/^([^']*)'[^']*'(.*)$/)
      if (charsetMatch) {
        paramVal.charset = charsetMatch[1] || 'utf-8'
        value = charsetMatch[2]
      }
    }

    paramVal.values.push({ nr, value, encoded })

    // remove the old reference
    delete header.params[key]
  }

  if (!paramKeys)
    return

  paramKeys.forEach((paramVal, key) => {
    let result = ''
    // Adjacent encoded sections are decoded together, because a single multi byte
    // character may be percent encoded across a section boundary.
    let pending = ''

    for (const part of paramVal.values.sort((a, b) => a.nr - b.nr)) {
      if (part.encoded) {
        pending += part.value
        continue
      }
      if (pending) {
        result += decodeURIComponentWithCharset(pending, paramVal.charset)
        pending = ''
      }
      result += part.value
    }

    if (pending)
      result += decodeURIComponentWithCharset(pending, paramVal.charset)

    header.params[key] = result
  })
}
