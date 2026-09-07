/**
 * A MIME email parser.
 *
 * Turns a raw RFC 5322 message into its headers, addresses, text and HTML bodies and
 * attachments.
 *
 * ```ts
 * import { parseEmail } from '@stacksjs/mail/mime'
 *
 * const email = await parseEmail(raw)
 * console.log(email.subject, email.from, email.attachments.length)
 * ```
 */

import type { Email, MimeParserOptions, RawEmail } from './types'
import { MimeParser } from './parser'

export { addressParser } from './address-parser'
export { Base64Decoder } from './base64'
export { decodeBase64, encodeBase64 } from './base64'
export { getDecoder } from './charsets'
export { decodeWord, decodeWords } from './decode-strings'
export { isEncodedWordsOnly } from './decode-strings'
export { MimeNode } from './mime-node'
export { MimeParser } from './parser'
export { PassThroughDecoder, QPDecoder } from './qp'
export { escapeHtml, htmlToText, textToHtml } from './text-format'
export { decodeHTMLEntities } from './text-format'
export type * from './types'

/**
 * Parses a raw email.
 *
 * Accepts a string, an ArrayBuffer, a typed array, a Blob or a ReadableStream.
 */
export async function parseEmail(email: RawEmail, options?: MimeParserOptions): Promise<Email> {
  return MimeParser.parse(email, options)
}

/**
 * Parses a raw email that is already in memory, without going through a promise.
 */
export function parseEmailSync(email: string | ArrayBuffer | ArrayBufferView, options?: MimeParserOptions): Email {
  return MimeParser.parseSync(email, options)
}

export default MimeParser
