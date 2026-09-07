/**
 * A single MIME part: its headers, and the decoder that turns its body lines back into
 * bytes.
 */

import type { StructuredHeader } from './decode-strings'
import type { ContentDecoder } from './qp'
import type { Header, HeaderLine } from './types'
import { Base64Decoder } from './base64'
import { decodeHeaderLine, textEncoder } from './bytes'
import { getDecoder } from './charsets'
import { decodeParameterValueContinuations } from './decode-strings'
import { PassThroughDecoder, QPDecoder } from './qp'

export interface ParsedContentType {
  value: string | false
  params: Record<string, string>
}

export interface ContentTypeHeader {
  value: string
  parsed: ParsedContentType
  /** Subtype of a multipart part, eg. `mixed`, or false for everything else */
  multipart: string | false
}

export interface MimeNodeHost {
  boundaries: { value: Uint8Array, node: MimeNode }[]
  headerSize: number
}

export interface MimeNodeOptions {
  host: MimeNodeHost
  parentNode?: MimeNode
  parentMultipartType?: string | false
  maxNestingDepth: number
  maxHeadersSize: number
}

const CHR_TAB = 0x09
const CHR_SPACE = 0x20

// Headers that decide how this part's body is read, see processHeaders
const CONTENT_HEADERS = new Set([
  'content-type',
  'content-transfer-encoding',
  'content-disposition',
  'content-id',
  'content-description',
])

/**
 * Trims only the whitespace RFC 5322 allows around a field name.
 *
 * String.prototype.trim also strips U+00A0, U+FEFF, U+2028 and the rest of the Unicode
 * spaces, which turns a line that a strict parser rejects into a canonical field name:
 * ` From:` becomes a `from` header, and since the first occurrence of a header wins it
 * outranks the real sender. Leaving the character in the key keeps the line visible
 * without letting it collide with a genuine header.
 */
function trimWsp(str: string): string {
  let start = 0
  let end = str.length

  while (start < end) {
    const code = str.charCodeAt(start)
    if (code !== CHR_SPACE && code !== CHR_TAB)
      break
    start++
  }

  while (end > start) {
    const code = str.charCodeAt(end - 1)
    if (code !== CHR_SPACE && code !== CHR_TAB)
      break
    end--
  }

  return start === 0 && end === str.length ? str : str.slice(start, end)
}

export class MimeNode {
  private options: MimeNodeOptions
  private host: MimeNodeHost
  private state: 'header' | 'body' | 'finished' = 'header'
  private headerLines: string[] = []
  private contentDecoder: ContentDecoder | null = null

  parentNode?: MimeNode
  childNodes: MimeNode[] = []
  // Cursor into childNodes for finalizeChildNodes. Every new part of a multipart
  // finalizes its parent's children, so re-walking the whole array each time is
  // quadratic in the number of parts.
  private finalizedChildCount = 0
  depth: number

  headers: Header[] = []
  rawHeaderLines: HeaderLine[] = []

  contentType: ContentTypeHeader
  contentTransferEncoding: { value: string, encoding?: string }
  contentDisposition: { value: string, parsed?: ParsedContentType }
  contentId?: string
  contentDescription?: string

  content: ArrayBuffer | null = null
  /** Parsed message of an inlined `message/rfc822` part */
  subMessage?: unknown

  constructor(options: MimeNodeOptions) {
    this.options = options
    this.host = options.host

    if (options.parentNode) {
      this.parentNode = options.parentNode
      this.depth = this.parentNode.depth + 1
      if (this.depth > options.maxNestingDepth)
        throw new Error(`Maximum MIME nesting depth of ${options.maxNestingDepth} levels exceeded`)

      options.parentNode.childNodes.push(this)
    }
    else {
      this.depth = 0
    }

    // RFC 2046 Section 5.1.5: multipart/digest defaults to message/rfc822
    const defaultContentType = options.parentMultipartType === 'digest' ? 'message/rfc822' : 'text/plain'

    // Replaced by the first matching header, see the CONTENT_HEADERS pass in
    // processHeaders
    this.contentType = { value: defaultContentType, parsed: { value: false, params: {} }, multipart: false }
    this.contentTransferEncoding = { value: '8bit' }
    this.contentDisposition = { value: '' }
  }

  // The encoding is matched as a substring, the way mail clients do, so the vendor
  // prefixed spellings (`x-base64`, `X-quoted-printable`) that turn up in the wild still
  // reach the right decoder instead of falling through undecoded.
  private setupContentDecoder(transferEncoding: string): void {
    if (transferEncoding.includes('base64'))
      this.contentDecoder = new Base64Decoder()
    else if (transferEncoding.includes('quoted-printable'))
      this.contentDecoder = new QPDecoder()
    else
      this.contentDecoder = new PassThroughDecoder()
  }

  finalize(): void {
    if (this.state === 'finished')
      return

    if (this.state === 'header')
      this.processHeaders()

    // remove self from the boundary listing
    const boundaries = this.host.boundaries
    for (let i = boundaries.length - 1; i >= 0; i--) {
      if (boundaries[i].node === this) {
        boundaries.splice(i, 1)
        break
      }
    }

    this.finalizeChildNodes()

    this.content = this.contentDecoder ? this.contentDecoder.finalize() : null

    // The decoder holds its own copy of the body, so keeping it around retains the
    // content twice for the lifetime of the node. Nothing reads it once the node is
    // finished.
    this.contentDecoder = null

    this.state = 'finished'
  }

  finalizeChildNodes(): void {
    // Children are only ever appended, so everything before the cursor is already
    // finished and re-visiting it only costs time.
    while (this.finalizedChildCount < this.childNodes.length)
      this.childNodes[this.finalizedChildCount++].finalize()
  }

  /**
   * Strips RFC 822 comments (parenthesized text) from a structured header value.
   *
   * Inside an unquoted parameter value a parenthesis that continues the current token is
   * content, because `filename=Invoice(1).pdf` is a filename and not a token followed by
   * a comment, and deleting the parens silently renames the attachment.
   */
  stripComments(str: string): string {
    // Nothing to strip without an opening paren, and most header values have none
    if (str.indexOf('(') < 0)
      return str

    let result = ''
    let depth = 0
    let escaped = false
    let inQuote = false
    // where the outermost comment opened, for the unbalanced case below
    let commentStart = -1
    // A parameter value starts at `=` and ends at the `;` that begins the next one
    let inParameterValue = false

    // A comment may only appear where linear whitespace is allowed, so inside a
    // parameter value the parenthesis has to follow whitespace to open one. Outside one,
    // eg. after the type itself, anything goes.
    const opensComment = (): boolean => {
      if (!inParameterValue || !result.length)
        return true
      const last = result.charCodeAt(result.length - 1)
      return last === CHR_SPACE || last === CHR_TAB
    }

    for (let i = 0; i < str.length; i++) {
      const chr = str.charAt(i)

      if (escaped) {
        if (depth === 0)
          result += chr
        escaped = false
        continue
      }

      if (chr === '\\') {
        escaped = true
        if (depth === 0)
          result += chr
        continue
      }

      if (chr === '"' && depth === 0) {
        inQuote = !inQuote
        result += chr
        continue
      }

      if (!inQuote) {
        if (chr === '(' && opensComment()) {
          if (depth === 0)
            commentStart = i
          depth++
          continue
        }
        if (chr === ')' && depth > 0) {
          depth--
          continue
        }
        if (depth === 0) {
          if (chr === '=')
            inParameterValue = true
          else if (chr === ';')
            inParameterValue = false
        }
      }

      if (depth === 0)
        result += chr
    }

    if (depth === 0)
      return result

    // An unbalanced `(` is not a comment. Dropping everything after it would take any
    // parameter that follows with it, including the boundary that holds the message
    // together, so the dangling text is only discarded when nothing follows it.
    return str.indexOf(';', commentStart) < 0 ? result : str
  }

  parseStructuredHeader(str: string): ParsedContentType {
    // Strip RFC 822 comments before parsing
    str = this.stripComments(str)

    const response: StructuredHeader = { value: false, params: {} }

    let key: string | false = false
    let value = ''
    let stage: 'key' | 'value' = 'value'

    // Whitespace seen outside a quoted string is held back until a significant character
    // follows it, so surrounding whitespace can be dropped without trimming spaces the
    // sender quoted on purpose. Trimming the stored value instead loses the trailing
    // space in `filename*0="Annual Report "`, which the next continuation section is
    // meant to be appended to.
    let pendingSpace = ''
    let quoteClosed = false

    let quote: string | false = false
    let escaped = false

    const addChr = (c: string): void => {
      if (value.length)
        value += pendingSpace
      pendingSpace = ''
      value += c
    }

    const takeValue = (): string => {
      const result = value
      value = ''
      pendingSpace = ''
      quoteClosed = false
      return result
    }

    // A duplicated parameter resolves to its first occurrence, matching how duplicated
    // headers are resolved. Letting the last one win means `boundary="b"; boundary="c"`
    // registers a boundary that no delimiter in the message matches, which drops the
    // body without an error. hasOwnProperty, because a parameter may be named
    // `constructor` or `toString`.
    const storeParam = (name: string, result: string): void => {
      if (!Object.prototype.hasOwnProperty.call(response.params, name))
        response.params[name] = result
    }

    const storeValue = (): void => {
      const result = takeValue()
      if (key === false)
        response.value = result
      else
        storeParam(key, result)
    }

    // A parameter name with no `=` is a valueless parameter, not the start of the next
    // one. Without this the name would keep growing across the `;` and swallow whatever
    // followed, which is how `x=1; flag; boundary="AAA"` loses its boundary.
    const storeEmptyKey = (): void => {
      const name = takeValue().trim()
      if (name)
        storeParam(name.toLowerCase(), '')
    }

    for (let i = 0, len = str.length; i < len; i++) {
      const chr = str.charAt(i)

      if (stage === 'key') {
        if (chr === '=') {
          key = takeValue().trim().toLowerCase()
          stage = 'value'
          continue
        }
        if (chr === ';') {
          storeEmptyKey()
          continue
        }
        value += chr
        continue
      }

      if (escaped) {
        addChr(chr)
      }
      else if (quote && chr === '\\') {
        // A backslash only escapes inside a quoted string, everywhere else it is an
        // ordinary character. Treating it as an escape turns `filename=C:\Users\me\a.txt`
        // into `C:Usersmea.txt`.
        escaped = true
        continue
      }
      else if (quote && chr === quote) {
        quote = false
        quoteClosed = true
      }
      else if (!quote && chr === '"') {
        quote = chr
        // whitespace before a quote that opens the value is padding, but between a token
        // and a quoted string it is content
        if (value.length)
          value += pendingSpace
        pendingSpace = ''
      }
      else if (!quote && chr === ';') {
        storeValue()
        stage = 'key'
      }
      else if (!quote && (chr === ' ' || chr === '\t')) {
        pendingSpace += chr
      }
      else if (!quoteClosed) {
        addChr(chr)
      }
      // Anything else is trailing junk after a closed quoted string. RFC 2045 says a
      // parameter value is a token or a quoted string, not both, and appending the junk
      // is how `boundary="AAA" (unterminated comment` turns into a boundary that no
      // delimiter in the message matches.

      escaped = false
    }

    // finalize the remainder
    if (stage === 'value') {
      storeValue()
    }
    else {
      // treat as a key without a value, as in: Header-Key: somevalue; key=value; emptykey
      storeEmptyKey()
    }

    if (response.value)
      response.value = (response.value as string).toLowerCase()

    // convert Parameter Value Continuations into single strings
    decodeParameterValueContinuations(response)

    return response as ParsedContentType
  }

  decodeFlowedText(str: string, delSp: boolean): string {
    return str
      .split(/\r?\n/)
      // remove whitespace stuffing before anything else
      // http://tools.ietf.org/html/rfc3676#section-4.4
      // doing it after the join leaves the stuffed space of a continuation line sitting
      // in the middle of the joined paragraph
      .map(line => (line.charAt(0) === ' ' ? line.slice(1) : line))
      // remove soft linebreaks, which are added after space symbols
      .reduce((previousValue, currentValue) => {
        if (previousValue.endsWith(' ') && previousValue !== '-- ' && !previousValue.endsWith('\n-- ')) {
          // delsp adds space to text to be able to fold it, and those spaces can be
          // removed once the text is unfolded
          return delSp
            ? previousValue.slice(0, -1) + currentValue
            : previousValue + currentValue
        }
        return `${previousValue}\n${currentValue}`
      })
  }

  getTextContent(): string {
    if (!this.content)
      return ''

    let str = getDecoder(this.contentType.parsed.params.charset).decode(this.content)

    if (/^flowed$/i.test(this.contentType.parsed.params.format || ''))
      str = this.decodeFlowedText(str, /^yes$/i.test(this.contentType.parsed.params.delsp || ''))

    return str
  }

  processHeaders(): void {
    // First pass: group folded continuation lines with the header they belong to.
    //
    // Only SP and HTAB continue a header (RFC 5322 3.2.2 WSP). A regex `\s` also matches
    // NBSP, vertical tab, form feed and U+2028, so a line starting with one of those
    // would be absorbed into the header above it and disappear from both `headers` and
    // `headerLines` while a strict parser still sees it as a header of its own.
    //
    // Collecting into an array and joining once keeps this linear. Appending onto the
    // previous string in a backward pass re-scans the joined value on every line, which
    // is quadratic in the number of folds and lets a message that fits inside
    // maxHeadersSize burn seconds of CPU.
    const foldedLines: string[][] = []
    for (const line of this.headerLines) {
      const first = line.charCodeAt(0)
      if (foldedLines.length && (first === CHR_SPACE || first === CHR_TAB))
        foldedLines[foldedLines.length - 1].push(line)
      else
        foldedLines.push([line])
    }

    const seenContentHeaders = new Set<string>()

    // Second pass: process headers in document order
    for (const parts of foldedLines) {
      const folded = parts.length > 1
      const rawLine = folded ? parts.join('\n') : parts[0]

      // Extract the key from the raw line for rawHeaderLines
      let sep = rawLine.indexOf(':')
      const rawKey = trimWsp(sep < 0 ? rawLine : rawLine.slice(0, sep))

      this.rawHeaderLines.push({ key: rawKey.toLowerCase(), line: rawLine })

      // Unfolding removes the line break and keeps the folding whitespace, so
      // `Subject: Hello\r\n    World` stays `Hello    World`. Collapsing every whitespace
      // run instead also rewrites boundary values and filenames, and it replaces the non
      // ASCII spaces that raw UTF-8 headers (RFC 6532) may carry.
      const unfoldedLine = folded ? parts.join('') : parts[0]
      sep = folded ? unfoldedLine.indexOf(':') : sep
      const key = folded ? trimWsp(sep < 0 ? unfoldedLine : unfoldedLine.slice(0, sep)) : rawKey

      // A bare CR is not legal in a field body. Folding it into a space, which a
      // whitespace collapse would do, hands consumers that write the value back out a
      // line of their own.
      let value = ''
      if (sep >= 0) {
        value = trimWsp(unfoldedLine.slice(sep + 1))
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0)
          value = trimWsp(value.replace(/[\n\r]+/g, ' '))
      }

      const lowerKey = key.toLowerCase()
      this.headers.push({ key: lowerKey, originalKey: key, value })

      // A header that decides how the body is read must resolve the same way every time
      // it is duplicated, otherwise a message can present one Content-Type to a scanner
      // and a different one here. Every one of these takes the first occurrence and later
      // copies are ignored.
      if (CONTENT_HEADERS.has(lowerKey) && !seenContentHeaders.has(lowerKey)) {
        seenContentHeaders.add(lowerKey)

        switch (lowerKey) {
          case 'content-type':
            this.contentType = { value, parsed: { value: false, params: {} }, multipart: false }
            break
          case 'content-transfer-encoding':
            this.contentTransferEncoding = { value }
            break
          case 'content-disposition':
            this.contentDisposition = { value }
            break
          case 'content-id':
            this.contentId = value
            break
          case 'content-description':
            this.contentDescription = value
            break
        }
      }
    }

    const parsedContentType = this.parseStructuredHeader(this.contentType.value)
    this.contentType.parsed = parsedContentType

    const typeValue = parsedContentType.value
    this.contentType.multipart = typeof typeValue === 'string' && typeValue.startsWith('multipart/')
      ? typeValue.slice(typeValue.indexOf('/') + 1)
      : false

    if (this.contentType.multipart && parsedContentType.params.boundary) {
      // add self to the boundary terminator listing
      this.host.boundaries.push({
        value: textEncoder.encode(parsedContentType.params.boundary),
        node: this,
      })
    }

    this.contentDisposition.parsed = this.parseStructuredHeader(this.contentDisposition.value)

    // Take the first token rather than splitting on the first non-token character.
    // `split()` returns an empty string for anything that does not start with a word
    // character, so `(comment) base64` and `"base64"` would fall through to the pass
    // through decoder and hand the caller undecoded base64 as the message body.
    this.contentTransferEncoding.encoding = (this.stripComments(this.contentTransferEncoding.value)
      .toLowerCase()
      .match(/[\w-]+/) || [''])[0]

    this.setupContentDecoder(this.contentTransferEncoding.encoding)
  }

  feed(line: Uint8Array): void {
    if (this.state === 'header') {
      if (!line.length) {
        this.state = 'body'
        this.processHeaders()
        return
      }

      // Counted across the whole message, not per part. A per node budget lets a
      // multipart carry the limit again for every part it declares, so a message many
      // times over the limit still parses.
      this.host.headerSize += line.length

      if (this.host.headerSize > this.options.maxHeadersSize)
        throw new Error(`Maximum header size of ${this.options.maxHeadersSize} bytes exceeded`)

      this.headerLines.push(decodeHeaderLine(line))
      return
    }

    if (this.state === 'body')
      this.contentDecoder!.update(line)
  }
}

export default MimeNode
