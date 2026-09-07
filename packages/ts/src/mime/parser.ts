/**
 * The MIME parser.
 *
 * Parsing is a synchronous pass over the raw bytes. The public `parse` stays async, so
 * that a stream or a Blob can be resolved first and so the API matches what callers of
 * an email parser expect, but nothing inside it awaits per line or per part: a parser
 * that awaits every line pays for a promise and a microtask turn on each one, which on
 * a large message costs more than all of the decoding put together.
 */

import type { MimeNodeHost } from './mime-node'
import type {
  Address,
  Attachment,
  AttachmentEncoding,
  Email,
  Mailbox,
  MimeParserOptions,
  RawEmail,
} from './types'
import { addressParser } from './address-parser'
import { encodeBase64 } from './base64'
import { textEncoder } from './bytes'
import { decodeWords } from './decode-strings'
import { MimeNode } from './mime-node'
import { formatHtmlHeader, formatTextHeader, htmlToText, textToHtml } from './text-format'

const MAX_NESTING_DEPTH = 256
const MAX_HEADERS_SIZE = 2 * 1024 * 1024

// Inline message/rfc822 parts are parsed recursively. Without a dedicated limit each
// nesting level spawns a new parser that retains the full nested message, so a small
// crafted email can exhaust memory. Cap the recursion and treat deeper nested messages
// as regular attachments instead.
const MAX_RFC822_NESTING_DEPTH = 10

const CHR_LF = 0x0A
const CHR_CR = 0x0D
const CHR_DASH = 0x2D
const CHR_TAB = 0x09
const CHR_SPACE = 0x20

function toCamelCase(key: string): string {
  return key.replace(/-(.)/g, match => match.charAt(1).toUpperCase())
}

/**
 * Limit options are validated rather than falsy-coalesced. `0` would silently restore
 * the default, and a string or NaN would disable the limit altogether, because every
 * `size > limit` comparison against such a value is false. A caller that forwards a
 * request supplied options object would otherwise hand an attacker a way to turn the
 * limits off.
 */
function parseLimitOption(value: unknown, defaultValue: number, name: string): number {
  if (value === undefined || value === null)
    return defaultValue

  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0)
    throw new TypeError(`${name} must be a non-negative integer`)

  return value
}

type TextType = 'html' | 'plain' | string

interface TextEntryText {
  type: 'text'
  value: string
}

interface TextEntrySubMessage {
  type: 'subMessage'
  value: Email
}

type TextEntryValue = TextEntryText | TextEntrySubMessage
type TextEntry = Record<TextType, TextEntryValue[]>

interface Boundary {
  value: Uint8Array
  node: MimeNode
}

export class MimeParser implements MimeNodeHost {
  private options: MimeParserOptions
  private mimeOptions: { maxNestingDepth: number, maxHeadersSize: number }
  private maxRfc822NestingDepth: number
  private rfc822NestingDepth: number
  private root: MimeNode
  private currentNode: MimeNode
  private attachmentEncoding: AttachmentEncoding
  private started = false
  private attachments: Attachment[] = []
  private textContent: Record<string, string> = {}
  private textMap: Map<MimeNode, TextEntry> | null = null

  /** Boundaries of every multipart currently open, innermost last */
  boundaries: Boundary[] = []
  /** Header bytes seen across every part of this message, see MimeNode.feed */
  headerSize = 0

  /**
   * `rfc822NestingDepth` is internal state that nested parsers receive from their
   * parent. It is deliberately a separate argument rather than an option, so that
   * forwarding a caller supplied options object can not seed it and switch the recursion
   * limit off.
   */
  constructor(options?: MimeParserOptions, rfc822NestingDepth = 0) {
    this.options = options || {}

    this.mimeOptions = {
      maxNestingDepth: parseLimitOption(this.options.maxNestingDepth, MAX_NESTING_DEPTH, 'maxNestingDepth'),
      maxHeadersSize: parseLimitOption(this.options.maxHeadersSize, MAX_HEADERS_SIZE, 'maxHeadersSize'),
    }

    // A limit of 0 disables inline parsing entirely, so every message/rfc822 part
    // becomes an attachment.
    this.maxRfc822NestingDepth = parseLimitOption(
      this.options.maxRfc822NestingDepth,
      MAX_RFC822_NESTING_DEPTH,
      'maxRfc822NestingDepth',
    )
    this.rfc822NestingDepth = rfc822NestingDepth

    this.root = this.currentNode = new MimeNode({ host: this, ...this.mimeOptions })

    this.attachmentEncoding = ((this.options.attachmentEncoding || '')
      .toString()
      .replace(/[\s_-]/g, '')
      .trim()
      .toLowerCase() || 'arraybuffer') as AttachmentEncoding
  }

  /** Parses an email and resolves with the structured message. */
  static async parse(email: RawEmail, options?: MimeParserOptions): Promise<Email> {
    // async, so that an invalid option rejects the returned promise instead of throwing
    // synchronously and escaping a `.catch()` chain
    const parser = new MimeParser(options)
    return parser.parse(email)
  }

  /** Parses an email that is already in memory, without going through a promise. */
  static parseSync(email: string | ArrayBuffer | ArrayBufferView, options?: MimeParserOptions): Email {
    const parser = new MimeParser(options)
    return parser.parseSync(email)
  }

  private processLine(line: Uint8Array, isFinal: boolean): void {
    const boundaries = this.boundaries

    // check if this is a mime boundary
    if (boundaries.length && line.length > 2 && line[0] === CHR_DASH && line[1] === CHR_DASH) {
      for (let i = boundaries.length - 1; i >= 0; i--) {
        const boundary = boundaries[i]
        const value = boundary.value
        const valueLength = value.length

        // Line must be at least long enough for "--" + boundary
        if (line.length < valueLength + 2)
          continue

        let boundaryMatches = true
        for (let j = 0; j < valueLength; j++) {
          if (line[j + 2] !== value[j]) {
            boundaryMatches = false
            break
          }
        }
        if (!boundaryMatches)
          continue

        // Check for the terminator (-- after the boundary) and where the boundary ends
        let boundaryEnd = valueLength + 2
        let isTerminator = false

        if (
          line.length >= valueLength + 4
          && line[valueLength + 2] === CHR_DASH
          && line[valueLength + 3] === CHR_DASH
        ) {
          isTerminator = true
          boundaryEnd = valueLength + 4
        }

        // RFC 2046: a boundary line may carry trailing whitespace before the CRLF
        let hasValidTrailing = true
        for (let j = boundaryEnd; j < line.length; j++) {
          if (line[j] !== CHR_SPACE && line[j] !== CHR_TAB) {
            hasValidTrailing = false
            break
          }
        }
        if (!hasValidTrailing)
          continue

        if (isTerminator) {
          boundary.node.finalize()
          this.currentNode = boundary.node.parentNode || this.root
        }
        else {
          // finalize any open child nodes (there should be just the one)
          boundary.node.finalizeChildNodes()

          this.currentNode = new MimeNode({
            host: this,
            parentNode: boundary.node,
            parentMultipartType: boundary.node.contentType.multipart,
            ...this.mimeOptions,
          })
        }

        if (isFinal)
          this.root.finalize()

        return
      }
    }

    this.currentNode.feed(line)

    if (isFinal)
      this.root.finalize()
  }

  /**
   * Splits the message into lines and feeds them to the current part.
   *
   * The scan for the line feed is a single native search per line rather than a
   * character at a time loop, and each line is a view into the source buffer, so a
   * message is never copied just to be split.
   */
  private readLines(bytes: Uint8Array): void {
    const len = bytes.length
    let pos = 0

    while (pos < len) {
      const lf = bytes.indexOf(CHR_LF, pos)
      const next = lf < 0 ? len : lf + 1

      let end = next
      while (end > pos) {
        const code = bytes[end - 1]
        if (code !== CHR_CR && code !== CHR_LF)
          break
        end--
      }

      this.processLine(bytes.subarray(pos, end), next >= len)
      pos = next
    }
  }

  private isInlineTextNode(node: MimeNode): boolean {
    if (node.contentDisposition.parsed?.value === 'attachment') {
      // no matter the type, this is an attachment
      return false
    }

    switch (node.contentType.parsed?.value) {
      case 'text/html':
      case 'text/plain':
        return true
      default:
        return false
    }
  }

  private isInlineMessageRfc822(node: MimeNode): boolean {
    if (node.contentType.parsed?.value !== 'message/rfc822')
      return false

    const disposition = node.contentDisposition.parsed?.value
      || (this.options.rfc822Attachments ? 'attachment' : 'inline')

    return disposition === 'inline'
  }

  /**
   * Report emails carry the original message as a `message/rfc822` part that belongs in
   * the attachment list rather than in the body text.
   */
  private forceRfc822Attachments(): boolean {
    if (this.options.forceRfc822Attachments)
      return true

    let force = false
    const walk = (node: MimeNode): void => {
      if (!node.contentType.multipart) {
        const value = node.contentType.parsed?.value
        if (value === 'message/delivery-status' || value === 'message/feedback-report')
          force = true
      }

      for (const childNode of node.childNodes)
        walk(childNode)
    }
    walk(this.root)

    return force
  }

  private processNodeTree(): void {
    const textContent: Record<string, string[]> = {}

    const textTypes = new Set<TextType>()
    const textMap = this.textMap = new Map<MimeNode, TextEntry>()

    const forceRfc822Attachments = this.forceRfc822Attachments()

    const walk = (node: MimeNode, alternative: MimeNode | false, related: MimeNode | false): void => {
      if (!node.contentType.multipart) {
        const inlineRfc822 = this.isInlineMessageRfc822(node) && !forceRfc822Attachments
        const rfc822DepthExceeded = inlineRfc822 && this.rfc822NestingDepth >= this.maxRfc822NestingDepth

        // is it an inline message/rfc822
        if (inlineRfc822 && !rfc822DepthExceeded) {
          const subParser = new MimeParser(
            {
              // Only the limits are inherited. Options that decide how a part is
              // classified stay with the parser that was configured.
              ...this.mimeOptions,
              maxRfc822NestingDepth: this.maxRfc822NestingDepth,
              // attachments are encoded by the parent parser, keep raw buffers here
              attachmentEncoding: 'arraybuffer',
            },
            this.rfc822NestingDepth + 1,
          )

          const subMessage = subParser.parseSync(node.content || new ArrayBuffer(0))
          node.subMessage = subMessage

          let textEntry = textMap.get(node)
          if (!textEntry) {
            textEntry = {}
            textMap.set(node, textEntry)
          }

          // default to text if there is no content
          if (subMessage.text || !subMessage.html) {
            textEntry.plain = textEntry.plain || []
            textEntry.plain.push({ type: 'subMessage', value: subMessage })
            textTypes.add('plain')
          }

          if (subMessage.html) {
            textEntry.html = textEntry.html || []
            textEntry.html.push({ type: 'subMessage', value: subMessage })
            textTypes.add('html')
          }

          if (subParser.textMap) {
            subParser.textMap.forEach((subTextEntry, subTextNode) => {
              textMap.set(subTextNode, subTextEntry)
            })
          }

          for (const attachment of subMessage.attachments || [])
            this.attachments.push(attachment)
        }

        // is it text?
        else if (this.isInlineTextNode(node)) {
          const typeValue = node.contentType.parsed.value as string
          const textType = typeValue.slice(typeValue.indexOf('/') + 1)

          const selectorNode = alternative || node
          let textEntry = textMap.get(selectorNode)
          if (!textEntry) {
            textEntry = {}
            textMap.set(selectorNode, textEntry)
          }

          textEntry[textType] = textEntry[textType] || []
          textEntry[textType].push({ type: 'text', value: node.getTextContent() })
          textTypes.add(textType)
        }

        // is it an attachment
        else if (node.content) {
          const filename = node.contentDisposition.parsed?.params?.filename
            || node.contentType.parsed.params.name
            || null

          const attachment: Attachment = {
            filename: filename ? decodeWords(filename) : null,
            mimeType: (node.contentType.parsed.value || '') as string,
            disposition: (node.contentDisposition.parsed?.value || null) as Attachment['disposition'],
            content: node.content,
          }

          // A nested message that was not parsed is not a renderable inline resource, so
          // it must not join the cid map behind an <img src>.
          if (related && node.contentId && !rfc822DepthExceeded)
            attachment.related = true

          if (rfc822DepthExceeded) {
            // Tell the caller this part would have been parsed inline but hit
            // maxRfc822NestingDepth, so anything inside it is not reflected in
            // email.text, email.html or email.attachments.
            attachment.rfc822DepthExceeded = true
          }

          if (node.contentDescription) {
            // decoded like the filename, it is an unstructured header that may carry
            // encoded words
            attachment.description = decodeWords(node.contentDescription)
          }

          if (node.contentId)
            attachment.contentId = node.contentId

          switch (node.contentType.parsed.value) {
            // Special handling for calendar events
            case 'text/calendar':
            case 'application/ics': {
              const method = node.contentType.parsed.params.method
              if (method)
                attachment.method = method.toString().toUpperCase().trim()

              // Enforce into unicode
              const decodedText = node.getTextContent().replace(/\r?\n/g, '\n').replace(/\n*$/, '\n')
              attachment.content = textEncoder.encode(decodedText)
              break
            }
          }

          this.attachments.push(attachment)
        }
      }
      else if (node.contentType.multipart === 'alternative') {
        alternative = node
      }
      else if (node.contentType.multipart === 'related') {
        related = node
      }

      for (const childNode of node.childNodes)
        walk(childNode, alternative, related)
    }

    walk(this.root, false, false)

    textMap.forEach((mapEntry) => {
      textTypes.forEach((textType) => {
        if (!textContent[textType])
          textContent[textType] = []

        const entries = mapEntry[textType]
        if (entries) {
          for (const textEntry of entries) {
            if (textEntry.type === 'text')
              textContent[textType].push(textEntry.value)
            else if (textType === 'html')
              textContent[textType].push(formatHtmlHeader(textEntry.value))
            else if (textType === 'plain')
              textContent[textType].push(formatTextHeader(textEntry.value))
          }
          return
        }

        // No content of this type in this part, so it is generated from the alternative
        const alternativeType = textType === 'html' ? 'plain' : textType === 'plain' ? 'html' : undefined
        const alternativeEntries = alternativeType ? mapEntry[alternativeType] : undefined

        for (const textEntry of alternativeEntries || []) {
          if (textEntry.type === 'text') {
            if (textType === 'html')
              textContent[textType].push(textToHtml(textEntry.value))
            else if (textType === 'plain')
              textContent[textType].push(htmlToText(textEntry.value))
          }
          else if (textType === 'html') {
            textContent[textType].push(formatHtmlHeader(textEntry.value))
          }
          else if (textType === 'plain') {
            textContent[textType].push(formatTextHeader(textEntry.value))
          }
        }
      })
    })

    const joined: Record<string, string> = {}
    for (const textType of Object.keys(textContent))
      joined[textType] = textContent[textType].join('\n')

    this.textContent = joined
  }

  private async resolveStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
    let chunkLen = 0
    const chunks: Uint8Array[] = []
    const reader = stream.getReader()

    while (true) {
      const { done, value } = await reader.read()
      if (done)
        break
      chunks.push(value)
      chunkLen += value.length
    }

    const result = new Uint8Array(chunkLen)
    let pointer = 0
    for (const chunk of chunks) {
      result.set(chunk, pointer)
      pointer += chunk.length
    }

    return result
  }

  /** Parses an email, resolving a stream or a Blob first if it is given one. */
  async parse(email: RawEmail): Promise<Email> {
    let input = email as unknown

    // Resolve a readable stream into bytes
    if (input && typeof (input as ReadableStream<Uint8Array>).getReader === 'function')
      input = await this.resolveStream(input as ReadableStream<Uint8Array>)

    // Resolve a Blob into bytes
    if (input instanceof Blob || Object.prototype.toString.call(input) === '[object Blob]')
      input = await (input as Blob).arrayBuffer()

    return this.parseSync(input as string | ArrayBuffer | ArrayBufferView)
  }

  /** Parses an email that is already in memory. */
  parseSync(email: string | ArrayBuffer | ArrayBufferView | null | undefined): Email {
    if (this.started)
      throw new Error('Can not reuse parser, create a new MimeParser object')
    this.started = true

    let bytes: Uint8Array

    if (typeof email === 'string') {
      bytes = textEncoder.encode(email)
    }
    else if (!email) {
      bytes = new Uint8Array(0)
    }
    else if (ArrayBuffer.isView(email)) {
      // A DataView is not an array-like, so `new Uint8Array(view)` would produce an
      // empty buffer and the message would parse to nothing without an error. Reading
      // through byteOffset also keeps views over a larger buffer from reading their
      // neighbours.
      bytes = new Uint8Array(email.buffer, email.byteOffset, email.byteLength)
    }
    else {
      bytes = new Uint8Array(email)
    }

    this.readLines(bytes)

    // A message that never reached a final line, eg. an empty one, still has open nodes
    this.root.finalize()

    this.processNodeTree()

    return this.buildMessage()
  }

  private buildMessage(): Email {
    const headers = this.root.headers

    // The node's header entries are already exactly the public shape, and the node is
    // discarded with the parser, so they are handed over rather than copied
    const message: Email = { headers } as Email

    // A single pass over the headers. Looking each field up with `find` walks the whole
    // list again for every one of them, and a message with a long Received chain carries
    // hundreds of entries.
    let fromHeader: string | undefined
    let senderHeader: string | undefined
    let deliveredToHeader: string | undefined
    let returnPathHeader: string | undefined
    let subjectHeader: string | undefined
    let messageIdHeader: string | undefined
    let inReplyToHeader: string | undefined
    let referencesHeader: string | undefined
    let dateHeader: string | undefined
    let toValues: string[] | undefined
    let ccValues: string[] | undefined
    let bccValues: string[] | undefined
    let replyToValues: string[] | undefined

    // The first occurrence of a header wins, matching how the content headers resolve
    const first = (current: string | undefined, value: string): string | undefined =>
      current === undefined ? value : current

    for (const header of headers) {
      switch (header.key) {
        case 'from':
          fromHeader = first(fromHeader, header.value)
          break
        case 'sender':
          senderHeader = first(senderHeader, header.value)
          break
        case 'delivered-to':
          deliveredToHeader = first(deliveredToHeader, header.value)
          break
        case 'return-path':
          returnPathHeader = first(returnPathHeader, header.value)
          break
        case 'subject':
          subjectHeader = first(subjectHeader, header.value)
          break
        case 'message-id':
          messageIdHeader = first(messageIdHeader, header.value)
          break
        case 'in-reply-to':
          inReplyToHeader = first(inReplyToHeader, header.value)
          break
        case 'references':
          referencesHeader = first(referencesHeader, header.value)
          break
        case 'date':
          dateHeader = first(dateHeader, header.value)
          break
        case 'to':
          if (header.value)
            (toValues = toValues || []).push(header.value)
          break
        case 'cc':
          if (header.value)
            (ccValues = ccValues || []).push(header.value)
          break
        case 'bcc':
          if (header.value)
            (bccValues = bccValues || []).push(header.value)
          break
        case 'reply-to':
          if (header.value)
            (replyToValues = replyToValues || []).push(header.value)
          break
      }
    }

    if (fromHeader) {
      const addresses = addressParser(fromHeader)
      if (addresses.length)
        message.from = addresses[0]
    }

    if (senderHeader) {
      const addresses = addressParser(senderHeader)
      if (addresses.length)
        message.sender = addresses[0]
    }

    if (deliveredToHeader) {
      const addresses = addressParser(deliveredToHeader)
      if (addresses.length && (addresses[0] as Mailbox).address)
        message.deliveredTo = (addresses[0] as Mailbox).address
    }

    if (returnPathHeader) {
      const addresses = addressParser(returnPathHeader)
      if (addresses.length && (addresses[0] as Mailbox).address)
        message.returnPath = (addresses[0] as Mailbox).address
    }

    const collect = (values: string[] | undefined): Address[] | undefined => {
      if (!values)
        return undefined
      let addresses: Address[] = []
      for (const value of values)
        addresses = addresses.concat(addressParser(value) || [])
      return addresses.length ? addresses : undefined
    }

    const to = collect(toValues)
    if (to)
      message.to = to

    const cc = collect(ccValues)
    if (cc)
      message.cc = cc

    const bcc = collect(bccValues)
    if (bcc)
      message.bcc = bcc

    const replyTo = collect(replyToValues)
    if (replyTo)
      message.replyTo = replyTo

    if (subjectHeader)
      message.subject = decodeWords(subjectHeader)

    if (messageIdHeader)
      message.messageId = decodeWords(messageIdHeader)

    if (inReplyToHeader)
      message.inReplyTo = decodeWords(inReplyToHeader)

    if (referencesHeader)
      message.references = decodeWords(referencesHeader)

    if (dateHeader !== undefined) {
      const date = new Date(dateHeader)
      // enforce ISO format when the header holds something that parses as a date
      message.date = Number.isNaN(date.getTime()) ? dateHeader : date.toISOString()
    }

    if (this.textContent.html)
      message.html = this.textContent.html

    if (this.textContent.plain)
      message.text = this.textContent.plain

    message.attachments = this.attachments

    // Expose the raw header lines, in the same order as the headers array
    message.headerLines = this.root.rawHeaderLines.slice()

    switch (this.attachmentEncoding) {
      case 'arraybuffer':
        break

      case 'base64':
        for (const attachment of message.attachments) {
          if (attachment.content) {
            attachment.content = encodeBase64(attachment.content as ArrayBuffer | Uint8Array)
            attachment.encoding = 'base64'
          }
        }
        break

      case 'utf8': {
        const attachmentDecoder = new TextDecoder('utf8')
        for (const attachment of message.attachments) {
          if (attachment.content) {
            attachment.content = attachmentDecoder.decode(attachment.content as ArrayBuffer)
            attachment.encoding = 'utf8'
          }
        }
        break
      }

      default:
        throw new Error('Unknown attachment encoding')
    }

    return message
  }
}

export default MimeParser
