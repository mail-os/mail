/**
 * Public types for the MIME parser.
 *
 * The shapes match what a caller of a MIME email parser expects to receive, so an
 * existing consumer can switch to this parser without rewriting the code that reads
 * the parsed message.
 */

export type RawEmail = string | ArrayBuffer | ArrayBufferView | Blob | ReadableStream<Uint8Array>

export interface Header {
  /** Lowercase header name */
  key: string
  /** Original header name, preserving case */
  originalKey: string
  /** Header value, unfolded */
  value: string
}

export interface HeaderLine {
  /** Lowercase header name */
  key: string
  /** Complete raw header line including the key, folded lines joined with `\n` */
  line: string
}

export interface Mailbox {
  name: string
  address: string
  group?: undefined
}

export interface AddressGroup {
  name: string
  address?: undefined
  group: Mailbox[]
}

export type Address = Mailbox | AddressGroup

export type AttachmentDisposition = 'attachment' | 'inline' | null

export interface Attachment {
  filename: string | null
  mimeType: string
  disposition: AttachmentDisposition
  /** Set when the part is referenced by a cid: URL from a multipart/related sibling */
  related?: boolean
  description?: string
  contentId?: string
  /** iTIP method of a text/calendar part, uppercased */
  method?: string
  /**
   * Set when a `message/rfc822` part hit `maxRfc822NestingDepth` and was emitted as an
   * attachment instead of being parsed. Its own parts are not reflected in `text`,
   * `html` or `attachments`.
   */
  rfc822DepthExceeded?: boolean
  content: ArrayBuffer | Uint8Array | string
  encoding?: 'base64' | 'utf8'
}

export interface Email {
  headers: Header[]
  headerLines: HeaderLine[]
  from?: Address
  sender?: Address
  replyTo?: Address[]
  deliveredTo?: string
  returnPath?: string
  to?: Address[]
  cc?: Address[]
  bcc?: Address[]
  subject?: string
  messageId?: string
  inReplyTo?: string
  references?: string
  date?: string
  html?: string
  text?: string
  attachments: Attachment[]
}

export type AttachmentEncoding = 'base64' | 'utf8' | 'arraybuffer'

export interface MimeParserOptions {
  /** Treat `message/rfc822` parts without a disposition as attachments */
  rfc822Attachments?: boolean
  /** Treat every `message/rfc822` part as an attachment, whatever its disposition */
  forceRfc822Attachments?: boolean
  /** How attachment content is returned, defaults to `arraybuffer` */
  attachmentEncoding?: AttachmentEncoding
  /** Maximum multipart nesting depth, defaults to 256 */
  maxNestingDepth?: number
  /** Maximum number of header bytes across the whole message, defaults to 2 MiB */
  maxHeadersSize?: number
  /** How deep `message/rfc822` parts are parsed inline, defaults to 10 */
  maxRfc822NestingDepth?: number
}

export interface AddressParserOptions {
  /** Return group members as plain mailboxes instead of nested groups */
  flatten?: boolean
}
