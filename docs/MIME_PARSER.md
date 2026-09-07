# MIME Parser

`@stacksjs/mail/mime` parses raw RFC 5322 messages: the bytes that arrive over SMTP, or
an `.eml` file on disk, become headers, addresses, a text body, an HTML body and
attachments.

It lives in `packages/ts/src/mime/` and has no dependencies.

```ts
import { parseEmail } from '@stacksjs/mail/mime'

const email = await parseEmail(await Bun.file('message.eml').bytes())

console.log(email.subject, email.from?.address, email.attachments.length)
```

## Why it exists

The mail server stores raw messages. Everything that reads them back (webmail, search
indexing, the REST API, an inbound webhook) needs the same structured view of a message,
and it needs it to be fast: indexing a mailbox parses every message in it.

The parser is a port of [postal-mime](https://github.com/postalsys/postal-mime) (MIT-0),
rewritten in TypeScript. postal-mime is the reference for behaviour, so the port is
verified against it rather than against a reading of the RFCs alone: a parity suite runs
both parsers over the same corpus and requires identical output, down to the bytes of
every attachment.

## API

| Export | What it does |
|---|---|
| `parseEmail(raw, options?)` | Parses a message, resolving a stream or Blob first. Returns `Promise<Email>` |
| `parseEmailSync(raw, options?)` | Parses a message that is already in memory. Returns `Email` |
| `MimeParser` | The parser class. `MimeParser.parse` / `MimeParser.parseSync` are the statics behind the two functions |
| `addressParser(field, options?)` | Parses an address field into mailboxes and groups |
| `decodeWords(value)` | Decodes RFC 2047 encoded words in a header value |
| `htmlToText` / `textToHtml` / `escapeHtml` / `decodeHTMLEntities` | The conversions used to synthesise a missing body view |
| `Base64Decoder` / `QPDecoder` / `PassThroughDecoder` | The streaming body decoders |
| `decodeBase64` / `encodeBase64` / `getDecoder` | Encoding helpers |
| `MimeNode` | One part of the MIME tree, for callers that walk the structure themselves |

`raw` accepts a `string`, `ArrayBuffer`, typed array, `DataView`, `Blob` or
`ReadableStream<Uint8Array>`.

### The parsed message

```ts
interface Email {
  headers: { key: string, originalKey: string, value: string }[]
  headerLines: { key: string, line: string }[]
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
```

`headers` holds unfolded values in document order; `headerLines` holds the same fields as
they were written, folds and all, for anything that needs to verify a signature or show
the raw message. `date` is ISO 8601 when the header parses as a date, and the raw header
value when it does not.

A view is only reported when the message carries it. A message with a single `text/html`
part has `html` and no `text`; a message that carries both kinds of part somewhere gets
the missing side of each part synthesised (`htmlToText` for the text view, `textToHtml`
for the HTML view).

### Options and limits

| Option | Default | Meaning |
|---|---|---|
| `attachmentEncoding` | `'arraybuffer'` | How attachment content comes back: `ArrayBuffer`, `base64` string, or `utf8` string |
| `rfc822Attachments` | `false` | Treat a `message/rfc822` part with no disposition as an attachment |
| `forceRfc822Attachments` | `false` | Never inline a nested message |
| `maxNestingDepth` | `256` | Multipart nesting limit |
| `maxHeadersSize` | `2 MiB` | Header bytes across the whole message, not per part |
| `maxRfc822NestingDepth` | `10` | How deep nested messages are parsed inline. Deeper ones become attachments flagged `rfc822DepthExceeded` |

Each limit is validated as a non-negative integer. A string, `NaN` or a negative number
throws a `TypeError`, because a limit that is not a number silently disables every
`size > limit` comparison it takes part in, and options objects are often forwarded
straight from a request.

Exceeding a limit throws: `Maximum header size of N bytes exceeded`, or
`Maximum MIME nesting depth of N levels exceeded`.

## Performance

`bun run bench:mime` from `packages/ts` runs the benchmark suite against postal-mime over
the same corpus the parity tests use: generated messages of each shape, plus real
messages (a bounce, an ARF report, a calendar invite, a MIME torture test).

On Bun 1.3.14, darwin/arm64, best of three rounds, the port is faster on all 26 cases:
the geometric mean over the 19 whole-message cases is 2.07x, attachment re-encoding is
3.2x to 4.0x, and the helper functions are 1.2x to 2.2x.

The benchmark exits non-zero if any case is not faster, so a regression fails the run
rather than hiding in a table.

### Where the difference comes from

Every one of these was measured, most of them with `bun --cpu-prof`, and several of the
obvious ideas turned out to be wrong.

**Parsing is synchronous.** The public `parse` is async so it can resolve a stream or a
Blob, but nothing inside it awaits. A parser that awaits per line pays for a promise and
a microtask turn on every line of every message, which on a large message costs more than
all of the decoding put together. `parseEmailSync` exposes the synchronous path directly.

**The body is never copied to be split.** Lines are found with one native search for the
line feed and handed on as views into the source buffer.

**Base64 is decoded from bytes.** The usual shape decodes each line to a string, strips
the characters outside the alphabet with a regex, and carries the remainder as a string.
That allocates two strings per line and copies the payload several times before a byte
comes out. This decoder keeps at most three 6 bit values of carry between lines and
writes decoded bytes straight into the output.

**Decoders write into one growable buffer.** Collecting chunks in a `Blob` and awaiting
`blob.arrayBuffer()`, the portable way to join them, costs an extra copy of every body and
a trip through the microtask queue for every part.

**Short runs are copied by hand.** `TypedArray.set` needs a view of the source range, and
allocating that view costs more than the copy for the short runs between two
quoted-printable escapes. Copying runs under 64 bytes in a loop instead made the
quoted-printable case 2.3x faster on its own.

**Resolved decoders are cached.** Constructing a `TextDecoder` costs far more than
decoding the handful of bytes an encoded word carries, and a header can hold dozens of
encoded words.

**The date formatter is built once.** `Intl.DateTimeFormat` has to load and resolve locale
data on construction. A forwarded message carries one date per nesting level, and building
a formatter for each of them was 60% of the total time on the MIME torture test.

**Headers are read in one pass.** Looking each field up with `find` walks the header list
again for every field, and a message with a long `Received` chain carries hundreds of
entries.

**Cheap scans guard expensive passes.** A header value with no `=?` in it needs no encoded
word tokenizing; a structured header with no `(` needs no comment stripping; text with no
`&` needs no entity decoding.

**What did not work:** building header strings from char codes to avoid the fixed per call
cost of `TextDecoder`. On Bun the native decode is roughly 18x faster than
`String.fromCharCode.apply` even on short header lines, and the first version of this
parser was slower than the reference on header heavy messages because of it. It was
measured, then reverted.

## Testing

Three suites live in `packages/ts/test/mime/`:

- `mime.test.ts` checks what the parser promises on its own terms: the envelope, folding,
  multipart trees, transfer encodings, charsets, attachments, nested messages and the
  limits.
- `parity.test.ts` runs both parsers over the whole corpus under six option combinations
  and requires identical output, with attachment content compared byte for byte.
- `edge-parity.test.ts` does the same for malformed input: forty hand written cases
  (unterminated boundaries, duplicated `Content-Type`, bare CR in a header, base64 padded
  on every line, unbalanced parens before a boundary, and so on) plus a deterministic
  mutation pass that truncates, flips bytes, removes the header separator and corrupts
  the boundary delimiters. Both parsers have to agree on the result, or on the error.

```bash
cd packages/ts
bun test          # all three suites
bun run bench:mime # the benchmarks
```

The corpus itself is in `test/mime/corpus.ts`. The generated messages are deterministic,
so a benchmark run is comparable to the one before it, and the real messages in
`test/mime/fixtures/` come from the postal-mime test suite (MIT-0).
