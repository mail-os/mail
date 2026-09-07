# @stacksjs/mail

The TypeScript SDK for the mail server: a typed runtime and management client, the
pre-built server binaries, and a MIME email parser.

## Install

```bash
bun add @stacksjs/mail
```

## Mail server client

```ts
import { MailServer } from '@stacksjs/mail'
```

See the [repository README](https://github.com/mail-os/mail#readme) for the server side
of it.

## MIME parser

A dependency free parser for raw RFC 5322 messages. It takes the bytes that arrived over
SMTP, or an `.eml` file, and gives back the headers, the addresses, the text and HTML
bodies, and the attachments.

```ts
import { parseEmail } from '@stacksjs/mail/mime'

const email = await parseEmail(raw)

email.subject // 'Quarterly report'
email.from // { name: 'Ada Lovelace', address: 'ada@example.com' }
email.to // [{ name: 'Alan', address: 'alan@example.net' }]
email.date // '2024-01-15T09:30:00.000Z'
email.text // plain text body
email.html // HTML body
email.attachments // [{ filename, mimeType, disposition, content, ... }]
```

`raw` may be a string, an `ArrayBuffer`, a typed array, a `Blob` or a `ReadableStream`.

When the message is already in memory, skip the promise:

```ts
import { parseEmailSync } from '@stacksjs/mail/mime'

const email = parseEmailSync(raw)
```

### Options

```ts
const email = await parseEmail(raw, {
  attachmentEncoding: 'base64', // 'arraybuffer' (default), 'base64' or 'utf8'
  rfc822Attachments: false, // treat undisposed message/rfc822 parts as attachments
  forceRfc822Attachments: false, // never inline a nested message
  maxNestingDepth: 256, // multipart nesting limit
  maxHeadersSize: 2 * 1024 * 1024, // header bytes across the whole message
  maxRfc822NestingDepth: 10, // how deep nested messages are parsed inline
})
```

Every limit is validated: a non-integer or negative value throws a `TypeError` rather
than quietly disabling the limit, so forwarding a request supplied options object can not
turn the limits off.

### What it handles

- Multipart trees, including `alternative`, `related`, `mixed` and `digest`
- `base64`, `quoted-printable` and 8bit bodies, with the vendor prefixed spellings
- RFC 2047 encoded words in every header, including characters split across two words
- RFC 2231 parameter continuations and percent encoded filenames
- Legacy charsets, with the aliases mail clients actually write (`cp932`, `iso-8859-8-i`,
  `x-euc-jp`, ...)
- `format=flowed` and `delsp=yes` text
- Nested `message/rfc822` parts, inlined into the body or kept as attachments
- Calendar invites, with the iTIP method surfaced on the attachment
- Bounce and feedback reports, where the original message stays an attachment

### Other exports

```ts
import {
  addressParser, // parse an address field into mailboxes and groups
  decodeWords, // decode RFC 2047 encoded words in a header value
  htmlToText, // the HTML to text conversion used for a missing text view
  MimeParser, // the parser class, if you want to hold it yourself
  textToHtml,
} from '@stacksjs/mail/mime'
```

### Performance

The parser is a port of [postal-mime](https://github.com/postalsys/postal-mime) (MIT-0),
which is the reference for its behaviour: a parity suite runs both parsers over the same
corpus, including malformed and mutated messages, and requires identical output. The port
is faster on every case in that corpus.

```bash
bun run bench:mime
```

On Bun 1.3.14, darwin/arm64, best of three rounds:

| case | postal-mime | this parser | speedup |
|---|---:|---:|---:|
| text/simple | 59,453/s | 125,790/s | 2.12x |
| text/alternative | 15,724/s | 29,024/s | 1.85x |
| text/large-html | 1,057/s | 1,943/s | 1.84x |
| text/quoted-printable-flowed | 2,360/s | 5,510/s | 2.33x |
| attachment/base64-1mb | 130.2/s | 281.9/s | 2.17x |
| attachment/many-small | 440.5/s | 1,011/s | 2.29x |
| headers/long-received-chain | 2,807/s | 5,015/s | 1.79x |
| structure/nested-rfc822 | 6,272/s | 25,462/s | 4.06x |
| real/mimetorture | 580.1/s | 2,522/s | 4.35x |
| real/bounce | 10,045/s | 18,856/s | 1.88x |

Geometric mean across the 19 message cases: **2.07x**, range 1.27x to 4.35x. Attachment
re-encoding (`attachmentEncoding: 'base64'`) is 3.2x to 4.0x, and the exported helpers are
1.2x to 2.2x.

Where the difference comes from is written up in
[docs/MIME_PARSER.md](https://github.com/mail-os/mail/blob/main/docs/MIME_PARSER.md).

## License

MIT
