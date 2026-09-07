/**
 * The message corpus shared by the MIME parity tests and the benchmarks.
 *
 * Every case is a raw RFC 5322 message. The generated ones are deterministic, so a
 * benchmark run is comparable to the one before it and a parity failure can be
 * reproduced from the case name alone.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

export interface Message {
  name: string
  /** Roughly what shape of message this is, used to group benchmark output */
  group: 'attachment' | 'headers' | 'real' | 'structure' | 'text'
  raw: string
}

const FIXTURE_DIR = join(import.meta.dir, 'fixtures')

// Real messages, from the postal-mime test fixtures (MIT-0). They cover the shapes that
// are tedious to write by hand: a bounce report, an ARF report, a calendar invite, and
// a MIME torture test.
const FIXTURES = ['arf.eml', 'bounce.eml', 'calendar-event.eml', 'mimetorture.eml', 'mixed.eml']

function crlf(lines: string[]): string {
  return `${lines.join('\r\n')}\r\n`
}

// A deterministic pseudo random generator, so payload bytes are incompressible-ish and
// the same on every run
function* pseudoRandom(seed: number): Generator<number> {
  let state = seed >>> 0
  while (true) {
    state = (state * 1664525 + 1013904223) >>> 0
    yield state & 0xFF
  }
}

function randomBytes(length: number, seed = 1): Uint8Array {
  const bytes = new Uint8Array(length)
  const random = pseudoRandom(seed)
  for (let i = 0; i < length; i++)
    bytes[i] = random.next().value as number
  return bytes
}

function base64Lines(bytes: Uint8Array, lineLength = 76): string[] {
  const encoded = Buffer.from(bytes).toString('base64')
  const lines: string[] = []
  for (let i = 0; i < encoded.length; i += lineLength)
    lines.push(encoded.slice(i, i + lineLength))
  return lines
}

const LOREM = 'The quick brown fox jumps over the lazy dog while the mail server keeps counting bytes'

function textParagraphs(count: number): string[] {
  const lines: string[] = []
  for (let i = 0; i < count; i++) {
    lines.push(`${i}: ${LOREM}`)
    if (i % 5 === 4)
      lines.push('')
  }
  return lines
}

function htmlBody(paragraphs: number): string[] {
  const lines: string[] = ['<html><head><title>Report</title></head><body>']
  for (let i = 0; i < paragraphs; i++) {
    lines.push(`<p class="row-${i}">Row ${i} &mdash; ${LOREM} &amp; more</p>`)
    lines.push(`<div><a href="https://example.com/item/${i}">item ${i}</a></div>`)
  }
  lines.push('</body></html>')
  return lines
}

function simpleText(): string {
  return crlf([
    'From: Sender Name <sender@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: A plain text message',
    'Date: Mon, 15 Jan 2024 09:30:00 +0000',
    'Message-ID: <simple-1@example.com>',
    'Content-Type: text/plain; charset=utf-8',
    '',
    ...textParagraphs(20),
  ])
}

function alternative(): string {
  return crlf([
    'From: Newsletter <news@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: =?utf-8?Q?Weekly_digest_=E2=80=93_issue_42?=',
    'Date: Tue, 16 Jan 2024 08:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="alt-boundary"',
    '',
    '--alt-boundary',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    ...textParagraphs(30).map(line => line.replace(/=/g, '=3D')),
    '--alt-boundary',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    ...htmlBody(40),
    '--alt-boundary--',
  ])
}

function largeHtml(): string {
  return crlf([
    'From: Reports <reports@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Large HTML report',
    'Date: Wed, 17 Jan 2024 08:00:00 +0000',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    ...htmlBody(1500),
  ])
}

function quotedPrintableText(): string {
  const body: string[] = []
  for (let i = 0; i < 800; i++)
    body.push(`Zeile ${i}: Gr=C3=BC=C3=9Fe aus M=C3=BCnchen, Stra=C3=9Fe ${i} =E2=80=93 alles gut=`)

  return crlf([
    'From: "Müller, Hans" <hans@example.de>',
    'To: Recipient <recipient@example.net>',
    'Subject: =?iso-8859-1?Q?Gr=FC=DFe_aus_M=FCnchen?=',
    'Date: Thu, 18 Jan 2024 08:00:00 +0000',
    'Content-Type: text/plain; charset=utf-8; format=flowed',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    ...body,
  ])
}

function bigAttachment(bytes: number): string {
  return crlf([
    'From: Backup <backup@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Nightly archive',
    'Date: Fri, 19 Jan 2024 02:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="mixed-boundary"',
    '',
    '--mixed-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Archive attached.',
    '',
    '--mixed-boundary',
    'Content-Type: application/octet-stream; name="archive.bin"',
    'Content-Disposition: attachment; filename="archive.bin"',
    'Content-Transfer-Encoding: base64',
    '',
    ...base64Lines(randomBytes(bytes, 7)),
    '--mixed-boundary--',
  ])
}

function manyAttachments(count: number, each: number): string {
  const lines: string[] = [
    'From: Scanner <scanner@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Scanned documents',
    'Date: Sat, 20 Jan 2024 12:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="many-boundary"',
    '',
    '--many-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    `${count} documents attached.`,
    '',
  ]

  for (let i = 0; i < count; i++) {
    lines.push(
      '--many-boundary',
      `Content-Type: image/png; name="page-${i}.png"`,
      `Content-Disposition: attachment; filename="page-${i}.png"`,
      `Content-ID: <page-${i}@example.com>`,
      'Content-Transfer-Encoding: base64',
      '',
      ...base64Lines(randomBytes(each, i + 11)),
    )
  }

  lines.push('--many-boundary--')

  return crlf(lines)
}

function manyHeaders(count: number): string {
  const lines: string[] = []

  for (let i = 0; i < count; i++) {
    lines.push(
      `Received: from mx${i}.example.com (mx${i}.example.com [198.51.100.${i % 255}])`,
      `\tby mx${i + 1}.example.net with ESMTPS id abc${i}def`,
      `\tfor <recipient@example.net>; Mon, 15 Jan 2024 09:${(i % 60).toString().padStart(2, '0')}:00 +0000`,
      `X-Trace-${i}: hop=${i}; server=mx${i}; status=ok`,
    )
  }

  lines.push(
    'From: Sender Name <sender@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Long delivery chain',
    'Date: Mon, 15 Jan 2024 09:30:00 +0000',
    'Content-Type: text/plain; charset=utf-8',
    '',
    ...textParagraphs(5),
  )

  return crlf(lines)
}

function encodedWordHeaders(count: number): string {
  const lines: string[] = [
    'From: =?utf-8?B?VGhvbWFzIE3DvGxsZXI=?= <thomas@example.de>',
    'Subject: =?utf-8?B?SGVsbG8g?= =?utf-8?B?d29ybGQg?= =?iso-8859-1?Q?=E4=F6=FC?=',
    'Date: Sun, 21 Jan 2024 12:00:00 +0000',
  ]

  const recipients: string[] = []
  for (let i = 0; i < count; i++)
    recipients.push(`=?utf-8?Q?Empf=C3=A4nger_${i}?= <user${i}@example.net>`)

  lines.push(`To: ${recipients.join(', ')}`)
  lines.push(
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Body.',
  )

  return crlf(lines)
}

function nestedStructure(depth: number): string {
  const lines: string[] = [
    'From: Sender <sender@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Deeply nested',
    'Date: Mon, 22 Jan 2024 12:00:00 +0000',
    'MIME-Version: 1.0',
  ]

  for (let i = 0; i < depth; i++) {
    lines.push(`Content-Type: multipart/mixed; boundary="level-${i}"`, '', `--level-${i}`)
  }

  lines.push('Content-Type: text/plain; charset=utf-8', '', 'Bottom of the tree.', '')

  for (let i = depth - 1; i >= 0; i--)
    lines.push(`--level-${i}--`)

  return crlf(lines)
}

function nestedRfc822(): string {
  const inner = crlf([
    'From: Original Sender <original@example.com>',
    'To: Original Recipient <orig-recipient@example.net>',
    'Subject: The original message',
    'Date: Mon, 15 Jan 2024 09:30:00 +0000',
    'Content-Type: multipart/alternative; boundary="inner-alt"',
    '',
    '--inner-alt',
    'Content-Type: text/plain; charset=utf-8',
    '',
    ...textParagraphs(10),
    '--inner-alt',
    'Content-Type: text/html; charset=utf-8',
    '',
    ...htmlBody(10),
    '--inner-alt--',
  ])

  return crlf([
    'From: Forwarder <forward@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Fwd: The original message',
    'Date: Tue, 23 Jan 2024 12:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="fwd-boundary"',
    '',
    '--fwd-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'See the message below.',
    '',
    '--fwd-boundary',
    'Content-Type: message/rfc822',
    'Content-Disposition: inline',
    '',
    inner,
    '--fwd-boundary--',
  ])
}

function relatedHtml(): string {
  return crlf([
    'From: Marketing <marketing@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Inline images',
    'Date: Wed, 24 Jan 2024 12:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/related; boundary="rel-boundary"; type="text/html"',
    '',
    '--rel-boundary',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<html><body>',
    '<img src="cid:logo@example.com" alt="logo" />',
    ...htmlBody(20),
    '</body></html>',
    '--rel-boundary',
    'Content-Type: image/png; name="logo.png"',
    'Content-ID: <logo@example.com>',
    'Content-Disposition: inline; filename="logo.png"',
    'Content-Transfer-Encoding: base64',
    '',
    ...base64Lines(randomBytes(8 * 1024, 23)),
    '--rel-boundary--',
  ])
}

function rfc2231Filenames(): string {
  return crlf([
    'From: Sender <sender@example.com>',
    'To: Recipient <recipient@example.net>',
    'Subject: Continued parameters',
    'Date: Thu, 25 Jan 2024 12:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="p2231"',
    '',
    '--p2231',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'See attached.',
    '',
    '--p2231',
    'Content-Type: application/pdf',
    'Content-Disposition: attachment;',
    '\tfilename*0*=utf-8\'\'%E2%82%AC%20Annual%20;',
    '\tfilename*1*=Report%20;',
    '\tfilename*2="2024.pdf"',
    'Content-Transfer-Encoding: base64',
    '',
    ...base64Lines(randomBytes(2048, 31)),
    '--p2231--',
  ])
}

function addressHeavy(count: number): string {
  const recipients: string[] = []
  for (let i = 0; i < count; i++)
    recipients.push(`"Person ${i}, Team" <person${i}@example.net>`)

  return crlf([
    'From: Sender <sender@example.com>',
    `To: ${recipients.slice(0, count / 2).join(', ')}`,
    `Cc: ${recipients.slice(count / 2).join(', ')}`,
    'Reply-To: Group Name: member1@example.com, member2@example.com;',
    'Subject: Wide distribution',
    'Date: Fri, 26 Jan 2024 12:00:00 +0000',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Body.',
  ])
}

function buildMessages(): Message[] {
  const messages: Message[] = [
    { name: 'text/simple', group: 'text', raw: simpleText() },
    { name: 'text/alternative', group: 'text', raw: alternative() },
    { name: 'text/large-html', group: 'text', raw: largeHtml() },
    { name: 'text/quoted-printable-flowed', group: 'text', raw: quotedPrintableText() },
    { name: 'attachment/base64-1mb', group: 'attachment', raw: bigAttachment(1024 * 1024) },
    { name: 'attachment/base64-64kb', group: 'attachment', raw: bigAttachment(64 * 1024) },
    { name: 'attachment/many-small', group: 'attachment', raw: manyAttachments(50, 4 * 1024) },
    { name: 'attachment/rfc2231-filename', group: 'attachment', raw: rfc2231Filenames() },
    { name: 'headers/long-received-chain', group: 'headers', raw: manyHeaders(200) },
    { name: 'headers/encoded-words', group: 'headers', raw: encodedWordHeaders(60) },
    { name: 'headers/address-heavy', group: 'headers', raw: addressHeavy(200) },
    { name: 'structure/nested-multipart', group: 'structure', raw: nestedStructure(20) },
    { name: 'structure/nested-rfc822', group: 'structure', raw: nestedRfc822() },
    { name: 'structure/related-inline-images', group: 'structure', raw: relatedHtml() },
  ]

  for (const fixture of FIXTURES) {
    messages.push({
      name: `real/${fixture.replace(/\.eml$/, '')}`,
      group: 'real',
      raw: readFileSync(join(FIXTURE_DIR, fixture), 'latin1'),
    })
  }

  return messages
}

export const messages: Message[] = buildMessages()

export function messageByName(name: string): Message {
  const message = messages.find(entry => entry.name === name)
  if (!message)
    throw new Error(`Unknown corpus message: ${name}`)
  return message
}
