/**
 * Behaviour of the MIME parser, checked against what the RFCs and the message itself
 * say rather than against another implementation. The parity suite pins compatibility;
 * this one pins what the parser promises on its own.
 */

import { describe, expect, it } from 'bun:test'
import {
  addressParser,
  Base64Decoder,
  decodeBase64,
  decodeWords,
  encodeBase64,
  htmlToText,
  MimeParser,
  parseEmail,
  parseEmailSync,
  QPDecoder,
} from '../../src/mime'

function crlf(lines: string[]): string {
  return `${lines.join('\r\n')}\r\n`
}

function text(content: ArrayBuffer | Uint8Array | string | undefined): string {
  if (typeof content === 'string')
    return content
  return new TextDecoder().decode(content)
}

const SIMPLE = crlf([
  'From: Ada Lovelace <ada@example.com>',
  'To: Alan <alan@example.net>, "Grace, Rear Admiral" <grace@example.org>',
  'Cc: cc@example.com',
  'Subject: =?utf-8?B?SGVsbG8sIHdvcmxkIQ==?=',
  'Message-ID: <abc123@example.com>',
  'Date: Mon, 15 Jan 2024 09:30:00 +0000',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Body line one',
  'Body line two',
])

describe('parseEmail', () => {
  it('reads the envelope headers', async () => {
    const email = await parseEmail(SIMPLE)

    expect(email.from).toEqual({ name: 'Ada Lovelace', address: 'ada@example.com' })
    expect(email.to).toEqual([
      { name: 'Alan', address: 'alan@example.net' },
      { name: 'Grace, Rear Admiral', address: 'grace@example.org' },
    ])
    expect(email.cc).toEqual([{ name: '', address: 'cc@example.com' }])
    expect(email.subject).toBe('Hello, world!')
    expect(email.messageId).toBe('<abc123@example.com>')
    expect(email.date).toBe('2024-01-15T09:30:00.000Z')
    expect(email.text).toBe('Body line one\nBody line two\n')
    expect(email.attachments).toEqual([])
  })

  it('keeps the raw header lines alongside the parsed ones', async () => {
    const email = await parseEmail(SIMPLE)

    expect(email.headers[0]).toEqual({ key: 'from', originalKey: 'From', value: 'Ada Lovelace <ada@example.com>' })
    expect(email.headerLines[0]).toEqual({ key: 'from', line: 'From: Ada Lovelace <ada@example.com>' })
    expect(email.headerLines).toHaveLength(email.headers.length)
  })

  it('unfolds a folded header without collapsing its whitespace', async () => {
    const email = await parseEmail(crlf([
      'Subject: first',
      '   second',
      'From: a@example.com',
      '',
      'body',
    ]))

    expect(email.subject).toBe('first   second')
    expect(email.headerLines[0].line).toBe('Subject: first\n   second')
  })

  it('keeps the raw date when it does not parse', async () => {
    const email = await parseEmail(crlf(['Date: not a date', 'From: a@example.com', '', 'body']))

    expect(email.date).toBe('not a date')
  })

  it('takes the first occurrence of a duplicated content header', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/plain; charset=utf-8',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<b>hi</b>',
    ]))

    // The part is read as text/plain, so the markup is body text and there is no HTML
    // view to report
    expect(email.text).toBe('<b>hi</b>\n')
    expect(email.html).toBeUndefined()
  })

  it('folds a space indented line into the header above it', async () => {
    const email = await parseEmail(crlf([
      'From: real@example.com',
      ' From: spoofed@evil.example',
      '',
      'body',
    ]))

    expect(email.headers).toHaveLength(1)
    expect(email.headers[0].value).toBe('real@example.com From: spoofed@evil.example')
  })

  it('does not fold a line that starts with a non-ASCII space', async () => {
    const email = await parseEmail(crlf([
      'From: real@example.com',
      '\u00A0From: spoofed@evil.example',
      '',
      'body',
    ]))

    // The line stays visible as a header of its own, under a key that can not collide
    // with the real one
    expect(email.from).toEqual({ name: '', address: 'real@example.com' })
    expect(email.headers.map(header => header.key)).toEqual(['from', '\u00A0from'])
  })

  it('accepts every input shape', async () => {
    const bytes = new TextEncoder().encode(SIMPLE)

    expect((await parseEmail(bytes)).subject).toBe('Hello, world!')
    expect((await parseEmail(bytes.buffer)).subject).toBe('Hello, world!')
    expect((await parseEmail(new Blob([bytes]))).subject).toBe('Hello, world!')
    expect((await parseEmail(new Response(bytes).body!)).subject).toBe('Hello, world!')
    expect((await parseEmail(new DataView(bytes.buffer))).subject).toBe('Hello, world!')
    expect(parseEmailSync(SIMPLE).subject).toBe('Hello, world!')
  })

  it('refuses to parse twice with the same parser', async () => {
    const parser = new MimeParser()
    await parser.parse(SIMPLE)

    await expect(parser.parse(SIMPLE)).rejects.toThrow('Can not reuse parser')
  })
})

describe('multipart handling', () => {
  const ALTERNATIVE = crlf([
    'From: a@example.com',
    'Content-Type: multipart/alternative; boundary="alt"',
    '',
    '--alt',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'plain version',
    '--alt',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>html version</p>',
    '--alt--',
  ])

  it('picks up both views of an alternative', async () => {
    const email = await parseEmail(ALTERNATIVE)

    expect(email.text).toBe('plain version\n')
    expect(email.html).toBe('<p>html version</p>\n')
  })

  it('generates the view a part is missing from the one it has', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      '--b',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'plain part',
      '--b',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<p>Hello &amp; welcome</p><ul><li>one</li><li>two</li></ul>',
      '--b--',
    ]))

    // The HTML part contributes to the text view and the plain part to the HTML view
    expect(email.text).toContain('Hello & welcome')
    expect(email.text).toContain('* one')
    expect(email.html).toContain('<div>plain part</div>')
  })

  it('reports only the views the message actually carries', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/html; charset=utf-8',
      '',
      '<p>html only</p>',
    ]))

    expect(email.html).toBe('<p>html only</p>\n')
    expect(email.text).toBeUndefined()
  })

  it('reads a part inside a boundary line with trailing whitespace', async () => {
    const email = await parseEmail('Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b \t\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b--\r\n')

    expect(email.text).toBe('body\n')
  })

  it('defaults the parts of a digest to message/rfc822', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: multipart/digest; boundary="d"',
      '',
      '--d',
      '',
      'From: inner@example.com',
      'Subject: inner subject',
      '',
      'inner body',
      '--d--',
    ]))

    expect(email.text).toContain('inner subject')
    expect(email.text).toContain('inner body')
  })

  it('refuses a message nested past the depth limit', async () => {
    let raw = 'Content-Type: text/plain\r\n\r\nbottom\r\n'
    for (let i = 0; i < 12; i++)
      raw = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n${raw}--b${i}--\r\n`

    await expect(parseEmail(raw, { maxNestingDepth: 4 })).rejects.toThrow('Maximum MIME nesting depth')
  })
})

describe('attachments', () => {
  const WITH_ATTACHMENT = crlf([
    'From: a@example.com',
    'Content-Type: multipart/mixed; boundary="mix"',
    '',
    '--mix',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'see attached',
    '--mix',
    'Content-Type: application/pdf; name="report.pdf"',
    'Content-Disposition: attachment; filename="report.pdf"',
    'Content-Description: =?utf-8?Q?Quarterly_report?=',
    'Content-Transfer-Encoding: base64',
    '',
    'SGVsbG8gcGRm',
    '--mix--',
  ])

  it('decodes a base64 attachment', async () => {
    const email = await parseEmail(WITH_ATTACHMENT)

    expect(email.attachments).toHaveLength(1)
    const [attachment] = email.attachments
    expect(attachment.filename).toBe('report.pdf')
    expect(attachment.mimeType).toBe('application/pdf')
    expect(attachment.disposition).toBe('attachment')
    expect(attachment.description).toBe('Quarterly report')
    expect(attachment.content).toBeInstanceOf(ArrayBuffer)
    expect(text(attachment.content)).toBe('Hello pdf')
  })

  it('re-encodes attachment content on request', async () => {
    const asBase64 = await parseEmail(WITH_ATTACHMENT, { attachmentEncoding: 'base64' })
    expect(asBase64.attachments[0].content).toBe('SGVsbG8gcGRm')
    expect(asBase64.attachments[0].encoding).toBe('base64')

    const asUtf8 = await parseEmail(WITH_ATTACHMENT, { attachmentEncoding: 'utf8' })
    expect(asUtf8.attachments[0].content).toBe('Hello pdf')
    expect(asUtf8.attachments[0].encoding).toBe('utf8')
  })

  it('marks an inline image that a related part references', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: multipart/related; boundary="rel"',
      '',
      '--rel',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<img src="cid:logo@example.com">',
      '--rel',
      'Content-Type: image/png',
      'Content-ID: <logo@example.com>',
      'Content-Transfer-Encoding: base64',
      '',
      'iVBORw0KGgo=',
      '--rel--',
    ]))

    expect(email.attachments[0].contentId).toBe('<logo@example.com>')
    expect(email.attachments[0].related).toBe(true)
  })

  it('reassembles a filename split across RFC 2231 sections', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      '--b',
      'Content-Type: application/pdf',
      'Content-Disposition: attachment;',
      '\tfilename*0*=utf-8\'\'%E2%82%AC%20Annual%20;',
      '\tfilename*1*=Report%20;',
      '\tfilename*2="2024.pdf"',
      '',
      'x',
      '--b--',
    ]))

    expect(email.attachments[0].filename).toBe('€ Annual Report 2024.pdf')
  })

  it('normalizes a calendar part and keeps its method', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/calendar; method=request; charset=utf-8',
      '',
      'BEGIN:VCALENDAR',
      'END:VCALENDAR',
      '',
      '',
    ]))

    const [attachment] = email.attachments
    expect(attachment.method).toBe('REQUEST')
    expect(text(attachment.content)).toBe('BEGIN:VCALENDAR\nEND:VCALENDAR\n')
  })

  it('keeps a windows path filename intact', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/plain',
      'Content-Disposition: attachment; filename=C:\\Users\\me\\a.txt',
      '',
      'hi',
    ]))

    expect(email.attachments[0].filename).toBe('C:\\Users\\me\\a.txt')
  })
})

describe('nested messages', () => {
  const FORWARDED = crlf([
    'From: forwarder@example.com',
    'Subject: Fwd: original',
    'Content-Type: multipart/mixed; boundary="fwd"',
    '',
    '--fwd',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'see below',
    '--fwd',
    'Content-Type: message/rfc822',
    '',
    'From: original@example.com',
    'Subject: original subject',
    'Date: Mon, 15 Jan 2024 09:30:00 +0000',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'original body',
    '--fwd--',
  ])

  it('inlines a forwarded message into the text view', async () => {
    const email = await parseEmail(FORWARDED)

    expect(email.text).toContain('original subject')
    expect(email.text).toContain('original body')
    expect(email.attachments).toEqual([])
  })

  it('keeps it as an attachment when asked to', async () => {
    const email = await parseEmail(FORWARDED, { rfc822Attachments: true })

    expect(email.attachments).toHaveLength(1)
    expect(email.attachments[0].mimeType).toBe('message/rfc822')
    expect(email.text).not.toContain('original body')
  })

  it('flags a nested message that hit the recursion limit', async () => {
    const email = await parseEmail(FORWARDED, { maxRfc822NestingDepth: 0 })

    expect(email.attachments[0].rfc822DepthExceeded).toBe(true)
  })
})

describe('limits', () => {
  it('rejects a message whose headers exceed the budget', async () => {
    const lines: string[] = []
    for (let i = 0; i < 100; i++)
      lines.push(`X-Padding-${i}: ${'x'.repeat(200)}`)
    lines.push('', 'body')

    await expect(parseEmail(crlf(lines), { maxHeadersSize: 1024 })).rejects.toThrow('Maximum header size')
  })

  it('counts the header budget across every part', async () => {
    const part = (index: number): string[] => [
      '--b',
      `X-Padding-${index}: ${'x'.repeat(400)}`,
      'Content-Type: text/plain',
      '',
      'body',
    ]

    const lines = ['Content-Type: multipart/mixed; boundary="b"', '']
    for (let i = 0; i < 10; i++)
      lines.push(...part(i))
    lines.push('--b--')

    await expect(parseEmail(crlf(lines), { maxHeadersSize: 1024 })).rejects.toThrow('Maximum header size')
  })

  it('refuses a limit that is not a non-negative integer', async () => {
    await expect(parseEmail(SIMPLE, { maxHeadersSize: 'lots' as never })).rejects.toThrow(TypeError)
    await expect(parseEmail(SIMPLE, { maxNestingDepth: -1 })).rejects.toThrow(TypeError)
    await expect(parseEmail(SIMPLE, { maxRfc822NestingDepth: 1.5 })).rejects.toThrow(TypeError)
  })

  it('rejects an unknown attachment encoding', async () => {
    await expect(parseEmail(SIMPLE, { attachmentEncoding: 'rot13' as never })).rejects.toThrow('Unknown attachment encoding')
  })
})

describe('transfer encodings', () => {
  it('joins quoted-printable soft line breaks', async () => {
    const email = await parseEmail('Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline one =\r\ncontinued=20here\r\n')

    expect(email.text).toBe('line one continued here\n')
  })

  it('decodes base64 that pads every line', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: application/octet-stream',
      'Content-Disposition: attachment; filename="p.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      'SGVsbG8=',
      'V29ybGQ=',
    ]))

    expect(text(email.attachments[0].content)).toBe('HelloWorld')
  })

  it('finds the encoding behind a comment', async () => {
    const email = await parseEmail('Content-Type: text/plain\r\nContent-Transfer-Encoding: (comment) base64\r\n\r\nSGVsbG8gd29ybGQh\r\n')

    expect(email.text).toBe('Hello world!')
  })

  it('unfolds format=flowed text', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/plain; format=flowed; charset=utf-8',
      '',
      'This is one ',
      'long sentence.',
      'And this is another.',
    ]))

    expect(email.text).toBe('This is one long sentence.\nAnd this is another.\n')
  })

  it('decodes a body in a legacy charset', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/plain; charset=iso-8859-1',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'Gr=FC=DFe',
    ]))

    expect(email.text).toBe('Grüße\n')
  })

  it('falls back for a charset nobody knows', async () => {
    const email = await parseEmail(crlf([
      'Content-Type: text/plain; charset=x-nonexistent',
      '',
      'plain body',
    ]))

    expect(email.text).toBe('plain body\n')
  })
})

describe('addressParser', () => {
  it('reads a display name and an address', () => {
    expect(addressParser('Ada Lovelace <ada@example.com>')).toEqual([
      { name: 'Ada Lovelace', address: 'ada@example.com' },
    ])
  })

  it('reads a group', () => {
    expect(addressParser('Team: one@example.com, two@example.com;')).toEqual([
      {
        name: 'Team',
        group: [
          { name: '', address: 'one@example.com' },
          { name: '', address: 'two@example.com' },
        ],
      },
    ])
  })

  it('flattens groups on request', () => {
    expect(addressParser('Team: one@example.com;', { flatten: true })).toEqual([
      { name: '', address: 'one@example.com' },
    ])
  })

  it('does not mine an address out of a quoted local part', () => {
    // RFC 5321 allows '@' inside a quoted local part, and taking the inner address
    // would route the message to a different domain than the one it names
    const [address] = addressParser('"user@domain"@example.com')

    expect(address.address).toBe('user@domain@example.com')
    expect(address.address).not.toBe('user@domain')
  })

  it('does not invent an address from a bare encoded word', () => {
    expect(addressParser('=?utf-8?B?dGVzdEBldmlsLmNv?=')).toEqual([
      { address: '', name: 'test@evil.co' },
    ])
  })
})

describe('decodeWords', () => {
  it('leaves plain text alone', () => {
    expect(decodeWords('Re: your invoice')).toBe('Re: your invoice')
  })

  it('decodes base64 and quoted-printable words', () => {
    expect(decodeWords('=?utf-8?B?SGVsbG8=?=')).toBe('Hello')
    expect(decodeWords('=?utf-8?Q?Gr=C3=BC=C3=9Fe?=')).toBe('Grüße')
    expect(decodeWords('=?iso-8859-1?Q?Gr=FC=DFe?=')).toBe('Grüße')
  })

  it('joins a character split across two words', () => {
    expect(decodeWords('=?utf-8?B?4pyT?= =?utf-8?B?4pyU?=')).toBe('✓✔')
    expect(decodeWords('=?utf-8?Q?=E2=9C?= =?utf-8?Q?=93?=')).toBe('✓')
  })

  it('keeps the text around a word', () => {
    expect(decodeWords('prefix =?utf-8?B?SGVsbG8=?= suffix')).toBe('prefix Hello suffix')
  })
})

describe('decoders', () => {
  it('round trips base64', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])

    expect(encodeBase64(bytes)).toBe(Buffer.from(bytes).toString('base64'))
    expect(new Uint8Array(decodeBase64(encodeBase64(bytes)))).toEqual(bytes)
  })

  it('decodes base64 fed one line at a time', () => {
    const decoder = new Base64Decoder()
    for (const line of ['SGVsbG8g', 'd29ybGQh'])
      decoder.update(new TextEncoder().encode(line))

    expect(text(decoder.finalize())).toBe('Hello world!')
  })

  it('decodes quoted-printable fed one line at a time', () => {
    const decoder = new QPDecoder()
    for (const line of ['Hello=20', 'world=21'])
      decoder.update(new TextEncoder().encode(line))

    expect(text(decoder.finalize())).toBe('Hello \nworld!\n')
  })

  it('turns html into readable text', () => {
    expect(htmlToText('<p>One</p><p>Two &amp; three</p>')).toContain('Two & three')
  })
})
