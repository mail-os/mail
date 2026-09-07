/**
 * Parity on malformed and adversarial input.
 *
 * The interesting differences between two MIME parsers are never in the well formed
 * messages, they are in what each one does with a truncated boundary, a duplicated
 * Content-Type or a header that folds where it should not. These cases pin that
 * behaviour, and the mutation pass looks for the ones nobody thought to write down.
 */

import type { Attachment, Email } from '../../src/mime'
import { describe, expect, it } from 'bun:test'
import PostalMime from 'postal-mime'
import { MimeParser } from '../../src/mime'
import { messages } from './corpus'

function contentShape(content: Attachment['content'] | undefined): unknown {
  if (content === undefined || content === null)
    return null
  if (typeof content === 'string')
    return { kind: 'string', value: content }

  const bytes = content instanceof Uint8Array ? content : new Uint8Array(content)
  return {
    kind: content instanceof Uint8Array ? 'Uint8Array' : 'ArrayBuffer',
    value: Buffer.from(bytes).toString('base64'),
  }
}

function normalize(email: Email): unknown {
  return {
    ...email,
    attachments: (email.attachments || []).map(attachment => ({
      ...attachment,
      content: contentShape(attachment.content),
    })),
  }
}

/** Parses with both parsers, returning either both results or both error messages. */
async function compare(raw: string | Uint8Array): Promise<void> {
  let expected: unknown
  let expectedError: string | null = null
  try {
    expected = normalize(await PostalMime.parse(raw as never) as Email)
  }
  catch (err) {
    expectedError = (err as Error).message
  }

  let actual: unknown
  let actualError: string | null = null
  try {
    actual = normalize(await MimeParser.parse(raw))
  }
  catch (err) {
    actualError = (err as Error).message
  }

  expect(actualError).toBe(expectedError)
  if (!expectedError)
    expect(actual).toEqual(expected as never)
}

const EDGE_CASES: Record<string, string> = {
  'empty message': '',
  'only a newline': '\r\n',
  'headers without a body': 'From: a@b.com\r\nSubject: No body\r\n',
  'body without headers': '\r\nJust a body\r\n',
  'header with no colon': 'From a@b.com\r\nSubject: Test\r\n\r\nBody\r\n',
  'leading space before a header name': ' From: spoofed@evil.com\r\nFrom: real@example.com\r\n\r\nBody\r\n',
  'duplicate content-type': 'Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\n<b>hi</b>\r\n',
  'duplicate boundary parameter': 'Content-Type: multipart/mixed; boundary="a"; boundary="b"\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--a--\r\n',
  'boundary with trailing whitespace': 'Content-Type: multipart/mixed; boundary="bnd"\r\n\r\n--bnd \t\r\nContent-Type: text/plain\r\n\r\nbody\r\n--bnd--\r\n',
  'unterminated boundary': 'Content-Type: multipart/mixed; boundary="bnd"\r\n\r\n--bnd\r\nContent-Type: text/plain\r\n\r\nno terminator\r\n',
  'boundary that never appears': 'Content-Type: multipart/mixed; boundary="missing"\r\n\r\nnothing here\r\n',
  'nested boundary reuse': 'Content-Type: multipart/mixed; boundary="x"\r\n\r\n--x\r\nContent-Type: multipart/mixed; boundary="x"\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\ninner\r\n--x--\r\n--x--\r\n',
  'bare LF line endings': 'From: a@b.com\nSubject: LF only\nContent-Type: text/plain\n\nBody line\n',
  'bare CR inside a header': 'Subject: broken\rvalue\r\nFrom: a@b.com\r\n\r\nBody\r\n',
  'folded header': 'Subject: first\r\n\tsecond\r\n  third\r\nFrom: a@b.com\r\n\r\nBody\r\n',
  'fold with a non-ASCII space': 'Subject: first\r\n\u00A0second\r\nFrom: a@b.com\r\n\r\nBody\r\n',
  'BOM before a header': '\uFEFFFrom: a@b.com\r\nSubject: BOM\r\n\r\nBody\r\n',
  'quoted printable soft break': 'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline one =\r\ncontinued=20here\r\n',
  'quoted printable invalid escape': 'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=ZZb=3Dc=\r\n',
  'base64 with padding on every line': 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="p.bin"\r\n\r\nSGVsbG8=\r\nV29ybGQ=\r\n',
  'base64 with stray characters': 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="p.bin"\r\n\r\nSGVs*bG8g **V29y bGQh\r\n',
  'base64 truncated group': 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="p.bin"\r\n\r\nSGVsbG8gd29ybGQhI\r\n',
  'transfer encoding in a comment': 'Content-Type: text/plain\r\nContent-Transfer-Encoding: (comment) base64\r\n\r\nSGVsbG8gd29ybGQh\r\n',
  'quoted transfer encoding': 'Content-Type: text/plain\r\nContent-Transfer-Encoding: "base64"\r\n\r\nSGVsbG8gd29ybGQh\r\n',
  'filename with parentheses': 'Content-Type: application/pdf; name=Invoice(1).pdf\r\nContent-Disposition: attachment; filename=Invoice(1).pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nSGk=\r\n',
  'windows path filename': 'Content-Type: text/plain\r\nContent-Disposition: attachment; filename=C:\\Users\\me\\a.txt\r\n\r\nhi\r\n',
  'unbalanced paren before boundary': 'Content-Type: multipart/mixed; boundary="AAA" (unterminated\r\n\r\n--AAA\r\nContent-Type: text/plain\r\n\r\nbody\r\n--AAA--\r\n',
  'valueless parameter before boundary': 'Content-Type: multipart/mixed; x=1; flag; boundary="AAA"\r\n\r\n--AAA\r\nContent-Type: text/plain\r\n\r\nbody\r\n--AAA--\r\n',
  'rfc2231 unencoded section': 'Content-Type: text/plain\r\nContent-Disposition: attachment;\r\n\tfilename*0="a%2F..%2Fetc";\r\n\tfilename*1="passwd"\r\n\r\nhi\r\n',
  'multipart digest defaults': 'Content-Type: multipart/digest; boundary="d"\r\n\r\n--d\r\n\r\nFrom: inner@example.com\r\nSubject: inner\r\n\r\ninner body\r\n--d--\r\n',
  'delivery status report': 'Content-Type: multipart/report; report-type=delivery-status; boundary="r"\r\n\r\n--r\r\nContent-Type: text/plain\r\n\r\nfailed\r\n--r\r\nContent-Type: message/delivery-status\r\n\r\nStatus: 5.1.1\r\n--r\r\nContent-Type: message/rfc822\r\n\r\nFrom: orig@example.com\r\nSubject: original\r\n\r\noriginal body\r\n--r--\r\n',
  'calendar invite part': 'Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n',
  'html only body': 'Content-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>Hello &amp; welcome</p><ul><li>one</li><li>two</li></ul></body></html>\r\n',
  'flowed text with delsp': 'Content-Type: text/plain; format=flowed; delsp=yes\r\n\r\nThis is a long \r\nsentence that was \r\nfolded.\r\n-- \r\nsignature\r\n',
  'unknown charset': 'Content-Type: text/plain; charset=x-nonexistent-charset\r\n\r\nplain body\r\n',
  'shift_jis body': 'Content-Type: text/plain; charset=cp932\r\nContent-Transfer-Encoding: base64\r\n\r\ng0GDQoND\r\n',
  'attachment without disposition': 'Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\nContent-Type: image/png; name="x.png"\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--m--\r\n',
  'content-id without related': 'Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\nContent-Type: image/png\r\nContent-ID: <cid@example.com>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--m--\r\n',
  'empty part': 'Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\n\r\n--m--\r\n',
  'preamble and epilogue': 'Content-Type: multipart/mixed; boundary="m"\r\n\r\nThis is the preamble.\r\n--m\r\nContent-Type: text/plain\r\n\r\nbody\r\n--m--\r\nThis is the epilogue.\r\n',
}

describe('mime parser parity on malformed input', () => {
  for (const [name, raw] of Object.entries(EDGE_CASES)) {
    it(name, async () => {
      await compare(raw)
    })
  }
})

// A deterministic LCG, so a failing mutation can be reproduced from its index alone
function mutationSeed(index: number): () => number {
  let state = (index * 2654435761) >>> 0
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state
  }
}

/** Corrupts a message the way a truncated download or a broken mailer would. */
function mutate(raw: string, index: number): string {
  const random = mutationSeed(index)
  const bytes = Buffer.from(raw, 'binary')

  switch (index % 5) {
    case 0:
      // truncate
      return bytes.subarray(0, random() % bytes.length).toString('binary')
    case 1: {
      // flip a byte
      const copy = Buffer.from(bytes)
      copy[random() % copy.length] = random() % 256
      return copy.toString('binary')
    }
    case 2:
      // drop the blank line that separates headers from the body
      return raw.replace('\r\n\r\n', '\r\n')
    case 3:
      // corrupt every boundary delimiter
      return raw.replace(/^--/gm, '-')
    default: {
      // splice a chunk out of the middle
      const start = random() % bytes.length
      const end = Math.min(bytes.length, start + (random() % 512))
      return Buffer.concat([bytes.subarray(0, start), bytes.subarray(end)]).toString('binary')
    }
  }
}

describe('mime parser parity on mutated messages', () => {
  // Kept to the smaller corpus entries so the suite stays quick
  const seeds = messages.filter(message => message.raw.length < 64 * 1024)

  for (let round = 0; round < 5; round++) {
    it(`mutation round ${round}`, async () => {
      for (const [index, message] of seeds.entries())
        await compare(mutate(message.raw, round * seeds.length + index))
    })
  }
})
