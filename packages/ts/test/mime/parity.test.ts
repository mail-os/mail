/**
 * Parity against postal-mime.
 *
 * The parser is a port, so the reference implementation is the specification: for every
 * message in the corpus and every option combination, both parsers have to produce the
 * same message object, down to the bytes of every attachment.
 */

import type { Attachment, Email, MimeParserOptions } from '../../src/mime'
import { describe, expect, it } from 'bun:test'
import PostalMime, { addressParser as postalAddressParser, decodeWords as postalDecodeWords } from 'postal-mime'
import { addressParser, decodeWords, MimeParser } from '../../src/mime'
import { messages } from './corpus'

type ContentShape = { kind: string, base64: string } | null

function contentShape(content: Attachment['content'] | undefined): ContentShape {
  if (content === undefined || content === null)
    return null

  if (typeof content === 'string')
    return { kind: 'string', base64: content }

  const bytes = content instanceof Uint8Array ? content : new Uint8Array(content)
  const kind = content instanceof Uint8Array ? 'Uint8Array' : 'ArrayBuffer'

  return { kind, base64: Buffer.from(bytes).toString('base64') }
}

/** Comparable form of a parsed message: every buffer becomes a tagged base64 string. */
function normalize(email: Email): unknown {
  return {
    ...email,
    attachments: (email.attachments || []).map(attachment => ({
      ...attachment,
      content: contentShape(attachment.content),
    })),
  }
}

const OPTION_SETS: { name: string, options?: MimeParserOptions }[] = [
  { name: 'defaults', options: undefined },
  { name: 'attachmentEncoding=base64', options: { attachmentEncoding: 'base64' } },
  { name: 'attachmentEncoding=utf8', options: { attachmentEncoding: 'utf8' } },
  { name: 'rfc822Attachments', options: { rfc822Attachments: true } },
  { name: 'forceRfc822Attachments', options: { forceRfc822Attachments: true } },
  { name: 'maxRfc822NestingDepth=0', options: { maxRfc822NestingDepth: 0 } },
]

describe('mime parser parity with postal-mime', () => {
  for (const optionSet of OPTION_SETS) {
    describe(optionSet.name, () => {
      for (const message of messages) {
        it(message.name, async () => {
          const expected = normalize(await PostalMime.parse(message.raw, optionSet.options as never) as Email)
          const actual = normalize(await MimeParser.parse(message.raw, optionSet.options))

          expect(actual).toEqual(expected as never)
        })
      }
    })
  }

  it('matches for every input shape', async () => {
    const raw = messages[0].raw
    const bytes = new TextEncoder().encode(raw)

    const expected = normalize(await PostalMime.parse(raw) as Email)

    expect(normalize(await MimeParser.parse(bytes))).toEqual(expected as never)
    expect(normalize(await MimeParser.parse(bytes.buffer))).toEqual(expected as never)
    expect(normalize(await MimeParser.parse(new Blob([bytes])))).toEqual(expected as never)
    expect(normalize(await MimeParser.parse(new Response(bytes).body!))).toEqual(expected as never)
    expect(normalize(MimeParser.parseSync(raw))).toEqual(expected as never)
  })
})

const ADDRESS_FIELDS = [
  'Test <test@example.com>',
  'test@example.com',
  '"Last, First" <first@example.com>, Second <second@example.com>',
  'Group Name: one@example.com, two@example.com;',
  '=?utf-8?B?VGhvbWFzIE3DvGxsZXI=?= <thomas@example.de>',
  '=?utf-8?B?dGVzdEBldmlsLmNv?=',
  'Nested: Inner: deep@example.com;;',
  'no-at-sign',
  '(comment only)',
  '"user@domain"@example.com',
  'Name <weird<@example.com>',
  'a@b.com, , c@d.com',
  'Sender (Comment) <sender@example.com>',
  'undisclosed-recipients:;',
  'multi @ at @ signs@example.com',
]

describe('address parser parity with postal-mime', () => {
  for (const field of ADDRESS_FIELDS) {
    it(JSON.stringify(field), () => {
      expect(addressParser(field)).toEqual(postalAddressParser(field) as never)
      expect(addressParser(field, { flatten: true })).toEqual(
        postalAddressParser(field, { flatten: true }) as never,
      )
    })
  }
})

const ENCODED_WORDS = [
  'plain text',
  '=?utf-8?B?SGVsbG8gd29ybGQ=?=',
  '=?utf-8?Q?Gr=C3=BC=C3=9Fe?=',
  '=?iso-8859-1?Q?=E4=F6=FC?=',
  '=?utf-8?B?SGVsbG8g?= =?utf-8?B?d29ybGQ=?=',
  '=?utf-8?B?4pyT?= and =?utf-8?B?4pyU?=',
  'prefix =?utf-8?B?SGVsbG8=?= suffix',
  '=?unknown-charset?Q?test?=',
  '=?utf-8?Q?a=?= =?utf-8?Q?b?=',
  '=?shift_jis?B?g0GDQoND?=',
]

describe('decodeWords parity with postal-mime', () => {
  for (const value of ENCODED_WORDS) {
    it(JSON.stringify(value), () => {
      expect(decodeWords(value)).toBe(postalDecodeWords(value))
    })
  }
})
