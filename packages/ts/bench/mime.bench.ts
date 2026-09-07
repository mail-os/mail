/* eslint-disable no-console */
/**
 * MIME parser benchmarks, against postal-mime.
 *
 * Run with `bun run bench:mime` from packages/ts. Both parsers get the same input and
 * the same async call shape, so the numbers compare the parsing work rather than the
 * calling convention.
 */

import type { CaseResult } from './harness'
import process from 'node:process'
import PostalMime, { addressParser as postalAddressParser, decodeWords as postalDecodeWords } from 'postal-mime'
import { addressParser, decodeWords, MimeParser } from '../src/mime'
import { messages } from '../test/mime/corpus'
import { benchCase, printResults } from './harness'

const BASELINE = 'postal-mime'
const SUBJECT = 'ts-mime'

const args = new Set(process.argv.slice(2))
const quick = args.has('--quick')
const options = quick ? { minTime: 120, rounds: 1, warmupTime: 50 } : {}

async function parseBenchmarks(): Promise<CaseResult[]> {
  const results: CaseResult[] = []

  for (const message of messages) {
    const raw = message.raw
    results.push(await benchCase(
      message.name,
      [
        { name: BASELINE, run: () => PostalMime.parse(raw) },
        { name: SUBJECT, run: () => MimeParser.parse(raw) },
      ],
      { ...options, bytes: Buffer.byteLength(raw) },
    ))
  }

  return results
}

async function attachmentEncodingBenchmarks(): Promise<CaseResult[]> {
  const results: CaseResult[] = []

  for (const name of ['attachment/base64-64kb', 'attachment/many-small']) {
    const raw = messages.find(message => message.name === name)!.raw

    for (const encoding of ['base64', 'utf8'] as const) {
      results.push(await benchCase(
        `${name} -> ${encoding}`,
        [
          { name: BASELINE, run: () => PostalMime.parse(raw, { attachmentEncoding: encoding }) },
          { name: SUBJECT, run: () => MimeParser.parse(raw, { attachmentEncoding: encoding }) },
        ],
        { ...options, bytes: Buffer.byteLength(raw) },
      ))
    }
  }

  return results
}

const ADDRESS_FIELD = [
  '"Doe, John" <john.doe@example.com>',
  'Jane Roe <jane@example.net>',
  '=?utf-8?B?VGhvbWFzIE3DvGxsZXI=?= <thomas@example.de>',
  'Group: one@example.com, two@example.com;',
  'plain@example.org',
].join(', ')

const ENCODED_SUBJECT = '=?utf-8?B?SGVsbG8g?= =?utf-8?B?d29ybGQg?= =?iso-8859-1?Q?=E4=F6=FC?= plain tail'
const PLAIN_SUBJECT = 'Re: Your invoice for January 2024 is ready to download'

async function helperBenchmarks(): Promise<CaseResult[]> {
  return [
    await benchCase('addressParser (mixed field)', [
      { name: BASELINE, run: () => postalAddressParser(ADDRESS_FIELD) },
      { name: SUBJECT, run: () => addressParser(ADDRESS_FIELD) },
    ], options),

    await benchCase('decodeWords (encoded)', [
      { name: BASELINE, run: () => postalDecodeWords(ENCODED_SUBJECT) },
      { name: SUBJECT, run: () => decodeWords(ENCODED_SUBJECT) },
    ], options),

    await benchCase('decodeWords (plain)', [
      { name: BASELINE, run: () => postalDecodeWords(PLAIN_SUBJECT) },
      { name: SUBJECT, run: () => decodeWords(PLAIN_SUBJECT) },
    ], options),
  ]
}

async function main(): Promise<void> {
  console.log(`bun ${Bun.version}  ${process.platform}/${process.arch}`)

  const parse = await parseBenchmarks()
  printResults('parse: full messages', parse, BASELINE, SUBJECT)

  const encoding = await attachmentEncodingBenchmarks()
  printResults('parse: attachment encodings', encoding, BASELINE, SUBJECT)

  const helpers = await helperBenchmarks()
  printResults('helpers', helpers, BASELINE, SUBJECT)

  const all = [...parse, ...encoding, ...helpers]
  const losses = all.filter((result) => {
    const baseline = result.candidates.find(candidate => candidate.name === BASELINE)!
    const subject = result.candidates.find(candidate => candidate.name === SUBJECT)!
    return subject.opsPerSecond <= baseline.opsPerSecond
  })

  if (losses.length) {
    console.log(`\n${losses.length} case(s) not faster than ${BASELINE}:`)
    for (const loss of losses)
      console.log(`  ${loss.name}`)
    process.exitCode = 1
    return
  }

  console.log(`\n${SUBJECT} is faster than ${BASELINE} in all ${all.length} cases.`)
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
