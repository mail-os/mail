import { describe, expect, test } from 'bun:test'
import { dateBoundary, mergeRecipients, messageKey, rangeSelection, readableBytes, recipient, recipients, splitRecipients } from './functions/mail-utils'

describe('recipient entry', () => {
  test('preserves quoted commas, escaped names, duplicates and incomplete addresses', () => {
    const input = '"Doe, Jane" <jane@example.com>; "A\\"B" <a@example.com>, JANE@example.com, incomplete@'
    const values = recipients(input)
    expect(values.map(item => item.address)).toEqual(['jane@example.com', 'a@example.com', 'incomplete@'])
    expect(values[0].name).toBe('Doe, Jane')
    expect(values[1].name).toBe('A"B')
    expect(values[2].valid).toBe(false)
    expect(splitRecipients('"unfinished, name')).toEqual(['"unfinished, name'])
  })
  test('deduplicates additions without replacing a known display name', () => {
    const known = recipients('Jane <jane@example.com>')
    const result = mergeRecipients(known, recipients('JANE@example.com, another@example.com'))
    expect(result).toHaveLength(2)
    expect(result[0].name).toBe('Jane')
    for (const value of ['a@b@c', '../x@example.com', 'a\\b@example.com', '.a@example.com', 'a..b@example.com', 'a@example.com\r\nBcc:x@y.test']) expect(recipient(value).valid).toBe(false)
  })
})

test('bulk selection distinguishes folder UIDs and selects both range directions', () => {
  const rows = [{ folder: 'INBOX', uid: 1 }, { folder: 'Sent', uid: 1 }, { folder: 'INBOX', uid: 2 }]
  expect(messageKey(rows[0])).not.toBe(messageKey(rows[1]))
  expect(rangeSelection(rows, messageKey(rows[2]), rows[0])).toEqual(rows)
  expect(rangeSelection(rows, 'missing:1', rows[1])).toEqual([rows[1]])
})

test('size labels and local date bounds cover a whole day', () => {
  expect(readableBytes(5 * 1024 * 1024)).toBe('5.0 MiB')
  expect(dateBoundary('')).toBeNull()
  expect(dateBoundary('2026-10-10', true)! - dateBoundary('2026-10-10')!).toBe(86399)
  expect(() => dateBoundary('invalid')).toThrow('Enter a valid date')
})
