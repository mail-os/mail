import type { MessageRef, Recipient } from './mail-types'

/** Delimit only outside quoted names and angle addresses; retain unfinished input. */
export function splitRecipients(value: string): string[] {
  const pieces: string[] = []
  let part = ''
  let quoted = false
  let angle = 0
  let escaped = false
  for (const character of value) {
    if (escaped) { part += character; escaped = false; continue }
    if (character === '\\' && quoted) { part += character; escaped = true; continue }
    if (character === '"') quoted = !quoted
    if (!quoted && character === '<') angle++
    if (!quoted && character === '>') angle = Math.max(0, angle - 1)
    if (!quoted && !angle && [',', ';', '\n', '\r'].includes(character)) {
      if (part.trim()) pieces.push(part.trim())
      part = ''
    }
    else part += character
  }
  if (part.trim()) pieces.push(part.trim())
  return pieces
}

export function validAddress(address: string): boolean {
  return address.length > 0 && new TextEncoder().encode(address).length <= 320
    && !/[\u0000-\u0020\u007f]/.test(address)
    && /^[^\s<>"/\\,;:@]+@[^\s<>"/\\,;:@]+$/.test(address)
    && !address.startsWith('.') && !address.includes('..')
}

export function recipient(raw: string): Recipient {
  const value = raw.trim()
  const match = /^\s*(.*?)\s*<([^<>]+)>\s*$/.exec(value)
  const address = (match?.[2] ?? value).trim()
  const name = (match?.[1] ?? '').trim().replace(/^"(.*)"$/, '$1').replace(/\\(["\\])/g, '$1')
  return { raw: value, name, address, valid: validAddress(address) }
}

export function recipientKey(item: Recipient): string { return (item.valid ? item.address : item.raw).toLowerCase() }
export function recipients(value: string): Recipient[] {
  const parsed = splitRecipients(value).map(recipient)
  return mergeRecipients([], parsed)
}

export function mergeRecipients(current: Recipient[], additions: Recipient[]): Recipient[] {
  const result = [...current]
  const known = new Set(current.map(recipientKey))
  for (const item of additions) {
    const key = recipientKey(item)
    if (!known.has(key)) { known.add(key); result.push(item) }
  }
  return result
}

export function messageKey(message: MessageRef): string { return `${encodeURIComponent(message.folder)}:${message.uid}` }
export function folderName(folder: string): string { return folder === 'INBOX' ? 'Inbox' : folder === '*' ? 'All mail' : folder }
export function readableBytes(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`
}
export function shortDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString([], { month: 'short', day: 'numeric' })
}
export function fullDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}
export function safeHtml(html: string): string {
  return `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">${html}`
}
export function dateBoundary(value: string, end = false): number | null {
  if (!value) return null
  const date = new Date(`${value}T00:00:00`)
  if (Number.isNaN(date.getTime())) throw new Error('Enter a valid date.')
  if (end) { date.setDate(date.getDate() + 1); date.setMilliseconds(-1) }
  return Math.floor(date.getTime() / 1000)
}
export function rangeSelection<T extends MessageRef>(rows: T[], anchor: string | null, target: T): T[] {
  const end = rows.findIndex(row => messageKey(row) === messageKey(target))
  const start = rows.findIndex(row => messageKey(row) === anchor)
  return start < 0 || end < 0 ? [target] : rows.slice(Math.min(start, end), Math.max(start, end) + 1)
}
