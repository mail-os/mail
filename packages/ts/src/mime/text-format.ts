/**
 * Conversions between the plain text and HTML views of a message, and the header block
 * rendered in front of an inlined `message/rfc822` part.
 */

import type { Address, Email, Mailbox } from './types'
import { htmlEntities } from './html-entities'

const ENTITY_REGEX = /&(#\d+|#x[a-f0-9]+|[a-z]+\d*);?/gi

export function decodeHTMLEntities(str: string): string {
  // The scan is far cheaper than the regex pass, and most text carries no entity
  if (str.indexOf('&') < 0)
    return str

  return str.replace(ENTITY_REGEX, (match, entity: string) => {
    const named = htmlEntities.get(match)
    if (named !== undefined)
      return named

    if (entity.charAt(0) !== '#' || match.charAt(match.length - 1) !== ';') {
      // keep as is, invalid or unknown sequence
      return match
    }

    let codePoint = entity.charAt(1) === 'x' || entity.charAt(1) === 'X'
      ? Number.parseInt(entity.slice(2), 16)
      : Number.parseInt(entity.slice(1), 10)

    let output = ''

    if ((codePoint >= 0xD800 && codePoint <= 0xDFFF) || codePoint > 0x10FFFF) {
      // Invalid range, return a replacement character instead
      return '�'
    }

    if (codePoint > 0xFFFF) {
      codePoint -= 0x10000
      output += String.fromCharCode(((codePoint >>> 10) & 0x3FF) | 0xD800)
      codePoint = 0xDC00 | (codePoint & 0x3FF)
    }

    output += String.fromCharCode(codePoint)

    return output
  })
}

export function escapeHtml(str: string): string {
  return str.trim().replace(/["'&<>?]/g, (c) => {
    let hex = c.charCodeAt(0).toString(16)
    if (hex.length < 2)
      hex = `0${hex}`
    return `&#x${hex.toUpperCase()};`
  })
}

export function textToHtml(str: string): string {
  const html = escapeHtml(str).replace(/\n/g, '<br />')
  return `<div>${html}</div>`
}

export function htmlToText(str: string): string {
  str = str
    // tags can not be matched across a line break, so newlines are parked on a marker
    // character that can not appear in the source and restored at the end
    .replace(/\r?\n/g, '\u0001')
    .replace(/<!--.*?-->/gi, ' ')

    .replace(/<br\b[^>]*>/gi, '\n')
    .replace(/<\/?(?:div|p|table|td|th|tr)\b[^>]*>/gi, '\n\n')
    .replace(/<script\b[^>]*>.*?<\/script\b[^>]*>/gi, ' ')
    .replace(/^.*<body\b[^>]*>/i, '')
    .replace(/^.*<\/head\b[^>]*>/i, '')
    .replace(/^.*<!doctype\b[^>]*>/i, '')
    .replace(/<\/body\b[^>]*>.*$/i, '')
    .replace(/<\/html\b[^>]*>.*$/i, '')

    // The attribute scan and the href capture overlap, so a crafted anchor that never
    // closes can make this backtrack. Kept as it is because it decides what a link turns
    // into in the plain text view, and narrowing the capture would silently rewrite the
    // href of every quoted URL that carries a '>'.
    // eslint-disable-next-line no-super-linear-backtracking
    .replace(/<a\b[^>]*href\s*=\s*["']?([^\s"']+)[^>]*>/gi, ' ($1) ')

    .replace(/<\/?(?:a|b|em|i|span|strong|u)\b[^>]*>/gi, '')

    .replace(/<li\b[^>]*>[\n\u0001\s]*/gi, '* ')

    .replace(/<hr\b[^>]*>/g, '\n-------------\n')

    .replace(/<[^>]*>/g, ' ')

    // convert linebreak placeholders back to newlines
    .replace(/\u0001/g, '\n')

    .replace(/[\t ]+/g, ' ')

    .replace(/^\s+$/gm, '')

    .replace(/\n\n+/g, '\n\n')
    .replace(/^\n+/, '\n')
    .replace(/\n+$/, '\n')

  return decodeHTMLEntities(str)
}

// Constructing an Intl.DateTimeFormat has to load and resolve the locale data, which
// costs orders of magnitude more than formatting with it. A forwarded message carries
// one date per nesting level, and building a formatter for each of them dominated the
// parse of a message with several inlined copies inside it.
let dateFormatter: Intl.DateTimeFormat | null = null

function getDateFormatter(): Intl.DateTimeFormat {
  if (!dateFormatter) {
    dateFormatter = new Intl.DateTimeFormat('default', {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
      hour12: false,
    })
  }
  return dateFormatter
}

// A message date is not always a date. The parser keeps the raw header value when it
// does not parse, and Intl.DateTimeFormat throws a RangeError on that, which would
// reject the whole parse of any message carrying a forwarded copy with a broken Date.
function formatDate(date: string): string {
  if (typeof Intl === 'undefined')
    return date

  const parsed = new Date(date)
  if (Number.isNaN(parsed.getTime()))
    return date

  return getDateFormatter().format(parsed)
}

function formatTextAddress(address: Mailbox): string {
  return ([] as string[])
    .concat(address.name || [])
    .concat(address.name ? `<${address.address}>` : address.address)
    .join(' ')
}

function formatTextAddresses(addresses: Address[]): string {
  const parts: string[] = []

  const processAddress = (address: Address, partCounter: number): void => {
    if (partCounter)
      parts.push(', ')

    if (address.group) {
      parts.push(`${address.name}:`)
      address.group.forEach(processAddress)
      parts.push(';')
    }
    else {
      parts.push(formatTextAddress(address))
    }
  }

  addresses.forEach(processAddress)

  return parts.join('')
}

function formatHtmlAddress(address: Mailbox): string {
  return `<a href="mailto:${escapeHtml(address.address)}" class="postal-email-address">${escapeHtml(address.name || `<${address.address}>`)}</a>`
}

function formatHtmlAddresses(addresses: Address[]): string {
  const parts: string[] = []

  const processAddress = (address: Address, partCounter: number): void => {
    if (partCounter)
      parts.push('<span class="postal-email-address-separator">, </span>')

    if (address.group) {
      parts.push(`<span class="postal-email-address-group">${escapeHtml(address.name)}:</span>`)
      address.group.forEach(processAddress)
      parts.push('<span class="postal-email-address-group">;</span>')
    }
    else {
      parts.push(formatHtmlAddress(address))
    }
  }

  addresses.forEach(processAddress)

  return parts.join(' ')
}

function foldLines(str: string, lineLength = 76, afterSpace = false): string {
  str = (str || '').toString()

  let pos = 0
  const len = str.length
  let result = ''
  let line: string
  let match: RegExpMatchArray | null

  while (pos < len) {
    line = str.substr(pos, lineLength)
    if (line.length < lineLength) {
      result += line
      break
    }

    match = line.match(/^[^\n\r]*(?:\r?\n|\r)/)
    if (match) {
      line = match[0]
      result += line
      pos += line.length
      continue
    }

    match = line.match(/(\s+)\S*$/)
    if (match && match[0].length - (afterSpace ? (match[1] || '').length : 0) < line.length) {
      line = line.slice(0, line.length - (match[0].length - (afterSpace ? (match[1] || '').length : 0)))
    }
    else {
      match = str.slice(pos + line.length).match(/^\S+(\s*)/)
      if (match)
        line = line + match[0].slice(0, match[0].length - (!afterSpace ? (match[1] || '').length : 0))
    }

    result += line
    pos += line.length
    if (pos < len)
      result += '\r\n'
  }

  return result
}

interface HeaderRow {
  key: string
  val: string
}

function headerRows(message: Email): HeaderRow[] {
  const rows: HeaderRow[] = []

  // through the plural formatter, because `From:` may hold RFC 5322 group syntax
  // and a group has no address of its own
  if (message.from)
    rows.push({ key: 'From', val: formatTextAddresses([message.from]) })

  if (message.subject)
    rows.push({ key: 'Subject', val: message.subject })

  if (message.date)
    rows.push({ key: 'Date', val: formatDate(message.date) })

  if (message.to && message.to.length)
    rows.push({ key: 'To', val: formatTextAddresses(message.to) })

  if (message.cc && message.cc.length)
    rows.push({ key: 'Cc', val: formatTextAddresses(message.cc) })

  if (message.bcc && message.bcc.length)
    rows.push({ key: 'Bcc', val: formatTextAddresses(message.bcc) })

  return rows
}

/**
 * Renders the header block shown above an inlined `message/rfc822` part in the plain
 * text view.
 *
 * Keys and values are aligned, and the separator line matches the longest row:
 *
 *     -----------------------------
 *     From:    xx xx <xxx@xxx.com>
 *     Subject: Example Subject
 *     Date:    16/02/2021, 02:57:06
 *     To:      not@found.com
 *     -----------------------------
 */
export function formatTextHeader(message: Email): string {
  const rows = headerRows(message)

  const maxKeyLength = rows.reduce((acc, row) => (row.key.length > acc ? row.key.length : acc), 0)

  const lines = rows.flatMap((row) => {
    const sepLen = maxKeyLength - row.key.length
    const prefix = `${row.key}: ${' '.repeat(sepLen)}`
    const emptyPrefix = `${' '.repeat(row.key.length + 1)} ${' '.repeat(sepLen)}`

    return foldLines(row.val, 80, true)
      .split(/\r?\n/)
      .map(line => line.trim())
      .map((line, i) => `${i ? emptyPrefix : prefix}${line}`)
  })

  const maxLineLength = lines.reduce((acc, line) => (line.length > acc ? line.length : acc), 0)
  const lineMarker = '-'.repeat(maxLineLength)

  return `
${lineMarker}
${lines.join('\n')}
${lineMarker}
`
}

/**
 * Renders the header block shown above an inlined `message/rfc822` part in the HTML
 * view.
 */
export function formatHtmlHeader(message: Email): string {
  const rows: string[] = []

  if (message.from) {
    rows.push(
      `<div class="postal-email-header-key">From</div><div class="postal-email-header-value">${formatHtmlAddresses([message.from])}</div>`,
    )
  }

  if (message.subject) {
    rows.push(
      // The class names are part of the rendered output, not utility classes to sort
      // eslint-disable-next-line pickier/sort-tailwind-classes
      `<div class="postal-email-header-key">Subject</div><div class="postal-email-header-value postal-email-header-subject">${escapeHtml(message.subject)}</div>`,
    )
  }

  if (message.date) {
    rows.push(
      // eslint-disable-next-line pickier/sort-tailwind-classes
      `<div class="postal-email-header-key">Date</div><div class="postal-email-header-value postal-email-header-date" data-date="${escapeHtml(message.date)}">${escapeHtml(formatDate(message.date))}</div>`,
    )
  }

  if (message.to && message.to.length) {
    rows.push(
      `<div class="postal-email-header-key">To</div><div class="postal-email-header-value">${formatHtmlAddresses(message.to)}</div>`,
    )
  }

  if (message.cc && message.cc.length) {
    rows.push(
      `<div class="postal-email-header-key">Cc</div><div class="postal-email-header-value">${formatHtmlAddresses(message.cc)}</div>`,
    )
  }

  if (message.bcc && message.bcc.length) {
    rows.push(
      `<div class="postal-email-header-key">Bcc</div><div class="postal-email-header-value">${formatHtmlAddresses(message.bcc)}</div>`,
    )
  }

  return `<div class="postal-email-header">${rows.length ? '<div class="postal-email-header-row">' : ''}${rows.join('</div>\n<div class="postal-email-header-row">')}${rows.length ? '</div>' : ''}</div>`
}
