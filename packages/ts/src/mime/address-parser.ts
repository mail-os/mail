/**
 * RFC 5322 address field parsing.
 */

import type { Address, AddressParserOptions, Mailbox } from './types'
import { decodeWords, isEncodedWordsOnly } from './decode-strings'

const WORD_CHAR_REGEX = /\w/
const NON_SPACE_TOKEN_REGEX = /\S+/g

/**
 * Finds the first address looking token in a run of text.
 *
 * This replaces a `\s*\b[^@\s]+@[^\s]+\b\s*` scan over the whole string, which
 * backtracks quadratically: the leading `\s*` makes every position inside a whitespace
 * run a viable start, and `[^@\s]+` then gives back one character at a time looking for
 * an '@'. A single header well inside the default size limit could hold a core busy for
 * minutes.
 *
 * Scanning whitespace delimited tokens instead is linear and keeps the word boundary
 * semantics of the regex: the local part has to open on a word character and the domain
 * has to end on one.
 */
function findAddressInText(text: string): { index: number, length: number, value: string } | null {
  NON_SPACE_TOKEN_REGEX.lastIndex = 0

  let match = NON_SPACE_TOKEN_REGEX.exec(text)
  while (match) {
    const token = match[0]
    const at = token.indexOf('@')

    // `\b[^@\s]+@` needs at least one character before the '@'
    let start = 0
    while (start < at && !WORD_CHAR_REGEX.test(token.charAt(start)))
      start++

    if (start < at) {
      // `[^\s]+\b` needs at least one character after the '@', ending on a word character
      let end = token.length
      while (end > at + 1 && !WORD_CHAR_REGEX.test(token.charAt(end - 1)))
        end--

      if (end > at + 1)
        return { index: match.index + start, length: end - start, value: token.substring(start, end) }
    }

    match = NON_SPACE_TOKEN_REGEX.exec(text)
  }

  return null
}

interface Token {
  type: 'operator' | 'text'
  value: string
  noBreak?: boolean
}

type TokenState = 'address' | 'comment' | 'group' | 'text'

/**
 * Converts the tokens of a single address into an address object.
 *
 * @param tokens Tokens of one comma separated address
 * @param depth Current recursion depth, for nested group protection
 */
function handleAddress(tokens: Token[], depth: number): Address[] {
  let isGroup = false
  let state: TokenState = 'text'
  const addresses: Address[] = []
  const data: Record<TokenState, string[]> = {
    address: [],
    comment: [],
    group: [],
    text: [],
  }
  // Track which text tokens came from inside quotes
  const textWasQuoted: boolean[] = []
  let insideQuotes = false

  // Filter out <addresses>, (comments) and regular text
  for (let i = 0, len = tokens.length; i < len; i++) {
    const token = tokens[i]
    const prevToken = i ? tokens[i - 1] : null

    if (token.type === 'operator') {
      switch (token.value) {
        case '<':
          state = 'address'
          insideQuotes = false
          break
        case '(':
          state = 'comment'
          insideQuotes = false
          break
        case ':':
          state = 'group'
          isGroup = true
          insideQuotes = false
          break
        case '"':
          // Track quote state for text tokens
          insideQuotes = !insideQuotes
          state = 'text'
          break
        default:
          state = 'text'
          insideQuotes = false
          break
      }
      continue
    }

    if (!token.value)
      continue

    let value = token.value
    if (state === 'address') {
      // handle the case where an unquoted name includes a "<"
      // Apple Mail truncates everything between an unexpected < and an address
      // and so will we
      value = value.replace(/^[^<]*<\s*/, '')
    }

    if (prevToken && prevToken.noBreak && data[state].length) {
      // join values
      data[state][data[state].length - 1] += value
      if (state === 'text' && insideQuotes)
        textWasQuoted[textWasQuoted.length - 1] = true
    }
    else {
      data[state].push(value)
      if (state === 'text')
        textWasQuoted.push(insideQuotes)
    }
  }

  // If there is no text but a comment, replace the two
  if (!data.text.length && data.comment.length) {
    data.text = data.comment
    data.comment = []
  }

  if (isGroup) {
    // http://tools.ietf.org/html/rfc2822#appendix-A.1.3
    const name = data.text.join(' ')

    // Parse group members, but flatten any nested groups (RFC 5322 does not allow nesting)
    let groupMembers: Mailbox[] = []
    if (data.group.length) {
      const parsedGroup = parseAddressList(data.group.join(','), depth + 1)
      parsedGroup.forEach((member) => {
        if (member.group)
          groupMembers = groupMembers.concat(member.group)
        else
          groupMembers.push(member)
      })
    }

    addresses.push({ name: decodeWords(name), group: groupMembers })
    return addresses
  }

  // If no address was found, try to detect one from regular text
  if (!data.address.length && data.text.length) {
    for (let i = data.text.length - 1; i >= 0; i--) {
      // Do not extract email addresses from quoted strings. RFC 5321 allows '@' inside a
      // quoted local part, as in "user@domain"@example.com, and extracting the inner
      // address from it misroutes the message.
      if (!textWasQuoted[i] && /^[^@\s]+@[^@\s]+$/.test(data.text[i])) {
        data.address = data.text.splice(i, 1)
        textWasQuoted.splice(i, 1)
        break
      }
    }

    // still no address
    if (!data.address.length) {
      for (let i = data.text.length - 1; i >= 0; i--) {
        if (textWasQuoted[i])
          continue

        // handles an email address that has more than one @
        const found = findAddressInText(data.text[i])
        if (found) {
          data.address = [found.value]
          // the address and the whitespace around it collapse to one space
          data.text[i] = (
            `${data.text[i].substring(0, found.index).replace(/\s+$/, '')} ${data.text[i].substring(found.index + found.length).replace(/^\s+/, '')}`
          ).trim()
          break
        }
        data.text[i] = data.text[i].trim()
      }
    }
  }

  // If there is still no text but a comment exists, replace the two
  if (!data.text.length && data.comment.length) {
    data.text = data.comment
    data.comment = []
  }

  // Keep only the first address occurrence, push others to regular text
  if (data.address.length > 1)
    data.text = data.text.concat(data.address.splice(1))

  const text = data.text.join(' ')
  const addressValue = data.address.join(' ')

  if (!addressValue && isEncodedWordsOnly(text.trim())) {
    // try to extract words from text content
    const decodedText = decodeWords(text)
    // Only re-parse if the decoded text contains an angle-bracket address. Without this,
    // a bare encoded email is fabricated into an address out of attacker controlled input.
    if (/<[^<>]+@[^<>]+>/.test(decodedText)) {
      const parsedSubAddresses = parseAddressList(decodedText, depth)
      if (parsedSubAddresses.length)
        return parsedSubAddresses
    }
    // No usable address found - treat the decoded text as a display name only
    return [{ address: '', name: decodedText }]
  }

  const address: Mailbox = {
    address: addressValue || text || '',
    name: decodeWords(text || addressValue || ''),
  }

  if (address.address === address.name) {
    if (address.address.includes('@'))
      address.name = ''
    else
      address.address = ''
  }

  addresses.push(address)

  return addresses
}

const CHR_TAB = 0x09
const CHR_LF = 0x0A
const CHR_CR = 0x0D
const CHR_SPACE = 0x20
const CHR_COMMA = 0x2C
const CHR_SEMICOLON = 0x3B

// Operator tokens and which token is expected to end the sequence. A semicolon is not a
// legal delimiter in the RFC 2822 grammar other than for terminating a group, but it is
// not valid for anything else in this context either, and mail clients have historically
// let their users write it in place of a comma.
const OPERATORS: Record<string, string> = {
  '"': '"',
  '(': ')',
  '<': '>',
  ',': '',
  ':': ';',
  ';': '',
}

// A break after an operator is any character that can not continue the token
function breaksToken(code: number): boolean {
  return code === CHR_SPACE || code === CHR_TAB || code === CHR_CR || code === CHR_LF || code === CHR_COMMA || code === CHR_SEMICOLON
}

/**
 * Splits an address field into operator and text tokens.
 */
function tokenize(str: string): Token[] {
  const nodes: Token[] = []

  let operatorExpecting = ''
  let escaped = false
  let node: Token | null = null

  for (let i = 0, len = str.length; i < len; i++) {
    const chr = str.charAt(i)

    if (!escaped) {
      if (chr === operatorExpecting) {
        const operator: Token = { type: 'operator', value: chr }
        if (i < len - 1 && !breaksToken(str.charCodeAt(i + 1)))
          operator.noBreak = true

        nodes.push(operator)
        node = null
        operatorExpecting = ''
        continue
      }

      if (!operatorExpecting && chr in OPERATORS) {
        nodes.push({ type: 'operator', value: chr })
        node = null
        operatorExpecting = OPERATORS[chr]
        continue
      }

      if (operatorExpecting === '"' && chr === '\\') {
        escaped = true
        continue
      }
    }

    if (!node) {
      node = { type: 'text', value: '' }
      nodes.push(node)
    }

    const code = str.charCodeAt(i)
    if (code === CHR_LF) {
      // Convert newlines to spaces. A carriage return is ignored, as \r and \n usually go
      // together and the \n already contributes the whitespace. A lone \r means something
      // is fishy.
      node.value += ' '
    }
    else if (code >= 0x21 || code === CHR_SPACE || code === CHR_TAB) {
      // skip command bytes
      node.value += chr
    }

    escaped = false
  }

  const tokens: Token[] = []
  for (const entry of nodes) {
    entry.value = entry.value.trim()
    if (entry.value)
      tokens.push(entry)
  }

  return tokens
}

/**
 * Maximum recursion depth for parsing nested groups. RFC 5322 does not allow nested
 * groups, so this only ever guards against input crafted to overflow the stack.
 */
const MAX_NESTED_GROUP_DEPTH = 50

function parseAddressList(str: string, depth: number): Address[] {
  if (depth > MAX_NESTED_GROUP_DEPTH)
    return []

  const tokens = tokenize((str || '').toString())

  const groups: Token[][] = []
  let current: Token[] = []

  for (const token of tokens) {
    if (token.type === 'operator' && (token.value === ',' || token.value === ';')) {
      if (current.length)
        groups.push(current)
      current = []
    }
    else {
      current.push(token)
    }
  }

  if (current.length)
    groups.push(current)

  let parsedAddresses: Address[] = []
  for (const group of groups) {
    const parsed = handleAddress(group, depth)
    if (parsed.length)
      parsedAddresses = parsedAddresses.concat(parsed)
  }

  return parsedAddresses
}

function flattenAddresses(list: Address[], into: Mailbox[]): Mailbox[] {
  for (const address of list) {
    if (address.group)
      flattenAddresses(address.group, into)
    else
      into.push(address)
  }
  return into
}

/**
 * Parses structured email addresses out of an address field.
 *
 * `'Name <address@domain>'` becomes `[{ name: 'Name', address: 'address@domain' }]`.
 */
export function addressParser(str: string, options?: AddressParserOptions): Address[] {
  const parsed = parseAddressList(str, 0)

  if (options?.flatten)
    return flattenAddresses(parsed, [])

  return parsed
}

export default addressParser
