import { randomUUID } from 'node:crypto'

export interface ParsedEmail {
  id: string
  from_addr: string
  from_name: string
  to_addrs: string[]
  cc_addrs: string[]
  bcc_addrs: string[]
  subject: string
  text_body: string
  html_body: string
  raw: string
  size: number
  attachments: { name: string; type: string; size: number; content: string }[]
  headers: Record<string, string>
}

export interface ChaosConfig {
  enabled: boolean
  reject_chance: number    // 0-100, chance of rejecting with 550
  slow_chance: number      // 0-100, chance of slow response (2-5s delay)
  disconnect_chance: number // 0-100, chance of dropping connection
  error_code: number       // custom error code to return
  error_message: string    // custom error message
}

const defaultChaos: ChaosConfig = {
  enabled: false,
  reject_chance: 0,
  slow_chance: 0,
  disconnect_chance: 0,
  error_code: 550,
  error_message: 'Mailbox unavailable (chaos mode)',
}

export function createSmtpServer(opts: {
  port?: number
  hostname?: string
  onMessage: (msg: ParsedEmail) => void
  getChaos?: () => ChaosConfig
}) {
  const port = opts.port || 1025
  const hostname = opts.hostname || '0.0.0.0'
  const getChaos = opts.getChaos || (() => defaultChaos)

  const server = Bun.listen({
    hostname,
    port,
    socket: {
      open(socket) {
        socket.data = { state: 'greeting', from: '', to: [] as string[], data: '', collecting: false }
        socket.write('220 mail-dev ESMTP Dev Mail Server\r\n')
      },
      data(socket, buffer) {
        const input = Buffer.from(buffer).toString()
        const session = socket.data as any
        const chaos = getChaos()

        // Chaos: random disconnect
        if (chaos.enabled && Math.random() * 100 < chaos.disconnect_chance) {
          socket.end()
          return
        }

        // Chaos: slow response
        const delay = chaos.enabled && Math.random() * 100 < chaos.slow_chance
          ? 2000 + Math.random() * 3000
          : 0

        const respond = (response: string) => {
          if (delay > 0) {
            setTimeout(() => {
              try { socket.write(response) } catch {}
            }, delay)
          } else {
            socket.write(response)
          }
        }

        // Helper to process collected data and deliver message
        const tryDeliverData = () => {
          // Handle both \r\n.\r\n and \n.\n line endings
          if (session.data.includes('\r\n.\r\n') || session.data.includes('\n.\n')) {
            // Strip terminator and dot-unstuff per RFC 5321 §4.5.2
            const raw = session.data.replace(/\r?\n\.\r?\n[\s\S]*$/, '').replace(/^\.\./gm, '.')

            // Chaos: reject after DATA
            if (chaos.enabled && Math.random() * 100 < chaos.reject_chance) {
              respond(`${chaos.error_code} ${chaos.error_message}\r\n`)
              session.collecting = false
              session.data = ''
              return
            }

            const parsed = parseEmail(raw, session.from, session.to)
            opts.onMessage(parsed)

            respond('250 2.0.0 Ok: message queued\r\n')
            session.collecting = false
            session.data = ''
            session.from = ''
            session.to = []
          }
        }

        if (session.collecting) {
          session.data += input
          tryDeliverData()
          return
        }

        const lines = input.split(/\r?\n/)
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]
          if (!line) continue // skip empty lines between commands
          const cmd = line.toUpperCase()

          if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
            respond(
              '250-mail-dev Hello\r\n' +
              '250-SIZE 52428800\r\n' +
              '250-8BITMIME\r\n' +
              '250-PIPELINING\r\n' +
              '250-SMTPUTF8\r\n' +
              '250 HELP\r\n'
            )
          } else if (cmd.startsWith('MAIL FROM:')) {
            // Chaos: reject at MAIL FROM
            if (chaos.enabled && Math.random() * 100 < chaos.reject_chance) {
              respond(`${chaos.error_code} ${chaos.error_message}\r\n`)
              continue
            }
            session.from = extractAddress(line.slice(10))
            respond('250 2.1.0 Ok\r\n')
          } else if (cmd.startsWith('RCPT TO:')) {
            session.to.push(extractAddress(line.slice(8)))
            respond('250 2.1.5 Ok\r\n')
          } else if (cmd === 'DATA') {
            session.collecting = true
            // Capture everything after the DATA line from the raw input (preserving blank lines)
            // Reconstruct the byte offset by joining the lines we've already processed
            // Find the actual position in the original input accounting for \r\n vs \n
            let pos = 0
            let lineCount = 0
            while (lineCount <= i && pos < input.length) {
              const nextCr = input.indexOf('\r\n', pos)
              const nextLf = input.indexOf('\n', pos)
              if (nextCr >= 0 && nextCr <= nextLf) {
                pos = nextCr + 2
              } else if (nextLf >= 0) {
                pos = nextLf + 1
              } else {
                pos = input.length
                break
              }
              lineCount++
            }
            session.data = input.slice(pos)
            respond('354 End data with <CR><LF>.<CR><LF>\r\n')
            tryDeliverData()
            return // Stop processing - rest is data, not commands
          } else if (cmd === 'RSET') {
            session.from = ''
            session.to = []
            session.data = ''
            session.collecting = false
            respond('250 2.0.0 Ok\r\n')
          } else if (cmd === 'QUIT') {
            respond('221 2.0.0 Bye\r\n')
            socket.end()
            return
          } else if (cmd === 'NOOP') {
            respond('250 2.0.0 Ok\r\n')
          } else if (cmd === 'VRFY') {
            respond('252 2.1.5 Cannot VRFY user\r\n')
          } else {
            respond('500 5.5.1 Unrecognized command\r\n')
          }
        }
      },
      close() {},
      error(socket, error) {
        console.error('[SMTP] Socket error:', error.message)
      },
    },
  })

  return server
}

function extractAddress(raw: string): string {
  const match = raw.match(/<([^>]*)>/)
  return match ? match[1] : raw.trim()
}

function parseEmail(raw: string, envelopeFrom: string, envelopeTo: string[]): ParsedEmail {
  const id = randomUUID()
  // Normalize line endings
  const normalized = raw.replace(/\r\n/g, '\n')
  const headerEnd = normalized.indexOf('\n\n')
  const headerSection = headerEnd >= 0 ? normalized.slice(0, headerEnd) : normalized
  const bodySection = headerEnd >= 0 ? normalized.slice(headerEnd + 2) : ''

  // Parse headers (handle folded lines)
  const headers: Record<string, string> = {}
  const headerLines = headerSection.replace(/\n([ \t])/g, ' ').split('\n')
  for (const line of headerLines) {
    const colonIdx = line.indexOf(':')
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim()
      const value = line.slice(colonIdx + 1).trim()
      headers[key.toLowerCase()] = value
    }
  }

  // Parse From
  const fromHeader = headers['from'] || envelopeFrom
  const fromMatch = fromHeader.match(/^"?([^"<]*)"?\s*<?([^>]*)>?$/)
  const from_name = fromMatch?.[1]?.trim() || ''
  const from_addr = fromMatch?.[2]?.trim() || fromHeader.trim()

  // Parse To
  const toHeader = headers['to'] || envelopeTo.join(', ')
  const to_addrs = parseAddressList(toHeader)

  // Parse CC
  const cc_addrs = headers['cc'] ? parseAddressList(headers['cc']) : []

  // Parse subject
  const subject = decodeHeader(headers['subject'] || '(No Subject)')

  // Parse body - handle MIME
  const contentType = headers['content-type'] || 'text/plain'
  let text_body = ''
  let html_body = ''
  const attachments: ParsedEmail['attachments'] = []

  if (contentType.includes('multipart/')) {
    const boundaryMatch = contentType.match(/boundary="?([^";\s]+)"?/)
    if (boundaryMatch) {
      const parts = parseMimeParts(bodySection, boundaryMatch[1])
      for (const part of parts) {
        const partCt = (part.headers['content-type'] || 'text/plain').toLowerCase()
        const disposition = (part.headers['content-disposition'] || '').toLowerCase()

        if (disposition.includes('attachment') || (partCt !== 'text/plain' && partCt !== 'text/html' && !partCt.startsWith('multipart/'))) {
          const nameMatch = disposition.match(/filename="?([^";\n]+)"?/) || partCt.match(/name="?([^";\n]+)"?/)
          attachments.push({
            name: nameMatch?.[1] || 'attachment',
            type: partCt.split(';')[0],
            size: part.body.length,
            content: part.body,
          })
        } else if (partCt.includes('text/html')) {
          html_body = decodeBody(part.body, part.headers['content-transfer-encoding'])
        } else if (partCt.includes('text/plain')) {
          text_body = decodeBody(part.body, part.headers['content-transfer-encoding'])
        } else if (partCt.includes('multipart/')) {
          // Nested multipart
          const nestedBoundary = partCt.match(/boundary="?([^";\s]+)"?/)
          if (nestedBoundary) {
            const nestedParts = parseMimeParts(part.body, nestedBoundary[1])
            for (const np of nestedParts) {
              const npCt = (np.headers['content-type'] || 'text/plain').toLowerCase()
              if (npCt.includes('text/html')) {
                html_body = decodeBody(np.body, np.headers['content-transfer-encoding'])
              } else if (npCt.includes('text/plain')) {
                text_body = decodeBody(np.body, np.headers['content-transfer-encoding'])
              }
            }
          }
        }
      }
    }
  } else if (contentType.includes('text/html')) {
    html_body = decodeBody(bodySection, headers['content-transfer-encoding'])
  } else {
    text_body = decodeBody(bodySection, headers['content-transfer-encoding'])
  }

  return {
    id,
    from_addr,
    from_name,
    to_addrs,
    cc_addrs,
    bcc_addrs: envelopeTo.filter(a => !to_addrs.includes(a) && !cc_addrs.includes(a)),
    subject,
    text_body,
    html_body,
    raw,
    size: raw.length,
    attachments,
    headers,
  }
}

function parseAddressList(raw: string): string[] {
  return raw.split(',').map(a => {
    const match = a.match(/<([^>]*)>/)
    return match ? match[1].trim() : a.trim()
  }).filter(Boolean)
}

function parseMimeParts(body: string, boundary: string): { headers: Record<string, string>, body: string }[] {
  const parts: { headers: Record<string, string>, body: string }[] = []
  const sep = `--${boundary}`
  const sections = body.split(sep)

  for (let i = 1; i < sections.length; i++) {
    const section = sections[i]
    if (section.startsWith('--')) break // closing boundary

    // Handle both \r\n and \n line endings
    const normalizedSection = section.replace(/\r\n/g, '\n')
    const headerEnd = normalizedSection.indexOf('\n\n')
    if (headerEnd < 0) continue

    const headerSection = normalizedSection.slice(0, headerEnd).replace(/^\n/, '')
    const bodyContent = normalizedSection.slice(headerEnd + 2).replace(/\n$/, '')

    const headers: Record<string, string> = {}
    const headerLines = headerSection.replace(/\n([ \t])/g, ' ').split('\n')
    for (const line of headerLines) {
      const colonIdx = line.indexOf(':')
      if (colonIdx > 0) {
        headers[line.slice(0, colonIdx).trim().toLowerCase()] = line.slice(colonIdx + 1).trim()
      }
    }

    parts.push({ headers, body: bodyContent })
  }

  return parts
}

function decodeBody(body: string, encoding?: string): string {
  if (!encoding) return body
  const enc = encoding.toLowerCase().trim()

  if (enc === 'base64') {
    try {
      return Buffer.from(body.replace(/\s/g, ''), 'base64').toString('utf-8')
    } catch {
      return body
    }
  }

  if (enc === 'quoted-printable') {
    return body
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  }

  return body
}

function decodeHeader(value: string): string {
  // Decode RFC 2047 encoded words: =?charset?encoding?text?=
  return value.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, encoding, text) => {
    void charset
    if (encoding.toUpperCase() === 'B') {
      try { return Buffer.from(text, 'base64').toString('utf-8') } catch { return text }
    }
    if (encoding.toUpperCase() === 'Q') {
      return text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_: string, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)))
    }
    return text
  })
}
