import type { MessageStore, Message } from './store'

export function createPop3Server(opts: {
  port?: number
  hostname?: string
  store: MessageStore
}) {
  const port = opts.port || 1110
  const hostname = opts.hostname || '0.0.0.0'
  const store = opts.store

  interface Session {
    user: string
    authed: boolean
    deleted: Set<string>
    messages: Message[] | null // cached after auth, per RFC 1939
  }

  // Per RFC 1939, message numbers are fixed for the session and never change.
  // Deleted messages remain in the array but are checked via the deleted set.
  function getSnapshot(session: Session): Message[] {
    if (!session.messages) {
      session.messages = store.getMessages({ limit: 10000 }).messages
    }
    return session.messages
  }

  function isDeleted(session: Session, idx: number): boolean {
    const msgs = getSnapshot(session)
    return idx >= 0 && idx < msgs.length && session.deleted.has(msgs[idx].id)
  }

  const server = Bun.listen({
    hostname,
    port,
    socket: {
      open(socket) {
        socket.data = { user: '', authed: false, deleted: new Set<string>(), messages: null } as Session
        socket.write('+OK mail-dev POP3 server ready\r\n')
      },
      data(socket, buffer) {
        const input = Buffer.from(buffer).toString()
        const session = socket.data as Session
        // Handle multiple commands in a single chunk
        const commandLines = input.split(/\r?\n/).filter(l => l.trim())
        for (const commandLine of commandLines) {
        const parts = commandLine.trim().split(' ')
        const cmd = parts[0].toUpperCase()

        if (cmd === 'CAPA') {
          socket.write(
            '+OK Capability list follows\r\n' +
            'USER\r\n' +
            'TOP\r\n' +
            'UIDL\r\n' +
            '.\r\n'
          )
        } else if (cmd === 'USER') {
          session.user = parts[1] || 'dev'
          socket.write('+OK\r\n')
        } else if (cmd === 'PASS') {
          session.authed = true
          // Snapshot messages at login time per RFC 1939
          session.messages = store.getMessages({ limit: 10000 }).messages
          socket.write('+OK Logged in\r\n')
        } else if (!session.authed && cmd !== 'QUIT') {
          socket.write('-ERR Not authenticated\r\n')
        } else if (cmd === 'STAT') {
          const msgs = getSnapshot(session)
          let count = 0, totalSize = 0
          for (let i = 0; i < msgs.length; i++) {
            if (!session.deleted.has(msgs[i].id)) {
              count++
              totalSize += msgs[i].size
            }
          }
          socket.write(`+OK ${count} ${totalSize}\r\n`)
        } else if (cmd === 'LIST') {
          const msgs = getSnapshot(session)
          if (parts[1]) {
            const idx = parseInt(parts[1]) - 1
            if (idx >= 0 && idx < msgs.length && !isDeleted(session, idx)) {
              socket.write(`+OK ${idx + 1} ${msgs[idx].size}\r\n`)
            } else {
              socket.write('-ERR No such message\r\n')
            }
          } else {
            let count = 0
            for (const m of msgs) { if (!session.deleted.has(m.id)) count++ }
            let response = `+OK ${count} messages\r\n`
            msgs.forEach((m, i) => {
              if (!session.deleted.has(m.id)) response += `${i + 1} ${m.size}\r\n`
            })
            response += '.\r\n'
            socket.write(response)
          }
        } else if (cmd === 'UIDL') {
          const msgs = getSnapshot(session)
          if (parts[1]) {
            const idx = parseInt(parts[1]) - 1
            if (idx >= 0 && idx < msgs.length && !isDeleted(session, idx)) {
              socket.write(`+OK ${idx + 1} ${msgs[idx].id}\r\n`)
            } else {
              socket.write('-ERR No such message\r\n')
            }
          } else {
            let response = `+OK\r\n`
            msgs.forEach((m, i) => {
              if (!session.deleted.has(m.id)) response += `${i + 1} ${m.id}\r\n`
            })
            response += '.\r\n'
            socket.write(response)
          }
        } else if (cmd === 'RETR') {
          const msgs = getSnapshot(session)
          const idx = parseInt(parts[1]) - 1
          if (idx >= 0 && idx < msgs.length && !isDeleted(session, idx)) {
            const msg = msgs[idx]
            const raw = msg.raw || `From: ${msg.from_addr}\r\nTo: ${JSON.parse(msg.to_addrs).join(', ')}\r\nSubject: ${msg.subject}\r\n\r\n${msg.text_body || msg.html_body}`
            socket.write(`+OK ${raw.length} octets\r\n${raw}\r\n.\r\n`)
            store.updateMessage(msg.id, { read: 1 })
          } else {
            socket.write('-ERR No such message\r\n')
          }
        } else if (cmd === 'TOP') {
          const msgs = getSnapshot(session)
          const idx = parseInt(parts[1]) - 1
          const lines = parseInt(parts[2]) || 0
          if (idx >= 0 && idx < msgs.length && !isDeleted(session, idx)) {
            const msg = msgs[idx]
            const raw = msg.raw || `From: ${msg.from_addr}\r\nSubject: ${msg.subject}\r\n\r\n${msg.text_body}`
            // Handle both \r\n and \n in raw content
            const sep = raw.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n'
            const headerEnd = raw.indexOf(sep)
            if (headerEnd >= 0) {
              const headers = raw.slice(0, headerEnd + sep.length)
              const lineSep = raw.includes('\r\n') ? '\r\n' : '\n'
              const body = raw.slice(headerEnd + sep.length).split(lineSep).slice(0, lines).join('\r\n')
              socket.write(`+OK\r\n${headers}${body}\r\n.\r\n`)
            } else {
              socket.write(`+OK\r\n${raw}\r\n.\r\n`)
            }
          } else {
            socket.write('-ERR No such message\r\n')
          }
        } else if (cmd === 'DELE') {
          const msgs = getSnapshot(session)
          const idx = parseInt(parts[1]) - 1
          if (idx >= 0 && idx < msgs.length && !isDeleted(session, idx)) {
            session.deleted.add(msgs[idx].id)
            socket.write('+OK Deleted\r\n')
          } else {
            socket.write('-ERR No such message\r\n')
          }
        } else if (cmd === 'RSET') {
          session.deleted.clear()
          socket.write('+OK\r\n')
        } else if (cmd === 'NOOP') {
          socket.write('+OK\r\n')
        } else if (cmd === 'QUIT') {
          // Actually delete marked messages on QUIT
          for (const id of session.deleted) {
            store.deleteMessage(id)
          }
          socket.write('+OK Bye\r\n')
          socket.end()
        } else {
          socket.write('-ERR Unknown command\r\n')
        }
        } // end for commandLines
      },
      close() {},
      error(socket, error) {
        console.error('[POP3] Socket error:', error.message)
      },
    },
  })

  return server
}
