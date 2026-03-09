import type { MessageStore, Message } from './store'

export function createPop3Server(opts: {
  port?: number
  hostname?: string
  store: MessageStore
}) {
  const port = opts.port || 1110
  const hostname = opts.hostname || '0.0.0.0'
  const store = opts.store

  const server = Bun.listen({
    hostname,
    port,
    socket: {
      open(socket) {
        socket.data = { state: 'auth', user: '', authed: false, deleted: new Set<string>() }
        socket.write('+OK mail-dev POP3 server ready\r\n')
      },
      data(socket, buffer) {
        const input = Buffer.from(buffer).toString().trim()
        const session = socket.data as any
        const parts = input.split(' ')
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
          socket.write('+OK Logged in\r\n')
        } else if (!session.authed && cmd !== 'QUIT') {
          socket.write('-ERR Not authenticated\r\n')
        } else if (cmd === 'STAT') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          const totalSize = active.reduce((s, m) => s + m.size, 0)
          socket.write(`+OK ${active.length} ${totalSize}\r\n`)
        } else if (cmd === 'LIST') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          if (parts[1]) {
            const idx = parseInt(parts[1]) - 1
            if (idx >= 0 && idx < active.length) {
              socket.write(`+OK ${idx + 1} ${active[idx].size}\r\n`)
            } else {
              socket.write('-ERR No such message\r\n')
            }
          } else {
            let response = `+OK ${active.length} messages\r\n`
            active.forEach((m, i) => { response += `${i + 1} ${m.size}\r\n` })
            response += '.\r\n'
            socket.write(response)
          }
        } else if (cmd === 'UIDL') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          if (parts[1]) {
            const idx = parseInt(parts[1]) - 1
            if (idx >= 0 && idx < active.length) {
              socket.write(`+OK ${idx + 1} ${active[idx].id}\r\n`)
            } else {
              socket.write('-ERR No such message\r\n')
            }
          } else {
            let response = `+OK\r\n`
            active.forEach((m, i) => { response += `${i + 1} ${m.id}\r\n` })
            response += '.\r\n'
            socket.write(response)
          }
        } else if (cmd === 'RETR') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          const idx = parseInt(parts[1]) - 1
          if (idx >= 0 && idx < active.length) {
            const msg = active[idx]
            const raw = msg.raw || `From: ${msg.from_addr}\r\nTo: ${JSON.parse(msg.to_addrs).join(', ')}\r\nSubject: ${msg.subject}\r\n\r\n${msg.text_body || msg.html_body}`
            socket.write(`+OK ${raw.length} octets\r\n${raw}\r\n.\r\n`)
            store.updateMessage(msg.id, { read: 1 })
          } else {
            socket.write('-ERR No such message\r\n')
          }
        } else if (cmd === 'TOP') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          const idx = parseInt(parts[1]) - 1
          const lines = parseInt(parts[2]) || 0
          if (idx >= 0 && idx < active.length) {
            const msg = active[idx]
            const raw = msg.raw || `From: ${msg.from_addr}\r\nSubject: ${msg.subject}\r\n\r\n${msg.text_body}`
            const headerEnd = raw.indexOf('\r\n\r\n')
            const headers = raw.slice(0, headerEnd + 4)
            const body = raw.slice(headerEnd + 4).split('\r\n').slice(0, lines).join('\r\n')
            socket.write(`+OK\r\n${headers}${body}\r\n.\r\n`)
          } else {
            socket.write('-ERR No such message\r\n')
          }
        } else if (cmd === 'DELE') {
          const { messages } = store.getMessages({ limit: 10000 })
          const active = messages.filter(m => !session.deleted.has(m.id))
          const idx = parseInt(parts[1]) - 1
          if (idx >= 0 && idx < active.length) {
            session.deleted.add(active[idx].id)
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
          // Actually delete marked messages
          for (const id of session.deleted) {
            store.deleteMessage(id)
          }
          socket.write('+OK Bye\r\n')
          socket.end()
        } else {
          socket.write('-ERR Unknown command\r\n')
        }
      },
      close() {},
      error(socket, error) {
        console.error('[POP3] Socket error:', error.message)
      },
    },
  })

  return server
}
