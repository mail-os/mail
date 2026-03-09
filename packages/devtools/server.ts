import { serve } from 'bun'
import { MessageStore } from './src/store'
import { createSmtpServer, type ChaosConfig, type ParsedEmail } from './src/smtp'
import { createPop3Server } from './src/pop3'
import { checkHtmlCompatibility, checkLinks, checkSpam, dispatchWebhook } from './src/utils'

// Config
const HTTP_PORT = parseInt(process.env.PORT || '8025')
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '1025')
const POP3_PORT = parseInt(process.env.POP3_PORT || '1110')
const DB_PATH = process.env.DB_PATH || './devmail.db'
const RELAY_HOST = process.env.RELAY_HOST || ''
const RELAY_PORT = parseInt(process.env.RELAY_PORT || '25')
const AUTO_RELAY = process.env.AUTO_RELAY === '1'
const QUIET = process.env.QUIET === '1'

// Initialize store
const store = new MessageStore(DB_PATH)

// Chaos config (in-memory)
let chaosConfig: ChaosConfig = {
  enabled: false,
  reject_chance: 0,
  slow_chance: 0,
  disconnect_chance: 0,
  error_code: 550,
  error_message: 'Mailbox unavailable (chaos mode)',
}

// WebSocket connections for live updates
const wsClients = new Set<any>()

function broadcast(event: string, data: any) {
  const msg = JSON.stringify({ event, data })
  for (const ws of wsClients) {
    try { ws.send(msg) } catch { wsClients.delete(ws) }
  }
}

// Auto-tag rules (simple pattern matching)
function autoTag(msg: ParsedEmail): string[] {
  const tags: string[] = []
  const sub = msg.subject.toLowerCase()

  if (sub.includes('newsletter') || msg.headers['list-unsubscribe']) tags.push('newsletter')
  if (sub.includes('invoice') || sub.includes('receipt') || sub.includes('payment')) tags.push('transactional')
  if (sub.includes('reset') || sub.includes('verify') || sub.includes('confirm')) tags.push('auth')
  if (sub.includes('alert') || sub.includes('warning') || sub.includes('urgent')) tags.push('alert')

  // Auto-create tags
  for (const tag of tags) {
    try { store.createTag(tag) } catch {}
  }

  return tags
}

// Handle incoming SMTP message
async function onMessage(msg: ParsedEmail) {
  const tags = autoTag(msg)

  const stored = store.addMessage({
    id: msg.id,
    from_addr: msg.from_addr,
    from_name: msg.from_name,
    to_addrs: JSON.stringify(msg.to_addrs),
    cc_addrs: JSON.stringify(msg.cc_addrs),
    bcc_addrs: JSON.stringify(msg.bcc_addrs),
    subject: msg.subject,
    text_body: msg.text_body,
    html_body: msg.html_body,
    raw: msg.raw,
    size: msg.size,
    tags: JSON.stringify(tags),
    attachments: JSON.stringify(msg.attachments.map(a => ({
      name: a.name, type: a.type, size: a.size,
    }))),
    headers: JSON.stringify(msg.headers),
  })

  if (!QUIET) {
    console.log(`[SMTP] ${msg.from_addr} → ${msg.to_addrs.join(', ')} | ${msg.subject}`)
  }

  // Broadcast to WebSocket clients
  const stats = store.getStats()
  broadcast('new-message', {
    message: stored,
    unread: stats.unread,
    total: stats.total,
  })

  // Dispatch webhooks
  const webhooks = store.getWebhooks()
  for (const wh of webhooks) {
    if (wh.enabled) {
      dispatchWebhook(wh.url, {
        event: 'new-message',
        message: {
          id: stored.id,
          from: msg.from_addr,
          to: msg.to_addrs,
          subject: msg.subject,
          size: msg.size,
          created_at: stored.created_at,
        },
      }).catch(() => {})
    }
  }

  // Auto-forward
  const rules = store.getForwardRules()
  for (const rule of rules) {
    if (!rule.enabled) continue
    const matchFrom = !rule.match_from || msg.from_addr.includes(rule.match_from)
    const matchTo = !rule.match_to || msg.to_addrs.some(a => a.includes(rule.match_to))
    const matchSubject = !rule.match_subject || msg.subject.includes(rule.match_subject)
    if (matchFrom && matchTo && matchSubject && RELAY_HOST) {
      console.log(`[Forward] → ${rule.forward_to} via ${RELAY_HOST}:${RELAY_PORT}`)
    }
  }
}

// Start SMTP server
const smtpServer = createSmtpServer({
  port: SMTP_PORT,
  onMessage,
  getChaos: () => chaosConfig,
})

// Start POP3 server
const pop3Server = createPop3Server({
  port: POP3_PORT,
  store,
})

// Read the app UI template
const appHtml = await Bun.file(new URL('./pages/app.stx', import.meta.url).pathname).text()

// JSON helper
function json(data: any, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}

// Parse URL params
function getParams(url: URL): Record<string, string> {
  const params: Record<string, string> = {}
  url.searchParams.forEach((v, k) => params[k] = v)
  return params
}

// Extract path segments: /api/v1/messages/:id → ['messages', id]
function parsePath(pathname: string): string[] {
  return pathname.replace('/api/v1/', '').split('/').filter(Boolean)
}

// HTTP Server
const server = serve({
  port: HTTP_PORT,

  websocket: {
    open(ws) {
      wsClients.add(ws)
      const stats = store.getStats()
      ws.send(JSON.stringify({ event: 'connected', data: stats }))
    },
    message() {},
    close(ws) {
      wsClients.delete(ws)
    },
  },

  routes: {
    '/': () => new Response(appHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }),

    '/ws': (req, server) => {
      if (server.upgrade(req)) return undefined
      return new Response('WebSocket upgrade failed', { status: 400 })
    },
  },

  async fetch(req, server) {
    const url = new URL(req.url)
    const method = req.method

    // WebSocket upgrade
    if (url.pathname === '/ws') {
      if (server.upgrade(req)) return undefined
      return new Response('WebSocket upgrade failed', { status: 400 })
    }

    // Serve the app for non-API routes
    if (!url.pathname.startsWith('/api/')) {
      return new Response(appHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    }

    // CORS headers for API
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders })
    }

    const path = parsePath(url.pathname)
    const params = getParams(url)

    try {
      // ── Messages ──────────────────────────────────────────────
      if (path[0] === 'messages') {
        // GET /api/v1/messages
        if (method === 'GET' && path.length === 1) {
          const result = store.getMessages({
            search: params.search,
            tag: params.tag,
            read: params.read !== undefined ? params.read === 'true' : undefined,
            starred: params.starred !== undefined ? params.starred === 'true' : undefined,
            limit: parseInt(params.limit || '50'),
            offset: parseInt(params.offset || '0'),
          })
          return json({ ...result, stats: store.getStats() })
        }

        // DELETE /api/v1/messages (delete all)
        if (method === 'DELETE' && path.length === 1) {
          store.deleteAllMessages()
          broadcast('messages-cleared', {})
          return json({ ok: true })
        }

        // PUT /api/v1/messages/read (mark all read)
        if (method === 'PUT' && path[1] === 'read') {
          store.markAllRead()
          broadcast('all-read', {})
          return json({ ok: true })
        }

        // GET /api/v1/messages/:id
        if (method === 'GET' && path.length === 2 && !['read'].includes(path[1])) {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          return json(msg)
        }

        // GET /api/v1/messages/:id/html
        if (method === 'GET' && path[2] === 'html') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          // Serve HTML in an iframe-safe way
          const html = msg.html_body || `<pre style="font-family: monospace; white-space: pre-wrap;">${escapeHtml(msg.text_body)}</pre>`
          return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders } })
        }

        // GET /api/v1/messages/:id/source
        if (method === 'GET' && path[2] === 'source') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          return new Response(msg.raw, { headers: { 'Content-Type': 'text/plain; charset=utf-8', ...corsHeaders } })
        }

        // GET /api/v1/messages/:id/html-check
        if (method === 'GET' && path[2] === 'html-check') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          return json(checkHtmlCompatibility(msg.html_body))
        }

        // GET /api/v1/messages/:id/link-check
        if (method === 'GET' && path[2] === 'link-check') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          const results = await checkLinks(msg.html_body, msg.text_body)
          return json(results)
        }

        // GET /api/v1/messages/:id/spam-check
        if (method === 'GET' && path[2] === 'spam-check') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          const headers = JSON.parse(msg.headers || '{}')
          return json(checkSpam(headers, msg.subject, msg.text_body, msg.html_body))
        }

        // POST /api/v1/messages/:id/relay
        if (method === 'POST' && path[2] === 'relay') {
          const msg = store.getMessage(path[1])
          if (!msg) return json({ error: 'Not found' }, 404)
          if (!RELAY_HOST) return json({ error: 'No relay host configured (set RELAY_HOST env)' }, 400)
          return json({ ok: true, message: `Would relay to ${RELAY_HOST}:${RELAY_PORT}` })
        }

        // PUT /api/v1/messages/:id
        if (method === 'PUT' && path.length === 2) {
          const body = await req.json() as any
          store.updateMessage(path[1], {
            read: body.read,
            starred: body.starred,
            tags: body.tags ? JSON.stringify(body.tags) : undefined,
          })
          const msg = store.getMessage(path[1])
          broadcast('message-updated', msg)
          return json(msg)
        }

        // DELETE /api/v1/messages/:id
        if (method === 'DELETE' && path.length === 2) {
          store.deleteMessage(path[1])
          broadcast('message-deleted', { id: path[1] })
          return json({ ok: true })
        }
      }

      // ── Tags ──────────────────────────────────────────────────
      if (path[0] === 'tags') {
        if (method === 'GET') return json(store.getTags())
        if (method === 'POST') {
          const body = await req.json() as any
          const tag = store.createTag(body.name, body.color)
          return json(tag)
        }
        if (method === 'DELETE' && path[1]) {
          store.deleteTag(parseInt(path[1]))
          return json({ ok: true })
        }
      }

      // ── Webhooks ──────────────────────────────────────────────
      if (path[0] === 'webhooks') {
        if (method === 'GET') return json(store.getWebhooks())
        if (method === 'POST') {
          const body = await req.json() as any
          const wh = store.addWebhook(body.url)
          return json(wh)
        }
        if (method === 'DELETE' && path[1]) {
          store.deleteWebhook(parseInt(path[1]))
          return json({ ok: true })
        }
      }

      // ── Forward Rules ─────────────────────────────────────────
      if (path[0] === 'forward-rules') {
        if (method === 'GET') return json(store.getForwardRules())
        if (method === 'POST') {
          const body = await req.json() as any
          const rule = store.addForwardRule(body)
          return json(rule)
        }
        if (method === 'DELETE' && path[1]) {
          store.deleteForwardRule(parseInt(path[1]))
          return json({ ok: true })
        }
      }

      // ── Chaos Engineering ─────────────────────────────────────
      if (path[0] === 'chaos') {
        if (method === 'GET') return json(chaosConfig)
        if (method === 'PUT') {
          const body = await req.json() as any
          chaosConfig = { ...chaosConfig, ...body }
          return json(chaosConfig)
        }
      }

      // ── Server Info ───────────────────────────────────────────
      if (path[0] === 'info') {
        return json({
          version: '0.1.0',
          smtp_port: SMTP_PORT,
          pop3_port: POP3_PORT,
          http_port: HTTP_PORT,
          relay_host: RELAY_HOST || null,
          auto_relay: AUTO_RELAY,
          stats: store.getStats(),
        })
      }

      return json({ error: 'Not found' }, 404)
    } catch (err: any) {
      return json({ error: err.message }, 500)
    }
  },
})

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Startup banner
console.log(`
  ╔══════════════════════════════════════════════╗
  ║            Mail Dev Server                   ║
  ╠══════════════════════════════════════════════╣
  ║  Web UI    http://localhost:${HTTP_PORT.toString().padEnd(5)}           ║
  ║  SMTP      localhost:${SMTP_PORT.toString().padEnd(5)}                 ║
  ║  POP3      localhost:${POP3_PORT.toString().padEnd(5)}                 ║
  ╠══════════════════════════════════════════════╣
  ║  API       http://localhost:${HTTP_PORT}/api/v1   ║
  ║  WebSocket ws://localhost:${HTTP_PORT}/ws          ║
  ╚══════════════════════════════════════════════╝

  Configure your app to send mail to localhost:${SMTP_PORT}
`)
