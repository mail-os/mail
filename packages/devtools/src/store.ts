import { Database } from 'bun:sqlite'
import { randomUUID } from 'node:crypto'

export interface Message {
  id: string
  from_addr: string
  from_name: string
  to_addrs: string
  cc_addrs: string
  bcc_addrs: string
  subject: string
  text_body: string
  html_body: string
  raw: string
  size: number
  read: number
  starred: number
  tags: string
  attachments: string
  headers: string
  snippet: string
  created_at: string
}

export interface Tag {
  id: number
  name: string
  color: string
}

export interface Webhook {
  id: number
  url: string
  enabled: number
}

export interface ForwardRule {
  id: number
  match_from: string
  match_to: string
  match_subject: string
  forward_to: string
  enabled: number
}

export class MessageStore {
  private db: Database

  constructor(dbPath = ':memory:') {
    this.db = new Database(dbPath)
    this.db.exec('PRAGMA journal_mode=WAL')
    this.db.exec('PRAGMA synchronous=NORMAL')
    this.init()
  }

  private init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        from_addr TEXT DEFAULT '',
        from_name TEXT DEFAULT '',
        to_addrs TEXT DEFAULT '[]',
        cc_addrs TEXT DEFAULT '[]',
        bcc_addrs TEXT DEFAULT '[]',
        subject TEXT DEFAULT '',
        text_body TEXT DEFAULT '',
        html_body TEXT DEFAULT '',
        raw TEXT DEFAULT '',
        size INTEGER DEFAULT 0,
        read INTEGER DEFAULT 0,
        starred INTEGER DEFAULT 0,
        tags TEXT DEFAULT '[]',
        attachments TEXT DEFAULT '[]',
        headers TEXT DEFAULT '{}',
        snippet TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        color TEXT DEFAULT '#007AFF'
      );

      CREATE TABLE IF NOT EXISTS webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        enabled INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS forward_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_from TEXT DEFAULT '',
        match_to TEXT DEFAULT '',
        match_subject TEXT DEFAULT '',
        forward_to TEXT NOT NULL,
        enabled INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_addr);
      CREATE INDEX IF NOT EXISTS idx_messages_read ON messages(read);
      CREATE INDEX IF NOT EXISTS idx_messages_starred ON messages(starred);
    `)
  }

  addMessage(msg: Partial<Message>): Message {
    const id = msg.id || randomUUID()
    const snippet = (msg.text_body || msg.html_body?.replace(/<[^>]*>/g, '') || '').slice(0, 150).trim()

    this.db.prepare(`
      INSERT INTO messages (id, from_addr, from_name, to_addrs, cc_addrs, bcc_addrs,
        subject, text_body, html_body, raw, size, tags, attachments, headers, snippet)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      msg.from_addr || '',
      msg.from_name || '',
      msg.to_addrs || '[]',
      msg.cc_addrs || '[]',
      msg.bcc_addrs || '[]',
      msg.subject || '(No Subject)',
      msg.text_body || '',
      msg.html_body || '',
      msg.raw || '',
      msg.size || 0,
      msg.tags || '[]',
      msg.attachments || '[]',
      msg.headers || '{}',
      snippet,
    )

    return this.getMessage(id)!
  }

  getMessage(id: string): Message | null {
    return this.db.prepare('SELECT * FROM messages WHERE id = ?').get(id) as Message | null
  }

  getMessages(opts: {
    search?: string
    tag?: string
    read?: boolean
    starred?: boolean
    limit?: number
    offset?: number
  } = {}): { messages: Message[], total: number } {
    const conditions: string[] = []
    const params: any[] = []

    if (opts.search) {
      conditions.push('(subject LIKE ? OR from_addr LIKE ? OR from_name LIKE ? OR text_body LIKE ?)')
      const term = `%${opts.search}%`
      params.push(term, term, term, term)
    }
    if (opts.tag) {
      conditions.push("tags LIKE ?")
      params.push(`%"${opts.tag}"%`)
    }
    if (opts.read !== undefined) {
      conditions.push('read = ?')
      params.push(opts.read ? 1 : 0)
    }
    if (opts.starred !== undefined) {
      conditions.push('starred = ?')
      params.push(opts.starred ? 1 : 0)
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''
    const total = (this.db.prepare(`SELECT COUNT(*) as c FROM messages ${where}`).get(...params) as any).c

    const limit = opts.limit || 50
    const offset = opts.offset || 0
    const messages = this.db.prepare(
      `SELECT * FROM messages ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset) as Message[]

    return { messages, total }
  }

  updateMessage(id: string, updates: Partial<Pick<Message, 'read' | 'starred' | 'tags'>>) {
    const sets: string[] = []
    const params: any[] = []

    if (updates.read !== undefined) { sets.push('read = ?'); params.push(updates.read) }
    if (updates.starred !== undefined) { sets.push('starred = ?'); params.push(updates.starred) }
    if (updates.tags !== undefined) { sets.push('tags = ?'); params.push(updates.tags) }

    if (sets.length === 0) return
    params.push(id)
    this.db.prepare(`UPDATE messages SET ${sets.join(', ')} WHERE id = ?`).run(...params)
  }

  deleteMessage(id: string) {
    this.db.prepare('DELETE FROM messages WHERE id = ?').run(id)
  }

  deleteAllMessages() {
    this.db.exec('DELETE FROM messages')
  }

  markAllRead() {
    this.db.exec('UPDATE messages SET read = 1')
  }

  getUnreadCount(): number {
    return (this.db.prepare('SELECT COUNT(*) as c FROM messages WHERE read = 0').get() as any).c
  }

  getStats() {
    const row = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END), 0) as unread,
        COALESCE(SUM(CASE WHEN starred = 1 THEN 1 ELSE 0 END), 0) as starred
      FROM messages
    `).get() as { total: number, unread: number, starred: number }
    return row
  }

  // Tags
  getTags(): Tag[] {
    return this.db.prepare('SELECT * FROM tags ORDER BY name').all() as Tag[]
  }

  createTag(name: string, color = '#007AFF'): Tag {
    this.db.prepare('INSERT OR IGNORE INTO tags (name, color) VALUES (?, ?)').run(name, color)
    return this.db.prepare('SELECT * FROM tags WHERE name = ?').get(name) as Tag
  }

  deleteTag(id: number) {
    this.db.prepare('DELETE FROM tags WHERE id = ?').run(id)
  }

  // Webhooks
  getWebhooks(): Webhook[] {
    return this.db.prepare('SELECT * FROM webhooks').all() as Webhook[]
  }

  addWebhook(url: string): Webhook {
    const result = this.db.prepare('INSERT INTO webhooks (url) VALUES (?)').run(url)
    return this.db.prepare('SELECT * FROM webhooks WHERE id = ?').get(result.lastInsertRowid) as Webhook
  }

  deleteWebhook(id: number) {
    this.db.prepare('DELETE FROM webhooks WHERE id = ?').run(id)
  }

  // Forward rules
  getForwardRules(): ForwardRule[] {
    return this.db.prepare('SELECT * FROM forward_rules').all() as ForwardRule[]
  }

  addForwardRule(rule: Partial<ForwardRule>): ForwardRule {
    const result = this.db.prepare(
      'INSERT INTO forward_rules (match_from, match_to, match_subject, forward_to) VALUES (?, ?, ?, ?)'
    ).run(rule.match_from || '', rule.match_to || '', rule.match_subject || '', rule.forward_to || '')
    return this.db.prepare('SELECT * FROM forward_rules WHERE id = ?').get(result.lastInsertRowid) as ForwardRule
  }

  deleteForwardRule(id: number) {
    this.db.prepare('DELETE FROM forward_rules WHERE id = ?').run(id)
  }

  // Settings
  getSetting(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as any
    return row?.value || null
  }

  setSetting(key: string, value: string) {
    this.db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value)
  }

  close() {
    this.db.close()
  }
}
