import { describe, expect, test } from 'bun:test'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { getSourcePath, MailAdminClient } from './index'

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('MailAdminClient', () => {
  test('resolves the sibling Zig package', () => {
    expect(existsSync(join(getSourcePath(), 'build.zig'))).toBeTrue()
  })

  test('acquires CSRF and creates a mailbox', async () => {
    const calls: Array<{ url: string, init?: RequestInit }> = []
    const client = new MailAdminClient({
      baseUrl: 'https://mail.example.com/',
      username: 'admin',
      password: 'secret',
      fetch: (async (url: string | URL | Request, init?: RequestInit) => {
        calls.push({ url: String(url), init })
        if (String(url).endsWith('/api/csrf-token')) return json({ csrf_token: 'csrf' })
        return json({ username: 'hello', email: 'hello@example.com' }, 201)
      }) as typeof fetch,
    })

    const mailbox = await client.createMailbox({ username: 'hello', email: 'hello@example.com', password: 'correct horse battery staple' })
    expect(mailbox.email).toBe('hello@example.com')
    expect(calls).toHaveLength(2)
    expect(new Headers(calls[1]?.init?.headers).get('X-CSRF-Token')).toBe('csrf')
  })

  test('ensures a domain through the supported config API', async () => {
    let updated: unknown
    const client = new MailAdminClient({
      baseUrl: 'http://127.0.0.1:8080',
      token: 'admin-token',
      fetch: (async (url: string | URL | Request, init?: RequestInit) => {
        const path = new URL(String(url)).pathname
        if (path === '/api/csrf-token') return json({ token: 'csrf' })
        if (path === '/api/config' && (!init?.method || init.method === 'GET')) return json({ config: { extra_local_domains: ['stacksjs.com'] } })
        updated = JSON.parse(String(init?.body))
        return json(updated)
      }) as typeof fetch,
    })
    expect(await client.ensureDomain('CommsHQ.org')).toEqual({ domain: 'commshq.org', configured: true })
    expect(updated).toEqual({ extra_local_domains: ['stacksjs.com', 'commshq.org'] })
  })
})
