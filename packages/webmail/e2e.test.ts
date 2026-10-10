/** Run against a disposable account: MAIL_WEBMAIL_E2E_URL/USER/PASSWORD. */
import { expect, test } from 'bun:test'

const base = process.env.MAIL_WEBMAIL_E2E_URL
const username = process.env.MAIL_WEBMAIL_E2E_USER
const password = process.env.MAIL_WEBMAIL_E2E_PASSWORD

test.skipIf(!base || !username || !password)('live HTTPS webmail mailbox and account lifecycle', async () => {
  let cookie = ''
  async function request(path: string, method = 'GET', body?: unknown): Promise<Response> {
    return fetch(new URL(path, base), {
      method,
      headers: { 'Content-Type': 'application/json', Origin: base!, Cookie: cookie },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  }
  async function json(path: string, method = 'GET', body?: unknown): Promise<any> {
    const response = await request(path, method, body)
    expect(response.status).toBe(200)
    return response.json()
  }
  expect((await request('/webmail/auth/me')).status).toBe(401)
  const login = await request('/webmail/auth/login', 'POST', { username, password })
  expect(login.status).toBe(200)
  const setCookie = login.headers.get('set-cookie')!
  expect(setCookie).toContain('HttpOnly')
  expect(setCookie).toContain('Secure')
  cookie = setCookie.split(';')[0]
  const me = await json('/webmail/auth/me')
  expect(me.user.username).toBe(username)
  expect(me.user.email).toBe(username)
  const subject = `Webmail E2E ${crypto.randomUUID()}`
  const text = 'Self-delivery check.\nSecond line with "quotes" and unicode: café.'
  const sent = await json('/webmail/api/compose', 'POST', { to: [username], subject, text })
  expect(sent.ok).toBe(true)
  expect(sent.delivered).toBe(1)
  for (const folder of ['INBOX', 'Sent']) {
    const list = await json(`/webmail/api/messages?folder=${folder}`)
    expect(list.total).toBeGreaterThan(0)
    const item = list.items.find((message: any) => message.subject === subject)
    expect(item).toBeDefined()
    const path = `/webmail/api/messages/${item.uid}?folder=${folder}`
    const detail = await json(path)
    expect(detail.text).toContain('Second line with "quotes" and unicode: café.')
    expect(detail.from).toBe(username)
    await json(path, 'PUT', { flags: { ...detail.flags, seen: true, flagged: true } })
    const updated = await json(path)
    expect(updated.flags.seen).toBe(true)
    expect(updated.flags.flagged).toBe(true)
    await json(path, 'DELETE')
  }
  const trash = await json('/webmail/api/messages?folder=Trash')
  expect(trash.items.some((message: any) => message.subject === subject)).toBe(true)
  const crossOrigin = await fetch(new URL('/webmail/auth/password', base), {
    method: 'POST', headers: { Origin: 'https://example.invalid', Cookie: cookie },
    body: JSON.stringify({ currentPassword: password, newPassword: 'must-not-be-applied' }),
  })
  expect(crossOrigin.status).toBe(403)
  const next = `E2E-${crypto.randomUUID()}-"café"`
  await json('/webmail/auth/password', 'POST', { currentPassword: password, newPassword: next })
  expect((await request('/webmail/auth/me')).status).toBe(401)
  expect((await request('/webmail/auth/login', 'POST', { username, password })).status).toBe(401)
  const newLogin = await request('/webmail/auth/login', 'POST', { username, password: next })
  expect(newLogin.status).toBe(200)
  cookie = newLogin.headers.get('set-cookie')!.split(';')[0]
  await json('/webmail/auth/logout', 'POST')
  expect((await request('/webmail/auth/me')).status).toBe(401)
}, 60000)
