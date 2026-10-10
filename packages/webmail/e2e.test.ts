/** Run against a disposable account: MAIL_WEBMAIL_E2E_URL/USER/PASSWORD. */
import { expect, test } from 'bun:test'

const base = process.env.MAIL_WEBMAIL_E2E_URL
const username = process.env.MAIL_WEBMAIL_E2E_USER
const password = process.env.MAIL_WEBMAIL_E2E_PASSWORD

test.skipIf(!base || !username || !password)('live HTTPS webmail mailbox and account lifecycle', async () => {
  if (password!.length < 12)
    throw new Error('Use a disposable E2E account with a password of at least 12 characters so password restoration can succeed.')
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
  const foreignLogin = await fetch(new URL('/webmail/auth/login', base), {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://example.invalid' },
    body: JSON.stringify({ username, password }),
  })
  expect(foreignLogin.status).toBe(403)
  expect((await request('/webmail/auth/me')).status).toBe(401)
  const login = await request('/webmail/auth/login', 'POST', { username, password })
  expect(login.status).toBe(200)
  const setCookie = login.headers.get('set-cookie')!
  expect(setCookie).toContain('HttpOnly')
  if (base!.startsWith('https:'))
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
  await json('/webmail/auth/password', 'POST', { currentPassword: next, newPassword: password })
  expect((await request('/webmail/auth/me')).status).toBe(401)
  const restoredLogin = await request('/webmail/auth/login', 'POST', { username, password })
  expect(restoredLogin.status).toBe(200)
  cookie = restoredLogin.headers.get('set-cookie')!.split(';')[0]
  await json('/webmail/auth/logout', 'POST')
  expect((await request('/webmail/auth/me')).status).toBe(401)
}, 60000)

test.skipIf(!base || !username || !password)('webmail drafts, attachments, search, moves and partial delivery', async () => {
  const login = await fetch(new URL('/webmail/auth/login', base), {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base! },
    body: JSON.stringify({ username, password }),
  })
  expect(login.status).toBe(200)
  const cookie = login.headers.get('set-cookie')!.split(';')[0]
  async function request(path: string, method = 'GET', body?: unknown): Promise<Response> {
    return fetch(new URL(path, base), {
      method, headers: { 'Content-Type': 'application/json', Origin: base!, Cookie: cookie },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  }
  async function json(path: string, method = 'GET', body?: unknown): Promise<any> {
    const response = await request(path, method, body)
    expect(response.status).toBe(200)
    return response.json()
  }
  const subject = `Draft E2E ${crypto.randomUUID()} café`
  const attachment = { filename: 'verification.txt', contentType: 'application/octet-stream', data: 'AAEC/w==' }
  const draft = await json('/webmail/api/drafts', 'POST', { subject, text: 'Unaddressed draft', attachments: [attachment] })
  const updated = await json('/webmail/api/drafts', 'POST', { draftUid: draft.uid, to: [username], bcc: [username], subject, text: 'Updated draft', attachments: [attachment] })
  expect(updated.uid).toBe(draft.uid)
  const drafts = await json(`/webmail/api/messages?folder=Drafts&q=${encodeURIComponent(subject)}`)
  expect(drafts.total).toBe(1)
  const detail = await json(`/webmail/api/messages/${draft.uid}?folder=Drafts`)
  expect(detail.text).toContain('Updated draft')
  expect(detail.bcc).toBe(username)
  expect(detail.flags.draft).toBe(true)
  expect(detail.attachments[0].size).toBe(4)
  const downloadPath = `/webmail/api/attachment?folder=Drafts&uid=${draft.uid}&index=0`
  const download = await request(downloadPath)
  expect(download.status).toBe(200)
  expect(download.headers.get('content-disposition')).toContain("filename*=UTF-8''")
  expect([...new Uint8Array(await download.arrayBuffer())]).toEqual([0, 1, 2, 255])
  expect((await fetch(new URL(downloadPath, base))).status).toBe(401)
  expect((await request(`/webmail/api/attachment?folder=Drafts&uid=${draft.uid}&index=1`)).status).toBe(404)
  const missing = `missing-${crypto.randomUUID()}@${username!.split('@')[1]}`
  const needle = `tail-${crypto.randomUUID()}`
  const result = await json('/webmail/api/compose', 'POST', {
    to: [username, missing], cc: [username], bcc: [username], subject,
    text: `${'Long text '.repeat(50)}${needle}`, attachments: [attachment],
  })
  expect(result.ok).toBe(false)
  expect(result.delivered).toBe(1)
  expect(result.failed).toEqual([missing])
  expect(result.sent_saved).toBe(true)
  const inbox = await json(`/webmail/api/messages?folder=INBOX&per_page=1&q=${needle.toUpperCase()}`)
  expect(inbox.total).toBe(1)
  expect(inbox.items.length).toBe(1)
  const uid = inbox.items[0].uid
  const received = await json(`/webmail/api/messages/${uid}?folder=INBOX`)
  expect(received.bcc).toBe('')
  expect(received.subject).toBe(subject)
  const moved = await json(`/webmail/api/messages/${uid}?folder=INBOX`, 'PUT', { folder: 'Archive' })
  expect((await json(`/webmail/api/messages?folder=INBOX&q=${needle}`)).total).toBe(0)
  const restored = await json(`/webmail/api/messages/${moved.uid}?folder=Archive`, 'PUT', { folder: 'INBOX' })
  expect(restored.uid).toBeGreaterThan(uid)
  expect((await json(`/webmail/api/messages/${restored.uid}?folder=INBOX`)).text).toContain(needle)
  await json(`/webmail/api/messages/${restored.uid}?folder=INBOX`, 'DELETE')
  await json(`/webmail/api/messages/${draft.uid}?folder=Drafts`, 'DELETE')
  const sent = await json(`/webmail/api/messages?folder=Sent&q=${encodeURIComponent(subject)}`)
  expect(sent.total).toBe(1)
  expect((await json(`/webmail/api/messages/${sent.items[0].uid}?folder=Sent`)).bcc).toBe(username)
  await json(`/webmail/api/messages/${sent.items[0].uid}?folder=Sent`, 'DELETE')
  await json('/webmail/auth/logout', 'POST')
}, 60000)
