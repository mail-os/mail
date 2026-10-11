/** Run with the same disposable-account variables as e2e.test.ts. */
import { expect, test } from 'bun:test'

const base = process.env.MAIL_WEBMAIL_E2E_URL
const username = process.env.MAIL_WEBMAIL_E2E_USER
const password = process.env.MAIL_WEBMAIL_E2E_PASSWORD
const enabled = Boolean(base && username && password)

async function client() {
  const login = await fetch(new URL('/webmail/auth/login', base), { method: 'POST', headers: { Origin: base!, 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
  expect(login.status).toBe(200)
  const cookie = login.headers.get('set-cookie')!.split(';')[0]
  async function request(path: string, method = 'GET', body?: unknown, extraHeaders?: Record<string, string>) {
    return fetch(new URL(path, base), { method, cache: 'no-store', headers: { Cookie: cookie, Origin: base!, 'Content-Type': 'application/json', 'X-Webmail-Account': encodeURIComponent(username!), ...extraHeaders }, body: body === undefined ? undefined : JSON.stringify(body) })
  }
  async function json(path: string, method = 'GET', body?: unknown): Promise<any> {
    const response = await request(path, method, body)
    expect(response.status).toBe(200)
    return response.json()
  }
  return { cookie, request, json }
}

test.skipIf(!enabled)('draft revisions preserve incomplete entry and isolate account changes', async () => {
  const api = await client()
  const id = crypto.randomUUID()
  const payload = { draftId: id, draftRevision: 0, saveToken: crypto.randomUUID(), to: ['unfinished@'], recipientInputs: { cc: 'still typing' }, recipientLabels: { to: ['Jane'] }, subject: `UX draft ${id}`, text: 'First body' }
  const saved = await api.json('/webmail/api/drafts', 'POST', payload)
  const replay = await api.json('/webmail/api/drafts', 'POST', payload)
  expect(replay.uid).toBe(saved.uid)
  expect(replay.revision).toBe(saved.revision)
  const reopened = await api.json(`/webmail/api/drafts?uid=${saved.uid}`)
  expect(reopened.message.to).toEqual(['unfinished@'])
  expect(reopened.message.recipientInputs.cc).toBe('still typing')
  expect(reopened.message.recipientLabels.to).toEqual(['Jane'])
  expect((await api.request('/webmail/api/drafts', 'POST', { ...payload, text: 'Overwrite', saveToken: crypto.randomUUID() })).status).toBe(409)
  const updated = await api.json('/webmail/api/drafts', 'POST', { ...payload, draftRevision: saved.revision, text: 'Second body', saveToken: crypto.randomUUID() })
  expect(updated.uid).toBe(saved.uid)
  expect(updated.revision).toBe(saved.revision + 1)
  const wrongAccount = await api.request('/webmail/api/drafts', 'POST', { ...payload, draftId: crypto.randomUUID() }, { 'X-Webmail-Account': 'other%40example.test' })
  expect(wrongAccount.status).toBe(409)
  expect((await wrongAccount.json()).error).toBe('account_changed')
  expect((await api.request('/webmail/api/drafts', 'POST', payload, { Origin: 'https://example.invalid' })).status).toBe(403)
  const removed = await api.json('/webmail/api/bulk', 'POST', { action: 'trash', messages: [{ uid: saved.uid, folder: 'Drafts' }] })
  expect(removed.ok).toBe(true)
  const restored = await api.json(`/webmail/api/undo/${removed.undoId}`, 'POST', {})
  expect(restored.ok).toBe(true)
  const fresh = restored.results[0].new_uid
  expect(fresh).not.toBe(saved.uid)
  expect((await api.json(`/webmail/api/drafts?uid=${fresh}`)).message.text).toBe('Second body')
  await api.json(`/webmail/api/messages/${fresh}?folder=Drafts`, 'DELETE')
  await api.json('/webmail/auth/logout', 'POST', {})
})

test.skipIf(!enabled)('binary uploads exceed the old cap and retain exact bytes through draft MIME', async () => {
  const api = await client()
  const config = await api.json('/webmail/api/config')
  const count = Math.min(1024 * 1024, config.maxFileBytes)
  expect(count).toBeGreaterThan(512 * 1024)
  const data = Uint8Array.from({ length: count }, (value, index) => index % 256)
  const uploadId = crypto.randomUUID()
  const uploadUrl = new URL(`/webmail/api/uploads?filename=acceptance.bin&contentType=application%2Foctet-stream&uploadId=${uploadId}`, base)
  const uploadHeaders = { Cookie: api.cookie, Origin: base!, 'X-Webmail-Account': encodeURIComponent(username!), 'Content-Type': 'application/octet-stream' }
  const upload = await fetch(uploadUrl, { method: 'POST', headers: uploadHeaders, body: data })
  expect(upload.status).toBe(200)
  const item = await upload.json() as any
  expect(item.size).toBe(count)
  expect(item.uploadId).toBe(uploadId)
  const replay = await fetch(uploadUrl, { method: 'POST', headers: uploadHeaders, body: data })
  expect(replay.status).toBe(200)
  expect((await replay.json() as any).uploadId).toBe(uploadId)
  const changed = data.slice()
  changed[0] = 255
  expect((await fetch(uploadUrl, { method: 'POST', headers: uploadHeaders, body: changed })).status).toBe(409)
  const saved = await api.json('/webmail/api/drafts', 'POST', { draftId: crypto.randomUUID(), saveToken: crypto.randomUUID(), subject: `UX binary ${crypto.randomUUID()}`, text: 'Binary test', attachments: [{ uploadId: item.uploadId }] })
  const detail = await api.json(`/webmail/api/messages/${saved.uid}?folder=Drafts`)
  expect(detail.attachments[0].size).toBe(count)
  const response = await api.request(`/webmail/api/attachment?folder=Drafts&uid=${saved.uid}&index=0`)
  expect(response.status).toBe(200)
  expect(new Uint8Array(await response.arrayBuffer())).toEqual(data)
  expect((await api.request(`/webmail/api/attachment?folder=Drafts&uid=${saved.uid}&index=0&account=other%40example.test`)).status).toBe(409)
  expect((await api.request('/webmail/api/drafts', 'POST', { attachments: [{ uploadId: crypto.randomUUID() }] })).status).toBe(404)
  await api.json(`/webmail/api/messages/${saved.uid}?folder=Drafts`, 'DELETE')
  await api.json('/webmail/auth/logout', 'POST', {})
})

test.skipIf(!enabled)('search filters and conversation grouping precede pagination across folders', async () => {
  const api = await client()
  const subject = `UX conversations ${crypto.randomUUID()}`
  const first = await api.json('/webmail/api/compose', 'POST', { to: [username], subject, text: 'Original matching message' })
  await api.json('/webmail/api/compose', 'POST', { to: [username], subject, text: 'Unrelated matching message' })
  await api.json('/webmail/api/compose', 'POST', { to: [username], subject: `Re: ${subject}`, text: 'Reply with different words', inReplyTo: first.message_id, references: first.message_id })
  const query = encodeURIComponent(subject)
  const list = await api.json(`/webmail/api/messages?folder=INBOX&q=${query}&conversations=true&per_page=1&page=999999`)
  expect(list.total).toBe(2)
  expect(list.page).toBe(2)
  expect(list.threads).toHaveLength(1)
  const all = await api.json(`/webmail/api/messages?folder=INBOX&q=${query}&conversations=true`)
  expect(all.threads.map((thread: any) => thread.count).sort()).toEqual([1, 2])
  const rows = await api.json(`/webmail/api/messages?folder=INBOX&q=${query}`)
  const firstRef = { folder: 'INBOX', uid: rows.items[0].uid }
  expect((await api.request('/webmail/api/bulk', 'POST', { action: 'trash', messages: [firstRef, { folder: 'INBOX', uid: 999999999 }] })).status).toBe(404)
  expect((await api.json(`/webmail/api/messages?folder=INBOX&q=${query}`)).total).toBe(3)
  const moved = await api.json('/webmail/api/bulk', 'POST', { action: 'move', folder: 'Archive', messages: [firstRef] })
  expect(moved.ok).toBe(true)
  const everywhere = await api.json(`/webmail/api/messages?folder=*&q=${query}&from=${encodeURIComponent(username!)}&after=0`)
  expect(everywhere.items.some((message: any) => message.folder === 'Archive')).toBe(true)
  expect((await api.json(`/webmail/api/messages?folder=*&q=${query}&after=${Math.floor(Date.now() / 1000) + 86400}`)).total).toBe(0)
  const undo = await api.json(`/webmail/api/undo/${moved.undoId}`, 'POST', {})
  expect(undo.ok).toBe(true)
  const marked = await api.json('/webmail/api/bulk', 'POST', { action: 'read', messages: [{ folder: 'INBOX', uid: undo.results[0].new_uid }] })
  expect(marked.ok).toBe(true)
  expect((await api.json(`/webmail/api/messages?folder=INBOX&q=${query}&unread=true`)).total).toBe(2)
  expect((await api.json(`/webmail/api/messages?folder=INBOX&q=${query}&flagged=true`)).total).toBe(0)
  const contacts = await api.json(`/webmail/api/contacts?q=${encodeURIComponent(username!.split('@')[0])}`)
  expect(contacts.some((contact: any) => contact.address.toLowerCase() === username!.toLowerCase())).toBe(true)
  for (const folder of ['INBOX', 'Sent']) {
    const messages = await api.json(`/webmail/api/messages?folder=${folder}&q=${query}`)
    for (const message of messages.items) await api.json(`/webmail/api/messages/${message.uid}?folder=${folder}`, 'DELETE')
  }
  await api.json('/webmail/auth/logout', 'POST', {})
})

test.skipIf(!enabled)('Undo Send holds dispatch, while delivery remains independent of a browser tab', async () => {
  const api = await client()
  const subject = `UX outbox ${crypto.randomUUID()}`
  const cancelledPayload = { to: [username], subject: `${subject} cancelled`, text: 'Never dispatch this test', sendId: crypto.randomUUID(), delaySeconds: 15 }
  const pending = await api.json('/webmail/api/compose', 'POST', cancelledPayload)
  expect(pending.state).toBe('pending')
  expect(pending.dueAt - pending.serverTime).toBeGreaterThan(0)
  expect((await api.json('/webmail/api/compose', 'POST', cancelledPayload)).id).toBe(pending.id)
  const cancelled = await api.json(`/webmail/api/outbox/${pending.id}`, 'DELETE')
  expect(cancelled.state).toBe('cancelled')
  expect((await api.json(`/webmail/api/messages?folder=INBOX&q=${encodeURIComponent(cancelledPayload.subject)}`)).total).toBe(0)
  const payload = { to: [username], subject: `${subject} sent`, text: 'Server-owned dispatch test', sendId: crypto.randomUUID(), delaySeconds: 2 }
  const queued = await api.json('/webmail/api/compose', 'POST', payload)
  let outcome = queued
  for (let attempt = 0; attempt < 50 && ['pending', 'sending'].includes(outcome.state); attempt++) { await Bun.sleep(200); outcome = await api.json(`/webmail/api/outbox/${queued.id}`) }
  expect(outcome.state).toBe('sent')
  expect(outcome.result.delivered).toBe(1)
  expect((await api.request(`/webmail/api/outbox/${queued.id}`, 'DELETE')).status).toBe(409)
  expect((await api.json('/webmail/api/compose', 'POST', payload)).state).toBe('sent')
  for (const folder of ['INBOX', 'Sent']) {
    const list = await api.json(`/webmail/api/messages?folder=${folder}&q=${encodeURIComponent(payload.subject)}`)
    expect(list.total).toBe(1)
    await api.json(`/webmail/api/messages/${list.items[0].uid}?folder=${folder}`, 'DELETE')
  }
  await api.json('/webmail/auth/logout', 'POST', {})
})
