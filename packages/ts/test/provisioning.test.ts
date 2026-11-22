import { expect, test } from 'bun:test'
import { createMailProvisioningClient } from '../src/index'

const token = 'a'.repeat(64)
const baseUrl = 'http://127.0.0.1:8091'

test('provisioning uses the dedicated versioned API and never follows a redirect', async () => {
  const requests: Request[] = []
  const client = createMailProvisioningClient({
    baseUrl,
    token,
    fetch: Object.assign(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      if (new URL(request.url).pathname.endsWith('/status'))
        return Response.json({ version: 1, domain: 'mailboxes.example.test' })
      return Response.json({ revision: 1, mailbox: 'reader@mailboxes.example.test', enabled: true })
    }, { preconnect: fetch.preconnect }),
  })
  expect((await client.status()).version).toBe(1)
  const change = {
    actor: 'actor-123456789012',
    operation_id: 'operation-123456789',
    mailbox: 'reader@mailboxes.example.test',
    revision: 1,
    quota_bytes: 10485760,
    send_recipients_per_day: 25,
    enabled: true,
    initial_password: 'disposable-password',
    initial_recovery: 'reader@elsewhere.example.test',
  }
  expect((await client.apply(change)).mailbox).toBe(change.mailbox)
  await client.mailbox(change.mailbox, change.actor)
  expect(requests.map(request => new URL(request.url).pathname)).toEqual([
    '/provisioning/v1/status',
    '/provisioning/v1/mailbox',
    '/provisioning/v1/mailbox',
  ])
  expect(requests.every(request => request.headers.get('Authorization') === `Bearer ${token}` && request.redirect === 'error')).toBe(true)
  expect(await requests[1].json()).toEqual(change)
  expect(new URL(requests[2].url).searchParams.get('actor')).toBe(change.actor)
})

test('provisioning rejects plaintext non-loopback origins and incompatible API revisions', async () => {
  expect(() => createMailProvisioningClient({ baseUrl: 'http://mail.example.test', token })).toThrow()
  const client = createMailProvisioningClient({
    baseUrl,
    token,
    fetch: Object.assign(async () => Response.json({ version: 2, domain: 'mailboxes.example.test' }), { preconnect: fetch.preconnect }),
  })
  await expect(client.status()).rejects.toHaveProperty('code', 'incompatible_version')
})
