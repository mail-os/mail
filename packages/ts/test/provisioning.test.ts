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
      if (new URL(request.url).pathname.endsWith('/mailbox/access'))
        return Response.json({ revision: 2, mailbox: 'reader@mailboxes.example.test', enabled: true, access: 'read_only' })
      if (new URL(request.url).pathname.endsWith('/team'))
        return Response.json({ created: request.method === 'POST', team: { id: 'hosted-studio', name: 'Studio', domain: 'studio.example.test' } })
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
  const renewal = {
    actor: change.actor,
    mailbox: change.mailbox,
    operation_id: 'access-revision-00002',
    revision: 2,
    access_window: { service_until: 1795485600, read_until: 1795492800 },
  }
  expect((await client.applyAccess(renewal)).access).toBe('read_only')
  const team = { mailbox: 'owner@studio.example.test', actor: change.actor, name: 'Studio' }
  expect((await client.team(team.mailbox, team.actor)).team?.id).toBe('hosted-studio')
  expect((await client.createTeam(team)).created).toBe(true)
  expect(requests.map(request => new URL(request.url).pathname)).toEqual([
    '/provisioning/v1/status',
    '/provisioning/v1/mailbox',
    '/provisioning/v1/mailbox',
    '/provisioning/v1/mailbox/access',
    '/provisioning/v1/team',
    '/provisioning/v1/team',
  ])
  expect(requests.every(request => request.headers.get('Authorization') === `Bearer ${token}` && request.redirect === 'error')).toBe(true)
  expect(await requests[1].json()).toEqual(change)
  expect(new URL(requests[2].url).searchParams.get('actor')).toBe(change.actor)
  expect(await requests[3].json()).toEqual(renewal)
  expect(Object.fromEntries(new URL(requests[4].url).searchParams)).toEqual({ mailbox: team.mailbox, actor: team.actor })
  expect(requests[4].method).toBe('GET')
  expect(await requests[5].json()).toEqual(team)
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
