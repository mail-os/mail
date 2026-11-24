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
      if (new URL(request.url).pathname.endsWith('/mailbox/activity'))
        return Response.json({ first_sent_at: null, first_received_at: 1795496580 })
      if (new URL(request.url).pathname.endsWith('/team'))
        return Response.json({ created: request.method === 'POST', can_invite: true, team: { id: 'hosted-studio', name: 'Studio', domain: 'studio.example.test' } })
      if (new URL(request.url).pathname.endsWith('/retirement'))
        return Response.json({ version: 1, id: 'retirement-00001', domain: 'studio.example.test', mailbox_count: 2 })
      if (new URL(request.url).pathname.endsWith('/webmail/sign-in')) {
        const { password } = await request.clone().json()
        return Response.json({ proof: 'b'.repeat(64), expires_at: 1795496580, password_verified: typeof password === 'string' })
      }
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
  expect(await client.team(team.mailbox, team.actor)).toMatchObject({ can_invite: true, team: { id: 'hosted-studio' } })
  expect((await client.createTeam(team)).created).toBe(true)
  expect(await client.retirement('retirement-00001')).toMatchObject({ domain: team.mailbox.split('@')[1], mailbox_count: 2 })
  expect(await client.webmailSignIn(change.mailbox, change.actor)).toEqual({ proof: 'b'.repeat(64), expires_at: 1795496580 })
  expect(await client.webmailSignInWithPassword(change.mailbox, change.actor, change.initial_password)).toEqual({ proof: 'b'.repeat(64), expires_at: 1795496580 })
  expect(await client.mailboxActivity(change.mailbox, change.actor)).toEqual({ first_sent_at: null, first_received_at: 1795496580 })
  expect(requests.map(request => new URL(request.url).pathname)).toEqual([
    '/provisioning/v1/status',
    '/provisioning/v1/mailbox',
    '/provisioning/v1/mailbox',
    '/provisioning/v1/mailbox/access',
    '/provisioning/v1/team',
    '/provisioning/v1/team',
    '/provisioning/v1/retirement',
    '/provisioning/v1/webmail/sign-in',
    '/provisioning/v1/webmail/sign-in',
    '/provisioning/v1/mailbox/activity',
  ])
  expect(requests.every(request => request.headers.get('Authorization') === `Bearer ${token}` && request.redirect === 'error')).toBe(true)
  expect(await requests[1].json()).toEqual(change)
  expect(new URL(requests[2].url).searchParams.get('actor')).toBe(change.actor)
  expect(await requests[3].json()).toEqual(renewal)
  expect(Object.fromEntries(new URL(requests[4].url).searchParams)).toEqual({ mailbox: team.mailbox, actor: team.actor })
  expect(requests[4].method).toBe('GET')
  expect(await requests[5].json()).toEqual(team)
  expect(new URL(requests[6].url).searchParams.get('id')).toBe('retirement-00001')
  expect(requests[6].method).toBe('GET')
  expect(await requests[7].json()).toEqual({ mailbox: change.mailbox, actor: change.actor })
  expect(requests[7].cache).toBe('no-store')
  expect(await requests[8].json()).toEqual({ mailbox: change.mailbox, actor: change.actor, password: change.initial_password })
  expect(Object.fromEntries(new URL(requests[9].url).searchParams)).toEqual({ mailbox: change.mailbox, actor: change.actor })
  expect(requests[9].method).toBe('GET')
})

test('provisioning rejects plaintext non-loopback origins and incompatible API revisions', async () => {
  expect(() => createMailProvisioningClient({ baseUrl: 'http://mail.example.test', token })).toThrow()
  const client = createMailProvisioningClient({
    baseUrl,
    token,
    fetch: Object.assign(async () => Response.json({ version: 2, domain: 'mailboxes.example.test' }), { preconnect: fetch.preconnect }),
  })
  await expect(client.status()).rejects.toHaveProperty('code', 'incompatible_version')
  await expect(client.webmailSignIn('reader@hosted.example.test', 'actor-123456789012')).rejects.toHaveProperty('code', 'invalid_sign_in_response')
  await expect(client.mailboxActivity('reader@hosted.example.test', 'actor-123456789012')).rejects.toHaveProperty('code', 'invalid_activity_response')
})

test('activation rejects a proof from a listener that did not confirm the password', async () => {
  const client = createMailProvisioningClient({
    baseUrl,
    token,
    fetch: Object.assign(async () => Response.json({ proof: 'b'.repeat(64), expires_at: 1795496580 }), { preconnect: fetch.preconnect }),
  })
  await expect(client.webmailSignInWithPassword('reader@hosted.example.test', 'actor-123456789012', 'activation-password'))
    .rejects.toHaveProperty('code', 'invalid_sign_in_response')
})
