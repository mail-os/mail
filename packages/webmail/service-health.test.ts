import type { HealthReport } from './functions/use-service-health'
import { expect, test } from 'bun:test'
import { healthState, useServiceHealth } from './functions/use-service-health'

const fresh: HealthReport = { available: true, stale: false, report: { checked_at: 1000, status: 'healthy', checks: [], events: [] } }

test('a previously green report expires even if polling stops', () => {
  expect(healthState(fresh, 1100)).toBe('healthy')
  expect(healthState(fresh, 1181)).toBe('unknown')
  expect(healthState(fresh, 900)).toBe('unknown')
  expect(healthState({ ...fresh, stale: true }, 1100)).toBe('unknown')
  expect(healthState(null, 1100)).toBe('unknown')
})

test('a failed refresh clears the old green report and uses uncached authenticated requests', async () => {
  const previous = globalThis.fetch
  const health = useServiceHealth()
  const now = Math.floor(Date.now() / 1000)
  globalThis.fetch = (async (url, options) => {
    expect(url).toBe('/webmail/api/health')
    expect(options?.credentials).toBe('same-origin')
    expect(options?.cache).toBe('no-store')
    return Response.json({ ...fresh, report: { ...fresh.report, checked_at: now } })
  }) as typeof fetch
  try {
    await health.refresh()
    expect(health.status()).toBe('healthy')
    globalThis.fetch = (async () => { throw new TypeError('offline') }) as unknown as typeof fetch
    await health.refresh()
    expect(health.status()).toBe('unknown')
    expect(health.snapshot()).toBeNull()
    expect(health.needsSignIn()).toBe(false)
    expect(health.error()).toContain('unavailable')
  }
  finally { globalThis.fetch = previous }
})

test('an unauthorized refresh clears the report and a successful refresh clears the sign-in prompt', async () => {
  const previous = globalThis.fetch
  const health = useServiceHealth()
  const report = { ...fresh, report: { ...fresh.report, checked_at: Math.floor(Date.now() / 1000) } }
  let unauthorized = false
  globalThis.fetch = (async () => unauthorized
    ? Response.json({ code: 'unauthorized', message: 'Invalid or expired session' }, { status: 401 })
    : Response.json(report)) as typeof fetch
  try {
    await health.refresh()
    expect(health.status()).toBe('healthy')
    unauthorized = true
    await health.refresh()
    expect(health.needsSignIn()).toBe(true)
    expect(health.status()).toBe('unknown')
    expect(health.snapshot()).toBeNull()
    expect(health.error()).toBe('')
    unauthorized = false
    await health.refresh()
    expect(health.needsSignIn()).toBe(false)
    expect(health.status()).toBe('healthy')
  }
  finally { globalThis.fetch = previous }
})
