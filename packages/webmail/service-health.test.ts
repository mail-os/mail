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
    expect(health.error()).toContain('unavailable')
  }
  finally { globalThis.fetch = previous }
})
