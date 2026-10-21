import { derived, state } from '@stacksjs/stx'
import { createMailApi } from './mail-api'

export interface HealthReport {
  available: boolean
  stale: boolean
  report?: {
    status: 'healthy' | 'degraded'
    checked_at: number
    last_alert_at?: number
    checks: { name: string, ok: boolean, count?: number, pending?: number, duration_ms?: number }[]
    events: { at: number, status: string, summary: string }[]
  }
}

export function healthState(value: HealthReport | null, now: number): 'unknown' | 'healthy' | 'degraded' {
  if (!value?.available || value.stale || !value.report || now - value.report.checked_at > 180 || value.report.checked_at > now + 30)
    return 'unknown'
  return value.report.status
}

export function useServiceHealth() {
  const snapshot = state<HealthReport | null>(null)
  const now = state(Math.floor(Date.now() / 1000))
  const busy = state(false)
  const error = state('')
  const api = createMailApi(() => undefined, () => {})
  const status = derived(() => healthState(snapshot(), now()))
  const label = derived(() => status() === 'healthy' ? 'Mail checks are passing' : status() === 'degraded' ? 'Mail needs attention' : 'Mail health is unknown')
  const checkedAt = derived(() => snapshot()?.report?.checked_at ? new Date(snapshot()!.report!.checked_at * 1000).toLocaleString() : 'No health report yet')
  async function refresh() {
    now.set(Math.floor(Date.now() / 1000))
    if (busy()) return
    busy.set(true)
    try {
      snapshot.set(await api<HealthReport>('/webmail/api/health', { signal: AbortSignal.timeout(10000) }))
      error.set('')
    }
    catch {
      snapshot.set(null)
      error.set('Health monitoring is unavailable. Retry or contact your administrator.')
    }
    finally { busy.set(false) }
  }
  return { snapshot, status, label, checkedAt, busy, error, refresh, tick: () => now.set(Math.floor(Date.now() / 1000)) }
}
