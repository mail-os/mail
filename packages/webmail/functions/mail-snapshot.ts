export interface SnapshotMessage { subject: string, from: string, timestamp: number, text: string }
export interface SnapshotView { messages: SnapshotMessage[], expires_at: number }

const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function snapshotDate(seconds: number): string {
  const time = new Date(seconds * 1000)
  return Number.isFinite(time.getTime()) ? formatter.format(time) : ''
}

export function reloadSnapshot(): void {
  globalThis.location.reload()
}

export async function openSnapshot(token: string, signal: AbortSignal): Promise<SnapshotView | null> {
  const response = await fetch('/webmail/public/snapshot', {
    method: 'POST', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
  })
  if (response.status === 404) return null
  if (!response.ok) throw new Error('Could not open this snapshot.')
  return await response.json() as SnapshotView
}
