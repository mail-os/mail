import { state } from '@stacksjs/stx'
import type { SnapshotMessage } from './mail-snapshot'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface SnapshotPreview { messages: SnapshotMessage[], digest: string }
interface SnapshotLink { id: number, subject: string, message_count: number, expires_at: number }
const endpoint = '/webmail/api/snapshot-links'
const maxMessages = 10
export const snapshotLifetimes = [
  { seconds: 3600, label: '1 hour' }, { seconds: 86400, label: '24 hours' }, { seconds: 604800, label: '7 days' },
]

export function useMessageSnapshots(api: ReturnType<typeof createMailApi>) {
  const snapshotMode = state<'preview' | 'issued' | 'manage' | null>(null)
  const snapshotBusy = state(false)
  const snapshotError = state('')
  const snapshotNotice = state('')
  const snapshotLifetime = state('86400')
  const snapshotPreview = state<SnapshotPreview | null>(null)
  const snapshotIssued = state<{ link: SnapshotLink, url: string } | null>(null)
  const snapshotLinks = state<SnapshotLink[]>([])
  const snapshotRevoke = state<SnapshotLink | null>(null)
  let references: string[] = []
  let request: AbortController | undefined

  function closeSnapshots() {
    request?.abort()
    request = undefined
    references = []
    snapshotMode.set(null)
    snapshotBusy.set(false)
    snapshotError.set('')
    snapshotNotice.set('')
    snapshotPreview.set(null)
    snapshotIssued.set(null)
    snapshotLinks.set([])
    snapshotRevoke.set(null)
  }

  async function runSnapshot<T>(path: string, init: RequestInit, apply: (result: T) => void) {
    if (snapshotBusy()) return
    const pending = new AbortController()
    request = pending
    snapshotBusy.set(true)
    snapshotError.set('')
    snapshotNotice.set('')
    try {
      const result = await api<T>(path, { ...init, signal: pending.signal })
      if (request === pending) apply(result)
    }
    catch (cause) {
      if (request !== pending) return
      snapshotError.set(cause instanceof Error ? cause.message : 'The snapshot request failed.')
      if (cause instanceof MailApiError && cause.code === 'snapshot_changed') snapshotPreview.set(null)
    }
    finally {
      if (request === pending) {
        request = undefined
        snapshotBusy.set(false)
      }
    }
  }

  async function refreshSnapshotPreview() {
    if (!references.length || snapshotMode() !== 'preview') return
    snapshotPreview.set(null)
    await runSnapshot<SnapshotPreview>(`${endpoint}/preview`, { method: 'POST', body: JSON.stringify({ references }) },
      result => snapshotPreview.set(result))
  }

  function previewSnapshot(picked: (string | undefined)[]) {
    if (snapshotBusy()) return
    closeSnapshots()
    snapshotMode.set('preview')
    snapshotLifetime.set('86400')
    if (!picked.length || picked.length > maxMessages || picked.some(reference => !reference)) {
      snapshotError.set('Choose one to ten messages. Open any message without a saved reference before sharing it.')
      return
    }
    references = picked as string[]
    void refreshSnapshotPreview()
  }

  async function createSnapshot() {
    const preview = snapshotPreview()
    if (!preview || snapshotMode() !== 'preview') return
    const body = JSON.stringify({ references, digest: preview.digest, lifetime: Number(snapshotLifetime()) })
    await runSnapshot<{ link: SnapshotLink, token: string }>(endpoint, { method: 'POST', body }, (result) => {
      const url = new URL('/snapshot', globalThis.location.origin)
      url.hash = `token=${result.token}`
      snapshotIssued.set({ link: result.link, url: url.href })
      snapshotPreview.set(null)
      snapshotMode.set('issued')
    })
  }

  function manageSnapshots() {
    if (snapshotBusy()) return
    closeSnapshots()
    snapshotMode.set('manage')
    void runSnapshot<{ links: SnapshotLink[] }>(endpoint, {}, result => snapshotLinks.set(result.links))
  }

  function revokeSnapshot() {
    const link = snapshotRevoke()
    if (!link || snapshotMode() !== 'manage') return
    void runSnapshot(`${endpoint}/${link.id}`, { method: 'DELETE' }, () => {
      snapshotLinks.update(current => current.filter(item => item.id !== link.id))
      snapshotRevoke.set(null)
      snapshotNotice.set('Link revoked.')
    })
  }

  async function copySnapshotUrl() {
    const issued = snapshotIssued()
    if (!issued) return
    try {
      await globalThis.navigator.clipboard.writeText(issued.url)
      if (snapshotIssued() === issued) snapshotNotice.set('Link copied.')
    }
    catch {
      if (snapshotIssued() === issued) snapshotNotice.set('Select and copy the link manually.')
    }
  }

  return {
    snapshotMode, snapshotBusy, snapshotError, snapshotNotice, snapshotLifetime, snapshotPreview, snapshotIssued, snapshotLinks,
    snapshotRevoke, previewSnapshot, refreshSnapshotPreview, createSnapshot, manageSnapshots, revokeSnapshot, copySnapshotUrl, closeSnapshots,
    snapshotCanRefresh: () => references.length > 0,
  }
}
