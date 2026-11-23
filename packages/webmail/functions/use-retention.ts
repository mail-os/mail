import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'

interface Policy { folder: string, days: number }
interface Rule {
  policy: Policy | null
  revision: number
  last_run: number | null
  last_moved: number
}
interface Preview {
  token: string
  policy: Policy
  total: number
  examples: { subject: string, received_at: number }[]
  expires_at: number
}
interface Status {
  rule: Rule
  recoverable: { reference: string, subject: string, source_folder: string, moved_at: number }[]
  page: number
  has_more: boolean
}

const endpoint = '/webmail/api/retention'

export function useRetention(api: ReturnType<typeof createMailApi>) {
  const retention = state<Status | null>(null)
  const retentionFolder = state('INBOX')
  const retentionDays = state('90')
  const retentionPreview = state<Preview | null>(null)
  const retentionPassword = state('')
  const retentionBusy = state(false)
  const retentionError = state('')
  const retentionNotice = state('')
  let generation = 0

  function discardRetentionPreview(): void {
    retentionPreview.set(null)
    retentionPassword.set('')
  }

  function clearRetention(): void {
    generation += 1
    retention.set(null)
    retentionFolder.set('INBOX')
    retentionDays.set('90')
    discardRetentionPreview()
    retentionBusy.set(false)
    retentionError.set('')
    retentionNotice.set('')
  }

  async function withRetention(work: (current: () => boolean) => Promise<void>): Promise<void> {
    if (retentionBusy()) return
    const request = generation
    const current = () => request === generation
    retentionBusy.set(true)
    retentionError.set('')
    retentionNotice.set('')
    try { await work(current) }
    catch (cause) {
      if (!current()) return
      if (cause instanceof MailApiError && ['preview_required', 'revision_mismatch'].includes(cause.code))
        discardRetentionPreview()
      retentionError.set(cause instanceof Error ? cause.message : 'Could not update automatic cleanup.')
    }
    finally { if (current()) retentionBusy.set(false) }
  }

  function loadRetention(page = 1): Promise<void> {
    return withRetention(async (current) => {
      const result = await api<Status>(`${endpoint}?page=${page}`)
      if (!current()) return
      const previous = retention()
      retention.set(result)
      if (previous?.rule.revision !== result.rule.revision) {
        discardRetentionPreview()
        retentionFolder.set(result.rule.policy?.folder || 'INBOX')
        retentionDays.set(String(result.rule.policy?.days ?? 90))
      }
    })
  }

  function prepareRetention(): Promise<void> {
    const settings = retention()
    if (!settings) return Promise.resolve()
    return withRetention(async (current) => {
      discardRetentionPreview()
      const result = await api<Preview>(`${endpoint}/preview`, {
        method: 'POST',
        body: JSON.stringify({ folder: retentionFolder(), days: Number(retentionDays()), revision: settings.rule.revision }),
      })
      if (current()) retentionPreview.set(result)
    })
  }

  function changeRetention(action: 'enable' | 'disable'): Promise<void> {
    const settings = retention()
    const preview = retentionPreview()
    if (!settings || (action === 'enable' && (!preview || !retentionPassword()))) return Promise.resolve()
    return withRetention(async (current) => {
      const body = JSON.stringify({
        action, revision: settings.rule.revision,
        ...(action === 'enable' ? { preview: preview?.token, currentPassword: retentionPassword() } : {}),
      })
      retentionPassword.set('')
      const result = await api<Rule>(endpoint, { method: 'PUT', body })
      if (!current()) return
      discardRetentionPreview()
      retention.set({ ...settings, rule: result })
    })
  }

  function restoreRetainedMessage(reference: string): Promise<void> {
    const settings = retention()
    if (!settings) return Promise.resolve()
    return withRetention(async (current) => {
      await api(`${endpoint}/restore`, { method: 'POST', body: JSON.stringify({ reference }) })
      if (!current()) return
      const remaining = settings.recoverable.filter(message => message.reference !== reference)
      retention.set({ ...settings, recoverable: remaining })
      retentionNotice.set('Message restored.')
      const page = !remaining.length && !settings.has_more ? Math.max(1, settings.page - 1) : settings.page
      const result = await api<Status>(`${endpoint}?page=${page}`)
      if (current()) retention.set(result)
    })
  }

  return {
    retention, retentionFolder, retentionDays, retentionPreview, retentionPassword, retentionBusy, retentionError, retentionNotice,
    clearRetention, discardRetentionPreview, loadRetention, prepareRetention, changeRetention, restoreRetainedMessage,
  }
}
