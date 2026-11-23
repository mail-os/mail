import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'

interface Permission { integration: string, read: boolean, draft: boolean }
interface Preview extends Permission {
  lifetime: number
  messages: { reference: string, subject: string, text: string }[]
  digest: string
}
interface Grant extends Permission { id: number, message_count: number, expires_at: number, subjects: string[] }
interface Audit { integration: string, actor: string, action: string, outcome: string, occurred_at: number }
const endpoint = '/webmail/api/assistant-grants'

export function useAssistantGrants(api: ReturnType<typeof createMailApi>) {
  const assistantMode = state<'edit' | 'manage' | 'issued' | null>(null)
  const assistantBusy = state(false)
  const assistantError = state('')
  const assistantNotice = state('')
  const assistantName = state('')
  const assistantRead = state(false)
  const assistantDraft = state(false)
  const assistantLifetime = state('3600')
  const assistantSelection = state<string[]>([])
  const assistantPreview = state<Preview | null>(null)
  const assistantIssued = state<{ grant: Grant, token: string } | null>(null)
  const assistantGrants = state<Grant[]>([])
  const assistantAudit = state<Audit[]>([])
  const assistantRevocation = state<Grant | null>(null)
  let request: AbortController | undefined

  function closeAssistant(): void {
    request?.abort()
    request = undefined
    assistantMode.set(null)
    assistantBusy.set(false)
    assistantError.set('')
    assistantNotice.set('')
    assistantName.set('')
    assistantRead.set(false)
    assistantDraft.set(false)
    assistantLifetime.set('3600')
    assistantSelection.set([])
    assistantPreview.set(null)
    assistantIssued.set(null)
    assistantGrants.set([])
    assistantAudit.set([])
    assistantRevocation.set(null)
  }

  async function run<T>(path: string, init: RequestInit, apply: (result: T) => void): Promise<void> {
    if (assistantBusy()) return
    const pending = new AbortController()
    request = pending
    assistantBusy.set(true)
    assistantError.set('')
    assistantNotice.set('')
    try {
      const result = await api<T>(path, { ...init, signal: pending.signal })
      if (request === pending) apply(result)
    }
    catch (cause) {
      if (request !== pending) return
      assistantError.set(cause instanceof Error ? cause.message : 'The assistant request failed.')
      if (cause instanceof MailApiError && cause.code === 'assistant_preview_changed') assistantPreview.set(null)
    }
    finally {
      if (request === pending) {
        request = undefined
        assistantBusy.set(false)
      }
    }
  }

  function beginAssistantGrant(picked: (string | undefined)[] = []): void {
    closeAssistant()
    assistantMode.set('edit')
    if (picked.length > 10 || picked.some(reference => !reference)) {
      assistantError.set('Choose up to ten messages that have stable references.')
      return
    }
    assistantSelection.set(picked as string[])
    assistantRead.set(Boolean(picked.length))
    assistantDraft.set(!picked.length)
  }

  function resetAssistantPreview(): void {
    assistantPreview.set(null)
  }

  function payload() {
    return {
      integration: assistantName(),
      read: assistantRead(),
      draft: assistantDraft(),
      lifetime: Number(assistantLifetime()),
      references: assistantRead() ? assistantSelection() : [],
    }
  }

  async function previewAssistantGrant(): Promise<void> {
    if (assistantMode() !== 'edit') return
    resetAssistantPreview()
    await run<Preview>(`${endpoint}/preview`, { method: 'POST', body: JSON.stringify(payload()) },
      result => assistantPreview.set(result))
  }

  async function approveAssistantGrant(): Promise<void> {
    const preview = assistantPreview()
    if (!preview || assistantMode() !== 'edit') return
    await run<{ grant: Grant, token: string }>(endpoint, { method: 'POST', body: JSON.stringify({ ...payload(), digest: preview.digest }) }, (result) => {
      assistantPreview.set(null)
      assistantSelection.set([])
      assistantIssued.set(result)
      assistantMode.set('issued')
    })
  }

  function manageAssistantGrants(): void {
    closeAssistant()
    assistantMode.set('manage')
    void run<{ grants: Grant[], audit: Audit[] }>(endpoint, {}, (result) => {
      assistantGrants.set(result.grants)
      assistantAudit.set(result.audit)
    })
  }

  async function revokeAssistantGrant(): Promise<void> {
    const grant = assistantRevocation()
    if (!grant || assistantMode() !== 'manage') return
    await run(`${endpoint}/${grant.id}`, { method: 'DELETE' }, () => {
      assistantGrants.update(current => current.filter(item => item.id !== grant.id))
      assistantRevocation.set(null)
      assistantNotice.set('Assistant access revoked.')
    })
  }

  async function copyAssistantToken(): Promise<void> {
    const current = assistantIssued()
    if (!current) return
    try {
      await globalThis.navigator.clipboard.writeText(current.token)
      if (assistantIssued() === current) assistantNotice.set('Credential copied.')
    }
    catch {
      if (assistantIssued() === current) assistantNotice.set('Select and copy the credential manually.')
    }
  }

  return {
    assistantMode, assistantBusy, assistantError, assistantNotice, assistantName, assistantRead, assistantDraft,
    assistantLifetime, assistantSelection, assistantPreview, assistantIssued, assistantGrants, assistantAudit, assistantRevocation,
    beginAssistantGrant, resetAssistantPreview, previewAssistantGrant, approveAssistantGrant, manageAssistantGrants,
    revokeAssistantGrant, copyAssistantToken, closeAssistant,
  }
}
