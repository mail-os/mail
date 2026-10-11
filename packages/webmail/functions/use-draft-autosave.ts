import type { ComposePayload, DraftAck, DraftDocument } from './mail-types'
import { derived, effect, state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'

type Content = Omit<ComposePayload, 'draftId' | 'draftUid' | 'draftRevision' | 'saveToken'>
interface Options {
  snapshot: () => Content
  hasContent: () => boolean
  active: () => boolean
  blocked: () => boolean
  save: (payload: ComposePayload) => Promise<DraftAck>
  delay?: number
}

/** One save at a time. Retries reuse their token and snapshot until acknowledged. */
export function useDraftAutosave(options: Options) {
  const id = state<string>(crypto.randomUUID())
  const uid = state<number | null>(null)
  const revision = state(0)
  const acknowledged = state('')
  const status = state<'empty' | 'unsaved' | 'saving' | 'saved' | 'error' | 'conflict'>('empty')
  const error = state('')
  const conflict = state(false)
  const saving = state(false)
  const savedAt = state(0)
  const signature = derived(() => JSON.stringify(options.snapshot()))
  const dirty = derived(() => options.hasContent() && signature() !== acknowledged())
  let timer: ReturnType<typeof setTimeout> | undefined
  let inFlight: Promise<void> | null = null
  let attempt: { signature: string, payload: ComposePayload } | null = null
  let destroyed = false
  let failures = 0

  function schedule(delay = options.delay ?? 1500): void {
    clearTimeout(timer)
    if (destroyed || !options.active() || !dirty() || options.blocked() || conflict()) return
    timer = setTimeout(() => { void flush().catch(() => {}) }, delay)
  }

  const stopEffect = effect(() => {
    const changed = signature()
    // Read the guards so upload completion and opening the composer reschedule.
    const active = options.active()
    const blocked = options.blocked()
    if (!options.hasContent()) { status.set('empty'); return }
    if (changed === acknowledged()) { if (!saving()) status.set('saved'); return }
    if (!saving() && !conflict()) status.set('unsaved')
    if (active && !blocked && !saving()) schedule()
  })

  async function perform(): Promise<void> {
    if (destroyed || !options.hasContent() || !dirty()) return
    if (conflict()) throw new Error('This draft changed in another window. Reload the saved version or save a copy.')
    if (options.blocked()) throw new Error('Wait for attachments to finish uploading before saving.')
    saving.set(true)
    status.set('saving')
    error.set('')
    attempt ??= { signature: signature(), payload: { ...options.snapshot(), draftId: id(), draftUid: uid(), draftRevision: revision(), saveToken: crypto.randomUUID() } }
    const pending = attempt
    try {
      const result = await options.save(pending.payload)
      if (destroyed) return
      id.set(result.draftId)
      uid.set(result.uid)
      revision.set(result.revision)
      acknowledged.set(pending.signature)
      savedAt.set(Date.now())
      attempt = null
      failures = 0
      status.set(signature() === pending.signature ? 'saved' : 'unsaved')
    }
    catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Draft could not be saved.'
      error.set(message)
      failures++
      if (cause instanceof MailApiError && cause.status === 409) { conflict.set(true); status.set('conflict') }
      else {
        // A definite rejection never saved this snapshot. Let corrected input
        // replace it; only uncertain network/server failures reuse the token.
        if (cause instanceof MailApiError && cause.status >= 400 && cause.status < 500) attempt = null
        status.set('error')
      }
      throw cause
    }
    finally { saving.set(false) }
  }

  async function flush(): Promise<void> {
    clearTimeout(timer)
    if (inFlight) return inFlight
    inFlight = perform()
    try { await inFlight }
    finally {
      inFlight = null
      if (dirty() && !conflict()) schedule(failures ? Math.min(30000, 2000 * 2 ** Math.min(failures, 4)) : options.delay)
    }
  }

  async function flushAll(): Promise<void> {
    // Explicit save/send freezes the editor; normally at most one old snapshot
    // and one current snapshot need acknowledging.
    for (let count = 0; count < 10 && dirty(); count++) await flush()
    if (dirty()) throw new Error('The draft is still changing. Finish typing and save again.')
  }

  function restore(document: DraftDocument | null, content: Content): void {
    if (inFlight) throw new Error('Wait for the current save to finish.')
    clearTimeout(timer)
    attempt = null
    failures = 0
    id.set(document?.draftId ?? crypto.randomUUID())
    uid.set(document?.uid ?? null)
    revision.set(document?.revision ?? 0)
    acknowledged.set(document ? JSON.stringify(content) : '')
    conflict.set(false)
    error.set('')
    status.set(document ? 'saved' : 'empty')
  }

  function saveCopy(): void {
    if (inFlight) return
    attempt = null
    id.set(crypto.randomUUID())
    uid.set(null)
    revision.set(0)
    acknowledged.set('')
    conflict.set(false)
    error.set('')
    schedule(0)
  }

  function destroy(): void { destroyed = true; clearTimeout(timer); stopEffect() }
  return { id, uid, revision, status, error, conflict, dirty, saving, savedAt, flush, flushAll, restore, saveCopy, schedule, destroy }
}
