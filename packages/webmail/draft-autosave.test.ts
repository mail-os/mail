import { expect, test } from 'bun:test'
import { state } from '@stacksjs/stx'
import { MailApiError } from './functions/mail-api'
import { useDraftAutosave } from './functions/use-draft-autosave'
import type { ComposePayload } from './functions/mail-types'

function content(text: string) {
  return { to: [], cc: [], bcc: [], subject: '', text, html: '', inReplyTo: '', references: '', recipientInputs: { to: 'unfinished@', cc: '', bcc: '' }, attachments: [], replyContext: null }
}

test('autosave acknowledges the saved snapshot before newer text and reuses a lost acknowledgement token', async () => {
  const body = state('first')
  const calls: ComposePayload[] = []
  let failFirst = true
  const autosave = useDraftAutosave({ snapshot: () => content(body()), hasContent: () => true, active: () => false, blocked: () => false, save: async payload => {
    calls.push(payload)
    if (failFirst) { failFirst = false; throw new TypeError('Network interrupted') }
    return { ok: true, uid: 1, draftId: payload.draftId!, revision: payload.draftRevision + 1 }
  } })
  try {
    await expect(autosave.flush()).rejects.toThrow('Network interrupted')
    body.set('second')
    await autosave.flushAll()
    expect(calls).toHaveLength(3)
    expect(calls[0].saveToken).toBe(calls[1].saveToken)
    expect(calls[1].text).toBe('first')
    expect(calls[2].text).toBe('second')
    expect(calls[2].draftRevision).toBe(1)
    expect(autosave.dirty()).toBe(false)
  }
  finally { autosave.destroy() }
})

test('a stale tab stops saving until the user explicitly saves a new copy', async () => {
  let stale = true
  const ids: string[] = []
  const autosave = useDraftAutosave({ snapshot: () => content('draft'), hasContent: () => true, active: () => false, blocked: () => false, save: async payload => {
    ids.push(payload.draftId!)
    if (stale) throw new MailApiError('Changed in another window', 409, 'conflict')
    return { ok: true, uid: 2, draftId: payload.draftId!, revision: 1 }
  } })
  try {
    await expect(autosave.flush()).rejects.toThrow('Changed in another window')
    expect(autosave.conflict()).toBe(true)
    stale = false
    await expect(autosave.flush()).rejects.toThrow('changed in another window')
    autosave.saveCopy()
    await autosave.flush()
    expect(ids).toHaveLength(2)
    expect(ids[0]).not.toBe(ids[1])
    expect(autosave.dirty()).toBe(false)
  }
  finally { autosave.destroy() }
})

test('corrected input replaces a definitely rejected draft snapshot', async () => {
  const body = state('too large')
  const calls: string[] = []
  const autosave = useDraftAutosave({ snapshot: () => content(body()), hasContent: () => true, active: () => false, blocked: () => false, save: async payload => {
    calls.push(payload.text)
    if (payload.text === 'too large') throw new MailApiError('Message too large', 413, 'too_large')
    return { ok: true, uid: 3, draftId: payload.draftId!, revision: 1 }
  } })
  try {
    await expect(autosave.flush()).rejects.toThrow('Message too large')
    body.set('corrected')
    await autosave.flush()
    expect(calls).toEqual(['too large', 'corrected'])
    expect(autosave.dirty()).toBe(false)
  }
  finally { autosave.destroy() }
})
