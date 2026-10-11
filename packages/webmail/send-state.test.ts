import type { ComposePayload, DraftDocument, MessageDetail, OutboxItem } from './functions/mail-types'
import { expect, test } from 'bun:test'
import { useWebmail } from './functions/use-webmail'

for (const lostAcknowledgement of [false, true]) {
  test(`sending an edited draft closes its obsolete reader (${lostAcknowledgement ? 'recovered acknowledgement' : 'normal acknowledgement'})`, async () => {
    const previous = globalThis.fetch
    const username = 'owned@example.test'
    const message: MessageDetail = { uid: 7, folder: 'Drafts', from: username, to: username, cc: '', bcc: '', reply_to: '', subject: 'Saved draft', date: new Date().toISOString(), snippet: 'Saved text', text: 'Saved text', html: '', size: 32, flags: { seen: true, answered: false, flagged: false, draft: true, deleted: false }, has_attachments: false, attachments: [], message_id: '<draft@example.test>', in_reply_to: '', references: '', timestamp: 1, matches_filters: true }
    const payload: ComposePayload = { to: [username], cc: [], bcc: [], subject: message.subject, text: message.text, html: '', inReplyTo: '', references: '', draftUid: 7, draftId: 'abcdefghijklmnop', draftRevision: 1, saveToken: 'saved', recipientInputs: { to: '', cc: '', bcc: '' }, attachments: [], replyContext: null }
    const document: DraftDocument = { draftId: payload.draftId!, revision: 1, uid: 7, state: 'saved', message: payload }
    let queued: OutboxItem | null = null
    let confirmationAvailable = !lostAcknowledgement
    globalThis.fetch = (async (input: RequestInfo | URL, options?: RequestInit) => {
      const path = String(input)
      let result: unknown
      if (path === '/webmail/auth/me') result = { user: { username, email: username } }
      else if (path === '/webmail/api/config') result = { maxFileBytes: 1024, maxTotalBytes: 1024, maxCount: 2, maxMessageBytes: 4096, undoSendSeconds: 10 }
      else if (path === '/webmail/api/folders') result = []
      else if (path.startsWith('/webmail/api/messages?')) result = { items: queued ? [] : [message], threads: [], page: 1, total: queued ? 0 : 1, message_total: queued ? 0 : 1, conversations: false }
      else if (path === '/webmail/api/drafts?uid=7') result = document
      else if (path === '/webmail/api/compose') {
        const submitted = JSON.parse(String(options?.body)) as ComposePayload
        queued = { id: submitted.sendId!, state: 'pending', dueAt: Math.floor(Date.now() / 1000) + 10, serverTime: Math.floor(Date.now() / 1000), message: submitted, result: null, error: null }
        if (lostAcknowledgement) throw new TypeError('Connection interrupted after queue acceptance')
        result = queued
      }
      else if (path.startsWith('/webmail/api/outbox/')) {
        if (!confirmationAvailable) return Response.json({ message: 'Temporarily unavailable' }, { status: 503 })
        result = queued
      }
      else if (path === '/webmail/api/outbox') result = queued ? [queued] : []
      else throw new Error(`Unexpected request ${path}`)
      return Response.json(result)
    }) as typeof fetch
    const mail = useWebmail({ composer: { current: null }, password: { current: null }, confirmation: { current: null }, fileInput: { current: null }, selectAll: { current: null }, navigate: () => {}, nextTick: callback => callback() })
    try {
      await mail.mount()
      mail.selected.set(message)
      await mail.editDraft()
      await mail.send()
      if (lostAcknowledgement) {
        expect(mail.sendUncertain()).toBe(true)
        expect(mail.selected()?.uid).toBe(7)
        confirmationAvailable = true
        await mail.confirmPendingSend()
      }
      expect(mail.selected()).toBeNull()
      expect(mail.composing()).toBe(false)
      expect(mail.sendUncertain()).toBe(false)
      expect(mail.pendingSend()?.state).toBe('pending')
    }
    finally { mail.destroy(); globalThis.fetch = previous }
  })
}
