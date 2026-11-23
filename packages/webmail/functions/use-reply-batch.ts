import { state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface ReplyReview {
  account: string
  from: string
  digest: string
  replies: { reference: string, to: string, subject: string }[]
}
interface ReplyRequest { batchId: string, references: string[], digest: string, text: string, delaySeconds: number }
interface Receipt { id: string, sends: string[], dueAt: number }
const endpoint = '/webmail/api/reply-batches'

export function useReplyBatch(api: ReturnType<typeof createMailApi>, undoSeconds: () => number) {
  const replyBatchOpen = state(false)
  const replyBatchBusy = state(false)
  const replyBatchReview = state<ReplyReview | null>(null)
  const replyBatchText = state('')
  const replyBatchError = state('')
  const replyBatchUncertain = state(false)
  const replyBatchReceipt = state<Receipt | null>(null)
  const replyBatchReferences = state<string[]>([])
  let pending: AbortController | undefined
  let frozen: ReplyRequest | undefined

  function closeReplyBatch() {
    pending?.abort()
    pending = undefined
    frozen = undefined
    replyBatchOpen.set(false)
    replyBatchBusy.set(false)
    replyBatchReview.set(null)
    replyBatchReceipt.set(null)
    replyBatchReferences.set([])
    replyBatchText.set('')
    replyBatchError.set('')
    replyBatchUncertain.set(false)
  }

  async function reviewReplyBatch() {
    if (replyBatchBusy() || !replyBatchReferences().length) return
    const request = new AbortController()
    pending = request
    replyBatchBusy.set(true)
    replyBatchError.set('')
    replyBatchReview.set(null)
    try {
      const result = await api<ReplyReview>(`${endpoint}/preview`, {
        method: 'POST', body: JSON.stringify({ references: replyBatchReferences() }), signal: request.signal,
      })
      if (pending === request) replyBatchReview.set(result)
    }
    catch (cause) {
      if (pending === request) replyBatchError.set(cause instanceof Error ? cause.message : 'Could not review these replies.')
    }
    finally {
      if (pending === request) {
        pending = undefined
        replyBatchBusy.set(false)
      }
    }
  }

  function startReplyBatch(selected: (string | undefined)[]) {
    if (replyBatchBusy() || replyBatchUncertain()) return
    closeReplyBatch()
    replyBatchOpen.set(true)
    if (selected.length < 1 || selected.length > 20) {
      replyBatchError.set('Choose one to twenty received messages.')
      return
    }
    if (!selected.every((reference): reference is string => !!reference)) {
      replyBatchError.set('Open each message to refresh its reference before replying in a batch.')
      return
    }
    replyBatchReferences.set(selected)
    void reviewReplyBatch()
  }

  function acknowledge(receipt: Receipt) {
    frozen = undefined
    replyBatchError.set('')
    replyBatchReceipt.set(receipt)
    replyBatchUncertain.set(false)
  }

  async function queueReplyBatch(check = false): Promise<Receipt | null> {
    const review = replyBatchReview()
    if (replyBatchBusy() || !review) return null
    if (!frozen) {
      const text = replyBatchText()
      if (!text.trim() || new TextEncoder().encode(text).length > 256 * 1024) {
        replyBatchError.set('Enter a reply of up to 256 KiB.')
        return null
      }
      frozen = {
        batchId: globalThis.crypto.randomUUID().replaceAll('-', ''), references: replyBatchReferences(),
        digest: review.digest, text, delaySeconds: undoSeconds(),
      }
    }
    const body = frozen
    const request = new AbortController()
    pending = request
    replyBatchBusy.set(true)
    replyBatchError.set('')
    try {
      let receipt: Receipt | undefined
      if (check) {
        try { receipt = await api<Receipt>(`${endpoint}/${body.batchId}`, { signal: request.signal }) }
        catch (cause) {
          if (!(cause instanceof MailApiError) || cause.status !== 404) throw cause
        }
      }
      receipt ??= await api<Receipt>(endpoint, { method: 'POST', body: JSON.stringify(body), signal: request.signal })
      if (pending !== request) return null
      acknowledge(receipt)
      return receipt
    }
    catch (cause) {
      if (pending === request) {
        if (cause instanceof MailApiError && cause.status < 500) {
          frozen = undefined
          replyBatchUncertain.set(false)
          replyBatchError.set(cause.message)
          if (cause.code === 'reply_preview_changed') replyBatchReview.set(null)
        }
        else {
          replyBatchUncertain.set(true)
          replyBatchError.set('The server did not confirm the batch. Check its status before editing or starting another batch.')
        }
      }
      return null
    }
    finally {
      if (pending === request) {
        pending = undefined
        replyBatchBusy.set(false)
      }
    }
  }

  return {
    replyBatchOpen, replyBatchBusy, replyBatchReview, replyBatchText, replyBatchError, replyBatchUncertain, replyBatchReceipt,
    replyBatchReferences, startReplyBatch, reviewReplyBatch, queueReplyBatch, closeReplyBatch,
  }
}
