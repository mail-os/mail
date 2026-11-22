import type { MessageRef } from './mail-types'
import { derived, state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'

export interface ReviewStatus { enabled: boolean, onboarding_pending: boolean, pending: number }
export type ReviewView = 'pending' | 'declined' | 'decisions'
export type ReviewAction = 'allow' | 'decline' | 'recover' | 'reset'
export interface ReviewItem extends MessageRef {
  reference: string
  revision: string
  author: string
  verified: boolean
  envelope_from: string
  recipient: string
  from: string
  subject: string
  date: string
  rule_revision: number
  applying: boolean
}
export interface ReviewRule { author: string, action: 'allow' | 'decline', forward: boolean, revision: number }
interface ReviewPage { status: ReviewStatus, items: ReviewItem[], rules: ReviewRule[], page: number, has_more: boolean }

export function useSenderReview(api: <T>(path: string, options?: RequestInit) => Promise<T>) {
  const senderReviewStatus = state<ReviewStatus | null>(null)
  const senderReviewOpen = state(false)
  const senderReviewView = state<ReviewView>('pending')
  const senderReviewPage = state(1)
  const senderReviewMore = state(false)
  const senderReviewLoading = state(false)
  const senderReviewSaving = state(false)
  const senderReviewError = state('')
  const senderReviewSelection = state<ReviewItem | null>(null)
  const senderReviewRules = state<ReviewRule[]>([])
  const items = state<ReviewItem[]>([])
  let request = 0

  const senderReviewGroups = derived(() => {
    const senders = new Map<string, { id: string, name: string, verified: boolean, messages: ReviewItem[] }>()
    for (const message of items()) {
      const name = message.author || message.envelope_from || 'Unknown sender'
      const id = `${message.verified ? 'verified' : 'unverified'}:${name.toLowerCase()}`
      const group = senders.get(id)
      if (group) group.messages.push(message)
      else senders.set(id, { id, name, verified: message.verified, messages: [message] })
    }
    return [...senders.values()]
  })

  async function refreshSenderReviewStatus(): Promise<void> {
    senderReviewStatus.set(await api<ReviewStatus>('/webmail/api/sender-review/status'))
  }

  async function loadSenderReview(view = senderReviewView(), page = senderReviewPage()): Promise<void> {
    const current = ++request
    senderReviewView.set(view)
    senderReviewPage.set(page)
    senderReviewLoading.set(true)
    senderReviewError.set('')
    try {
      const params = new URLSearchParams({ view, page: String(page) })
      const listing = await api<ReviewPage>(`/webmail/api/sender-review?${params}`)
      if (current !== request) return
      items.set(listing.items)
      senderReviewRules.set(listing.rules)
      senderReviewStatus.set(listing.status)
      senderReviewMore.set(listing.has_more)
      if (page > 1 && !listing.items.length && !listing.rules.length && !listing.has_more) await loadSenderReview(view, page - 1)
    }
    catch (cause) { if (current === request) senderReviewError.set(message(cause)) }
    finally { if (current === request) senderReviewLoading.set(false) }
  }

  function closeSenderReview(): void {
    ++request
    senderReviewOpen.set(false)
    senderReviewLoading.set(false)
    senderReviewSelection.set(null)
    senderReviewError.set('')
  }

  async function setSenderReview(setting: 'enable' | 'disable' | 'onboard'): Promise<void> {
    if (senderReviewSaving()) return
    senderReviewSaving.set(true)
    senderReviewError.set('')
    try {
      senderReviewStatus.set(await api<ReviewStatus>('/webmail/api/sender-review', { method: 'PUT', body: JSON.stringify({ setting }) }))
    }
    catch (cause) { senderReviewError.set(message(cause)) }
    finally { senderReviewSaving.set(false) }
  }

  async function decideSenderReview(action: ReviewAction, target: ReviewItem | ReviewRule, forward?: boolean): Promise<boolean> {
    if (senderReviewSaving() || senderReviewLoading()) return false
    senderReviewSaving.set(true)
    senderReviewError.set('')
    const options: RequestInit = { method: 'POST' }
    if ('reference' in target) {
      options.headers = { 'If-Match': target.revision }
      options.body = JSON.stringify({ action, reference: target.reference, apply_to_sender: target.verified && action !== 'recover', rule_revision: target.rule_revision })
    }
    else options.body = JSON.stringify({ action, author: target.author, rule_revision: target.revision, forward })
    try {
      senderReviewStatus.set(await api<ReviewStatus>('/webmail/api/sender-review/decision', options))
      await loadSenderReview()
      return true
    }
    catch (cause) {
      if (cause instanceof MailApiError && (cause.status === 412 || cause.status === 404 || cause.status === 409)) await loadSenderReview()
      senderReviewError.set(message(cause))
      return false
    }
    finally { senderReviewSaving.set(false) }
  }

  return { senderReviewStatus, senderReviewOpen, senderReviewView, senderReviewPage, senderReviewMore, senderReviewLoading, senderReviewSaving, senderReviewError, senderReviewSelection, senderReviewRules, senderReviewGroups, refreshSenderReviewStatus, loadSenderReview, closeSenderReview, setSenderReview, decideSenderReview }
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : 'Sender Review could not complete the request.'
}
