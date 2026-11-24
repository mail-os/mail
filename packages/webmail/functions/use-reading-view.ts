import { derived, state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'
import { renderMailReader } from './mail-reader'
import { messageIdentity } from './mail-triage'
import type { MessageDetail, MessageRef, MessageSummary } from './mail-types'

export const readingViewLimit = 12
export type ReadingReference = MessageRef & Partial<Pick<MessageSummary, 'from' | 'subject' | 'date' | 'personal_subject'>>

interface ReadingCard {
  key: string
  message: ReadingReference
  open: boolean
  busy: boolean
  error: string
  archived: { receipt: string | null } | null
  detail: MessageDetail | null
  imagesAllowed: boolean
  html: ReturnType<typeof renderMailReader> | null
}

interface ReadingViewPorts {
  reader: { current: HTMLElement | null }
  nextTick: (callback: () => void) => unknown
  load: (message: MessageRef, signal: AbortSignal) => Promise<MessageDetail>
  markRead: (message: MessageDetail, active: () => boolean, update: (message: MessageDetail) => void) => Promise<void>
  archive: (message: MessageRef) => Promise<string | null | false>
  canChange: () => boolean
}

export function useReadingView(ports: ReadingViewPorts) {
  const readingView = state<{ kind: 'unread' | 'selected', total: number, cards: ReadingCard[] } | null>(null)
  const readingViewActiveCard = state<string | null>(null)
  const reads = new Map<string, AbortController>()
  let generation = 0
  const readingViewNext = derived(() => selectNextCard())

  function selectNextCard() {
    const cards = readingView()?.cards ?? []
    const after = cards.findIndex(card => card.key === readingViewActiveCard())
    return [...cards.slice(after + 1), ...cards.slice(0, after + 1)]
      .find(card => !card.open && !card.archived && !card.busy)
  }

  function cardFor(key: string) {
    return readingView()?.cards.find(card => card.key === key)
  }

  function updateCard(key: string, changes: Partial<ReadingCard>) {
    const view = readingView()
    if (view) readingView.set({ ...view, cards: view.cards.map(card => card.key === key ? { ...card, ...changes } : card) })
  }

  function cardHeading(key: string) {
    return Array.from(ports.reader.current?.querySelectorAll<HTMLElement>('[data-reading-card]') ?? [])
      .find(node => node.dataset.readingCard === key)?.querySelector<HTMLElement>('[data-reading-heading]')
  }

  function focusCard(key: string, scroll = false) {
    ports.nextTick(() => {
      const heading = cardHeading(key)
      if (scroll) heading?.scrollIntoView({ block: 'nearest' })
      heading?.focus({ preventScroll: true })
    })
  }

  function updateAnchoredCard(key: string, changes: Partial<ReadingCard>) {
    const reader = ports.reader.current
    const top = cardHeading(key)?.getBoundingClientRect().top
    updateCard(key, changes)
    ports.nextTick(() => {
      const heading = cardHeading(key)
      if (!reader || !heading) return
      if (top !== undefined) reader.scrollTop += heading.getBoundingClientRect().top - top
      heading.focus({ preventScroll: true })
    })
  }

  function closeReadingView() {
    generation++
    for (const request of reads.values()) request.abort()
    reads.clear()
    readingView.set(null)
    readingViewActiveCard.set(null)
  }

  function showReadingView(kind: 'unread' | 'selected', items: ReadingReference[], total: number) {
    closeReadingView()
    const cards = items.slice(0, readingViewLimit).map(message => ({
      key: messageIdentity(message),
      message,
      open: false,
      busy: false,
      error: '',
      archived: null,
      detail: null,
      imagesAllowed: false,
      html: null,
    }))
    readingView.set({ kind, total, cards })
    if (cards[0]) void openReadingCard(cards[0].key, true)
  }

  async function openReadingCard(key: string, focus = false) {
    const card = cardFor(key)
    if (!card || card.busy || card.archived || !ports.canChange()) return
    readingViewActiveCard.set(key)
    if (focus) focusCard(key, true)

    const request = new AbortController()
    reads.set(key, request)
    const active = () => reads.get(key) === request && !request.signal.aborted
    updateCard(key, { open: true, busy: true, error: '', detail: null, html: null, imagesAllowed: false })
    try {
      const loaded = await ports.load(card.message, request.signal)
      const detail = { ...loaded, folder: loaded.folder || card.message.folder, personal_subject: card.message.personal_subject }
      if (!active()) return
      const update = (message: MessageDetail) => {
        const current = cardFor(key)
        if (!active() || !current) return
        updateCard(key, {
          message,
          detail: message,
          html: renderMailReader(message.html, message.embedded_images, current.imagesAllowed),
        })
      }
      update(detail)
      if (detail.folder !== 'Drafts' && !detail.flags.seen) await ports.markRead(detail, active, update)
    }
    catch (cause) {
      if (!active()) return
      updateCard(key, {
        error: cause instanceof MailApiError && cause.status === 404 ? 'This message is no longer available.'
          : cause instanceof Error ? cause.message : 'The message could not be opened.',
      })
    }
    finally {
      if (active()) {
        reads.delete(key)
        updateCard(key, { busy: false })
      }
    }
  }

  function toggleReadingCard(key: string) {
    const card = cardFor(key)
    if (!card || card.busy || card.archived) return
    if (!card.open) void openReadingCard(key)
    else updateCard(key, { open: false, detail: null, html: null, imagesAllowed: false, error: '' })
  }

  function nextReadingCard() {
    const card = readingViewNext()
    if (card) void openReadingCard(card.key, true)
  }

  function toggleReadingImages(key: string) {
    const card = cardFor(key)
    if (!card?.detail || card.busy || !card.html?.remoteImages) return
    const imagesAllowed = !card.imagesAllowed
    updateCard(key, { imagesAllowed, html: renderMailReader(card.detail.html, card.detail.embedded_images, imagesAllowed) })
  }

  async function archiveReadingCard(key: string) {
    const started = generation
    const card = cardFor(key)
    if (!card?.detail || card.busy || card.archived || !ports.canChange()) return
    const receipt = await ports.archive(card.detail)
    if (receipt === false || started !== generation) return
    updateAnchoredCard(key, { archived: { receipt }, open: false, detail: null, html: null, imagesAllowed: false, error: '' })
  }

  function undoReadingArchive(receipt: string) {
    const card = readingView()?.cards.find(card => card.archived?.receipt === receipt)
    if (card) updateAnchoredCard(card.key, { archived: null })
  }

  return {
    readingView, readingViewActiveCard, readingViewNext, showReadingView, closeReadingView,
    toggleReadingCard, openReadingCard, nextReadingCard, toggleReadingImages, archiveReadingCard, undoReadingArchive,
  }
}
