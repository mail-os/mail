import type { PrivateCollection, AttachmentPage, IndexProgress, LibraryAttachment, AttentionStatus, AttentionView, BulkAction, BulkResult, CategoryRule, ComposePayload, Contact, Conversation, DraftAck, DraftDocument, Folder, MailLimits, MailNotificationScope, MessageDetail, MessagePage, MessageRef, MessageSummary, OutboxCounts, OutboxItem, OutboxPage, OutboxSummary, OutboxView, SenderIdentity, SharedReplyContext, User } from './mail-types'
import { batch, derived, effect, state } from '@stacksjs/stx'
import { createMailApi, MailApiError } from './mail-api'
import { mailEventLink, takeMailEventLink } from './mail-event-link'
import type { InvitationCalendarTarget, InvitationResponse, InvitationRsvp } from './mail-invitations'
import type { Calendar } from './calendar-types'
import { invitationRevision, rsvpPending } from './mail-invitations'
import { attentionViews, deadlineLabel, localDateInput, localDeadline } from './mail-attention'
import { captureListViewport, isShortcutEvent, messageIdentity, messagePageSize, restoreListViewport, triageShortcuts } from './mail-triage'
import { receiptExcerpt, renderMailReader } from './mail-reader'
import { dateBoundary, folderName, fullDate, messageKey, rangeSelection, readableBytes, recipient, recipients, shortDate } from './mail-utils'
import { useAttachments } from './use-attachments'
import { useDraftAutosave } from './use-draft-autosave'
import { useRecipientEditor } from './use-recipient-editor'
import { useRecoverySettings } from './use-recovery-settings'
import { useForwarding } from './use-forwarding'
import { useExternalSenders } from './use-external-senders'
import { useVacationSettings } from './use-vacation-settings'
import type { ReviewAction, ReviewItem, ReviewView } from './use-sender-review'
import { useSenderReview } from './use-sender-review'
import { useMailNotifications } from './use-mail-notifications'
import { usePrivateMail } from './use-private-mail'
import { useAddressBook } from './use-address-book'
import { useComposeLibrary } from './use-compose-library'
import { useMessageSnapshots } from './use-message-snapshots'
import { useFileLinks } from './use-file-links'
import { linkedFilesInText } from './mail-public-links'
import { useReplyBatch } from './use-reply-batch'

interface Ref<T> { current: T | null }
interface ExternalSendReview { account: string, from: string, to: string[], cc: string[], bcc: string[], token: string }
const categoryFolders = ['Newsletters', 'Receipts']
const categorySettingsPath = '/webmail/api/category-settings'
interface CategorySettings { automatic: boolean }
type ReadingBatch = { kind: 'unread', read: number } | { kind: 'selected', items: MessageRef[], index: number }
type OpenResult = 'opened' | 'seen' | 'missing' | 'failed' | 'cancelled'
type ReadingPosition = Pick<MessageSummary, 'timestamp' | 'folder' | 'uid'>
const emptyOutboxCounts: OutboxCounts = { upcoming: 0, review: 0, history: 0 }
const outboxViews: { id: OutboxView, label: string, empty: string }[] = [
  { id: 'upcoming', label: 'Upcoming', empty: 'No messages waiting to send.' },
  { id: 'review', label: 'Needs review', empty: 'No messages need review.' },
  { id: 'history', label: 'History', empty: 'No send history.' },
]
const emptyFilters = { location: '', sender: '', recipient: '', filename: '', after: '', before: '', status: 'any', flagged: false, attachments: false }

export interface WebmailPorts {
  composer: Ref<HTMLDialogElement>
  password: Ref<HTMLDialogElement>
  confirmation: Ref<HTMLDialogElement>
  fileInput: Ref<HTMLInputElement>
  selectAll: Ref<HTMLInputElement>
  messageList: Ref<HTMLElement>
  messageReader: Ref<HTMLElement>
  shortcutsDialog: Ref<HTMLDialogElement>
  collectionsDialog: Ref<HTMLDialogElement>
  contactsDialog: Ref<HTMLDialogElement>
  navigate: (path: string, options?: { reload?: boolean }) => unknown
  nextTick: (callback: () => void) => unknown
}

export function useWebmail(ports: WebmailPorts) {
  const user = state<User | null>(null)
  const folders = state<Folder[]>([])
  const folder = state('INBOX')
  const messages = state<MessageSummary[]>([])
  const threads = state<Conversation[]>([])
  const expandedThreads = state<string[]>([])
  const selected = state<MessageDetail | null>(null)
  const rsvpBusy = state(false)
  const rsvpError = state<{ index: number, message: string } | null>(null)
  const invitationCalendar = state<{ index: number, choices?: Calendar[], error?: string } | null>(null)
  const invitationDestination = state('')
  const invitationCalendarBusy = state(false)
  const loading = state(false)
  const refreshing = state(false)
  const listError = state('')
  const readerError = state('')
  const readerTarget = state<MessageRef | null>(null)
  const reading = state(false)
  const readingLoading = state(false)
  const mutating = state(false)
  const error = state('')
  const notice = state('')
  const query = state('')
  const activeQuery = state('')
  const appliedFilters = state(emptyFilters)
  const libraryView = state(false)
  const collectionId = state<string | null>(null)
  const libraryFiles = state<LibraryAttachment[]>([])
  const indexProgress = state<IndexProgress | null>(null)
  const searchFolder = derived(() => appliedFilters().location || folder())
  const appliedSearchAll = derived(() => searchFolder() !== folder() || folder() === '*')
  const filterLocation = state('')
  const attentionView = state<AttentionView | null>(null)
  const followUpFocused = state(false)
  const attentionSaving = state(false)
  const attentionSchedule = state<'snoozed' | 'reminders' | null>(null)
  const attentionDate = state('')
  const attentionZone = Intl.DateTimeFormat().resolvedOptions().timeZone
  const dueReminders = state(0)
  const categoryList = derived(() => !libraryView() && !attentionView() && !appliedSearchAll() && categoryFolders.includes(folder()))
  const newsletterExpanded = state(true)
  const receiptFull = state(false)
  const remoteImagesAllowed = state(false)
  const readerExpanded = derived(() => reading() && selected()?.folder === 'Newsletters' && newsletterExpanded())
  const receiptCompact = derived(() => selected()?.folder === 'Receipts' && !receiptFull())
  const receiptPreview = derived(() => {
    const item = selected()
    return item && receiptCompact() ? receiptExcerpt(item.text || '', item.html || '') : ''
  })
  const sortingSettings = state<CategorySettings | null>(null)
  const sortingSaving = state(false)
  const sortingError = state('')
  const categoryRule = state<CategoryRule>('automatic')
  const categoryRuleSaving = state(false)
  const placementText = derived(() => {
    const item = selected()
    if (!item) return ''
    const source = item.placement
    if (!source) return categoryFolders.includes(item.folder) ? 'This copy is filed in ' + folderName(item.folder) + '.' : ''
    if (item.folder !== source.original_folder) return 'Delivered to ' + folderName(source.original_folder) + '. This copy is now in ' + folderName(item.folder) + '.'
    switch (source.reason) {
      case 'sender_rule': return 'Filed here by a rule for this sender.'
      case 'mailing_list': return 'Filed in Newsletters because it came from a mailing list.'
      case 'receipt_subject': return 'Filed in Receipts because the subject looks like a receipt, invoice, or order confirmation.'
      case 'sender_review': return 'Released to Inbox from Sender Review.'
      case 'spam_filter': return 'The spam filter placed this message here.'
      case 'junk_feedback': return 'Filed here based on your Junk feedback for this sender.'
      case 'not_junk_feedback': return 'Delivered to Inbox based on your Not Junk feedback for this sender.'
      default: return ''
    }
  })
  const filterSender = state('')
  const filterRecipient = state('')
  const filterFilename = state('')
  const filterAfter = state('')
  const filterBefore = state('')
  const filterStatus = state('any')
  const filterFlagged = state(false)
  const filterAttachments = state(false)
  const filtersOpen = state(false)
  const conversations = state(true)
  const page = state(1)
  const total = state(0)
  const matchingTotal = state(0)
  const moveTo = state('Archive')
  const showHtml = state(true)
  const formattedReader = derived(() => {
    const item = selected()
    return renderMailReader(item?.html || '', item?.embedded_images, remoteImagesAllowed())
  })
  const checked = state<MessageRef[]>([])
  const readingBatch = state<ReadingBatch | null>(null)
  const triageBusy = state(false)
  const shortcutsOpen = state(false)
  const undoAction = state<{ id: string, expiresAt: number, kind?: 'group' } | null>(null)
  const now = state(Date.now() / 1000)
  const outbox = state<OutboxSummary[]>([])
  const outboxCounts = state<OutboxCounts>(emptyOutboxCounts)
  const outboxSection = state<OutboxView>('upcoming')
  const outboxCursors = state<(string | null)[]>([null])
  const outboxNext = state<string | null>(null)
  const outboxPageNumber = derived(() => outboxCursors().length)
  const outboxEmpty = derived(() => outboxViews.find(view => view.id === outboxSection())!.empty)
  const outboxLoading = state(false)
  const outboxError = state('')
  const pendingSend = state<OutboxSummary | null>(null)
  const outboxView = state(false)
  const cancelling = state(false)
  const authExpired = state(false)
  const composing = state(false)
  const title = state('New message')
  const sharedReply = state<SharedReplyContext | null>(null)
  const senderId = state('')
  const externalSender = derived(() => senderId().startsWith('external-'))
  const reviewedExternalSend = state<(ExternalSendReview & { senderId: string }) | null>(null)
  const senderIdentities = state<SenderIdentity[] | null>(null)
  const missingSender = derived(() => Boolean(senderId() && !senderIdentities()?.some(identity => identity.id === senderId())))
  const senderError = state('')
  const senderStatus = derived(() => senderError() || (missingSender() && senderIdentities() ? 'Choose an available From address to send this message.' : ''))
  const subject = state('')
  const body = state('')
  const automaticSignature = state('')
  const snippetChoice = state('')
  const signatureChoice = state('')
  const draftHtml = state('')
  const initialText = state('')
  const inReplyTo = state('')
  const references = state('')
  const replyContext = state<MessageRef | null>(null)
  const clearFollowUp = state(false)
  const showCc = state(false)
  const showBcc = state(false)
  const sending = state(false)
  const sendUncertain = state(false)
  const composeError = state('')
  const sendDelay = state(10)
  const scheduleOpen = state(false)
  const scheduleDate = state('')
  const scheduleZoneFormat = new Intl.DateTimeFormat(undefined, { timeZoneName: 'long' })
  const scheduleZone = derived(() => {
    const selected = selectedSchedule()
    return scheduleZoneFormat.formatToParts(selected == null ? Date.now() : selected * 1000).find(part => part.type === 'timeZoneName')?.value || attentionZone
  })
  const sendDelayOptions = derived(() => [...new Set([0, 5, 10, 30, sendDelay()])].sort((left, right) => left - right))
  const settings = state(false)
  const leavingAccount = state(false)
  const accountChangeError = state('')
  const currentPassword = state('')
  const newPassword = state('')
  const confirmPassword = state('')
  const passwordError = state('')
  const savingPassword = state(false)
  const confirmation = state('')
  const confirming = state(false)
  const limits = state<MailLimits>({ maxFileBytes: 0, maxTotalBytes: 0, maxCount: 0, maxMessageBytes: 0, undoSendSeconds: 10 })
  let listRequest = 0
  let messageRequest = 0
  let triageRequest = 0
  let readingViewport: ReturnType<typeof captureListViewport> = null
  let retryReading: (() => Promise<void>) | null = null
  let shortcutsTrigger: HTMLElement | null = null
  let selectionAnchor: string | null = null
  let clockOffset = 0
  let lastRefresh = 0
  let lastOutboxPoll = 0
  let lastRsvpPoll = 0
  let pollingRsvp = false
  let pollingOutbox = false
  let outboxRequest = 0
  let senderRequest = 0
  let destroyed = false
  let confirmationRefs: MessageRef[] = []
  let reviewedOutboxId: string | null = null
  let lastQueuedPayload: ComposePayload | null = null
  const announcedSends = new Set<string>()

  function clearAccountState(): void {
    destroyed = true
    invalidateList()
    closeReader()
    snapshots.closeSnapshots()
    fileSharing.closeFileLinkManager()
    replyBatch.closeReplyBatch()
    contactBook.closeContacts()
    forwardingSettings.clearForwarding()
    externalSenderSettings.clearExternalAddresses()
    vacationSettings.clearVacationSettings()
    writing.clearWritingLibrary()
    senderIdentities.set(null)
    privateMail.privateCollections.set([])
    draft.destroy()
    resetComposition()
    recipientEditor.destroy()
    batch(() => {
      user.set(null)
      messages.set([])
      threads.set([])
      folders.set([])
      libraryFiles.set([])
      outbox.set([])
      outboxCounts.set(emptyOutboxCounts)
      checked.set([])
      undoAction.set(null)
      pendingSend.set(null)
      settings.set(false)
    })
  }

  function onAuthError(cause: MailApiError): void {
    if (destroyed) return
    authExpired.set(true)
    if (cause.code === 'account_changed') {
      clearAccountState()
      ports.navigate('/login', { reload: true })
    }
    else if (!user()) ports.navigate('/login', { reload: true })
  }
  const api = createMailApi(() => user()?.username, onAuthError, () => !destroyed)
  const snapshots = useMessageSnapshots(api)
  const fileSharing = useFileLinks(api, () => limits().maxFileLinkBytes ?? 0)
  const replyBatch = useReplyBatch(api, sendDelay)
  const messageFileLinks = derived(() => linkedFilesInText(selected()?.text ?? ''))
  async function loadSenderIdentities(): Promise<void> {
    const request = ++senderRequest
    try {
      const choices = await api<SenderIdentity[]>('/webmail/api/sender-identities')
      if (request === senderRequest && !destroyed && Array.isArray(choices)) senderIdentities.set(choices)
    }
    catch { /* Delivery rechecks the grant even when the list is unavailable. */ }
  }
  function chooseSender(event: Event): void {
    senderId.set((event.target as HTMLSelectElement).value)
    senderError.set('')
  }
  const writing = useComposeLibrary(api)
  const notifications = useMailNotifications(api, () => user()?.username)
  const senderReview = useSenderReview(api)
  const privateMail = usePrivateMail(api, selected)
  const contactBook = useAddressBook(api)
  async function showContacts(): Promise<void> {
    if (contactBook.contactsOpen()) return
    contactBook.contactsOpen.set(true)
    ports.nextTick(() => { if (contactBook.contactsOpen() && !ports.contactsDialog.current?.open) ports.contactsDialog.current?.showModal() })
    await contactBook.loadContacts()
  }
  async function composeSavedCard(): Promise<void> {
    const addresses = contactBook.savedContactRecipients()
    if (addresses.length === 0) {
      contactBook.contactsError.set('This card has no available email addresses.')
      return
    }
    if (sending() || mutating() || contactBook.contactsBusy()) return
    contactBook.contactsBusy.set(true)
    try {
      if (hasComposition()) await draft.flushAll()
      await writing.loadWritingLibrary()
      if (destroyed || !user() || authExpired()) return
      contactBook.closeContacts()
      resetComposition()
      recipientEditor.restore({ to: addresses, cc: [], bcc: [] }, { to: '', cc: '', bcc: '' })
      title.set('New message')
      applyDefaultSignature()
      showComposer()
    }
    catch (cause) { contactBook.contactsError.set(errorMessage(cause)) }
    finally { contactBook.contactsBusy.set(false) }
  }

  const collectionView = derived(() => privateMail.privateCollections().find(item => item.id === collectionId()) || null)
  const canOpenPrivate = derived(() => Boolean(selected()?.reference && selected()?.folder !== 'Drafts' && !senderReview.senderReviewOpen()))

  const recipientEditor = useRecipientEditor(value => api<Contact[]>(`/webmail/api/contacts?q=${encodeURIComponent(value)}`))
  const recoverySettings = useRecoverySettings(api, () => user()?.username || '')
  const forwardingSettings = useForwarding(api)
  const externalSenderSettings = useExternalSenders(api, () => { void loadSenderIdentities() })
  const vacationSettings = useVacationSettings(api)
  const attachmentEditor = useAttachments(() => user()?.username, limits, cause => {
    if (cause instanceof MailApiError && (cause.status === 401 || cause.code === 'account_changed')) onAuthError(cause)
  }, id => api(`/webmail/api/uploads/${id}`, { method: 'DELETE' }))
  const hasComposition = derived(() => Boolean(subject() || (body() && body() !== automaticSignature()) || draftHtml() || attachmentEditor.attachments().length || recipientEditor.toRecipients().length || recipientEditor.ccRecipients().length || recipientEditor.bccRecipients().length || recipientEditor.toInput() || recipientEditor.ccInput() || recipientEditor.bccInput()))
  function selectedSchedule(): number | null {
    if (!scheduleOpen()) return null
    try { return localDeadline(scheduleDate(), -Infinity) }
    catch { return null }
  }
  function content() {
    return { ...recipientEditor.snapshot(), subject: subject(), text: body(), html: body() === initialText() ? draftHtml() : '', inReplyTo: inReplyTo(), references: references(), attachments: attachmentEditor.snapshot(), replyContext: replyContext(), clearFollowUp: clearFollowUp(), scheduleAt: selectedSchedule(), senderId: senderId() || null, sharedReply: sharedReply() }
  }
  const externalSendReview = derived(() => {
    const review = reviewedExternalSend()
    if (!review || senderId() !== review.senderId || user()?.username !== review.account) return null
    const draftRecipients = recipientEditor.snapshot()
    if (Object.values(draftRecipients.recipientInputs).some(Boolean)) return null
    return (['to', 'cc', 'bcc'] as const).every(field => JSON.stringify(draftRecipients[field]) === JSON.stringify(review[field])) ? review : null
  })
  const draft = useDraftAutosave({ snapshot: content, hasContent: hasComposition, active: () => composing() && !sending(), blocked: () => attachmentEditor.attachmentPending() || fileSharing.fileLinkUploading() || authExpired(), save: payload => api<DraftAck>('/webmail/api/drafts', { method: 'POST', body: JSON.stringify(payload) }) })
  const hasUnsavedChanges = derived(() => draft.dirty() || attachmentEditor.attachmentPending() || fileSharing.fileLinkUploading())
  const saveStatus = derived(() => {
    if (attachmentEditor.attachments().some(item => item.status === 'loading')) return 'Loading forwarded attachments…'
    if (attachmentEditor.attachmentUploading()) return 'Uploading attachments…'
    if (attachmentEditor.attachmentPending()) return 'An attachment needs attention.'
    if (draft.status() === 'saved') return 'Saved to Drafts'
    if (draft.status() === 'saving') return 'Saving…'
    if (draft.status() === 'conflict') return 'This draft changed in another window.'
    if (draft.status() === 'error') return 'Draft not saved. Your changes are still here.'
    return hasComposition() ? 'Unsaved changes' : 'Drafts save automatically as you type.'
  })
  const visibleMessages = derived(() => threads().length ? threads().flatMap(thread => thread.members.filter(message => message.matches_filters !== false)) : messages())
  const checkedKeys = derived(() => checked().map(messageIdentity))
  const selectedCount = derived(() => checked().length)
  function isJunkFolder(name: string): boolean { return name === 'Junk' || name === limits().junkFolder }
  const canShareSnapshot = derived(() => {
    const item = selected()
    return !!item?.reference && !['Drafts', 'Trash', 'Screening', 'Declined'].includes(item.folder)
      && !isJunkFolder(item.folder) && !item.flags.deleted && !item.flags.draft && !senderReview.senderReviewOpen()
  })
  function shareMessageSnapshot() {
    if (canShareSnapshot()) snapshots.previewSnapshot([selected()?.reference])
  }
  function shareSelectedSnapshot() {
    snapshots.previewSnapshot(checked().map(item => item.reference))
  }
  function replyToSelection() {
    replyBatch.startReplyBatch(checked().map(item => item.reference))
  }
  async function submitReplyBatch(check = false) {
    if (await replyBatch.queueReplyBatch(check)) {
      clearSelection()
      await refreshOutbox(true)
    }
  }
  function junkActionFor(name: string): 'junk' | 'not_junk' | null {
    if (isJunkFolder(name)) return 'not_junk'
    if (['sent', 'drafts', 'trash', 'screening', 'declined'].includes(name.toLowerCase())) return null
    return 'junk'
  }
  const readerJunkAction = derived(() => selected() ? junkActionFor(selected()!.folder) : null)
  const selectionJunkAction = derived(() => {
    const messages = checked()
    if (!messages.length) return null
    const action = junkActionFor(messages[0].folder)
    return messages.every(item => junkActionFor(item.folder) === action) ? action : null
  })
  const allChecked = derived(() => visibleMessages().length > 0 && visibleMessages().every(message => checkedKeys().includes(messageIdentity(message))))
  const someChecked = derived(() => !allChecked() && visibleMessages().some(message => checkedKeys().includes(messageIdentity(message))))
  const unreadAvailable = derived(() => !libraryView() && !outboxView() && !senderReview.senderReviewOpen() && !attentionView() && appliedFilters().status !== 'read' && (appliedSearchAll() || folder() !== 'Drafts'))
  const filterActive = derived(() => {
    const filter = appliedFilters()
    return Boolean(activeQuery() || filter.sender || filter.recipient || filter.filename || filter.after || filter.before || filter.status !== 'any' || filter.flagged || filter.attachments || (filter.location && filter.location !== folder()))
  })
  const undoRemaining = derived(() => Math.min(30, Math.max(0, Math.ceil((undoAction()?.expiresAt ?? 0) - now()))))
  const sendRemaining = derived(() => pendingSend()?.scheduled ? 0 : Math.max(0, Math.ceil((pendingSend()?.dueAt ?? 0) - now())))
  const outboxCount = derived(() => outboxCounts().upcoming + outboxCounts().review)
  const currentFolderName = derived(() => {
    if (outboxView()) return 'Outbox'
    if (libraryView()) return 'Attachments'
    if (collectionView()) return collectionView()!.name
    return attentionViews.find(item => item.name === attentionView())?.label || folderName(searchFolder())
  })
  const selectionEffect = effect(() => { const partial = someChecked(); if (ports.selectAll.current) ports.selectAll.current.indeterminate = partial })

  function messagePath(message: MessageRef): string {
    return message.reference
      ? `/webmail/api/messages/ref/${encodeURIComponent(message.reference)}`
      : `/webmail/api/messages/${message.uid}?folder=${encodeURIComponent(message.folder)}`
  }
  function messageRef(message: MessageRef): MessageRef {
    return { uid: message.uid, folder: message.folder, reference: message.reference, revision: message.revision }
  }
  function createEventLink(): string | null {
    const message = selected()
    const account = user()?.username
    if (!limits().calendarAvailable || !message?.reference || !account || message.folder === 'Drafts' || senderReview.senderReviewOpen()) return null
    if (message.calendar_history_pending || message.calendar_invitation_events?.some(Boolean)) return null
    if (message.calendar_invites?.length && !message.calendar_invites.some((invite, index) => {
      const availability = message.calendar_rsvps?.[index]?.availability
      return invite.method === 'request' && (!availability || availability === 'current')
    })) return null
    return mailEventLink('/calendar', account, message.reference)
  }
  async function chooseInvitationCalendar(index: number): Promise<void> {
    if (invitationCalendarBusy() || readingLoading()) return
    const request = messageRequest
    invitationCalendar.set({ index })
    invitationCalendarBusy.set(true)
    try {
      const { calendars } = await api<{ calendars: Calendar[] }>('/webmail/api/calendars')
      if (!destroyed && request === messageRequest) {
        invitationDestination.set(String(calendars[0]?.id ?? ''))
        invitationCalendar.set({ index, choices: calendars })
      }
    }
    catch (cause) {
      if (request === messageRequest) invitationCalendar.set({ index, error: errorMessage(cause) })
    }
    finally { invitationCalendarBusy.set(false) }
  }
  async function saveInvitationCalendar(index: number): Promise<void> {
    const message = selected()
    const action = message?.calendar_invitation_events?.[index]
    if (invitationCalendarBusy() || readingLoading() || !message?.reference || !message.revision || !action || action.applied) return
    const calendarId = action.target?.calendarId ?? Number(invitationDestination())
    if (!calendarId) return
    const request = messageRequest
    invitationCalendar.set({ index })
    invitationCalendarBusy.set(true)
    try {
      const result = await api<InvitationCalendarTarget>('/webmail/api/calendar-invitation-event', {
        method: 'POST',
        headers: { 'If-Match': message.revision },
        body: JSON.stringify({ reference: message.reference, index, calendarId, eventRevision: action.target?.etag }),
      })
      const current = selected()
      if (!destroyed && request === messageRequest && current?.calendar_invitation_events) {
        const actions = [...current.calendar_invitation_events]
        actions[index] = { target: { id: result.id, calendarId: result.calendarId, etag: result.etag }, applied: true }
        selected.set({ ...current, calendar_invitation_events: actions })
      }
    }
    catch (cause) {
      if (request === messageRequest) invitationCalendar.set({ index, error: errorMessage(cause) })
    }
    finally { invitationCalendarBusy.set(false) }
  }
  function canRespondToInvitation(index: number, response: InvitationResponse): boolean {
    const message = selected()
    const invite = message?.calendar_invites?.[index]
    const action = message?.calendar_rsvps?.[index]
    if (!invite || !action) return false
    if (action.availability && action.availability !== 'current') return false
    const status = action.status
    if (!status) return true
    if (rsvpPending(status) || status.state === 'unknown') return false
    const revision = invitationRevision(invite, status)
    if (revision < 0) return false
    const delivered = status.state === 'sent' || status.state === 'sent_unfiled'
    return revision > 0 || !delivered || response !== status.decision.response
  }
  async function respondToInvitation(index: number, response: InvitationResponse): Promise<void> {
    const message = selected()
    if (!message?.reference || !message.revision || rsvpBusy() || readingLoading() || !canRespondToInvitation(index, response)) return
    const request = messageRequest
    rsvpBusy.set(true)
    rsvpError.set(null)
    try {
      const status = await api<InvitationRsvp>('/webmail/api/calendar-rsvp', {
        method: 'POST',
        headers: { 'If-Match': message.revision },
        body: JSON.stringify({ reference: message.reference, index, response, previousSendId: message.calendar_rsvps?.[index]?.status?.decision.sendId }),
      })
      const current = selected()
      if (!destroyed && request === messageRequest && current?.calendar_rsvps) {
        const actions = [...current.calendar_rsvps]
        actions[index] = { status }
        selected.set({ ...current, calendar_rsvps: actions })
      }
      void refreshOutbox(true)
    }
    catch (cause) {
      if (request === messageRequest) rsvpError.set({ index, message: errorMessage(cause) })
    }
    finally { rsvpBusy.set(false) }
  }
  async function pollInvitationReplies(): Promise<void> {
    const actions = selected()?.calendar_rsvps
    if (!actions?.some(action => rsvpPending(action?.status)) || pollingRsvp || Date.now() - lastRsvpPoll < 2000) return
    const request = messageRequest
    pollingRsvp = true
    lastRsvpPoll = Date.now()
    try {
      const updated = await Promise.all(actions.map(async (action) => {
        const status = action?.status
        if (!status || !rsvpPending(status)) return action
        const item = await api<OutboxItem>(`/webmail/api/outbox/${encodeURIComponent(status.decision.sendId)}`)
        return { ...action, status: { ...status, state: item.state } }
      }))
      const current = selected()
      if (!destroyed && request === messageRequest && current?.calendar_rsvps === actions) {
        selected.set({ ...current, calendar_rsvps: updated })
        if (!updated.some(action => rsvpPending(action?.status))) void refreshOutbox(true)
      }
    }
    catch { /* Leave the last known state visible and poll again. */ }
    finally { pollingRsvp = false }
  }
  function displaySubject(message: Pick<MessageSummary, 'subject' | 'personal_subject'> | null): string {
    return message?.personal_subject || message?.subject || '(no subject)'
  }
  function senderLabel(from: string): string { return recipient(from).name || from }
  function attachmentPath(index: number, message: MessageRef | null = selected()): string {
    const params = new URLSearchParams({ index: String(index), account: user()?.username || '' })
    const revision = message?.content_revision || message?.revision
    if (message?.reference && revision) {
      params.set('reference', message.reference)
      params.set(message.content_revision ? 'content_revision' : 'revision', revision)
    }
    else {
      params.set('uid', String(message?.uid))
      params.set('folder', message?.folder || folder())
    }
    return `/webmail/api/attachment?${params}`
  }
  function cancelBatch(): void {
    ++triageRequest
    readingBatch.set(null)
    triageBusy.set(false)
  }
  function closeReader(restoreFocus = false): void {
    cancelBatch()
    const saved = readingViewport
    readingViewport = null
    ++messageRequest
    selected.set(null)
    invitationCalendar.set(null)
    privateMail.closePrivate()
    remoteImagesAllowed.set(false)
    senderReview.senderReviewSelection.set(null)
    reading.set(false)
    readingLoading.set(false)
    readerError.set('')
    rsvpError.set(null)
    readerTarget.set(null)
    retryReading = null
    followUpFocused.set(false)
    attentionSchedule.set(null)
    if (restoreFocus) ports.nextTick(() => {
      if (saved) restoreListViewport(saved, true)
      else ports.messageList.current?.focus({ preventScroll: true })
    })
  }
  async function loadFolders(): Promise<void> { folders.set(await api<Folder[]>('/webmail/api/folders')) }
  function listParams(): URLSearchParams {
    const filter = appliedFilters()
    const after = dateBoundary(filter.after)
    const before = dateBoundary(filter.before, true)
    if (after !== null && before !== null && before < after) throw new Error('End date must follow start date.')
    const params = new URLSearchParams({
      folder: searchFolder(), page: String(page()), per_page: String(messagePageSize), q: libraryView() ? '' : activeQuery(),
      from: filter.sender, to: filter.recipient, filename: filter.filename, index_budget: '256', status: filter.status, flagged: String(filter.flagged), attachments: String(filter.attachments),
      conversations: String(conversations() && folder() !== 'Drafts'), bundles: String(categoryList()),
    })
    const workflow = attentionView()
    if (workflow) params.set('attention', workflow)
    if (!libraryView()) params.set('personal', 'true')
    const collection = collectionId()
    if (collection) params.set('collection', collection)
    if (after !== null) params.set('after', String(after))
    if (before !== null) params.set('before', String(before))
    return params
  }
  function invalidateList(): void {
    ++listRequest
    loading.set(false)
    refreshing.set(false)
    listError.set('')
    indexProgress.set(null)
  }
  async function loadMessages(quiet = false): Promise<boolean> {
    if (outboxView() || senderReview.senderReviewOpen() || (quiet && loading())) return false
    const request = ++listRequest
    refreshing.set(quiet)
    if (!quiet) {
      loading.set(true)
      messages.set([])
      threads.set([])
      libraryFiles.set([])
      indexProgress.set(null)
    }
    try {
      const route = libraryView() ? 'attachments' : 'messages'
      const path = `/webmail/api/${route}?${listParams()}`
      let result = await api<MessagePage | AttachmentPage>(path)
      while (result.index?.pending && !destroyed && request === listRequest) {
        indexProgress.set(result.index)
        await new Promise(resolve => setTimeout(resolve, 75))
        if (destroyed || request !== listRequest) return false
        result = await api<MessagePage | AttachmentPage>(path)
      }
      if (destroyed || request !== listRequest) return false
      const viewport = quiet ? captureListViewport(ports.messageList.current) : null
      batch(() => {
        if ('message_total' in result) {
          messages.set(result.items || [])
          threads.set(result.threads || [])
          matchingTotal.set(result.message_total)
        }
        else {
          libraryFiles.set(result.items)
          matchingTotal.set(result.total)
        }
        indexProgress.set(null)
        total.set(result.total)
        page.set(result.page)
        listError.set('')
      })
      ports.nextTick(() => {
        if (request !== listRequest) return
        if (ports.selectAll.current) ports.selectAll.current.indeterminate = someChecked()
        if (quiet) restoreListViewport(viewport)
        else if (ports.messageList.current) ports.messageList.current.scrollTop = 0
      })
      return true
    }
    catch (cause) {
      if (request === listRequest) listError.set(errorMessage(cause))
      return false
    }
    finally {
      if (request === listRequest) {
        loading.set(false)
        refreshing.set(false)
        indexProgress.set(null)
      }
    }
  }
  async function refresh(quiet = false): Promise<void> {
    lastRefresh = Date.now()
    const reviewOpen = senderReview.senderReviewOpen()
    await Promise.all([
      reviewOpen ? senderReview.loadSenderReview() : loadMessages(quiet),
      loadFolders().catch(cause => error.set(errorMessage(cause))),
      reviewOpen ? Promise.resolve() : senderReview.refreshSenderReviewStatus().catch(() => {}),
      refreshAttention().catch(() => {}),
    ])
  }
  async function refreshAttention(): Promise<void> {
    const before = selected()
    const status = before?.attention
    const marked = status?.saved || status?.follow_up || status?.muted || status?.snooze_until || status?.remind_at
    const reference = marked && !readingLoading() && !attentionSaving() ? before?.reference : null
    const request = reference ? '?reference=' + encodeURIComponent(reference) : ''
    const result = await api<{ due_reminders: number, attention: AttentionStatus | null }>('/webmail/api/attention' + request)
    dueReminders.set(result.due_reminders)
    if (before && reference && result.attention && selected() === before && !attentionSaving()) selected.set({ ...before, attention: result.attention })
  }
  function clearSelection(): void { checked.set([]); selectionAnchor = null }
  function resetSearch(): void {
    batch(() => {
      query.set('')
      activeQuery.set('')
      appliedFilters.set(emptyFilters)
      filterLocation.set('')
      filterSender.set('')
      filterRecipient.set('')
      filterFilename.set('')
      filterAfter.set('')
      filterBefore.set('')
      filterStatus.set('any')
      filterFlagged.set(false)
      filterAttachments.set(false)
      page.set(1)
    })
  }
  async function selectFolder(name: string, workflow: AttentionView | null = null, library = false, collection: string | null = null): Promise<void> {
    if (mutating()) return
    senderReview.closeSenderReview()
    batch(() => {
      folder.set(name)
      attentionView.set(workflow)
      libraryView.set(library)
      collectionId.set(collection)
      outboxView.set(false)
      expandedThreads.set([])
      resetSearch()
    })
    clearSelection()
    closeReader()
    await refresh()
  }
  async function showAttachmentLibrary(): Promise<void> { await selectFolder('*', null, true) }
  async function selectCollection(item: PrivateCollection): Promise<void> {
    closeCollectionManager()
    await selectFolder('*', null, false, item.id)
  }
  async function showCollectionManager(): Promise<void> {
    if (privateMail.collectionsOpen()) return
    privateMail.clearCollectionEditor()
    privateMail.collectionsError.set('')
    privateMail.collectionsOpen.set(true)
    ports.nextTick(() => { if (privateMail.collectionsOpen() && !ports.collectionsDialog.current?.open) ports.collectionsDialog.current?.showModal() })
    await privateMail.loadPrivateCollections()
  }
  function closeCollectionManager(): void {
    privateMail.collectionsOpen.set(false)
    privateMail.clearCollectionEditor()
  }
  async function confirmCollectionDeletion(): Promise<void> {
    const id = privateMail.deletingCollection()?.id
    if (id && await privateMail.deletePrivateCollection() && collectionId() === id) {
      closeCollectionManager()
      await selectFolder('*')
    }
  }
  async function savePrivateLabel(): Promise<void> {
    const reference = selected()?.reference
    const result = await privateMail.storePrivateLabel()
    const current = selected()
    if (result && current && current.reference === reference) {
      selected.set({ ...current, personal_subject: result.label.value })
      await refresh(true)
    }
  }
  async function setPrivateMembership(item: PrivateCollection, event: Event): Promise<void> {
    if (await privateMail.changePrivateMembership(item, event) && collectionId()) await loadMessages(true)
  }

  async function selectAttention(view: AttentionView): Promise<void> { await selectFolder('INBOX', view) }
  async function nextFollowUp(): Promise<void> {
    if (loading() || readingLoading() || mutating() || attentionView() !== 'follow_up') return
    const rows = messages()
    const current = selected()
    const index = current ? rows.findIndex(item => item.reference === current.reference) : -1
    let next = rows[index + 1]
    if (!next && page() * messagePageSize < total()) {
      page.update(value => value + 1)
      clearSelection()
      await loadMessages()
      next = messages()[0]
    }
    if (!next) { notice.set('You’re at the end of the reply queue.'); return }
    followUpFocused.set(true)
    await openMessage(next)
  }
  async function search(): Promise<void> {
    appliedFilters.set({
      location: attentionView() || collectionId() ? '' : filterLocation(), sender: filterSender().trim(), recipient: filterRecipient().trim(),
      filename: (libraryView() ? query() : filterFilename()).trim(), after: filterAfter(), before: filterBefore(),
      status: filterStatus(), flagged: filterFlagged(), attachments: filterAttachments(),
    })
    page.set(1)
    activeQuery.set(query().trim())
    clearSelection()
    closeReader()
    await loadMessages()
  }
  async function clearSearch(): Promise<void> {
    cancelBatch()
    resetSearch()
    clearSelection()
    await loadMessages()
  }
  async function changeConversationView(): Promise<void> { cancelBatch(); clearSelection(); expandedThreads.set([]); page.set(1); await loadMessages() }
  async function turnPage(delta: number): Promise<void> { if (loading() || mutating()) return; page.update(value => Math.max(1, value + delta)); closeReader(); await loadMessages() }
  function toggleThread(id: string): void { expandedThreads.update(ids => ids.includes(id) ? ids.filter(value => value !== id) : [...ids, id]) }
  function toggleSelection(message: MessageSummary, event?: MouseEvent): void {
    event?.stopPropagation()
    const wanted = !checkedKeys().includes(messageIdentity(message))
    const rows = event?.shiftKey ? rangeSelection(visibleMessages(), selectionAnchor, message, messageIdentity) : [message]
    const result = new Map(checked().map(ref => [messageIdentity(ref), ref]))
    for (const row of rows) { if (wanted) result.set(messageIdentity(row), messageRef(row)); else result.delete(messageIdentity(row)) }
    if (result.size > 100) {
      event?.preventDefault()
      notice.set('Select up to 100 messages at a time.')
      return
    }
    checked.set([...result.values()])
    selectionAnchor = messageIdentity(message)
  }
  function toggleAll(): void {
    if (allChecked()) {
      const pageKeys = new Set(visibleMessages().map(messageIdentity))
      checked.update(items => items.filter(item => !pageKeys.has(messageIdentity(item))))
      selectionAnchor = null
      return
    }
    const result = new Map(checked().map(ref => [messageIdentity(ref), ref]))
    for (const message of visibleMessages()) { if (result.size >= 100) break; result.set(messageIdentity(message), messageRef(message)) }
    checked.set([...result.values()])
    if (visibleMessages().length > 100) notice.set('Selected the first 100 matching messages. Process these before selecting more.')
  }
  function toggleThreadSelection(thread: Conversation, event: MouseEvent): void {
    event.stopPropagation()
    const members = thread.members.filter(message => message.matches_filters !== false)
    const wanted = !members.every(message => checkedKeys().includes(messageIdentity(message)))
    const result = new Map(checked().map(ref => [messageIdentity(ref), ref]))
    for (const message of members) { if (wanted) result.set(messageIdentity(message), messageRef(message)); else result.delete(messageIdentity(message)) }
    if (result.size > 100) {
      event.preventDefault()
      notice.set('This conversation exceeds the selection limit. Expand it and select up to 100 messages.')
      return
    }
    checked.set([...result.values()])
    selectionAnchor = messageIdentity(thread.latest)
  }
  function threadChecked(thread: Conversation): boolean { return thread.members.filter(message => message.matches_filters !== false).every(message => checkedKeys().includes(messageIdentity(message))) }
  function threadPartial(thread: Conversation): boolean { return !threadChecked(thread) && thread.members.some(message => checkedKeys().includes(messageIdentity(message))) }
  function focusReader(request: number): void {
    ports.nextTick(() => {
      if (request !== messageRequest || !reading()) return
      const reader = ports.messageReader.current
      if (!reader) return
      reader.scrollTop = 0
      reader.querySelector<HTMLElement>('[data-reader-focus]')?.focus({ preventScroll: true })
    })
  }
  function updateOwnSelection(before: MessageRef, after: MessageRef): void {
    const key = messageIdentity(before)
    checked.update(items => items.map(item => messageIdentity(item) === key && item.revision === before.revision ? messageRef(after) : item))
  }
  async function openMessage(message: MessageRef & { personal_subject?: string }, autoRead = true, skipSeen = false, skipMissing = false, requireRevision = false): Promise<OpenResult> {
    if (mutating()) return 'cancelled'
    const request = ++messageRequest
    invitationCalendar.set(null)
    privateMail.closePrivate()
    const viewport = !reading() ? captureListViewport(ports.messageList.current) : null
    readerTarget.set(message)
    retryReading = null
    readerError.set('')
    rsvpError.set(null)
    readingLoading.set(true)
    try {
      if (requireRevision && (!message.reference || !message.revision)) throw new Error('Refresh the attachment list and open the message again.')
      const detail = await api<MessageDetail>(messagePath(message), requireRevision ? { headers: { 'If-Match': message.revision! } } : undefined)
      detail.folder ||= message.folder
      detail.personal_subject = message.personal_subject
      if (destroyed || request !== messageRequest) return 'cancelled'
      if (skipSeen && detail.flags.seen) return 'seen'
      if (viewport) readingViewport = viewport
      batch(() => {
        reading.set(true)
        selected.set(detail)
        showHtml.set(true)
        newsletterExpanded.set(true)
        receiptFull.set(false)
        remoteImagesAllowed.set(false)
        attentionSchedule.set(null)
        categoryRule.set(detail.placement?.rule || 'automatic')
      })
      focusReader(request)
      if (autoRead && detail.folder !== 'Drafts' && !detail.flags.seen) {
        await markOpenedMessageRead(detail, request)
        if (request === messageRequest) void refresh(true)
      }
      return 'opened'
    }
    catch (cause) {
      if (destroyed || request !== messageRequest) return 'cancelled'
      if (skipMissing && cause instanceof MailApiError && cause.status === 404) return 'missing'
      if (viewport) readingViewport = viewport
      readerError.set(errorMessage(cause))
      reading.set(true)
      focusReader(request)
      return 'failed'
    }
    finally { if (request === messageRequest) readingLoading.set(false) }
  }
  async function markOpenedMessageRead(detail: MessageDetail, request: number): Promise<void> {
    let current = detail
    for (let attempt = 0; attempt < 2 && !current.flags.seen && request === messageRequest; attempt++) {
      try {
        const result = await api<MessageRef>(messagePath(current), {
          method: 'PUT',
          headers: current.revision ? { 'If-Match': current.revision } : undefined,
          body: JSON.stringify({ flags: { ...current.flags, seen: true } }),
        })
        const updated = { ...current, ...result, flags: { ...current.flags, seen: true } }
        updateOwnSelection(current, updated)
        if (request === messageRequest) selected.set(updated)
        return
      }
      catch (cause) {
        if (!(cause instanceof MailApiError) || cause.status !== 412 || attempt > 0) throw cause
        current = await api<MessageDetail>(messagePath(current))
        if (request === messageRequest) selected.set(current)
      }
    }
  }
  async function openListMessage(message: MessageRef): Promise<void> {
    cancelBatch()
    followUpFocused.set(false)
    await openMessage(message)
  }
  async function retryReader(): Promise<void> {
    if (retryReading) { await retryReading(); return }
    const target = readerTarget()
    if (target) await openMessage(target, !senderReview.senderReviewOpen(), false, false, libraryView())
  }
  async function runTriage(work: (request: number) => Promise<void>): Promise<void> {
    if (loading() || readingLoading() || mutating() || triageBusy() || authExpired()) return
    const request = ++triageRequest
    triageBusy.set(true)
    readerError.set('')
    error.set('')
    try { await work(request) }
    catch (cause) {
      if (request === triageRequest) error.set(errorMessage(cause))
    }
    finally {
      if (request === triageRequest) triageBusy.set(false)
    }
  }
  async function nextUnread(start = selected()): Promise<void> {
    if (!unreadAvailable()) return
    await runTriage(async (request) => {
      const params = listParams()
      params.set('queue', 'unread')
      let previous: ReadingPosition | null = start
      const attempted = new Set<string>()
      for (let attempt = 0; attempt < 10; attempt++) {
        if (previous && Number.isFinite(previous.timestamp)) {
          params.set('cursor_time', String(previous.timestamp))
          params.set('cursor_folder', previous.folder)
          params.set('cursor_uid', String(previous.uid))
        }
        const listing = await api<MessagePage>(`/webmail/api/messages?${params}`)
        if (destroyed || request !== triageRequest) return
        const next = listing.items[0]
        if (!next || attempted.has(messageIdentity(next))) {
          notice.set('No unread messages match this view.')
          return
        }
        attempted.add(messageIdentity(next))
        previous = next
        const result = await openMessage(next, true, true, true)
        if (request !== triageRequest || result === 'cancelled') return
        if (result === 'opened') {
          const current = readingBatch()
          readingBatch.set({ kind: 'unread', read: (current?.kind === 'unread' ? current.read : 0) + 1 })
          return
        }
        if (result === 'failed') {
          retryReading = () => nextUnread(start)
          return
        }
      }
      notice.set('Unread messages changed while loading. Try Next unread again.')
    })
  }
  async function readSelection(): Promise<void> {
    const items = new Map(checked().map(item => [messageIdentity(item), item]))
    if (!items.size) return
    const ordered: MessageRef[] = []
    for (const message of visibleMessages()) {
      const key = messageIdentity(message)
      const item = items.get(key)
      if (item) {
        ordered.push(item)
        items.delete(key)
      }
    }
    ordered.push(...items.values())
    await openSelectedBatch({ kind: 'selected', items: ordered, index: -1 }, 1)
  }
  async function openSelectedBatch(mode: Extract<ReadingBatch, { kind: 'selected' }>, delta: number): Promise<void> {
    await runTriage(async (request) => {
      for (let index = mode.index + delta; index >= 0 && index < mode.items.length; index += delta) {
        const result = await openMessage(mode.items[index], true, false, true)
        if (request !== triageRequest || result === 'cancelled') return
        if (result === 'failed') {
          retryReading = () => openSelectedBatch(mode, delta)
          return
        }
        if (result === 'opened') {
          readingBatch.set({ ...mode, index })
          return
        }
      }
      notice.set(delta > 0 ? 'You’ve reached the end of this batch.' : 'You’re at the beginning of this batch.')
    })
  }
  async function advanceBatch(delta = 1): Promise<void> {
    const mode = readingBatch()
    if (mode?.kind === 'selected') await openSelectedBatch(mode, delta)
    else if (delta > 0 && mode?.kind === 'unread') await nextUnread()
  }
  async function changeAttention(kind: AttentionView, enabled: boolean, deadline = 0): Promise<void> {
    const item = selected()
    if (!item?.reference || !item.revision || attentionSaving() || readingLoading()) return
    const request = messageRequest
    attentionSaving.set(true)
    error.set('')
    try {
      const status = await api<AttentionStatus>('/webmail/api/attention', {
        method: 'PUT',
        headers: { 'If-Match': item.revision },
        body: JSON.stringify({ reference: item.reference, kind, enabled, deadline }),
      })
      if (request === messageRequest) {
        const current = selected()
        if (current) selected.set({ ...current, attention: status })
        attentionSchedule.set(null)
      }
      await refresh(true)
    }
    catch (cause) { if (request === messageRequest) error.set(errorMessage(cause)) }
    finally { attentionSaving.set(false) }
  }
  function startAttentionSchedule(kind: 'snoozed' | 'reminders'): void {
    attentionSchedule.set(kind)
    const current = kind === 'snoozed' ? selected()?.attention?.snooze_until : selected()?.attention?.remind_at
    const suggested = new Date(Date.now() + (kind === 'snoozed' ? 1 : 48) * 3_600_000)
    attentionDate.set(localDateInput(current && current * 1000 > Date.now() ? new Date(current * 1000) : suggested))
  }
  async function saveAttentionSchedule(): Promise<void> {
    const kind = attentionSchedule()
    if (!kind) return
    try { await changeAttention(kind, true, localDeadline(attentionDate())) }
    catch (cause) { error.set(errorMessage(cause)) }
  }
  async function saveCategoryRule(): Promise<void> {
    const item = selected()
    if (!item?.reference || !item.revision || !item.placement?.verified_author || readingLoading() || categoryRuleSaving()) return
    const request = messageRequest
    categoryRuleSaving.set(true)
    error.set('')
    try {
      const result = await api<{ destination: CategoryRule }>('/webmail/api/category-rule', {
        method: 'PUT',
        headers: { 'If-Match': item.revision },
        body: JSON.stringify({ reference: item.reference, destination: categoryRule() }),
      })
      if (request === messageRequest) {
        const latest = selected()
        if (latest?.placement) selected.set({ ...latest, placement: { ...latest.placement, rule: result.destination } })
        notice.set(result.destination === 'automatic' ? 'Sender rule cleared for future mail.' : 'Sender rule saved for future mail.')
      }
    }
    catch (cause) { if (request === messageRequest) error.set(errorMessage(cause)) }
    finally { categoryRuleSaving.set(false) }
  }
  async function loadSortingSettings(): Promise<void> {
    sortingError.set('')
    sortingSettings.set(null)
    try { sortingSettings.set(await api<CategorySettings>(categorySettingsPath)) }
    catch (cause) { sortingError.set(errorMessage(cause)) }
  }
  async function toggleAutomaticSorting(): Promise<void> {
    const current = sortingSettings()
    if (!current || sortingSaving()) return
    sortingSaving.set(true)
    sortingError.set('')
    try {
      sortingSettings.set(await api<CategorySettings>(categorySettingsPath, {
        method: 'PUT',
        body: JSON.stringify({ automatic: !current.automatic }),
      }))
    }
    catch (cause) { sortingError.set(errorMessage(cause)) }
    finally { sortingSaving.set(false) }
  }
  async function showSenderReview(view: ReviewView = 'pending', page = 1): Promise<void> {
    if (mutating() || senderReview.senderReviewSaving()) return
    closeReader()
    invalidateList()
    clearSelection()
    outboxView.set(false)
    attentionView.set(null)
    libraryView.set(false)
    collectionId.set(null)
    senderReview.senderReviewOpen.set(true)
    await senderReview.loadSenderReview(view, page)
  }

  async function openAttachmentMessage(file: LibraryAttachment): Promise<void> {
    await openMessage(file.message, true, false, false, true)
  }

  async function openReviewMessage(item: ReviewItem): Promise<void> {
    senderReview.senderReviewSelection.set(item)
    await openMessage(item, false)
  }

  async function reviewMessage(action: ReviewAction, reply = false): Promise<void> {
    const item = senderReview.senderReviewSelection()
    if (!item || item.applying || readingLoading() || senderReview.senderReviewSaving()) return
    if (!await senderReview.decideSenderReview(action, item)) return
    const applying = senderReview.senderReviewGroups().some(group => group.messages.some(message => message.reference === item.reference && message.applying))
    closeReader()
    await loadFolders().catch(cause => error.set(errorMessage(cause)))
    if (reply) {
      await openMessage(item, false)
      if (selected()?.reference === item.reference) await compose('reply')
      closeReader()
    }
    const sender = item.verified && action !== 'recover'
    notice.set(applying ? 'Decision saved. Moving mail…' : action === 'decline' ? (sender ? 'Sender declined.' : 'Message declined.') : action === 'recover' ? 'Message recovered.' : sender ? 'Sender allowed.' : 'Message allowed.')
  }
  function showConfirmation(action: string, refs: MessageRef[] = []): void {
    confirmationRefs = refs
    confirmation.set(action)
    ports.nextTick(() => { if (!ports.confirmation.current?.open) ports.confirmation.current?.showModal() })
  }
  function actionNotice(action: BulkAction, count: number, destination: string): string {
    const label = count === 1 ? 'Message' : `${count} messages`
    if (action === 'junk') return `${label} moved to ${folderName(limits().junkFolder || 'Junk')}.`
    if (action === 'not_junk') return count === 1 ? 'Message recovered.' : `${label} recovered.`
    return action === 'move' ? `${label} moved to ${folderName(destination)}.` : action === 'trash' ? `${label} moved to Trash.` : action === 'read' ? `${label} marked read.` : action === 'unread' ? `${label} marked unread.` : action === 'flag' ? `${label} flagged.` : action === 'unflag' ? `${label} unflagged.` : `${label} permanently deleted.`
  }
  async function performBulk(action: BulkAction, refs: MessageRef[], destination = moveTo(), confirmed = false, keepReader = false): Promise<boolean> {
    if (mutating() || readingLoading() || !refs.length) return false
    if (refs.some(ref => ref.reference === null || ref.revision === null)) {
      await refresh(true)
      error.set('A message changed while the list was loading. Review the messages and select them again.')
      return false
    }
    if (action === 'purge' && !confirmed) { showConfirmation('purge', refs); return false }
    mutating.set(true); error.set('')
    try {
      const result = await api<BulkResult>('/webmail/api/bulk', { method: 'POST', body: JSON.stringify({ action, messages: refs, folder: destination }) })
      const succeeded = result.results.filter(item => item.ok)
      const failed = result.results.filter(item => !item.ok)
      const completed = new Set(refs.filter(ref => succeeded.some(item => messageKey(item) === messageKey(ref))).map(messageIdentity))
      checked.update(items => items.filter(item => !completed.has(messageIdentity(item))))
      if (result.undoId && result.expiresAt) undoAction.set({ id: result.undoId, expiresAt: result.expiresAt })
      if (succeeded.length) notice.set(actionNotice(action, succeeded.length, destination))
      if (failed.length) error.set(`${failed.length} ${failed.length === 1 ? 'message could' : 'messages could'} not be changed.`)
      const current = selected()
      if (current && completed.has(messageIdentity(current))) {
        if (['move', 'trash', 'purge', 'junk', 'not_junk'].includes(action)) {
          if (keepReader) selected.set(null)
          else closeReader(true)
        }
        else {
          const updated = await api<MessageDetail>(messagePath(current))
          if (selected() === current) selected.set({ ...updated, folder: updated.folder || current.folder })
        }
      }
      await refresh(true)
      return result.ok && succeeded.length > 0
    }
    catch (cause) {
      if (cause instanceof MailApiError && cause.status === 412) {
        await refresh(true)
        error.set('A message changed after you selected it. Review the current messages and reselect before trying again.')
      }
      else error.set(errorMessage(cause))
      return false
    }
    finally { mutating.set(false) }
  }
  async function bulkAction(action: BulkAction, destination?: string): Promise<void> { await performBulk(action, checked(), destination) }
  async function selectedAction(action: BulkAction, destination?: string): Promise<void> {
    const item = selected()
    if (item) await performBulk(action, [messageRef(item)], destination)
  }
  async function triageAndNext(action: 'archive' | 'trash'): Promise<void> {
    const current = selected()
    const mode = readingBatch()
    if (!current || !mode || triageBusy()) return
    const request = triageRequest
    const moved = await performBulk(action === 'archive' ? 'move' : 'trash', [messageRef(current)], 'Archive', false, true)
    if (!moved || request !== triageRequest) return
    if (mode.kind === 'unread') await nextUnread(current)
    else await openSelectedBatch(mode, 1)
    if (!selected() && !readerError()) closeReader(true)
  }
  async function groupSelected(): Promise<void> {
    const rows = checked()
    if (rows.length < 2 || mutating() || readingLoading()) return
    if (rows.some(item => !item.reference || !item.revision || item.folder === 'Drafts')) {
      error.set('Choose at least two saved messages to group.')
      return
    }
    mutating.set(true)
    error.set('')
    try {
      const messages = rows.map(item => ({ reference: item.reference, revision: item.revision }))
      const result = await api<{ undoId: string, expiresAt: number }>('/webmail/api/private/group', { method: 'POST', body: JSON.stringify({ messages }) })
      undoAction.set({ id: result.undoId, expiresAt: result.expiresAt, kind: 'group' })
      notice.set('Messages grouped.')
      conversations.set(true)
      expandedThreads.set([])
      clearSelection()
      closeReader()
      await loadMessages()
    }
    catch (cause) { error.set(errorMessage(cause)) }
    finally { mutating.set(false) }
  }
  async function undoLastAction(): Promise<void> {
    const receipt = undoAction()
    if (!receipt || undoRemaining() <= 0 || mutating() || readingLoading() || triageBusy()) return
    mutating.set(true)
    try {
      if (receipt.kind === 'group') {
        await api('/webmail/api/private/undo-group', { method: 'POST', body: JSON.stringify({ id: receipt.id }) })
        undoAction.set(null)
        notice.set('Grouping undone.')
        expandedThreads.set([])
        closeReader()
        await loadMessages()
        return
      }
      const result = await api<BulkResult>(`/webmail/api/undo/${receipt.id}`, { method: 'POST', body: '{}' })
      undoAction.set(null)
      notice.set(result.ok ? 'Action undone.' : 'Some messages changed since that action and could not be restored.')
      const current = selected()
      if (current && result.results.some(item => item.ok && (messageKey(item) === messageKey(current) || (item.new_uid === current.uid && item.new_folder === current.folder)))) {
        const updated = await api<MessageDetail>(messagePath(current))
        if (selected() === current) {
          selected.set(updated)
          updateOwnSelection(current, updated)
        }
      }
      await refresh(true)
    }
    catch (cause) { error.set(errorMessage(cause)); undoAction.set(null) }
    finally { mutating.set(false) }
  }
  function showShortcuts(): void {
    if (shortcutsOpen() || composing() || settings() || confirmation()) return
    shortcutsTrigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
    shortcutsOpen.set(true)
    ports.nextTick(() => { if (shortcutsOpen() && !ports.shortcutsDialog.current?.open) ports.shortcutsDialog.current?.showModal() })
  }
  function closeShortcuts(): void {
    shortcutsOpen.set(false)
    const trigger = shortcutsTrigger
    shortcutsTrigger = null
    ports.nextTick(() => { if (trigger?.isConnected) trigger.focus({ preventScroll: true }) })
  }
  function handleShortcut(event: KeyboardEvent): void {
    if (!isShortcutEvent(event) || !user() || authExpired() || composing() || settings() || confirmation() || shortcutsOpen() || privateMail.collectionsOpen() || contactBook.contactsOpen()) return
    if (event.key === '?') {
      event.preventDefault()
      showShortcuts()
      return
    }
    if (outboxView() || senderReview.senderReviewOpen()) return
    if (event.key === 'Escape' && reading() && !mutating()) {
      event.preventDefault()
      closeReader(true)
      return
    }
    if (!event.shiftKey || mutating() || triageBusy() || readingLoading() || loading()) return
    const current = selected()
    const key = event.key.toLowerCase()
    if (key === 'n' && unreadAvailable()) {
      event.preventDefault()
      void nextUnread()
    }
    else if (key === 'j' && readingBatch()) {
      event.preventDefault()
      void advanceBatch()
    }
    else if (key === 'x' && current) {
      event.preventDefault()
      toggleSelection(current)
    }
    else if (key === 'e' && (checked().length || current)) {
      event.preventDefault()
      const selection = checked()
      if (selection.length) void bulkAction('move', 'Archive')
      else if (readingBatch()) void triageAndNext('archive')
      else if (current) void performBulk('move', [messageRef(current)], 'Archive')
    }
    else if (key === 'u' && undoAction()) {
      event.preventDefault()
      void undoLastAction()
    }
  }

  function resetComposition(): void {
    batch(() => {
      composing.set(false)
      fileSharing.clearFileLinkComposer()
      sharedReply.set(null)
      senderId.set('')
      reviewedExternalSend.set(null)
      senderError.set('')
      subject.set(''); body.set(''); draftHtml.set(''); initialText.set(''); inReplyTo.set(''); references.set(''); replyContext.set(null); clearFollowUp.set(false); composeError.set(''); showCc.set(false); showBcc.set(false)
      recipientEditor.restore({ to: [], cc: [], bcc: [] }, { to: '', cc: '', bcc: '' })
      attachmentEditor.restore([])
      scheduleOpen.set(false); scheduleDate.set('')
      automaticSignature.set('')
      snippetChoice.set('')
      signatureChoice.set('')
      if (!destroyed) draft.restore(null, content())
      lastQueuedPayload = null
      sendUncertain.set(false)
    })
  }
  function showComposer(): void {
    void loadSenderIdentities()
    composing.set(true)
    ports.nextTick(() => { if (!ports.composer.current?.open) ports.composer.current?.showModal() })
  }
  async function closeComposer(): Promise<void> {
    if (sending() || sendUncertain() || fileSharing.fileLinkUploading()) return
    try { if (draft.saving()) await draft.flush(); if (hasComposition()) await draft.flushAll(); composing.set(false); if (selected()?.folder === 'Drafts') closeReader(); await refresh(true) }
    catch (cause) { composeError.set(`Keep this window open: ${errorMessage(cause)}`) }
  }
  async function compose(mode = 'new'): Promise<void> {
    if (mode === 'new' && hasComposition()) { showComposer(); return }
    try { if (hasComposition()) await draft.flushAll() }
    catch (cause) { composeError.set(errorMessage(cause)); showComposer(); return }
    const original = selected()
    await writing.loadWritingLibrary()
    if (destroyed || !user() || authExpired()) return
    if (mode === 'new' && composing()) return
    resetComposition()
    if (mode !== 'new' && original) {
      const own = user()?.email.toLowerCase()
      const sender = recipients(original.reply_to || original.from).filter(item => item.address.toLowerCase() !== own)
      const to = recipients(original.to).filter(item => item.address.toLowerCase() !== own)
      const cc = recipients(original.cc || '').filter(item => item.address.toLowerCase() !== own)
      const replyingToSent = original.folder === 'Sent' || recipients(original.from).some(item => item.address.toLowerCase() === own)
      const targets = mode === 'forward' ? [] : mode === 'all' ? [...sender, ...to] : replyingToSent && !original.reply_to ? to : sender
      recipientEditor.restore({ to: targets.map(item => item.raw), cc: mode === 'all' ? cc.map(item => item.raw) : [], bcc: [] }, { to: '', cc: '', bcc: '' })
      subject.set(`${mode === 'forward' ? 'Fwd: ' : /^re:/i.test(original.subject) ? '' : 'Re: '}${original.subject}`)
      title.set(mode === 'forward' ? 'Forward' : mode === 'all' ? 'Reply all' : 'Reply')
      body.set(`\n\nOn ${original.date}, ${original.from} wrote:\n${(original.text || '').split('\n').map(line => `> ${line}`).join('\n')}`)
      if (mode !== 'forward') {
        inReplyTo.set(original.message_id)
        references.set(`${original.references || ''} ${original.message_id}`.trim())
        replyContext.set(messageRef(original))
        clearFollowUp.set(followUpFocused() && !!original.attention?.follow_up)
      }
      showCc.set(mode === 'all' && cc.length > 0)
      if (mode === 'forward') void importAttachments(original)
    }
    else title.set('New message')
    applyDefaultSignature()
    showComposer()
  }
  function applyDefaultSignature(): void {
    const library = writing.writingLibrary()
    const signature = library?.signatures.find(entry => entry.id === library.defaultSignatureId)
    if (signature) {
      const block = separatorSignature(signature.text)
      if (!body()) automaticSignature.set(block)
      body.set(block + body())
    }
  }
  function composeBody(): HTMLTextAreaElement | null {
    return ports.composer.current?.querySelector<HTMLTextAreaElement>('.wm-composer-body') ?? null
  }
  function focusComposeBody(position: number): void {
    ports.nextTick(() => {
      const editor = composeBody()
      editor?.focus()
      editor?.setSelectionRange(position, position)
    })
  }
  function insertSnippet(): void {
    const snippet = writing.writingLibrary()?.snippets.find(entry => entry.id === snippetChoice())
    if (!snippet || sending() || sendUncertain()) return
    const editor = composeBody()
    const start = editor?.selectionStart ?? body().length
    const end = editor?.selectionEnd ?? start
    const text = snippet.text.replace(/\r\n?/g, '\n')
    body.set(body().slice(0, start) + text + body().slice(end))
    snippetChoice.set('')
    focusComposeBody(start + text.length)
  }
  function insertSignature(): void {
    const signature = writing.writingLibrary()?.signatures.find(entry => entry.id === signatureChoice())
    if (!signature || sending() || sendUncertain()) return
    const block = separatorSignature(signature.text)
    const current = body()
    if (!current.endsWith(block) && !current.includes(block + '\n')) body.set(current + block)
    signatureChoice.set('')
    focusComposeBody(body().length)
  }
  function separatorSignature(text: string): string { return '\n\n-- \n' + text.replace(/\r\n?/g, '\n') }
  async function importAttachments(message: MessageDetail): Promise<void> {
    try {
      await attachmentEditor.addRemoteFiles(message.attachments.map((item, index) => ({
        filename: item.filename, contentType: item.content_type, size: item.size,
        read: async (signal: AbortSignal) => {
          const response = await fetch(attachmentPath(index, message), { credentials: 'same-origin', cache: 'no-store', signal })
          if (!response.ok) throw new Error('Could not load an attachment from this message. Retry it or remove it to send without it.')
          return new File([await response.arrayBuffer()], item.filename, { type: item.content_type })
        },
      })))
    }
    catch (cause) { composeError.set(errorMessage(cause)) }
  }
  function installPayload(payload: ComposePayload, document: DraftDocument | null, metadata: MessageDetail | null = null): void {
    resetComposition()
    batch(() => {
      sharedReply.set(payload.sharedReply ?? null)
      senderId.set(payload.senderId ?? '')
      recipientEditor.restore({ to: payload.to, cc: payload.cc, bcc: payload.bcc }, payload.recipientInputs || { to: '', cc: '', bcc: '' }, payload.recipientLabels)
      subject.set(payload.subject); body.set(payload.text); initialText.set(payload.text); draftHtml.set(payload.html); inReplyTo.set(payload.inReplyTo); references.set(payload.references); replyContext.set(payload.replyContext)
      clearFollowUp.set(!!payload.clearFollowUp)
      const sendTime = payload.scheduleAt ? new Date(payload.scheduleAt * 1000) : null
      if (sendTime && Number.isFinite(sendTime.getTime())) {
        scheduleOpen.set(true)
        scheduleDate.set(localDateInput(sendTime))
      }
      showCc.set(Boolean(payload.cc.length || payload.recipientInputs?.cc)); showBcc.set(Boolean(payload.bcc.length || payload.recipientInputs?.bcc))
      attachmentEditor.restore(payload.attachments.filter(item => item.uploadId).map((item, index) => ({ key: crypto.randomUUID(), uploadId: item.uploadId, filename: item.filename, contentType: item.contentType, size: metadata?.attachments[index]?.size ?? item.size ?? 0, progress: 100, status: 'ready' as const })))
      draft.restore(document, content())
      title.set(payload.sharedReply ? 'Shared inbox reply' : 'Edit draft')
    })
    showComposer()
  }
  async function editDraft(): Promise<void> {
    const message = selected()
    if (!message || message.folder !== 'Drafts') return
    if (hasComposition()) { try { await draft.flushAll() } catch (cause) { composeError.set(errorMessage(cause)); showComposer(); return } }
    try {
      const document = await api<DraftDocument>(`/webmail/api/drafts?uid=${message.uid}`)
      if (document.state !== 'saved') throw new Error('This draft is queued for sending. Undo Send from Outbox before editing it.')
      installPayload(document.message, document, message)
    }
    catch (cause) {
      if (cause instanceof MailApiError && cause.status === 404) {
        const payload: ComposePayload = { to: recipients(message.to).map(item => item.raw), cc: recipients(message.cc).map(item => item.raw), bcc: recipients(message.bcc).map(item => item.raw), subject: message.subject, text: message.text, html: message.html, inReplyTo: message.in_reply_to, references: message.references, draftId: null, draftUid: message.uid, draftRevision: 0, saveToken: '', recipientInputs: { to: '', cc: '', bcc: '' }, attachments: [], replyContext: null }
        installPayload(payload, null, message)
        draft.uid.set(message.uid)
        await importAttachments(message)
      }
      else error.set(errorMessage(cause))
    }
  }
  async function saveDraft(): Promise<void> {
    if (fileSharing.fileLinkUploading()) return
    composeError.set('')
    try { if (!hasComposition()) throw new Error('Write something before saving a draft.'); await draft.flushAll(); await refresh(true) }
    catch (cause) { composeError.set(errorMessage(cause)) }
  }
  async function insertFileLink(): Promise<void> {
    if (!composing() || sending() || sendUncertain()) return
    const link = await fileSharing.uploadFileLink()
    if (link && composing() && !destroyed) body.update(current => current ? `${current}\n\n${link}\n` : `${link}\n`)
  }
  async function reloadSavedDraft(): Promise<void> {
    if (!draft.uid()) return
    const document = await api<DraftDocument>(`/webmail/api/drafts?uid=${draft.uid()}`)
    const message = await api<MessageDetail>(messagePath({ uid: document.uid, folder: 'Drafts' }))
    installPayload(document.message, document, message)
  }
  async function attachFiles(): Promise<void> {
    const input = ports.fileInput.current
    if (!input?.files) return
    composeError.set('')
    try { await attachmentEditor.addFiles(input.files) }
    catch (cause) { composeError.set(errorMessage(cause)) }
    finally { input.value = '' }
  }
  async function dropAttachments(event: DragEvent): Promise<void> {
    if (sending()) return
    composeError.set('')
    try { await attachmentEditor.dropAttachments(event) }
    catch (cause) { composeError.set(errorMessage(cause)) }
  }
  async function saveSendPreference(): Promise<void> {
    try { await api('/webmail/api/preferences', { method: 'PUT', body: JSON.stringify({ undoSendSeconds: sendDelay() }) }) }
    catch (cause) { composeError.set(errorMessage(cause)) }
  }
  function closeQueuedDraft(payload: ComposePayload): void {
    const message = selected()
    if (message?.folder === 'Drafts' && message.uid === payload.draftUid) closeReader()
  }
  function chooseSendTime(): void {
    scheduleDate.set(localDateInput(new Date(now() * 1000 + 3_600_000)))
    scheduleOpen.set(true)
    ports.nextTick(() => ports.composer.current?.querySelector<HTMLInputElement>('#composeSendTime')?.focus())
  }
  async function send(): Promise<void> {
    if (sending() || sendUncertain() || attachmentEditor.attachmentPending() || fileSharing.fileLinkUploading()) return
    composeError.set('')
    senderError.set('')
    recipientEditor.commitAll()
    const values = [...recipientEditor.toRecipients(), ...recipientEditor.ccRecipients(), ...recipientEditor.bccRecipients()]
    const invalid = values.find(item => !item.valid)
    if (invalid) { composeError.set(`Check this email address: ${invalid.raw}`); return }
    if (!values.length || values.length > 100) { composeError.set(values.length ? 'Use at most 100 recipients.' : 'Add at least one recipient.'); return }
    if (new TextEncoder().encode(body()).length > 256 * 1024) { composeError.set('Keep the message body under 256 KiB.'); return }
    const scheduleAt = selectedSchedule()
    if (scheduleOpen() && (scheduleAt == null || scheduleAt <= now() || scheduleAt > now() + 365 * 86400)) {
      composeError.set('Choose a valid local send time in the next 365 days.')
      return
    }
    sending.set(true)
    try {
      const review = externalSendReview()
      if (externalSender() && !review && !lastQueuedPayload) {
        const { to, cc, bcc } = recipientEditor.snapshot()
        const id = senderId()
        const result = await api<ExternalSendReview>('/webmail/api/external-sender-review', {
          method: 'POST', body: JSON.stringify({ senderId: id, to, cc, bcc }),
        })
        reviewedExternalSend.set({ ...result, senderId: id })
        ports.nextTick(() => {
          const panel = ports.composer.current?.querySelector<HTMLElement>('#composeExternalReview')
          panel?.focus({ preventScroll: true })
          panel?.scrollIntoView({ block: 'center' })
        })
        return
      }
      await draft.flushAll()
      const payload = lastQueuedPayload ?? { ...content(), draftId: draft.id(), draftUid: draft.uid(), draftRevision: draft.revision(), saveToken: '', sendId: crypto.randomUUID(), ...(review ? { externalReview: review.token } : {}), ...(scheduleAt == null ? { delaySeconds: sendDelay() } : { scheduleAt }) }
      lastQueuedPayload = payload
      let queued: OutboxItem
      try { queued = await api<OutboxItem>('/webmail/api/compose', { method: 'POST', body: JSON.stringify(payload) }) }
      catch (cause) {
        // A lost POST response must never cause a duplicate send.
        if (cause instanceof MailApiError) throw cause
        try { queued = await api<OutboxItem>(`/webmail/api/outbox/${payload.sendId}`) }
        catch { sendUncertain.set(true); throw new Error('Could not confirm the send. Check its status before editing or retrying.') }
      }
      pendingSend.set(queued)
      closeQueuedDraft(payload)
      clockOffset = queued.serverTime - Date.now() / 1000
      now.set(Date.now() / 1000 + clockOffset)
      notice.set(queued.scheduled ? 'Message scheduled for ' + deadlineLabel(queued.dueAt) + '.' : queued.state === 'pending' && queued.dueAt > queued.serverTime ? `Message queued. Undo Send is available for ${queued.dueAt - queued.serverTime} seconds.` : 'Message queued for delivery.')
      resetComposition()
      await refreshOutbox(true)
      await refresh(true)
    }
    catch (cause) {
      if (cause instanceof MailApiError && cause.status < 500) lastQueuedPayload = null
      else if (lastQueuedPayload) sendUncertain.set(true)
      if (cause instanceof MailApiError && cause.code === 'external_review_required') reviewedExternalSend.set(null)
      if (cause instanceof MailApiError && ['sender_identity_unavailable', 'external_sender_unavailable'].includes(cause.code)) {
        reviewedExternalSend.set(null)
        senderError.set(errorMessage(cause))
        void loadSenderIdentities()
      }
      else composeError.set(errorMessage(cause))
    }
    finally { sending.set(false) }
  }
  function cancelExternalReview(): void {
    reviewedExternalSend.set(null)
    ports.nextTick(() => ports.composer.current?.querySelector<HTMLInputElement>('#recipient-to')?.focus())
  }
  async function confirmPendingSend(): Promise<void> {
    const payload = lastQueuedPayload
    if (!payload || sending()) return
    sending.set(true)
    try {
      let item: OutboxItem
      try { item = await api<OutboxItem>(`/webmail/api/outbox/${payload.sendId}`) }
      catch (cause) {
        if (!(cause instanceof MailApiError) || cause.status !== 404) throw cause
        // Reuse the original identifier and frozen payload: even if the first
        // request arrives late, the server accepts only one queued message.
        item = await api<OutboxItem>('/webmail/api/compose', { method: 'POST', body: JSON.stringify(payload) })
      }
      pendingSend.set(item)
      closeQueuedDraft(payload)
      resetComposition()
      notice.set('Send status confirmed. Check Outbox for its delivery result.')
      await refreshOutbox(true)
    }
    catch (cause) { composeError.set(errorMessage(cause)) }
    finally { sending.set(false) }
  }
  async function refreshOutbox(force = false): Promise<void> {
    if ((pollingOutbox && !force) || !user()) return
    const request = ++outboxRequest
    const view = outboxView() ? outboxSection() : 'overview'
    const after = view === 'overview' ? null : outboxCursors().at(-1)
    const params = new URLSearchParams({ view })
    if (after) params.set('after', after)
    const pending = pendingSend()
    const track = pending && !announcedSends.has(pending.id) ? pending.id : null
    if (track) params.set('track', track)
    pollingOutbox = true
    lastOutboxPoll = Date.now()
    try {
      const result = await api<OutboxPage>('/webmail/api/outbox?' + params)
      if (destroyed || request !== outboxRequest) return
      if (!result.counts || !Array.isArray(result.items)) throw new Error('Could not load Outbox status.')
      if (after && !result.items.length && outboxView()) {
        await openOutboxPage([null])
        return
      }
      outboxCounts.set(result.counts)
      clockOffset = result.serverTime - Date.now() / 1000
      if (view !== 'overview' && outboxView()) {
        outbox.set(result.items)
        outboxNext.set(result.nextCursor)
        outboxError.set('')
      }
      if (track && pendingSend()?.id === track) {
        const update = result.tracked
        pendingSend.set(update)
        if (update && !['pending', 'sending', 'cancelled'].includes(update.state)) {
          announcedSends.add(update.id)
          const failed = update.result?.failed.length || 0
          notice.set(update.state === 'sent' ? 'Message sent.' : update.state === 'sent_unfiled' ? 'Message delivered, but the Sent copy could not be saved. Do not resend.' : update.state === 'partial' ? `${update.result?.delivered} recipient(s) received the message. ${failed} did not; retry only those recipients from Outbox.` : update.state === 'unknown' ? 'Delivery was interrupted. Check Sent before retrying this message.' : update.error || 'Delivery failed. Open Outbox to review and retry.')
          await refresh(true)
        }
      }
    }
    catch (cause) {
      if (destroyed || request !== outboxRequest || !outboxView()) return
      if (after && cause instanceof MailApiError && cause.code === 'outbox_cursor_expired') {
        await openOutboxPage([null])
        return
      }
      outboxError.set(errorMessage(cause))
    }
    finally {
      if (request === outboxRequest) {
        pollingOutbox = false
        outboxLoading.set(false)
      }
    }
  }
  function openOutboxPage(cursors: (string | null)[]): Promise<void> {
    outboxLoading.set(true)
    outboxError.set('')
    outbox.set([])
    outboxNext.set(null)
    outboxCursors.set(cursors)
    return refreshOutbox(true)
  }
  function selectOutboxView(view: OutboxView): Promise<void> {
    outboxSection.set(view)
    error.set('')
    return openOutboxPage([null])
  }
  async function turnOutboxPage(next: boolean): Promise<void> {
    const cursors = outboxCursors()
    const cursor = outboxNext()
    if (outboxLoading() || (next ? !cursor : cursors.length < 2)) return
    await openOutboxPage(next ? [...cursors, cursor] : cursors.slice(0, -1))
  }
  async function showOutbox(): Promise<void> {
    senderReview.closeSenderReview()
    attentionView.set(null)
    libraryView.set(false)
    collectionId.set(null)
    outboxView.set(true)
    closeReader()
    invalidateList()
    clearSelection()
    const counts = outboxCounts()
    const firstView = counts.upcoming ? 'upcoming' : counts.review ? 'review' : counts.history ? 'history' : 'upcoming'
    await selectOutboxView(firstView)
  }
  async function cancelSend(id = pendingSend()?.id, edit = false): Promise<void> {
    if (!id || cancelling() || sending() || sendUncertain()) return
    cancelling.set(true)
    error.set('')
    try {
      if (edit && hasComposition()) await draft.flushAll()
      const cancelled = await api<OutboxItem>(`/webmail/api/outbox/${id}`, { method: 'DELETE' })
      if (pendingSend()?.id === id) pendingSend.set(null)
      outbox.set(outbox().filter(item => item.id !== id))
      notice.set('Send cancelled. Nothing was dispatched.')
      if (cancelled.scheduled && !edit) {
        await refreshOutbox(true)
        if (!outboxView()) await refresh(true)
        return
      }
      if (hasComposition()) await draft.flushAll()
      let document: DraftDocument | null = null
      let metadata: MessageDetail | null = null
      if (cancelled.message.draftUid) {
        try { document = await api<DraftDocument>(`/webmail/api/drafts?uid=${cancelled.message.draftUid}`); metadata = await api<MessageDetail>(messagePath({ uid: document.uid, folder: 'Drafts' })) }
        catch (cause) {
          if (cancelled.scheduled) throw cause
          document = null
        }
      }
      if (document && document.state !== 'saved') throw new Error('This draft is already queued. Refresh Outbox to see its status.')
      const payload = document?.message || cancelled.message
      installPayload(edit ? { ...payload, scheduleAt: cancelled.dueAt } : payload, document, metadata)
      if (edit) {
        title.set('Scheduled send paused')
        notice.set('Schedule paused. Save this draft or choose a new send time.')
      }
      await refreshOutbox(true)
    }
    catch (cause) { error.set(cause instanceof MailApiError && cause.status === 409 ? 'The cancellation window has closed. Check Outbox for the delivery result.' : errorMessage(cause)); await refreshOutbox(true) }
    finally { cancelling.set(false) }
  }
  function reviewUnknown(id: string): void { reviewedOutboxId = id; showConfirmation('retry-unknown') }
  async function retryOutbox(id: string, reviewed = false): Promise<void> {
    try {
      if (hasComposition()) await draft.flushAll()
      let item = await api<OutboxItem>(`/webmail/api/outbox/${id}`)
      if (item.calendarRsvp) throw new Error('Open the invitation to retry this RSVP.')
      if (!['failed', 'partial', 'cancelled', 'unknown'].includes(item.state)) throw new Error('This message is already queued or delivered.')
      if (item.scheduled && item.state === 'cancelled') throw new Error('This schedule was cancelled. Edit its saved draft to send it again.')
      if (item.state === 'unknown') {
        if (!reviewed) { reviewUnknown(id); return }
        item = await api<OutboxItem>(`/webmail/api/outbox/${id}`, { method: 'PATCH', body: JSON.stringify({ reviewed: true }) })
        void refreshOutbox(true)
      }
      if (item.message.draftUid) {
        try {
          const document = await api<DraftDocument>(`/webmail/api/drafts?uid=${item.message.draftUid}`)
          if (document.state === 'saved') {
            const metadata = await api<MessageDetail>(messagePath({ uid: document.uid, folder: 'Drafts' }))
            installPayload({ ...document.message, scheduleAt: null }, document, metadata)
            title.set('Review unsent recipients')
            return
          }
        }
        catch { /* The original draft may have been moved or deleted; keep a copy. */ }
      }
      const payload = { ...item.message, scheduleAt: null }
      if (item.result) {
        const retry = new Set([...item.result.failed, ...(item.result.unknown || [])].map(address => address.toLowerCase()))
        payload.to = payload.to.filter(address => retry.has(address.toLowerCase()))
        payload.cc = payload.cc.filter(address => retry.has(address.toLowerCase()))
        payload.bcc = payload.bcc.filter(address => retry.has(address.toLowerCase()))
        payload.recipientLabels = { to: [], cc: [], bcc: [] }
      }
      installPayload(payload, null)
      title.set('Review unsent recipients')
    }
    catch (cause) { error.set(errorMessage(cause)) }
  }
  async function leaveAccount(): Promise<void> {
    if (sending() || mutating() || leavingAccount()) return
    leavingAccount.set(true)
    accountChangeError.set('')
    try {
      if (hasComposition()) await draft.flushAll()
      await api('/webmail/auth/logout', { method: 'POST', body: '{}' })
      clearAccountState()
      ports.navigate('/login', { reload: true })
    }
    catch (cause) {
      const message = errorMessage(cause)
      if (settings()) accountChangeError.set(message)
      else error.set(message)
    }
    finally { leavingAccount.set(false) }
  }
  async function changeNotificationRule(scope: MailNotificationScope, event: Event): Promise<void> {
    const item = selected()
    const select = event.target instanceof HTMLSelectElement ? event.target : null
    const value = select?.value
    if (!item?.notifications || !select || readingLoading() || (value !== 'default' && value !== 'notify' && value !== 'quiet')) return
    const result = await notifications.saveNotificationRule(item, scope, value)
    const current = selected()
    if (current && current.reference === item.reference) {
      if (result) selected.set({ ...current, notifications: result })
      else select.value = item.notifications[scope]
    }
  }
  function showSettings(): void {
    settings.set(true)
    passwordError.set('')
    accountChangeError.set('')
    void recoverySettings.loadRecovery()
    void forwardingSettings.loadForwarding()
    void externalSenderSettings.loadExternalAddresses()
    void vacationSettings.loadVacationSettings()
    void writing.loadWritingLibrary(true)
    void loadSortingSettings()
    void notifications.loadNotificationSettings().catch(() => {})
    ports.nextTick(() => { if (!ports.password.current?.open) ports.password.current?.showModal() })
  }
  async function changePassword(): Promise<void> {
    if (savingPassword()) return
    passwordError.set('')
    if (newPassword() !== confirmPassword()) { passwordError.set('The new passwords do not match.'); return }
    if (newPassword().length < 12) { passwordError.set('Use at least 12 characters.'); return }
    savingPassword.set(true)
    try { if (hasComposition()) await draft.flushAll(); await api('/webmail/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword: currentPassword(), newPassword: newPassword() }) }); currentPassword.set(''); newPassword.set(''); confirmPassword.set(''); ports.navigate('/login', { reload: true }) }
    catch (cause) { passwordError.set(errorMessage(cause)) }
    finally { savingPassword.set(false) }
  }
  async function confirmAction(): Promise<void> {
    if (confirming()) return
    confirming.set(true)
    try {
      if (confirmation() === 'purge') await performBulk('purge', confirmationRefs, 'Trash', true)
      else if (confirmation() === 'discard') {
        if (draft.saving()) await draft.flush()
        if (draft.uid()) {
          const result = await api<BulkResult>('/webmail/api/bulk', { method: 'POST', body: JSON.stringify({ action: 'trash', messages: [{ uid: draft.uid(), folder: 'Drafts' }] }) })
          undoAction.set(result.undoId && result.expiresAt ? { id: result.undoId, expiresAt: result.expiresAt } : null)
          notice.set('Draft moved to Trash.')
        }
        resetComposition(); await refresh(true)
      }
      else if (confirmation() === 'reload-draft') await reloadSavedDraft()
      else if (confirmation() === 'retry-unknown' && reviewedOutboxId) await retryOutbox(reviewedOutboxId, true)
      confirmation.set('')
    }
    catch (cause) { composeError.set(errorMessage(cause)) }
    finally { confirming.set(false) }
  }
  async function openSharedReplyDraft(): Promise<void> {
    if (!globalThis.location?.href) return
    const page = new URL(globalThis.location.href)
    const link = page.searchParams.get('sharedReplyDraft')
    const parts = link?.match(/^([1-9]\d{0,18})\.([a-z0-9-]{16,64})$/i)
    if (!parts) return
    const [, uid, id] = parts
    const document = await api<DraftDocument>('/webmail/api/drafts?uid=' + uid)
    if (document.draftId !== id || document.state !== 'saved' || !document.message.sharedReply)
      throw new Error('This shared reply draft is unavailable.')
    if (destroyed || !user()) return
    page.searchParams.delete('sharedReplyDraft')
    globalThis.history.replaceState(null, '', page.href)
    installPayload(document.message, document)
  }
  async function mount(): Promise<void> {
    try {
      const result = await api<{ user: User }>('/webmail/auth/me')
      user.set(result.user)
      const config = await api<MailLimits>('/webmail/api/config')
      limits.set(config); sendDelay.set(config.undoSendSeconds)
      void writing.loadWritingLibrary()
      void loadSenderIdentities()
      await Promise.all([refresh(), refreshOutbox()])
      void notifications.loadNotificationSettings().catch(() => {})
      void privateMail.loadPrivateCollections()
      await openSharedReplyDraft()
      const source = takeMailEventLink('/')
      if (source) {
        if (source.account !== result.user.username) throw new Error('Sign in to the mailbox that owns the source email.')
        const opened = await openMessage({ uid: 0, folder: '', reference: source.reference }, false)
        const message = selected()
        if (opened === 'opened' && message?.reference === source.reference && message.folder !== folder()) {
          folder.set(message.folder)
          void refresh(true)
        }
      }
    }
    catch (cause) { error.set(errorMessage(cause)) }
  }
  async function resume(): Promise<void> {
    if (!user()) return
    try { const result = await api<{ user: User }>('/webmail/auth/me'); if (result.user.username === user()?.username) { authExpired.set(false); draft.schedule(0); await refreshOutbox() } }
    catch { /* Preserve unsaved composition while the user signs in again. */ }
  }
  function tick(): void {
    now.set(Date.now() / 1000 + clockOffset)
    if (undoAction() && undoRemaining() <= 0) undoAction.set(null)
    if (!user() || authExpired()) return
    void pollInvitationReplies()
    const pending = (item: OutboxSummary | null) => item?.state === 'sending' || (item?.state === 'pending' && item.dueAt <= now() + 2)
    const pollDelay = outbox().some(pending) || pending(pendingSend()) ? 1000 : outboxView() ? 10000 : 30000
    if (Date.now() - lastOutboxPoll >= pollDelay) void refreshOutbox()
    if (Date.now() - lastRefresh >= 30000 && !loading() && !refreshing() && !mutating() && !settings() && !confirmation()) {
      void refresh(true)
    }
  }
  function preventUnload(event: BeforeUnloadEvent): void { if (hasUnsavedChanges()) { event.preventDefault(); event.returnValue = '' } }
  function destroy(): void {
    destroyed = true
    ++listRequest
    ++messageRequest
    recipientEditor.destroy()
    attachmentEditor.destroy()
    draft.destroy()
    privateMail.closePrivate()
    contactBook.closeContacts()
    snapshots.closeSnapshots()
    fileSharing.clearFileLinkComposer()
    fileSharing.closeFileLinkManager()
    replyBatch.closeReplyBatch()
    selectionEffect()
  }
  return { user, folders, folder, messages, threads, expandedThreads, selected, loading, refreshing, listError, readerError, readerTarget, reading, readingLoading, mutating, error, notice, query, activeQuery, appliedSearchAll, filterLocation, filterSender, filterRecipient, filterFilename, libraryView, libraryFiles, indexProgress, filterAfter, filterBefore, filterStatus, filterFlagged, filterAttachments, filtersOpen, filterActive, conversations, page, total, matchingTotal, moveTo, showHtml, formattedReader, remoteImagesAllowed, checked, checkedKeys, selectedCount, isJunkFolder, readerJunkAction, selectionJunkAction, allChecked, someChecked, undoAction, undoRemaining, readingBatch, triageBusy, unreadAvailable, shortcutsOpen, triageShortcuts, pendingSend, sendRemaining, outbox, outboxCount, outboxCounts, outboxSection, outboxViews, outboxEmpty, outboxPageNumber, outboxNext, outboxLoading, outboxError, outboxView, cancelling, authExpired, currentFolderName, now, composing, title, sharedReply, senderId, senderIdentities, missingSender, senderStatus, chooseSender, externalSender, externalSendReview, cancelExternalReview, subject, body, showCc, showBcc, sending, sendUncertain, composeError, hasComposition, hasUnsavedChanges, saveStatus, savingDraft: draft.saving, draftError: draft.error, draftConflict: draft.conflict, sendDelay, sendDelayOptions, scheduleOpen, scheduleDate, scheduleZone, chooseSendTime, settings, currentPassword, newPassword, confirmPassword, passwordError, savingPassword, confirmation, confirming, limits, ...senderReview, ...notifications, ...privateMail, ...contactBook, showContacts, composeSavedCard, collectionView, collectionId, canOpenPrivate,
    createEventLink, canRespondToInvitation, respondToInvitation, rsvpBusy, rsvpError,
    ...snapshots, canShareSnapshot, shareMessageSnapshot, shareSelectedSnapshot,
    ...fileSharing, messageFileLinks, insertFileLink,
    ...replyBatch, replyToSelection, submitReplyBatch,
    invitationCalendar, invitationCalendarBusy, invitationDestination, chooseInvitationCalendar, saveInvitationCalendar,
    showCollectionManager, closeCollectionManager, selectCollection, confirmCollectionDeletion, savePrivateLabel, setPrivateMembership, groupSelected, displaySubject, changeNotificationRule, ...recipientEditor, ...attachmentEditor, ...recoverySettings, ...forwardingSettings, ...externalSenderSettings, ...vacationSettings, ...writing, snippetChoice, signatureChoice, insertSnippet, insertSignature, attentionViews, attentionView, followUpFocused, attentionSaving, attentionSchedule, attentionDate, attentionZone, dueReminders, replyContext, clearFollowUp, selectAttention, nextFollowUp, changeAttention, startAttentionSchedule, saveAttentionSchedule, deadlineLabel, categoryList, newsletterExpanded, readerExpanded, receiptFull, receiptCompact, receiptPreview, senderLabel, sortingSettings, sortingSaving, sortingError, toggleAutomaticSorting, placementText, categoryRule, categoryRuleSaving, saveCategoryRule, showSenderReview, openReviewMessage, reviewMessage, refresh, loadMessages, selectFolder, search, clearSearch, changeConversationView, turnPage, toggleThread, toggleSelection, toggleAll, toggleThreadSelection, threadChecked, threadPartial, clearSelection, openListMessage, openAttachmentMessage, showAttachmentLibrary, retryReader, closeReader, nextUnread, readSelection, advanceBatch, triageAndNext, bulkAction, selectedAction, undoLastAction, showShortcuts, closeShortcuts, handleShortcut, compose, closeComposer, editDraft, saveDraft, attachFiles, dropAttachments, saveSendPreference, send, confirmPendingSend, showOutbox, refreshOutbox, selectOutboxView, turnOutboxPage, cancelSend, retryOutbox, leaveAccount, leavingAccount, accountChangeError, showSettings, changePassword, showConfirmation, confirmAction, saveDraftCopy: draft.saveCopy, mount, resume, tick, preventUnload, destroy, messageIdentity, messagePageSize, folderName, shortDate, fullDate, readableBytes, attachmentPath }
}

function errorMessage(cause: unknown): string { return cause instanceof Error ? cause.message : 'Something went wrong. Please try again.' }
