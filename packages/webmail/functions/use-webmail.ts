import type { BulkAction, BulkResult, ComposePayload, Contact, Conversation, DraftAck, DraftDocument, Folder, MailLimits, MessageDetail, MessagePage, MessageRef, MessageSummary, OutboxItem, User } from './mail-types'
import { batch, derived, effect, state } from '@stacksjs/stx'
import { createMailApi, MailApiError } from './mail-api'
import { dateBoundary, folderName, fullDate, messageKey, rangeSelection, readableBytes, recipients, safeHtml, shortDate } from './mail-utils'
import { useAttachments } from './use-attachments'
import { useDraftAutosave } from './use-draft-autosave'
import { useRecipientEditor } from './use-recipient-editor'

interface Ref<T> { current: T | null }
export interface WebmailPorts {
  composer: Ref<HTMLDialogElement>
  password: Ref<HTMLDialogElement>
  confirmation: Ref<HTMLDialogElement>
  fileInput: Ref<HTMLInputElement>
  selectAll: Ref<HTMLInputElement>
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
  const loading = state(false)
  const reading = state(false)
  const readingLoading = state(false)
  const mutating = state(false)
  const error = state('')
  const notice = state('')
  const query = state('')
  const activeQuery = state('')
  const searchAll = state(false)
  const filterSender = state('')
  const filterAfter = state('')
  const filterBefore = state('')
  const filterUnread = state(false)
  const filterFlagged = state(false)
  const filterAttachments = state(false)
  const filtersOpen = state(false)
  const conversations = state(true)
  const page = state(1)
  const total = state(0)
  const matchingTotal = state(0)
  const moveTo = state('Archive')
  const showHtml = state(true)
  const checked = state<MessageRef[]>([])
  const undoAction = state<{ id: string, expiresAt: number } | null>(null)
  const now = state(Date.now() / 1000)
  const outbox = state<OutboxItem[]>([])
  const pendingSend = state<OutboxItem | null>(null)
  const outboxView = state(false)
  const cancelling = state(false)
  const authExpired = state(false)
  const composing = state(false)
  const title = state('New message')
  const subject = state('')
  const body = state('')
  const draftHtml = state('')
  const initialText = state('')
  const inReplyTo = state('')
  const references = state('')
  const replyContext = state<MessageRef | null>(null)
  const showCc = state(false)
  const showBcc = state(false)
  const sending = state(false)
  const sendUncertain = state(false)
  const composeError = state('')
  const sendDelay = state(10)
  const sendDelayOptions = derived(() => [...new Set([0, 5, 10, 30, sendDelay()])].sort((left, right) => left - right))
  const settings = state(false)
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
  let selectionAnchor: string | null = null
  let clockOffset = 0
  let lastRefresh = 0
  let lastOutboxPoll = 0
  let pollingOutbox = false
  let destroyed = false
  let confirmationRefs: MessageRef[] = []
  let reviewedOutboxId: string | null = null
  let lastQueuedPayload: ComposePayload | null = null
  const announcedSends = new Set<string>()

  function onAuthError(cause: MailApiError): void {
    authExpired.set(true)
    if (cause.code === 'account_changed') {
      // Never move a private composition into a newly signed-in account.
      closeReader()
      messages.set([])
      threads.set([])
      checked.set([])
      composing.set(false)
      batch(() => { subject.set(''); body.set(''); draftHtml.set(''); recipientEditor.restore({ to: [], cc: [], bcc: [] }, { to: '', cc: '', bcc: '' }); attachmentEditor.destroy(); user.set(null) })
      draft.destroy()
      ports.navigate('/login', { reload: true })
    }
    else if (!user()) ports.navigate('/login', { reload: true })
  }
  const api = createMailApi(() => user()?.username, onAuthError)
  const recipientEditor = useRecipientEditor(value => api<Contact[]>(`/webmail/api/contacts?q=${encodeURIComponent(value)}`))
  const attachmentEditor = useAttachments(() => user()?.username, limits, cause => { if (cause instanceof MailApiError && cause.status === 401) onAuthError(cause) }, id => api(`/webmail/api/uploads/${id}`, { method: 'DELETE' }))
  const hasComposition = derived(() => Boolean(subject() || body() || draftHtml() || attachmentEditor.attachments().length || recipientEditor.toRecipients().length || recipientEditor.ccRecipients().length || recipientEditor.bccRecipients().length || recipientEditor.toInput() || recipientEditor.ccInput() || recipientEditor.bccInput()))
  function content() {
    return { ...recipientEditor.snapshot(), subject: subject(), text: body(), html: body() === initialText() ? draftHtml() : '', inReplyTo: inReplyTo(), references: references(), attachments: attachmentEditor.snapshot(), replyContext: replyContext() }
  }
  const draft = useDraftAutosave({ snapshot: content, hasContent: hasComposition, active: () => composing() && !sending(), blocked: () => attachmentEditor.attachmentPending() || authExpired(), save: payload => api<DraftAck>('/webmail/api/drafts', { method: 'POST', body: JSON.stringify(payload) }) })
  const hasUnsavedChanges = derived(() => draft.dirty() || attachmentEditor.attachmentPending())
  const saveStatus = derived(() => {
    if (attachmentEditor.attachmentUploading()) return 'Uploading attachments…'
    if (attachmentEditor.attachmentPending()) return 'An attachment needs attention.'
    if (draft.status() === 'saved') return 'Saved to Drafts'
    if (draft.status() === 'saving') return 'Saving…'
    if (draft.status() === 'conflict') return 'This draft changed in another window.'
    if (draft.status() === 'error') return 'Draft not saved. Your changes are still here.'
    return hasComposition() ? 'Unsaved changes' : 'Drafts save automatically as you type.'
  })
  const visibleMessages = derived(() => conversations() && folder() !== 'Drafts' ? threads().flatMap(thread => thread.members.filter(message => message.matches_filters !== false)) : messages())
  const checkedKeys = derived(() => checked().map(messageKey))
  const selectedCount = derived(() => checked().length)
  const allChecked = derived(() => visibleMessages().length > 0 && visibleMessages().every(message => checkedKeys().includes(messageKey(message))))
  const someChecked = derived(() => !allChecked() && visibleMessages().some(message => checkedKeys().includes(messageKey(message))))
  const filterActive = derived(() => Boolean(activeQuery() || filterSender() || filterAfter() || filterBefore() || filterUnread() || filterFlagged() || filterAttachments() || searchAll()))
  const undoRemaining = derived(() => Math.min(30, Math.max(0, Math.ceil((undoAction()?.expiresAt ?? 0) - now()))))
  const sendRemaining = derived(() => Math.max(0, Math.ceil((pendingSend()?.dueAt ?? 0) - now())))
  const outboxCount = derived(() => outbox().filter(item => ['pending', 'sending', 'failed', 'partial', 'unknown', 'sent_unfiled'].includes(item.state)).length)
  const currentFolderName = derived(() => outboxView() ? 'Outbox' : folderName(searchAll() ? '*' : folder()))
  const selectionEffect = effect(() => { const partial = someChecked(); if (ports.selectAll.current) ports.selectAll.current.indeterminate = partial })

  function messagePath(message: MessageRef): string { return `/webmail/api/messages/${message.uid}?folder=${encodeURIComponent(message.folder)}` }
  function attachmentPath(index: number, message: MessageRef | null = selected()): string {
    return `/webmail/api/attachment?uid=${message?.uid}&folder=${encodeURIComponent(message?.folder || folder())}&index=${index}&account=${encodeURIComponent(user()?.username || '')}`
  }
  function closeReader(): void { selected.set(null); reading.set(false); readingLoading.set(false); ++messageRequest }
  async function loadFolders(): Promise<void> { folders.set(await api<Folder[]>('/webmail/api/folders')) }
  async function loadMessages(quiet = false): Promise<void> {
    if (outboxView()) return
    const request = ++listRequest
    const name = searchAll() ? '*' : folder()
    if (!quiet) { loading.set(true); messages.set([]); threads.set([]) }
    error.set('')
    try {
      const after = dateBoundary(filterAfter())
      const before = dateBoundary(filterBefore(), true)
      if (after !== null && before !== null && before < after) throw new Error('End date must follow start date.')
      const params = new URLSearchParams({ folder: name, page: String(page()), per_page: '50', q: activeQuery(), from: filterSender().trim(), unread: String(filterUnread()), flagged: String(filterFlagged()), attachments: String(filterAttachments()), conversations: String(conversations() && folder() !== 'Drafts') })
      if (after !== null) params.set('after', String(after))
      if (before !== null) params.set('before', String(before))
      const result = await api<MessagePage>(`/webmail/api/messages?${params}`)
      if (destroyed || request !== listRequest) return
      batch(() => { messages.set(result.items || []); threads.set(result.threads || []); total.set(result.total); matchingTotal.set(result.message_total); page.set(result.page) })
      const detail = selected()
      if (detail) {
        const summary = [...result.items, ...result.threads.flatMap(thread => thread.members)].find(item => messageKey(item) === messageKey(detail))
        if (summary) selected.set({ ...detail, flags: summary.flags })
      }
      ports.nextTick(() => { if (ports.selectAll.current) ports.selectAll.current.indeterminate = someChecked() })
    }
    catch (cause) { if (request === listRequest) error.set(errorMessage(cause)) }
    finally { if (request === listRequest) loading.set(false) }
  }
  async function refresh(quiet = false): Promise<void> {
    lastRefresh = Date.now()
    await Promise.all([loadMessages(quiet), loadFolders().catch(cause => error.set(errorMessage(cause)))])
  }
  function clearSelection(): void { checked.set([]); selectionAnchor = null }
  async function selectFolder(name: string): Promise<void> {
    if (mutating()) return
    batch(() => { folder.set(name); outboxView.set(false); page.set(1); query.set(''); activeQuery.set(''); searchAll.set(name === '*'); filterSender.set(''); filterAfter.set(''); filterBefore.set(''); filterUnread.set(false); filterFlagged.set(false); filterAttachments.set(false); expandedThreads.set([]) })
    clearSelection()
    closeReader()
    await refresh()
  }
  async function search(): Promise<void> { page.set(1); activeQuery.set(query().trim()); clearSelection(); closeReader(); await loadMessages() }
  async function clearSearch(): Promise<void> {
    batch(() => { query.set(''); activeQuery.set(''); filterSender.set(''); filterAfter.set(''); filterBefore.set(''); filterUnread.set(false); filterFlagged.set(false); filterAttachments.set(false); searchAll.set(folder() === '*'); page.set(1) })
    clearSelection()
    await loadMessages()
  }
  async function changeConversationView(): Promise<void> { clearSelection(); expandedThreads.set([]); page.set(1); await loadMessages() }
  async function turnPage(delta: number): Promise<void> { if (loading() || mutating()) return; page.update(value => Math.max(1, value + delta)); closeReader(); await loadMessages() }
  function toggleThread(id: string): void { expandedThreads.update(ids => ids.includes(id) ? ids.filter(value => value !== id) : [...ids, id]) }
  function toggleSelection(message: MessageSummary, event: MouseEvent): void {
    event.stopPropagation()
    const wanted = !checkedKeys().includes(messageKey(message))
    const rows = event.shiftKey ? rangeSelection(visibleMessages(), selectionAnchor, message) : [message]
    const result = new Map(checked().map(ref => [messageKey(ref), ref]))
    for (const row of rows) { if (wanted) result.set(messageKey(row), { uid: row.uid, folder: row.folder }); else result.delete(messageKey(row)) }
    if (result.size > 100) { notice.set('Select up to 100 messages at a time.'); return }
    checked.set([...result.values()])
    selectionAnchor = messageKey(message)
  }
  function toggleAll(): void {
    if (allChecked()) { clearSelection(); return }
    const result = new Map(checked().map(ref => [messageKey(ref), ref]))
    for (const message of visibleMessages()) { if (result.size >= 100) break; result.set(messageKey(message), { uid: message.uid, folder: message.folder }) }
    checked.set([...result.values()])
    if (visibleMessages().length > 100) notice.set('Selected the first 100 matching messages. Process these before selecting more.')
  }
  function toggleThreadSelection(thread: Conversation, event: MouseEvent): void {
    event.stopPropagation()
    const members = thread.members.filter(message => message.matches_filters !== false)
    const wanted = !members.every(message => checkedKeys().includes(messageKey(message)))
    const result = new Map(checked().map(ref => [messageKey(ref), ref]))
    for (const message of members) { if (wanted) result.set(messageKey(message), { uid: message.uid, folder: message.folder }); else result.delete(messageKey(message)) }
    if (result.size > 100) { notice.set('This conversation exceeds the selection limit. Expand it and select up to 100 messages.'); return }
    checked.set([...result.values()])
    selectionAnchor = messageKey(thread.latest)
  }
  function threadChecked(thread: Conversation): boolean { return thread.members.filter(message => message.matches_filters !== false).every(message => checkedKeys().includes(messageKey(message))) }
  function threadPartial(thread: Conversation): boolean { return !threadChecked(thread) && thread.members.some(message => checkedKeys().includes(messageKey(message))) }
  async function openMessage(message: MessageRef): Promise<void> {
    if (mutating()) return
    const request = ++messageRequest
    reading.set(true); readingLoading.set(true); selected.set(null); showHtml.set(true); error.set('')
    try {
      const detail = await api<MessageDetail>(messagePath(message))
      if (destroyed || request !== messageRequest) return
      selected.set({ ...detail, folder: message.folder })
      if (!detail.flags.seen) {
        await api(messagePath(message), { method: 'PUT', body: JSON.stringify({ flags: { ...detail.flags, seen: true } }) })
        if (request === messageRequest) selected.set({ ...detail, folder: message.folder, flags: { ...detail.flags, seen: true } })
        await refresh(true)
      }
    }
    catch (cause) { if (request === messageRequest) error.set(errorMessage(cause)) }
    finally { if (request === messageRequest) readingLoading.set(false) }
  }
  function showConfirmation(action: string, refs: MessageRef[] = []): void {
    confirmationRefs = refs
    confirmation.set(action)
    ports.nextTick(() => { if (!ports.confirmation.current?.open) ports.confirmation.current?.showModal() })
  }
  function actionNotice(action: BulkAction, count: number, destination: string): string {
    const label = count === 1 ? 'Message' : `${count} messages`
    return action === 'move' ? `${label} moved to ${folderName(destination)}.` : action === 'trash' ? `${label} moved to Trash.` : action === 'read' ? `${label} marked read.` : action === 'unread' ? `${label} marked unread.` : action === 'flag' ? `${label} flagged.` : action === 'unflag' ? `${label} unflagged.` : `${label} permanently deleted.`
  }
  async function performBulk(action: BulkAction, refs: MessageRef[], destination = moveTo(), confirmed = false): Promise<void> {
    if (mutating() || !refs.length) return
    if (action === 'purge' && !confirmed) { showConfirmation('purge', refs); return }
    mutating.set(true); error.set('')
    try {
      const result = await api<BulkResult>('/webmail/api/bulk', { method: 'POST', body: JSON.stringify({ action, messages: refs, folder: destination }) })
      const succeeded = result.results.filter(item => item.ok)
      const failed = result.results.filter(item => !item.ok)
      checked.set(failed.map(item => ({ uid: item.uid, folder: item.folder })))
      undoAction.set(result.undoId && result.expiresAt ? { id: result.undoId, expiresAt: result.expiresAt } : null)
      notice.set(actionNotice(action, succeeded.length, destination) + (failed.length ? ` ${failed.length} could not be changed; they remain selected.` : ''))
      const current = selected()
      if (current && succeeded.some(item => messageKey(item) === messageKey(current))) {
        if (['move', 'trash', 'purge'].includes(action)) closeReader()
        else selected.set({ ...current, flags: { ...current.flags, ...(action === 'read' || action === 'unread' ? { seen: action === 'read' } : { flagged: action === 'flag' }) } })
      }
      await refresh(true)
    }
    catch (cause) { error.set(errorMessage(cause)) }
    finally { mutating.set(false) }
  }
  async function bulkAction(action: BulkAction, destination?: string): Promise<void> { await performBulk(action, checked(), destination) }
  async function selectedAction(action: BulkAction): Promise<void> { const item = selected(); if (item) await performBulk(action, [{ uid: item.uid, folder: item.folder }]) }
  async function undoLastAction(): Promise<void> {
    const receipt = undoAction()
    if (!receipt || undoRemaining() <= 0 || mutating()) return
    mutating.set(true)
    try {
      const result = await api<BulkResult>(`/webmail/api/undo/${receipt.id}`, { method: 'POST', body: '{}' })
      undoAction.set(null)
      notice.set(result.ok ? 'Action undone.' : 'Some messages changed since that action and could not be restored.')
      clearSelection(); closeReader(); await refresh(true)
    }
    catch (cause) { error.set(errorMessage(cause)); undoAction.set(null) }
    finally { mutating.set(false) }
  }

  function resetComposition(): void {
    batch(() => {
      composing.set(false)
      subject.set(''); body.set(''); draftHtml.set(''); initialText.set(''); inReplyTo.set(''); references.set(''); replyContext.set(null); composeError.set(''); showCc.set(false); showBcc.set(false)
      recipientEditor.restore({ to: [], cc: [], bcc: [] }, { to: '', cc: '', bcc: '' })
      attachmentEditor.restore([])
      draft.restore(null, content())
      lastQueuedPayload = null
      sendUncertain.set(false)
    })
  }
  function showComposer(): void { composing.set(true); ports.nextTick(() => { if (!ports.composer.current?.open) ports.composer.current?.showModal() }) }
  async function closeComposer(): Promise<void> {
    if (sending() || sendUncertain()) return
    try { if (draft.saving()) await draft.flush(); if (hasComposition()) await draft.flushAll(); composing.set(false); if (selected()?.folder === 'Drafts') closeReader(); await refresh(true) }
    catch (cause) { composeError.set(`Keep this window open: ${errorMessage(cause)}`) }
  }
  async function compose(mode = 'new'): Promise<void> {
    if (mode === 'new' && hasComposition()) { showComposer(); return }
    try { if (hasComposition()) await draft.flushAll() }
    catch (cause) { composeError.set(errorMessage(cause)); showComposer(); return }
    const original = selected()
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
      if (mode !== 'forward') { inReplyTo.set(original.message_id); references.set(`${original.references || ''} ${original.message_id}`.trim()); replyContext.set({ uid: original.uid, folder: original.folder }) }
      showCc.set(mode === 'all' && cc.length > 0)
      if (mode === 'forward') void importAttachments(original)
    }
    else title.set('New message')
    showComposer()
  }
  async function importAttachments(message: MessageDetail): Promise<void> {
    try {
      for (let index = 0; index < message.attachments.length; index++) {
        const item = message.attachments[index]
        if (item.size > limits().maxFileBytes || attachmentEditor.attachmentBytes() + item.size > limits().maxTotalBytes) throw new Error('This message has an attachment above your current limit. Forward the text or download the attachment separately.')
        const response = await fetch(attachmentPath(index, message), { credentials: 'same-origin', cache: 'no-store' })
        if (!response.ok) throw new Error('Could not load an attachment from this message.')
        await attachmentEditor.addFiles([new File([await response.arrayBuffer()], item.filename, { type: item.content_type })])
      }
    }
    catch (cause) { composeError.set(errorMessage(cause)) }
  }
  function installPayload(payload: ComposePayload, document: DraftDocument | null, metadata: MessageDetail | null = null): void {
    resetComposition()
    batch(() => {
      recipientEditor.restore({ to: payload.to, cc: payload.cc, bcc: payload.bcc }, payload.recipientInputs || { to: '', cc: '', bcc: '' }, payload.recipientLabels)
      subject.set(payload.subject); body.set(payload.text); initialText.set(payload.text); draftHtml.set(payload.html); inReplyTo.set(payload.inReplyTo); references.set(payload.references); replyContext.set(payload.replyContext)
      showCc.set(Boolean(payload.cc.length || payload.recipientInputs?.cc)); showBcc.set(Boolean(payload.bcc.length || payload.recipientInputs?.bcc))
      attachmentEditor.restore(payload.attachments.filter(item => item.uploadId).map((item, index) => ({ key: crypto.randomUUID(), uploadId: item.uploadId, filename: item.filename, contentType: item.contentType, size: metadata?.attachments[index]?.size ?? item.size ?? 0, progress: 100, status: 'ready' as const })))
      draft.restore(document, content())
      title.set('Edit draft')
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
    composeError.set('')
    try { if (!hasComposition()) throw new Error('Write something before saving a draft.'); await draft.flushAll(); await refresh(true) }
    catch (cause) { composeError.set(errorMessage(cause)) }
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
  async function send(): Promise<void> {
    if (sending() || sendUncertain() || attachmentEditor.attachmentPending()) return
    composeError.set('')
    recipientEditor.commitAll()
    const values = [...recipientEditor.toRecipients(), ...recipientEditor.ccRecipients(), ...recipientEditor.bccRecipients()]
    const invalid = values.find(item => !item.valid)
    if (invalid) { composeError.set(`Check this email address: ${invalid.raw}`); return }
    if (!values.length || values.length > 100) { composeError.set(values.length ? 'Use at most 100 recipients.' : 'Add at least one recipient.'); return }
    if (new TextEncoder().encode(body()).length > 256 * 1024) { composeError.set('Keep the message body under 256 KiB.'); return }
    sending.set(true)
    try {
      await draft.flushAll()
      const payload = lastQueuedPayload ?? { ...content(), draftId: draft.id(), draftUid: draft.uid(), draftRevision: draft.revision(), saveToken: '', sendId: crypto.randomUUID(), delaySeconds: sendDelay() }
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
      notice.set(queued.state === 'pending' && queued.dueAt > queued.serverTime ? `Message queued. Undo Send is available for ${queued.dueAt - queued.serverTime} seconds.` : 'Message queued for delivery.')
      resetComposition()
      await refreshOutbox()
      await refresh(true)
    }
    catch (cause) {
      if (cause instanceof MailApiError && cause.status < 500) lastQueuedPayload = null
      else if (lastQueuedPayload) sendUncertain.set(true)
      composeError.set(errorMessage(cause))
    }
    finally { sending.set(false) }
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
      await refreshOutbox()
    }
    catch (cause) { composeError.set(errorMessage(cause)) }
    finally { sending.set(false) }
  }
  async function refreshOutbox(): Promise<void> {
    if (pollingOutbox || !user()) return
    pollingOutbox = true
    lastOutboxPoll = Date.now()
    try {
      const items = await api<OutboxItem[]>('/webmail/api/outbox')
      if (destroyed) return
      outbox.set(items)
      if (items[0]) clockOffset = items[0].serverTime - Date.now() / 1000
      const pending = pendingSend()
      const update = pending ? items.find(item => item.id === pending.id) : null
      if (update) {
        pendingSend.set(update)
        if (!['pending', 'sending', 'cancelled'].includes(update.state) && !announcedSends.has(update.id)) {
          announcedSends.add(update.id)
          const failed = update.result?.failed.length || 0
          notice.set(update.state === 'sent' ? 'Message sent.' : update.state === 'sent_unfiled' ? 'Message delivered, but the Sent copy could not be saved. Do not resend.' : update.state === 'partial' ? `${update.result?.delivered} recipient(s) received the message. ${failed} did not; retry only those recipients from Outbox.` : update.state === 'unknown' ? 'Delivery was interrupted. Check Sent before retrying this message.' : update.error || 'Delivery failed. Open Outbox to review and retry.')
          await refresh(true)
        }
      }
    }
    catch (cause) { if (outboxView()) error.set(errorMessage(cause)) }
    finally { pollingOutbox = false }
  }
  async function showOutbox(): Promise<void> { outboxView.set(true); closeReader(); clearSelection(); await refreshOutbox() }
  async function cancelSend(id = pendingSend()?.id): Promise<void> {
    if (!id || cancelling()) return
    cancelling.set(true)
    try {
      const cancelled = await api<OutboxItem>(`/webmail/api/outbox/${id}`, { method: 'DELETE' })
      pendingSend.set(null)
      notice.set('Send cancelled. Nothing was dispatched.')
      if (hasComposition()) await draft.flushAll()
      let document: DraftDocument | null = null
      let metadata: MessageDetail | null = null
      if (cancelled.message.draftUid) {
        try { document = await api<DraftDocument>(`/webmail/api/drafts?uid=${cancelled.message.draftUid}`); metadata = await api<MessageDetail>(messagePath({ uid: document.uid, folder: 'Drafts' })) }
        catch { document = null }
      }
      installPayload(document?.message || cancelled.message, document, metadata)
      await refreshOutbox()
    }
    catch (cause) { error.set(cause instanceof MailApiError && cause.status === 409 ? 'The cancellation window has closed. Check Outbox for the delivery result.' : errorMessage(cause)); await refreshOutbox() }
    finally { cancelling.set(false) }
  }
  function reviewUnknown(id: string): void { reviewedOutboxId = id; showConfirmation('retry-unknown') }
  async function retryOutbox(id: string, reviewed = false): Promise<void> {
    try {
      if (hasComposition()) await draft.flushAll()
      let item = await api<OutboxItem>(`/webmail/api/outbox/${id}`)
      if (!['failed', 'partial', 'cancelled', 'unknown'].includes(item.state)) throw new Error('This message is already queued or delivered.')
      if (item.state === 'unknown') {
        if (!reviewed) { reviewUnknown(id); return }
        item = await api<OutboxItem>(`/webmail/api/outbox/${id}`, { method: 'PATCH', body: JSON.stringify({ reviewed: true }) })
      }
      if (item.message.draftUid) {
        try {
          const document = await api<DraftDocument>(`/webmail/api/drafts?uid=${item.message.draftUid}`)
          if (document.state === 'saved') {
            const metadata = await api<MessageDetail>(messagePath({ uid: document.uid, folder: 'Drafts' }))
            installPayload(document.message, document, metadata)
            title.set('Review unsent recipients')
            return
          }
        }
        catch { /* The original draft may have been moved or deleted; keep a copy. */ }
      }
      const payload = { ...item.message }
      if (item.result?.failed.length) {
        const failed = new Set(item.result.failed.map(address => address.toLowerCase()))
        payload.to = payload.to.filter(address => failed.has(address.toLowerCase()))
        payload.cc = payload.cc.filter(address => failed.has(address.toLowerCase()))
        payload.bcc = payload.bcc.filter(address => failed.has(address.toLowerCase()))
        payload.recipientLabels = { to: [], cc: [], bcc: [] }
      }
      installPayload(payload, null)
      title.set('Review unsent recipients')
    }
    catch (cause) { error.set(errorMessage(cause)) }
  }
  async function signOut(): Promise<void> {
    if (sending()) return
    try { if (hasComposition()) await draft.flushAll(); await api('/webmail/auth/logout', { method: 'POST', body: '{}' }); resetComposition(); ports.navigate('/login', { reload: true }) }
    catch (cause) { error.set(errorMessage(cause)) }
  }
  function showSettings(): void { settings.set(true); passwordError.set(''); ports.nextTick(() => { if (!ports.password.current?.open) ports.password.current?.showModal() }) }
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
  async function mount(): Promise<void> {
    try {
      const result = await api<{ user: User }>('/webmail/auth/me')
      user.set(result.user)
      const config = await api<MailLimits>('/webmail/api/config')
      limits.set(config); sendDelay.set(config.undoSendSeconds)
      await Promise.all([refresh(), refreshOutbox()])
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
    const pending = outbox().some(item => item.state === 'pending' || item.state === 'sending') || pendingSend()?.state === 'pending' || pendingSend()?.state === 'sending'
    if ((pending || outboxView()) && Date.now() - lastOutboxPoll >= 1000) void refreshOutbox()
    if (Date.now() - lastRefresh >= 30000 && !loading() && !mutating() && !composing() && !settings() && !confirmation()) { void refresh(true); void refreshOutbox() }
  }
  function preventUnload(event: BeforeUnloadEvent): void { if (hasUnsavedChanges()) { event.preventDefault(); event.returnValue = '' } }
  function destroy(): void { destroyed = true; ++listRequest; ++messageRequest; recipientEditor.destroy(); attachmentEditor.destroy(); draft.destroy(); selectionEffect() }
  return { user, folders, folder, messages, threads, expandedThreads, selected, loading, reading, readingLoading, mutating, error, notice, query, activeQuery, searchAll, filterSender, filterAfter, filterBefore, filterUnread, filterFlagged, filterAttachments, filtersOpen, filterActive, conversations, page, total, matchingTotal, moveTo, showHtml, checked, checkedKeys, selectedCount, allChecked, someChecked, undoAction, undoRemaining, pendingSend, sendRemaining, outbox, outboxCount, outboxView, cancelling, authExpired, currentFolderName, now, composing, title, subject, body, showCc, showBcc, sending, sendUncertain, composeError, hasComposition, hasUnsavedChanges, saveStatus, savingDraft: draft.saving, draftError: draft.error, draftConflict: draft.conflict, sendDelay, sendDelayOptions, settings, currentPassword, newPassword, confirmPassword, passwordError, savingPassword, confirmation, confirming, limits, ...recipientEditor, ...attachmentEditor, refresh, loadMessages, selectFolder, search, clearSearch, changeConversationView, turnPage, toggleThread, toggleSelection, toggleAll, toggleThreadSelection, threadChecked, threadPartial, clearSelection, openMessage, closeReader, bulkAction, selectedAction, undoLastAction, compose, closeComposer, editDraft, saveDraft, attachFiles, dropAttachments, saveSendPreference, send, confirmPendingSend, showOutbox, refreshOutbox, cancelSend, retryOutbox, signOut, showSettings, changePassword, showConfirmation, confirmAction, saveDraftCopy: draft.saveCopy, mount, resume, tick, preventUnload, destroy, messageKey, folderName, shortDate, fullDate, readableBytes, safeHtml, attachmentPath }
}

function errorMessage(cause: unknown): string { return cause instanceof Error ? cause.message : 'Something went wrong. Please try again.' }
