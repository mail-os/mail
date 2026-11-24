import type { EmbeddedImage } from './mail-reader'
import { derived, state } from '@stacksjs/stx'
import { createMailApi, MailApiError } from './mail-api'
import { renderMailReader } from './mail-reader'

interface Inbox { team: string, name: string, id: string, address: string }
interface Teammate { id: string, address: string }
interface StageLabel { id: string, name: string }
interface Stage extends StageLabel { sender: string | null, revision: number }
interface StageSettings { canManage: boolean, items: Stage[] }
interface Workflow {
  assignee: Teammate | null
  stage: StageLabel | null
  resolved: boolean
  revision: number
  changedBy: string | null
  changedAt: number | null
  action: Action | 'access_removed' | 'route' | 'stage_retired' | null
}
interface InboxMessage { reference: string, revision: string, from: string, subject: string, snippet: string, date: string }
interface Row { message: InboxMessage, workflow: Workflow }
interface MessagePage { page: number, total: number, more: boolean, items: Row[] }
interface Detail extends Pick<InboxMessage, 'reference' | 'revision' | 'from' | 'subject' | 'date'> {
  to: string
  text: string
  html: string
  hasAttachments: boolean
  attachments: { filename: string, size: number }[]
  embedded_images: EmbeddedImage[]
  assignable: Teammate[]
  workflow: Workflow
  canReply: boolean
  reply: ReplyStatus | null
}
interface ReplyStatus { state: 'queued' | 'sending' | 'review' | 'replied', actor: string | null, dueAt: number | null }
type Action = 'assign' | 'unassign' | 'resolve' | 'reopen' | 'move'

const endpoint = '/webmail/api/shared-inboxes'
export function inboxKey(inbox: Inbox) { return inbox.team + '/' + inbox.id }
export function inboxLabel(inbox: Inbox) { return inbox.name + ' · ' + inbox.address }
export function workflowActivity(workflow: Workflow): string {
  if (workflow.action === 'access_removed') return 'Assignment cleared after access changed'
  if (workflow.action === 'route') return 'Routed when mail arrived'
  if (workflow.action === 'stage_retired') return 'Stage retired by ' + workflow.changedBy
  if (!workflow.changedBy || !workflow.action) return ''
  const label = {
    assign: 'Assigned by',
    unassign: 'Unassigned by',
    resolve: 'Resolved by',
    reopen: 'Reopened by',
    move: 'Moved by',
  }[workflow.action]
  return label ? label + ' ' + workflow.changedBy : ''
}

export function replyActivity(reply: ReplyStatus): string {
  const labels = { queued: ['Reply queued', 'Reply queued by'], sending: ['Reply sending', 'Reply sending by'], review: ['Reply awaiting delivery review', 'Reply awaiting delivery review for'], replied: ['Replied', 'Replied by'] }
  return reply.actor ? labels[reply.state][1] + ' ' + reply.actor : labels[reply.state][0]
}

export function useSharedInbox(signIn: () => void, openReplyDraft: (uid: number, id: string) => void) {
  const account = state('')
  const inboxes = state<Inbox[]>([])
  const selectedInbox = state('')
  const mailbox = derived(() => inboxes().find(inbox => inboxKey(inbox) === selectedInbox()) ?? null)
  const listing = state<MessagePage | null>(null)
  const detail = state<Detail | null>(null)
  const reference = state('')
  const stageSettings = state<StageSettings | null>(null)
  const managingStages = state(false)
  const editingStage = state<Stage | null>(null)
  const stageName = state('')
  const stageSender = state('')
  const loading = state(false)
  const opening = state(false)
  const saving = state(false)
  const error = state('')
  const ready = state(false)
  const formatted = derived(() => renderMailReader(detail()?.html ?? '', detail()?.embedded_images))
  let active = true
  let listRequest = 0
  let detailRequest = 0
  let pendingReply: { inbox: string, reference: string, revision: string, id: string } | null = null

  function closeMessage(): void {
    detailRequest++
    detail.set(null)
    reference.set('')
    opening.set(false)
  }
  function clear(): void {
    listRequest++
    inboxes.set([])
    selectedInbox.set('')
    listing.set(null)
    clearStages()
    closeMessage()
  }
  const api = createMailApi(() => account() || undefined, () => {
    clear()
    signIn()
  }, () => active)

  function messagePath(inbox: string, id: string) { return endpoint + '/' + inbox + '/messages/' + encodeURIComponent(id) }
  function stagesPath(inbox: string) { return endpoint + '/' + inbox + '/stages' }
  function clearStages(): void {
    stageSettings.set(null)
    managingStages.set(false)
    editStage(null)
  }
  function toggleStages(): void {
    managingStages.set(!managingStages())
  }
  function editStage(stage: Stage | null): void {
    editingStage.set(stage)
    stageName.set(stage?.name ?? '')
    stageSender.set(stage?.sender ?? '')
  }
  function attachmentPath(index: number): string {
    const opened = detail()
    if (!opened) return ''
    return messagePath(selectedInbox(), opened.reference) + '/attachments/' + index
      + '?revision=' + encodeURIComponent(opened.revision) + '&account=' + encodeURIComponent(account())
  }

  async function loadPage(page: number): Promise<void> {
    const current = selectedInbox()
    if (!current) return
    const request = ++listRequest
    loading.set(true)
    try {
      const [result, stages] = await Promise.all([
        api<MessagePage>(endpoint + '/' + current + '?page=' + page),
        api<StageSettings>(stagesPath(current)),
      ])
      if (request === listRequest && active) {
        listing.set(result)
        stageSettings.set(stages)
        if (!stages.canManage) managingStages.set(false)
      }
    }
    catch (cause) {
      if (request !== listRequest || !active) return
      if (cause instanceof MailApiError && cause.status === 404) {
        inboxes.set(inboxes().filter(inbox => inboxKey(inbox) !== current))
        selectedInbox.set('')
        listing.set(null)
        clearStages()
        closeMessage()
      }
      error.set(cause instanceof Error ? cause.message : 'Could not open the shared inbox.')
    }
    finally { if (request === listRequest) loading.set(false) }
  }

  async function readMessage(id: string, showProgress = true): Promise<void> {
    const current = selectedInbox()
    if (!current) return
    const request = ++detailRequest
    if (showProgress) {
      opening.set(true)
      detail.set(null)
      error.set('')
    }
    reference.set(id)
    try {
      const result = await api<Detail>(messagePath(current, id))
      if (request === detailRequest && current === selectedInbox() && active) detail.set(result)
    }
    catch (cause) {
      if (request !== detailRequest || !active) return
      if (cause instanceof MailApiError && cause.status === 404) {
        closeMessage()
        await loadPage(listing()?.page ?? 1)
      }
      else if (showProgress) closeMessage()
      error.set(cause instanceof Error ? cause.message : 'Could not open the shared message.')
    }
    finally { if (request === detailRequest) opening.set(false) }
  }

  async function selectInbox(key: string): Promise<void> {
    if (saving() || key === selectedInbox()) return
    error.set('')
    closeMessage()
    selectedInbox.set(key)
    listing.set(null)
    clearStages()
    await loadPage(1)
  }

  async function refresh(): Promise<void> {
    if (!active || !account() || saving() || opening() || loading()) return
    const current = selectedInbox()
    const request = ++listRequest
    loading.set(true)
    try {
      const available = await api<Inbox[]>(endpoint)
      if (request !== listRequest || !active) return
      inboxes.set(available)
      const retained = available.some(inbox => inboxKey(inbox) === current)
      if (!retained) {
        closeMessage()
        listing.set(null)
        clearStages()
        selectedInbox.set(available.length ? inboxKey(available[0]) : '')
        if (current) error.set('Access to this shared inbox changed.')
      }
      await loadPage(retained ? listing()?.page ?? 1 : 1)
      if (reference() && !saving()) await readMessage(reference(), false)
    }
    catch (cause) {
      if (request === listRequest && active) error.set(cause instanceof Error ? cause.message : 'Could not load shared inboxes.')
    }
    finally { if (request === listRequest) loading.set(false) }
  }

  async function turnPage(delta: number): Promise<void> {
    if (loading() || saving() || !listing()) return
    closeMessage()
    error.set('')
    await loadPage(listing()!.page + delta)
  }

  async function change(action: Action, assignee?: string): Promise<void> {
    const opened = detail()
    if (opened) await updateWorkflow(opened, opened.workflow, action, { assignee })
  }

  async function moveRow(row: Row, stageId: string): Promise<void> {
    await updateWorkflow(row.message, row.workflow, 'move', { stageId: stageId || undefined })
  }

  async function updateWorkflow(message: InboxMessage | Detail, before: Workflow, action: Action, fields: { assignee?: string, stageId?: string }): Promise<void> {
    if (saving() || loading() || opening()) return
    const current = selectedInbox()
    saving.set(true)
    error.set('')
    try {
      const workflow = await api<Workflow>(messagePath(current, message.reference) + '/workflow', {
        method: 'PUT', body: JSON.stringify({ action, ...fields, revision: before.revision, messageRevision: message.revision }),
      })
      if (!active || selectedInbox() !== current) return
      const opened = detail()
      if (opened?.reference === message.reference) detail.set({ ...opened, workflow })
      const page = listing()
      if (page) listing.set({ ...page, items: page.items.map(row => row.message.reference === message.reference ? { ...row, workflow } : row) })
    }
    catch (cause) {
      if (!active || selectedInbox() !== current) return
      error.set(cause instanceof Error ? cause.message : 'Could not update the shared message.')
      if (reference() === message.reference) {
        if (cause instanceof MailApiError && cause.status === 404) closeMessage()
        else await readMessage(message.reference, false)
      }
      await loadPage(listing()?.page ?? 1)
    }
    finally { saving.set(false) }
  }

  async function saveStage(): Promise<void> {
    const stage = editingStage()
    await updateStage(stage ? 'update' : 'create', stage, stageName().trim(), stageSender().trim() || undefined)
  }

  async function retireStage(stage: Stage): Promise<void> {
    await updateStage('retire', stage)
  }

  async function updateStage(action: 'create' | 'update' | 'retire', stage: Stage | null, name?: string, sender?: string): Promise<void> {
    if (saving() || loading() || !stageSettings()?.canManage) return
    const current = selectedInbox()
    saving.set(true)
    error.set('')
    try {
      const settings = await api<StageSettings>(stagesPath(current), {
        method: 'PUT', body: JSON.stringify({ action, id: stage?.id, revision: stage?.revision, name, sender }),
      })
      if (!active || selectedInbox() !== current) return
      stageSettings.set(settings)
      if (action !== 'retire' || editingStage()?.id === stage?.id) editStage(null)
      await loadPage(listing()?.page ?? 1)
      if (reference()) await readMessage(reference(), false)
    }
    catch (cause) {
      if (!active || selectedInbox() !== current) return
      error.set(cause instanceof Error ? cause.message : 'Could not update the inbox stage.')
      await loadPage(listing()?.page ?? 1)
    }
    finally { saving.set(false) }
  }

  async function startReply(): Promise<void> {
    const opened = detail()
    if (!opened?.canReply || saving() || loading()) return
    saving.set(true)
    error.set('')
    try {
      const inbox = selectedInbox()
      if (pendingReply?.inbox !== inbox || pendingReply.reference !== opened.reference || pendingReply.revision !== opened.revision)
        pendingReply = { inbox, reference: opened.reference, revision: opened.revision, id: crypto.randomUUID() }
      const result = await api<{ uid: number, draftId: string }>(messagePath(inbox, opened.reference) + '/reply', {
        method: 'POST', body: JSON.stringify({ draftId: pendingReply.id, messageRevision: opened.revision }),
      })
      if (active) openReplyDraft(result.uid, result.draftId)
    }
    catch (cause) {
      if (!active) return
      if (cause instanceof MailApiError && cause.status < 500) {
        pendingReply = null
        await readMessage(opened.reference, false)
      }
      error.set(cause instanceof Error ? cause.message : 'Could not prepare the shared reply.')
    }
    finally { saving.set(false) }
  }

  async function mount(): Promise<void> {
    try {
      const response = await api<{ user: { username: string } }>('/webmail/auth/me')
      account.set(response.user.username)
      await refresh()
    }
    catch (cause) {
      if (active) error.set(cause instanceof Error ? cause.message : 'Could not open shared inboxes.')
    }
    finally { ready.set(true) }
  }

  return { inboxes, selectedInbox, mailbox, listing, detail, reference, loading, opening, saving, error, ready, formatted,
    stageSettings, managingStages, editingStage, stageName, stageSender, toggleStages, editStage, moveRow, saveStage, retireStage,
    mount, refresh, selectInbox, turnPage, readMessage, closeMessage, attachmentPath, change, startReply,
    destroy() { active = false; clear() } }
}
