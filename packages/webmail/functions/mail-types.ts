export interface Flags { seen: boolean, answered: boolean, flagged: boolean, draft: boolean, deleted: boolean }
export interface MessageRef { uid: number, folder: string }
export interface MessageSummary extends MessageRef {
  from: string
  to: string
  subject: string
  date: string
  snippet: string
  flags: Flags
  has_attachments: boolean
  size: number
  message_id: string
  in_reply_to: string
  references: string
  timestamp: number
  matches_filters: boolean
}
export interface MessageDetail extends MessageSummary {
  cc: string
  bcc: string
  reply_to: string
  text: string
  html: string
  attachments: Array<{ filename: string, content_type: string, size: number }>
}
export interface Conversation { id: string, count: number, unread: number, matching: number, latest: MessageSummary, members: MessageSummary[] }
export interface MessagePage { items: MessageSummary[], threads: Conversation[], page: number, total: number, message_total: number, conversations: boolean }
export interface Folder { name: string, unread: number, total: number }
export interface User { username: string, email: string }
export interface Contact { name: string, address: string }
export interface Recipient { raw: string, name: string, address: string, valid: boolean }
export type RecipientField = 'to' | 'cc' | 'bcc'
export interface Upload { uploadId: string, filename: string, contentType: string, size: number }
export interface ComposeAttachment extends Partial<Upload> {
  key: string
  filename: string
  contentType: string
  size: number
  progress: number
  status: 'uploading' | 'loading' | 'ready' | 'failed'
  error?: string
}
export interface ComposePayload {
  to: string[]
  cc: string[]
  bcc: string[]
  subject: string
  text: string
  html: string
  inReplyTo: string
  references: string
  draftUid: number | null
  draftId: string | null
  draftRevision: number
  saveToken: string
  recipientInputs: Record<RecipientField, string>
  recipientLabels?: Record<RecipientField, string[]>
  attachments: Array<{ uploadId?: string, filename: string, contentType: string, size?: number, data?: string }>
  replyContext: MessageRef | null
  sendId?: string
  delaySeconds?: number
}
export interface DraftAck { ok: boolean, uid: number, draftId: string, revision: number }
export interface DraftDocument { draftId: string, revision: number, uid: number, state: string, message: ComposePayload }
export interface SendResult { message_id: string, delivered: number, failed: string[], sent_saved: boolean }
export interface OutboxItem { id: string, state: string, dueAt: number, serverTime: number, message: ComposePayload, result: SendResult | null, error: string | null }
export type BulkAction = 'move' | 'trash' | 'read' | 'unread' | 'flag' | 'unflag' | 'purge'
export interface ActionResult extends MessageRef { ok: boolean, new_uid: number | null, new_folder: string | null, error_code: string | null }
export interface BulkResult { ok: boolean, results: ActionResult[], undoId: string | null, expiresAt: number | null }
export interface MailLimits { maxFileBytes: number, maxTotalBytes: number, maxCount: number, maxMessageBytes: number, undoSendSeconds: number }
