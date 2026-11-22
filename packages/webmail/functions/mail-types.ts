import type { EmbeddedImage } from './mail-reader'

export interface Flags { seen: boolean, answered: boolean, flagged: boolean, draft: boolean, deleted: boolean }
export interface MessageRef {
  uid: number
  folder: string
  reference?: string | null
  revision?: string | null
  content_revision?: string
}
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
  attention_deadline?: number
  personal_subject?: string
}
export interface MessageDetail extends MessageSummary {
  cc: string
  bcc: string
  reply_to: string
  text: string
  html: string
  attachments: Array<{ filename: string, content_type: string, size: number }>
  embedded_images?: EmbeddedImage[]
  placement?: MessagePlacement
  attention?: AttentionStatus
  notifications?: MailNotificationRules
}
export type MailNotificationRule = 'default' | 'notify' | 'quiet'
export type MailNotificationScope = 'sender' | 'thread'
export interface MailNotificationRules {
  verified_author: string
  sender: MailNotificationRule
  thread: MailNotificationRule
}
export type AttentionView = 'follow_up' | 'saved' | 'snoozed' | 'muted' | 'reminders'
export interface AttentionStatus {
  follow_up: boolean
  saved: boolean
  muted: boolean
  snooze_until: number | null
  remind_at: number | null
}
export type CategoryRule = 'automatic' | 'inbox' | 'newsletters' | 'receipts'
export interface MessagePlacement {
  original_folder: string
  reason: '' | 'sender_rule' | 'mailing_list' | 'receipt_subject' | 'sender_review' | 'spam_filter' | 'junk_feedback' | 'not_junk_feedback'
  verified_author: string
  rule: CategoryRule
}
export interface Conversation { id: string, count: number, unread: number, matching: number, latest: MessageSummary, members: MessageSummary[] }
export interface IndexProgress { indexed: number, total: number, pending: boolean }
export interface MessagePage { items: MessageSummary[], threads: Conversation[], page: number, total: number, message_total: number, conversations: boolean, index?: IndexProgress }
export interface LibraryAttachment { index: number, size: number, filename: string, content_type: string, message: MessageSummary }
export interface PrivateCollection { id: string, name: string, revision: number, included: boolean }
export interface PrivateEntry {
  id: string
  kind: 'note' | 'clip'
  body: string
  source_subject: string
  created_at: number
  revision: number
}
export interface PrivateMessageTools {
  label: { value: string, revision: string }
  entries: PrivateEntry[]
  collections: PrivateCollection[]
  clip_source: string
}
export interface AttachmentPage { items: LibraryAttachment[], page: number, total: number, index: IndexProgress }
export interface Folder { name: string, unread: number, total: number }
export interface User { username: string, email: string }
export interface Contact { name: string, address: string }
export interface AddressBookCard {
  uid: string
  card_uid: string
  name: string
  note: string
  kind: 'contact' | 'group'
  emails: string[]
  members: string[]
  etag: string
}
export interface AddressBook { books: string[], book: string, cards: AddressBookCard[] }
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
export interface SenderIdentity { id: string, address: string }
export interface SharedReplyContext { team: string, sourceId: string, reference: string, messageRevision: string }
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
  clearFollowUp?: boolean
  sendId?: string
  delaySeconds?: number
  scheduleAt?: number | null
  senderId?: string | null
  sharedReply?: SharedReplyContext | null
}
export interface DraftAck { ok: boolean, uid: number, draftId: string, revision: number }
export interface DraftDocument { draftId: string, revision: number, uid: number, state: string, message: ComposePayload }
export interface SendResult { message_id: string, delivered: number, failed: string[], sent_saved: boolean, unknown?: string[] }
export interface OutboxSummary { id: string, state: string, dueAt: number, scheduled?: boolean, message: Pick<ComposePayload, 'subject' | 'to'>, result: SendResult | null, error: string | null }
export interface OutboxItem extends OutboxSummary { serverTime: number, message: ComposePayload }
export type OutboxView = 'upcoming' | 'review' | 'history'
export type OutboxCounts = Record<OutboxView, number>
export interface OutboxPage { items: OutboxSummary[], counts: OutboxCounts, nextCursor: string | null, tracked: OutboxSummary | null, serverTime: number }
export type BulkAction = 'move' | 'trash' | 'read' | 'unread' | 'flag' | 'unflag' | 'purge' | 'junk' | 'not_junk'
export interface ActionResult extends MessageRef { ok: boolean, new_uid: number | null, new_folder: string | null, error_code: string | null }
export interface BulkResult { ok: boolean, results: ActionResult[], undoId: string | null, expiresAt: number | null }
export interface MailLimits { maxFileBytes: number, maxTotalBytes: number, maxCount: number, maxMessageBytes: number, undoSendSeconds: number, calendarAvailable?: boolean, sharedInboxesAvailable?: boolean, junkFolder?: string }
