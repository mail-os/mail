export interface InvitationTime {
  wall: number
  zone: string | null
  all_day: boolean
}

export interface InvitationPreview {
  method: 'request' | 'cancel'
  uid: string
  organizer: string
  organizer_verified: boolean
  for_mailbox: boolean
  sequence: number
  dtstamp: number
  occurrence: InvitationTime | null
  this_and_future: boolean
  summary: string | null
  location: string | null
  start: InvitationTime | null
  end: InvitationTime | null
}

export type InvitationResponse = 'accepted' | 'tentative' | 'declined'
export interface InvitationRsvp {
  decision: { sequence: number, dtstamp: number, response: InvitationResponse, sendId: string }
  state: string
}
export interface InvitationAction { status: InvitationRsvp | null }

export const invitationResponses = [
  { value: 'accepted', label: 'Accept', icon: 'check' },
  { value: 'tentative', label: 'Tentative', icon: 'clock' },
  { value: 'declined', label: 'Decline', icon: 'close' },
] as const

export function invitationRevision(invite: InvitationPreview, status: InvitationRsvp): number {
  return invite.sequence - status.decision.sequence || invite.dtstamp - status.decision.dtstamp
}

export function rsvpPending(status: InvitationRsvp | null | undefined): boolean {
  return status?.state === 'pending' || status?.state === 'sending'
}

export function rsvpLabel(invite: InvitationPreview, status: InvitationRsvp): string {
  if (invitationRevision(invite, status) < 0) return 'You responded to a newer version of this invitation.'
  if (rsvpPending(status)) return 'Sending RSVP…'
  if (status.state === 'unknown') return 'Delivery is unconfirmed. Check Outbox and Sent.'
  if (invitationRevision(invite, status) > 0) return 'The organizer updated this invitation. You can respond again.'
  if (status.state === 'failed' || status.state === 'cancelled') return 'The RSVP was not sent. Choose your response to retry.'
  const labels = { accepted: 'Acceptance sent.', tentative: 'Tentative response sent.', declined: 'Decline sent.' }
  return labels[status.decision.response]
}

const dateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'full', timeZone: 'UTC' })
const timeFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' })

export function invitationTime(time: InvitationTime, exclusiveEnd = false): string {
  // Format the organizer's wall clock as supplied, including custom TZIDs and
  // floating times which do not identify an instant in the reader's zone.
  const wall = new Date((time.wall - (exclusiveEnd && time.all_day ? 86400 : 0)) * 1000)
  if (time.all_day)
    return dateFormatter.format(wall)
  return `${timeFormatter.format(wall)} · ${time.zone ?? 'Local time'}`
}

export function invitationLabel(invitation: InvitationPreview): string {
  if (invitation.method === 'cancel')
    return 'Calendar cancellation'
  return invitation.sequence > 0 ? 'Calendar update' : 'Calendar invitation'
}
