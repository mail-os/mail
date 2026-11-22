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
