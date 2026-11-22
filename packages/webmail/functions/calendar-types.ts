export interface Calendar {
  id: number
  name: string
  display_name?: string | null
  color: string | null
}

export type CalendarAccess = 'viewer' | 'editor' | 'free_busy'

export interface CalendarShare {
  team: string
  source: string
  grantee: string
  calendarId: number
  calendarName: string
  displayName?: string | null
  access: CalendarAccess
}

export const calendarAccessLabels = {
  viewer: 'View events',
  editor: 'Edit events',
  free_busy: 'Free/busy only',
}

export interface CalendarEvent {
  id: number
  calendar_id: number
  summary: string
  location: string | null
  start: number
  end: number | null
  all_day: boolean
  recurrence_rule: string | null
  recurring: boolean
  icalendar?: string | null
  status: 'tentative' | 'confirmed' | 'cancelled'
  etag: string
}

export interface CalendarEventDetail {
  event: CalendarEvent
  calendarId: number
  description: string | null
  icalendar?: string | null
}

export function calendarColor(color: string | null | undefined): string {
  return color && /^#[0-9a-f]{6}(?:[0-9a-f]{2})?$/i.test(color) ? color.slice(0, 7) : '#0a73da'
}
