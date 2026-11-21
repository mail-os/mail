import { derived, state } from '@stacksjs/stx'
import { createMailApi } from './mail-api'
import type { User } from './mail-types'

interface Calendar {
  id: number
  name: string
}

interface CalendarEvent {
  id: number
  summary: string
  location: string | null
  start: number
  end: number | null
  all_day: boolean
  recurrence_rule: string | null
  status: 'tentative' | 'confirmed' | 'cancelled'
}

function dayStart(): Date {
  const date = new Date()
  date.setHours(0, 0, 0, 0)
  return date
}

function addDays(date: Date, count: number): Date {
  const next = new Date(date)
  next.setDate(next.getDate() + count)
  return next
}

const dateLabel = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })
const dateTimeLabel = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const allDayLabel = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' })

function utcDate(date: Date): number {
  return Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()) / 1000
}

function calendarEventDate(event: CalendarEvent): string {
  const date = new Date(event.start * 1000)
  return event.all_day ? `${allDayLabel.format(date)} · All day` : dateTimeLabel.format(date)
}

export function useMailCalendar(onAuthError: () => void) {
  const account = state<string | undefined>(undefined)
  const calendars = state<Calendar[]>([])
  const activeCalendar = state<number | null>(null)
  const startDay = state(dayStart())
  const events = state<CalendarEvent[]>([])
  const ordinaryEvents = derived(() => events().filter(event => !event.recurrence_rule))
  const recurringSeries = derived(() => events().filter(event => event.recurrence_rule))
  const rangeLabel = derived(() => `${dateLabel.format(startDay())} – ${dateLabel.format(addDays(startDay(), 6))}`)
  const loading = state(true)
  const error = state('')
  let request: AbortController | undefined
  const api = createMailApi(account, () => {
    request?.abort()
    account.set(undefined)
    calendars.set([])
    activeCalendar.set(null)
    events.set([])
    onAuthError()
  })

  async function refresh() {
    request?.abort()
    const pending = new AbortController()
    request = pending
    loading.set(true)
    error.set('')
    events.set([])
    const signal = AbortSignal.any([pending.signal, AbortSignal.timeout(10_000)])
    try {
      if (!account()) {
        const { user } = await api<{ user: User }>('/webmail/auth/me', { signal })
        if (pending.signal.aborted) return
        account.set(user.username)
      }
      const { calendars: visible } = await api<{ calendars: Calendar[] }>('/webmail/api/calendars', { signal })
      if (pending.signal.aborted) return
      calendars.set(visible)
      const selected = visible.find(calendar => calendar.id === activeCalendar()) ?? visible[0]
      activeCalendar.set(selected?.id ?? null)
      if (!selected) return
      const start = startDay()
      const end = addDays(start, 7)
      const firstInstant = Math.floor(start.getTime() / 1000)
      const lastInstant = Math.floor(end.getTime() / 1000)
      const firstDate = utcDate(start)
      const lastDate = utcDate(end)
      const params = new URLSearchParams({
        calendarId: String(selected.id),
        start: String(Math.min(firstInstant, firstDate)),
        end: String(Math.max(lastInstant, lastDate)),
      })
      const result = await api<{ events: CalendarEvent[] }>(`/webmail/api/calendar-events?${params}`, { signal })
      if (!pending.signal.aborted) {
        events.set(result.events.filter((event) => {
          const from = event.all_day ? firstDate : firstInstant
          const until = event.all_day ? lastDate : lastInstant
          const eventEnd = event.end ?? event.start + (event.all_day ? 86400 : 0)
          return event.start < until && (event.recurrence_rule || event.start >= from || eventEnd > from)
        }))
      }
    }
    catch (cause) {
      if (!pending.signal.aborted)
        error.set(cause instanceof Error ? cause.message : 'Could not load your calendar.')
    }
    finally {
      if (request === pending) loading.set(false)
    }
  }

  function selectCalendar(id: number) {
    activeCalendar.set(id)
    return refresh()
  }

  function shiftWeek(count: number) {
    startDay.set(addDays(startDay(), 7 * count))
    return refresh()
  }

  function goToToday() {
    startDay.set(dayStart())
    return refresh()
  }

  return {
    account, calendars, activeCalendar, ordinaryEvents, recurringSeries, rangeLabel, loading, error,
    refresh, selectCalendar, shiftWeek, goToToday, calendarEventDate, destroy: () => request?.abort(),
  }
}
