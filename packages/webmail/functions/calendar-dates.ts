export type CalendarView = 'day' | 'week' | 'month' | 'agenda'

const daySeconds = 86_400
const zonedFormatters = new Map<string, Intl.DateTimeFormat>()
const dateOnly = /^\d{4}-\d{2}-\d{2}$/
const localTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/

export const browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone
export const calendarTimeZones = [...new Set([browserTimeZone, 'UTC', ...(Intl.supportedValuesOf?.('timeZone') ?? [])])].sort()

export function allDayInstant(day: string): number | null {
  if (!dateOnly.test(day)) return null
  const stamp = Date.parse(`${day}T00:00:00Z`)
  return Number.isFinite(stamp) && new Date(stamp).toISOString().slice(0, 10) === day ? stamp / 1000 : null
}

export function utcDay(instant: number): string {
  return new Date(instant * 1000).toISOString().slice(0, 10)
}

export function addCalendarDays(day: string, count: number): string {
  return utcDay(Date.parse(`${day}T00:00:00Z`) / 1000 + count * daySeconds)
}

export function zonedDateTime(instant: number, zone: string): string {
  let formatter = zonedFormatters.get(zone)
  if (!formatter) {
    formatter = new Intl.DateTimeFormat('en-CA', {
      timeZone: zone, calendar: 'iso8601', numberingSystem: 'latn',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    })
    zonedFormatters.set(zone, formatter)
  }
  const fields = Object.fromEntries(formatter.formatToParts(new Date(instant * 1000)).map(part => [part.type, part.value]))
  return `${fields.year.padStart(4, '0')}-${fields.month}-${fields.day}T${fields.hour}:${fields.minute}:${fields.second}`
}

export function zonedDay(instant: number, zone: string): string {
  return zonedDateTime(instant, zone).slice(0, 10)
}

/** An ambiguous wall time resolves to the first occurrence. A gap has no instant. */
export function instantForLocal(input: string, zone: string): number | null {
  if (!localTime.test(input)) return null
  const wallTime = input.length === 16 ? `${input}:00` : input
  const naive = Date.parse(`${wallTime}Z`) / 1000
  if (!Number.isFinite(naive) || new Date(naive * 1000).toISOString().slice(0, 19) !== wallTime) return null
  const offsets = [naive - daySeconds, naive, naive + daySeconds].map(sample =>
    Date.parse(`${zonedDateTime(sample, zone)}Z`) / 1000 - sample)
  const matching = offsets.map(offset => naive - offset).filter(instant => zonedDateTime(instant, zone) === wallTime)
  return matching.length ? Math.min(...matching) : null
}

export function startOfZonedDay(day: string, zone: string): number {
  const midnight = instantForLocal(`${day}T00:00`, zone)
  if (midnight !== null) return midnight
  // Handle midnight offset changes and civil dates skipped by a zone change.
  const dayStamp = Date.parse(`${day}T00:00:00Z`) / 1000
  let before = dayStamp - daySeconds * 2
  let after = dayStamp + daySeconds * 2
  while (before + 1 < after) {
    const middle = Math.floor((before + after) / 2)
    if (zonedDay(middle, zone) < day) before = middle
    else after = middle
  }
  return after
}

function weekStart(day: string): string {
  const weekday = new Date(`${day}T00:00:00Z`).getUTCDay()
  return addCalendarDays(day, -((weekday + 6) % 7))
}

function monthStart(day: string, shift: number): string {
  const date = new Date(`${day.slice(0, 7)}-01T00:00:00Z`)
  date.setUTCMonth(date.getUTCMonth() + shift)
  return date.toISOString().slice(0, 10)
}

export function calendarRange(view: CalendarView, day: string): { start: string, end: string } {
  switch (view) {
    case 'day': return { start: day, end: addCalendarDays(day, 1) }
    case 'week': {
      const start = weekStart(day)
      return { start, end: addCalendarDays(start, 7) }
    }
    case 'month': {
      const start = weekStart(monthStart(day, 0))
      return { start, end: addCalendarDays(weekStart(addCalendarDays(monthStart(day, 1), -1)), 7) }
    }
    case 'agenda': return { start: day, end: addCalendarDays(day, 30) }
  }
}

export function shiftCalendarDay(view: CalendarView, day: string, count: number): string {
  if (view === 'month') return monthStart(day, count)
  return addCalendarDays(day, count * (view === 'week' ? 7 : view === 'agenda' ? 30 : 1))
}

export function formatCalendarDay(day: string, options: Intl.DateTimeFormatOptions): string {
  return new Intl.DateTimeFormat(undefined, { ...options, timeZone: 'UTC' }).format(new Date(`${day}T00:00:00Z`))
}

export function eventOverlaps(start: number, end: number | null, from: number, until: number, allDay: boolean): boolean {
  return from < until && start < until && (start >= from || (end ?? start + (allDay ? daySeconds : 0)) > from)
}
