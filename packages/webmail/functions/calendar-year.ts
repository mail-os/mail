import { addCalendarDays, allDayInstant, calendarRange, eventOverlaps, monthStart, startOfZonedDay } from './calendar-dates'

interface EventTime { start: number, end: number | null, all_day: boolean }
export interface BusyPeriod { start: number, end: number }

const fullDate = new Intl.DateTimeFormat(undefined, { dateStyle: 'full', timeZone: 'UTC' })
const monthName = new Intl.DateTimeFormat(undefined, { month: 'long', timeZone: 'UTC' })

/** Keep the zoned and all-day bounds well inside the server's 366-day window. */
export function calendarYearWindows(day: string) {
  const { start } = calendarRange('year', day)
  return Array.from({ length: 4 }, (_, index) => ({
    start: monthStart(start, index * 3),
    end: monthStart(start, index * 3 + 3),
  }))
}

export function calendarYear(day: string, zone: string, today: string, events: EventTime[], busy: BusyPeriod[]) {
  const { start } = calendarRange('year', day)
  let from = startOfZonedDay(start, zone)
  return Array.from({ length: 12 }, (_, index) => {
    const first = monthStart(start, index)
    const end = monthStart(start, index + 1)
    const firstDate = new Date(first + 'T00:00:00Z')
    const days = []
    for (let date = first; date < end; date = addCalendarDays(date, 1)) {
      const next = addCalendarDays(date, 1)
      const until = startOfZonedDay(next, zone)
      const dateFrom = allDayInstant(date)!
      const dateUntil = allDayInstant(next)!
      let count = 0
      for (const event of events) {
        if (eventOverlaps(event.start, event.end, event.all_day ? dateFrom : from,
          event.all_day ? dateUntil : until, event.all_day)) count++
      }
      days.push({
        date, label: fullDate.format(dateFrom * 1000), number: Number(date.slice(8)),
        today: date === today, count,
        busy: busy.some(period => eventOverlaps(period.start, period.end, from, until, false)),
      })
      from = until
    }
    return { id: first, name: monthName.format(firstDate), firstColumn: (firstDate.getUTCDay() + 6) % 7 + 1, days }
  })
}

const dateSteps: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 }

export function nextYearDate(day: string, key: string): string | null {
  let step = dateSteps[key]
  if (key === 'Home' || key === 'End') {
    const offset = (new Date(day + 'T00:00:00Z').getUTCDay() + 6) % 7
    step = key === 'Home' ? -offset : 6 - offset
  }
  if (step === undefined || !Number.isInteger(step)) return null
  const next = addCalendarDays(day, step)
  const { start, end } = calendarRange('year', day)
  return next < start ? start : next >= end ? addCalendarDays(end, -1) : next
}
