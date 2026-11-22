import { instantForLocal } from './calendar-dates'

export interface TimeWindow { start: number, end: number }

export function freeTimeWindow(date: string, startTime: string, endTime: string, zone: string): TimeWindow | null {
  const start = instantForLocal(`${date}T${startTime}`, zone)
  const end = instantForLocal(`${date}T${endTime}`, zone)
  return start === null || end === null || end <= start ? null : { start, end }
}

/** Return the ordered complement of busy intervals in a half-open window. */
export function freeTimeRanges(window: TimeWindow, busy: TimeWindow[], minimumSeconds: number): TimeWindow[] {
  if (!Array.isArray(busy)) throw new Error('The calendar returned no availability data.')
  const intervals = busy.map(({ start, end }) => {
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end <= start)
      throw new Error('The calendar returned an invalid busy period.')
    return { start: Math.max(window.start, start), end: Math.min(window.end, end) }
  }).filter(period => period.start < period.end)
    .sort((left, right) => left.start - right.start)
  const free: TimeWindow[] = []
  let start = window.start
  for (const busyPeriod of intervals) {
    if (busyPeriod.start - start >= minimumSeconds) free.push({ start, end: busyPeriod.start })
    start = Math.max(start, busyPeriod.end)
  }
  if (window.end - start >= minimumSeconds) free.push({ start, end: window.end })
  return free
}

export function formatFreeTime(window: TimeWindow, slots: TimeWindow[], zone: string) {
  const hasSeconds = slots.some(slot => slot.start % 60 || slot.end % 60)
  const options: Intl.DateTimeFormatOptions = { hour: 'numeric', minute: '2-digit', second: hasSeconds ? '2-digit' : undefined, timeZone: zone }
  const format = new Intl.DateTimeFormat(undefined, options)
  const withOffset = new Intl.DateTimeFormat(undefined, { ...options, timeZoneName: 'shortOffset' })
  const offset = (seconds: number) => withOffset.formatToParts(seconds * 1000).find(part => part.type === 'timeZoneName')?.value
  const clock = offset(window.start) === offset(window.end) ? format : withOffset
  return slots.map(({ start, end }) => ({
    start,
    time: `${clock.format(start * 1000)} – ${clock.format(end * 1000)}`,
    minutes: Math.floor((end - start) / 60),
  }))
}
