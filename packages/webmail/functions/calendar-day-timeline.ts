import { addCalendarDays, allDayInstant, eventOverlaps, startOfZonedDay, zonedDateTime } from './calendar-dates'
import type { TimeWindow } from './calendar-free-time'
import type { CalendarEvent } from './calendar-types'

const minute = 60
const hour = 60 * minute
const quarterHour = 15 * minute
const minimumCardMinutes = 20

interface TimelineLabels {
  label: string
  startLabel: string
}

interface TimelineEvent<T> extends TimelineLabels {
  event: T
  startMinute: number
  duration: number
  lane: number
  lanes: number
}

function positionEvents<T extends CalendarEvent>(events: T[], start: number, end: number,
  timeLabels: (start: number, end: number | null) => TimelineLabels): TimelineEvent<T>[] {
  const positioned: TimelineEvent<T>[] = []
  let groupStart = 0
  let groupEnd = 0
  let laneEnds: number[] = []

  function finishGroup() {
    for (let i = groupStart; i < positioned.length; i++) positioned[i].lanes = laneEnds.length
    groupStart = positioned.length
    laneEnds = []
    groupEnd = 0
  }

  const ordered = events.filter(event => !event.all_day && eventOverlaps(event.start, event.end, start, end, false))
    .sort((a, b) => a.start - b.start || (b.end ?? b.start) - (a.end ?? a.start) || a.id - b.id)
  for (const event of ordered) {
    const startMinute = (Math.max(event.start, start) - start) / minute
    const duration = Math.max(0, (Math.min(event.end ?? event.start, end) - start) / minute - startMinute)
    const endMinute = startMinute + Math.max(duration, minimumCardMinutes)
    if (startMinute >= groupEnd) finishGroup()
    const available = laneEnds.findIndex(laneEnd => laneEnd <= startMinute)
    const lane = available === -1 ? laneEnds.length : available
    laneEnds[lane] = endMinute
    groupEnd = Math.max(groupEnd, endMinute)
    positioned.push({ event, startMinute, duration, lane, lanes: 1, ...timeLabels(event.start, event.end) })
  }
  finishGroup()
  return positioned
}

function clippedBusy(periods: TimeWindow[], start: number, end: number): TimeWindow[] {
  const merged: TimeWindow[] = []
  const ordered = periods.map(period => ({ start: Math.max(period.start, start), end: Math.min(period.end, end) }))
    .filter(period => period.start < period.end).sort((a, b) => a.start - b.start)
  for (const period of ordered) {
    const previous = merged.at(-1)
    if (previous && period.start <= previous.end) previous.end = Math.max(previous.end, period.end)
    else merged.push(period)
  }
  return merged
}

export function calendarDayTimeline<T extends CalendarEvent>(day: string, zone: string, events: T[], periods: TimeWindow[]) {
  const next = addCalendarDays(day, 1)
  const start = startOfZonedDay(day, zone)
  const end = startOfZonedDay(next, zone)
  const minutes = (end - start) / minute
  const dayStart = allDayInstant(day)!
  const dayEnd = allDayInstant(next)!
  const options: Intl.DateTimeFormatOptions = { timeZone: zone, hour: 'numeric', minute: '2-digit' }
  const clock = new Intl.DateTimeFormat(undefined, options)
  const offsetClock = new Intl.DateTimeFormat(undefined, { ...options, timeZoneName: 'shortOffset' })
  const offset = (stamp: number, wall: string) => Date.parse(`${wall}Z`) / 1000 - stamp

  const quarters: { stamp: number, wallTime: string, offset: number }[] = []
  const wallCounts = new Map<string, number>()
  for (let stamp = start; stamp < end; stamp += quarterHour) {
    const wall = zonedDateTime(stamp, zone)
    const wallTime = wall.slice(11, 16)
    wallCounts.set(wallTime, (wallCounts.get(wallTime) ?? 0) + 1)
    quarters.push({ stamp, wallTime, offset: offset(stamp, wall) })
  }
  const offsetChanges = quarters.some(slot => slot.offset !== quarters[0].offset)
  const ticks = []
  const slots = []
  for (const [index, quarter] of quarters.entries()) {
    const { stamp, wallTime } = quarter
    const repeated = wallCounts.get(wallTime)! > 1
    const label = (repeated ? offsetClock : clock).format(stamp * 1000)
    const startMinute = (stamp - start) / minute
    const tick = index === 0 || wallTime.endsWith(':00') || quarter.offset !== quarters[index - 1].offset
    if (tick) ticks.push({ minute: startMinute, label, repeated })
    slots.push({ stamp, value: String(stamp), label, wallTime })
  }
  const format = offsetChanges ? offsetClock : clock
  const timeLabels = (start: number, end: number | null) => {
    const startLabel = format.format(start * 1000)
    const label = end === null || end <= start ? startLabel : `${startLabel} – ${format.format(end * 1000)}`
    return { label, startLabel }
  }
  const timed = positionEvents(events, start, end, timeLabels)
  const allDay = events.filter(event => event.all_day && eventOverlaps(event.start, event.end, dayStart, dayEnd, true))
  const busy = clippedBusy(periods, start, end).map(period => ({
    startMinute: (period.start - start) / minute,
    duration: (period.end - period.start) / minute,
    label: timeLabels(period.start, period.end).label,
  }))
  const defaultSlot = slots.find(slot => slot.wallTime >= '09:00') ?? slots[0]
  const first = Math.min(timed[0]?.startMinute ?? Infinity, busy[0]?.startMinute ?? Infinity)
  const anchor = Number.isFinite(first) ? Math.max(0, (Math.floor(first / 60) - 1) * 60)
    : defaultSlot ? Math.max(0, (defaultSlot.stamp - start - hour) / minute) : 0

  return {
    minutes, ticks, slots, defaultSlot, anchor, allDay, timed, busy,
    lanes: timed.reduce((most, item) => Math.max(most, item.lanes), 1),
  }
}
