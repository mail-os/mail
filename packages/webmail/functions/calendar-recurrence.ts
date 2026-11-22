import ICAL from 'ical.js'
import { addCalendarDays, eventOverlaps, instantForLocal, startOfZonedDay, utcDay, zonedDateTime } from './calendar-dates'
import { recurrenceRule, repeatFromEvent, timeFromStamp } from './calendar-repeat'
import type { CalendarRepeat, CalendarWallTime } from './calendar-repeat'
import { displayAlarms, reminderPreference, setReminder } from './calendar-alarms'
import type { AlarmPreference, DisplayAlarm, ReminderChoice } from './calendar-alarms'
import type { CalendarEvent } from './calendar-types'

type Component = ICAL.Component
type Event = ICAL.Event
type Period = ICAL.Period
type Property = ICAL.Property
type Recur = ICAL.Recur
type Time = ICAL.Time
type Timezone = ICAL.Timezone

const day = 86_400
const maxIterations = 8000
const maxInstances = 1000
const timeProperties = ['dtstart', 'dtend', 'recurrence-id', 'rdate', 'exdate']
const observedDays = new WeakMap<Timezone, Map<number, WallTransition | null>>()

interface WallTransition { boundary: number, before: number, after: number }

export interface OccurrenceRef {
  /** Typed recurrence ID as a stable calendar date or resolved instant. */
  key: string
  original: number
}

export interface CalendarOccurrence extends CalendarEvent {
  occurrence: OccurrenceRef
  description: string
  canEditOccurrence: boolean
  reminder: AlarmPreference
}

type Series = {
  calendar: Component
  master: Event
  exceptions: Map<string, Event>
  floatingZone: string
  pending: number
}

interface Candidate {
  time: Time
  period?: Period
}

export interface RecurrenceBudget { remaining: number }

function zoneOf(calendar: Component, property: Property | null): string | undefined {
  const id = property?.getParameter('tzid')
  return typeof id === 'string' && !calendar.getTimeZoneByID(id) ? id : undefined
}

function readSeries(source: string, zone: string): Series {
  const calendar = new ICAL.Component(ICAL.parse(source))
  const components = calendar.getAllSubcomponents('vevent')
  const masters = components.filter(component => !component.hasProperty('recurrence-id'))
  if (calendar.name !== 'vcalendar' || masters.length !== 1) throw new Error('This calendar resource has no single series.')
  const definition = masters[0]
  const zoneIds = new Set<string>()
  for (const component of components) {
    for (const name of timeProperties) {
      for (const property of component.getAllProperties(name)) {
        const unbound = zoneOf(calendar, property)
        if (unbound) zoneIds.add(unbound)
      }
    }
  }
  if (zoneIds.size > 1) throw new Error('This series has several time zones without definitions.')
  const floatingZone = zoneIds.values().next().value ?? zone
  if (zoneIds.size) new Intl.DateTimeFormat('en', { timeZone: floatingZone })
  const master = new ICAL.Event(definition, {
    strictExceptions: true,
    exceptions: components.filter(component => component !== definition),
  })
  if (!master.startDate) throw new Error('This series has no start date.')
  const exceptions = new Map<string, Event>()
  for (const item of Object.values(master.exceptions)) {
    const key = recurrenceKey(item.recurrenceId, floatingZone)
    if (!key || exceptions.has(key)) throw new Error('This series has invalid or duplicate exceptions.')
    exceptions.set(key, item)
  }
  return { calendar, master, exceptions, floatingZone, pending: maxIterations }
}

function instant(time: Time, zone: string, generated = false): number | null {
  if (time.isDate || time.zone === ICAL.Timezone.utcTimezone) return time.toUnixTime()
  if (time.zone === ICAL.Timezone.localTimezone) return instantForLocal(time.toString(), zone)
  const wallTime = Date.parse(`${time.toString()}Z`) / 1000
  const transition = wallTransition(time.zone, wallTime)
  if (transition && wallTime >= transition.boundary && wallTime < transition.boundary + Math.abs(transition.after - transition.before)) {
    if (generated && transition.after > transition.before) return null
    return wallTime - transition.before
  }
  return time.toUnixTime()
}

/** Find the first affected local second from the embedded VTIMEZONE.
 * The public utcOffset method switches at the lower wall-clock boundary.
 */
function wallTransition(zone: Timezone, wallTime: number): WallTransition | null {
  let days = observedDays.get(zone)
  if (!days) {
    days = new Map()
    observedDays.set(zone, days)
  }
  const date = Math.floor(wallTime / day) * day
  const cached = days.get(date)
  if (cached !== undefined) return cached

  const clock = new ICAL.Time({ year: 1970, month: 1, day: 1, isDate: false }, ICAL.Timezone.utcTimezone)
  function offset(local: number): number {
    clock.fromUnixTime(local)
    return zone.utcOffset(clock)
  }
  let left = date - day / 2
  let right = date + 3 * day / 2
  const before = offset(left)
  const after = offset(right)
  if (before === after) {
    days.set(date, null)
    return null
  }
  while (left + 1 < right) {
    const middle = Math.floor((left + right) / 2)
    if (offset(middle) === before) left = middle
    else right = middle
  }
  const transition = { boundary: right, before, after }
  days.set(date, transition)
  return transition
}

function recurrenceKey(time: Time, zone: string): string | null {
  const stamp = instant(time, zone)
  return stamp === null ? null : `${time.isDate ? 'date' : 'time'}:${stamp}`
}

function recurrenceStatus(event: Event): CalendarEvent['status'] {
  const status = event.component.getFirstPropertyValue('status')
  if (status === 'CANCELLED') return 'cancelled'
  if (status === 'TENTATIVE') return 'tentative'
  return 'confirmed'
}

function datesFrom(component: Component, name: string): (Time | Period)[] {
  return component.getAllProperties(name).flatMap(property => property.getValues() as (Time | Period)[])
}

function* candidates(series: Series, through: number, budget: RecurrenceBudget): Generator<Candidate> {
  const { master, floatingZone } = series
  // RDATE periods carry a duration specific to the instance. Yield them
  // before the base start or rule so they take precedence when IDs coincide.
  for (const date of datesFrom(master.component, 'rdate')) {
    if (date instanceof ICAL.Period) yield { time: date.start, period: date }
    else yield { time: date }
  }
  yield { time: master.startDate }

  for (const property of master.component.getAllProperties('rrule')) {
    const rule = (property.getFirstValue() as Recur).clone()
    const count = rule.count
    const last = rule.until ? instant(rule.until, floatingZone) : null
    rule.count = null
    rule.until = null
    const iterator = rule.iterator(master.startDate)
    let emitted = 0
    while (count === null || emitted < count) {
      if (series.pending-- <= 0 || budget.remaining-- <= 0) throw new Error('This recurrence is too dense for the calendar view.')
      const next: Time | null = iterator.next()
      if (!next) break
      // A nonexistent local time does not consume a COUNT slot.
      const stamp = instant(next, floatingZone, true)
      if ((stamp ?? next.toUnixTime()) > through + day * 2) break
      if (stamp === null) continue
      if (last !== null && stamp > last) break
      emitted++
      yield { time: next.clone() }
    }
  }
}

function excludedDates(series: Series) {
  const ids = new Set<string>()
  const dates = new Set<string>()
  for (const value of datesFrom(series.master.component, 'exdate')) {
    if (!(value instanceof ICAL.Time)) continue
    const key = recurrenceKey(value, series.floatingZone)
    if (key) ids.add(key)
    if (value.isDate) dates.add(value.toString())
  }
  return (time: Time, key: string) => ids.has(key) || dates.has(time.toString().slice(0, 10))
}

interface ResolvedOccurrence {
  row: CalendarOccurrence
  owner: Event
  start: Time
  end: Time | null
}

function instance(series: Series, candidate: Candidate, event: CalendarEvent): ResolvedOccurrence | null {
  const { time, period } = candidate
  const original = instant(time, series.floatingZone)
  const key = recurrenceKey(time, series.floatingZone)
  if (key === null || original === null) return null

  const detached = series.exceptions.get(key)
  if (detached && recurrenceStatus(detached) === 'cancelled') return null
  const details = detached
    ? { item: detached, startDate: detached.startDate, endDate: detached.endDate }
    : series.master.getOccurrenceDetails(time)
  const status = recurrenceStatus(details.item)
  if (status === 'cancelled' || !details.startDate) return null

  const actualEnd = period && details.item === series.master ? period.getEnd() : details.endDate
  const start = instant(details.startDate, series.floatingZone)
  let end = actualEnd ? instant(actualEnd, series.floatingZone) : null
  if (start === null) return null
  if (!period && !detached && details.item.component.hasProperty('dtend')) {
    // DTEND specifies an exact duration for every occurrence of the rule.
    const baseStart = instant(details.item.startDate, series.floatingZone)
    const baseEnd = instant(details.item.endDate, series.floatingZone)
    if (baseStart !== null && baseEnd !== null) end = start + baseEnd - baseStart
  }
  const row = {
    ...event,
    summary: details.item.summary ?? series.master.summary ?? event.summary,
    description: details.item.description ?? series.master.description ?? '',
    location: details.item.location ?? series.master.location ?? null,
    start,
    end: end !== null && end > start ? end : null,
    all_day: details.startDate.isDate,
    status,
    occurrence: { key, original },
    canEditOccurrence: !detached?.modifiesFuture(),
    reminder: reminderPreference(details.item.component),
  }
  return { row, owner: details.item, start: details.startDate, end: actualEnd || null }
}

function shifts(series: Series) {
  let later = 0
  let earlier = 0
  for (const item of series.exceptions.values()) {
    if (!item.modifiesFuture() || !item.startDate) continue
    const moved = instant(item.startDate, series.floatingZone)
    const original = instant(item.recurrenceId, series.floatingZone)
    if (moved === null || original === null) continue
    later = Math.max(later, moved - original)
    earlier = Math.max(earlier, original - moved)
  }
  return { earlier, later }
}

export function expandSeries(event: CalendarEvent, source: string, zone: string, start: number, end: number, budget: RecurrenceBudget): CalendarOccurrence[] {
  return expandReadSeries(readSeries(source, zone), event, start, end, budget).map(item => item.row)
}

function expandReadSeries(series: Series, event: CalendarEvent, start: number, end: number, budget: RecurrenceBudget): ResolvedOccurrence[] {
  const { earlier, later } = shifts(series)
  const exclude = excludedDates(series)
  const duration = Math.max(0, series.master.duration.toSeconds(),
    ...[...series.exceptions.values()].filter(item => item.startDate).map(item => item.duration.toSeconds()))
  const seen = new Set<string>()
  const result: ResolvedOccurrence[] = []

  function append(candidate: Candidate, key: string) {
    if (seen.has(key)) return
    seen.add(key)
    const item = instance(series, candidate, event)
    if (item && eventOverlaps(item.row.start, item.row.end, start, end, item.row.all_day)) {
      if (result.length >= maxInstances) throw new Error('This series has too many occurrences in the selected dates.')
      result.push(item)
    }
  }

  // Moved exceptions can appear inside the window even when their original
  // recurrence IDs would never be reached by this window's iteration.
  for (const [key, item] of series.exceptions) append({ time: item.recurrenceId }, key)
  for (const candidate of candidates(series, end + earlier, budget)) {
    const key = recurrenceKey(candidate.time, series.floatingZone)
    if (key === null || exclude(candidate.time, key)) continue
    const stamp = instant(candidate.time, series.floatingZone)!
    if (!candidate.period && (stamp < start - duration - later - day || stamp >= end + earlier + day)) continue
    append(candidate, key)
  }
  return result
}

function findCandidate(series: Series, reference: OccurrenceRef): Candidate | undefined {
  const detached = series.exceptions.get(reference.key)
  if (detached) return { time: detached.recurrenceId }
  const exclude = excludedDates(series)
  for (const candidate of candidates(series, reference.original, { remaining: maxIterations })) {
    const key = recurrenceKey(candidate.time, series.floatingZone)
    if (key === reference.key && !exclude(candidate.time, key)) return candidate
  }
}

export function readOccurrence(event: CalendarEvent, source: string, zone: string, reference: OccurrenceRef): CalendarOccurrence | null {
  const series = readSeries(source, zone)
  const candidate = findCandidate(series, reference)
  return candidate ? instance(series, candidate, event)?.row ?? null : null
}

export interface OccurrenceEdit {
  summary?: string
  description?: string
  location?: string
  time?: { start: number, end: number | null, allDay: boolean }
  cancel?: boolean
  reminder?: ReminderChoice
}

export function editOccurrence(event: CalendarEvent, source: string, zone: string, reference: OccurrenceRef, changes: OccurrenceEdit): string {
  const series = readSeries(source, zone)
  const candidate = findCandidate(series, reference)
  const current = candidate && instance(series, candidate, event)?.row
  if (!candidate || !current) throw new Error('This occurrence is no longer in the series.')
  if (!current.canEditOccurrence) throw new Error('This exception also changes later dates. Edit it through CalDAV.')
  const detached = series.exceptions.get(reference.key)
  const inherited = series.master.getOccurrenceDetails(candidate.time).item
  const target = detached ?? new ICAL.Event(new ICAL.Component(structuredClone(inherited.component.toJSON())))
  if (!detached) {
    for (const name of ['rrule', 'rdate', 'exdate', 'recurrence-id']) target.component.removeAllProperties(name)
    target.recurrenceId = candidate.time
    const missingZone = zoneOf(series.calendar, series.master.component.getFirstProperty('dtstart'))
    if (missingZone && !candidate.time.isDate && candidate.time.zone === ICAL.Timezone.localTimezone)
      target.component.getFirstProperty('recurrence-id')?.setParameter('tzid', missingZone)
    series.calendar.addSubcomponent(target.component)
  }

  if (!detached || changes.time) {
    const timing = changes.time ?? { start: current.start, end: current.end, allDay: current.all_day }
    target.startDate = timeFromStamp(timing.start, timing.allDay)
    if (timing.end !== null) target.endDate = timeFromStamp(timing.end, timing.allDay)
    else {
      target.component.removeAllProperties('dtend')
      target.component.removeAllProperties('duration')
    }
  }
  for (const name of ['summary', 'description', 'location'] as const) {
    const value = changes[name]
    if (value !== undefined) target.component.updatePropertyWithValue(name, value)
    else if (!detached && !target.component.hasProperty(name))
      target.component.updatePropertyWithValue(name, current[name] ?? '')
  }
  if (changes.cancel) target.component.updatePropertyWithValue('status', 'CANCELLED')
  if (changes.reminder !== undefined) setReminder(target.component, changes.reminder, target.summary)
  target.component.updatePropertyWithValue('dtstamp', timeFromStamp(Math.floor(Date.now() / 1000), false))
  return `${series.calendar.toString()}\r\n`
}

export interface SeriesSchedule extends CalendarWallTime {
  repeat: CalendarRepeat
  floating: boolean
  editable: boolean
  embedded: boolean
}

function timeZoneId(event: Event, field: 'dtstart' | 'dtend'): string | undefined {
  const zone = event.component.getFirstProperty(field)?.getParameter('tzid')
  if (typeof zone === 'string') return zone
  const time = event.component.getFirstPropertyValue(field)
  return time instanceof ICAL.Time && time.zone === ICAL.Timezone.utcTimezone ? 'UTC' : undefined
}

function inputDate(time: Time): string {
  if (time.isDate) return time.toString()
  return time.toString().replace(/Z$/, '').replace(/:00$/, '')
}

function scheduleOf(series: Series): SeriesSchedule {
  const { master } = series
  const id = timeZoneId(master, 'dtstart')
  const endZone = timeZoneId(master, 'dtend')
  const zone = id ?? series.floatingZone
  const allDay = master.startDate.isDate
  let editable = !master.component.hasProperty('dtend') || endZone === id
  try { new Intl.DateTimeFormat('en', { timeZone: zone }) }
  catch { editable = false }
  const explicitEnd = master.component.hasProperty('dtend') || master.component.hasProperty('duration')
  const end = explicitEnd ? (allDay ? addCalendarDays(master.endDate.toString(), -1) : inputDate(master.endDate)) : ''
  return {
    start: inputDate(master.startDate), end, allDay, zone, editable, floating: !allDay && id === undefined,
    embedded: Boolean(id && series.calendar.getTimeZoneByID(id)),
    repeat: repeatFromEvent(master, editable ? zone : 'UTC'),
  }
}

export function readSeriesSchedule(source: string, zone: string): SeriesSchedule {
  return scheduleOf(readSeries(source, zone))
}

function defineZone(calendar: Component, clock: CalendarWallTime, floating: boolean, source?: string): Timezone {
  if (clock.allDay || floating) return ICAL.Timezone.localTimezone
  if (clock.zone === 'UTC') return ICAL.Timezone.utcTimezone
  const existing = calendar.getTimeZoneByID(clock.zone)
  if (existing) return existing
  if (!source) throw new Error('The event time zone definition is unavailable.')
  const definition = new ICAL.Component(ICAL.parse(source))
  if (definition.name !== 'vtimezone' || definition.getFirstPropertyValue('tzid') !== clock.zone)
    throw new Error('The event time zone definition is invalid.')
  calendar.addSubcomponent(definition)
  return new ICAL.Timezone({ tzid: clock.zone, component: definition })
}

function wallDate(value: string, allDay: boolean, timezone: Timezone): Time {
  const text = !allDay && value.length === 16 ? `${value}:00` : value
  if (!(allDay ? /^\d{4}-\d{2}-\d{2}$/ : /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/).test(text))
    throw new Error('Enter a valid date or time.')
  const time = ICAL.Time.fromString(text, undefined)
  if (time.toString() !== text) throw new Error('Enter a valid date or time.')
  time.zone = timezone
  return time
}

function setClock(event: Event, clock: CalendarWallTime, timezone: Timezone) {
  const begin = wallDate(clock.start, clock.allDay, timezone)
  const finish = clock.end ? wallDate(clock.allDay ? addCalendarDays(clock.end, 1) : clock.end, clock.allDay, timezone) : null
  const start = instant(begin, clock.zone, true)
  const end = finish ? instant(finish, clock.zone, true) : null
  if (start === null || (finish && end === null)) throw new Error('Enter times that exist in the event time zone.')
  if (end !== null && end <= start) throw new Error('The event must end after it starts.')
  event.startDate = begin
  if (finish) event.endDate = finish
  else {
    event.component.removeAllProperties('dtend')
    event.component.removeAllProperties('duration')
  }
}

function setRepeat(event: Event, repeat: CalendarRepeat, clock: CalendarWallTime, floating: boolean) {
  if (repeat.frequency === 'custom') return
  event.component.removeAllProperties('rrule')
  const cutoff = repeat.frequency !== 'none' && repeat.end === 'date' && repeat.until && !clock.allDay && !floating
    ? instant(wallDate(`${repeat.until}T23:59:59`, false, event.startDate.zone), clock.zone, true) : undefined
  const rule = recurrenceRule(repeat, clock, floating, cutoff)
  if (rule) event.component.addPropertyWithValue('rrule', rule)
}

function setDetails(event: Event, changes: OccurrenceEdit) {
  for (const name of ['summary', 'description', 'location'] as const) {
    const value = changes[name]
    if (value !== undefined) event.component.updatePropertyWithValue(name, value)
  }
  if (changes.reminder !== undefined) setReminder(event.component, changes.reminder, event.summary)
  event.component.updatePropertyWithValue('dtstamp', timeFromStamp(Math.floor(Date.now() / 1000), false))
}

function pickMaster(source: string) {
  const calendar = new ICAL.Component(ICAL.parse(source))
  const masters = calendar.getAllSubcomponents('vevent').filter(event => !event.hasProperty('recurrence-id'))
  if (masters.length !== 1) throw new Error('This calendar resource has no single event to edit.')
  return { calendar, master: new ICAL.Event(masters[0]) }
}

export function readEventReminder(source: string): AlarmPreference {
  return reminderPreference(pickMaster(source).master.component)
}

export function editEventReminder(source: string, changes: OccurrenceEdit): string {
  const { calendar, master } = pickMaster(source)
  setDetails(master, changes)
  return `${calendar.toString()}\r\n`
}

export interface AlarmNotice {
  key: string
  due: number
  summary: string
  message: string
  event: CalendarEvent | CalendarOccurrence
}

function relativeTrigger(alarm: DisplayAlarm, item: ResolvedOccurrence, zone: string, dateZone: string): number | null {
  if (!(alarm.trigger instanceof ICAL.Duration)) return null
  const source = alarm.end ? item.end : item.start
  const timestamp = alarm.end ? item.row.end : item.row.start
  if (!source || timestamp === null) return null
  const duration = alarm.trigger
  const polarity = duration.isNegative ? -1 : 1
  const dayShift = polarity * (duration.days + duration.weeks * 7)
  const elapsed = polarity * (duration.hours * 3600 + duration.minutes * 60 + duration.seconds)
  if (item.row.all_day) return startOfZonedDay(addCalendarDays(utcDay(timestamp), dayShift), dateZone) + elapsed
  if (!dayShift) return timestamp + elapsed
  const wall = source.clone()
  wall.adjust(dayShift, 0, 0, 0)
  const base = instant(wall, zone)
  const unshifted = instant(source, zone)
  return base === null || unshifted === null ? null : base + (timestamp - unshifted) + elapsed
}

export function alarmsInWindow(event: CalendarEvent, source: string, zone: string, start: number, end: number, budget: RecurrenceBudget): AlarmNotice[] {
  const series = readSeries(source, zone)
  const notices = new Map<string, AlarmNotice>()
  const byComponent = new Map<Component, DisplayAlarm[]>()
  let shortest = Infinity
  let longest = -Infinity
  let timeZonePad = event.all_day ? 2 * day : 0

  function emit(alarm: DisplayAlarm, first: number, target: CalendarEvent | CalendarOccurrence, identity: string) {
    const firstIndex = alarm.interval > 0 ? Math.max(0, Math.ceil((start - first) / alarm.interval)) : 0
    for (let index = firstIndex; index <= alarm.repeat; index++) {
      const due = first + index * alarm.interval
      if (due >= end) break
      if (due < start || (alarm.acknowledged !== null && alarm.acknowledged >= due)) continue
      if (notices.size >= maxInstances) throw new Error('Too many reminder firings in this window.')
      const key = `${event.id}:${due}:${identity}`
      notices.set(key, { key, due, summary: target.summary || 'Untitled event', message: alarm.message, event: target })
    }
  }

  for (const item of [series.master, ...series.exceptions.values()]) {
    if (recurrenceStatus(item) === 'cancelled') continue
    const alarms = displayAlarms(item.component)
    byComponent.set(item.component, alarms)
    for (const alarm of alarms) {
      if (alarm.trigger instanceof ICAL.Time) {
        // An absolute alarm belongs to the component and fires once, even
        // when the master has many occurrences.
        const occurrence = item === series.master ? null : instance(series, { time: item.recurrenceId }, event)
        const target = occurrence?.row ?? event
        emit(alarm, alarm.trigger.toUnixTime(), target, `absolute:${occurrence?.row.occurrence.key ?? 'master'}`)
        continue
      }
      shortest = Math.min(shortest, alarm.trigger.toSeconds())
      longest = Math.max(longest, alarm.trigger.toSeconds() + alarm.repeat * alarm.interval)
      if (alarm.trigger.days || alarm.trigger.weeks || item.startDate?.isDate) timeZonePad = 2 * day
    }
  }
  if (shortest !== Infinity) {
    const items = expandReadSeries(series, event, start - longest - timeZonePad - 1, end - shortest + timeZonePad, budget)
    for (const item of items) {
      for (const alarm of byComponent.get(item.owner.component) ?? []) {
        const due = relativeTrigger(alarm, item, series.floatingZone, zone)
        if (due !== null) emit(alarm, due, event.recurring ? item.row : event, item.row.occurrence.key)
      }
    }
  }
  return [...notices.values()]
}

export function createSeriesSource(uid: string, clock: CalendarWallTime, repeat: CalendarRepeat, changes: OccurrenceEdit, zoneSource?: string): string {
  const calendar = new ICAL.Component('vcalendar')
  calendar.addPropertyWithValue('version', '2.0')
  calendar.addPropertyWithValue('prodid', '-//Mail//Webmail Calendar//EN')
  calendar.addPropertyWithValue('calscale', 'GREGORIAN')
  const event = new ICAL.Event()
  event.uid = uid
  calendar.addSubcomponent(event.component)
  setClock(event, clock, defineZone(calendar, clock, false, zoneSource))
  setRepeat(event, repeat, clock, false)
  setDetails(event, changes)
  return `${calendar.toString()}\r\n`
}

function civilSeconds(value: string): number {
  const text = value.length === 10 ? `${value}T00:00` : value.replace(/Z$/, '')
  return Date.parse(`${text}Z`) / 1000
}

function translateException(time: Time, old: SeriesSchedule, next: CalendarWallTime, timezone: Timezone, shift: number): Time {
  if (time.isDate) {
    const days = (civilSeconds(next.start.slice(0, 10)) - civilSeconds(old.start.slice(0, 10))) / day
    return wallDate(addCalendarDays(time.toString(), days), true, ICAL.Timezone.localTimezone)
  }
  const original = instant(time, old.zone)
  if (original === null) throw new Error('An existing exception has an invalid date.')
  // The identity follows the original scheduled wall time. The override's
  // DTSTART and DTEND still represent the user's detached appointment.
  const wall = time.isDate || time.zone === ICAL.Timezone.localTimezone || time.zone.tzid === old.zone
    ? time.toString() : zonedDateTime(original, old.zone)
  const moved = civilSeconds(wall) + shift
  const iso = new Date(moved * 1000).toISOString()
  return wallDate(iso.slice(0, 19), next.allDay, timezone)
}

function writeExcludedDate(event: Event, time: Time) {
  const property = new ICAL.Property('exdate')
  if (!time.isDate && time.zone !== ICAL.Timezone.utcTimezone && time.zone !== ICAL.Timezone.localTimezone)
    property.setParameter('tzid', time.zone.tzid)
  property.setValue(time)
  event.component.addProperty(property)
}

function ensureExceptionsMatch(series: Series) {
  const keys = new Set(series.exceptions.keys())
  const days = new Set<string>()
  let through = -Infinity
  const exclusions = datesFrom(series.master.component, 'exdate')
  for (const value of [...exclusions, ...[...series.exceptions.values()].map(item => item.recurrenceId)]) {
    if (!(value instanceof ICAL.Time)) continue
    const key = recurrenceKey(value, series.floatingZone)
    const instantValue = instant(value, series.floatingZone)
    if (key === null || instantValue === null) throw new Error('An exception falls in a missing local time.')
    if (value.isDate && !series.master.startDate.isDate) days.add(value.toString())
    else keys.add(key)
    through = Math.max(through, instantValue + (value.isDate ? day * 2 : 0))
  }
  if (!keys.size && !days.size) return
  for (const candidate of candidates(series, through, { remaining: maxIterations })) {
    const key = recurrenceKey(candidate.time, series.floatingZone)
    if (key) keys.delete(key)
    days.delete(candidate.time.toString().slice(0, 10))
    if (!keys.size && !days.size) return
  }
  throw new Error('This schedule would leave an existing exception without a date. Adjust its recurrence in CalDAV first.')
}

export function editSeriesSource(
  source: string, displayZone: string, clock: CalendarWallTime, repeat: CalendarRepeat,
  timeChanged: boolean, repeatChanged: boolean, changes: OccurrenceEdit, zoneSource?: string,
): string {
  const series = readSeries(source, displayZone)
  const { master, calendar } = series
  const old = scheduleOf(series)
  if (!old.editable) throw new Error('Adjust this series in CalDAV to retain its original time zones.')
  const exclusions = datesFrom(master.component, 'exdate').filter((date): date is Time => date instanceof ICAL.Time)
  const additions = datesFrom(master.component, 'rdate').map(value => value instanceof ICAL.Period ? value.start : value)
  const hasDates = exclusions.length > 0 || additions.length > 0 || series.exceptions.size > 0
  if (hasDates && (repeat.frequency === 'none' || clock.allDay !== old.allDay))
    throw new Error('Changing this series to a different event type would discard its existing exceptions.')

  const floating = old.floating && clock.zone === old.zone
  if (timeChanged) {
    const timezone = defineZone(calendar, clock, floating, zoneSource)
    setClock(master, clock, timezone)
    const shift = civilSeconds(clock.start) - civilSeconds(old.start)
    if (shift || clock.zone !== old.zone) {
      // RDATEs are explicit dates. Exceptions attached to those dates retain
      // their original identities, even when the base RRULE moves.
      const fixedDates = new Set(additions.map(value => recurrenceKey(value, old.zone)))
      const translate = (value: Time) => fixedDates.has(recurrenceKey(value, old.zone))
        ? value : translateException(value, old, clock, timezone, shift)
      master.component.removeAllProperties('exdate')
      for (const value of exclusions) writeExcludedDate(master, translate(value))
      for (const item of series.exceptions.values()) item.recurrenceId = translate(item.recurrenceId)
    }
  }
  if (repeatChanged || (timeChanged && repeat.end === 'date')) setRepeat(master, repeat, clock, floating)
  if (timeChanged && repeat.frequency === 'custom') {
    for (const property of master.component.getAllProperties('rrule')) {
      const first = (property.getFirstValue() as Recur).iterator(master.startDate).next()
      if (!first || first.toString() !== master.startDate.toString())
        throw new Error('The new start time does not match this custom repeat rule.')
    }
  }
  setDetails(master, changes)
  const updated = `${calendar.toString()}\r\n`
  if (hasDates) ensureExceptionsMatch(readSeries(updated, displayZone))
  return updated
}
