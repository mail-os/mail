import { expect, test } from 'bun:test'
import moment from 'moment-timezone'
import { createSeriesSource, editOccurrence, editSeriesSource, expandSeries, readOccurrence, readSeriesSchedule } from './functions/calendar-recurrence'
import type { CalendarEvent } from './functions/calendar-types'
import { defaultRepeat } from './functions/calendar-repeat'
import { calendarTimeZoneSource } from './build-calendar-timezones'

const stamp = (date: string) => Date.parse(date) / 1000
const zone = 'America/New_York'
const row: CalendarEvent = {
  id: 1, calendar_id: 2, uid: 'fixture', summary: 'Office hours', location: null,
  start: stamp('2026-03-01T14:00Z'), end: stamp('2026-03-01T15:00Z'),
  all_day: false, recurring: true, recurrence_rule: 'FREQ=WEEKLY;COUNT=5',
  status: 'confirmed', etag: '"fixture"',
}

function calendar(...lines: string[]) {
  return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Mail//Calendar tests//EN', ...lines, 'END:VCALENDAR', ''].join('\r\n')
}
const timezone = [
  'BEGIN:VTIMEZONE', 'TZID:America/New_York', 'BEGIN:STANDARD',
  'DTSTART:20071104T020000', 'TZOFFSETFROM:-0400', 'TZOFFSETTO:-0500', 'RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU',
  'END:STANDARD', 'BEGIN:DAYLIGHT', 'DTSTART:20070311T020000',
  'TZOFFSETFROM:-0500', 'TZOFFSETTO:-0400', 'RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU', 'END:DAYLIGHT', 'END:VTIMEZONE',
]
const source = calendar(
  ...timezone,
  'BEGIN:VEVENT', 'UID:fixture', 'DTSTART;TZID=America/New_York:20260301T090000',
  'DTEND;TZID=America/New_York:20260301T100000', 'SUMMARY:Office hours', 'DESCRIPTION:Bring notes',
  'RRULE:FREQ=WEEKLY;COUNT=5', 'EXDATE;TZID=America/New_York:20260308T090000',
  'RDATE;VALUE=PERIOD:20260311T120000Z/20260311T143000Z',
  'BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:Reminder', 'TRIGGER:-PT15M', 'END:VALARM',
  'END:VEVENT',
  'BEGIN:VEVENT', 'UID:fixture', 'RECURRENCE-ID;TZID=America/New_York:20260315T090000',
  'DTSTART;TZID=America/New_York:20260228T093000', 'DTEND;TZID=America/New_York:20260228T100000',
  'SUMMARY:Moved before the master', 'END:VEVENT',
  'BEGIN:VEVENT', 'UID:fixture', 'RECURRENCE-ID:20260322T130000Z', 'STATUS:CANCELLED', 'END:VEVENT',
)

function expand(body: string, from = '2026-02-27T00:00Z', through = '2026-04-07T00:00Z') {
  return expandSeries(row, body, zone, stamp(from), stamp(through), { remaining: 30_000 }).sort((a, b) => a.start - b.start)
}

test('expands a named-zone series with exclusions, moved and cancelled exceptions, and an RDATE period', () => {
  const occurrences = expand(source)
  expect(occurrences.map(event => [event.summary, event.start, event.end])).toEqual([
    ['Moved before the master', stamp('2026-02-28T14:30Z'), stamp('2026-02-28T15:00Z')],
    ['Office hours', stamp('2026-03-01T14:00Z'), stamp('2026-03-01T15:00Z')],
    ['Office hours', stamp('2026-03-11T12:00Z'), stamp('2026-03-11T14:30Z')],
    ['Office hours', stamp('2026-03-29T13:00Z'), stamp('2026-03-29T14:00Z')],
  ])
  expect(expand(source, '2026-02-28T00:00Z', '2026-03-01T00:00Z')).toHaveLength(1)
})

test('reschedules and cancels one occurrence while keeping the master, alarms, and other exceptions', () => {
  const selection = expand(source).find(event => event.start === stamp('2026-03-29T13:00Z'))!
  const replaced = editOccurrence(row, source, zone, selection.occurrence, {
    summary: 'One-time review',
    description: '',
    time: { start: stamp('2026-03-30T15:00Z'), end: stamp('2026-03-30T16:00Z'), allDay: false },
  })
  expect(replaced).toContain('RECURRENCE-ID;TZID=America/New_York:20260329T090000')
  expect(replaced).toContain('RRULE:FREQ=WEEKLY;COUNT=5')
  expect(replaced).toContain('TRIGGER:-PT15M')
  expect(replaced).toContain('SUMMARY:Moved before the master')
  const edited = readOccurrence(row, replaced, zone, selection.occurrence)
  expect(edited).toMatchObject({ summary: 'One-time review', start: stamp('2026-03-30T15:00Z'), description: '' })
  const cancelled = editOccurrence(row, replaced, zone, selection.occurrence, { cancel: true })
  expect(readOccurrence(row, cancelled, zone, selection.occurrence)).toBeNull()
  expect(expand(cancelled)).toHaveLength(3)
})

test('keeps all-day recurrence at midnight UTC and skips a spring-forward gap in a floating rule', () => {
  const allDay = calendar('BEGIN:VEVENT', 'UID:fixture', 'SUMMARY:All day',
    'DTSTART;VALUE=DATE:20260307', 'DTEND;VALUE=DATE:20260309',
    'RRULE:FREQ=WEEKLY;COUNT=2', 'END:VEVENT')
  expect(expand(allDay).map(event => [event.start, event.end])).toEqual([
    [stamp('2026-03-07T00:00Z'), stamp('2026-03-09T00:00Z')],
    [stamp('2026-03-14T00:00Z'), stamp('2026-03-16T00:00Z')],
  ])
  const floating = calendar('BEGIN:VEVENT', 'UID:fixture', 'SUMMARY:Morning work',
    'DTSTART:20260307T023000', 'RRULE:FREQ=DAILY;COUNT=2', 'END:VEVENT')
  expect(expand(floating).map(event => event.start)).toEqual([
    stamp('2026-03-07T07:30Z'), stamp('2026-03-09T06:30Z'),
  ])
})

test('honors gaps and repeated times in an embedded daylight-saving definition', () => {
  const spring = calendar(...timezone, 'BEGIN:VEVENT', 'UID:fixture',
    'DTSTART;TZID=America/New_York:20260307T023000', 'RRULE:FREQ=DAILY;COUNT=2', 'END:VEVENT')
  expect(expand(spring).map(event => event.start)).toEqual([
    stamp('2026-03-07T07:30Z'), stamp('2026-03-09T06:30Z'),
  ])
  const autumn = calendar(...timezone, 'BEGIN:VEVENT', 'UID:fixture',
    'DTSTART;TZID=America/New_York:20261031T013000', 'RRULE:FREQ=DAILY;COUNT=3', 'END:VEVENT')
  expect(expand(autumn, '2026-10-31T00:00Z', '2026-11-03T00:00Z').map(event => event.start)).toEqual([
    stamp('2026-10-31T05:30Z'), stamp('2026-11-01T05:30Z'), stamp('2026-11-02T06:30Z'),
  ])
})

test('applies this-and-future shifts and protects that exception from single-instance replacement', () => {
  const ranged = calendar('BEGIN:VEVENT', 'UID:fixture', 'DTSTART:20260301T090000Z',
    'RRULE:FREQ=WEEKLY;COUNT=4', 'SUMMARY:Original', 'END:VEVENT',
    'BEGIN:VEVENT', 'UID:fixture', 'RECURRENCE-ID;RANGE=THISANDFUTURE:20260308T090000Z',
    'DTSTART:20260308T130000Z', 'DTEND:20260308T140000Z', 'SUMMARY:Shifted', 'END:VEVENT')
  const dates = expand(ranged)
  expect(dates.map(item => [item.summary, item.start, item.canEditOccurrence])).toEqual([
    ['Original', stamp('2026-03-01T09:00Z'), true],
    ['Shifted', stamp('2026-03-08T13:00Z'), false],
    ['Shifted', stamp('2026-03-15T13:00Z'), true],
    ['Shifted', stamp('2026-03-22T13:00Z'), true],
  ])
  expect(() => editOccurrence(row, ranged, zone, dates[1].occurrence, { cancel: true })).toThrow('later dates')
  const edit = editOccurrence(row, ranged, zone, dates[2].occurrence, { summary: 'One-off shift' })
  expect(expand(edit).map(item => item.summary)).toEqual(['Original', 'Shifted', 'One-off shift', 'Shifted'])
})

test('bounds time spent iterating an unusually dense rule', () => {
  const dense = calendar('BEGIN:VEVENT', 'UID:fixture', 'DTSTART:20200101T000000Z',
    'RRULE:FREQ=SECONDLY', 'END:VEVENT')
  expect(() => expandSeries(row, dense, zone, stamp('2026-03-01T00:00Z'), stamp('2026-03-02T00:00Z'),
    { remaining: 20 })).toThrow('too dense')
})

test('creates and reschedules a named-zone series through a DST transition', () => {
  const start = { start: '2026-03-01T09:00', end: '2026-03-01T10:00', zone, allDay: false }
  const repeat = { ...defaultRepeat, frequency: 'weekly', end: 'count', count: 3 } as const
  const data = calendarTimeZoneSource(zone)!
  const created = createSeriesSource('fixture', start, repeat, { summary: 'Stand-up' }, data)
  expect(created).toContain('DTSTART;TZID=America/New_York:20260301T090000')
  expect(expand(created).map(item => item.start)).toEqual([
    stamp('2026-03-01T14:00Z'), stamp('2026-03-08T13:00Z'), stamp('2026-03-15T13:00Z'),
  ])
  const schedule = readSeriesSchedule(created, 'UTC')
  expect(schedule.zone).toBe(zone)
  expect(schedule.repeat).toEqual(repeat)
  const changed = editSeriesSource(created, 'UTC', { ...start, start: '2026-03-01T10:30', end: '2026-03-01T11:15' },
    { ...repeat, end: 'date', until: '2026-03-08' }, true, true, { summary: 'Late stand-up' })
  expect(changed).toContain('UNTIL=20260309T035959Z')
  expect(expand(changed).map(item => [item.summary, item.start])).toEqual([
    ['Late stand-up', stamp('2026-03-01T15:30Z')], ['Late stand-up', stamp('2026-03-08T14:30Z')],
  ])
  const oneTime = editSeriesSource(changed, 'UTC', readSeriesSchedule(changed, 'UTC'), defaultRepeat, false, true, {})
  expect(readSeriesSchedule(oneTime, 'UTC').repeat.frequency).toBe('none')
})

test('rebases exception keys while retaining moved appointments and explicit dates', () => {
  const schedule = readSeriesSchedule(source, 'UTC')
  const next = { ...schedule, start: '2026-03-01T10:30', end: '2026-03-01T11:30' }
  const updated = editSeriesSource(source, 'UTC', next, schedule.repeat, true, false, {})
  for (const line of [
    'RECURRENCE-ID;TZID=America/New_York:20260315T103000',
    'RECURRENCE-ID;TZID=America/New_York:20260322T103000',
    'EXDATE;TZID=America/New_York:20260308T103000',
    'DTSTART;TZID=America/New_York:20260228T093000',
    'RDATE;VALUE=PERIOD:20260311T120000Z/20260311T143000Z',
    'TRIGGER:-PT15M',
  ]) expect(updated).toContain(line)
  expect(expand(updated).map(item => item.start)).toEqual([
    stamp('2026-02-28T14:30Z'), stamp('2026-03-01T15:30Z'), stamp('2026-03-11T12:00Z'), stamp('2026-03-29T14:30Z'),
  ])
  const nextDay = editSeriesSource(source, 'UTC',
    { ...schedule, start: '2026-03-02T09:00', end: '2026-03-02T10:00' }, schedule.repeat, true, false, {})
  expect(nextDay).toContain('EXDATE;TZID=America/New_York:20260309T090000')
  expect(nextDay).toContain('RECURRENCE-ID;TZID=America/New_York:20260323T090000')
  expect(expand(nextDay).map(item => item.start)).toEqual([
    stamp('2026-02-28T14:30Z'), stamp('2026-03-02T14:00Z'), stamp('2026-03-11T12:00Z'), stamp('2026-03-30T13:00Z'),
  ])
  expect(() => editSeriesSource(source, 'UTC', schedule, { ...schedule.repeat, count: 2 }, false, true, {}))
    .toThrow('existing exception without a date')
})

test('creates all-day repeats with an inclusive stop date and fixed-offset named times', () => {
  const repeat = { ...defaultRepeat, frequency: 'daily', end: 'date', until: '2026-03-08' } as const
  const date = createSeriesSource('fixture', { start: '2026-03-07', end: '', zone, allDay: true }, repeat, {})
  expect(date).toContain('DTSTART;VALUE=DATE:20260307')
  expect(date).toContain('RRULE:FREQ=DAILY;UNTIL=20260308')
  expect(expand(date).map(event => event.start)).toEqual([stamp('2026-03-07T00:00Z'), stamp('2026-03-08T00:00Z')])

  const kathmandu = 'Asia/Kathmandu'
  const timed = createSeriesSource('fixture', { start: '2026-03-07T09:00', end: '', zone: kathmandu, allDay: false },
    repeat, {}, calendarTimeZoneSource(kathmandu)!)
  expect(expand(timed).map(event => event.start)).toEqual([stamp('2026-03-07T03:15Z'), stamp('2026-03-08T03:15Z')])
})

test('includes irregular future transitions from the bundled IANA data', () => {
  const region = 'Asia/Gaza'
  const table = calendarTimeZoneSource(region)!
  const clock = { start: '2026-03-01T09:00', end: '', zone: region, allDay: false }
  const calendar = createSeriesSource('fixture', clock, { ...defaultRepeat, frequency: 'daily' }, {}, table)
  const rows = expand(calendar, '2026-03-15T00:00Z', '2026-05-01T00:00Z')
  const date = moment.utc('2026-03-15')
  const expected = Array.from({ length: 47 }, () => {
    const next = moment.tz(`${date.format('YYYY-MM-DD')} 09:00`, region).unix()
    date.add(1, 'day')
    return next
  })
  expect(new Set(expected.map(value => value % 86400)).size).toBeGreaterThan(1)
  expect(rows.map(event => event.start)).toEqual(expected)
})

test('respects repeat intervals and skips months that have no matching day', () => {
  const monthly = createSeriesSource('fixture', { start: '2026-01-31', end: '', zone, allDay: true },
    { ...defaultRepeat, frequency: 'monthly', end: 'count', count: 3 }, {})
  expect(expand(monthly, '2026-01-01T00:00Z', '2026-06-01T00:00Z').map(event => event.start)).toEqual([
    stamp('2026-01-31T00:00Z'), stamp('2026-03-31T00:00Z'), stamp('2026-05-31T00:00Z'),
  ])
  const yearly = createSeriesSource('fixture', { start: '2026-03-02', end: '', zone, allDay: true },
    { ...defaultRepeat, frequency: 'yearly', interval: 2, end: 'count', count: 2 }, {})
  expect(expand(yearly, '2026-03-01T00:00Z', '2029-03-05T00:00Z').map(event => event.start)).toEqual([
    stamp('2026-03-02T00:00Z'), stamp('2028-03-02T00:00Z'),
  ])
})
