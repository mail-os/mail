import { expect, test } from 'bun:test'
import { alarmsInWindow, createSeriesSource, editEventReminder, editOccurrence, expandSeries, readEventReminder } from './functions/calendar-recurrence'
import type { CalendarEvent } from './functions/calendar-types'
import { defaultRepeat } from './functions/calendar-repeat'

const stamp = (value: string) => Date.parse(value) / 1000
const zone = 'America/New_York'
const event: CalendarEvent = {
  id: 41, calendar_id: 2, uid: 'reminders', summary: 'Calendar work', location: null,
  start: stamp('2026-03-08T17:00Z'), end: stamp('2026-03-08T18:00Z'),
  all_day: false, recurring: false, recurrence_rule: null, status: 'confirmed', etag: '"reminder"',
}
const calendar = (...lines: string[]) => ['BEGIN:VCALENDAR', 'VERSION:2.0', ...lines, 'END:VCALENDAR', ''].join('\r\n')
const display = (trigger: string, ...extra: string[]) => ['BEGIN:VALARM', 'ACTION:DISPLAY', trigger, 'DESCRIPTION:Reminder', ...extra, 'END:VALARM']
const base = ['BEGIN:VEVENT', 'UID:reminders', 'DTSTART:20260308T170000Z', 'DTEND:20260308T180000Z', 'SUMMARY:Calendar work']
const audio = ['BEGIN:VALARM', 'ACTION:AUDIO', 'TRIGGER:-PT5M', 'ATTACH:https://example.test/sound', 'END:VALARM']

function due(source: string, start: string, end: string, record = event) {
  return alarmsInWindow(record, source, zone, stamp(start), stamp(end), { remaining: 8000 })
}

test('creates a display alarm and edits an imported simple alarm without removing other alarms', () => {
  const first = calendar(...base, ...display('TRIGGER:-PT10M'), ...audio,
    ...display('TRIGGER;RELATED=END:PT5M', 'REPEAT:2', 'DURATION:PT1M'), 'END:VEVENT')
  expect(readEventReminder(first)).toEqual({ choice: '10', others: 2 })
  const replaced = editEventReminder(first, { reminder: '30', summary: 'Review notes' })
  expect(readEventReminder(replaced)).toEqual({ choice: '30', others: 2 })
  expect(replaced).toContain('TRIGGER:-PT30M')
  expect(replaced).toContain(audio.join('\r\n'))
  expect(replaced).toContain('TRIGGER;RELATED=END:PT5M')
  expect(replaced).toContain('SUMMARY:Review notes')
  const removed = editEventReminder(replaced, { reminder: 'none' })
  expect(readEventReminder(removed)).toEqual({ choice: 'none', others: 2 })
  expect(removed).toContain(audio.join('\r\n'))
  const created = createSeriesSource('reminders', { start: '2026-03-08T17:00', end: '', allDay: false, zone: 'UTC' },
    defaultRepeat, { summary: 'New event', reminder: 'start' })
  expect(readEventReminder(created)).toEqual({ choice: 'start', others: 0 })
  expect(due(created, '2026-03-08T17:00Z', '2026-03-08T17:01Z')).toHaveLength(1)
})

test('honors absolute and end-relative display alarms, repetitions, and imported acknowledgements', () => {
  const source = calendar(...base, 'RRULE:FREQ=DAILY;COUNT=3', ...audio,
    ...display('TRIGGER;VALUE=DATE-TIME:20260306T140000Z', 'REPEAT:2', 'DURATION:PT10M', 'ACKNOWLEDGED:20260306T141000Z'),
    ...display('TRIGGER;RELATED=END:PT5M', 'REPEAT:2', 'DURATION:PT6M'), 'END:VEVENT')
  const recurring = { ...event, recurring: true }
  expect(due(source, '2026-03-06T14:00Z', '2026-03-07T00:00Z', recurring).map(alarm => alarm.due))
    .toEqual([stamp('2026-03-06T14:20Z')])
  expect(due(source, '2026-03-08T18:06Z', '2026-03-08T18:17Z', recurring).map(alarm => alarm.due))
    .toEqual([stamp('2026-03-08T18:11Z')])
  expect(due(source, '2026-03-09T00:00Z', '2026-03-10T00:00Z', recurring).map(alarm => alarm.due))
    .toEqual([stamp('2026-03-09T18:05Z'), stamp('2026-03-09T18:11Z'), stamp('2026-03-09T18:17Z')])
})

test('anchors an all-day reminder to local midnight across daylight saving time', () => {
  const source = calendar('BEGIN:VEVENT', 'UID:reminders', 'DTSTART;VALUE=DATE:20260309',
    'SUMMARY:Calendar work', ...display('TRIGGER:-P1D'), 'END:VEVENT')
  const record = { ...event, all_day: true }
  expect(due(source, '2026-03-08T00:00Z', '2026-03-09T00:00Z', record).map(alarm => alarm.due))
    .toEqual([stamp('2026-03-08T05:00Z')])
})

test('a reminder change applies just to the chosen occurrence and a cancelled date stays quiet', () => {
  const source = calendar(...base, 'RRULE:FREQ=DAILY;COUNT=3', ...display('TRIGGER:-PT15M'),
    'EXDATE:20260310T170000Z', 'END:VEVENT')
  const recurring = { ...event, recurring: true }
  const occurrences = expandSeries(recurring, source, zone, stamp('2026-03-08T00:00Z'), stamp('2026-03-11T00:00Z'), { remaining: 30 })
  expect(occurrences).toHaveLength(2)
  const [first, second] = occurrences
  const removed = editOccurrence(recurring, source, zone, first.occurrence, { reminder: 'none' })
  const adjusted = editOccurrence(recurring, removed, zone, second.occurrence, {
    reminder: '5', time: { start: stamp('2026-03-09T18:00Z'), end: null, allDay: false },
  })
  expect(due(adjusted, '2026-03-08T00:00Z', '2026-03-11T00:00Z', recurring).map(alarm => alarm.due))
    .toEqual([stamp('2026-03-09T17:55Z')])
  const cancelled = editOccurrence(recurring, adjusted, zone, second.occurrence, { cancel: true })
  expect(due(cancelled, '2026-03-08T00:00Z', '2026-03-11T00:00Z', recurring)).toEqual([])
})
