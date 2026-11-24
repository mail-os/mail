import { expect, test } from 'bun:test'
import { calendarDayTimeline } from './functions/calendar-day-timeline'
import type { CalendarEvent } from './functions/calendar-types'

const stamp = (text: string) => Date.parse(text) / 1000
function event(id: number, start: string, end: string | null, allDay = false): CalendarEvent {
  return {
    id, calendar_id: id % 2, summary: `Event ${id}`, location: null, recurring: false,
    recurrence_rule: null, start: stamp(start), end: end === null ? null : stamp(end),
    all_day: allDay, status: 'confirmed', etag: `event-${id}`,
  }
}

test('positions overlaps, reuses lanes and clips events across midnight', () => {
  const result = calendarDayTimeline('2026-11-24', 'UTC', [
    event(1, '2026-11-23T23:30Z', '2026-11-24T09:30Z'),
    event(2, '2026-11-24T09:00Z', '2026-11-24T10:00Z'),
    event(3, '2026-11-24T09:45Z', '2026-11-24T10:30Z'),
    event(4, '2026-11-24T11:00Z', '2026-11-24T12:30Z'),
    event(5, '2026-11-24T23:00Z', '2026-11-25T01:00Z'),
    event(6, '2026-11-25T00:00Z', null),
  ], [])
  expect(result.minutes).toBe(1440)
  expect(result.lanes).toBe(2)
  expect(result.timed.map(item => [item.event.id, item.startMinute, item.duration, item.lane, item.lanes])).toEqual([
    [1, 0, 570, 0, 2], [2, 540, 60, 1, 2], [3, 585, 45, 0, 2], [4, 660, 90, 0, 1], [5, 1380, 60, 0, 1],
  ])
})

test('keeps an all-day event on its civil date across display zones', () => {
  const records = [
    event(1, '2026-11-24T00:00Z', '2026-11-25T00:00Z', true),
    event(2, '2026-11-24T15:00Z', null),
    event(3, '2026-11-24T15:05Z', '2026-11-24T15:10Z'),
    event(4, '2026-11-23T00:00Z', '2026-11-24T00:00Z', true),
  ]
  const result = calendarDayTimeline('2026-11-24', 'America/Los_Angeles', records, [])
  expect(result.allDay.map(item => item.id)).toEqual([1])
  expect(result.timed.map(item => [item.startMinute, item.duration, item.lane])).toEqual([[420, 0, 0], [425, 5, 1]])
  expect(calendarDayTimeline('2026-11-23', 'America/Los_Angeles', records, []).allDay.map(item => item.id)).toEqual([4])
})

test('spring day skips nonexistent times and fall day distinguishes both repeated slots', () => {
  const zone = 'America/New_York'
  const spring = calendarDayTimeline('2026-03-08', zone, [
    event(1, '2026-03-08T06:30Z', '2026-03-08T07:30Z'),
  ], [])
  expect(spring.minutes).toBe(23 * 60)
  expect(spring.slots).toHaveLength(92)
  expect(spring.slots.some(slot => slot.wallTime.startsWith('02:'))).toBe(false)
  expect(spring.timed[0]).toMatchObject({ startMinute: 90, duration: 60 })

  const autumn = calendarDayTimeline('2026-11-01', zone, [
    event(2, '2026-11-01T05:30Z', '2026-11-01T06:00Z'),
    event(3, '2026-11-01T06:30Z', '2026-11-01T07:00Z'),
  ], [])
  expect(autumn.minutes).toBe(25 * 60)
  expect(autumn.slots).toHaveLength(100)
  const repeated = autumn.slots.filter(slot => slot.wallTime === '01:30')
  expect(repeated.map(slot => slot.stamp)).toEqual([stamp('2026-11-01T05:30Z'), stamp('2026-11-01T06:30Z')])
  expect(repeated[0].label).not.toBe(repeated[1].label)
  expect(autumn.timed.map(item => [item.startMinute, item.duration, item.lane])).toEqual([[90, 30, 0], [150, 30, 0]])
})

test('handles a half-hour transition and a skipped civil date', () => {
  const partial = calendarDayTimeline('2026-10-04', 'Australia/Lord_Howe', [], [])
  expect(partial.minutes).toBe(23.5 * 60)
  expect(partial.slots.some(slot => slot.wallTime === '02:00')).toBe(false)
  expect(partial.slots.some(slot => slot.wallTime === '02:30')).toBe(true)
  const skipped = calendarDayTimeline('2011-12-30', 'Pacific/Apia', [], [])
  expect(skipped.minutes).toBe(0)
  expect(skipped.slots).toEqual([])
})

test('clips and merges overlapping busy periods without joining separate gaps', () => {
  const time = (clock: string) => stamp(`2026-11-24T${clock}Z`)
  const result = calendarDayTimeline('2026-11-24', 'UTC', [], [
    { start: time('09:00'), end: time('10:15') },
    { start: time('09:15'), end: time('11:00') },
    { start: time('11:00'), end: time('11:30') },
    { start: time('12:00'), end: time('13:00') },
    { start: stamp('2026-11-23T23:30Z'), end: time('00:15') },
  ])
  expect(result.busy.map(item => [item.startMinute, item.duration])).toEqual([[0, 15], [540, 150], [720, 60]])
})
