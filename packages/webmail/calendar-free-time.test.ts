import { expect, test } from 'bun:test'
import { formatFreeTime, freeTimeRanges, freeTimeWindow } from './functions/calendar-free-time'

test('free ranges clip and merge busy entries with half-open boundaries', () => {
  const window = { start: 0, end: 100 }
  const busy = [
    { start: 60, end: 70 },
    { start: 10, end: 25 },
    { start: 20, end: 30 },
    { start: 30, end: 35 },
    { start: 75, end: 115 },
    { start: -5, end: 0 },
    { start: 100, end: 150 },
  ]
  expect(freeTimeRanges(window, busy, 10)).toEqual([{ start: 0, end: 10 }, { start: 35, end: 60 }])
  expect(freeTimeRanges(window, [], 100)).toEqual([window])
  expect(freeTimeRanges(window, [{ start: -10, end: 110 }], 1)).toEqual([])
  expect(() => freeTimeRanges(window, [{ start: 40, end: 30 }], 1)).toThrow('invalid busy period')
})

test('free-time windows use elapsed time in the display zone across clock changes', () => {
  const zone = 'America/New_York'
  expect(freeTimeWindow('2028-03-12', '02:30', '04:00', zone)).toBeNull()
  expect(freeTimeWindow('2028-03-12', '17:00', '09:00', zone)).toBeNull()
  const spring = freeTimeWindow('2028-03-12', '01:00', '04:00', zone)!
  const autumn = freeTimeWindow('2028-11-05', '01:00', '03:00', zone)!
  expect(spring.end - spring.start).toBe(120 * 60)
  expect(autumn.end - autumn.start).toBe(180 * 60)
  const slots = formatFreeTime(autumn, [autumn], zone)
  expect(slots[0].minutes).toBe(180)
  expect(slots[0].time).toMatch(/GMT-4.*GMT-5/)
})
