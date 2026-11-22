import { describe, expect, test } from 'bun:test'
import {
  allDayInstant, calendarRange, eventOverlaps, instantForLocal, shiftCalendarDay,
  startOfZonedDay, zonedDay,
} from './functions/calendar-dates'

const zone = 'America/New_York'

describe('calendar times', () => {
  test('rejects missing spring times and chooses the first repeated wall time', () => {
    expect(instantForLocal('2026-03-08T02:30', zone)).toBeNull()
    expect(instantForLocal('2026-11-01T01:30', zone)).toBe(Date.parse('2026-11-01T05:30Z') / 1000)
    expect(instantForLocal('2026-02-30T09:00', zone)).toBeNull()
    expect(instantForLocal('2026-11-01T09:00', 'Asia/Kathmandu')).toBe(Date.parse('2026-11-01T03:15Z') / 1000)
  })

  test('keeps civil day boundaries through offset changes', () => {
    expect(startOfZonedDay('2026-03-09', zone) - startOfZonedDay('2026-03-08', zone)).toBe(23 * 3600)
    expect(startOfZonedDay('2026-11-02', zone) - startOfZonedDay('2026-11-01', zone)).toBe(25 * 3600)
    const midnightGap = startOfZonedDay('2018-11-04', 'America/Sao_Paulo')
    expect(midnightGap).toBe(Date.parse('2018-11-04T03:00Z') / 1000)
    const skipped = startOfZonedDay('2011-12-30', 'Pacific/Apia')
    expect(skipped).toBe(startOfZonedDay('2011-12-31', 'Pacific/Apia'))
    expect(zonedDay(skipped, 'Pacific/Apia')).toBe('2011-12-31')
  })

  test('keeps all-day dates independent of the display zone and excludes the end', () => {
    const day = allDayInstant('2026-11-01')!
    const next = allDayInstant('2026-11-02')!
    expect(zonedDay(day, zone)).toBe('2026-10-31')
    expect(eventOverlaps(day, null, day, next, true)).toBe(true)
    expect(eventOverlaps(day, next, next, next + 86400, true)).toBe(false)
    expect(eventOverlaps(next, null, day, next, false)).toBe(false)
    expect(eventOverlaps(day - 120, day + 120, day, next, false)).toBe(true)
    expect(eventOverlaps(day - 120, day + 120, day, day, false)).toBe(false)
  })
})

test('weeks align on Mondays and month navigation includes adjacent dates', () => {
  expect(calendarRange('week', '2026-11-01')).toEqual({ start: '2026-10-26', end: '2026-11-02' })
  expect(calendarRange('month', '2026-11-28')).toEqual({ start: '2026-10-26', end: '2026-12-07' })
  expect(shiftCalendarDay('month', '2026-01-31', -1)).toBe('2025-12-01')
  expect(shiftCalendarDay('month', '2026-01-31', 1)).toBe('2026-02-01')
  expect(shiftCalendarDay('agenda', '2026-12-15', 1)).toBe('2027-01-14')
})
