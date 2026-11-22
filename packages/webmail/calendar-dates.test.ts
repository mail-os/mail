import { describe, expect, test } from 'bun:test'
import {
  allDayInstant, calendarRange, eventOverlaps, instantForLocal, shiftCalendarDay,
  startOfZonedDay, zonedDay,
} from './functions/calendar-dates'
import { calendarYear, calendarYearWindows, nextYearDate } from './functions/calendar-year'

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

test('year navigation preserves the civil date and bounds the calendar requests', () => {
  expect(calendarRange('year', '2028-02-29')).toEqual({ start: '2028-01-01', end: '2029-01-01' })
  expect(shiftCalendarDay('year', '2028-02-29', 1)).toBe('2029-02-28')
  expect(shiftCalendarDay('year', '2028-02-29', -4)).toBe('2024-02-29')
  expect(calendarYearWindows('2028-02-29')).toEqual([
    { start: '2028-01-01', end: '2028-04-01' },
    { start: '2028-04-01', end: '2028-07-01' },
    { start: '2028-07-01', end: '2028-10-01' },
    { start: '2028-10-01', end: '2029-01-01' },
  ])
  expect(nextYearDate('2028-02-29', 'ArrowRight')).toBe('2028-03-01')
  expect(nextYearDate('2028-02-29', 'ArrowUp')).toBe('2028-02-22')
  expect(nextYearDate('2028-12-31', 'ArrowDown')).toBe('2028-12-31')
  expect(nextYearDate('2028-01-02', 'Home')).toBe('2028-01-01')
  expect(nextYearDate('2028-02-29', 'Tab')).toBeNull()
})

test('year marks retain all-day dates and use the display zone for timed events and busy periods', () => {
  const stamp = (iso: string) => Date.parse(iso) / 1000
  const months = calendarYear('2028-03-01', zone, '2028-02-29', [
    { start: stamp('2028-02-29T00:00Z'), end: stamp('2028-03-01T00:00Z'), all_day: true },
    { start: stamp('2028-04-01T03:30Z'), end: stamp('2028-04-01T04:00Z'), all_day: false },
    { start: stamp('2028-03-12T06:45Z'), end: stamp('2028-03-12T07:15Z'), all_day: false },
  ], [{ start: stamp('2028-04-01T03:30Z'), end: stamp('2028-04-01T04:00Z') }])
  expect(months).toHaveLength(12)
  expect(months[0].firstColumn).toBe(6)
  expect(months.flatMap(month => month.days)).toHaveLength(366)
  expect(months[1].days.at(-1)).toMatchObject({ date: '2028-02-29', today: true, count: 1, busy: false })
  expect(months[2].days[11]).toMatchObject({ date: '2028-03-12', count: 1, busy: false })
  expect(months[2].days.at(-1)).toMatchObject({ date: '2028-03-31', count: 1, busy: true })
  expect(months[3].days[0]).toMatchObject({ date: '2028-04-01', count: 0, busy: false })
})
