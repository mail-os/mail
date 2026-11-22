import { derived, state } from '@stacksjs/stx'
import { formatFreeTime, freeTimeRanges, freeTimeWindow } from './calendar-free-time'
import type { TimeWindow } from './calendar-free-time'
import type { CalendarAccess } from './calendar-types'
import type { createMailApi } from './mail-api'

interface CalendarScope { id: number | null, name: string, access?: CalendarAccess, canIncludeOwned: boolean }

export function useCalendarFreeTime(api: ReturnType<typeof createMailApi>, focusDay: () => string, zone: () => string, scope: () => CalendarScope) {
  const freeTimeOpen = state(false)
  const freeTimeDate = state('')
  const freeTimeStart = state('09:00')
  const freeTimeEnd = state('17:00')
  const freeTimeMinutes = state('30')
  const freeTimeIncludeOwned = state(true)
  const freeTimeBusy = state(false)
  const freeTimeDurations = [15, 30, 45, 60, 90, 120]
  const freeTimeCanIncludeOwned = derived(() => scope().canIncludeOwned)
  const includeOwned = () => freeTimeCanIncludeOwned() && freeTimeIncludeOwned()
  const freeTimeScope = derived(() => scope().name + (includeOwned() ? ' and my calendars' : ''))
  const results = state<{ key: string, slots: ReturnType<typeof formatFreeTime> } | null>(null)
  const failure = state<{ key: string, message: string } | null>(null)
  let pending: AbortController | undefined

  function requestKey() {
    const { id, access } = scope()
    return JSON.stringify([id, access, includeOwned(), freeTimeDate(), freeTimeStart(), freeTimeEnd(), freeTimeMinutes(), zone()])
  }

  const freeTimeResults = derived(() => {
    const result = results()
    return result?.key === requestKey() ? result.slots : null
  })
  const freeTimeError = derived(() => {
    const current = failure()
    return current?.key === requestKey() ? current.message : ''
  })

  function clearFreeTimeResults() {
    pending?.abort()
    pending = undefined
    results.set(null)
    failure.set(null)
    freeTimeBusy.set(false)
  }

  function toggleFreeTime() {
    clearFreeTimeResults()
    if (!freeTimeOpen()) freeTimeDate.set(focusDay())
    freeTimeOpen.set(!freeTimeOpen())
  }

  async function findFreeTime() {
    clearFreeTimeResults()
    const key = requestKey()
    const displayZone = zone()
    const window = freeTimeWindow(freeTimeDate(), freeTimeStart(), freeTimeEnd(), displayZone)
    const minutes = Number(freeTimeMinutes())
    if (!window || !freeTimeDurations.includes(minutes)) {
      failure.set({ key, message: 'Choose a date and valid times in the display time zone. The end time must follow the start time.' })
      return
    }

    const request = new AbortController()
    pending = request
    freeTimeBusy.set(true)
    const params = new URLSearchParams({ start: String(window.start), end: String(window.end) })
    const id = scope().id
    if (id !== null) params.set('calendarId', String(id))
    if (includeOwned()) params.set('includeOwned', '1')
    try {
      const { busy } = await api<{ busy: TimeWindow[] }>(`/webmail/api/calendar-free-busy?${params}`, {
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]),
      })
      if (!request.signal.aborted && key === requestKey())
        results.set({ key, slots: formatFreeTime(window, freeTimeRanges(window, busy, minutes * 60), displayZone) })
    }
    catch (cause) {
      if (!request.signal.aborted && key === requestKey())
        failure.set({ key, message: cause instanceof Error ? cause.message : 'Could not check calendar availability.' })
    }
    finally {
      if (pending === request) {
        pending = undefined
        freeTimeBusy.set(false)
      }
    }
  }

  return { freeTimeOpen, freeTimeDate, freeTimeStart, freeTimeEnd, freeTimeMinutes, freeTimeIncludeOwned, freeTimeBusy,
    freeTimeDurations, freeTimeCanIncludeOwned, freeTimeScope, freeTimeResults, freeTimeError,
    clearFreeTimeResults, toggleFreeTime, findFreeTime }
}
