import { derived, state } from '@stacksjs/stx'
import { createMailApi, MailApiError } from './mail-api'
import type { User } from './mail-types'

import {
  addCalendarDays, allDayInstant, browserTimeZone, calendarRange, calendarTimeZones, eventOverlaps,
  formatCalendarDay, shiftCalendarDay, startOfZonedDay, zonedDay,
} from './calendar-dates'
import type { CalendarView } from './calendar-dates'
import { calendarAccessLabels, calendarColor } from './calendar-types'
import type { Calendar, CalendarAccess, CalendarEvent, CalendarShare } from './calendar-types'
import { expandSeries } from './calendar-recurrence'
import type { CalendarOccurrence } from './calendar-recurrence'
import { useCalendarEditor } from './use-calendar-editor'
import { useCalendarReminders } from './use-calendar-reminders'
import type { CalendarDialog } from './use-calendar-editor'

interface ImportEvent {
  number: number
  summary: string
  start: number | null
  allDay: boolean
  status: 'ready' | 'imported' | 'skipped' | 'error'
  message: string | null
}

interface ImportResult {
  calendarId: number | null
  events: ImportEvent[]
}

const importStatusLabels = {
  ready: 'Ready to import', imported: 'Imported', skipped: 'Skipped', error: 'Error',
}

function calendarName(name: string): string {
  try { return decodeURIComponent(name) }
  catch { return name }
}

const calendarViews: { id: CalendarView, name: string }[] = [
  { id: 'day', name: 'Day' }, { id: 'week', name: 'Week' },
  { id: 'month', name: 'Month' }, { id: 'agenda', name: 'Agenda' },
]
const shortDate: Intl.DateTimeFormatOptions = { dateStyle: 'medium' }
const dateLabel = new Intl.DateTimeFormat(undefined, { ...shortDate, timeZone: 'UTC' })
const dateTimeLabel = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const accessPriority = { free_busy: 0, viewer: 1, editor: 2 }

interface BusyPeriod { start: number, end: number }
interface CalendarTeam { id: string, name: string }

function calendarEventDate(event: CalendarEvent, zone: string): string {
  const date = new Date(event.start * 1000)
  if (event.all_day) return `${dateLabel.format(date)} · All day`
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: zone }).format(date)
}

export function useMailCalendar(onAuthError: () => void, dialog: CalendarDialog) {
  const account = state<string | undefined>(undefined)
  const calendars = state<Calendar[]>([])
  const shares = state<CalendarShare[]>([])
  const teams = state<CalendarTeam[]>([])
  const outgoingShares = derived(() => shares().filter(share => share.source === account()))
  const sharedCalendars = derived(() => {
    const incoming = new Map<number, CalendarShare>()
    for (const share of shares()) {
      if (share.grantee !== account()) continue
      const current = incoming.get(share.calendarId)
      if (!current || accessPriority[share.access] > accessPriority[current.access])
        incoming.set(share.calendarId, share)
    }
    return Array.from(incoming.values())
  })
  const activeCalendar = state<number | null>(null)
  const selectedShare = derived(() => sharedCalendars().find(share => share.calendarId === activeCalendar()))
  const availabilityOnly = derived(() => selectedShare()?.access === 'free_busy')
  const writableCalendars = derived(() => [
    ...calendars(),
    ...sharedCalendars().filter(share => share.access === 'editor').map(share => ({
      id: share.calendarId, name: `${share.calendarName} · ${share.source}`,
    })),
  ])
  const canCreateEvent = derived(() => activeCalendar() === null
    ? calendars().length > 0 : writableCalendars().some(calendar => calendar.id === activeCalendar()))
  const target = new URLSearchParams(globalThis.location?.search).get('day')
  const initialDay = target && allDayInstant(target) !== null ? target : undefined
  const view = state<CalendarView>(initialDay ? 'day' : 'week')
  const displayZone = state(browserTimeZone)
  const today = () => zonedDay(Date.now() / 1000, displayZone())
  const focusDay = state(initialDay ?? today())
  const events = state<CalendarEvent[]>([])
  const busyPeriods = state<BusyPeriod[]>([])
  const shareNotice = state('')
  const searchInput = state('')
  const searchTerm = state('')
  const calendarSettings = state(false)
  const calendarSettingsError = state('')
  const calendarSettingsBusy = state(false)
  const calendarNameInput = state('')
  const shareCalendarInput = state('')
  const shareTeamInput = state('')
  const shareGranteeInput = state('')
  const shareAccessInput = state<CalendarAccess>('viewer')
  const range = derived(() => calendarRange(view(), focusDay()))
  const rangeLabel = derived(() => {
    const { start, end } = range()
    switch (view()) {
      case 'day': return formatCalendarDay(start, { dateStyle: 'full' })
      case 'month': return formatCalendarDay(focusDay(), { month: 'long', year: 'numeric' })
      default: return `${formatCalendarDay(start, shortDate)} – ${formatCalendarDay(addCalendarDays(end, -1), shortDate)}`
    }
  })
  const occurrences = derived(() => {
    const rows: (CalendarEvent | CalendarOccurrence)[] = []
    const unavailable: CalendarEvent[] = []
    if (searchTerm()) return { rows, unavailable }
    const { start, end } = range()
    const zone = displayZone()
    const from = Math.min(startOfZonedDay(start, zone), allDayInstant(start)!)
    const until = Math.max(startOfZonedDay(end, zone), allDayInstant(end)!)
    const budget = { remaining: 30_000 }
    for (const event of events()) {
      if (!event.recurring) rows.push(event)
      else if (!event.icalendar || rows.length >= 5000) unavailable.push(event)
      else {
        try {
          const expanded = expandSeries(event, event.icalendar, zone, from, until, budget)
          if (rows.length + expanded.length > 5000) unavailable.push(event)
          else rows.push(...expanded)
        }
        catch { unavailable.push(event) }
      }
    }
    return { rows, unavailable }
  })
  const recurringSeries = derived(() => occurrences().unavailable)
  const activeCalendarName = derived(() => selectedShare()?.calendarName ?? calendars().find(item => item.id === activeCalendar())?.name ?? 'All calendars')
  const downloadCalendar = derived(() => selectedShare() ? null : activeCalendar() ?? (calendars().length === 1 ? calendars()[0].id : null))
  const calendarExport = derived(() => {
    const id = downloadCalendar()
    if (id === null || !account()) return ''
    const params = new URLSearchParams({ calendarId: String(id), account: account()! })
    return `/webmail/api/calendar-export?${params}`
  })
  const calendarDays = derived(() => {
    if (searchTerm()) return []
    const { start, end } = range()
    const mode = view()
    const zone = displayZone()
    const thisMonth = focusDay().slice(0, 7)
    const currentDay = today()
    const records = occurrences().rows
    const formatter = new Intl.DateTimeFormat(undefined, { timeZone: zone, timeStyle: 'short' })
    const days = []
    let from = startOfZonedDay(start, zone)
    for (let day = start; day < end; day = addCalendarDays(day, 1)) {
      const nextDay = addCalendarDays(day, 1)
      const until = startOfZonedDay(nextDay, zone)
      const dateFrom = allDayInstant(day)!
      const dateUntil = allDayInstant(nextDay)!
      const entries = records.filter(event => eventOverlaps(event.start, event.end,
        event.all_day ? dateFrom : from, event.all_day ? dateUntil : until, event.all_day))
        .sort((a, b) => Number(b.all_day) - Number(a.all_day) || a.start - b.start || a.id - b.id)
        .map(event => ({
          ...event,
          time: eventTime(event, from, until, mode, formatter),
        }))
      from = until
      if (mode === 'agenda' && !entries.length) continue
      days.push({
        day, entries, markers: entries.slice(0, 3), dimmed: mode === 'month' && !day.startsWith(thisMonth), today: day === currentDay,
        label: formatCalendarDay(day, { weekday: 'short', month: 'short', day: 'numeric' }),
        number: Number(day.slice(8)),
      })
    }
    return days
  })
  const monthWeekdays = Array.from({ length: 7 }, (_, index) =>
    formatCalendarDay(addCalendarDays('2026-01-05', index), { weekday: 'short' }))
  const loading = state(true)
  const error = state('')
  const reminders = useCalendarReminders(account, () => !error())
  const importOpen = state(false)
  const importFile = state<File | null>(null)
  const importDestination = state('new')
  const newCalendarName = state('')
  const importRows = state<ImportEvent[]>([])
  const importBusy = state(false)
  const importError = state('')
  const importFinished = state(false)
  const canPreview = derived(() => Boolean(importFile() && !importBusy() && (importDestination() !== 'new' || newCalendarName().trim())))
  const readyCount = derived(() => importRows().filter(event => event.status === 'ready').length)
  const resultSummary = derived(() => {
    const counts = importRows().reduce((result, event) => {
      result[event.status]++
      return result
    }, { ready: 0, imported: 0, skipped: 0, error: 0 })
    const parts = [`${importFinished() ? counts.imported : counts.ready} ${importFinished() ? 'imported' : 'ready'}`]
    if (counts.skipped) parts.push(`${counts.skipped} skipped`)
    if (counts.error) parts.push(`${counts.error} ${counts.error === 1 ? 'error' : 'errors'}`)
    return parts.join(', ')
  })
  let request: AbortController | undefined
  let shareRequest: AbortController | undefined
  let importRequest: AbortController | undefined
  let settingsRequest: AbortController | undefined
  const api = createMailApi(account, () => {
    request?.abort()
    shareRequest?.abort()
    importRequest?.abort()
    settingsRequest?.abort()
    editor.clearEditor()
    account.set(undefined)
    calendars.set([])
    shares.set([])
    activeCalendar.set(null)
    events.set([])
    busyPeriods.set([])
    onAuthError()
  })

  function applyShares(rows: CalendarShare[]) {
    const accessBefore = selectedShare()?.access
    const editorId = Number(editor.editorCalendar())
    const findEditorShare = () => sharedCalendars().find(share => share.calendarId === editorId)
    const editorBefore = findEditorShare()?.access
    shares.set(rows.map(share => ({ ...share, calendarName: share.displayName ?? calendarName(share.calendarName) })))
    if (editorBefore && editorBefore !== findEditorShare()?.access) editor.clearEditor()
    const accessAfter = selectedShare()?.access
    if (accessBefore === accessAfter) return false
    if (!accessAfter) {
      activeCalendar.set(null)
      shareNotice.set('You no longer have access to this shared calendar.')
    }
    else if (accessBefore) shareNotice.set('Your access to this calendar changed.')
    if (accessAfter === 'free_busy' || !accessAfter) {
      searchTerm.set('')
      searchInput.set('')
    }
    return true
  }

  async function refresh() {
    request?.abort()
    shareRequest?.abort()
    const pending = new AbortController()
    request = pending
    loading.set(true)
    error.set('')
    events.set([])
    busyPeriods.set([])
    const signal = AbortSignal.any([pending.signal, AbortSignal.timeout(10_000)])
    try {
      if (!account()) {
        const { user } = await api<{ user: User }>('/webmail/auth/me', { signal })
        if (pending.signal.aborted) return
        account.set(user.username)
      }
      const [{ calendars: visible }, { shares: currentShares }, roster] = await Promise.all([
        api<{ calendars: Calendar[] }>('/webmail/api/calendars', { signal }),
        api<{ shares: CalendarShare[] }>('/webmail/api/calendar-shares', { signal }),
        calendarSettings() ? api<CalendarTeam[]>('/webmail/api/teams', { signal }) : Promise.resolve(null),
      ])
      if (pending.signal.aborted) return
      calendars.set(visible.map(calendar => ({ ...calendar, name: calendar.display_name ?? calendarName(calendar.name) })))
      applyShares(currentShares)
      if (roster) teams.set(roster)
      if (activeCalendar() !== null && !selectedShare() && !visible.some(item => item.id === activeCalendar())) activeCalendar.set(null)
      await loadCalendarView(signal)
    }
    catch (cause) {
      if (!pending.signal.aborted)
        error.set(cause instanceof Error ? cause.message : 'Could not load your calendar.')
    }
    finally {
      if (request === pending) {
        request = undefined
        loading.set(false)
      }
    }
  }

  async function loadCalendarView(signal: AbortSignal) {
    if (!calendars().length && !selectedShare()) return
    const params = new URLSearchParams()
    const selected = activeCalendar()
    if (selected !== null) params.set('calendarId', String(selected))
    const { start, end } = range()
    const zone = displayZone()
    if (availabilityOnly()) {
      params.set('start', String(startOfZonedDay(start, zone)))
      params.set('end', String(startOfZonedDay(end, zone)))
      const result = await api<{ busy: BusyPeriod[] }>(`/webmail/api/calendar-free-busy?${params}`, { signal })
      if (!signal.aborted) busyPeriods.set(result.busy)
    }
    else {
      const query = searchTerm()
      if (query) params.set('q', query)
      else {
        params.set('instances', '1')
        params.set('start', String(Math.min(startOfZonedDay(start, zone), allDayInstant(start)!)))
        params.set('end', String(Math.max(startOfZonedDay(end, zone), allDayInstant(end)!)))
      }
      const result = await api<{ events: CalendarEvent[] }>(`/webmail/api/calendar-events?${params}`, { signal })
      if (!signal.aborted) events.set(result.events)
    }
  }

  async function recheckOpenSharedEvent(signal: AbortSignal) {
    const id = editor.editingId()
    const calendarId = Number(editor.editorCalendar())
    if (id === null || !editor.editorOpen() || !sharedCalendars().some(share => share.calendarId === calendarId)) return
    try {
      await api(`/webmail/api/calendar-events/${id}`, { signal })
    }
    catch (cause) {
      if (!(cause instanceof MailApiError) || cause.status !== 404) throw cause
      if (!signal.aborted && editor.editingId() === id && editor.editorOpen()) {
        editor.clearEditor()
        shareNotice.set('This shared event is no longer available.')
      }
    }
  }

  async function recheckShares() {
    if (!account() || request || shareRequest || calendarSettingsBusy()) return
    const pending = new AbortController()
    shareRequest = pending
    const signal = AbortSignal.any([pending.signal, AbortSignal.timeout(10_000)])
    try {
      const { shares: current } = await api<{ shares: CalendarShare[] }>('/webmail/api/calendar-shares', { signal })
      if (signal.aborted) return
      if (applyShares(current)) await refresh()
      else if (selectedShare()) {
        await recheckOpenSharedEvent(signal)
        await loadCalendarView(signal)
        if (!signal.aborted) error.set('')
      }
    }
    catch (cause) {
      if (!pending.signal.aborted && selectedShare()) {
        events.set([])
        busyPeriods.set([])
        error.set(cause instanceof Error ? cause.message : 'Could not refresh the shared calendar.')
      }
    }
    finally {
      if (shareRequest === pending) shareRequest = undefined
    }
  }

  const editor = useCalendarEditor(api, dialog, async () => {
    await refresh()
    void reminders.pollReminders()
  })

  function selectCalendar(id: number | null) {
    shareNotice.set('')
    activeCalendar.set(id)
    if (availabilityOnly()) {
      searchTerm.set('')
      searchInput.set('')
    }
    return refresh()
  }

  function showView(mode: CalendarView) {
    view.set(mode)
    searchTerm.set('')
    searchInput.set('')
    return refresh()
  }

  function shiftView(count: number) {
    focusDay.set(shiftCalendarDay(view(), focusDay(), count))
    return refresh()
  }

  function goToToday() {
    focusDay.set(today())
    return refresh()
  }

  function showDay(day: string) {
    focusDay.set(day)
    return showView('day')
  }

  function changeDate(change: Event) {
    const day = (change.target as HTMLInputElement).value
    if (allDayInstant(day) === null) return
    focusDay.set(day)
    return refresh()
  }

  function changeZone(change: Event) {
    displayZone.set((change.target as HTMLSelectElement).value)
    return refresh()
  }

  function search() {
    searchTerm.set(searchInput().trim())
    return refresh()
  }

  function clearSearch() {
    searchInput.set('')
    return search()
  }

  function openNewEvent(day = focusDay()) {
    if (!canCreateEvent()) return
    const id = activeCalendar() ?? calendars()[0]?.id
    if (id !== undefined) editor.createEvent(day, id, displayZone())
  }

  function openEvent(event: CalendarEvent | CalendarOccurrence) {
    const share = sharedCalendars().find(item => item.calendarId === event.calendar_id)
    if (share?.access === 'free_busy') return
    return editor.editEvent(event, displayZone(), share?.access === 'viewer')
  }

  function nameFor(event: CalendarEvent) {
    return selectedShare()?.calendarName ?? calendars().find(calendar => calendar.id === event.calendar_id)?.name ?? ''
  }

  function eventColor(event: CalendarEvent) {
    return calendarColor(calendars().find(calendar => calendar.id === event.calendar_id)?.color)
  }

  async function saveCalendar(write: (signal: AbortSignal) => Promise<void>) {
    if (calendarSettingsBusy()) return false
    const pending = new AbortController()
    settingsRequest = pending
    calendarSettingsBusy.set(true)
    calendarSettingsError.set('')
    try {
      await write(AbortSignal.any([pending.signal, AbortSignal.timeout(10_000)]))
      if (!pending.signal.aborted) await refresh()
      return !pending.signal.aborted
    }
    catch (cause) {
      if (!pending.signal.aborted) calendarSettingsError.set(cause instanceof Error ? cause.message : 'Could not save your calendar.')
      return false
    }
    finally {
      if (settingsRequest === pending) calendarSettingsBusy.set(false)
    }
  }

  function createCalendar() {
    const name = calendarNameInput().trim()
    if (!name) return
    return saveCalendar(async (signal) => {
      const created = await api<{ id: number }>('/webmail/api/calendars', { method: 'POST', body: JSON.stringify({ name }), signal })
      if (!signal.aborted) {
        activeCalendar.set(created.id)
        calendarNameInput.set('')
      }
    })
  }

  function setCalendarColor(calendar: Calendar, change: Event) {
    const color = (change.target as HTMLInputElement).value
    return saveCalendar(async (signal) => {
      await api(`/webmail/api/calendars/${calendar.id}`, { method: 'PATCH', body: JSON.stringify({ color }), signal })
    })
  }

  function toggleCalendarSettings() {
    calendarSettings.set(!calendarSettings())
    if (calendarSettings()) return refresh()
  }

  function writeShare(team: string, calendarId: number, grantee: string, access: CalendarAccess | null) {
    return saveCalendar(async (signal) => {
      await api(`/webmail/api/teams/${encodeURIComponent(team)}/calendar-shares`, {
        method: 'PUT', body: JSON.stringify({ calendarId, grantee, access }), signal,
      })
    })
  }

  async function grantCalendar() {
    const team = shareTeamInput() || teams()[0]?.id
    const calendarId = Number(shareCalendarInput()) || calendars()[0]?.id
    const grantee = shareGranteeInput().trim()
    if (team && calendarId && grantee && await writeShare(team, calendarId, grantee, shareAccessInput()))
      shareGranteeInput.set('')
  }

  function selectGrantAccess(share: CalendarShare, event: Event) {
    const select = event.target as HTMLSelectElement
    const access = select.value as CalendarAccess
    select.value = share.access
    return writeShare(share.team, share.calendarId, share.grantee, access)
  }

  function revokeCalendarGrant(share: CalendarShare) {
    return writeShare(share.team, share.calendarId, share.grantee, null)
  }

  function resetImportResult() {
    importRows.set([])
    importError.set('')
    importFinished.set(false)
  }

  function toggleImport() {
    importOpen.set(!importOpen())
    importFile.set(null)
    importDestination.set(activeCalendar() === null || selectedShare() ? 'new' : String(activeCalendar()))
    newCalendarName.set('')
    resetImportResult()
  }

  function selectImportFile(event: Event) {
    const file = (event.target as HTMLInputElement).files?.[0] ?? null
    importFile.set(file)
    resetImportResult()
  }

  function selectImportDestination(event: Event) {
    importDestination.set((event.target as HTMLSelectElement).value)
    resetImportResult()
  }

  function setNewCalendarName(event: Event) {
    newCalendarName.set((event.target as HTMLInputElement).value)
    resetImportResult()
  }

  function importEventDate(event: ImportEvent): string {
    if (event.start === null) return ''
    const date = new Date(event.start * 1000)
    return event.allDay ? `${dateLabel.format(date)} · All day` : dateTimeLabel.format(date)
  }

  async function submitImport(mode: 'preview' | 'import') {
    const file = importFile()
    if (!file || !canPreview() || (mode === 'import' && readyCount() === 0)) return
    importBusy.set(true)
    importError.set('')
    const pending = new AbortController()
    importRequest = pending
    const params = new URLSearchParams({ mode })
    if (importDestination() === 'new') params.set('calendarName', newCalendarName().trim())
    else params.set('calendarId', importDestination())
    try {
      const result = await api<ImportResult>(`/webmail/api/calendar-import?${params}`, {
        method: 'POST', body: file, headers: { 'Content-Type': 'text/calendar' },
        signal: AbortSignal.any([pending.signal, AbortSignal.timeout(60000)]),
      })
      if (pending.signal.aborted) return
      importRows.set(result.events)
      importFinished.set(mode === 'import')
      if (result.calendarId !== null) {
        importDestination.set(String(result.calendarId))
        if (mode === 'import') await selectCalendar(result.calendarId)
      }
    }
    catch (cause) {
      if (!pending.signal.aborted) importError.set(cause instanceof Error ? cause.message : 'Could not import this calendar.')
    }
    finally {
      if (importRequest === pending) importBusy.set(false)
    }
  }

  return {
    account, calendars, activeCalendar, activeCalendarName, calendarExport, calendarColor, eventColor, nameFor,
    sharedCalendars, selectedShare, availabilityOnly, canCreateEvent, writableCalendars, busyPeriods, shareNotice, recheckShares,
    busyPeriodLabel: (period: BusyPeriod) => new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium', timeStyle: 'short', timeZone: displayZone(),
    }).formatRange(new Date(period.start * 1000), new Date(period.end * 1000)),
    view, calendarViews, calendarDays, monthWeekdays, recurringSeries, rangeLabel, loading, error,
    searchInput, searchTerm, events, search, clearSearch, focusDay, displayZone, calendarTimeZones,
    refresh, selectCalendar, showView, shiftView, goToToday, showDay, changeDate, changeZone,
    calendarSettings, calendarSettingsError, calendarSettingsBusy, calendarNameInput, createCalendar, setCalendarColor, toggleCalendarSettings,
    teams, outgoingShares, shareCalendarInput, shareTeamInput, shareGranteeInput, shareAccessInput,
    calendarAccessLabels, grantCalendar, revokeCalendarGrant, selectGrantAccess,
    teamName: (id: string) => teams().find(team => team.id === id)?.name ?? id,
    openEvent, openNewEvent, calendarEventDate: (event: CalendarEvent) => calendarEventDate(event, displayZone()),
    ...editor,
    ...reminders,
    importOpen, importDestination, newCalendarName, importBusy, importError, importRows, importFinished,
    readyCount, canPreview, resultSummary, toggleImport, selectImportFile, selectImportDestination,
    setNewCalendarName, submitImport, importEventDate, importStatusLabels,
    destroy: () => {
      request?.abort()
      shareRequest?.abort()
      importRequest?.abort()
      settingsRequest?.abort()
      editor.clearEditor()
    },
  }
}

function eventTime(event: CalendarEvent, from: number, until: number, mode: CalendarView, formatter: Intl.DateTimeFormat): string {
  if (event.all_day) return 'All day'
  if (event.start < from)
    return event.end !== null && event.end < until ? `Until ${formatter.format(event.end * 1000)}` : 'Continues'
  const start = formatter.format(event.start * 1000)
  if (mode === 'month' || event.end === null || event.end <= event.start) return start
  if (event.end > until) return `${start} · Continues`
  return formatter.formatRange(new Date(event.start * 1000), new Date(event.end * 1000))
}
