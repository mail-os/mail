import { derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'
import { addCalendarDays, allDayInstant, calendarTimeZones, instantForLocal, utcDay, zonedDateTime } from './calendar-dates'
import type { TimeWindow } from './calendar-free-time'
import type { CalendarEvent, CalendarEventDetail } from './calendar-types'
import { createSeriesSource, editEventReminder, editOccurrence, editSeriesSource, readEventReminder, readOccurrence, readSeriesSchedule } from './calendar-recurrence'
import type { CalendarOccurrence, OccurrenceRef } from './calendar-recurrence'
import { defaultRepeat } from './calendar-repeat'
import type { CalendarRepeat, CalendarWallTime, RepeatEnd, RepeatFrequency } from './calendar-repeat'
import { noReminder, reminderOptions } from './calendar-alarms'
import type { AlarmPreference, ReminderChoice } from './calendar-alarms'

export interface CalendarDialog {
  ref: { current?: HTMLDialogElement | null }
  nextTick: (callback: () => void) => void
}

export function useCalendarEditor(api: ReturnType<typeof createMailApi>, dialog: CalendarDialog, refresh: () => Promise<void>) {
  const editorOpen = state(false)
  const editorBusy = state(false)
  const editorLoaded = state(false)
  const editorError = state('')
  const editorConflict = state(false)
  const editingId = state<number | null>(null)
  const editorRecurring = state(false)
  const editorOccurrence = state(false)
  const editorHasOccurrence = state(false)
  const editorViewer = state(false)
  const editorProtectedOccurrence = state(false)
  const editorReadOnly = derived(() => editorViewer() || editorProtectedOccurrence())
  const confirmDelete = state(false)
  const editorCalendar = state('')
  const editorTitle = state('')
  const editorLocation = state('')
  const editorDescription = state('')
  const editorSourceMessage = state<string | null>(null)
  const editorAllDay = state(false)
  const editorStart = state('')
  const editorEnd = state('')
  const editorZone = state('UTC')
  const editorRepeatedHour = state(false)
  const editorScheduleEditable = state(true)
  const editorReminderEditable = state(true)
  const editorReminder = state<ReminderChoice>('none')
  const otherReminders = state(0)
  const repeatFrequency = state<RepeatFrequency>('none')
  const repeatEvery = state(1)
  const repeatEnd = state<RepeatEnd>('never')
  const repeatCount = state(10)
  const repeatUntil = state('')
  const repeatOptions = derived(() => repeatFrequency() !== 'none' && repeatFrequency() !== 'custom')
  const editorTimeZones = derived(() => calendarTimeZones.includes(editorZone())
    ? calendarTimeZones : [...calendarTimeZones, editorZone()].sort())
  const editorLabel = derived(() => editorViewer() ? 'Event details' : editingId() === null ? 'New event' : editorRecurring() ? 'Edit series' : editorOccurrence() ? 'Edit occurrence' : 'Edit event')
  let initial: { detail: CalendarEventDetail, start: string, end: string, zone: string, repeat: CalendarRepeat, reminder: ReminderChoice } | undefined
  let occurrence: { ref: OccurrenceRef, displayZone: string } | undefined
  let draftSeriesUid: string | undefined
  let displayZone = 'UTC'
  let pending: AbortController | undefined

  function showEditor() {
    editorError.set('')
    editorConflict.set(false)
    confirmDelete.set(false)
    editorOpen.set(true)
    dialog.nextTick(() => { if (dialog.ref.current && !dialog.ref.current.open) dialog.ref.current.showModal() })
  }

  function closeEditor() {
    if (editorBusy()) return
    const wasStale = editorConflict()
    dialog.ref.current?.close()
    editorOpen.set(false)
    if (wasStale) void refresh()
  }

  function createEvent(day: string, calendarId: number, zone: string, source?: { reference: string, subject: string }, slot?: TimeWindow) {
    if (editorBusy()) return
    initial = undefined
    occurrence = undefined
    draftSeriesUid = undefined
    displayZone = zone
    editingId.set(null)
    editorRecurring.set(false)
    editorOccurrence.set(false)
    editorHasOccurrence.set(false)
    editorViewer.set(false)
    editorProtectedOccurrence.set(false)
    editorScheduleEditable.set(true)
    editorReminderEditable.set(true)
    editorReminder.set('none')
    otherReminders.set(0)
    loadRepeat(defaultRepeat)
    editorCalendar.set(String(calendarId))
    editorTitle.set(source?.subject ?? '')
    editorSourceMessage.set(source?.reference ?? null)
    editorLocation.set('')
    editorDescription.set('')
    // A TZID local time resolves to the first occurrence of a repeated hour.
    // Use explicit UTC fields when the selected slot requires the later one.
    const repeatedHour = slot ? [slot.start, slot.end].some(stamp => instantForLocal(zonedDateTime(stamp, zone), zone) !== stamp) : false
    const timeZone = repeatedHour ? 'UTC' : zone
    editorRepeatedHour.set(repeatedHour)
    editorZone.set(timeZone)
    editorAllDay.set(false)
    editorStart.set(slot ? dateTimeInput(slot.start, timeZone) : `${day}T09:00`)
    editorEnd.set(slot ? dateTimeInput(slot.end, timeZone) : `${day}T10:00`)
    editorLoaded.set(true)
    showEditor()
  }

  async function load(id: number, zone: string, thisOccurrence = editorOccurrence()) {
    editorBusy.set(true)
    const request = new AbortController()
    pending = request
    try {
      const selection = thisOccurrence ? occurrence : undefined
      const detail = await api<CalendarEventDetail>(`/webmail/api/calendar-events/${id}?source=1`, {
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]),
      })
      if (request.signal.aborted) return
      editorSourceMessage.set(detail.source_message ?? null)
      const local = selection && detail.icalendar ? readOccurrence(detail.event, detail.icalendar, selection.displayZone, selection.ref) : null
      if (selection && !local) {
        editorError.set('This occurrence changed or no longer exists. Close the editor to refresh the calendar.')
        editorConflict.set(true)
        return
      }
      const event = local ?? detail.event
      const series = !selection && event.recurring
      let schedule
      if (series && detail.icalendar) {
        try { schedule = readSeriesSchedule(detail.icalendar, zone) }
        catch { /* The existing metadata editor still works for this resource. */ }
      }
      const inputZone = schedule?.editable ? schedule.zone : zone
      const start = schedule?.editable ? schedule.start : event.all_day ? utcDay(event.start) : dateTimeInput(event.start, inputZone)
      const end = schedule?.editable ? schedule.end
        : event.end === null ? '' : event.all_day ? addCalendarDays(utcDay(event.end), -1) : dateTimeInput(event.end, inputZone)
      const repeat = schedule?.repeat ?? { ...defaultRepeat, frequency: series ? 'custom' as const : 'none' as const }
      const description = local ? local.description : detail.description
      let reminder: AlarmPreference | undefined = local?.reminder
      if (!reminder && detail.icalendar) {
        try { reminder = readEventReminder(detail.icalendar) }
        catch { /* Leave alarms as-is if the resource has no primary event. */ }
      }
      const settings = reminder ?? noReminder
      initial = { detail: { ...detail, event, description }, start, end, zone: inputZone, repeat, reminder: settings.choice }
      editorCalendar.set(String(detail.calendarId))
      editorTitle.set(event.summary)
      editorLocation.set(event.location ?? '')
      editorDescription.set(description ?? '')
      editorZone.set(inputZone)
      editorAllDay.set(event.all_day)
      editorStart.set(start)
      editorEnd.set(end)
      editorOccurrence.set(Boolean(selection))
      editorRecurring.set(series)
      editorProtectedOccurrence.set(local?.canEditOccurrence === false)
      editorScheduleEditable.set(!series || schedule?.editable === true)
      editorReminderEditable.set(Boolean(reminder))
      editorReminder.set(settings.choice)
      otherReminders.set(settings.others)
      loadRepeat(repeat)
      editorLoaded.set(true)
      editorError.set('')
      editorConflict.set(false)
      confirmDelete.set(false)
    }
    catch (error) {
      if (!request.signal.aborted) editorError.set(error instanceof Error ? error.message : 'Could not open the event.')
    }
    finally {
      if (pending === request) editorBusy.set(false)
    }
  }

  function editEvent(event: CalendarEvent | CalendarOccurrence, zone: string, readOnly: boolean) {
    if (editorBusy()) return
    initial = undefined
    editorRepeatedHour.set(false)
    displayZone = zone
    editingId.set(event.id)
    editorCalendar.set(String(event.calendar_id))
    editorZone.set(zone)
    occurrence = 'occurrence' in event ? { ref: event.occurrence, displayZone: zone } : undefined
    editorHasOccurrence.set(Boolean(occurrence))
    editorOccurrence.set(Boolean(occurrence))
    editorViewer.set(readOnly)
    editorProtectedOccurrence.set(false)
    editorRecurring.set(event.recurring && !occurrence)
    editorLoaded.set(false)
    showEditor()
    return load(event.id, zone)
  }

  function clearEditor() {
    pending?.abort()
    pending = undefined
    initial = undefined
    occurrence = undefined
    draftSeriesUid = undefined
    dialog.ref.current?.close()
    editorOpen.set(false)
    editorBusy.set(false)
    editorLoaded.set(false)
    editingId.set(null)
    editorCalendar.set('')
    editorTitle.set('')
    editorSourceMessage.set(null)
    editorLocation.set('')
    editorDescription.set('')
    editorStart.set('')
    editorEnd.set('')
    editorError.set('')
  }

  function reloadEvent() {
    const id = editingId()
    if (id !== null && !editorBusy()) return load(id, displayZone)
  }

  function showEventScope(thisOccurrence: boolean) {
    const id = editingId()
    if (id !== null && editorHasOccurrence() && !editorBusy() && thisOccurrence !== editorOccurrence())
      return load(id, displayZone, thisOccurrence)
  }

  function loadRepeat(repeat: CalendarRepeat) {
    repeatFrequency.set(repeat.frequency)
    repeatEvery.set(repeat.interval)
    repeatEnd.set(repeat.end)
    repeatCount.set(repeat.count)
    repeatUntil.set(repeat.until)
  }

  function changeRepeatEnd(event: Event) {
    const end = (event.target as HTMLSelectElement).value as RepeatEnd
    repeatEnd.set(end)
    if (end === 'date' && !repeatUntil()) repeatUntil.set(editorStart().slice(0, 10))
  }

  function toggleAllDay(change: Event) {
    const allDay = (change.target as HTMLInputElement).checked
    if (allDay === editorAllDay()) return
    const start = editorStart().slice(0, 10)
    const end = editorEnd().slice(0, 10)
    editorStart.set(allDay || !start ? start : `${start}T09:00`)
    editorEnd.set(allDay || !end ? end : `${end}T10:00`)
    editorAllDay.set(allDay)
  }

  function setEventBoundary(field: 'start' | 'end', change: Event) {
    const input = change.target as HTMLInputElement
    const value = input.value
    if (field === 'end') {
      editorEnd.set(value)
      return
    }

    // Move the default end with the start when it would otherwise be before it.
    if (editingId() === null && value && editorEnd() && value > editorEnd()) {
      editorEnd.set(editorAllDay() ? value : `${value.slice(0, 10)}T${editorEnd().slice(11)}`)
      if (!editorAllDay() && editorEnd() <= value) editorEnd.set('')
    }
    editorStart.set(value)
  }

  function timing() {
    const allDay = editorAllDay()
    const raw = initial?.detail.event
    const sameBasis = initial && raw?.all_day === allDay && (allDay || initial.zone === editorZone()) ? initial : undefined
    const start = sameBasis && editorStart() === sameBasis.start ? sameBasis.detail.event.start
      : allDay ? allDayInstant(editorStart()) : instantForLocal(editorStart(), editorZone())
    if (start === null) throw new Error(allDay ? 'Enter a valid start date.' : 'Enter a start time that exists in the selected time zone.')
    let end: number | null = null
    if (editorEnd()) {
      end = sameBasis && editorEnd() === sameBasis.end ? sameBasis.detail.event.end
        : allDay ? endOfAllDayEvent(editorEnd()) : instantForLocal(editorEnd(), editorZone())
      if (end === null) throw new Error(allDay ? 'Enter a valid last day.' : 'Enter an end time that exists in the selected time zone.')
      if (end <= start) throw new Error(allDay ? 'The last day must be on or after the start date.' : 'The end time must follow the start time.')
    }
    return { start, end, allDay }
  }

  async function saveEvent() {
    if (editorBusy() || !editorLoaded() || editorConflict() || editorReadOnly()) return
    const match = initial
    const summary = editorTitle().trim()
    if (!summary) {
      editorError.set('Enter an event title.')
      return
    }

    const changes: Parameters<typeof editOccurrence>[4] = {}
    if (!match || summary !== match.detail.event.summary) changes.summary = summary
    if (!match || editorLocation() !== (match.detail.event.location ?? '')) changes.location = editorLocation()
    if (!match || editorDescription() !== (match.detail.description ?? '')) changes.description = editorDescription()
    const reminderChanged = editorReminderEditable() && editorReminder() !== (match?.reminder ?? 'none')
    if (reminderChanged) changes.reminder = editorReminder()
    const timeChanged = !match || (editorScheduleEditable() && (
      editorAllDay() !== match.detail.event.all_day || (!editorAllDay() && editorZone() !== match.zone)
      || editorStart() !== match.start || editorEnd() !== match.end
    ))
    const repeat: CalendarRepeat = {
      frequency: repeatFrequency(), interval: repeatEvery(), end: repeatEnd(), count: repeatCount(), until: repeatUntil(),
    }
    const repeatChanged = Boolean(match && editorScheduleEditable() && !editorOccurrence() && repeatDiffers(match.repeat, repeat))
    const newSeries = !match && (repeat.frequency !== 'none' || reminderChanged)
    const becomesSeries = Boolean(match && !match.detail.event.recurring && repeatChanged)
    const rescheduledSeries = Boolean(match && !editorOccurrence() && (repeatChanged || ((editorRecurring() || reminderChanged) && timeChanged)))
    if (timeChanged && !newSeries && !rescheduledSeries) {
      try { changes.time = timing() }
      catch (error) {
        editorError.set(error instanceof Error ? error.message : 'Enter valid event dates.')
        return
      }
    }
    if (match && !rescheduledSeries && !Object.keys(changes).length) {
      closeEditor()
      return
    }

    await mutate(async (signal) => {
      if (match && editorOccurrence()) {
        await replaceOccurrence(match.detail, changes, signal)
      }
      else if (newSeries || rescheduledSeries) {
        const clock = { start: editorStart(), end: editorEnd(), allDay: editorAllDay(), zone: editorZone() }
        await saveSeries(match?.detail, clock, repeat, timeChanged || becomesSeries, repeatChanged, changes, signal)
      }
      else if (match && reminderChanged) {
        if (!match.detail.icalendar) throw new Error('This event has no calendar resource to update.')
        await replaceEventSource(match.detail, editEventReminder(match.detail.icalendar, changes), signal)
      }
      else if (match) {
        await api(`/webmail/api/calendar-events/${match.detail.event.id}`, {
          method: 'PATCH', headers: { 'If-Match': match.detail.event.etag }, body: JSON.stringify(changes), signal,
        })
      }
      else {
        await api('/webmail/api/calendar-events', {
          method: 'POST', headers: sourceMessageHeaders(), body: JSON.stringify({ ...changes, calendarId: Number(editorCalendar()) }), signal,
        })
      }
    })
  }

  function sourceMessageHeaders(): Headers {
    const headers = new Headers()
    const reference = editorSourceMessage()
    if (reference) headers.set('X-Webmail-Source-Message', reference)
    return headers
  }

  async function saveSeries(detail: CalendarEventDetail | undefined, clock: CalendarWallTime, repeat: CalendarRepeat,
    timeChanged: boolean, repeatChanged: boolean, changes: Parameters<typeof editOccurrence>[4], signal: AbortSignal) {
    const old = detail?.icalendar ? readSeriesSchedule(detail.icalendar, displayZone) : undefined
    const floating = old?.floating && old.zone === clock.zone
    const hasDefinition = old?.embedded && old.zone === clock.zone
    let zoneSource: string | undefined
    if (timeChanged && !clock.allDay && !floating && !hasDefinition && clock.zone !== 'UTC') {
      const query = new URLSearchParams({ zone: clock.zone })
      const definition = await api<{ icalendar: string }>(`/webmail/api/calendar-timezone?${query}`, { signal })
      zoneSource = definition.icalendar
    }
    if (detail && !detail.icalendar) throw new Error('This event has no calendar resource to update.')
    const source = detail?.icalendar
      ? editSeriesSource(detail.icalendar, displayZone, clock, repeat, timeChanged, repeatChanged, changes, zoneSource)
      : createSeriesSource(draftSeriesUid ??= crypto.randomUUID(), clock, repeat, changes, zoneSource)
    if (detail) {
      await replaceEventSource(detail, source, signal)
    }
    else {
      const query = new URLSearchParams({ calendarId: editorCalendar() })
      await api(`/webmail/api/calendar-events?${query}`, {
        method: 'POST', headers: sourceMessageHeaders(), body: new Blob([source], { type: 'text/calendar;charset=utf-8' }), signal,
      })
    }
  }

  async function deleteEvent() {
    const detail = initial?.detail
    if (!detail || !confirmDelete() || editorBusy() || editorConflict() || editorReadOnly()) return
    await mutate(signal => editorOccurrence() ? replaceOccurrence(detail, { cancel: true }, signal)
      : api(`/webmail/api/calendar-events/${detail.event.id}`, {
          method: 'DELETE', headers: { 'If-Match': detail.event.etag }, signal,
        }))
  }

  function replaceOccurrence(detail: CalendarEventDetail, changes: Parameters<typeof editOccurrence>[4], signal: AbortSignal) {
    if (!detail.icalendar || !occurrence) throw new Error('The occurrence is unavailable. Reload it before saving.')
    const source = editOccurrence(detail.event, detail.icalendar, occurrence.displayZone, occurrence.ref, changes)
    return replaceEventSource(detail, source, signal)
  }

  function replaceEventSource(detail: CalendarEventDetail, source: string, signal: AbortSignal) {
    return api(`/webmail/api/calendar-events/${detail.event.id}`, {
      method: 'PUT',
      headers: { 'If-Match': detail.event.etag },
      body: new Blob([source], { type: 'text/calendar;charset=utf-8' }),
      signal,
    })
  }

  async function mutate(write: (signal: AbortSignal) => Promise<unknown>) {
    const request = new AbortController()
    pending = request
    editorBusy.set(true)
    editorError.set('')
    let saved = false
    try {
      await write(AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]))
      saved = !request.signal.aborted
    }
    catch (error) {
      if (!request.signal.aborted) {
        editorConflict.set(error instanceof MailApiError && error.status === 412)
        editorError.set(error instanceof Error ? error.message : 'Could not save the change.')
      }
    }
    finally {
      if (pending === request) editorBusy.set(false)
    }
    if (saved) {
      closeEditor()
      await refresh()
    }
  }

  return {
    editorOpen, editorBusy, editorLoaded, editorError, editorConflict, editingId, editorLabel,
    editorRecurring, editorOccurrence, editorHasOccurrence, editorReadOnly, editorViewer, editorProtectedOccurrence, editorCalendar, editorTitle, editorLocation, editorDescription,
    editorSourceMessage,
    editorAllDay, editorStart, editorEnd, editorZone, editorRepeatedHour, editorScheduleEditable, editorTimeZones,
    editorReminder, editorReminderEditable, otherReminders, reminderOptions,
    repeatFrequency, repeatEvery, repeatEnd, repeatCount, repeatUntil, repeatOptions, changeRepeatEnd,
    confirmDelete, toggleAllDay, setEventBoundary,
    createEvent, editEvent, closeEditor, reloadEvent, saveEvent, deleteEvent, showEventScope,
    clearEditor,
  }
}

function repeatDiffers(before: CalendarRepeat, after: CalendarRepeat): boolean {
  if (before.frequency !== after.frequency) return true
  if (after.frequency === 'none' || after.frequency === 'custom') return false
  return before.interval !== after.interval || before.end !== after.end
    || (after.end === 'count' && before.count !== after.count) || (after.end === 'date' && before.until !== after.until)
}

function dateTimeInput(stamp: number, zone: string): string {
  return zonedDateTime(stamp, zone).replace(/:00$/, '')
}

function endOfAllDayEvent(lastDay: string): number | null {
  const start = allDayInstant(lastDay)
  return start === null ? null : allDayInstant(addCalendarDays(lastDay, 1))
}
