import { derived, state } from '@stacksjs/stx'
import { addCalendarDays } from './calendar-dates'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface DayLabel { day: string, label: string | null, revision: number }
interface DateRange { start: string, end: string }
const endpoint = '/webmail/api/calendar-day-labels'

export function useCalendarDayLabels(api: ReturnType<typeof createMailApi>, focusDay: () => string, visible: () => boolean, editable: () => boolean) {
  const records = state(new Map<string, DayLabel>())
  const ready = state(false)
  const edit = state<{ day: string, revision: number } | null>(null)
  const dayLabelDraft = state('')
  const dayLabelSaving = state(false)
  const dayLabelConflict = state(false)
  const dayLabelError = state('')
  const dayLabelNotice = state('')
  const dayLabelsUnavailable = state('')
  const canEditDayLabel = derived(() => ready() && editable() && !dayLabelSaving())
  const editingDayLabel = derived(() => editable() && edit()?.day === focusDay())
  const hasDayLabels = derived(() => visible() && [...records().values()].some(row => row.label))
  let activeRange: DateRange | undefined
  let generation = 0

  function labelOnDate(day: string): string {
    return visible() ? records().get(day)?.label ?? '' : ''
  }
  const currentDayLabel = derived(() => labelOnDate(focusDay()))

  function cancelDayLabel() {
    edit.set(null)
    dayLabelDraft.set('')
    dayLabelError.set('')
    dayLabelConflict.set(false)
  }

  function prepareDayLabels(range: DateRange) {
    const active = edit()
    if (!editable() || (active && active.day !== focusDay())) {
      cancelDayLabel()
      dayLabelNotice.set('')
    }
    if (activeRange?.start !== range.start || activeRange.end !== range.end) {
      records.set(new Map())
      dayLabelNotice.set('')
    }
    activeRange = range
    ready.set(false)
    dayLabelsUnavailable.set('')
  }

  async function loadDayLabels(range: DateRange, signal: AbortSignal) {
    if (!visible()) return
    const current = generation
    const params = new URLSearchParams({ start: range.start, end: addCalendarDays(range.end, -1) })
    try {
      const { labels } = await api<{ labels: DayLabel[] }>(`${endpoint}?${params}`, { signal })
      if (signal.aborted || current !== generation || activeRange !== range) return
      const latest = new Map(labels.map(label => [label.day, label]))
      // A save may have finished after this list request read the old revision.
      for (const [day, saved] of records()) {
        if (saved.revision > (latest.get(day)?.revision ?? 0)) latest.set(day, saved)
      }
      records.set(latest)
      ready.set(true)
    }
    catch (cause) {
      if (current === generation && activeRange === range && (!signal.aborted || signal.reason?.name === 'TimeoutError'))
        dayLabelsUnavailable.set(cause instanceof Error ? cause.message : 'Could not load day labels.')
    }
  }

  function startDayLabel() {
    if (!canEditDayLabel()) return
    const day = focusDay()
    const current = records().get(day)
    edit.set({ day, revision: current?.revision ?? 0 })
    dayLabelDraft.set(current?.label ?? '')
    dayLabelNotice.set('')
    dayLabelError.set('')
    dayLabelConflict.set(false)
  }

  async function saveDayLabel(clear = false): Promise<boolean> {
    const target = edit()
    if (!target || !editingDayLabel() || dayLabelSaving() || dayLabelConflict()) return false
    const label = clear ? null : dayLabelDraft().trim()
    if (label !== null && (!label || [...label].length > 80)) {
      dayLabelError.set('Enter a day label of up to 80 characters.')
      return false
    }
    const current = generation
    dayLabelSaving.set(true)
    dayLabelError.set('')
    try {
      const result = await api<DayLabel>(`${endpoint}/${target.day}`, {
        method: 'PUT',
        body: JSON.stringify({ label, revision: target.revision }),
      })
      if (current !== generation) return false
      if (activeRange && result.day >= activeRange.start && result.day < activeRange.end)
        records.update(previous => new Map(previous).set(result.day, result))
      if (edit() !== target || !editingDayLabel()) return false
      cancelDayLabel()
      dayLabelNotice.set(clear ? 'Day label removed.' : 'Day label saved.')
      return true
    }
    catch (cause) {
      if (current === generation && edit() === target) {
        dayLabelError.set(cause instanceof Error ? cause.message : 'Could not save the day label.')
        dayLabelConflict.set(cause instanceof MailApiError && cause.code === 'day_label_changed')
      }
      return false
    }
    finally {
      if (current === generation) dayLabelSaving.set(false)
    }
  }

  function clearDayLabels() {
    generation++
    records.set(new Map())
    activeRange = undefined
    ready.set(false)
    dayLabelSaving.set(false)
    dayLabelsUnavailable.set('')
    dayLabelNotice.set('')
    cancelDayLabel()
  }

  return { hasDayLabels, labelOnDate, currentDayLabel, canEditDayLabel, editingDayLabel, dayLabelDraft, dayLabelSaving,
    dayLabelConflict, dayLabelError, dayLabelNotice, dayLabelsUnavailable, startDayLabel, cancelDayLabel,
    saveDayLabel, prepareDayLabels, loadDayLabels, clearDayLabels }
}
