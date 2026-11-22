import { derived, state } from '@stacksjs/stx'
import { browserTimeZone, utcDay, zonedDay } from './calendar-dates'
import { alarmsInWindow } from './calendar-recurrence'
import type { AlarmNotice } from './calendar-recurrence'
import type { CalendarEvent } from './calendar-types'
import { createMailApi } from './mail-api'

interface ReminderSnapshot {
  now: number
  start: number
  end: number
  events: CalendarEvent[]
  dismissed: string[]
}

const day = 86_400

export function useCalendarReminders(account: () => string | undefined, enabled: () => boolean = () => true) {
  const notices = state<AlarmNotice[]>([])
  const loadedFor = state<string | undefined>(undefined)
  const clock = state(0)
  const dismissingReminder = state('')
  const reminderError = state('')
  const visibleReminders = derived(() => account() && enabled() && account() === loadedFor()
    ? notices().filter(item => item.due <= clock() && item.due >= clock() - day).slice(0, 25) : [])
  let anchor = { server: 0, local: 0 }
  let pending: AbortController | undefined
  let dismissal: AbortController | undefined
  const locallyDismissed = new Map<string, number>()

  function clear() {
    notices.set([])
    loadedFor.set(undefined)
    reminderError.set('')
    locallyDismissed.clear()
  }
  const api = createMailApi(account, clear)

  function tickReminders() {
    if (anchor.server) clock.set(anchor.server + Math.floor((performance.now() - anchor.local) / 1000))
  }

  async function pollReminders() {
    const owner = account()
    if (!owner || !enabled()) {
      pending?.abort()
      clear()
      return
    }
    if (loadedFor() !== owner) clear()
    pending?.abort()
    const request = new AbortController()
    pending = request
    try {
      const snapshot = await api<ReminderSnapshot>('/webmail/api/calendar-reminders', {
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]),
      })
      if (request.signal.aborted || account() !== owner) return
      const acknowledged = new Set(snapshot.dismissed)
      const budget = { remaining: 30_000 }
      const next: AlarmNotice[] = []
      let incomplete = false
      for (const event of snapshot.events) {
        if (!event.icalendar) continue
        try {
          const result = alarmsInWindow(event, event.icalendar, browserTimeZone, snapshot.start, snapshot.end, budget)
          next.push(...result.filter(item => !acknowledged.has(item.key) && !locallyDismissed.has(item.key)))
        }
        catch {
          incomplete = true
        }
      }
      for (const [key, due] of locallyDismissed) {
        if (due < snapshot.start || acknowledged.has(key)) locallyDismissed.delete(key)
      }
      if (next.length > 2048) incomplete = true
      next.sort((left, right) => right.due - left.due || left.key.localeCompare(right.key))
      anchor = { server: snapshot.now, local: performance.now() }
      tickReminders()
      loadedFor.set(owner)
      notices.set(next.slice(0, 2048))
      reminderError.set(incomplete ? 'Some calendar reminders could not be checked.' : '')
    }
    catch (error) {
      if (request.signal.aborted || account() !== owner) return
      if (error instanceof Error && 'status' in error && error.status === 413) {
        loadedFor.set(owner)
        reminderError.set('Too many calendar resources to check for reminders.')
      }
    }
    finally {
      if (pending === request) pending = undefined
    }
  }

  async function dismissReminder(item: AlarmNotice) {
    const owner = account()
    if (!owner || owner !== loadedFor() || dismissingReminder()) return
    const request = new AbortController()
    dismissal = request
    dismissingReminder.set(item.key)
    try {
      await api('/webmail/api/calendar-reminders/dismiss', {
        method: 'POST', body: JSON.stringify({ eventId: item.event.id, key: item.key, due: item.due }),
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]),
      })
      if (request.signal.aborted || owner !== account()) return
      locallyDismissed.set(item.key, item.due)
      notices.set(notices().filter(notice => notice.key !== item.key))
    }
    catch {
      if (!request.signal.aborted && owner === account() && loadedFor() === owner)
        reminderError.set('Could not dismiss the calendar reminder. Try again.')
    }
    finally {
      if (dismissal === request) {
        dismissingReminder.set('')
        dismissal = undefined
      }
    }
  }

  return {
    visibleReminders, reminderError, dismissingReminder, tickReminders, pollReminders, dismissReminder,
    destroyReminders: () => {
      pending?.abort()
      dismissal?.abort()
      clear()
    },
  }
}

export function reminderDayLink(item: AlarmNotice): string {
  const { all_day: allDay, start } = item.event
  const date = allDay ? utcDay(start) : zonedDay(start, browserTimeZone)
  return `/calendar?day=${encodeURIComponent(date)}`
}
