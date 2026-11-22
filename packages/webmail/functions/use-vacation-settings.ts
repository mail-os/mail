import type { createMailApi } from './mail-api'
import { batch, state } from '@stacksjs/stx'
import { localDateInput } from './mail-attention'

interface VacationSettings {
  enabled: boolean
  subject: string
  body: string
  startsAt: number | null
  endsAt: number | null
  revision: number
}

const endpoint = '/webmail/api/vacation'

function toInput(seconds: number | null): string {
  return seconds === null ? '' : localDateInput(new Date(seconds * 1000))
}

function toTimestamp(value: string, previous: number | null): number | null {
  if (!value) return null
  const date = new Date(value)
  if (!Number.isFinite(date.getTime()) || localDateInput(date) !== value)
    throw new Error('Choose a valid local date and time.')
  return value === toInput(previous) ? previous : Math.floor(date.getTime() / 1000)
}

export function vacationStatus(settings: VacationSettings | null, now: number): string {
  if (!settings?.enabled) return 'Off'
  if (settings.endsAt !== null && settings.endsAt <= now) return 'Ended'
  if (settings.startsAt !== null && settings.startsAt > now) return 'Scheduled'
  return 'On'
}

export function useVacationSettings(api: ReturnType<typeof createMailApi>) {
  const vacation = state<VacationSettings | null>(null)
  const vacationEnabled = state(false)
  const vacationSubject = state('')
  const vacationBody = state('')
  const vacationStart = state('')
  const vacationEnd = state('')
  const vacationBusy = state(false)
  const vacationError = state('')
  const vacationNotice = state('')
  let request = 0

  function install(settings: VacationSettings | null): void {
    batch(() => {
      vacation.set(settings)
      vacationEnabled.set(settings?.enabled ?? false)
      vacationSubject.set(settings?.subject ?? '')
      vacationBody.set(settings?.body ?? '')
      vacationStart.set(toInput(settings?.startsAt ?? null))
      vacationEnd.set(toInput(settings?.endsAt ?? null))
    })
  }

  function clearVacationSettings(): void {
    request += 1
    install(null)
    vacationBusy.set(false)
    vacationError.set('')
    vacationNotice.set('')
  }

  async function loadVacationSettings(): Promise<void> {
    clearVacationSettings()
    const current = request
    vacationBusy.set(true)
    try {
      const settings = await api<VacationSettings>(endpoint)
      if (current === request) install(settings)
    }
    catch (cause) {
      if (current === request) vacationError.set(cause instanceof Error ? cause.message : 'Could not load vacation replies.')
    }
    finally {
      if (current === request) vacationBusy.set(false)
    }
  }

  async function saveVacationSettings(): Promise<void> {
    const saved = vacation()
    if (!saved || vacationBusy()) return
    const current = request
    vacationBusy.set(true)
    vacationError.set('')
    vacationNotice.set('')
    try {
      const settings: VacationSettings = {
        enabled: vacationEnabled(), subject: vacationSubject(), body: vacationBody(), revision: saved.revision,
        startsAt: toTimestamp(vacationStart(), saved.startsAt), endsAt: toTimestamp(vacationEnd(), saved.endsAt),
      }
      const result = await api<VacationSettings>(endpoint, { method: 'PUT', body: JSON.stringify(settings) })
      if (current !== request) return
      install(result)
      vacationNotice.set('Vacation reply saved.')
    }
    catch (cause) {
      if (current === request) vacationError.set(cause instanceof Error ? cause.message : 'Could not save vacation replies.')
    }
    finally {
      if (current === request) vacationBusy.set(false)
    }
  }

  return { vacation, vacationEnabled, vacationSubject, vacationBody, vacationStart, vacationEnd, vacationBusy, vacationError, vacationNotice, loadVacationSettings, saveVacationSettings, clearVacationSettings }
}
