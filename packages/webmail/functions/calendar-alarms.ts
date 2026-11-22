import ICAL from 'ical.js'

type Component = ICAL.Component
type Duration = ICAL.Duration
type Time = ICAL.Time

export const reminderOptions = [
  { id: 'none', label: 'None' },
  { id: 'start', label: 'At the start' },
  { id: '5', label: '5 minutes before' },
  { id: '10', label: '10 minutes before' },
  { id: '15', label: '15 minutes before' },
  { id: '30', label: '30 minutes before' },
  { id: '60', label: '1 hour before' },
  { id: '1440', label: '1 day before' },
  { id: '10080', label: '1 week before' },
] as const

export type ReminderChoice = typeof reminderOptions[number]['id']
export interface AlarmPreference {
  choice: ReminderChoice
  others: number
}

export const noReminder: AlarmPreference = { choice: 'none', others: 0 }

const marker = 'x-mail-webmail-reminder'

function isDisplay(alarm: Component): boolean {
  const action = alarm.getFirstPropertyValue('action')
  return typeof action === 'string' && action.toUpperCase() === 'DISPLAY'
}

function choiceFor(alarm: Component): ReminderChoice | undefined {
  const trigger = alarm.getFirstProperty('trigger')
  const value = trigger?.getFirstValue()
  if (!isDisplay(alarm) || !(value instanceof ICAL.Duration) || trigger?.getParameter('related')?.toString().toUpperCase() === 'END'
    || alarm.hasProperty('repeat') || alarm.hasProperty('duration')) return undefined
  const seconds = value.toSeconds()
  if (!seconds) return 'start'
  return reminderOptions.find(option => Number(option.id) * -60 === seconds)?.id
}

function editableAlarm(event: Component): Component | undefined {
  const alarms = event.getAllSubcomponents('valarm')
  const owned = alarms.find(alarm => alarm.hasProperty(marker) && choiceFor(alarm) !== undefined)
  if (owned) return owned
  return alarms.find(alarm => !alarm.hasProperty('acknowledged') && choiceFor(alarm) !== undefined)
}

export function reminderPreference(event: Component): AlarmPreference {
  const editable = editableAlarm(event)
  return {
    choice: editable ? choiceFor(editable) ?? 'none' : 'none',
    others: event.getAllSubcomponents('valarm').length - Number(Boolean(editable)),
  }
}

export function setReminder(event: Component, choice: ReminderChoice, summary: string) {
  const existing = editableAlarm(event)
  if (existing && choiceFor(existing) === choice) return
  if (choice === 'none') {
    if (existing) event.removeSubcomponent(existing)
    return
  }
  const seconds = choice === 'start' ? 0 : Number(choice) * -60
  if (!Number.isFinite(seconds)) throw new Error('Choose a supported calendar reminder.')
  const alarm = existing ?? new ICAL.Component('valarm')
  if (!existing) {
    alarm.addPropertyWithValue('action', 'DISPLAY')
    alarm.addPropertyWithValue('description', summary || 'Calendar reminder')
    event.addSubcomponent(alarm)
  }
  const property = alarm.updatePropertyWithValue('trigger', ICAL.Duration.fromSeconds(seconds))
  property.removeParameter('related')
  alarm.updatePropertyWithValue(marker, 'TRUE')
}

export interface DisplayAlarm {
  trigger: Time | Duration
  end: boolean
  message: string
  repeat: number
  interval: number
  acknowledged: number | null
}

function acknowledgedTime(value: unknown): number | null {
  if (value instanceof ICAL.Time) return value.zone === ICAL.Timezone.utcTimezone ? value.toUnixTime() : null
  // RFC 9074 is newer than the default ical.js property design, so a parsed
  // ACKNOWLEDGED line may still be an undecorated UTC value.
  if (typeof value !== 'string') return null
  const fields = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(value)
  if (!fields) return null
  const [, year, month, day, hours, minutes, seconds] = fields
  const iso = `${year}-${month}-${day}T${hours}:${minutes}:${seconds}Z`
  const parsed = Date.parse(iso)
  return Number.isFinite(parsed) && new Date(parsed).toISOString().replace('.000Z', 'Z') === iso ? parsed / 1000 : null
}

export function displayAlarms(event: Component): DisplayAlarm[] {
  const alarms: DisplayAlarm[] = []
  for (const alarm of event.getAllSubcomponents('valarm')) {
    if (!isDisplay(alarm)) continue
    const trigger = alarm.getFirstProperty('trigger')
    const value = trigger?.getFirstValue()
    if (!(value instanceof ICAL.Duration) && !(value instanceof ICAL.Time && !value.isDate && value.zone === ICAL.Timezone.utcTimezone)) continue
    const related = trigger?.getParameter('related')
    const message = alarm.getFirstPropertyValue('description')
    const repeats = alarm.getFirstPropertyValue('repeat')
    const spacing = alarm.getFirstPropertyValue('duration')
    const acknowledged = alarm.getFirstPropertyValue('acknowledged')
    const interval = spacing instanceof ICAL.Duration ? Math.max(0, spacing.toSeconds()) : 0
    alarms.push({
      trigger: value,
      end: typeof related === 'string' && related.toUpperCase() === 'END',
      message: typeof message === 'string' ? message : '',
      repeat: interval > 0 && typeof repeats === 'number' ? Math.max(0, Math.min(10_000, repeats)) : 0,
      interval,
      acknowledged: acknowledgedTime(acknowledged),
    })
  }
  return alarms
}
