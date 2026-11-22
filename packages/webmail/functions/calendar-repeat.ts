import ICAL from 'ical.js'
import { utcDay, zonedDay } from './calendar-dates'

export type RepeatFrequency = 'none' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'custom'
export type RepeatEnd = 'never' | 'count' | 'date'

export interface CalendarRepeat {
  frequency: RepeatFrequency
  interval: number
  end: RepeatEnd
  count: number
  until: string
}

export interface CalendarWallTime {
  start: string
  end: string
  allDay: boolean
  zone: string
}

export const defaultRepeat: CalendarRepeat = { frequency: 'none', interval: 1, end: 'never', count: 10, until: '' }
const frequencies = ['daily', 'weekly', 'monthly', 'yearly'] as const

export function timeFromStamp(stamp: number, allDay: boolean): ICAL.Time {
  if (allDay) return ICAL.Time.fromString(utcDay(stamp), undefined)
  const time = new ICAL.Time({ year: 1970, month: 1, day: 1, isDate: false }, ICAL.Timezone.utcTimezone)
  time.fromUnixTime(stamp)
  return time
}

export function repeatFromEvent(master: ICAL.Event, zone: string): CalendarRepeat {
  const properties = master.component.getAllProperties('rrule')
  if (!properties.length) return { ...defaultRepeat, frequency: master.component.hasProperty('rdate') ? 'custom' : 'none' }
  const rule = properties[0].getFirstValue() as ICAL.Recur
  const frequency = frequencies.find(item => item.toUpperCase() === rule?.freq)
  if (!frequency || properties.length !== 1 || Object.keys(rule.parts).length
    || rule.interval < 1 || rule.interval > 999 || (rule.count !== null && (rule.count < 1 || rule.count > 9999)))
    return { ...defaultRepeat, frequency: 'custom' }
  return {
    frequency,
    interval: rule.interval,
    end: rule.count !== null ? 'count' : rule.until ? 'date' : 'never',
    count: rule.count ?? defaultRepeat.count,
    until: rule.until ? (
      rule.until.isDate || rule.until.zone === ICAL.Timezone.localTimezone
        ? rule.until.toString().slice(0, 10)
        : zonedDay(rule.until.toUnixTime(), zone)
    ) : '',
  }
}

export function recurrenceRule(repeat: CalendarRepeat, clock: CalendarWallTime, floating: boolean, cutoff?: number | null): ICAL.Recur | null {
  if (repeat.frequency === 'none' || repeat.frequency === 'custom') return null
  if (!frequencies.includes(repeat.frequency)) throw new Error('Choose how often this event repeats.')
  if (!Number.isInteger(repeat.interval) || repeat.interval < 1 || repeat.interval > 999)
    throw new Error('Enter a repeat interval from 1 to 999.')
  let source = `FREQ=${repeat.frequency.toUpperCase()}`
  if (repeat.interval !== 1) source += `;INTERVAL=${repeat.interval}`
  if (repeat.end === 'count') {
    if (!Number.isInteger(repeat.count) || repeat.count < 1 || repeat.count > 9999)
      throw new Error('Enter a repeat count from 1 to 9999.')
    source += `;COUNT=${repeat.count}`
  }
  if (repeat.end === 'date') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(repeat.until) || repeat.until < clock.start.slice(0, 10))
      throw new Error('The last repeat date must be on or after the start.')
    let until: ICAL.Time
    if (clock.allDay || floating) {
      until = ICAL.Time.fromString(clock.allDay ? repeat.until : `${repeat.until}T23:59:59`, undefined)
    }
    else {
      if (cutoff == null) throw new Error('Choose a last repeat date that exists in the event time zone.')
      until = timeFromStamp(cutoff, false)
    }
    source += `;UNTIL=${until.toICALString()}`
  }
  return ICAL.Recur.fromString(source)
}
