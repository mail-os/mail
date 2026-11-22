import moment from 'moment-timezone'

interface TransitionGroup {
  from: number
  to: number
  dates: Date[]
}

const weekday = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA']

function stamp(date: Date): string {
  return date.toISOString().slice(0, 19).replace(/[-:]/g, '')
}

function offset(seconds: number): string {
  const absolute = Math.abs(seconds)
  const fields = [Math.floor(absolute / 3600), Math.floor(absolute % 3600 / 60)]
  if (absolute % 60) fields.push(absolute % 60)
  return (seconds < 0 ? '-' : '+') + fields.map(value => String(value).padStart(2, '0')).join('')
}

function position(date: Date, fromEnd: boolean): number {
  if (!fromEnd) return Math.ceil(date.getUTCDate() / 7)
  const nextMonth = new Date(date)
  nextMonth.setUTCMonth(date.getUTCMonth() + 1, 0)
  return -Math.ceil((nextMonth.getUTCDate() - date.getUTCDate() + 1) / 7)
}

/** Compact a stable annual tail while retaining the exact dated transitions
 * before it. Zones with finite or irregular transitions keep explicit dates.
 */
function annualTail(dates: Date[]): { index: number, rule: string } | null {
  const last = dates.at(-1)
  if (!last || last.getUTCFullYear() < 2498 || dates.length < 16) return null
  const month = last.getUTCMonth()
  const time = stamp(last).slice(8)
  const patterns = [
    { rule: `BYMONTHDAY=${last.getUTCDate()}`, match: (date: Date) => date.getUTCDate() === last.getUTCDate() },
    ...[true, false].map(fromEnd => ({
      rule: `BYDAY=${position(last, fromEnd)}${weekday[last.getUTCDay()]}`,
      match: (date: Date) => date.getUTCDay() === last.getUTCDay() && position(date, fromEnd) === position(last, fromEnd),
    })),
  ]
  for (const pattern of patterns) {
    let index = dates.length - 1
    while (index > 0) {
      const previous = dates[index - 1]
      if (previous.getUTCFullYear() + 1 !== dates[index].getUTCFullYear()
        || previous.getUTCMonth() !== month || stamp(previous).slice(8) !== time || !pattern.match(previous)) break
      index--
    }
    if (dates.length - index >= 16) return { index, rule: `FREQ=YEARLY;BYMONTH=${month + 1};${pattern.rule}` }
  }
  return null
}

function observance(group: TransitionGroup, dates: Date[], rule?: string): string[] {
  const kind = group.to > group.from ? 'DAYLIGHT' : 'STANDARD'
  return [
    `BEGIN:${kind}`, `DTSTART:${stamp(dates[0])}`, `TZOFFSETFROM:${offset(group.from)}`, `TZOFFSETTO:${offset(group.to)}`,
    ...dates.slice(1).map(date => `RDATE:${stamp(date)}`), ...(rule ? [`RRULE:${rule}`] : []), `END:${kind}`,
  ]
}

export function calendarTimeZoneSource(name: string): string | null {
  const zone = moment.tz.zone(name)
  if (!zone || !/^[A-Za-z0-9_+./-]+$/.test(name)) return null
  const initial = Math.round(-zone.offsets[0] * 60)
  const lines = [
    'BEGIN:VTIMEZONE', `TZID:${name}`, 'BEGIN:STANDARD', 'DTSTART:00010101T000000',
    `TZOFFSETFROM:${offset(initial)}`, `TZOFFSETTO:${offset(initial)}`, 'END:STANDARD',
  ]
  const groups = new Map<string, TransitionGroup>()
  for (let index = 0; index < zone.untils.length - 1; index++) {
    const from = Math.round(-zone.offsets[index] * 60)
    const to = Math.round(-zone.offsets[index + 1] * 60)
    if (from === to) continue
    const key = `${from}/${to}`
    const group = groups.get(key) ?? { from, to, dates: [] }
    group.dates.push(new Date(zone.untils[index] + from * 1000))
    groups.set(key, group)
  }
  for (const group of groups.values()) {
    const tail = annualTail(group.dates)
    const history = tail ? group.dates.slice(0, tail.index) : group.dates
    if (history.length) lines.push(...observance(group, history))
    if (tail) lines.push(...observance(group, [group.dates[tail.index]], tail.rule))
  }
  return [...lines, 'END:VTIMEZONE', ''].join('\r\n')
}

export function calendarTimeZoneCatalog(): string {
  return moment.tz.names().map(calendarTimeZoneSource).filter(Boolean).join('')
}
