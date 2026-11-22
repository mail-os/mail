/** Run against a disposable webmail account and the same server's CalDAV endpoint. */
import { expect, test } from 'bun:test'

const base = process.env.MAIL_WEBMAIL_E2E_URL
const dav = process.env.MAIL_WEBMAIL_E2E_CALDAV_URL
const username = process.env.MAIL_WEBMAIL_E2E_USER
const password = process.env.MAIL_WEBMAIL_E2E_PASSWORD

test.skipIf(!base || !dav || !username || !password)('CalDAV writes appear in the signed-in webmail agenda', async () => {
  const name = `Webmail-${crypto.randomUUID()}`
  const collection = new URL(`/calendars/${encodeURIComponent(username!)}/${name}/`, dav)
  const resource = new URL('first.ics', collection)
  const recurring = new URL('recurring.ics', collection)
  const timezone = new URL('second-timezone.ics', collection)
  const authorization = `Basic ${btoa(`${username}:${password}`)}`
  const requestDav = (url: URL, method: string, body?: string) => fetch(url, {
    method,
    body,
    headers: { Authorization: authorization, ...(body ? { 'Content-Type': 'text/calendar; charset=utf-8' } : {}) },
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  })
  const login = await fetch(new URL('/webmail/auth/login', base), {
    method: 'POST',
    headers: { Origin: base!, 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  expect(login.status).toBe(200)
  const cookie = login.headers.get('set-cookie')!.split(';', 1)[0]
  const requestWebmail = (path: string) => fetch(new URL(path, base), {
    headers: { Cookie: cookie, 'X-Webmail-Account': encodeURIComponent(username!) },
    signal: AbortSignal.timeout(5000),
  })
  expect((await fetch(new URL('/webmail/api/calendars', base))).status).toBe(401)
  expect((await fetch(new URL('/webmail/api/calendar-export?calendarId=1', base))).status).toBe(401)
  const page = await requestWebmail('/calendar')
  expect(page.status).toBe(200)
  expect(await page.text()).toContain('Download .ics')
  const config = await requestWebmail('/webmail/api/config')
  expect((await config.json() as { calendarAvailable: boolean }).calendarAvailable).toBe(true)

  expect((await requestDav(collection, 'MKCALENDAR')).status).toBe(201)
  try {
    const calendarText = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//Mail//Webmail integration tests//EN',
      'BEGIN:VEVENT',
      'UID:first',
      'DTSTAMP:20261121T180000Z',
      'DTSTART:20261121T183000Z',
      'DTEND:20261121T193000Z',
      'SUMMARY:Calendar browser handoff',
      'LOCATION:Studio',
      'END:VEVENT',
      'END:VCALENDAR',
      '',
    ].join('\r\n')
    expect((await requestDav(resource, 'PUT', calendarText)).status).toBe(201)
    const list = await requestWebmail('/webmail/api/calendars')
    expect(list.status).toBe(200)
    const { calendars } = await list.json() as { calendars: { id: number, name: string }[] }
    const calendar = calendars.find(item => item.name === name)
    expect(calendar).toBeDefined()

    const start = Date.parse('2026-11-21T18:00:00Z') / 1000
    const end = start + 2 * 3600
    const response = await requestWebmail(`/webmail/api/calendar-events?calendarId=${calendar!.id}&start=${start}&end=${end}`)
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ events: [{ summary: 'Calendar browser handoff', location: 'Studio' }] })
    expect((await requestWebmail(`/webmail/api/calendar-events?calendarId=${calendar!.id}&start=${start}&end=${start}`)).status).toBe(400)

    const tz = [
      'BEGIN:VTIMEZONE', 'TZID:America/Phoenix', 'BEGIN:STANDARD', 'DTSTART:19700101T000000',
      'TZOFFSETFROM:-0700', 'TZOFFSETTO:-0700', 'END:STANDARD', 'END:VTIMEZONE',
    ]
    const makeCalendar = (lines: string[], eol: string) => [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Mail//Calendar export fixture//EN', 'METHOD:PUBLISH',
      ...tz, ...lines, 'END:VCALENDAR', '',
    ].join(eol)
    const summary = `Planning ${'é'.repeat(48)}`
    expect((await requestDav(recurring, 'PUT', makeCalendar([
      'BEGIN:VEVENT', 'UID:recurring', 'DTSTAMP:20261121T180000Z', 'DTSTART;TZID=America/Phoenix:20261121T120000',
      'SUMMARY:Recurring in Phoenix', 'RRULE:FREQ=WEEKLY;COUNT=3', 'BEGIN:VALARM', 'ACTION:DISPLAY',
      'TRIGGER:-PT15M', 'DESCRIPTION:Reminder', 'END:VALARM', 'END:VEVENT',
      'BEGIN:VEVENT', 'UID:recurring', 'RECURRENCE-ID;TZID=America/Phoenix:20261128T120000',
      'DTSTAMP:20261121T180000Z', 'DTSTART;TZID=America/Phoenix:20261128T130000',
      `SUMMARY:${summary}`, 'X-MICROSOFT-CDO-BUSYSTATUS:BUSY', 'END:VEVENT',
    ], '\r\n'))).status).toBe(201)
    const secondTimezone = makeCalendar([
      'BEGIN:VEVENT', 'UID:second-timezone', 'DTSTAMP:20261121T180000Z', 'DTSTART;TZID=America/Phoenix:20261122T120000',
      'SUMMARY:Shared timezone', 'END:VEVENT',
    ], '\n')
    expect((await requestDav(timezone, 'PUT', secondTimezone)).status).toBe(201)

    const download = await requestWebmail(`/webmail/api/calendar-export?calendarId=${calendar!.id}`)
    expect(download.status).toBe(200)
    expect(download.headers.get('content-type')).toBe('text/calendar; charset=utf-8')
    expect(download.headers.get('content-disposition')).toBe('attachment; filename="calendar.ics"')
    expect(download.headers.get('cache-control')).toBe('no-store')
    const ics = await download.text()
    expect(Number(download.headers.get('content-length'))).toBe(Buffer.byteLength(ics))
    expect(ics.match(/BEGIN:VCALENDAR/g)).toHaveLength(1)
    expect(ics.match(/BEGIN:VTIMEZONE/g)).toHaveLength(1)
    expect(ics.match(/BEGIN:VEVENT/g)).toHaveLength(4)
    expect(ics.indexOf('BEGIN:VTIMEZONE')).toBeLessThan(ics.indexOf('BEGIN:VEVENT'))
    expect(ics).not.toContain('METHOD:PUBLISH')
    expect(ics).toContain('RECURRENCE-ID;TZID=America/Phoenix:20261128T120000')
    expect(ics).toContain('BEGIN:VALARM\r\nACTION:DISPLAY')
    expect(ics).toContain('X-MICROSOFT-CDO-BUSYSTATUS:BUSY')
    expect(ics.replace(/\r\n[ \t]/g, '')).toContain(`SUMMARY:${summary}`)
    expect(ics.split('\r\n').every(line => Buffer.byteLength(line) <= 75)).toBe(true)
    expect((await requestWebmail('/webmail/api/calendar-export?calendarId=bogus')).status).toBe(400)
    expect((await requestWebmail('/webmail/api/calendar-export?calendarId=18446744073709551615')).status).toBe(404)

    expect((await requestDav(timezone, 'PUT', secondTimezone.replace('TZOFFSETTO:-0700', 'TZOFFSETTO:-0600'))).status).toBe(204)
    const conflict = await requestWebmail(`/webmail/api/calendar-export?calendarId=${calendar!.id}`)
    expect(conflict.status).toBe(422)
    expect(await conflict.json()).toMatchObject({ error: 'conflicting_timezone' })
  }
  finally {
    // Use the single generated resource and calendar. The test never lists or
    // deletes events belonging to an existing calendar.
    await requestDav(resource, 'DELETE')
    await requestDav(recurring, 'DELETE')
    await requestDav(timezone, 'DELETE')
    await requestDav(collection, 'DELETE')
  }
}, 30_000)
