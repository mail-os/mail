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
  expect((await requestWebmail('/calendar')).status).toBe(200)
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
  }
  finally {
    // Use the single generated resource and calendar. The test never lists or
    // deletes events belonging to an existing calendar.
    await requestDav(resource, 'DELETE')
    await requestDav(collection, 'DELETE')
  }
}, 30_000)
