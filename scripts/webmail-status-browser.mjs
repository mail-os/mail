import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_STATUS_URL: url, MAIL_STATUS_OWNER: owner, MAIL_STATUS_PASSWORD: password, MAIL_STATUS_DB: db } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, engine) && output && url && owner && password && db, 'Run through test-webmail-status.py')
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
assert(basename(dirname(db)).startsWith('mail-status-') && basename(db) === 'smtp.db')
const browser = await engines[engine].launch()
const page = await browser.newPage({ viewport: { width: 320, height: 760 }, colorScheme: 'light', ignoreHTTPSErrors: true })
page.setDefaultTimeout(8_000)
const errors = []
page.on('pageerror', error => errors.push(error.message))

const healthUrl = url + '/webmail/api/health'
const now = Math.floor(Date.now() / 1000)
const check = { name: 'Authenticated delivery fixture', ok: true }
const incident = 'Fixture delivery delay'
const report = {
  available: true,
  stale: false,
  report: {
    status: 'healthy', checked_at: now,
    checks: [check], events: [{ at: now - 40, status: 'degraded', summary: incident }],
  },
}
let fixtureReply = { status: 200, json: report }
const heading = name => page.getByRole('heading', { name, exact: true })
const refresh = page.getByRole('button', { name: 'Refresh', exact: true })
const signIn = page.getByRole('link', { name: 'Sign in to Mail', exact: true })

async function snapshot(name) {
  await mkdir(output, { recursive: true })
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'The status page has horizontal overflow')
  await page.screenshot({ path: join(output, name + '.png'), animations: 'disabled', fullPage: true })
}

async function signedOut() {
  await heading('Sign in to check Mail delivery').waitFor()
  assert.equal(await signIn.getAttribute('href'), '/login#status')
  assert((await signIn.boundingBox()).height >= 44, 'Sign-in should have a 44 px hit target')
  await heading('Current checks').waitFor({ state: 'hidden' })
  await heading('Incident history').waitFor({ state: 'hidden' })
  await heading('Mail health is unknown').waitFor({ state: 'hidden' })
  await refresh.waitFor({ state: 'hidden' })
  await page.getByRole('alert').waitFor({ state: 'hidden' })
}

async function authenticate() {
  await signIn.focus()
  await signIn.press('Enter')
  await heading('Sign in to Mail').waitFor()
  await page.getByLabel('Email or username').fill(owner)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await page.waitForURL(url + '/status')
}

async function refreshAs(reply, summary) {
  fixtureReply = reply
  const response = page.waitForResponse(value => value.url() === healthUrl)
  await refresh.click()
  assert.equal((await response).status(), reply.status)
  await heading(summary).waitFor()
}

try {
  const unauthenticated = page.waitForResponse(value => value.url() === healthUrl)
  assert.equal((await page.goto(url + '/status')).status(), 200)
  const unauthorized = await unauthenticated
  assert.equal(unauthorized.status(), 401)
  assert.equal(Object.hasOwn(await unauthorized.json(), 'report'), false)
  await signedOut()
  await snapshot('delivery-signed-out-phone')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.emulateMedia({ colorScheme: 'dark' })
  await signedOut()
  await snapshot('delivery-signed-out-desktop')

  // Vary the sanitized report only after the actual native endpoint accepts
  // the mailbox session. A real 401 always reaches the browser unchanged.
  await page.route(healthUrl, async (route) => {
    const response = await route.fetch()
    if (response.status() !== 200) await route.fulfill({ response })
    else await route.fulfill({ response, ...fixtureReply })
  })

  await authenticate()
  await heading('Mail checks are passing').waitFor()
  await page.getByText(check.name, { exact: true }).waitFor()
  await page.getByText(incident, { exact: true }).waitFor()
  await snapshot('delivery-signed-in-healthy')
  await page.setViewportSize({ width: 320, height: 760 })
  await page.emulateMedia({ colorScheme: 'light' })
  assert((await refresh.boundingBox()).height >= 44, 'Refresh should have a 44 px hit target on a phone')
  await snapshot('delivery-signed-in-phone')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.emulateMedia({ colorScheme: 'dark' })

  const degraded = { ...report, report: { ...report.report, status: 'degraded', checks: [{ ...check, ok: false, count: 4 }] } }
  await refreshAs({ status: 200, json: degraded }, 'Mail needs attention')
  await page.getByText('4 errors in 5 minutes', { exact: true }).waitFor()

  await refreshAs({ status: 200, json: { ...report, stale: true } }, 'Mail health is unknown')
  await page.getByText('Outdated', { exact: true }).waitFor()
  await snapshot('delivery-signed-in-stale')

  await refreshAs({ status: 200, json: { available: false, stale: true } }, 'Mail health is unknown')
  await heading('Current checks').waitFor({ state: 'hidden' })
  await heading('Incident history').waitFor({ state: 'hidden' })
  await page.getByRole('alert').waitFor({ state: 'hidden' })

  await refreshAs({ status: 503, json: { error: 'unavailable' } }, 'Mail health is unknown')
  await page.getByRole('alert').filter({ hasText: 'Health monitoring is unavailable.' }).waitFor()
  await signIn.waitFor({ state: 'hidden' })

  await refreshAs({ status: 200, json: report }, 'Mail checks are passing')
  execFileSync('python3', ['-c', [
    'import sqlite3, sys',
    'with sqlite3.connect(sys.argv[1]) as db:',
    '    result = db.execute("UPDATE webmail_sessions SET expires_at=0 WHERE username=?", (sys.argv[2],))',
    '    assert result.rowcount == 1',
  ].join('\n'), db, owner])
  const expired = page.waitForResponse(value => value.url() === healthUrl)
  await refresh.click()
  assert.equal((await expired).status(), 401)
  await signedOut()
  await page.getByText(incident, { exact: true }).waitFor({ state: 'hidden' })
  await snapshot('delivery-session-expired')
  await authenticate()
  await heading('Mail checks are passing').waitFor()
  assert.deepEqual(errors, [])
  console.log(`${engine} passed Mail delivery sign-in, actual session expiry, and signed-in report states.`)
}
finally { await browser.close() }
