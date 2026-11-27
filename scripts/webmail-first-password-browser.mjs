import assert from 'node:assert/strict'
import { chromium } from 'playwright'
import { randomBytes } from 'node:crypto'
const fixture = JSON.parse(await Bun.stdin.text())
const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH, headless: true })
try {
  const page = await browser.newPage({ ignoreHTTPSErrors: true })
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const password = page.getByLabel('Password', { exact: true })
  const next = page.getByLabel('New password', { exact: true })
  const confirm = page.getByLabel('Confirm new password', { exact: true })
  const replacement = randomBytes(24).toString('base64url')
  await page.goto(fixture.url + '/login')
  await page.getByLabel('Email or username').fill(fixture.address)
  await password.fill(fixture.temporary)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await next.waitFor({ state: 'visible' })
  assert.ok(await next.evaluate(element => element === document.activeElement))
  assert.equal((await page.context().cookies()).filter(cookie => cookie.name === 'webmail_session').length, 0)
  await next.fill(replacement)
  await confirm.fill('mismatch-test-password')
  await page.getByRole('button', { name: 'Set new password' }).click()
  await page.getByText('The new passwords do not match.').waitFor()
  await confirm.fill(replacement)
  await page.getByRole('button', { name: 'Set new password' }).click()
  await page.getByText('Password updated. Sign in with your new password.').waitFor()
  assert.ok(await password.evaluate(element => element.value === ''))
  await password.fill(replacement)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await page.waitForURL(url => url.pathname === '/')
  assert.equal((await page.context().cookies()).filter(cookie => cookie.name === 'webmail_session' && cookie.secure).length, 1)
  assert.deepEqual(errors, [])
  console.log('PASS Chromium first sign-in requires password update and a new login')
}
finally { await browser.close() }
