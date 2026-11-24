import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_NAVIGATION_URL: url, MAIL_NAVIGATION_OWNER: owner, MAIL_NAVIGATION_PEER: peer,
  MAIL_NAVIGATION_PASSWORD: password, MAIL_NAVIGATION_DAY: day, MAIL_NAVIGATION_REVISION: revision } = process.env
const [engine, device, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
const phone = device === 'phone'
const viewport = phone ? { width: 390, height: 844 } : { width: 1440, height: 940 }
const button = (scope, name) => scope.getByRole('button', { name, exact: typeof name === 'string' })
const heading = (scope, name) => scope.getByRole('heading', { name, exact: true })
const folders = page => page.getByRole('navigation', { name: 'Mail folders', exact: true })
const reader = page => page.getByRole('region', { name: 'Message reader', exact: true })
const handoff = 'Tuesday design handoff'
const inboxReview = 'First note from Devon'
const inboxDecline = 'First note from Taylor'
const teamMessage = 'Studio proof approval'
const timings = {}

async function act(control) {
  if (phone) await control.tap()
  else await control.click()
}

async function measure(name, operation) {
  const start = performance.now()
  await operation()
  timings[name] = Math.round(performance.now() - start)
}

async function capture(page, name) {
  const metrics = await page.evaluate(() => ({
    width: innerWidth, page: document.documentElement.scrollWidth, pixelRatio: devicePixelRatio,
  }))
  assert.equal(metrics.width, viewport.width, name)
  assert(metrics.page <= metrics.width, `${name} has horizontal overflow`)
  assert.equal(metrics.pixelRatio, phone ? 2 : 1, name)
  await page.screenshot({ path: join(output, `${name}.png`), animations: 'disabled' })
}

async function signIn(page, name) {
  await page.goto(`${url}/login`)
  await page.getByLabel('Email or username').fill(name)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await act(button(page, 'Sign in'))
}

async function openNavigation(page) {
  if (phone && !await folders(page).isVisible()) await act(button(page, 'Mailboxes'))
  await folders(page).waitFor()
}

async function openFolder(page, name, sample, id) {
  await measure(id, async () => {
    await openNavigation(page)
    await act(button(folders(page), new RegExp(`^${name}(?:\\s|$)`)))
    await heading(page, name).waitFor()
    await button(page, new RegExp(sample)).waitFor()
  })
  await capture(page, id)
}

async function triage(page) {
  await measure('next-unread', async () => {
    await act(button(page, 'Next unread'))
    await heading(reader(page), handoff).waitFor()
  })
  await measure('archive-and-next', async () => {
    await act(button(reader(page), 'Archive & next'))
    await heading(reader(page), 'Studio launch notes').waitFor()
    await button(page, 'Undo last action').waitFor()
  })
  await capture(page, 'triage')
  await measure('undo-archive', async () => {
    await act(button(page, 'Undo last action'))
    await button(page, 'Undo last action').waitFor({ state: 'hidden' })
  })
  await act(button(reader(page), 'Back to messages'))
  await button(page, new RegExp(handoff)).waitFor()
}

async function review(page) {
  const panel = page.getByRole('region', { name: 'Sender Review', exact: true })
  const first = button(panel, new RegExp(inboxReview))
  const second = button(panel, new RegExp(inboxDecline))
  await measure('sender-review', async () => {
    await openNavigation(page)
    await act(button(folders(page), /^Sender Review(?:\s|$)/))
    await first.waitFor()
    await second.waitFor()
  })
  await capture(page, 'sender-review')
  await act(first)
  await heading(reader(page), inboxReview).waitFor()
  await measure('allow-first-contact', async () => {
    await act(button(reader(page), 'Allow sender'))
    await second.waitFor()
    await first.waitFor({ state: 'hidden' })
  })
  await act(second)
  await heading(reader(page), inboxDecline).waitFor()
  await act(button(reader(page), 'Decline sender'))
  await panel.getByText('No senders are waiting for review.', { exact: true }).waitFor()
  await second.waitFor({ state: 'hidden' })
  await act(button(panel, 'Declined'))
  await second.waitFor()
  await openNavigation(page)
  await act(button(folders(page), /^Inbox(?:\s|$)/))
  await button(page, new RegExp(inboxReview)).waitFor()
  assert.equal(await button(page, new RegExp(inboxDecline)).count(), 0, 'Declined mail stays out of Inbox')
}

async function followUpAndSaved(page) {
  await openNavigation(page)
  await act(button(folders(page), /^Inbox(?:\s|$)/))
  await act(button(page, new RegExp(handoff)))
  await heading(reader(page), handoff).waitFor()
  const actions = page.getByRole('region', { name: 'Message follow-up' })
  await act(button(actions, 'Add follow-up'))
  await button(actions, 'Clear follow-up').waitFor()
  await act(button(actions, 'Save message'))
  await button(actions, 'Remove from Saved').waitFor()
  if (phone) await act(button(reader(page), 'Back to messages'))
  await openFolder(page, 'Follow-up', handoff, 'follow-up')
  await openFolder(page, 'Saved', handoff, 'saved')
}

async function rsvp(page) {
  await openNavigation(page)
  await act(button(folders(page), /^Inbox(?:\s|$)/))
  await act(button(page, /Thursday studio reservation/))
  const invitation = page.getByRole('region', { name: 'Calendar invitations', exact: true })
  await heading(invitation, 'Studio reservation').waitFor()
  await invitation.getByText('Verified sender', { exact: true }).waitFor()
  await measure('rsvp', async () => {
    await act(button(invitation, 'Accept'))
    await invitation.getByText('Acceptance sent.', { exact: true }).waitFor()
  })
  await invitation.scrollIntoViewIfNeeded()
  await capture(page, 'rsvp')
  if (phone) await act(button(reader(page), 'Back to messages'))
}

async function calendar(page) {
  await measure('calendar', async () => {
    await openNavigation(page)
    await act(folders(page).getByRole('link', { name: 'Calendar', exact: true }))
    const area = page.getByRole('region', { name: 'Calendar workspace' })
    await area.getByText('Studio review', { exact: true }).first().waitFor()
  })
  assert.equal(await page.getByLabel('Jump to date').inputValue(), day)
  await capture(page, 'calendar')
}

async function openShared(page) {
  const picker = page.getByRole('combobox', { name: 'Shared inbox', exact: true })
  const option = picker.locator('option', { hasText: /studio@/ })
  await option.waitFor({ state: 'attached' })
  await picker.selectOption(await option.getAttribute('value'))
  await act(button(page, new RegExp(teamMessage)))
  const area = page.getByRole('region', { name: 'Shared message reader' })
  await heading(area, teamMessage).waitFor()
  await area.getByText('The revised proof is ready for approval.', { exact: true }).waitFor()
  return area
}

async function team(page, browser, options) {
  await page.goto(`${url}/`)
  let area
  await measure('team', async () => {
    await openNavigation(page)
    await act(folders(page).getByRole('link', { name: 'Shared inboxes', exact: true }))
    area = await openShared(page)
  })
  const assignee = area.getByLabel('Assigned to', { exact: true })
  assert.equal(await assignee.inputValue(), '', 'The first reader starts with an unassigned message')
  await measure('team-handoff', async () => {
    const saved = page.waitForResponse(response => response.request().method() === 'PUT'
      && new URL(response.url()).pathname.endsWith('/workflow'))
    await assignee.selectOption({ label: peer })
    assert((await saved).ok(), 'The server accepted the assignment')
    await area.getByRole('status').filter({ hasText: `Assigned by ${owner}` }).waitFor()
    assert.equal(await assignee.locator('option:checked').textContent(), peer)
  })
  await capture(page, 'team')

  const separate = await browser.newPage(options)
  try {
    await signIn(separate, peer)
    await heading(separate, 'Inbox').waitFor()
    await separate.goto(`${url}/shared`)
    const received = await openShared(separate)
    assert.equal(await received.getByLabel('Assigned to').locator('option:checked').textContent(), peer)
  }
  finally { await separate.close() }
}

async function main() {
  assert(Object.hasOwn(engines, engine) && ['desktop', 'phone'].includes(device) && output && url && owner && peer && password && day && revision,
    'Run via test-webmail-navigation.py')
  assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
  await mkdir(output, { recursive: true })
  const browser = await engines[engine].launch()
  const options = {
    viewport, colorScheme: phone ? 'dark' : 'light', deviceScaleFactor: phone ? 2 : 1,
    isMobile: phone && engine !== 'firefox', hasTouch: phone, locale: 'en-US', timezoneId: 'UTC', ignoreHTTPSErrors: true,
  }
  const page = await browser.newPage(options)
  page.setDefaultTimeout(10_000)
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  try {
    await signIn(page, owner)
    await button(page, new RegExp(handoff)).waitFor()
    await capture(page, 'inbox')
    if (phone) {
      await openNavigation(page)
      await capture(page, 'navigation')
      await act(button(page, 'Mailboxes'))
    }
    await triage(page)
    await review(page)
    await openFolder(page, 'Newsletters', 'November studio digest', 'newsletters')
    await openFolder(page, 'Receipts', 'Your receipt #1046', 'receipts')
    await followUpAndSaved(page)
    await openFolder(page, 'Design reviews', 'Archived color proofs', 'folders')
    await rsvp(page)
    await calendar(page)
    await team(page, browser, options)
    assert.deepEqual(errors, [])
    const metadata = { revision, engine, browser: browser.version(), device, viewport, host: process.platform, architecture: process.arch, timings_ms: timings }
    await writeFile(join(output, 'timings.json'), `${JSON.stringify(metadata, null, 2)}\n`)
    console.log(`${engine} ${device} recorded ${Object.keys(timings).length} navigation and workflow timings`)
  }
  finally { await browser.close() }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
