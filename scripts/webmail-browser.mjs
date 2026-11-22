import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_BROWSER_URL: url, MAIL_BROWSER_OWNER: owner, MAIL_BROWSER_SENDER: sender, MAIL_BROWSER_PASSWORD: password, MAIL_BROWSER_DAY: day } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, engine) && output && url && owner && sender && password && day, 'Run through test-webmail-browser.py')
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/, 'Browser tests require a disposable loopback HTTPS server')

const browser = await engines[engine].launch()
const errors = []
const handoff = 'Tuesday design handoff'
const sentSubject = 'Browser acceptance handoff'
const button = (page, name) => page.getByRole('button', { name, exact: typeof name === 'string' })
const heading = (page, name) => page.getByRole('heading', { name, exact: true })
const folders = page => page.getByRole('navigation', { name: 'Mail folders' })
const drawer = page => button(page, 'Mailboxes')

async function screenshot(page, name) {
  await mkdir(output, { recursive: true })
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
  await page.screenshot({ path: join(output, name + '.png'), animations: 'disabled' })
}

async function fitsViewport(page) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Page has horizontal overflow')
  if (await page.locator('.wm').count())
    assert(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight + 1), 'Mail shell exceeds the viewport')
}

async function openMailbox(page, name) {
  await button(folders(page), name).click()
}

async function signIn({ phone = false } = {}) {
  const context = await browser.newContext({
    viewport: phone ? { width: 390, height: 844 } : { width: 1440, height: 940 },
    colorScheme: phone ? 'dark' : 'light',
    hasTouch: phone,
    // Firefox does not support Playwright's isMobile option.
    isMobile: phone && engine !== 'firefox',
    locale: 'en-US',
    timezoneId: 'UTC',
    // The disposable loopback listener presents a freshly generated certificate.
    ignoreHTTPSErrors: true,
  })
  const page = await context.newPage()
  page.setDefaultTimeout(12_000)
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(url + '/login')
  await heading(page, 'Sign in to Mail').waitFor()
  await screenshot(page, phone ? 'phone-sign-in' : 'desktop-sign-in')
  await page.getByLabel('Email or username').fill(owner)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await button(page, 'Sign in').click()
  await button(page, /Tuesday design handoff/).waitFor()
  if (phone) await drawer(page).click()
  const activeFolder = folders(page).locator('[aria-current=page]')
  assert.match(await activeFolder.innerText(), /^Inbox/)
  assert.match(await activeFolder.locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  assert.match(await page.evaluate(() => getComputedStyle(document.body).fontFamily), /-apple-system/)
  if (phone) await drawer(page).click()
  return page
}

async function desktopJourney(page) {
  const search = page.getByRole('searchbox', { name: 'Search messages' })
  await search.focus()
  assert.equal(await search.evaluate(input => getComputedStyle(input.parentElement).outlineStyle), 'solid')
  await search.fill(handoff)
  await search.press('Enter')
  await page.getByText('1 message', { exact: true }).waitFor()
  await button(page, 'Filters').press('Enter')
  assert.equal(await button(page, 'Filters').getAttribute('aria-expanded'), 'true')
  await page.getByRole('textbox', { name: 'Filter by sender' }).waitFor()
  await button(page, 'Filters').press('Enter')
  await button(page, 'Clear search and filters').click()
  await page.getByText('3 messages', { exact: true }).waitFor()

  await button(page, /Tuesday design handoff/).click()
  await heading(page, handoff).waitFor()
  await page.frameLocator('iframe[title="Email content"]').getByText('For Tuesday', { exact: true }).waitFor()
  const tools = page.getByRole('group', { name: 'Message actions', exact: true })
  for (const name of ['Reply', 'Reply all', 'Forward', 'Flag', 'Mark unread', 'Move this message', 'Trash']) {
    const control = button(tools, name)
    await control.waitFor()
    assert.match(await control.locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  }
  await fitsViewport(page)
  await screenshot(page, 'desktop-inbox-light')
  await page.emulateMedia({ colorScheme: 'dark' })
  assert(await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches))
  await button(page, 'Show plain text').click()
  await page.locator('.wm-read-text').getByText(/Please confirm the sidebar order/).waitFor()
  await screenshot(page, 'desktop-inbox-dark')
  await page.emulateMedia({ colorScheme: 'light' })
  await button(tools, 'Flag').click()
  await button(tools, 'Unflag').waitFor()

  await button(page, 'Compose').click()
  const composer = page.getByRole('dialog', { name: 'Compose message' })
  const recipient = composer.getByRole('combobox', { name: 'To', exact: true })
  await recipient.fill(sender)
  await recipient.press('Enter')
  await composer.getByLabel('Subject', { exact: true }).fill(sentSubject)
  await composer.getByLabel('Message body').fill('Sent from the native browser fixture.')
  await composer.getByLabel('Add attachments', { exact: true }).dispatchEvent('cancel', { bubbles: true })
  const fileChooser = page.waitForEvent('filechooser')
  await composer.getByText('Add attachments', { exact: true }).click()
  const picker = await fileChooser
  await picker.setFiles({ name: 'handoff-checklist.txt', mimeType: 'text/plain', buffer: Buffer.from('Review the handoff') })
  await composer.getByText(/handoff-checklist.txt/).waitFor()
  await composer.getByRole('progressbar').waitFor({ state: 'hidden' })
  await screenshot(page, 'desktop-compose')
  await composer.getByLabel('Undo Send delay', { exact: true }).selectOption('0')
  await button(composer, 'Send').click()
  await composer.waitFor({ state: 'hidden' })
  await openMailbox(page, /^Sent(?:\s|$)/)
  await button(page, /Browser acceptance handoff/).waitFor()

  await page.getByRole('link', { name: 'Calendar', exact: true }).click()
  await page.getByRole('region', { name: 'Calendar workspace' }).waitFor()
  await page.getByLabel('Jump to date', { exact: true }).fill(day)
  await button(page, 'Week').click()
  await page.getByText('Studio review', { exact: true }).waitFor()
  await fitsViewport(page)
  await screenshot(page, 'desktop-calendar')

  await page.goto(url + '/status')
  await heading(page, 'Mail delivery').waitFor()
  await screenshot(page, 'desktop-service-health')
  await page.goto(url + '/forgot')
  await heading(page, 'Forgot your password?').waitFor()
  await screenshot(page, 'desktop-recovery')
}

async function phoneJourney(page) {
  const toggle = drawer(page)
  assert.equal(await toggle.getAttribute('aria-controls'), 'mailNavigation')
  assert(!await folders(page).isVisible(), 'Phone starts with the mailbox drawer closed')
  assert((await page.locator('.wm-folders').boundingBox()).height < 64, 'Closed drawer fits in a one-row header')
  await screenshot(page, 'phone-inbox-dark')
  await page.emulateMedia({ colorScheme: 'light' })
  await screenshot(page, 'phone-inbox-light')
  await page.emulateMedia({ colorScheme: 'dark' })

  for (const width of [320, 390, 620, 860, 861]) {
    await page.setViewportSize({ width, height: 844 })
    await fitsViewport(page)
    assert.equal(await toggle.isVisible(), width <= 860, 'Drawer switches at the mobile breakpoint')
  }
  await page.setViewportSize({ width: 390, height: 844 })
  await toggle.press('Enter')
  await button(folders(page), /^Inbox(?:\s|$)/).press('Escape')
  await page.waitForFunction(() => document.activeElement?.getAttribute('aria-controls') === 'mailNavigation')
  assert(!await folders(page).isVisible(), 'Escape closes the drawer and restores focus')
  if (engine === 'firefox') await toggle.click()
  else await toggle.tap()
  await screenshot(page, 'phone-mailboxes')
  await openMailbox(page, /^Receipts(?:\s|$)/)
  assert.equal(await toggle.getAttribute('aria-expanded'), 'false')
  await page.waitForFunction(() => document.activeElement?.getAttribute('aria-controls') === 'mailNavigation')
  await button(page, /Your receipt #1046/).click()
  await heading(page, 'Your receipt #1046').waitFor()
  const attachment = page.getByRole('link', { name: /receipt-1046.txt/ })
  const response = await page.request.get(new URL(await attachment.getAttribute('href'), url).href)
  assert.equal(response.status(), 200)
  assert.equal(await response.text(), 'Receipt 1046 for Studio Hosting\n')
  await button(page, 'Reply').waitFor()
  await fitsViewport(page)
  await screenshot(page, 'phone-reader')
  await button(page, 'Back to messages').click()

  await button(page, 'Compose').click()
  const composer = page.getByRole('dialog', { name: 'Compose message' })
  const subject = composer.getByLabel('Subject', { exact: true })
  const body = composer.getByLabel('Message body')
  await subject.fill('Keyboard draft')
  await body.fill('Save this draft when Escape closes the composer.')
  await body.press('Escape')
  await composer.waitFor({ state: 'hidden' })
  await button(page, 'Resume draft').click()
  assert.equal(await subject.inputValue(), 'Keyboard draft', 'Escape saved the draft subject')
  assert.equal(await body.inputValue(), 'Save this draft when Escape closes the composer.', 'Escape saved the draft body')
  await screenshot(page, 'phone-compose')
  await button(composer, 'Close composer').click()
  await composer.waitFor({ state: 'hidden' })

  await toggle.click()
  await button(page, 'Account').click()
  const account = page.getByRole('dialog', { name: 'Account settings' })
  await account.waitFor()
  await screenshot(page, 'phone-account')
  await button(account, 'Close').click()
  await account.waitFor({ state: 'hidden' })
  await openMailbox(page, /^Outbox(?:\s|$)/)
  await heading(page, 'Outbox').waitFor()
  assert(!await folders(page).isVisible(), 'Outbox selection closes the drawer')
  await toggle.click()
  await page.getByRole('link', { name: 'Calendar', exact: true }).click()
  await page.getByRole('region', { name: 'Calendar workspace' }).waitFor()
  await button(page, 'Month').click()
  await page.locator('.calendar-loading').waitFor({ state: 'hidden' })
  await fitsViewport(page)
  await screenshot(page, 'phone-calendar')
}

try {
  const desktop = await signIn()
  await desktopJourney(desktop)
  const phone = await signIn({ phone: true })
  await phoneJourney(phone)
  assert.deepEqual(errors, [], 'Browser pages raised uncaught errors')
  process.stdout.write(`${engine} passed the desktop and phone webmail journeys.\n`)
}
catch (error) {
  if (errors.length) process.stderr.write(`Uncaught browser errors:\n${errors.join('\n')}\n`)
  for (const context of browser.contexts()) {
    for (const [index, page] of context.pages().entries()) {
      const appearance = (page.viewportSize()?.width ?? 0) <= 860 ? 'phone' : 'desktop'
      await screenshot(page, `failure-${appearance}-${index}`).catch(() => {})
    }
  }
  throw error
}
finally {
  await browser.close()
}
