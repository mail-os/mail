import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_BROWSER_URL: url, MAIL_BROWSER_OWNER: owner, MAIL_BROWSER_SENDER: sender, MAIL_BROWSER_PASSWORD: password, MAIL_BROWSER_DAY: day, MAIL_BROWSER_CERT: certificate } = process.env
const { MAIL_BROWSER_NEWCOMER: newcomer } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, engine) && output && url && owner && sender && password && day && certificate && newcomer, 'Run through test-webmail-browser.py')
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/, 'Browser tests require a disposable loopback HTTPS server')

const launchOptions = {}
if (engine === 'chromium') {
  // Chromium downloads use the browser's certificate verification. Trust only
  // the freshly generated key for this loopback fixture.
  const { publicKey } = new X509Certificate(await readFile(certificate))
  const pin = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
  launchOptions.args = [`--ignore-certificate-errors-spki-list=${pin}`]
}
const browser = await engines[engine].launch(launchOptions)
const errors = []
const diagnostics = []
const handoff = 'Tuesday design handoff'
const sentSubject = 'Browser acceptance handoff'
const calendarLabel = 'Design & Research'
const button = (page, name) => page.getByRole('button', { name, exact: typeof name === 'string' })
const heading = (page, name) => page.getByRole('heading', { name, exact: true })
const folders = page => page.getByRole('navigation', { name: 'Mail folders' })
const drawer = page => button(page, 'Mailboxes')

function observePage(page) {
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', (entry) => {
    if (entry.type() === 'error') diagnostics.push(`${new URL(page.url()).pathname} console: ${entry.text()}`)
  })
  page.on('requestfailed', (request) => {
    const path = new URL(request.url()).pathname
    if (request.isNavigationRequest() || path.startsWith('/webmail/'))
      diagnostics.push(`${request.method()} ${path}: ${request.failure()?.errorText}`)
  })
}

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

async function verifySelect(control, minimumHeight = 36) {
  const appearance = await control.evaluate((select) => {
    const style = getComputedStyle(select)
    return { tag: select.tagName, appearance: style.appearance, icon: style.backgroundImage, height: select.getBoundingClientRect().height }
  })
  assert.equal(appearance.tag, 'SELECT', 'The picker retains native keyboard and touch behavior')
  assert.equal(appearance.appearance, 'none')
  assert.match(appearance.icon, /data:image\/svg\+xml/)
  assert(appearance.height >= minimumHeight, 'The picker meets the minimum control height')
}

async function verifyControlRow(container, selector, height, sameRow = true) {
  const controls = await container.locator(selector).evaluateAll(nodes => nodes.map((node) => {
    const style = getComputedStyle(node)
    const box = node.getBoundingClientRect()
    const borderChannels = style.getPropertyValue('--control-border').trim().slice(1).match(/../g)
    const border = `rgb(${borderChannels.map(channel => Number.parseInt(channel, 16)).join(', ')})`
    return {
      name: node.getAttribute('aria-label') || node.labels?.[0]?.textContent.trim() || node.textContent.trim(),
      height: box.height,
      top: box.top,
      bottom: box.bottom,
      left: box.left,
      right: box.right,
      neutral: !node.classList.contains('calendar-primary'),
      borderMatches: style.borderColor === border && style.borderWidth === '1px',
      radius: style.borderRadius,
    }
  }))
  assert(controls.length > 1, 'A control group must have multiple visible controls')
  for (const control of controls) {
    assert(Math.abs(control.height - height) < 0.5, `${control.name} should be ${height}px tall, got ${control.height}px`)
    assert.equal(control.radius, '8px', `${control.name} should use the shared control radius`)
    if (control.neutral) assert(control.borderMatches, `${control.name} should use the shared one-pixel border`)
    if (sameRow) assert(Math.abs(control.top - controls[0].top) < 0.5, `${control.name} should align with the first control`)
  }
  return controls
}

async function verifyCalendarPeriod(page, label, height, stacked = false) {
  const group = page.getByRole('group', { name: 'Change date range' })
  const controls = await verifyControlRow(page.locator('.calendar-view-toolbar'), '.calendar-period > *, .calendar-zone select', height, false)
  assert.equal(controls.length, 5)
  const row = controls.slice(0, stacked ? 3 : 4)
  for (let index = 1; index < row.length; index++) {
    assert(Math.abs(row[index].top - row[0].top) < 0.5, 'Date navigation buttons should align')
    assert(Math.abs(row[index].left - row[index - 1].right - 6) < 0.5, 'Date controls should have matching 6px gaps')
  }
  const date = controls[3]
  assert(date.right - date.left >= 136, 'Jump to date leaves room for the native date and picker')
  if (height === 36) assert(Math.abs(controls[4].top - date.top) < 0.5, 'The time zone picker aligns with the desktop date controls')
  if (stacked) {
    assert(Math.abs(date.top - row[0].bottom - 6) < 0.5, 'Jump to date has the same gap below date navigation')
    assert(Math.abs(date.left - row[0].left) < 0.5 && Math.abs(date.right - row[2].right) < 0.5, 'Jump to date spans the date navigation row')
  }
  await mkdir(output, { recursive: true })
  await group.screenshot({ path: join(output, `${label}-date-controls.png`), animations: 'disabled' })
}

async function verifyAppearance(page, scheme) {
  await page.emulateMedia({ colorScheme: scheme })
  const theme = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement)
    const luminance = token => {
      const hex = style.getPropertyValue(token).trim().slice(1)
      const levels = hex.match(/../g).map(byte => Number.parseInt(byte, 16) / 255)
      const [red, green, blue] = levels.map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
      return 0.2126 * red + 0.7152 * green + 0.0722 * blue
    }
    const pairs = [
      ['--text', '--panel'], ['--muted', '--panel'], ['--muted', '--surface'],
      ['--muted', '--toolbar'], ['--muted', '--selected'], ['--muted', '--sidebar'],
      ['--text', '--list'], ['--muted', '--list'], ['--accent', '--selected'],
      ['--violet', '--sidebar'], ['--teal', '--sidebar'], ['--warning', '--sidebar'],
      ['--accent', '--accent-soft'], ['--warning', '--warning-soft'],
      ['--on-primary', '--primary'], ['--message-selection-text', '--message-selection'],
      ['--message-selection-muted', '--message-selection'],
    ]
    const borders = ['--panel', '--toolbar', '--surface', '--sidebar'].map(background => {
      const a = luminance('--control-border')
      const b = luminance(background)
      return [(Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05), background]
    })
    return {
      scheme: style.colorScheme,
      font: getComputedStyle(document.body).fontFamily,
      fontStack: style.getPropertyValue('--app-font').trim(),
      borders,
      ratios: pairs.map(([foreground, background]) => {
        const a = luminance(foreground)
        const b = luminance(background)
        return [(Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05), foreground, background]
      }),
    }
  })
  assert.equal(theme.scheme, scheme)
  assert.match(theme.fontStack, /^-apple-system,\s*BlinkMacSystemFont,\s*system-ui/i)
  assert.match(theme.font, /^-apple-system,/i)
  for (const [ratio, foreground, background] of theme.ratios)
    assert(ratio >= 4.5, `${scheme} ${foreground} on ${background} must reach 4.5:1, got ${ratio.toFixed(2)}`)
  for (const [ratio, background] of theme.borders)
    assert(ratio >= 3, `${scheme} control borders on ${background} must reach 3:1, got ${ratio.toFixed(2)}`)
}

async function verifyMessageSelection(message, child) {
  const appearance = await message.evaluate((node, selector) => {
    // Resolve the tokens to the browser's computed color serialization.
    const sample = document.createElement('span')
    sample.style.cssText = 'display:none;color:var(--message-selection-text);background:var(--message-selection)'
    document.body.append(sample)
    const expected = getComputedStyle(sample)
    const row = node.closest('.wm-message-row') ?? node
    const colors = {
      backgroundMatches: getComputedStyle(row).backgroundColor === expected.backgroundColor,
      textMatches: getComputedStyle(node.querySelector(selector)).color === expected.color,
    }
    sample.remove()
    return colors
  }, child)
  assert(appearance.backgroundMatches && appearance.textMatches,
    'The selected message uses the high-contrast selection colors')
}

async function openMailbox(page, name) {
  await button(folders(page), name).click()
}

async function openReceiptAndDownload(page) {
  const messagePath = /\/webmail\/api\/messages\/ref\/[^/?]+$/
  const isMarkRead = request => request.method() === 'PUT' && messagePath.test(request.url())
  const attachment = page.getByRole('link', { name: /receipt-1046.txt/ })
  let download
  let saved
  let downloadError
  const holdMarkRead = async (route) => {
    if (!isMarkRead(route.request())) return route.continue()
    const response = await route.fetch()
    try {
      // The server has committed the read flag. The browser still has the
      // attachment link it rendered before receiving the new message revision.
      const href = await attachment.getAttribute('href')
      download = await page.request.get(new URL(href, url).href)
      if (engine === 'chromium' && download.ok()) {
        const [file] = await Promise.all([
          page.waitForEvent('download', { timeout: 5000 }),
          attachment.click({ timeout: 5000 }),
        ])
        saved = { name: file.suggestedFilename(), text: await readFile(await file.path(), 'utf8') }
      }
    }
    catch (error) { downloadError = error }
    finally { await route.fulfill({ response }) }
  }
  await page.route(messagePath, holdMarkRead)
  try {
    const [marked] = await Promise.all([
      page.waitForResponse(response => isMarkRead(response.request())),
      button(page, /Your receipt #1046/).click(),
    ])
    assert.equal(marked.status(), 200, 'The automatic read flag was committed')
    assert.notEqual((await marked.json()).revision, marked.request().headers()['if-match'])
    assert.ifError(downloadError)
    assert.equal(download?.status(), 200, 'Attachment downloads while the mark-read response is held')
    assert.equal(await download.text(), 'Receipt 1046 for Studio Hosting\n')
    if (engine === 'chromium')
      assert.deepEqual(saved, { name: 'receipt-1046.txt', text: 'Receipt 1046 for Studio Hosting\n' })
  }
  finally { await page.unroute(messagePath, holdMarkRead) }
}

async function signIn({ phone = false, account = owner, initialSubject = handoff } = {}) {
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
  observePage(page)
  await page.goto(url + '/login')
  await heading(page, 'Sign in to Mail').waitFor()
  await screenshot(page, phone ? 'phone-sign-in' : 'desktop-sign-in')
  await page.getByLabel('Email or username').fill(account)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await button(page, 'Sign in').click()
  await button(page, new RegExp(initialSubject)).waitFor()
  if (phone) await drawer(page).click()
  const activeFolder = folders(page).locator('[aria-current=page]')
  assert.match(await activeFolder.innerText(), /^Inbox/)
  assert.match(await activeFolder.locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  assert.match(await button(page, 'Compose').locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  assert.match(await page.evaluate(() => getComputedStyle(document.body).fontFamily), /-apple-system/)
  if (phone) await drawer(page).click()
  return page
}

async function desktopJourney(page) {
  await verifyAppearance(page, 'light')
  await page.locator('.wm-reader-empty').waitFor()
  assert.equal(await button(page, /Tuesday design handoff/).getAttribute('aria-description'), 'Unread')
  await screenshot(page, 'desktop-mailbox')
  const conversations = page.getByRole('checkbox', { name: 'Conversations' })
  await conversations.focus()
  assert.equal(await conversations.evaluate(input => getComputedStyle(input.parentElement).outlineStyle), 'solid')
  await conversations.press('Space')
  assert.equal(await conversations.isChecked(), false)
  await conversations.press('Space')
  assert.equal(await conversations.isChecked(), true)
  await button(page, 'Select').press('Enter')
  const selectAll = page.getByRole('checkbox', { name: 'Select messages on this page' })
  await selectAll.check()
  await page.getByText('7 selected', { exact: true }).waitFor()
  await button(page, 'Done').press('Enter')
  assert.equal(await selectAll.isVisible(), false)
  assert.equal(await button(page, 'Select').getAttribute('aria-expanded'), 'false')
  assert.equal(await button(page, 'Select').evaluate(node => node === document.activeElement), true)

  const search = page.getByRole('searchbox', { name: 'Search messages' })
  await search.focus()
  assert.equal(await search.evaluate(input => getComputedStyle(input.parentElement).outlineStyle), 'solid')
  await search.fill(handoff)
  await search.press('Enter')
  await page.getByText('1 message', { exact: true }).waitFor()
  await button(page, 'Filters').press('Enter')
  assert.equal(await button(page, 'Filters').getAttribute('aria-expanded'), 'true')
  await page.getByRole('textbox', { name: 'Filter by sender' }).waitFor()
  const statusFilter = page.getByRole('combobox', { name: 'Filter by message status' })
  await verifySelect(statusFilter)
  await statusFilter.focus()
  assert.equal(await statusFilter.evaluate(node => getComputedStyle(node).outlineStyle), 'solid')
  if (engine === 'chromium') {
    await page.emulateMedia({ forcedColors: 'active' })
    assert.equal(await statusFilter.evaluate(node => getComputedStyle(node).appearance), 'auto')
    await page.emulateMedia({ forcedColors: 'none' })
  }
  await button(page, 'Filters').press('Enter')
  await button(page, 'Clear search and filters').click()
  await page.getByText('7 messages', { exact: true }).waitFor()

  await button(page, /Tuesday design handoff/).click()
  await heading(page, handoff).waitFor()
  assert.equal(await button(page, /Tuesday design handoff/).getAttribute('aria-current'), 'true')
  await verifyMessageSelection(button(page, /Tuesday design handoff/), '.wm-msg-from')
  await page.frameLocator('iframe[title="Email content"]').getByText('For Tuesday', { exact: true }).waitFor()
  const sorting = page.getByText('Sender sorting', { exact: true })
  const destination = page.getByLabel(/Future mail from/)
  assert.equal(await destination.isVisible(), false)
  const indicator = sorting.locator('.wm-disclosure-indicator')
  assert.match(await indicator.evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  await sorting.press('Enter')
  await destination.waitFor()
  await sorting.press('Enter')
  await destination.waitFor({ state: 'hidden' })
  await sorting.blur()
  const tools = page.getByRole('group', { name: 'Message actions', exact: true })
  for (const name of ['Reply', 'Reply all', 'Forward', 'Archive message', 'Flag', 'Mark unread', 'Move this message', 'Trash']) {
    const control = button(tools, name)
    await control.waitFor()
    assert.match(await control.locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  }
  await fitsViewport(page)
  const paper = page.locator('.wm-message-paper')
  await paper.locator('iframe[title="Email content"]').contentFrame().getByText('For Tuesday').waitFor()
  assert(await paper.evaluate(node => getComputedStyle(node).boxShadow === 'none'),
    'The message sits directly on the reading surface')
  await page.locator('.wm-message-row--active:not(.wm-message-row--unread)').waitFor()
  await page.mouse.move(1410, 910)
  await screenshot(page, 'desktop-inbox-light')
  await verifyAppearance(page, 'dark')
  await verifyMessageSelection(button(page, /Tuesday design handoff/), '.wm-msg-from')
  await button(page, 'Show plain text').click()
  await page.locator('.wm-read-text').getByText(/Please confirm the sidebar order/).waitFor()
  assert.match(await button(page, 'Show formatted email').locator('.mail-icon').evaluate(node => getComputedStyle(node).maskImage), /data:image/)
  await page.mouse.move(1410, 910)
  await screenshot(page, 'desktop-inbox-dark')
  await page.emulateMedia({ colorScheme: 'light' })
  await button(tools, 'Archive message').press('Enter')
  await page.getByText('Message moved to Archive.', { exact: true }).waitFor()
  await button(page, /Tuesday design handoff/).waitFor({ state: 'hidden' })
  await button(page, 'Undo last action').click()
  await button(page, /Tuesday design handoff/).click()
  await heading(page, handoff).waitFor()
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
  await page.emulateMedia({ colorScheme: 'dark' })
  await screenshot(page, 'desktop-compose-dark')
  await page.emulateMedia({ colorScheme: 'light' })
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
  await verifyCalendarPeriod(page, 'desktop-light', 36)
  await page.emulateMedia({ colorScheme: 'dark' })
  await screenshot(page, 'desktop-calendar-dark')
  await verifyCalendarPeriod(page, 'desktop-dark', 36)
  await page.emulateMedia({ colorScheme: 'light' })
  await page.getByRole('searchbox', { name: 'Search events' }).fill('Studio review')
  await button(page, 'Search').click()
  await page.getByRole('heading', { name: /^Search results/ }).waitFor()
  await page.getByText('Studio review', { exact: true }).waitFor()
  await button(page, 'Clear').click()

  await page.goto(url)
  await page.getByRole('link', { name: 'Shared inboxes', exact: true }).click()
  await sharedJourney(page)
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

  const firstCheckbox = page.locator('.wm-message-check').first()
  assert.equal(await firstCheckbox.isVisible(), false)
  await button(page, 'Select').click()
  await firstCheckbox.click()
  await page.getByText('1 selected', { exact: true }).waitFor()
  assert.equal(await firstCheckbox.isChecked(), true)
  await screenshot(page, 'phone-selection')
  await button(page, 'Done').click()
  assert.equal(await firstCheckbox.isVisible(), false)
  assert.equal(await firstCheckbox.isChecked(), false)

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
  assert((await button(folders(page), /^Inbox(?:\s|$)/).boundingBox()).height >= 44, 'Mailboxes have full-size touch targets')
  await screenshot(page, 'phone-mailboxes')
  await openMailbox(page, /^Receipts(?:\s|$)/)
  assert.equal(await toggle.getAttribute('aria-expanded'), 'false')
  await page.waitForFunction(() => document.activeElement?.getAttribute('aria-controls') === 'mailNavigation')
  await openReceiptAndDownload(page)
  await heading(page, 'Your receipt #1046').waitFor()
  await page.locator('.wm-receipt-meta .wm-avatar').waitFor()
  await page.locator('.wm-receipt-sender').getByText('Studio Hosting', { exact: true }).waitFor()
  await button(page, 'Reply').waitFor()
  await fitsViewport(page)
  await page.setViewportSize({ width: 320, height: 844 })
  await fitsViewport(page)
  const actions = page.getByRole('group', { name: 'Message actions', exact: true })
  await screenshot(page, 'phone-reader-narrow')
  assert((await actions.boundingBox()).height < 124, 'Reader actions fit into two rows on narrow phones')
  for (const name of ['Reply', 'Reply all', 'Forward', 'Archive message', 'Flag', 'Mark unread', 'Trash', 'Mark junk', 'Next unread', 'Move this message']) {
    const control = await button(actions, name).boundingBox()
    assert(control.width >= 44 && control.height >= 44, `${name} has a full-size touch target`)
  }
  assert((await actions.getByRole('combobox', { name: 'Move destination' }).boundingBox()).height >= 44,
    'Move destination has a full-size touch target')
  await button(actions, 'Mark junk').waitFor()
  await page.setViewportSize({ width: 390, height: 540 })
  const reader = page.getByRole('region', { name: 'Message reader' })
  const back = button(reader, 'Back to messages')
  const originalBack = await back.boundingBox()
  await reader.evaluate(node => { node.scrollTop = node.scrollHeight })
  assert(await reader.evaluate(node => node.scrollTop > 0), 'The short phone viewport scrolls the reader')
  const scrolledBack = await back.boundingBox()
  assert.equal(scrolledBack.y, originalBack.y, 'Back to messages remains visible while scrolling')
  assert((await actions.boundingBox()).y >= scrolledBack.y + scrolledBack.height,
    'Message actions stay below the Back button while scrolling')
  await reader.evaluate(node => { node.scrollTop = 0 })
  await page.setViewportSize({ width: 390, height: 844 })
  await screenshot(page, 'phone-reader')
  await page.emulateMedia({ colorScheme: 'light' })
  await screenshot(page, 'phone-reader-light')
  await page.emulateMedia({ colorScheme: 'dark' })
  await button(page, 'Back to messages').click()

  await button(page, 'Compose').click()
  const composer = page.getByRole('dialog', { name: 'Compose message' })
  const subject = composer.getByLabel('Subject', { exact: true })
  const body = composer.getByLabel('Message body')
  const send = button(composer, 'Send')
  assert((await send.boundingBox()).height >= 44, 'The phone Send button has a full-size touch target')
  await verifySelect(composer.getByLabel('Undo Send delay', { exact: true }), 44)
  await subject.fill('Keyboard draft')
  await body.fill('Save this draft when Escape closes the composer.')
  await body.press('Escape')
  await composer.waitFor({ state: 'hidden' })
  await button(page, 'Resume draft').click()
  assert.equal(await subject.inputValue(), 'Keyboard draft', 'Escape saved the draft subject')
  assert.equal(await body.inputValue(), 'Save this draft when Escape closes the composer.', 'Escape saved the draft body')
  for (const width of [320, 390]) {
    await page.setViewportSize({ width, height: 844 })
    const sheet = await composer.locator('.wm-composer').boundingBox()
    assert(sheet && sheet.width === width && Math.abs(sheet.y + sheet.height - 844) < 1, 'Composer is a full-width bottom sheet on phones')
    await fitsViewport(page)
  }
  await screenshot(page, 'phone-compose')
  await page.emulateMedia({ colorScheme: 'light' })
  await screenshot(page, 'phone-compose-light')
  await page.emulateMedia({ colorScheme: 'dark' })
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
  await heading(page, sentSubject).waitFor()
  assert(!await folders(page).isVisible(), 'Outbox selection closes the drawer')
  await screenshot(page, 'phone-outbox')
  await toggle.click()
  await page.getByRole('link', { name: 'Calendar', exact: true }).click()
  await page.getByRole('region', { name: 'Calendar workspace' }).waitFor()
  await button(page, 'Month').click()
  await page.locator('.calendar-loading').waitFor({ state: 'hidden' })
  await fitsViewport(page)
  await screenshot(page, 'phone-calendar')
  await verifyCalendarPeriod(page, 'phone-dark', 44)
  await page.setViewportSize({ width: 320, height: 844 })
  await fitsViewport(page)
  await verifyCalendarPeriod(page, 'narrow-phone-dark', 44, true)
  await page.setViewportSize({ width: 390, height: 844 })
  await page.emulateMedia({ colorScheme: 'light' })
  await verifyCalendarPeriod(page, 'phone-light', 44)
  await page.emulateMedia({ colorScheme: 'dark' })
  await button(page, /, 2 events$/).click()
  await page.getByText('Studio review', { exact: true }).waitFor()
  await screenshot(page, 'phone-calendar-day')
  await button(page, 'Manage calendars').click()
  const sharing = page.getByRole('region', { name: 'Share a calendar' })
  const access = sharing.getByRole('combobox', { name: /^Access\b/ })
  await access.waitFor()
  await verifySelect(access, 44)
  await verifyControlRow(sharing.locator('form'), 'select, input, button', 44, false)
  await page.locator('.calendar-loading').waitFor({ state: 'hidden' })
  await fitsViewport(page)
  await sharing.scrollIntoViewIfNeeded()
  await screenshot(page, 'phone-calendar-selects')
  await page.goto(url + '/shared')
  await sharedJourney(page, true)
}

async function sharedJourney(page, phone = false) {
  await heading(page, 'Shared inboxes').waitFor()
  const picker = page.getByLabel('Shared inbox', { exact: true })
  const studio = picker.locator('option', { hasText: /studio@hosted\.example\.test/ })
  await studio.waitFor({ state: 'attached' })
  await verifySelect(picker, phone ? 44 : 36)
  await picker.selectOption(await studio.getAttribute('value'))
  const message = button(page, /Studio proof approval/)
  await message.click()
  await heading(page, 'Studio proof approval').waitFor()
  if (!phone) await verifyMessageSelection(message, '.wm-msg-from')
  await page.getByRole('region', { name: 'Shared message reader' })
    .getByText('The revised proof is ready for approval.', { exact: true }).waitFor()
  await button(page, 'Resolve').click()
  await button(page, 'Reopen').waitFor()
  await fitsViewport(page)
  await screenshot(page, phone ? 'phone-shared' : 'desktop-shared')
  await button(page, 'Reopen').click()
  await button(page, 'Resolve').waitFor()
  await button(page, 'Back to messages').click()
  await message.waitFor()
}

async function calendarSharingJourney(captain) {
  const calendarUrl = `${url}/calendar?day=${day}`
  const initialCalendars = Promise.withResolvers()
  await captain.route(/\/webmail\/api\/calendars$/, async (route) => {
    // Download and New event can shift the header while calendars are loading.
    await initialCalendars.promise
    await route.continue()
  }, { times: 1 })
  const manage = button(captain, 'Manage calendars')
  try {
    await captain.goto(calendarUrl)
    await manage.waitFor()
    assert(await manage.isDisabled(), 'Manage calendars waits for the initial calendar controls to settle')
  }
  finally { initialCalendars.resolve() }
  await manage.click()
  const sharing = captain.getByRole('region', { name: 'Share a calendar' })
  await sharing.getByLabel('Calendar to share').selectOption({ label: calendarLabel })
  await sharing.getByRole('combobox', { name: /^Team\b/ }).selectOption({ label: 'Studio' })
  await sharing.getByLabel('Teammate').fill(sender)
  await sharing.getByRole('combobox', { name: /^Access\b/ }).selectOption('viewer')
  await heading(captain, 'Share a calendar').click()
  await captain.locator('.calendar-loading').waitFor({ state: 'hidden' })
  const shareForm = sharing.locator('form')
  assert.equal((await verifyControlRow(shareForm, 'select, input, button', 36)).length, 5)
  await captain.emulateMedia({ colorScheme: 'dark' })
  await verifyControlRow(shareForm, 'select, input, button', 36)
  await screenshot(captain, 'desktop-calendar-selects-dark')
  await captain.emulateMedia({ colorScheme: 'light' })
  await screenshot(captain, 'desktop-calendar-selects')
  await button(sharing, 'Share calendar').click()
  const role = captain.getByRole('combobox', { name: `Access for ${sender} to ${calendarLabel}` })
  await role.waitFor()
  await verifyControlRow(sharing.getByRole('listitem').filter({ has: role }), 'select, button', 36)

  const context = await browser.newContext({
    viewport: { width: 390, height: 844 }, colorScheme: 'dark', hasTouch: true,
    isMobile: engine !== 'firefox', locale: 'en-US', timezoneId: 'UTC', ignoreHTTPSErrors: true,
  })
  const teammate = await context.newPage()
  teammate.setDefaultTimeout(12_000)
  observePage(teammate)
  await teammate.goto(url + '/login')
  await teammate.getByLabel('Email or username').fill(sender)
  await teammate.getByLabel('Password', { exact: true }).fill(password)
  await button(teammate, 'Sign in').click()
  await teammate.waitForURL(url + '/')
  await teammate.goto(calendarUrl)
  const sharedCalendar = button(teammate, /^Design & Research.*View events/)
  await sharedCalendar.click()
  const privateTitle = teammate.getByText('Private budget check', { exact: true })
  const publicEvent = button(teammate, /Studio review/)
  await publicEvent.waitFor()
  assert.equal(await privateTitle.count(), 0)
  assert.equal(await button(teammate, 'New event').count(), 0)
  assert.equal(await teammate.getByRole('link', { name: 'Download .ics' }).count(), 0)
  await fitsViewport(teammate)
  await screenshot(teammate, 'phone-calendar-viewer')
  await publicEvent.click()
  const details = teammate.getByRole('dialog', { name: 'Event details' })
  await details.getByText('You have view access to this calendar.').waitFor()
  assert.equal(await details.getByRole('textbox', { name: 'Title' }).isDisabled(), true)
  assert.equal(await button(details, 'Save event').count(), 0)
  await screenshot(teammate, 'phone-calendar-viewer-detail')

  const checkAccess = () => teammate.evaluate(() => globalThis.dispatchEvent(new Event('focus')))
  async function changeRole(access) {
    const response = captain.waitForResponse(result => result.url().endsWith('/teams/studio/calendar-shares') && result.request().method() === 'PUT')
    await role.selectOption(access)
    assert.equal((await response).status(), 200)
    await checkAccess()
  }

  await changeRole('editor')
  await details.waitFor({ state: 'hidden' })
  await button(teammate, /^Design & Research.*Edit events/).waitFor()
  await publicEvent.click()
  const editor = teammate.getByRole('dialog', { name: 'Edit event' })
  await editor.getByRole('textbox', { name: 'Title' }).fill('Studio review updated')
  await button(editor, 'Save event').click()
  await editor.waitFor({ state: 'hidden' })
  await button(teammate, 'New event').click()
  const creation = teammate.getByRole('dialog', { name: 'New event' })
  assert.match(await creation.getByRole('combobox', { name: 'Calendar', exact: true }).locator('option:checked').innerText(), /^Design & Research/)
  await creation.getByRole('textbox', { name: 'Title' }).fill('Shared draft review')
  await button(creation, 'Save event').click()
  await creation.waitFor({ state: 'hidden' })
  await button(teammate, /Shared draft review/).click()
  await button(editor, 'Delete event').click()
  await button(editor, 'Confirm deletion').click()
  await editor.waitFor({ state: 'hidden' })
  const updated = button(teammate, /Studio review updated/)
  await updated.click()
  await editor.getByRole('textbox', { name: 'Title' }).waitFor()

  const eventsResponse = await captain.request.get(`${url}/webmail/api/calendar-events?q=Studio+review+updated`)
  assert.equal(eventsResponse.status(), 200)
  const [publicRow] = (await eventsResponse.json()).events
  const resource = `${url}/webmail/api/calendar-events/${publicRow.id}`
  const sourceResponse = await captain.request.get(resource + '?source=1')
  assert.equal(sourceResponse.status(), 200)
  const { icalendar } = await sourceResponse.json()
  const privateResponse = await captain.request.put(resource, {
    data: icalendar.replace('CLASS:PUBLIC', 'CLASS:PRIVATE'),
    headers: { Origin: url, 'Content-Type': 'text/calendar', 'If-Match': sourceResponse.headers().etag },
  })
  assert.equal(privateResponse.status(), 200)
  await checkAccess()
  await editor.waitFor({ state: 'hidden' })
  await updated.waitFor({ state: 'hidden' })
  await teammate.getByText('This shared event is no longer available.', { exact: true }).waitFor()

  const restored = await captain.request.put(resource, {
    data: icalendar,
    headers: { Origin: url, 'Content-Type': 'text/calendar', 'If-Match': privateResponse.headers().etag },
  })
  assert.equal(restored.status(), 200)
  await checkAccess()
  await updated.click()
  await editor.getByRole('textbox', { name: 'Title' }).waitFor()
  await changeRole('free_busy')
  await editor.waitFor({ state: 'hidden' })
  const busy = teammate.getByRole('list', { name: 'Busy periods' })
  await busy.waitFor()
  assert.equal(await busy.getByRole('listitem').count(), 2)
  assert.equal(await privateTitle.count(), 0)
  assert.equal(await button(teammate, /Studio review updated/).count(), 0)
  await teammate.setViewportSize({ width: 320, height: 844 })
  await fitsViewport(teammate)
  await teammate.setViewportSize({ width: 390, height: 844 })
  await fitsViewport(teammate)
  await screenshot(teammate, 'phone-calendar-free-busy')

  await screenshot(captain, 'desktop-calendar-sharing')
  await button(sharing, `Revoke access for ${sender} to ${calendarLabel}`).click()
  await role.waitFor({ state: 'hidden' })
  await checkAccess()
  await teammate.getByText('You no longer have access to this shared calendar.', { exact: true }).waitFor()
  await busy.waitFor({ state: 'hidden' })
  await button(teammate, /^Design & Research/).waitFor({ state: 'hidden' })
  await context.close()
}

async function invitationJourney(page, phone = false) {
  await page.goto(url + '/')
  await button(page, /Thursday studio reservation/).click()
  const invitation = page.getByRole('region', { name: 'Calendar invitations', exact: true })
  await heading(invitation, 'Studio reservation').waitFor()
  await invitation.getByText('Calendar invitation', { exact: true }).waitFor()
  await invitation.getByText(sender, { exact: true }).waitFor()
  await invitation.getByText('Verified sender', { exact: true }).waitFor()
  assert.equal(await invitation.getByText(/America\/New_York/).count(), 2)
  await invitation.getByText('South room <Studio>', { exact: true }).waitFor()
  assert.equal(await invitation.locator('studio').count(), 0)
  await page.getByRole('region', { name: 'Message reader' }).getByText('We have the south room from 10 to noon.', { exact: true }).waitFor()
  await fitsViewport(page)
  await screenshot(page, phone ? 'phone-calendar-invitation' : 'desktop-calendar-invitation')
  const actions = invitation.getByRole('group', { name: 'RSVP to organizer' })
  if (phone) {
    await invitation.getByText('Acceptance sent.', { exact: true }).waitFor()
    assert(await button(actions, 'Accept').isDisabled(), 'The earlier decision is visible in a second session')
  }
  // Marking an invitation read changes its ETag. Wait for the reader to
  // apply the new revision and re-enable the controls before pressing Enter.
  const action = button(actions, phone ? 'Tentative' : 'Accept').and(page.locator(':enabled'))
  await action.waitFor()
  const [queued] = await Promise.all([
    page.waitForResponse(response => response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/webmail/api/calendar-rsvp'),
    phone ? (engine === 'firefox' ? action.click() : action.tap()) : action.press('Enter'),
  ])
  assert.equal(queued.status(), 200)
  await invitation.getByText(phone ? 'Tentative response sent.' : 'Acceptance sent.', { exact: true }).waitFor()
  await fitsViewport(page)
  await screenshot(page, phone ? 'phone-calendar-rsvp' : 'desktop-calendar-rsvp')
  if (!phone) {
    await button(invitation, 'Add to Calendar').click()
    await invitation.getByRole('combobox', { name: 'Calendar', exact: true }).waitFor()
    await button(invitation, 'Save invitation').click()
    await invitation.getByText('Saved in Calendar.', { exact: true }).waitFor()
    await screenshot(page, 'desktop-saved-calendar-invitation')
    await openMailbox(page, /^Archive(?:\s|$)/)
    await button(page, /Team breakfast invitation/).click()
    await page.getByText('The organizer cancelled this invitation.', { exact: true }).waitFor()
    assert.equal(await page.getByRole('group', { name: 'RSVP to organizer' }).count(), 0)
    assert.equal(await page.getByRole('link', { name: 'Create event from email', exact: true }).count(), 0)
    await screenshot(page, 'desktop-cancelled-invitation')
  }
  else {
    await invitation.getByText('Saved in Calendar.', { exact: true }).waitFor()
    await screenshot(page, 'phone-saved-calendar-invitation')
  }
}

async function invitationRangeJourney(desktop, phone) {
  await desktop.goto(url + '/')
  await openMailbox(desktop, /^Archive(?:\s|$)/)
  for (const subject of [/Studio sessions moved from Friday/, /Friday studio session only moved again/]) {
    await button(desktop, subject).click()
    const invitation = desktop.getByRole('region', { name: 'Calendar invitations', exact: true })
    await button(invitation, 'Apply to Calendar').click()
    await invitation.getByText('Saved in Calendar.', { exact: true }).waitFor()
  }
  await screenshot(desktop, 'desktop-calendar-range-update')

  await desktop.goto(url + '/calendar?day=2026-11-27')
  await button(desktop, 'Week').click()
  const exact = button(desktop, /Friday studio reservation/)
  const future = button(desktop, /Studio reservation series/)
  await exact.waitFor()
  await future.waitFor()
  assert.match(await exact.locator('.calendar-entry-time').textContent(), /^8:00(?:\s*PM)?\s*–\s*10:00\s*PM$/)
  assert.match(await future.locator('.calendar-entry-time').textContent(), /^6:00(?:\s*PM)?\s*–\s*8:00\s*PM$/)
  await fitsViewport(desktop)
  await screenshot(desktop, 'desktop-calendar-range-week')

  await phone.goto(url + '/calendar?day=2026-11-28')
  await button(phone, 'Day').click()
  const later = button(phone, /Studio reservation series/)
  await later.waitFor()
  assert.match(await later.locator('.calendar-entry-time').textContent(), /^6:00(?:\s*PM)?\s*–\s*8:00\s*PM$/)
  assert.equal(await button(phone, /Friday studio reservation/).count(), 0)
  await fitsViewport(phone)
  await screenshot(phone, 'phone-calendar-range-day')
}

async function mailEventJourney(page, { phone = false, firstCalendar = false } = {}) {
  await verifyAppearance(page, phone ? 'dark' : 'light')
  await page.goto(url + '/')
  await button(page, /Studio launch notes/).click()
  const create = page.getByRole('link', { name: 'Create event from email' })
  assert.match(await create.getAttribute('href'), /^\/calendar#account=.*&message=[a-f0-9]{32}$/)
  await create.click()
  if (firstCalendar) {
    const settings = page.getByRole('region', { name: 'Manage calendars' })
    await settings.getByText('Create a calendar to save an event from this email.').waitFor()
    await settings.getByLabel('Calendar name').fill('Personal calendar')
    await button(settings, 'Create calendar').click()
  }
  const draft = page.getByRole('dialog', { name: 'New event' })
  await draft.waitFor()
  assert.equal(await draft.getByRole('textbox', { name: 'Title' }).inputValue(), 'Studio launch notes')
  assert.equal(await draft.getByRole('textbox', { name: 'Description' }).inputValue(), '')
  await draft.getByText('A private link to the source email will be saved with this event.').waitFor()
  assert.equal(new URL(page.url()).hash, '')
  const title = phone ? 'Phone launch review' : 'Desktop launch review'
  await draft.getByRole('textbox', { name: 'Title' }).fill(title)
  const save = button(draft, 'Save event')
  const primaryAppearance = await save.evaluate(node => {
    const theme = document.createElement('span')
    theme.style.cssText = 'color:var(--on-primary);background:var(--primary)'
    node.append(theme)
    const expected = getComputedStyle(theme)
    const buttonStyle = getComputedStyle(node)
    const usesPrimary = buttonStyle.color === expected.color && buttonStyle.backgroundColor === expected.backgroundColor
    theme.remove()
    return usesPrimary
  })
  assert(primaryAppearance, 'Save event uses the visible Calendar primary colors')
  await screenshot(page, phone ? 'phone-new-event-from-email' : 'desktop-new-event-from-email')
  await save.click()
  await draft.waitFor({ state: 'hidden' })
  if (phone) await button(page, 'Day').click()
  await button(page, new RegExp(title)).click()
  const saved = page.getByRole('dialog', { name: 'Edit event' })
  const source = saved.getByRole('link', { name: 'Open source email' })
  await source.waitFor()
  await screenshot(page, phone ? 'phone-event-backlink' : 'desktop-event-backlink')
  await source.click()
  await heading(page, 'Studio launch notes').waitFor()
  assert.equal(new URL(page.url()).hash, '')
  await page.getByRole('region', { name: 'Message reader' }).getByText('Here is the handoff for Thursday.', { exact: true }).waitFor()
}

async function navigationRequestsJourney(page) {
  await page.goto(url + '/')
  const refresh = button(page, 'Refresh messages')
  await refresh.waitFor()

  const messagePath = /\/webmail\/api\/messages\?/
  const unavailable = route => route.fulfill({ status: 503, json: { message: 'Mailbox temporarily unavailable.' } })
  await page.route(messagePath, unavailable, { times: 1 })
  await refresh.click()
  await page.getByRole('alert').filter({ hasText: 'Mailbox temporarily unavailable.' }).waitFor()
  const retry = button(page, 'Retry messages')
  await retry.click()
  await retry.waitFor({ state: 'hidden' })

  // Keep every read started by Refresh pending through the native link
  // navigation. Record the abort in the outgoing document before it is gone.
  const paths = ['messages', 'folders', 'sender-review/status', 'attention'].map(path => '/webmail/api/' + path)
  const key = 'mail-navigation-cancelled-reads'
  await page.evaluate(({ paths, key }) => {
    const fetchRequest = globalThis.fetch
    sessionStorage.removeItem(key)
    globalThis.fetch = (input, init) => {
      const path = new URL(input, location.href).pathname
      if (paths.includes(path)) {
        init?.signal?.addEventListener('abort', () => {
          const cancelled = JSON.parse(sessionStorage.getItem(key) ?? '[]')
          sessionStorage.setItem(key, JSON.stringify([...cancelled, path]))
        }, { once: true })
      }
      return fetchRequest(input, init)
    }
  }, { paths, key })
  const delayed = request => request.method() === 'GET' && paths.includes(new URL(request.url()).pathname)
  const release = Promise.withResolvers()
  const holdRead = async route => {
    if (!delayed(route.request())) return route.fallback()
    await release.promise
    await route.abort().catch(() => {}) // The browser may already have discarded the request.
  }
  const apiPath = /\/webmail\/api\//
  await page.route(apiPath, holdRead)
  try {
    await Promise.all([
      ...paths.map(path => page.waitForRequest(request => delayed(request) && new URL(request.url()).pathname === path)),
      refresh.click(),
    ])
    await page.getByRole('link', { name: 'Calendar', exact: true }).click()
    await page.getByRole('region', { name: 'Calendar workspace' }).waitFor()
    const cancelled = await page.evaluate(key => JSON.parse(sessionStorage.getItem(key) ?? '[]'), key)
    assert.deepEqual([...new Set(cancelled)].sort(), paths.sort(), 'Leaving Mail cancels all pending refresh reads')
  }
  finally {
    release.resolve()
    await page.unroute(apiPath, holdRead)
  }
}

try {
  const desktop = await signIn()
  await desktopJourney(desktop)
  const phone = await signIn({ phone: true })
  await phoneJourney(phone)
  await invitationJourney(desktop)
  await invitationJourney(phone, true)
  await calendarSharingJourney(desktop)
  await mailEventJourney(desktop)
  const firstRun = await signIn({ phone: true, account: newcomer, initialSubject: 'Studio launch notes' })
  await mailEventJourney(firstRun, { phone: true, firstCalendar: true })
  await invitationRangeJourney(desktop, phone)
  await navigationRequestsJourney(desktop)
  assert.deepEqual(errors, [], 'Browser pages raised uncaught errors')
  process.stdout.write(`${engine} passed the desktop and phone webmail journeys.\n`)
}
catch (error) {
  if (errors.length) process.stderr.write(`Uncaught browser errors:\n${errors.join('\n')}\n`)
  if (diagnostics.length) process.stderr.write(`Browser diagnostics:\n${diagnostics.slice(-20).join('\n')}\n`)
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
