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

async function verifySelectedOptionFits(control) {
  const { label, used, available } = await control.evaluate((select) => {
    const style = getComputedStyle(select)
    const context = document.createElement('canvas').getContext('2d')
    context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
    const label = select.selectedOptions[0].text
    return {
      label,
      used: context.measureText(label).width,
      available: select.clientWidth - Number.parseFloat(style.paddingLeft) - Number.parseFloat(style.paddingRight),
    }
  })
  assert(available >= used, `The picker has ${available}px for “${label}”, which needs ${used}px`)
}

async function verifyControlRow(container, selector, height, sameRow = true) {
  const controls = await container.evaluate((group, selector) => Array.from(group.querySelectorAll(selector), (node) => {
    const style = getComputedStyle(node)
    const box = node.getBoundingClientRect()
    const borderChannels = style.getPropertyValue('--control-border').trim().slice(1).match(/../g)
    const border = `rgb(${borderChannels.map(channel => Number.parseInt(channel, 16)).join(', ')})`
    const neutral = !node.matches('.calendar-primary, .wm-snapshot-primary, .wm-list-toggle, .wm-action--quiet, .mail-auth-page button:not(.login-secondary)')
    return {
      name: node.getAttribute('aria-label') || node.id || node.tagName,
      height: box.height,
      top: box.top,
      bottom: box.bottom,
      left: box.left,
      right: box.right,
      neutral,
      borderMatches: style.border === `1px solid ${border}`,
      radius: style.borderRadius,
      fontSize: style.fontSize,
    }
  }), selector)
  assert(controls.length > 1, 'A control group must have multiple visible controls')
  for (const control of controls) {
    assert(Math.abs(control.height - height) < 0.5, `${control.name} should be ${height}px tall, got ${control.height}px`)
    assert.equal(control.radius, '8px', `${control.name} should use the shared control radius`)
    if (control.neutral) assert(control.borderMatches, `${control.name} should use the shared one-pixel border`)
    if (sameRow) {
      assert(Math.abs(control.top - controls[0].top) < 0.5, `${control.name} should align with the first control`)
      assert(Math.abs(control.bottom - controls[0].bottom) < 0.5, `${control.name} should align at the bottom`)
    }
  }
  return controls
}

function verifyControlGaps(controls, gap) {
  for (let index = 1; index < controls.length; index++) {
    assert(Math.abs(controls[index].left - controls[index - 1].right - gap) < 0.5,
      `${controls[index].name} should be ${gap}px from the preceding control`)
  }
}

async function verifyCalendarPeriod(page, label, height) {
  const group = page.getByRole('group', { name: 'Change date range' })
  const toolbar = page.locator('.calendar-view-toolbar')
  const controls = await verifyControlRow(toolbar, '.calendar-period :is(button, input), .calendar-zone select', height, false)
  assert.equal(controls.length, 5)
  const stacked = Math.abs(controls[3].top - controls[0].top) >= 0.5
  const width = page.viewportSize()?.width ?? 0
  if (width <= 320) assert(stacked, 'The date field wraps at 320px')
  if (width >= 390) assert(!stacked, 'Date navigation fits on one row at this width')
  const row = controls.slice(0, stacked ? 3 : 4)
  for (const control of row) {
    assert(Math.abs(control.top - row[0].top) < 0.5, 'Date navigation controls should align')
  }
  verifyControlGaps(row, 6)
  for (const arrow of [controls[0], controls[2]]) {
    assert(Math.abs(arrow.right - arrow.left - height) < 0.5, 'Previous and next have square hit areas')
  }
  const date = controls[3]
  assert(date.right - date.left >= 136, 'Jump to date leaves room for the native date and picker')
  const views = await verifyControlRow(toolbar.getByRole('group', { name: 'Calendar view' }), 'button', height)
  verifyControlGaps(views, 6)
  assert([...controls, ...views].every(control => control.fontSize === date.fontSize), 'Toolbar fields and actions share a text size')
  const crampedViews = await toolbar.locator('.calendar-view-modes button').evaluateAll(buttons => buttons.flatMap((button) => {
    const box = button.getBoundingClientRect()
    const range = document.createRange()
    range.selectNodeContents(button)
    const text = range.getBoundingClientRect()
    return text.left - box.left < 5.5 || box.right - text.right < 5.5 ? [button.textContent] : []
  }))
  assert.deepEqual(crampedViews, [], 'View labels have clear space inside each border')
  if (width >= 1160) {
    for (const control of [...views, controls[4]]) {
      assert(Math.abs(control.top - date.top) < 0.5 && Math.abs(control.bottom - date.bottom) < 0.5,
        'The view and time zone controls align with both edges of the date controls')
    }
  }
  if (stacked) {
    assert(Math.abs(date.top - row[0].bottom - 6) < 0.5, 'Jump to date has the same gap below date navigation')
    assert(Math.abs(date.left - row[0].left) < 0.5 && Math.abs(date.right - row[2].right) < 0.5, 'Jump to date spans the date navigation row')
  }
  await fitsViewport(page)
  if (!label) return
  await mkdir(output, { recursive: true })
  await group.screenshot({ path: join(output, `${label}-date-controls.png`), animations: 'disabled' })
  await toolbar.screenshot({ path: join(output, `${label}-calendar-toolbar.png`), animations: 'disabled' })
}

async function verifyReaderToolbar(toolbar, height) {
  const controls = await toolbar.locator('.wm-tool:visible, .wm-action:visible, select:visible').evaluateAll(elements =>
    elements.map((element) => {
      const { top, bottom, height } = element.getBoundingClientRect()
      return { top, bottom, height, name: element.getAttribute('aria-label') || element.textContent.trim() }
    }),
  )
  assert(controls.length >= 10)
  for (const control of controls) {
    assert(Math.abs(control.height - height) < 0.5, `${control.name} should be ${height}px tall`)
    for (const other of controls) {
      if (control.top < other.bottom - 0.5 && control.bottom > other.top + 0.5)
        assert(Math.abs(control.top - other.top) < 0.5, `${control.name} and ${other.name} should align on their row`)
    }
  }
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
  await verifyControlRow(page.locator('.mail-auth-page form'), 'input, button', 44, false)
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
  const move = page.getByRole('group', { name: 'Move message', exact: true })
  verifyControlGaps(await verifyControlRow(move, 'select, button', 36), 6)
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
  await verifyReaderToolbar(tools, 36)
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
  await move.getByLabel('Move destination').selectOption('Archive')
  await button(move, 'Move this message').press('Enter')
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
  for (const width of [371, 490, 491, 860, 861, 1159, 1160]) {
    await page.setViewportSize({ width, height: 940 })
    await verifyCalendarPeriod(page, null, width > 860 ? 36 : 44)
  }
  await page.setViewportSize({ width: 1440, height: 940 })
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
  await verifyControlRow(page.locator('.mail-auth-page form:visible'), 'input, button', 44, false)
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
  await verifyReaderToolbar(actions, 44)
  await screenshot(page, 'phone-reader-narrow')
  assert((await actions.boundingBox()).height < 124, 'Reader actions fit into two rows on narrow phones')
  for (const name of ['Reply', 'Reply all', 'Forward', 'Archive message', 'Flag', 'Mark unread', 'Trash', 'Mark junk', 'Next unread', 'Move this message']) {
    const control = await button(actions, name).boundingBox()
    assert(control.width >= 44 && control.height >= 44, `${name} has a full-size touch target`)
  }
  const move = actions.getByRole('group', { name: 'Move message', exact: true })
  const [destination, moveButton] = await verifyControlRow(move, 'select, button', 44)
  verifyControlGaps([destination, moveButton], 6)
  assert(destination.right - destination.left >= 108, 'Move destination leaves room for the Archive label')
  await verifySelectedOptionFits(move.getByLabel('Move destination'))
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
  await verifyCalendarPeriod(page, 'narrow-phone-dark', 44)
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
  await verifyControlRow(page.locator('.calendar-create-form'), 'input, button', 44)
  const shareForm = sharing.locator('form')
  const calendarPicker = sharing.getByLabel('Calendar to share')
  const [calendar, team, teammate, role, submit] = await verifyControlRow(shareForm, 'select, input, button', 44, false)
  assert(Math.abs(calendar.top - team.top) < 0.5, 'The first two sharing labels and pickers align')
  assert(Math.abs(role.top - submit.top) < 0.5, 'The access picker and share button align')
  assert(Math.abs(teammate.left - calendar.left) < 0.5, 'The teammate field starts at the left column')
  assert(Math.abs(teammate.right - team.right) < 0.5, 'The teammate field spans the grid')
  verifyControlGaps([calendar, team], 12)
  verifyControlGaps([role, submit], 12)
  await verifySelectedOptionFits(calendarPicker)
  await page.setViewportSize({ width: 320, height: 844 })
  await fitsViewport(page)
  const narrowSharing = await verifyControlRow(shareForm, 'select, input, button', 44, false)
  assert(narrowSharing.every(control => Math.abs(control.left - narrowSharing[0].left) < 0.5 && Math.abs(control.right - narrowSharing[0].right) < 0.5),
    'Sharing controls use the full column on narrow phones')
  await access.selectOption('free_busy')
  for (const picker of await shareForm.getByRole('combobox').all()) await verifySelectedOptionFits(picker)
  await access.selectOption('viewer')
  await shareForm.screenshot({ path: join(output, 'narrow-phone-calendar-sharing-dark.png'), animations: 'disabled' })
  await page.setViewportSize({ width: 390, height: 844 })
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

async function calendarTasksJourney(page, phone = false) {
  if (phone) await page.setViewportSize({ width: 320, height: 844 })
  await page.goto(`${url}/calendar?day=${day}`)
  const trigger = button(page, 'Tasks')
  await trigger.click()
  const panel = page.getByRole('region', { name: 'Personal tasks' })
  const panelHeading = heading(panel, 'Personal tasks')
  await panelHeading.waitFor()
  await page.waitForFunction(() => document.activeElement?.id === 'calendar-tasks-heading')
  const add = button(panel, 'Add task')
  await add.click()
  const editor = panel.getByRole('form', { name: 'Task details' })
  const title = editor.getByRole('textbox', { name: 'Task title' })
  const date = editor.getByLabel('Date (optional)', { exact: true })
  const name = phone ? 'Prepare travel documents' : 'Send the quarterly notes'
  await title.waitFor()
  await page.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'taskTitleField')
  assert.equal(await date.inputValue(), '')
  await editor.getByText('No date', { exact: true }).waitFor()
  await verifyControlRow(editor, 'input, button', phone ? 44 : 36, !phone)
  await title.fill(name)
  await panel.screenshot({ path: join(output, phone ? 'phone-calendar-task-editor.png' : 'desktop-calendar-task-editor.png'), animations: 'disabled' })
  await button(editor, 'Add task').click()
  const task = panel.getByRole('listitem').filter({ hasText: name })
  await task.getByText('No date', { exact: true }).waitFor()
  await button(task, `Edit ${name}`).click()
  await date.fill('2028-03-12')
  await button(editor, 'Save task').click()
  const scheduled = task.getByRole('link', { name: 'Mar 12, 2028' })
  await scheduled.waitFor()
  assert.equal(await scheduled.getAttribute('href'), '/calendar?day=2028-03-12')
  await task.scrollIntoViewIfNeeded()
  await verifyControlRow(task, 'button', phone ? 44 : 36)
  await fitsViewport(page)
  await panel.screenshot({ path: join(output, phone ? 'phone-calendar-tasks.png' : 'desktop-calendar-tasks.png'), animations: 'disabled' })

  await page.getByRole('combobox', { name: 'Display time zone' }).selectOption('America/Los_Angeles')
  await page.locator('.calendar-loading').waitFor({ state: 'hidden' })
  await scheduled.waitFor()
  await scheduled.click()
  await page.waitForURL(`${url}/calendar?day=2028-03-12`)
  await heading(page, 'Sunday, March 12, 2028').waitFor()
  await trigger.click()
  await scheduled.waitFor()
  await button(task, `Complete ${name}`).click()
  await task.waitFor({ state: 'hidden' })
  await button(panel, 'Completed').click()
  await scheduled.waitFor()
  await button(task, `Reopen ${name}`).click()
  await task.waitFor({ state: 'hidden' })
  await button(panel, 'Open').click()
  await scheduled.waitFor()
  await button(task, `Edit ${name}`).click()

  // A second tab editing the same task should leave this tab's draft visible.
  const list = await page.request.get(url + '/webmail/api/calendar-tasks')
  const latest = (await list.json()).tasks.find(task => task.title === name)
  const moved = await page.request.put(`${url}/webmail/api/calendar-tasks/${latest.id}`, {
    headers: { Origin: url },
    data: { title: name, day: '2028-11-05', completed: false, revision: latest.revision },
  })
  assert.equal(moved.status(), 200, await moved.text())
  await date.fill('2028-03-13')
  await button(editor, 'Save task').click()
  await panel.getByRole('alert').filter({ hasText: 'This task changed' }).waitFor()
  assert.equal(await date.inputValue(), '2028-03-13')
  await button(panel, 'Load latest tasks').click()
  await task.getByRole('link', { name: 'Nov 5, 2028' }).waitFor()
  await button(task, `Edit ${name}`).click()
  const clearDate = button(editor, 'Clear date')
  await clearDate.waitFor()
  await verifyControlRow(editor.locator('.calendar-task-date'), 'input, button', phone ? 44 : 36)
  await clearDate.click()
  assert.equal(await date.inputValue(), '')
  await page.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'taskSaveButton')
  await editor.getByText('No date', { exact: true }).waitFor()
  await button(editor, 'Save task').click()
  await task.getByText('No date', { exact: true }).waitFor()
  await button(task, `Edit ${name}`).click()
  await button(editor, 'Delete task').click()
  await page.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'taskDeleteButton')
  await button(editor, 'Confirm deletion').press('Enter')
  await task.waitFor({ state: 'hidden' })
  await panel.getByText('Task deleted.', { exact: true }).waitFor()
  await trigger.click()
  await panel.waitFor({ state: 'hidden' })
  if (phone) await page.setViewportSize({ width: 390, height: 844 })
}

async function calendarToolsJourney(desktop, phone) {
  const calendarUrl = `${url}/calendar?day=2028-02-29`
  const endpoint = `${url}/webmail/api/calendar-tools`
  const journal = '  Bring the design notes.\nCheck the prototype before lunch.\n'
  await desktop.goto(calendarUrl)
  await button(desktop, 'Personal tools').click()
  const panel = desktop.getByRole('region', { name: 'Personal tools' })
  await heading(panel, 'Personal tools').waitFor()
  await desktop.waitForFunction(() => document.activeElement?.id === 'calendar-tools-heading')
  assert.equal(await button(panel, 'Countdowns').count(), 0)
  await button(panel, 'Enable personal tools').click()
  const form = panel.getByRole('form', { name: 'Personal tool entry' })
  await form.waitFor()
  await verifyControlRow(form, 'input, button', 36)
  await panel.getByLabel('Countdown name').fill('Spring workshop')
  await panel.getByLabel('Target date').fill('2028-03-12')
  await button(panel, 'Add countdown').click()
  await panel.getByText('Spring workshop', { exact: true }).waitFor()
  await panel.getByText(/Mar 12, 2028 · (?:[\d,]+ days? (?:left|ago)|Today)/).waitFor()
  await panel.screenshot({ path: join(output, 'desktop-calendar-countdowns.png'), animations: 'disabled' })

  await button(panel, 'Habits').click()
  await panel.getByLabel('Habit name').fill('Read a chapter')
  await button(panel, 'Add habit').click()
  const check = button(panel, 'Check in for Read a chapter')
  await check.click()
  await panel.getByText('1 check-in', { exact: true }).waitFor()
  assert.equal(await check.getAttribute('aria-pressed'), 'true')
  const entryDate = panel.getByLabel('Entry date', { exact: true })
  await entryDate.fill('2028-03-01')
  assert.equal(await check.getAttribute('aria-pressed'), 'false')
  await entryDate.fill('2028-02-29')
  assert.equal(await check.getAttribute('aria-pressed'), 'true')
  await entryDate.evaluate((input) => {
    input.value = ''
    input.dispatchEvent(new Event('change', { bubbles: true }))
  })
  assert.equal(await entryDate.inputValue(), '2028-02-29', 'An empty entry date keeps the selected day visible')
  await button(panel, 'Edit Read a chapter').click()
  await panel.getByLabel('Habit name').fill('Read after lunch')
  await button(panel, 'Save entry').click()
  await button(panel, 'Check in for Read after lunch').waitFor()
  assert.equal(await button(panel, 'Check in for Read after lunch').getAttribute('aria-pressed'), 'true')

  await button(panel, 'Journal').click()
  const note = panel.getByRole('textbox', { name: 'Journal note' })
  await note.fill(journal)
  await button(panel, 'Save note').click()
  await panel.getByText('Journal note saved.', { exact: true }).waitFor()
  await entryDate.fill('2028-03-01')
  assert.equal(await note.inputValue(), '')
  await panel.getByLabel('Saved notes').selectOption('2028-02-29')
  assert.equal(await note.inputValue(), journal)

  await button(panel, 'Time log').click()
  await panel.getByLabel('Activity').fill('Design review')
  await panel.getByLabel('Minutes').fill('25')
  await button(panel, 'Log time').click()
  await panel.getByText('25 min logged', { exact: true }).waitFor()
  await panel.getByLabel('Activity').fill('Test run')
  await panel.getByLabel('Minutes').fill('35')
  await button(panel, 'Log time').click()
  await panel.getByText('60 min logged', { exact: true }).waitFor()
  await button(panel, 'Remove Test run').click()
  await desktop.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'toolRemovalButton')
  await button(panel, 'Confirm removal').press('Enter')
  await panel.getByText('25 min logged', { exact: true }).waitFor()

  await button(panel, 'Display & data').click()
  await verifyControlRow(panel.locator('.calendar-tools-data'), 'input, button', 36)
  await button(desktop, 'Month').click()
  const calendarCell = desktop.locator('.calendar-board-month .calendar-day').first()
  const standardHeight = await calendarCell.evaluate(cell => Number.parseFloat(getComputedStyle(cell).minHeight))
  const read = await desktop.request.get(endpoint)
  const current = await read.json()
  const changed = await desktop.request.put(endpoint, { headers: { Origin: url }, data: current })
  assert.equal(changed.status(), 200, await changed.text())
  await button(panel, 'Compact').click()
  await panel.getByRole('alert').filter({ hasText: 'changed in another window' }).waitFor()
  await button(panel, 'Load latest personal tools').click()
  await button(panel, 'Compact').click()
  await desktop.locator('.calendar-workspace-compact').waitFor()
  assert(await calendarCell.evaluate(cell => Number.parseFloat(getComputedStyle(cell).minHeight)) < standardHeight)
  const [download] = await Promise.all([desktop.waitForEvent('download'), button(panel, 'Export JSON').click()])
  assert.equal(download.suggestedFilename(), 'mail-personal-tools.json')
  const exported = await readFile(await download.path())
  const portable = JSON.parse(exported.toString())
  assert.equal(portable.version, 1)
  assert.equal(portable.appearance, 'compact')
  assert.equal(portable.journal[0].text, journal)
  assert.deepEqual(portable.habits[0].days, ['2028-02-29'])
  assert.equal(portable.time[0].minutes, 25)
  assert(!('revision' in portable) && !('user_id' in portable))

  await phone.setViewportSize({ width: 320, height: 844 })
  await phone.goto(calendarUrl)
  await phone.locator('.calendar-workspace-compact').waitFor()
  await button(phone, 'Personal tools').click()
  const mobile = phone.getByRole('region', { name: 'Personal tools' })
  await button(mobile, 'Habits').click()
  const mobileCheck = button(mobile, 'Check in for Read after lunch')
  await mobileCheck.waitFor()
  assert.equal(await mobileCheck.getAttribute('aria-pressed'), 'true')
  await verifyControlRow(mobile.locator('form'), 'input, button', 44, false)
  await fitsViewport(phone)
  await mobile.screenshot({ path: join(output, 'phone-calendar-habits.png'), animations: 'disabled' })
  await button(mobile, 'Display & data').click()
  const density = mobile.getByRole('group', { name: 'Calendar density' })
  const densityButtons = await verifyControlRow(density, 'button', 44)
  assert.equal(densityButtons[0].right - densityButtons[0].left, densityButtons[1].right - densityButtons[1].left)
  assert.equal(await button(density, 'Compact').getAttribute('aria-pressed'), 'true')
  await verifyControlRow(mobile.locator('.calendar-tools-data'), 'input, button', 44, false)
  await mobile.screenshot({ path: join(output, 'phone-calendar-tools-display.png'), animations: 'disabled' })
  await button(mobile, 'Turn off personal tools').click()
  await button(mobile, 'Enable personal tools').waitFor()
  assert.equal(await phone.locator('.calendar-workspace-compact').count(), 0)
  assert.equal(await mobileCheck.count(), 0)
  const file = mobile.getByLabel('Import personal tools')
  await file.setInputFiles({ name: 'personal-tools.json', mimeType: 'application/json', buffer: exported })
  const confirm = mobile.getByRole('group', { name: 'Confirm personal tools import' })
  await confirm.waitFor()
  await button(confirm, 'Cancel import').click()
  await button(mobile, 'Enable personal tools').waitFor()
  await file.setInputFiles({ name: 'personal-tools.json', mimeType: 'application/json', buffer: exported })
  await button(confirm, 'Replace personal tools').click()
  await phone.locator('.calendar-workspace-compact').waitFor()
  await button(mobile, 'Journal').click()
  assert.equal(await mobile.getByRole('textbox', { name: 'Journal note' }).inputValue(), journal)
  await fitsViewport(phone)
  await mobile.screenshot({ path: join(output, 'phone-calendar-journal.png'), animations: 'disabled' })
  const exportLink = desktop.getByRole('link', { name: 'Download .ics', exact: true })
  const ics = await desktop.request.get(url + await exportLink.getAttribute('href'))
  assert.equal(ics.status(), 200)
  assert(!(await ics.text()).includes('Spring workshop'), 'Calendar export keeps personal tools private')
  await phone.clock.setFixedTime(new Date('2028-03-12T00:30:00Z'))
  await phone.evaluate(() => globalThis.dispatchEvent(new Event('focus')))
  await button(mobile, 'Countdowns').click()
  await mobile.getByText('Mar 12, 2028 · Today', { exact: true }).waitFor()
  await phone.getByRole('combobox', { name: 'Display time zone' }).selectOption('America/Los_Angeles')
  await mobile.getByText('Mar 12, 2028 · 1 day left', { exact: true }).waitFor()
  await phone.setViewportSize({ width: 390, height: 844 })
}

async function shareLaterReply(desktop, viewer, originalUrl, originalSubject) {
  const replyText = 'Please use the updated billing contact for the next payment.'
  const replySubject = `Re: ${originalSubject}`
  await button(desktop, 'Reply').click()
  const composer = desktop.getByRole('dialog', { name: 'Compose message' })
  const body = composer.getByLabel('Message body')
  const quote = await body.inputValue()
  assert.match(quote, /> Your November payment of \$18\.00 was received\./)
  await body.fill(replyText + quote)
  await composer.getByLabel('Undo Send delay', { exact: true }).selectOption('0')
  await button(composer, 'Send').click()
  await composer.waitFor({ state: 'hidden' })

  await openMailbox(desktop, /^Sent(?:\s|$)/)
  await button(desktop, /Re: Your receipt #1046/).click()
  await heading(desktop, replySubject).waitFor()
  await viewer.goto(originalUrl)
  await heading(viewer, originalSubject).waitFor()
  assert.equal(await viewer.getByText(replyText).count(), 0, 'The original link never picks up a sent reply')

  await button(desktop, 'Share snapshot').click()
  const dialog = desktop.getByRole('dialog', { name: 'Share a snapshot' })
  const preview = dialog.getByRole('region', { name: 'Snapshot preview' })
  await heading(preview, replySubject).waitFor()
  assert.equal(await preview.locator('.wm-snapshot-message').count(), 1)
  const approved = await preview.locator('.wm-snapshot-body').textContent()
  assert(approved.includes(replyText) && approved.includes('> Your November payment'))
  await dialog.getByLabel('Link expires in').selectOption('86400')
  await dialog.locator('.wm-snapshot-panel').screenshot({ path: join(output, 'desktop-later-reply-preview.png'), animations: 'disabled' })
  await button(dialog, 'Create link').click()
  const created = desktop.getByRole('dialog', { name: 'Snapshot link created' })
  const replyUrl = await created.getByRole('textbox', { name: 'Snapshot link' }).inputValue()
  assert.notEqual(replyUrl, originalUrl)
  await button(created, 'Close').click()

  await viewer.goto(replyUrl)
  await heading(viewer, replySubject).waitFor()
  assert.equal(await viewer.locator('.wm-snapshot-message').count(), 1)
  assert.equal(await viewer.locator('.wm-snapshot-body').textContent(), approved)
  await screenshot(viewer, 'phone-later-reply-viewer')
  return replySubject
}

async function snapshotSharingJourney(desktop, phone) {
  const subject = 'Your receipt #1046'
  await desktop.goto(url + '/')
  await openMailbox(desktop, /^Receipts(?:\s|$)/)
  await button(desktop, /Your receipt #1046/).click()
  await heading(desktop, subject).waitFor()
  const share = button(desktop, 'Share snapshot')
  await share.click()
  const previewDialog = desktop.getByRole('dialog', { name: 'Share a snapshot' })
  const preview = previewDialog.getByRole('region', { name: 'Snapshot preview' })
  await preview.getByText('Your November payment of $18.00 was received.', { exact: true }).waitFor()
  assert.equal(await preview.getByText('receipt-1046.txt', { exact: true }).count(), 0)
  await verifyControlRow(previewDialog.locator('form'), 'select, button', 36)
  const unpublished = await desktop.request.get(url + '/webmail/api/snapshot-links')
  assert.deepEqual(await unpublished.json(), { links: [] })
  await previewDialog.getByLabel('Link expires in').selectOption('3600')
  await previewDialog.locator('.wm-snapshot-panel').screenshot({ path: join(output, 'desktop-snapshot-preview.png'), animations: 'disabled' })
  await button(previewDialog, 'Create link').click()
  const created = desktop.getByRole('dialog', { name: 'Snapshot link created' })
  const linkField = created.getByRole('textbox', { name: 'Snapshot link' })
  await linkField.waitFor()
  await desktop.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'snapshotUrlField')
  const singleUrl = await linkField.inputValue()
  assert.equal(new URL(singleUrl).pathname, '/snapshot')
  assert.match(new URL(singleUrl).hash, /^#token=[0-9a-f]{64}$/)
  await button(created, 'Close').click()

  await phone.setViewportSize({ width: 320, height: 844 })
  await phone.goto(url + '/')
  await button(phone, 'Select').click()
  await phone.getByRole('checkbox', { name: 'Select conversation: Studio launch notes', exact: true }).check()
  await phone.getByRole('checkbox', { name: 'Select conversation: November research interviews', exact: true }).check()
  await phone.getByText('2 selected', { exact: true }).waitFor()
  const bulk = phone.getByLabel('Selected message actions')
  await button(bulk, 'Share snapshot').click()
  const mobilePreview = phone.getByRole('dialog', { name: 'Share a snapshot' })
  const mobileMessages = mobilePreview.getByRole('region', { name: 'Snapshot preview' })
  await heading(mobileMessages, 'Studio launch notes').waitFor()
  await heading(mobileMessages, 'November research interviews').waitFor()
  await verifyControlRow(mobilePreview.locator('form'), 'select, button', 44, false)
  await fitsViewport(phone)
  await mobilePreview.locator('.wm-snapshot-panel').screenshot({ path: join(output, 'phone-snapshot-preview.png'), animations: 'disabled' })
  await button(mobilePreview, 'Create link').click()
  const mobileCreated = phone.getByRole('dialog', { name: 'Snapshot link created' })
  const bulkUrl = await mobileCreated.getByRole('textbox', { name: 'Snapshot link' }).inputValue()
  await button(mobileCreated, 'Close').click()

  const viewerContext = await browser.newContext({ viewport: { width: 320, height: 844 }, colorScheme: 'dark',
    ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC' })
  try {
    const viewer = await viewerContext.newPage()
    viewer.setDefaultTimeout(12_000)
    observePage(viewer)
    const externalRequests = []
    viewer.on('request', (request) => { if (new URL(request.url()).origin !== url) externalRequests.push(request.url()) })
    await viewer.goto(singleUrl)
    await heading(viewer, subject).waitFor()
    await viewer.getByText('Your November payment of $18.00 was received.', { exact: true }).waitFor()
    assert.equal(await viewer.getByText(/receipt-1046\.txt/).count(), 0)
    await viewer.goto(bulkUrl)
    await heading(viewer, 'Studio launch notes').waitFor()
    await heading(viewer, 'November research interviews').waitFor()
    assert.equal(await heading(viewer, subject).count(), 0)
    assert.equal(await viewer.locator('.wm-snapshot-message').count(), 2)
    assert.equal(await viewer.getByRole('alert').count(), 0)
    assert.deepEqual(await viewerContext.cookies(), [])
    assert.deepEqual(externalRequests, [], 'Snapshot viewing never requests remote content')
    await fitsViewport(viewer)
    await screenshot(viewer, 'phone-snapshot-viewer')

    const replySubject = await shareLaterReply(desktop, viewer, singleUrl, subject)
    await button(desktop, 'Account').click()
    const account = desktop.getByRole('dialog', { name: 'Account settings' })
    await button(account, 'Manage shared links').click()
    const manager = desktop.getByRole('dialog', { name: 'Shared links' })
    const revokeReply = button(manager, `Revoke link for ${replySubject}`)
    await revokeReply.click()
    await button(manager.getByRole('group', { name: 'Confirm revocation' }), 'Revoke link').click()
    await revokeReply.waitFor({ state: 'hidden' })
    await viewer.reload()
    await viewer.getByText(/This snapshot link is unavailable/).waitFor()
    await viewer.goto(singleUrl)
    await heading(viewer, subject).waitFor()
    assert.equal(await viewer.locator('.wm-snapshot-message').count(), 1)
    const revoke = button(manager, `Revoke link for ${subject}`)
    await revoke.click()
    await button(manager.getByRole('group', { name: 'Confirm revocation' }), 'Revoke link').click()
    await revoke.waitFor({ state: 'hidden' })
    await viewer.reload()
    await viewer.getByText(/This snapshot link is unavailable/).waitFor()
    assert.equal(await heading(viewer, subject).count(), 0)
    await viewer.goto(bulkUrl)
    await heading(viewer, 'Studio launch notes').waitFor()
    await button(manager, 'Close').click()
    await button(account, 'Close').click()
  }
  finally { await viewerContext.close() }
  await phone.setViewportSize({ width: 390, height: 844 })
}

async function fileLinkJourney(desktop, phone) {
  const filename = 'Workshop proofs.bin'
  const subject = 'Download the workshop proofs'
  const contents = Buffer.alloc(128 * 1024, 0x9b)
  contents.write('Disposable file-link fixture')
  await desktop.goto(url + '/')
  await button(desktop, 'Compose').click()
  const desktopCompose = desktop.getByRole('dialog', { name: 'Compose message' })
  await button(desktopCompose, 'Add file link').click()
  const desktopPanel = desktopCompose.getByRole('region', { name: 'Add a file link' })
  await verifyControlRow(desktopPanel.locator('.wm-file-link-controls'), 'input, select, button', 36)
  await desktopPanel.screenshot({ path: join(output, 'desktop-compose-file-link.png'), animations: 'disabled' })
  await button(desktopCompose, 'Close composer').click()
  await desktopCompose.waitFor({ state: 'hidden' })

  await phone.setViewportSize({ width: 320, height: 844 })
  await phone.goto(url + '/')
  await button(phone, 'Compose').click()
  const compose = phone.getByRole('dialog', { name: 'Compose message' })
  await button(compose, 'Add file link').click()
  const panel = compose.getByRole('region', { name: 'Add a file link' })
  const picker = panel.getByLabel('Choose file')
  await picker.setInputFiles({ name: filename, mimeType: 'application/octet-stream', buffer: contents })
  assert.equal(await picker.evaluate(input => input.files[0]?.name), filename)
  await panel.getByLabel('Link expires in').selectOption('3600')
  await verifyControlRow(panel.locator('.wm-file-link-controls'), 'input, select, button', 44, false)
  await fitsViewport(phone)
  await compose.locator('.wm-composer').evaluate(form => {
    const panel = form.querySelector('#compose-file-link').getBoundingClientRect()
    const header = form.querySelector('.wm-composer-head').getBoundingClientRect()
    const footer = form.querySelector('.wm-composer-foot').getBoundingClientRect()
    if (panel.top < header.bottom || panel.bottom > footer.top) throw new Error('File link controls should fit between the composer header and footer')
  })
  await panel.screenshot({ path: join(output, 'phone-compose-file-link.png'), animations: 'disabled' })
  const to = compose.getByRole('combobox', { name: 'To', exact: true })
  await to.fill(sender)
  await to.press('Enter')
  await compose.getByLabel('Subject', { exact: true }).fill(subject)
  await compose.getByLabel('Message body').fill('Here are the proofs for the workshop.')
  await button(panel, 'Upload and insert link').click()
  await compose.getByText('File link inserted.', { exact: true }).waitFor()
  const draftText = await compose.getByLabel('Message body').inputValue()
  assert(draftText.includes(filename))
  const href = draftText.split('\n').find(line => line.startsWith(url + '/file-link#token='))
  assert.match(new URL(href).hash, /^#token=[a-f0-9]{64}$/)
  assert.equal(await compose.locator('.wm-compose-attachments li').count(), 0)
  await compose.getByLabel('Undo Send delay').selectOption('0')
  await button(compose, 'Send').click()
  await compose.waitFor({ state: 'hidden' })

  const recipient = await signIn({ account: sender, initialSubject: subject })
  try {
    await button(recipient, new RegExp(subject)).click()
    await heading(recipient, subject).waitFor()
    const delivered = recipient.getByRole('link', { name: 'Open shared file', exact: true })
    await delivered.waitFor()
    assert.equal(await delivered.getAttribute('href'), href)
    assert.equal(await recipient.getByRole('link', { name: filename, exact: true }).count(), 0)
  }
  finally { await recipient.context().close() }

  const unauthenticated = await browser.newContext({ viewport: { width: 320, height: 844 }, colorScheme: 'dark', ignoreHTTPSErrors: true })
  try {
    const viewer = await unauthenticated.newPage()
    viewer.setDefaultTimeout(12_000)
    observePage(viewer)
    await viewer.goto(href)
    await heading(viewer, filename).waitFor()
    await fitsViewport(viewer)
    await screenshot(viewer, 'phone-file-link-viewer')
    const [download] = await Promise.all([viewer.waitForEvent('download'), button(viewer, 'Download file').click()])
    // Linux WebKit sanitizes spaces in download names. The API suite checks
    // the exact server header, while this journey verifies the saved bytes.
    const suggested = download.suggestedFilename()
    assert(suggested === filename || (engine === 'webkit' && process.platform === 'linux' && suggested === 'Workshop_proofs.bin'))
    assert.deepEqual(await readFile(await download.path()), contents)
    assert.deepEqual(await unauthenticated.cookies(), [])

    await button(desktop, 'Account').click()
    const settings = desktop.getByRole('dialog', { name: 'Account settings' })
    await button(settings, 'Manage file links').click()
    await button(settings, `Revoke file link for ${filename}`).click()
    await button(settings.getByRole('group', { name: 'Confirm file link revocation' }), 'Revoke file link').click()
    await settings.getByText('File link revoked.', { exact: true }).waitFor()
    await viewer.reload()
    await viewer.getByText(/This file link is unavailable/).waitFor()
    assert.equal(await button(viewer, 'Download file').count(), 0)
    await button(settings, 'Close').click()
  }
  finally { await unauthenticated.close() }
  await phone.setViewportSize({ width: 390, height: 844 })
}

async function replyBatchJourney(desktop, phone) {
  const subjects = ['Studio launch notes', 'November research interviews']
  async function selectReplies(page, height) {
    await page.goto(url + '/')
    await button(page, 'Select').click()
    for (const subject of subjects) {
      await page.getByRole('checkbox', { name: 'Select conversation: ' + subject, exact: true }).check()
    }
    const actions = page.getByLabel('Selected message actions')
    await verifyControlRow(actions, 'button, select', height, false)
    await verifyControlRow(actions.getByRole('group', { name: 'Move selected messages' }), 'select, button', height)
    await verifyControlRow(page.locator('.wm-list-options'), '.wm-list-toggle, .wm-selection-mode', height)
    await screenshot(page, height === 44 ? 'phone-batch-selection-dark' : 'desktop-batch-selection-light')
    await button(actions, 'Reply separately').click()
    const dialog = page.getByRole('dialog', { name: 'Reply separately' })
    const replies = dialog.getByRole('list', { name: 'Replies to send' })
    await replies.getByText('Re: ' + subjects[0], { exact: true }).waitFor()
    assert.equal(await replies.getByRole('listitem').count(), 2)
    for (const subject of subjects) {
      const row = replies.getByRole('listitem').filter({ hasText: 'Re: ' + subject })
      await row.getByText('To: ' + sender, { exact: true }).waitFor()
    }
    const from = dialog.locator('.wm-reply-sender')
    await from.getByText('From your account', { exact: true }).waitFor()
    await from.getByText(owner, { exact: true }).waitFor()
    await verifyControlRow(dialog.locator('.wm-reply-batch'), 'header button, form button', height, false)
    await fitsViewport(page)
    return dialog
  }

  await phone.setViewportSize({ width: 320, height: 844 })
  const mobile = await selectReplies(phone, 44)
  await mobile.getByLabel('Reply text').fill('Thanks for the update. I will review both items this afternoon.')
  await mobile.locator('.wm-reply-batch').screenshot({ path: join(output, 'phone-reply-batch-dark.png'), animations: 'disabled' })
  await button(mobile, 'Close').click()
  await mobile.waitFor({ state: 'hidden' })
  await phone.setViewportSize({ width: 390, height: 844 })

  const dialog = await selectReplies(desktop, 36)
  await dialog.getByLabel('Reply text').fill('Thanks for the update. I will be in touch this afternoon.')
  await dialog.locator('.wm-reply-batch').screenshot({ path: join(output, 'desktop-reply-batch-light.png'), animations: 'disabled' })
  const endpoint = url + '/webmail/api/reply-batches'
  let receipt
  await desktop.route(endpoint, async (route) => {
    const response = await route.fetch()
    receipt = await response.json()
    await route.abort()
  }, { times: 1 })
  await button(dialog, 'Queue 2 replies').click()
  await dialog.getByRole('alert').getByText(/server did not confirm/).waitFor()
  assert.equal(receipt?.sends?.length, 2)
  await button(dialog, 'Check batch status').click()
  await dialog.getByText('2 separate replies queued.', { exact: true }).waitFor()
  await button(dialog, 'View Outbox').click()
  await dialog.waitFor({ state: 'hidden' })
  for (const id of receipt.sends) {
    const response = await desktop.request.get(url + '/webmail/api/outbox/' + id)
    assert(response.ok())
    const item = await response.json()
    assert.deepEqual(item.message.to, [sender])
    assert(subjects.some(subject => item.message.subject === 'Re: ' + subject))
  }
}

async function combinedInboxJourney(page) {
  await page.goto(url + '/')
  await page.getByRole('link', { name: 'Combined inbox', exact: true }).click()
  await heading(page, 'Combined inbox').waitFor()
  await button(page, 'Linked accounts').click()
  const settings = page.getByRole('region', { name: 'Linked accounts' })
  await button(settings, 'Link a mailbox').click()
  await settings.getByLabel('Mailbox username').fill(sender)
  await settings.getByLabel('Mailbox password').fill(password)
  await verifyControlRow(settings.locator('form'), 'input, button', 36)
  await button(settings, 'Verify and link').click()
  await button(settings, 'Remove ' + sender).waitFor()
  await screenshot(page, 'desktop-combined-linked-accounts')
  await button(page, 'Linked accounts').click()
  const source = page.getByRole('link', { name: 'Open Combined source briefing in ' + sender, exact: true })
  await source.waitFor()
  await page.getByRole('checkbox', { name: 'Select Tuesday design handoff in ' + owner, exact: true }).check()
  await page.getByRole('checkbox', { name: 'Select Combined source briefing in ' + sender, exact: true }).check()
  await button(page.getByRole('group', { name: 'Selected messages' }), 'Mark read').click()
  await page.getByText('2 messages updated.', { exact: true }).waitFor()
  await page.getByRole('searchbox', { name: 'Search mail' }).fill('Combined source briefing')
  await button(page.getByRole('search'), 'Search').click()
  await source.waitFor()
  await page.getByRole('link', { name: 'Open Tuesday design handoff in ' + owner, exact: true }).waitFor({ state: 'hidden' })
  await verifyControlRow(page.getByRole('search'), 'input, select, button', 36)
  await screenshot(page, 'desktop-combined-inbox')

  await page.setViewportSize({ width: 320, height: 844 })
  await page.emulateMedia({ colorScheme: 'dark' })
  const searchControls = await verifyControlRow(page.getByRole('search'), 'input, select, button', 44, false)
  assert(Math.abs(searchControls[1].top - searchControls[2].top) < 0.5, 'Search in and Search align on narrow phones')
  await fitsViewport(page)
  await screenshot(page, 'phone-combined-inbox')
  await page.setViewportSize({ width: 1440, height: 940 })
  await page.emulateMedia({ colorScheme: 'light' })

  const reader = await page.context().newPage()
  reader.setDefaultTimeout(12_000)
  observePage(reader)
  try {
    const href = await source.getAttribute('href')
    const scoped = new URL(href, url)
    assert.equal(scoped.searchParams.get('account'), sender)
    assert.match(scoped.searchParams.get('linked'), /^[a-f0-9]{32}$/)
    await reader.goto(scoped.href)
    await heading(reader, 'Combined source briefing').waitFor()
    await reader.locator('.wm-linked-banner').getByText(sender, { exact: true }).waitFor()
    await button(reader, 'Reply').click()
    const composer = reader.getByRole('dialog', { name: 'Compose message' })
    assert.equal(await composer.getByLabel('From', { exact: true }).locator('option:checked').innerText(), sender)
    await composer.locator('.wm-recipient-chip').getByRole('button', { name: 'Remove recipient ' + owner, exact: true }).waitFor()
    await composer.getByLabel('Message body').fill('Here are the notes from the linked mailbox.')
    await screenshot(reader, 'desktop-combined-source-reply')
    await composer.getByLabel('Undo Send delay', { exact: true }).selectOption('0')
    const acknowledgement = reader.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/webmail/api/compose')
    await button(composer, 'Send').click()
    const queued = await acknowledgement
    assert(queued.ok())
    assert.equal(new URL(queued.url()).searchParams.get('linked'), scoped.searchParams.get('linked'))
    assert.deepEqual((await queued.json()).message.to, [owner])
    await composer.waitFor({ state: 'hidden' })

    await button(page, 'Linked accounts').click()
    const captured = Promise.withResolvers()
    const release = Promise.withResolvers()
    await page.route(/\/webmail\/api\/combined\/messages\?/, async (route) => {
      const response = await route.fetch()
      captured.resolve(await response.json())
      await release.promise
      await route.fulfill({ response }).catch(() => {})
    }, { times: 1 })
    try {
      await button(page.getByRole('search'), 'Search').click()
      const stale = await captured.promise
      assert(stale.items.some(row => row.source.username === sender), 'The pre-revocation search contains linked results')
      await button(settings, 'Remove ' + sender).click()
      await page.getByText('Mailbox removed from this browser.', { exact: true }).waitFor()
      release.resolve()
      await source.waitFor({ state: 'hidden' })
      await reader.getByText('The linked mailbox is no longer available.', { exact: true }).waitFor()
      await heading(reader, 'Combined source briefing').waitFor({ state: 'hidden' })
    }
    finally { release.resolve() }

    const combinedList = /\/webmail\/api\/combined\/messages\?/
    await page.route(combinedList, route => route.fulfill({
      status: 403, json: { error: 'linked_account_unavailable', message: 'The linked mailbox changed.' },
    }), { times: 1 })
    const fresh = page.waitForResponse(response => combinedList.test(response.url()) && response.ok())
    await button(page.getByRole('search'), 'Search').click()
    await fresh
    assert.equal(new URL(page.url()).pathname, '/combined', 'A revoked source does not end the signed-in account session')
  }
  finally { await reader.close() }
}

async function freeTimeJourney(page, phone = false) {
  await page.goto(`${url}/calendar?day=${day}`)
  await button(page, 'Find free time').click()
  const panel = page.getByRole('region', { name: 'Find free time' })
  await page.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'freeTimeDateField')
  if (phone) await page.setViewportSize({ width: 320, height: 844 })
  await verifyControlRow(panel.locator('form'), 'input, select, button', phone ? 44 : 36, !phone)
  const check = button(panel, 'Check availability')
  const slots = panel.getByRole('list', { name: 'Open windows' })
  await check.click()
  await panel.getByRole('status').filter({ hasText: '3 open windows' }).waitFor()
  const displayed = await slots.evaluate(list => Array.from(list.querySelectorAll('li'), item => ({
    time: item.querySelector('span').textContent.replace(/\s+/g, ' ').trim(),
    duration: item.querySelector('small').textContent.replace(/\s+/g, ' ').trim(),
  })))
  assert.deepEqual(displayed, [
    { time: '9:00 AM – 11:00 AM', duration: '120 min' },
    { time: '12:00 PM – 2:00 PM', duration: '120 min' },
    { time: '3:00 PM – 5:00 PM', duration: '120 min' },
  ])
  await fitsViewport(page)
  await page.mouse.move(0, 0)
  await panel.screenshot({ path: join(output, phone ? 'phone-calendar-free-time.png' : 'desktop-calendar-free-time.png'), animations: 'disabled' })
  await panel.getByLabel('From', { exact: true }).fill('10:40')
  await panel.getByLabel('To', { exact: true }).fill('15:30')
  await panel.getByLabel('Minimum duration').selectOption('120')
  assert.equal(await slots.count(), 0, 'Changing the search window clears stale availability')
  await check.click()
  await panel.getByRole('status').filter({ hasText: '1 open window' }).waitFor()
  await slots.getByText('12:00 PM – 2:00 PM', { exact: true }).waitFor()

  const calculation = /\/webmail\/api\/calendar-free-busy\?/
  await page.route(calculation, route => route.fulfill({
    status: 422, json: { error: 'availability_incomplete', message: 'Some busy times could not be calculated' },
  }), { times: 1 })
  await check.click()
  await panel.getByRole('alert').filter({ hasText: 'Some busy times could not be calculated' }).waitFor()
  assert.equal(await slots.count(), 0, 'Incomplete calculations show no open times')
  if (phone) await page.setViewportSize({ width: 390, height: 844 })
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
  const privateDayLabel = 'Planning note for the owner'
  const dayLabelResponse = await captain.request.put(`${url}/webmail/api/calendar-day-labels/${day}`, {
    headers: { Origin: url },
    data: { label: privateDayLabel, revision: 0 },
  })
  assert.equal(dayLabelResponse.status(), 200, await dayLabelResponse.text())
  const privateTask = 'Private planning task for the owner'
  const taskResponse = await captain.request.post(`${url}/webmail/api/calendar-tasks`, {
    headers: { Origin: url },
    data: { title: privateTask, day, completed: false, revision: 0 },
  })
  assert.equal(taskResponse.status(), 201, await taskResponse.text())
  const exportPath = await captain.getByRole('link', { name: 'Download .ics' }).getAttribute('href')
  const exported = await captain.request.get(url + exportPath)
  assert.equal(exported.status(), 200)
  const calendarData = await exported.text()
  assert(!calendarData.includes(privateDayLabel), 'Calendar export omits personal day labels')
  assert(!calendarData.includes(privateTask), 'Calendar export omits personal tasks')
  const sharing = captain.getByRole('region', { name: 'Share a calendar' })
  await sharing.getByLabel('Calendar to share').selectOption({ label: calendarLabel })
  await sharing.getByRole('combobox', { name: /^Team\b/ }).selectOption({ label: 'Studio' })
  await sharing.getByLabel('Teammate').fill(sender)
  await sharing.getByRole('combobox', { name: /^Access\b/ }).selectOption('viewer')
  await heading(captain, 'Share a calendar').click()
  await captain.locator('.calendar-loading').waitFor({ state: 'hidden' })
  await verifyControlRow(captain.locator('.calendar-create-form'), 'input, button', 36)
  const shareForm = sharing.locator('form')
  const shareControls = await verifyControlRow(shareForm, 'select, input, button', 36)
  assert.equal(shareControls.length, 5)
  verifyControlGaps(shareControls, 12)
  await captain.emulateMedia({ colorScheme: 'dark' })
  verifyControlGaps(await verifyControlRow(shareForm, 'select, input, button', 36), 12)
  await shareForm.screenshot({ path: join(output, 'desktop-calendar-sharing-dark.png'), animations: 'disabled' })
  await screenshot(captain, 'desktop-calendar-selects-dark')
  await captain.setViewportSize({ width: 861, height: 940 })
  await fitsViewport(captain)
  await verifyControlRow(shareForm, 'select, input, button', 36, false)
  await verifySelectedOptionFits(sharing.getByLabel('Calendar to share'))
  await shareForm.screenshot({ path: join(output, 'tablet-calendar-sharing-dark.png'), animations: 'disabled' })
  await captain.setViewportSize({ width: 1440, height: 940 })
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
  await button(teammate, 'Tasks').click()
  const teammateTasks = teammate.getByRole('region', { name: 'Personal tasks' })
  await teammateTasks.getByText('No open tasks.').waitFor()
  const sharedCalendar = button(teammate, /^Design & Research.*View events/)
  await sharedCalendar.click()
  const privateTitle = teammate.getByText('Private budget check', { exact: true })
  const publicEvent = button(teammate, /Studio review/)
  await publicEvent.waitFor()
  assert.equal(await privateTitle.count(), 0)
  assert.equal(await teammateTasks.count(), 0)
  assert.equal(await button(teammate, 'Tasks').count(), 0)
  assert.equal(await button(teammate, 'Personal tools').count(), 0)
  const peerTasks = await teammate.request.get(`${url}/webmail/api/calendar-tasks`)
  assert.deepEqual(await peerTasks.json(), { tasks: [] }, 'Sharing a calendar never shares its owner’s personal tasks')
  assert.equal(await button(teammate, 'New event').count(), 0)
  assert.equal(await teammate.getByText(privateDayLabel, { exact: true }).count(), 0)
  assert.equal(await teammate.getByRole('region', { name: 'Day label', exact: true }).count(), 0)
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
  assert.equal(await teammate.getByRole('region', { name: 'Day label', exact: true }).count(), 0)
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
  await button(teammate, 'Year').click()
  const sharedYear = teammate.getByRole('region', { name: 'Year overview' })
  const busyDay = sharedYear.locator(`[data-date="${day}"]`)
  await sharedYear.getByRole('button', { name: /, busy$/ }).first().waitFor()
  assert.match(await busyDay.getAttribute('aria-label'), /, busy$/)
  assert(!(await busyDay.getAttribute('aria-label')).includes(privateDayLabel))
  assert.equal(await sharedYear.getByRole('button', { name: /\d events?$/ }).count(), 0)
  assert.equal(await privateTitle.count(), 0)
  await fitsViewport(teammate)
  await busyDay.click()
  await busy.waitFor()

  const ownCalendar = await teammate.request.post(url + '/webmail/api/calendars', {
    headers: { Origin: url },
    data: { name: 'My planning' },
  })
  assert.equal(ownCalendar.status(), 201)
  const { id: ownCalendarId } = await ownCalendar.json()
  const personalEvent = await teammate.request.post(url + '/webmail/api/calendar-events', {
    headers: { Origin: url },
    data: {
      calendarId: ownCalendarId, summary: 'My own appointment',
      time: { start: Date.parse(day + 'T12:30:00Z') / 1000, end: Date.parse(day + 'T13:00:00Z') / 1000 },
    },
  })
  assert.equal(personalEvent.status(), 201, await personalEvent.text())
  await button(teammate, 'Day').click()
  await button(teammate, 'My planning').waitFor()
  await busy.waitFor()
  await button(teammate, 'Find free time').click()
  const availability = teammate.getByRole('region', { name: 'Find free time' })
  const include = availability.getByRole('checkbox', { name: 'Include my calendars' })
  assert(await include.isChecked())
  const check = button(availability, 'Check availability')
  await check.click()
  await availability.getByRole('status').filter({ hasText: '4 open windows' }).waitFor()
  await include.uncheck()
  await check.click()
  await availability.getByRole('status').filter({ hasText: '3 open windows' }).waitFor()
  const slots = availability.getByRole('list', { name: 'Open windows' })
  await slots.getByText('12:00 PM – 2:00 PM', { exact: true }).waitFor()
  assert.equal(await availability.getByText('Private budget check', { exact: true }).count(), 0)

  await screenshot(captain, 'desktop-calendar-sharing')
  await button(sharing, `Revoke access for ${sender} to ${calendarLabel}`).click()
  await role.waitFor({ state: 'hidden' })
  await checkAccess()
  await teammate.getByText('You no longer have access to this shared calendar.', { exact: true }).waitFor()
  await busy.waitFor({ state: 'hidden' })
  await slots.waitFor({ state: 'hidden' })
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

async function yearCalendarJourney(desktop, phone) {
  const leapDay = '2028-02-29'
  const calendarUrl = `${url}/calendar?day=${leapDay}`
  await desktop.goto(calendarUrl)
  const listing = await desktop.request.get(url + '/webmail/api/calendars')
  assert.equal(listing.status(), 200)
  const { calendars } = await listing.json()
  const calendar = calendars.find(item => item.display_name === calendarLabel)
  assert(calendar, 'The browser fixture calendar must exist')

  async function createEvent(uid, fields) {
    const icalendar = [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Mail browser fixture//EN', 'BEGIN:VEVENT',
      `UID:${uid}@mail.example`, 'DTSTAMP:20261122T100000Z', ...fields, 'END:VEVENT', 'END:VCALENDAR', '',
    ].join('\r\n')
    const response = await desktop.request.post(`${url}/webmail/api/calendar-events?calendarId=${calendar.id}`, {
      headers: { Origin: url, 'Content-Type': 'text/calendar' },
      data: icalendar,
    })
    assert.equal(response.status(), 201, await response.text())
  }

  await createEvent('leap-day', ['DTSTART;VALUE=DATE:20280229', 'DTEND;VALUE=DATE:20280301', 'SUMMARY:Leap day'])
  await createEvent('quarter-handoff', ['DTSTART:20280401T003000Z', 'DURATION:PT1H', 'SUMMARY:Quarter handoff'])
  await createEvent('weekly-planning', ['DTSTART:20280325T120000Z', 'DURATION:PT1H', 'RRULE:FREQ=WEEKLY;COUNT=3', 'SUMMARY:Weekly planning'])

  await button(desktop, 'Year').click()
  const year = desktop.getByRole('region', { name: 'Year overview' })
  const leap = year.locator(`[data-date="${leapDay}"]`)
  await year.getByRole('button', { name: /February 29, 2028, 1 event$/ }).waitFor()
  assert.equal(await year.getByRole('heading', { level: 3 }).count(), 12)
  assert.equal(await year.locator('[data-date]').count(), 366)
  assert.equal(await year.locator('[tabindex="0"]').count(), 1)
  assert.equal(await year.locator('.calendar-year').evaluate(grid => getComputedStyle(grid).gridTemplateColumns.split(' ').length), 4)
  assert.equal(await leap.getAttribute('tabindex'), '0')
  const april = year.locator('[data-date="2028-04-01"]')
  const march = year.locator('[data-date="2028-03-31"]')
  assert.match(await april.getAttribute('aria-label'), /, 2 events$/)
  await desktop.getByRole('combobox', { name: 'Display time zone' }).selectOption('America/New_York')
  await year.getByRole('button', { name: /March 31, 2028, 1 event$/ }).waitFor()
  assert.match(await april.getAttribute('aria-label'), /, 1 event$/)
  assert.match(await march.getAttribute('aria-label'), /, 1 event$/)
  assert.match(await leap.getAttribute('aria-label'), /, 1 event$/)
  await fitsViewport(desktop)
  await desktop.getByRole('region', { name: 'Calendar workspace' })
    .screenshot({ path: join(output, 'desktop-calendar-year.png'), animations: 'disabled' })

  await leap.press('ArrowRight')
  const marchFirst = year.locator('[data-date="2028-03-01"]')
  assert(await marchFirst.evaluate(node => document.activeElement === node), 'Arrow navigation moves focus to the next date')
  assert.equal(await year.locator('[tabindex="0"]').count(), 1)
  await marchFirst.press('ArrowLeft')
  await leap.press('Enter')
  await heading(desktop, 'Tuesday, February 29, 2028').waitFor()
  await desktop.waitForFunction(() => document.activeElement?.id === 'calendar-range')
  await button(desktop, /Leap day/).waitFor()
  const progress = desktop.locator('.calendar-loading')
  await progress.waitFor({ state: 'hidden' })
  const nextPeriod = button(desktop, 'Next period')
  const before = await nextPeriod.boundingBox()
  const holdRefresh = Promise.withResolvers()
  await desktop.route(`${url}/webmail/api/calendars`, async (route) => {
    await holdRefresh.promise
    await route.continue().catch(() => {}) // The next period supersedes this request.
  }, { times: 1 })
  try {
    await button(desktop, 'Year').click()
    await progress.waitFor()
    const during = await nextPeriod.boundingBox()
    assert.equal(during.y, before.y, 'Calendar refresh keeps the navigation controls in place')
    await nextPeriod.click()
  }
  finally { holdRefresh.resolve() }
  await heading(desktop, '2029').waitFor()
  assert.equal(await year.locator('[data-date]').count(), 365)
  assert.equal(await desktop.getByLabel('Jump to date', { exact: true }).inputValue(), '2029-02-28')

  await phone.goto(calendarUrl)
  await button(phone, 'Year').click()
  const phoneYear = phone.getByRole('region', { name: 'Year overview' })
  await phoneYear.getByRole('button', { name: /February 29, 2028, 1 event$/ }).waitFor()
  await phone.setViewportSize({ width: 320, height: 844 })
  await fitsViewport(phone)
  const february = phoneYear.getByRole('region', { name: 'February', exact: true })
  assert((await february.locator(`[data-date="${leapDay}"]`).boundingBox()).height >= 44)
  await phone.mouse.move(0, 0)
  await february.screenshot({ path: join(output, 'phone-calendar-year.png'), animations: 'disabled' })
  await phone.setViewportSize({ width: 390, height: 844 })
}

async function dayLabelJourney(desktop, phone) {
  const date = '2028-03-01'
  const calendarUrl = `${url}/calendar?day=${date}`
  const label = 'Travel <desk>'
  await desktop.goto(calendarUrl)
  const panel = desktop.getByRole('region', { name: 'Day label', exact: true })
  const field = panel.getByRole('textbox', { name: 'Day label' })
  await button(panel, 'Add day label').click()
  await desktop.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'labelField')
  await field.fill(label)
  await button(panel, 'Save label').click()
  await panel.getByText(label, { exact: true }).waitFor()
  assert.equal(await panel.locator('desk').count(), 0, 'Day labels render as plain text')
  await screenshot(desktop, 'desktop-calendar-day-label')

  await button(desktop, 'Agenda').click()
  await desktop.getByText(label, { exact: true }).waitFor()
  await button(desktop, 'Month').click()
  await desktop.getByRole('button', { name: /Mar 1, Travel <desk>$/ }).waitFor()
  await button(desktop, 'Year').click()
  const dateCell = desktop.locator(`[data-date="${date}"]`)
  await desktop.getByRole('button', { name: /March 1, 2028, Travel <desk>$/ }).waitFor()
  await dateCell.click()
  await panel.getByText(label, { exact: true }).waitFor()
  await button(panel, 'Edit day label').click()
  await field.fill('Uncommitted edit')

  await phone.goto(calendarUrl)
  const phonePanel = phone.getByRole('region', { name: 'Day label', exact: true })
  await phone.getByRole('combobox', { name: 'Display time zone' }).selectOption('America/New_York')
  await button(phonePanel, 'Edit day label').click()
  const phoneField = phonePanel.getByRole('textbox', { name: 'Day label' })
  assert.equal(await phoneField.inputValue(), label)
  await phoneField.fill('Remote work')
  await fitsViewport(phone)
  await screenshot(phone, 'phone-calendar-day-label')
  await button(phonePanel, 'Save label').click()
  await phonePanel.getByText('Remote work', { exact: true }).waitFor()

  await button(panel, 'Save label').click()
  await panel.getByRole('alert').filter({ hasText: /changed in another window/ }).waitFor()
  assert.equal(await field.inputValue(), 'Uncommitted edit')
  await button(panel, 'Load latest label').click()
  await panel.getByText('Remote work', { exact: true }).waitFor()
  await button(panel, 'Edit day label').click()
  await button(panel, 'Remove label').click()
  await button(panel, 'Add day label').waitFor()
  await phone.reload()
  await button(phonePanel, 'Add day label').waitFor()
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

async function senderInvitationJourney(desktop, phone) {
  const enabled = await desktop.request.put(url + '/webmail/api/sender-review', {
    headers: { Origin: url }, data: { setting: 'enable' },
  })
  assert.equal(enabled.status(), 200)
  await desktop.goto(url + '/')
  await button(folders(desktop), 'Sender Review').click()
  const desktopReview = desktop.getByRole('region', { name: 'Sender Review' })
  await button(desktopReview, 'Invitations').click()
  const form = desktopReview.locator('form')
  await form.getByLabel('Sender email').fill(sender)
  await form.getByLabel('Allow for').selectOption('3600')
  const controls = await verifyControlRow(form, 'input, select, button', 36, false)
  assert(Math.abs(controls[1].bottom - controls[2].bottom) < 0.5, 'The invitation duration and action align')
  await button(form, 'Allow temporarily').click()
  await desktopReview.getByText('Invitation added.', { exact: true }).waitFor()
  const revokeLabel = `Revoke invitation for ${sender}`
  await button(desktopReview, revokeLabel).waitFor()
  assert(!await desktop.getByRole('region', { name: 'Message reader' }).isVisible(), 'Invitations use the workspace without a message reader')
  assert((await desktopReview.boundingBox()).width >= 600, 'Invitations use the expanded desktop workspace')
  await screenshot(desktop, 'desktop-sender-invitation')

  await phone.setViewportSize({ width: 320, height: 844 })
  await phone.goto(url + '/')
  await drawer(phone).click()
  await button(folders(phone), 'Sender Review').click()
  const phoneReview = phone.getByRole('region', { name: 'Sender Review' })
  await button(phoneReview, 'Invitations').click()
  const revoke = button(phoneReview, revokeLabel)
  await revoke.waitFor()
  await verifyControlRow(phoneReview.locator('form'), 'input, select, button', 44, false)
  await fitsViewport(phone)
  await screenshot(phone, 'phone-sender-invitation')
  await revoke.click()
  await phoneReview.getByText('Invitation revoked.', { exact: true }).waitFor()
  await phoneReview.getByText('No active invitations.', { exact: true }).waitFor()
  await button(desktopReview, 'Refresh').click()
  await desktopReview.getByText('No active invitations.', { exact: true }).waitFor()
}

async function forwardingFilterJourney(desktop, phone) {
  const peer = await signIn({ account: sender, initialSubject: 'Combined source briefing' })
  await desktop.goto(url + '/')
  await button(desktop, 'Account').click()
  const forwarding = desktop.getByRole('region', { name: 'Forwarding', exact: true })
  await forwarding.getByLabel('Destination email').fill(sender)
  await forwarding.getByLabel('Current password', { exact: true }).fill(password)
  await button(forwarding, 'Send verification code').click()
  await forwarding.getByLabel('Verification code').waitFor()
  const lookup = '/webmail/api/messages?folder=INBOX&conversations=false&q=Confirm+mail+forwarding'
  const verification = await peer.waitForFunction(async (path) => {
    const response = await fetch(path)
    if (!response.ok) return false
    const { items } = await response.json()
    return items.find(item => item.subject === 'Confirm mail forwarding')?.reference || false
  }, lookup, { polling: 300 })
  const reference = await verification.jsonValue()
  const message = await peer.request.get(url + '/webmail/api/messages/ref/' + reference)
  assert.equal(message.status(), 200)
  const code = (await message.json()).text.split(/\r?\n/).find(line => /^[a-f0-9]{32}$/.test(line))
  assert(code, 'The destination mailbox received a forwarding verification code')
  await forwarding.getByLabel('Messages to forward').selectOption('matching')
  await forwarding.getByLabel('Verification code').fill(code)
  await button(forwarding, 'Confirm forwarding').click()
  await forwarding.getByRole('alert').filter({ hasText: 'Enter a sender or a delivered-to address.' }).waitFor()
  await forwarding.getByLabel('Verified sender').fill(newcomer)
  await forwarding.getByLabel('Delivered to').fill(owner)
  await button(forwarding, 'Confirm forwarding').click()
  await forwarding.getByText('Forwarding is on.', { exact: true }).waitFor()
  const endpoint = url + '/webmail/api/forwarding'
  const verified = await desktop.request.get(endpoint)
  assert.equal(verified.status(), 200)
  const active = await verified.json()
  assert.equal(active.address, sender)
  assert.deepEqual(active.scope, { sender: newcomer, recipient: owner })
  await forwarding.screenshot({ path: join(output, 'desktop-filtered-forwarding.png'), animations: 'disabled' })

  await phone.setViewportSize({ width: 320, height: 844 })
  await phone.goto(url + '/')
  await drawer(phone).click()
  await button(phone, 'Account').click()
  const mobile = phone.getByRole('region', { name: 'Forwarding', exact: true })
  const mode = mobile.getByLabel('Messages to forward')
  await verifySelect(mode, 44)
  assert.equal(await mode.inputValue(), 'matching')
  assert.equal(await mobile.getByLabel('Verified sender').inputValue(), newcomer)
  await mobile.getByLabel('Verified sender').fill('')
  await mobile.getByLabel('Current password for filters').fill(password)
  await fitsViewport(phone)
  await button(mobile, 'Save forwarding filters').click()
  await mobile.getByText('Forwarding filters saved.', { exact: true }).waitFor()
  const updated = await desktop.request.get(endpoint)
  assert.deepEqual((await updated.json()).scope, { sender: null, recipient: owner })
  await mobile.locator('.wm-forwarding-confirm').screenshot({ path: join(output, 'phone-filtered-forwarding.png'), animations: 'disabled' })
}

try {
  const desktop = await signIn()
  await desktopJourney(desktop)
  const phone = await signIn({ phone: true })
  await phoneJourney(phone)
  await invitationJourney(desktop)
  await invitationJourney(phone, true)
  await freeTimeJourney(desktop)
  await freeTimeJourney(phone, true)
  await calendarSharingJourney(desktop)
  await mailEventJourney(desktop)
  const firstRun = await signIn({ phone: true, account: newcomer, initialSubject: 'Studio launch notes' })
  await mailEventJourney(firstRun, { phone: true, firstCalendar: true })
  await invitationRangeJourney(desktop, phone)
  await yearCalendarJourney(desktop, phone)
  await dayLabelJourney(desktop, phone)
  await calendarTasksJourney(desktop)
  await calendarTasksJourney(phone, true)
  await calendarToolsJourney(desktop, phone)
  await snapshotSharingJourney(desktop, phone)
  await fileLinkJourney(desktop, phone)
  await replyBatchJourney(desktop, phone)
  await combinedInboxJourney(desktop)
  await navigationRequestsJourney(desktop)
  await senderInvitationJourney(desktop, phone)
  await forwardingFilterJourney(desktop, phone)
  assert.deepEqual(errors, [], 'Browser pages raised uncaught errors')
  process.stdout.write(`${engine} passed the desktop and phone webmail journeys.\n`)
}
catch (error) {
  if (errors.length) process.stderr.write(`Uncaught browser errors:\n${errors.join('\n')}\n`)
  if (diagnostics.length) process.stderr.write(`Browser diagnostics:\n${diagnostics.slice(-20).join('\n')}\n`)
  for (const [contextIndex, context] of browser.contexts().entries()) {
    for (const [index, page] of context.pages().entries()) {
      const appearance = (page.viewportSize()?.width ?? 0) <= 860 ? 'phone' : 'desktop'
      await screenshot(page, `failure-${appearance}-${contextIndex}-${index}`).catch(() => {})
    }
  }
  throw error
}
finally {
  await browser.close()
}
