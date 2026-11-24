import assert from 'node:assert/strict'
import { readFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import axe from 'axe-core'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_READING_URL: url, MAIL_READING_DESKTOP: desktop, MAIL_READING_PHONE: phone,
  MAIL_READING_PASSWORD: password, MAIL_READING_REFERENCES: references } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
const subjects = ['Studio design notes', 'Print proof updates', 'Pickup details']
const button = (scope, name) => scope.getByRole('button', { name, exact: typeof name === 'string' })
const viewIn = page => page.getByRole('region', { name: 'Read together', exact: true })
const cardIn = (page, name) => viewIn(page).getByRole('article', { name, exact: true })
const controlsIn = page => viewIn(page).getByRole('navigation', { name: 'Reading controls', exact: true })
const messageURL = reference => `${url}/webmail/api/messages/ref/${reference}`
const image = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==', 'base64')

async function signIn(browser, account, small) {
  const context = await browser.newContext({
    viewport: small ? { width: 320, height: 844 } : { width: 1440, height: 940 },
    colorScheme: small ? 'dark' : 'light', hasTouch: small, isMobile: small && engine !== 'firefox',
    deviceScaleFactor: small ? 2 : 1, ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC',
  })
  const page = await context.newPage()
  page.setDefaultTimeout(12_000)
  await page.goto(`${url}/login`)
  await page.getByLabel('Email or username').fill(account)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await button(page, 'Sign in').click()
  await page.waitForURL(`${url}/`)
  await button(page, /Studio design notes/).waitFor()
  const onboard = button(page, 'Continue to inbox')
  if (await onboard.isVisible()) {
    await onboard.click()
    await onboard.waitFor({ state: 'hidden' })
    await button(page, /Studio design notes/).waitFor()
  }
  return page
}

async function capture(page, name) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await page.screenshot({ path: join(output, `${name}.png`), animations: 'disabled' })
}

async function mailboxMessage(page, reference) {
  const response = await page.request.get(messageURL(reference))
  assert.equal(response.status(), 200)
  return response.json()
}

async function attachment(page, card, subject, reference) {
  const link = card.getByRole('link', { name: /^proof.txt/ })
  const href = new URL(await link.getAttribute('href'), url)
  assert.equal(href.searchParams.get('reference'), reference)
  assert(href.searchParams.has('content_revision') || href.searchParams.has('revision'))
  const response = await page.request.get(href.href)
  const text = await response.text()
  assert.equal(response.status(), 200, `${href.search}: ${text}`)
  assert.equal(text, `Attachment for ${subject}\n`)
  if (engine === 'chromium') {
    const [file] = await Promise.all([page.waitForEvent('download'), link.click()])
    assert.equal(file.suggestedFilename(), 'proof.txt')
    assert.equal(await file.failure(), null)
    assert.equal(await readFile(await file.path(), 'utf8'), text)
  }
}

async function unreadJourney(page, refs, small) {
  const [firstSubject, secondSubject, thirdSubject] = subjects
  const details = []
  const remoteImages = []
  page.on('request', (request) => {
    if (request.method() === 'GET' && request.url().startsWith(`${url}/webmail/api/messages/ref/`)) details.push(request.url())
  })
  await page.route('https://reading-images.example.test/**', (route) => {
    remoteImages.push(new URL(route.request().url()).pathname)
    return route.fulfill({ status: 200, contentType: 'image/png', body: image })
  })

  const start = button(page, 'Read unread together')
  const opened = page.waitForResponse(response => response.request().method() === 'PUT' && response.url() === messageURL(refs[firstSubject]))
  if (small) await start.tap()
  else await start.press('Enter')
  const view = viewIn(page)
  const first = cardIn(page, firstSubject)
  const second = cardIn(page, secondSubject)
  const third = cardIn(page, thirdSubject)
  const secondFrame = second.frameLocator('iframe')
  assert.equal((await opened).status(), 200)
  await first.frameLocator('iframe').getByText(`Formatted notes for ${firstSubject}.`, { exact: true }).waitFor()
  assert.equal(await view.getByRole('article').count(), 12)
  if (small) {
    const back = button(view, 'Back to messages')
    const next = button(controlsIn(page), 'Read next')
    const pickerRows = await Promise.all([back.boundingBox(), next.boundingBox(),
      view.getByRole('heading', { name: 'Unread messages' }).boundingBox()])
    assert.equal(pickerRows[0].height, 44)
    assert.equal(pickerRows[1].height, 44)
    assert(Math.abs(pickerRows[0].y + pickerRows[0].height / 2 - pickerRows[2].y - pickerRows[2].height / 2) < 14, 'The title and back control share one row')
  }
  assert.deepEqual(details, [messageURL(refs[firstSubject])])
  assert.deepEqual(remoteImages, [])
  assert((await mailboxMessage(page, refs[firstSubject])).flags.seen)
  assert(!(await mailboxMessage(page, refs[secondSubject])).flags.seen)

  const openNext = page.waitForResponse(response => response.request().method() === 'PUT' && response.url() === messageURL(refs[secondSubject]))
  if (small) await button(controlsIn(page), 'Read next').tap()
  else await page.keyboard.press('Shift+J')
  assert.equal((await openNext).status(), 200)
  await secondFrame.getByText(`Formatted notes for ${secondSubject}.`, { exact: true }).waitFor()
  assert.equal(await first.locator('iframe').count(), 1)
  assert.deepEqual(details, [messageURL(refs[firstSubject]), messageURL(refs[secondSubject])])
  assert(!(await mailboxMessage(page, refs[thirdSubject])).flags.seen)

  await first.getByRole('button', { name: 'Load remote images' }).click()
  await first.frameLocator('iframe').getByText(`Formatted notes for ${firstSubject}.`).waitFor()
  await first.frameLocator('iframe').locator('img').waitFor({ state: 'attached' })
  await button(second, 'Load remote images').waitFor()
  assert(!(await second.locator('iframe').getAttribute('srcdoc')).includes('reading-images.example.test'))
  assert(remoteImages.includes('/0.png'))
  assert(!remoteImages.includes('/1.png'))
  await page.unroute('https://reading-images.example.test/**')

  await attachment(page, first, firstSubject, refs[firstSubject])
  await attachment(page, second, secondSubject, refs[secondSubject])

  const refresh = button(controlsIn(page), 'Refresh mailbox')
  await refresh.and(page.locator(':enabled')).waitFor()
  const refreshTarget = await refresh.evaluate((node) => {
    const box = node.getBoundingClientRect()
    const x = box.x + box.width / 2
    const y = box.y + box.height / 2
    return { x, y, reachable: node.contains(document.elementFromPoint(x, y)) }
  })
  assert(refreshTarget.reachable)
  const top = await second.getByRole('heading').evaluate(node => node.getBoundingClientRect().top)
  const refreshed = page.waitForResponse(response => new URL(response.url()).pathname === '/webmail/api/messages')
  if (small) await page.touchscreen.tap(refreshTarget.x, refreshTarget.y)
  else await page.mouse.click(refreshTarget.x, refreshTarget.y)
  assert.equal((await refreshed).status(), 200)
  await refresh.and(page.locator(':enabled')).waitFor()
  await secondFrame.getByText(`Formatted notes for ${secondSubject}.`).waitFor()
  const refreshedTop = await second.getByRole('heading').evaluate(node => node.getBoundingClientRect().top)
  assert(Math.abs(refreshedTop - top) <= 1, `Refresh moved the card from ${top}px to ${refreshedTop}px`)
  await first.getByRole('button', { name: 'Block remote images' }).waitFor()
  await second.getByRole('heading').scrollIntoViewIfNeeded()
  await capture(page, small ? 'phone-dark-reading' : 'desktop-light-reading')

  if (!small) {
    await page.evaluate(axe.source)
    const violations = await page.evaluate(async () => (await window.axe.run('.wm-reading-view', {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    })).violations.map(({ id, nodes }) => [id, nodes.map(node => node.target)]))
    assert.deepEqual(violations, [])
  }

  const archive = button(second, 'Archive message')
  await archive.evaluate(control => control.scrollIntoView({ block: 'center' }))
  if (!small) await archive.focus()
  const archiveAnchor = await second.getByRole('heading').evaluate(node => node.getBoundingClientRect().top)
  if (small) await archive.tap()
  else await archive.press('Enter')
  await second.getByText('Archived', { exact: true }).waitFor()
  await second.getByRole('heading').and(page.locator(':focus')).waitFor()
  const archivedAnchor = await second.getByRole('heading').evaluate(node => node.getBoundingClientRect().top)
  assert(Math.abs(archivedAnchor - archiveAnchor) <= 1, `Archive moved the card from ${archiveAnchor}px to ${archivedAnchor}px`)
  assert.equal((await mailboxMessage(page, refs[secondSubject])).folder, 'Archive')
  assert.equal((await mailboxMessage(page, refs[firstSubject])).folder, 'INBOX')
  const undo = button(controlsIn(page), 'Undo last action')
  await undo.waitFor()
  if (small) await capture(page, 'phone-dark-archive-undo')
  if (small) await undo.tap()
  else await page.keyboard.press('Shift+U')
  await button(second, 'Read message').waitFor()
  assert.equal((await mailboxMessage(page, refs[secondSubject])).folder, 'INBOX')

  await page.route(messageURL(refs[thirdSubject]), route => route.fulfill({
    status: 503, json: { message: 'Message temporarily unavailable.' },
  }), { times: 1 })
  if (small) await button(third, 'Read message').tap()
  else await button(third, 'Read message').press('Enter')
  await third.getByRole('alert').getByText('Message temporarily unavailable.').waitFor()
  assert(!(await mailboxMessage(page, refs[thirdSubject])).flags.seen)
  assert.equal(await first.locator('iframe').count(), 1)
  await button(third, 'Retry message').click()
  await third.getByText(`Notes for ${thirdSubject}.`, { exact: false }).waitFor()
  await third.locator('[aria-busy="false"]').waitFor()
  assert((await mailboxMessage(page, refs[thirdSubject])).flags.seen)

  if (small) await button(view, 'Back to messages').tap()
  else await page.keyboard.press('Escape')
  await view.waitFor({ state: 'hidden' })
  await start.and(page.locator(':focus')).waitFor()
}

async function selectedJourney(page) {
  const list = page.getByRole('region', { name: 'Messages', exact: true })
  await list.getByRole('checkbox', { name: /Select conversation: Studio design notes/ }).check()
  await button(list, 'Next').click()
  await list.getByText('Page 2 of 2', { exact: true }).waitFor()
  const last = 'Studio correspondence 56'
  await list.getByRole('checkbox', { name: new RegExp(`Select conversation: ${last}`) }).check()
  await button(list, 'Read together').press('Enter')
  const view = viewIn(page)
  const later = cardIn(page, last)
  const first = cardIn(page, subjects[0])
  await later.getByText(`Notes for ${last}.`, { exact: false }).waitFor()
  await button(first, 'Read message').press('Enter')
  await first.frameLocator('iframe').getByText(`Formatted notes for ${subjects[0]}.`).waitFor()
  assert.equal(await view.getByRole('article').count(), 2)
  await capture(page, 'desktop-light-selected-across-pages')
  await button(first, 'Open in message reader').click()
  await view.waitFor({ state: 'hidden' })
  await page.getByRole('region', { name: 'Message reader' }).getByRole('heading', { name: subjects[0], exact: true }).waitFor()
}

async function main() {
  assert(Object.hasOwn(engines, engine) && output && url && desktop && phone && password && references)
  assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
  await mkdir(output, { recursive: true })
  const refs = JSON.parse(references)
  // Chromium downloads use the browser process, outside the test page's TLS override.
  const browser = await engines[engine].launch(engine === 'chromium' ? { args: ['--ignore-certificate-errors'] } : {})
  try {
    for (const [account, small] of [[desktop, false], [phone, true]]) {
      const page = await signIn(browser, account, small)
      const errors = []
      page.on('pageerror', error => errors.push(error.message))
      await unreadJourney(page, refs[account], small)
      if (!small) await selectedJourney(page)
      assert.deepEqual(errors, [])
      await page.context().close()
    }
  }
  finally { await browser.close() }
  console.log(`${engine} passed desktop and phone continuous reading`)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
