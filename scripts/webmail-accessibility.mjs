import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import axe from 'axe-core'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_BROWSER_URL: url, MAIL_BROWSER_OWNER: owner, MAIL_BROWSER_PASSWORD: password, MAIL_BROWSER_DAY: day } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, engine) && output && url && owner && password && day, 'Run through test-webmail-browser.py --accessibility')
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/, 'Browser tests require a disposable loopback HTTPS server')

const wcagTags = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const button = (page, name) => page.getByRole('button', { name, exact: typeof name === 'string' })
const heading = (page, name) => page.getByRole('heading', { name, exact: true })
const handoff = 'Tuesday design handoff'
const results = []
const tree = {}
const failures = []

function luminance(channels) {
  const weights = [.2126, .7152, .0722]
  return channels.reduce((result, value, index) => {
    const channel = value / 255
    const linear = channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4
    return result + weights[index] * linear
  }, 0)
}

function rgb(color) {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(color)
  assert(match, `Expected an opaque sRGB color, got ${color}`)
  return match.slice(1).map(Number)
}

function contrast(first, second) {
  const a = luminance(first)
  const b = luminance(second)
  return (Math.max(a, b) + .05) / (Math.min(a, b) + .05)
}

// axe leaves color contrast unresolved when it encounters the SVG background.
// The picker has a solid fill, with the chevron and text in separate areas.
async function verifyPickers(page) {
  const colors = await page.locator('select:visible:enabled').evaluateAll(pickers => pickers.map((picker) => {
    const style = getComputedStyle(picker)
    const name = picker.getAttribute('aria-label') || picker.labels?.[0]?.textContent.trim() || picker.id
    return { name, text: style.color, fill: style.backgroundColor, border: style.borderInlineStartColor, image: style.backgroundImage }
  }))
  return colors.map(({ name, text, fill, border, image }) => {
    const chevron = /stroke="#([\da-f]{6})"/i.exec(decodeURIComponent(image))
    assert(chevron, `${name}: expected the shared picker chevron`)
    const stroke = chevron[1].match(/../g).map(channel => Number.parseInt(channel, 16))
    const background = rgb(fill)
    const ratios = { text: contrast(rgb(text), background), border: contrast(rgb(border), background), chevron: contrast(stroke, background) }
    assert(ratios.text >= 4.5, `${name}: picker text contrast ${ratios.text.toFixed(2)}:1`)
    for (const part of ['border', 'chevron'])
      assert(ratios[part] >= 3, `${name}: picker ${part} contrast ${ratios[part].toFixed(2)}:1`)
    return { name, ...ratios }
  })
}

function summarize({ id, nodes }) {
  return { id, nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary })) }
}

async function audit(page, name) {
  // Scans run with the document's real CSP and bypass no rules or elements.
  await page.evaluate(axe.source)
  const report = await page.evaluate(async tags => window.axe.run({ runOnly: { type: 'tag', values: tags } }), wcagTags)
  const violations = report.violations.map(summarize)
  const pickers = await verifyPickers(page)
  results.push({ name, passes: report.passes.length, violations, needsReview: report.incomplete.map(summarize), pickers })
  for (const item of violations)
    failures.push(`${name} ${item.id}: ${item.nodes.map(node => node.target.join(' > ')).join(', ')}`)
}

async function snapshot(locator, name, expected) {
  const value = await locator.ariaSnapshot()
  assert.match(value, expected, name)
  tree[name] = value
}

async function journey(browser, width, colorScheme) {
  const phone = width === 320
  const variant = `${phone ? 'phone' : 'desktop'}-${colorScheme}`
  const context = await browser.newContext({
    viewport: { width, height: phone ? 844 : 940 },
    colorScheme,
    hasTouch: phone,
    isMobile: phone && engine !== 'firefox',
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    timezoneId: 'UTC',
  })
  try {
    const page = await context.newPage()
    page.setDefaultTimeout(12_000)
    const scan = name => audit(page, `${variant}-${name}`)
    await page.goto(`${url}/status`)
    await heading(page, 'Mail delivery').waitFor()
    await page.getByRole('link', { name: 'Sign in to Mail' }).waitFor()
    await scan('delivery')

    await page.goto(`${url}/forgot`)
    await heading(page, 'Forgot your password?').waitFor()
    await scan('recovery')

    await page.goto(`${url}/login`)
    await heading(page, 'Sign in to Mail').waitFor()
    await scan('sign-in')
    await page.getByLabel('Email or username').fill(owner)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await button(page, 'Sign in').click()
    const message = button(page, /Tuesday design handoff/)
    await message.waitFor()
    await scan('inbox')

    await button(page, 'Select').click()
    const list = page.getByRole('region', { name: 'Messages', exact: true })
    const checkbox = page.getByRole('checkbox', { name: `Select conversation: ${handoff}`, exact: true })
    const target = await checkbox.boundingBox()
    assert(target && target.width >= 24 && target.height >= 24, 'Message selection has a full checkbox target')
    const marker = await checkbox.evaluate((input) => {
      const style = getComputedStyle(input, '::before')
      const field = getComputedStyle(input.closest('.wm-list').querySelector('.mail-search-field'))
      return { width: style.inlineSize, height: style.blockSize, borderMatches: style.border === field.border }
    })
    assert.deepEqual(marker, { width: '16px', height: '16px', borderMatches: true }, 'The checkbox mark matches the shared border without crowding the text')
    const corner = { x: target.x + 3, y: target.y + 3 }
    if (phone) await page.touchscreen.tap(corner.x, corner.y)
    else await page.mouse.click(corner.x, corner.y)
    assert(await checkbox.isChecked(), 'The checkbox can be selected at the edge of its target')
    assert(!await heading(page, handoff).isVisible(), 'Selecting does not open the reader')
    await checkbox.press('Space')
    assert(!await checkbox.isChecked(), 'Space clears the selection')
    await checkbox.press('Space')
    assert(await checkbox.isChecked(), 'Space selects the conversation')
    await snapshot(list, `${variant}-selected-message`, /group "Selected message actions"[\s\S]+checkbox "Select conversation: Tuesday design handoff" \[checked\]/)
    await scan('selection')
    await page.screenshot({ path: join(output, `${variant}-selection.png`), animations: 'disabled' })
    if (engine === 'chromium' && variant === 'desktop-light') {
      await page.emulateMedia({ forcedColors: 'active' })
      assert.equal(await checkbox.evaluate(input => getComputedStyle(input).appearance), 'auto', 'Forced colors use the system checkbox')
      await page.screenshot({ path: join(output, 'desktop-forced-colors-selection.png'), animations: 'disabled' })
      await page.emulateMedia({ forcedColors: 'none' })
    }
    await button(page, 'Done').click()

    await button(page, 'Filters').click()
    await page.getByRole('combobox', { name: 'Search in folder' }).waitFor()
    await scan('search-filters')
    await button(page, 'Filters').click()

    await message.click()
    await heading(page, handoff).waitFor()
    await scan('reader')

    if (phone) await button(page, 'Back to messages').click()
    await button(page, 'Compose').click()
    const composer = page.getByRole('dialog', { name: 'Compose message' })
    await composer.waitFor()
    await snapshot(composer, `${variant}-composer`, /combobox "To"/)
    await scan('compose')
    await button(composer, 'Close composer').click()
    await composer.waitFor({ state: 'hidden' })

    if (phone) await button(page, 'Mailboxes').click()
    await button(page, 'Account').click()
    const settings = page.getByRole('dialog', { name: 'Account settings' })
    await settings.waitFor()
    await scan('account')

    await page.goto(`${url}/calendar?day=${day}`)
    await page.getByRole('region', { name: 'Calendar workspace' }).waitFor()
    const newEvent = button(page, 'New event')
    await newEvent.waitFor()
    await scan('calendar')
    await button(page, 'Manage calendars').click()
    const sharing = page.getByRole('region', { name: 'Manage calendars' })
    await sharing.getByRole('combobox', { name: 'Calendar to share' }).waitFor()
    await snapshot(sharing, `${variant}-calendar-sharing`, /combobox "Calendar to share"/)
    await scan('calendar-settings')
    await sharing.locator('.calendar-share-form').screenshot({ path: join(output, `${variant}-calendar-share.png`), animations: 'disabled' })

    await newEvent.click()
    const editor = page.getByRole('dialog', { name: 'New event' })
    await editor.waitFor()
    await snapshot(editor, `${variant}-calendar-event`, /combobox "Event time zone"/)
    await scan('new-event')

    await page.goto(`${url}/shared`)
    await heading(page, 'Shared inboxes').waitFor()
    const source = page.getByRole('combobox', { name: 'Shared inbox', exact: true })
    const studio = source.locator('option', { hasText: /studio@hosted\.example\.test/ })
    await studio.waitFor({ state: 'attached' })
    await source.selectOption(await studio.getAttribute('value'))
    await button(page, /Studio proof approval/).waitFor()
    await scan('shared-inbox')
  }
  finally {
    await context.close()
  }
}

async function main() {
  await mkdir(output, { recursive: true })
  const browser = await engines[engine].launch()
  try {
    for (const width of [1440, 320]) {
      for (const scheme of ['light', 'dark'])
        await journey(browser, width, scheme)
    }
  }
  finally {
    await browser.close()
    await writeFile(join(output, 'wcag.json'), `${JSON.stringify({ engine, results, tree }, null, 2)}\n`)
  }
  assert.equal(failures.length, 0, failures.join('\n'))
  console.log(`${engine}: ${results.length} WCAG-tagged page states passed. Review items and accessibility snapshots are in wcag.json.`)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
