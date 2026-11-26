import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium } from 'playwright'

const {
  MAIL_THREAD_TEST_URL: url,
  MAIL_THREAD_TEST_CERT: certificate,
  MAIL_THREAD_TEST_PEER: peer,
  MAIL_THREAD_TEST_PASSWORD: password,
  MAIL_THREAD_TEST_ATTACHMENT: expectedAttachment,
  MAIL_TEST_CHROMIUM_EXECUTABLE: executablePath,
} = process.env
const [mode, output] = process.argv.slice(2)
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
assert(['live', 'retained'].includes(mode) && output && certificate && peer && password)
const { publicKey } = new X509Certificate(await readFile(certificate))
const pin = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
const browser = await chromium.launch({ executablePath, args: [`--ignore-certificate-errors-spki-list=${pin}`] })
const retained = mode === 'retained'
await mkdir(output, { recursive: true })

const appearances = [
  { width: 1440, height: 920, colorScheme: 'light' },
  { width: 1440, height: 920, colorScheme: 'dark' },
  { width: 390, height: 844, colorScheme: 'light' },
  { width: 390, height: 844, colorScheme: 'dark' },
  { width: 320, height: 720, colorScheme: 'light' },
  { width: 320, height: 720, colorScheme: 'dark' },
  { width: 390, height: 844, colorScheme: 'dark', contrast: 'more' },
  { width: 390, height: 844, colorScheme: 'light', forcedColors: 'active' },
]

async function waitForFocus(page, selector) {
  await page.waitForFunction(selector => document.activeElement?.matches(selector), selector)
}

async function verifyAppearance({ width, height, colorScheme, contrast, forcedColors }) {
  const phone = width < 860
  const appearance = `${width}-${colorScheme}${contrast ? '-high-contrast' : ''}${forcedColors ? '-forced-colors' : ''}`
  const page = await browser.newPage({ viewport: { width, height }, colorScheme, hasTouch: phone, acceptDownloads: true })
  try {
    await page.emulateMedia({ contrast, forcedColors })
    page.setDefaultTimeout(8000)
    const faults = []
    page.on('pageerror', error => faults.push(error.message))

    async function capture(view) {
      await page.screenshot({ path: join(output, `${appearance}-${view}.png`), animations: 'disabled' })
    }

    await page.goto(url + '/login')
    await page.getByLabel('Email or username').fill(peer)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.waitForURL(url + '/')
    const trigger = page.getByRole('button', { name: 'Shared mail', exact: true })
    const triggerSelector = '#mailNavigation button[aria-haspopup=dialog]:has([data-icon="message-stack"])'
    const menu = page.getByRole('button', { name: 'Mailboxes', exact: true })
    const menuSelector = '.wm-folders-toggle'
    const closeSelector = '.wm-team-thread-header button[aria-label=Close]'
    const backSelector = '.wm-team-thread-header button[aria-label="Back to shared mail"]'
    async function openDialog() {
      await page.locator(triggerSelector).waitFor({ state: 'attached' })
      if (phone && await menu.getAttribute('aria-expanded') !== 'true') {
        await menu.click()
        await page.locator(`${menuSelector}[aria-expanded=true]`).waitFor()
      }
      await trigger.click()
    }
    await openDialog()

    const dialog = page.getByRole('dialog', { name: 'Shared mail' })
    const close = dialog.getByRole('button', { name: 'Close', exact: true })
    const list = dialog.getByRole('list', { name: 'Shared conversations and collections' })
    const thread = list.getByRole('listitem').filter({ hasText: 'Approved source' })
    const collection = list.getByRole('listitem').filter({ hasText: 'Approved collection' })
    await thread.waitFor()
    await collection.waitFor()
    await waitForFocus(page, closeSelector)
    assert.equal(await list.getByText(/Retained copy/).count(), retained ? 2 : 0)
    assert.equal(await list.getByText('Private sibling', { exact: true }).count(), retained ? 0 : 1)
    await capture('list')

    await thread.getByRole('button', { name: 'Open Approved source' }).click()
    const messages = dialog.getByRole('region', { name: 'Shared messages' })
    const attachment = messages.getByRole('link', { name: 'allowed.bin' })
    const search = dialog.getByRole('searchbox', { name: 'Search conversation' })
    await attachment.waitFor()
    await dialog.getByText('Approved teammate discussion', { exact: true }).waitFor()
    await waitForFocus(page, backSelector)
    assert.equal(await dialog.getByText('blocked.eml', { exact: true }).count(), 0)
    assert.equal(await dialog.getByRole('button', { name: 'Post comment' }).count(), retained ? 0 : 1)
    assert.equal(await dialog.getByRole('button', { name: 'Revoke access' }).count(), 0)
    assert.equal(await dialog.getByRole('group', { name: 'Teammate permissions' }).count(), 0)

    await capture('conversation')
    const dimensions = await dialog.evaluate((element) => {
      const panel = element.querySelector('.wm-snapshot-panel')
      const field = element.querySelector('.wm-team-thread-search .mail-search-field')
      const action = element.querySelector('.wm-team-thread-search button')
      const firstMessage = element.querySelector('.wm-snapshot-message')
      const controls = [...element.querySelectorAll('.wm-team-thread-header button, .wm-team-thread-download')]
      const bounds = panel.getBoundingClientRect()
      return {
        width: bounds.width, right: bounds.right, scroll: panel.scrollWidth, client: panel.clientWidth,
        firstMessageOffset: firstMessage.getBoundingClientRect().top - bounds.top,
        actionTop: action.getBoundingClientRect().top, actionHeight: action.getBoundingClientRect().height,
        fieldTop: field.getBoundingClientRect().top, fieldHeight: field.getBoundingClientRect().height,
        actionBorder: getComputedStyle(action).borderTopColor,
        neutralBorder: getComputedStyle(field).borderTopColor,
        controls: controls.map((control) => {
          const rect = control.getBoundingClientRect()
          return { width: rect.width, height: rect.height, border: getComputedStyle(control).borderTopColor }
        }),
      }
    })
    assert(dimensions.width <= width && dimensions.right <= width + 1, JSON.stringify(dimensions))
    assert(dimensions.scroll <= dimensions.client + 1, JSON.stringify(dimensions))
    assert(dimensions.firstMessageOffset < 250, JSON.stringify(dimensions))
    assert.equal(dimensions.actionTop, dimensions.fieldTop)
    assert.equal(dimensions.actionHeight, dimensions.fieldHeight)
    if (phone) assert(dimensions.controls.every(control => control.height >= 44 && control.width >= 44))
    const quietOutline = 'rgba(0, 0, 0, 0)'
    if (contrast || forcedColors) assert(dimensions.controls.every(control => control.border !== quietOutline))
    else {
      assert(dimensions.controls.every(control => control.border === quietOutline))
      assert.notEqual(dimensions.actionBorder, dimensions.neutralBorder)
    }
    // Tab keeps keyboard focus visible after programmatic focus moves into the detail.
    await page.keyboard.press('Tab')
    await waitForFocus(page, closeSelector)
    assert.equal(await close.evaluate(node => getComputedStyle(node).outlineStyle), 'solid')
    if (contrast || forcedColors) await capture('focus')

    await search.fill('verified reply excerpt')
    await dialog.getByRole('button', { name: 'Search', exact: true }).click()
    await messages.getByText('Verified reply excerpt', { exact: true }).waitFor()
    await messages.getByText('Approved original body', { exact: true }).waitFor({ state: 'hidden' })
    await search.fill('')
    await search.press('Enter')
    await attachment.waitFor()
    const [download] = await Promise.all([page.waitForEvent('download'), attachment.click()])
    assert.equal(download.suggestedFilename(), 'allowed.bin')
    const bytes = await readFile(await download.path())
    assert.equal(bytes.toString('base64'), expectedAttachment)

    const back = dialog.getByRole('button', { name: 'Back to shared mail' })
    await back.click()
    await collection.waitFor()
    await waitForFocus(page, closeSelector)
    await collection.getByRole('button', { name: 'Open Approved collection' }).click()
    const pager = dialog.getByRole('group', { name: 'Collection pages' })
    const next = pager.getByRole('button', { name: 'Next page' })
    const previous = pager.getByRole('button', { name: 'Previous page' })
    await next.waitFor()
    assert.equal(await dialog.getByRole('searchbox').count(), 0)
    await capture('collection')
    await next.click()
    await pager.getByText('Page 2', { exact: true }).waitFor()
    await messages.getByText('Approved original body', { exact: true }).waitFor()
    assert(await next.isDisabled())
    await previous.click()
    await pager.getByText('Page 1', { exact: true }).waitFor()
    assert(await previous.isDisabled())

    await page.keyboard.press('Escape')
    await dialog.waitFor({ state: 'hidden' })
    await waitForFocus(page, phone ? menuSelector : triggerSelector)
    await openDialog()
    await collection.waitFor()
    await close.click()
    await dialog.waitFor({ state: 'hidden' })
    await waitForFocus(page, phone ? menuSelector : triggerSelector)
    assert.deepEqual(faults, [])
    console.log(`Verified ${mode} Shared Mail at ${appearance}. First message at ${Math.round(dimensions.firstMessageOffset)}px within dialog.`)
  }
  finally {
    await page.close()
  }
}

try {
  for (const appearance of appearances) await verifyAppearance(appearance)
}
finally {
  await browser.close()
}
