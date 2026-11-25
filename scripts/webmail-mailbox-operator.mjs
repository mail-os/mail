import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import axe from 'axe-core'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_OPERATOR_URL: url, MAIL_OPERATOR_USER: operator, MAIL_OPERATOR_OTHER: other, MAIL_OPERATOR_PASSWORD: password, MAIL_OPERATOR_NEW: created } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }

async function signIn(page, name) {
  await page.getByLabel('Email or username').fill(name)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

async function verifyForm(page, height) {
  const form = page.locator('.mailbox-operator-form')
  const controls = await form.locator('input, button').evaluateAll(elements => elements.map((element) => {
    const style = getComputedStyle(element)
    const token = element.matches('.wm-action--accent:not(:disabled)') ? '--accent-button-border' : '--control-border'
    const channels = style.getPropertyValue(token).trim().slice(1).match(/../g)
      .map(channel => Number.parseInt(channel, 16)).join(', ')
    return {
      height: element.getBoundingClientRect().height,
      border: style.border,
      expectedBorder: `1px solid rgb(${channels})`,
      radius: style.borderRadius,
    }
  }))
  assert.equal(controls.length, 4)
  for (const control of controls) {
    assert.equal(control.height, height)
    assert.equal(control.border, control.expectedBorder)
    assert.equal(control.radius, '8px')
  }
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mailbox management fits the viewport')

  await page.evaluate(axe.source)
  const issues = await page.evaluate(async () => (await window.axe.run({
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
  })).violations.map(issue => [issue.id, issue.nodes.map(node => node.target)]))
  assert.deepEqual(issues, [])
}

async function main() {
  assert(Object.hasOwn(engines, engine) && output && url && operator && other && password && created, 'Run via test-webmail-mailbox-operator.py')
  assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
  await mkdir(output, { recursive: true })
  const browser = await engines[engine].launch()
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 940 }, colorScheme: 'light', ignoreHTTPSErrors: true })
    const page = await context.newPage()
    page.setDefaultTimeout(10_000)
    await page.goto(`${url}/mailboxes`)
    await page.waitForURL('**/login#mailboxes')
    await signIn(page, operator)
    await page.waitForURL('**/mailboxes')
    const create = page.getByRole('button', { name: 'Create mailbox', exact: true })
    const firstMailbox = page.getByText(other, { exact: true })
    await firstMailbox.waitFor()
    await verifyForm(page, 36)
    const pages = page.getByRole('navigation', { name: 'Mailbox pages' })
    await pages.getByRole('button', { name: 'Next' }).click()
    await page.getByText(operator, { exact: true }).waitFor()
    await firstMailbox.waitFor({ state: 'hidden' })
    await pages.getByRole('button', { name: 'Previous' }).click()
    await firstMailbox.waitFor()
    await page.screenshot({ path: join(output, 'operator-desktop-light.png'), animations: 'disabled' })

    const phone = await browser.newContext({
      viewport: { width: 320, height: 844 },
      colorScheme: 'dark',
      hasTouch: true,
      isMobile: engine !== 'firefox',
      ignoreHTTPSErrors: true,
      storageState: await context.storageState(),
    })
    const mobile = await phone.newPage()
    await mobile.goto(`${url}/mailboxes`)
    await mobile.getByText(other, { exact: true }).waitFor()
    await verifyForm(mobile, 44)
    await mobile.screenshot({ path: join(output, 'operator-phone-dark.png'), animations: 'disabled' })

    await page.getByLabel('Mailbox address').fill(created)
    await page.getByLabel('Initial password').fill(password)
    await page.getByLabel('Your mailbox password').fill(password)
    await create.click()
    await page.getByRole('status').filter({ hasText: 'ready to sign in' }).waitFor()
    await page.getByText(created, { exact: true }).waitFor()
    assert.equal(await page.getByLabel('Initial password').inputValue(), '')
    assert.equal(await page.getByLabel('Your mailbox password').inputValue(), '')
    await page.getByRole('link', { name: 'Mail', exact: true }).click()
    await page.getByRole('link', { name: 'Manage mailboxes', exact: true }).waitFor()

    const member = await browser.newPage({ ignoreHTTPSErrors: true })
    await member.goto(`${url}/login`)
    await signIn(member, other)
    await member.getByRole('button', { name: /Mailbox handoff/ }).click()
    await member.getByRole('heading', { name: 'Mailbox handoff', exact: true }).waitFor()
    assert.equal(await member.getByRole('link', { name: 'Manage mailboxes', exact: true }).count(), 0)
    await member.goto(`${url}/mailboxes`)
    await member.getByRole('alert').filter({ hasText: 'cannot manage server mailboxes' }).waitFor()
    assert(!await member.getByRole('button', { name: 'Create mailbox', exact: true }).isVisible())
    await member.close()

    const newcomer = await browser.newPage({ ignoreHTTPSErrors: true })
    await newcomer.goto(`${url}/login`)
    await signIn(newcomer, created)
    await newcomer.getByRole('heading', { name: 'Inbox', exact: true }).waitFor()
    assert.equal(await newcomer.getByRole('link', { name: 'Manage mailboxes', exact: true }).count(), 0)
  }
  finally { await browser.close() }
  console.log(`${engine} passed mailbox operator sign-in, creation, directory and ordinary-mailbox journeys.`)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
