import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_INVITE_TEST_URL: url, MAIL_INVITE_TEST_OWNER: owner, MAIL_INVITE_TEST_RECIPIENT: recipient,
  MAIL_INVITE_TEST_PASSWORD: password, MAIL_INVITE_TEST_CERT: certificate } = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, engine) && output && owner && recipient && password && certificate)
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
await mkdir(output, { recursive: true })

const options = {}
if (engine === 'chromium') {
  const { publicKey } = new X509Certificate(await readFile(certificate))
  const pin = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
  options.args = [`--ignore-certificate-errors-spki-list=${pin}`]
}
const browser = await engines[engine].launch(options)
const errors = []

async function signIn(account, phone = false) {
  const page = await browser.newPage({
    viewport: phone ? { width: 320, height: 844 } : { width: 1440, height: 920 },
    colorScheme: phone ? 'dark' : 'light', deviceScaleFactor: phone ? 2 : 1,
    hasTouch: phone, ignoreHTTPSErrors: engine !== 'chromium',
  })
  page.setDefaultTimeout(12_000)
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(url + '/login')
  await page.getByLabel('Email or username').fill(account)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await page.waitForURL(url + '/')
  await page.goto(url + '/shared')
  return page
}

async function alignedControls(group, selector, height, sameRow) {
  const controls = await group.locator(selector).evaluateAll(nodes => nodes.map((node) => {
    const { top, bottom, height } = node.getBoundingClientRect()
    const style = getComputedStyle(node)
    const color = style.getPropertyValue('--control-border').trim().slice(1).match(/../g)
    const channels = color.map(channel => Number.parseInt(channel, 16)).join(', ')
    return { top, bottom, height, sharesOutline: style.border === `1px solid rgb(${channels})`, radius: style.borderRadius }
  }))
  assert(controls.length >= 2)
  for (const control of controls) {
    assert(control.sharesOutline)
    assert.equal(control.height, height)
    assert.equal(control.radius, '8px')
    if (sameRow) assert.deepEqual([control.top, control.bottom], [controls[0].top, controls[0].bottom])
  }
}

try {
  const captain = await signIn(owner)
  const captainPanel = captain.locator('.wm-team-invitations')
  await captainPanel.getByText('Team invitations', { exact: true }).click()
  const form = captainPanel.locator('form')
  await form.getByLabel('Team', { exact: true }).selectOption({ label: 'Design Studio' })
  await form.getByLabel('Teammate', { exact: true }).fill(recipient)
  await alignedControls(form, 'select, input, button', 36, true)
  await captainPanel.screenshot({ path: join(output, 'team-invitation-desktop.png'), animations: 'disabled' })
  await form.getByRole('button', { name: 'Invite to team', exact: true }).click()
  const sent = captainPanel.getByRole('list', { name: 'Invitations you sent' })
  await sent.getByText(recipient, { exact: true }).waitFor()

  const member = await signIn(recipient, true)
  const memberPanel = member.locator('.wm-team-invitations')
  await memberPanel.getByText('Team invitations (1)', { exact: true }).click()
  const incoming = memberPanel.getByRole('list', { name: 'Invitations to join' })
  await incoming.getByText('Design Studio', { exact: true }).waitFor()
  await alignedControls(incoming, 'button', 44, true)
  assert(await member.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await memberPanel.screenshot({ path: join(output, 'team-invitation-phone.png'), animations: 'disabled' })
  await incoming.getByRole('button', { name: 'Accept', exact: true }).click()
  await memberPanel.getByRole('status').filter({ hasText: 'You joined the team.' }).waitFor()
  await incoming.waitFor({ state: 'hidden' })
  const membership = await member.evaluate(async () => {
    const response = await fetch('/webmail/api/teams', { credentials: 'same-origin' })
    return { status: response.status, teams: await response.json() }
  })
  assert.equal(membership.status, 200)
  assert.deepEqual(membership.teams, [{ id: 'studio', name: 'Design Studio', role: 'member' }])
  await captain.getByRole('button', { name: 'Refresh shared inbox', exact: true }).click()
  await sent.waitFor({ state: 'hidden' })
  assert.deepEqual(errors, [])
  process.stdout.write(`${engine} verified the desktop owner and phone recipient journeys.\n`)
}
catch (error) {
  for (const [index, context] of browser.contexts().entries()) {
    const page = context.pages()[0]
    if (page) await page.screenshot({ path: join(output, `team-invitation-failure-${index}.png`) }).catch(() => {})
  }
  throw error
}
finally {
  await browser.close()
}
