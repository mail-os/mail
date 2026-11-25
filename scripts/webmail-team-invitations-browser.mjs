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

async function readMailboxApi(page, path) {
  const result = await page.evaluate(async (path) => {
    const response = await fetch('/webmail/api/' + path, { cache: 'no-store' })
    return { status: response.status, body: await response.json() }
  }, path)
  assert.equal(result.status, 200)
  return result.body
}

async function selectedLabelFits(select) {
  const fits = await select.evaluate((control) => {
    const style = getComputedStyle(control)
    const canvas = document.createElement('canvas')
    const context = canvas.getContext('2d')
    context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
    const available = control.clientWidth - Number.parseFloat(style.paddingLeft) - Number.parseFloat(style.paddingRight)
    return context.measureText(control.selectedOptions[0].label).width <= available
  })
  assert(fits, 'The selected access label fits beside the select arrow')
}

try {
  const captain = await signIn(owner)
  const captainPanel = captain.locator('.wm-team-invitations')
  const access = captain.locator('.wm-team-access')
  const accessSummary = access.getByText('Share mailbox', { exact: true })
  const accessForm = access.locator('form')
  const enabled = captain.locator(':enabled')
  const grant = accessForm.getByRole('button', { name: 'Grant access', exact: true }).and(enabled)
  const team = accessForm.getByLabel('Team', { exact: true })
  const teammate = accessForm.getByLabel('Teammate', { exact: true })
  const scope = accessForm.getByLabel('Access', { exact: true })
  const accessList = access.getByRole('list', { name: 'Current mailbox access' })
  await accessSummary.press('Enter')
  await access.getByText('No teammates have access to this mailbox on this team.').waitFor()
  await team.selectOption('studio')
  await teammate.fill(recipient)
  assert.equal(await scope.inputValue(), 'mailbox')
  await alignedControls(accessForm, 'select, input, button', 36, true)
  await selectedLabelFits(scope)
  await grant.press('Enter')
  await access.getByRole('alert').filter({ hasText: 'Your teammate needs to join this team' }).waitFor()
  await access.getByRole('button', { name: 'Invite teammate', exact: true }).press('Enter')
  const form = captainPanel.locator('form')
  await form.waitFor()
  assert.equal(await access.evaluate(panel => panel.open), false, 'Only one team panel stays expanded')
  assert.equal(await form.getByLabel('Team', { exact: true }).inputValue(), 'studio')
  const inviteAddress = form.getByLabel('Teammate', { exact: true })
  assert.equal(await inviteAddress.inputValue(), recipient)
  await captain.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'invitationField')
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
  assert.deepEqual(await readMailboxApi(member, 'teams'), [{ id: 'studio', name: 'Design Studio', role: 'member' }])
  assert.deepEqual(await readMailboxApi(member, 'shared-inboxes'), [])
  assert.deepEqual(await readMailboxApi(member, 'sender-identities'), [])
  await captain.getByRole('button', { name: 'Refresh shared inbox', exact: true }).click()
  await sent.waitFor({ state: 'hidden' })

  const loadedAccess = captain.waitForResponse(response => response.url() === url + '/webmail/api/teams/studio'
    && response.request().method() === 'GET')
  await accessSummary.press('Enter')
  assert.equal((await loadedAccess).status(), 200)
  await access.getByText('No teammates have access to this mailbox on this team.').waitFor()
  await teammate.fill(recipient)
  const grantedAccess = captain.waitForResponse(response => response.url() === url + '/webmail/api/teams/studio/grants'
    && response.request().method() === 'PUT')
  await grant.press('Enter')
  assert.equal((await grantedAccess).status(), 200)
  const inboxRevoke = accessList.getByRole('button', { name: `Revoke Inbox access for ${recipient}`, exact: true })
  await inboxRevoke.waitFor()
  assert.deepEqual(await readMailboxApi(member, 'sender-identities'), [])
  await member.getByRole('button', { name: 'Refresh shared inbox', exact: true }).tap()
  const sharedMessage = member.getByRole('button', { name: /A message in the shared Inbox/ })
  await sharedMessage.tap()
  await member.getByRole('heading', { name: 'A message in the shared Inbox', exact: true }).waitFor()

  await scope.selectOption('sender')
  await grant.press('Enter')
  const senderRevoke = accessList.getByRole('button', { name: `Revoke Send-as access for ${recipient}`, exact: true })
  await senderRevoke.waitFor()
  assert(await inboxRevoke.isVisible(), 'Granting sender access keeps the Inbox grant')
  const [source] = await readMailboxApi(member, 'sender-identities')
  assert.equal(source.address, owner)
  await access.locator('.wm-team-access-body').screenshot({ path: join(output, 'mailbox-access-desktop-light.png'), animations: 'disabled' })
  await team.selectOption('second-studio')
  await access.getByText('No teammates have access to this mailbox on this team.').waitFor()
  assert.equal(await teammate.inputValue(), '')
  await team.selectOption('studio')
  await inboxRevoke.waitFor()
  await senderRevoke.waitFor()
  await teammate.fill(recipient)

  await captain.emulateMedia({ colorScheme: 'dark' })
  await captain.setViewportSize({ width: 660, height: 844 })
  await alignedControls(accessForm, 'select, input, button', 44, false)
  await captain.setViewportSize({ width: 390, height: 844 })
  await alignedControls(accessForm, 'select, input, button', 44, false)
  await selectedLabelFits(scope)
  assert(await captain.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await accessForm.screenshot({ path: join(output, 'mailbox-access-phone-dark.png'), animations: 'disabled' })
  await captain.setViewportSize({ width: 1440, height: 920 })
  await captain.emulateMedia({ colorScheme: 'light' })

  await inboxRevoke.and(enabled).press('Enter')
  await inboxRevoke.waitFor({ state: 'hidden' })
  await access.getByRole('status').filter({ hasText: 'Inbox access revoked.' }).waitFor()
  await captain.waitForFunction(() => document.activeElement?.getAttribute('data-stx-ref') === 'accessField')
  await member.getByRole('button', { name: 'Refresh shared inbox', exact: true }).tap()
  await member.getByRole('alert').filter({ hasText: 'Access to this shared inbox changed.' }).waitFor()
  await sharedMessage.waitFor({ state: 'hidden' })
  assert.deepEqual(await readMailboxApi(member, 'shared-inboxes'), [])
  assert(await senderRevoke.isVisible(), 'Revoking Inbox access keeps the sender grant')
  assert.deepEqual(await readMailboxApi(member, 'sender-identities'), [source])

  await member.goto(url + '/')
  const personal = member.getByRole('button', { name: /A message in the personal Inbox/ })
  await personal.waitFor()
  await member.getByRole('button', { name: 'Compose', exact: true }).tap()
  const compose = member.getByRole('dialog', { name: 'Compose message' })
  await compose.getByLabel('From', { exact: true }).selectOption(source.id)
  const to = compose.getByRole('combobox', { name: 'To', exact: true })
  await to.fill(recipient)
  await to.press('Enter')
  await compose.getByLabel('Subject', { exact: true }).fill('Sent from the shared address')
  await compose.getByLabel('Message body').fill('This delivery uses only the sender grant.')
  await compose.getByLabel('Undo Send delay', { exact: true }).selectOption('0')
  await compose.getByRole('button', { name: 'Send', exact: true }).tap()
  await compose.waitFor({ state: 'hidden' })
  const deadline = Date.now() + 12_000
  let delivered
  while (!delivered && Date.now() < deadline) {
    const inbox = await readMailboxApi(member, 'messages?folder=INBOX')
    delivered = inbox.items.find(item => item.subject === 'Sent from the shared address')
    if (!delivered) await new Promise(resolve => setTimeout(resolve, 200))
  }
  assert(delivered, 'The delegated send was delivered to the personal Inbox')
  assert.equal(delivered.from, owner)

  await senderRevoke.and(enabled).press('Enter')
  await access.getByRole('status').filter({ hasText: 'Send-as access revoked.' }).waitFor()
  await accessList.waitFor({ state: 'hidden' })
  assert.deepEqual(await readMailboxApi(member, 'sender-identities'), [])
  await personal.waitFor()

  await member.goto(url + '/shared')
  const memberAccess = member.locator('.wm-team-access')
  await memberAccess.getByText('Share mailbox', { exact: true }).tap()
  await memberAccess.getByLabel('Teammate', { exact: true }).fill(owner)
  await alignedControls(memberAccess.locator('form'), 'select, input, button', 44, false)
  assert(await member.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  const mobileGrant = memberAccess.getByRole('button', { name: 'Grant access', exact: true })
  const panelBounds = await memberAccess.boundingBox()
  const grantBounds = await mobileGrant.boundingBox()
  assert(grantBounds.y + grantBounds.height <= panelBounds.y + panelBounds.height, 'The full action fits inside the 320px panel')
  await memberAccess.screenshot({ path: join(output, 'mailbox-access-narrow-phone.png'), animations: 'disabled' })
  await mobileGrant.tap()
  const reverseGrant = memberAccess.getByRole('button', { name: `Revoke Inbox access for ${owner}`, exact: true })
  await reverseGrant.waitFor()
  assert((await readMailboxApi(captain, 'shared-inboxes')).some(inbox => inbox.address === recipient))
  const roster = await readMailboxApi(member, 'teams/studio')
  assert.deepEqual(roster.members, [{ mailbox: recipient, role: 'member', enabled: true }])
  await reverseGrant.tap()
  await reverseGrant.waitFor({ state: 'hidden' })
  assert.deepEqual(errors, [])
  process.stdout.write(`${engine} verified hosted invitations, Inbox and sender grants, delivery, and revocation.\n`)
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
