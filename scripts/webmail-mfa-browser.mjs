import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const {
  MAIL_MFA_URL: url, MAIL_MFA_ORIGIN: origin, MAIL_MFA_PRIVATE: privateUrl, MAIL_MFA_TOKEN: token,
  MAIL_MFA_OWNER: owner, MAIL_MFA_OTHER: other, MAIL_MFA_PASSWORD: password, MAIL_MFA_ACTOR: actor,
} = process.env
const [engine, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const codeField = scope => scope.getByLabel('Authenticator or recovery code', { exact: true })
const signIn = scope => button(scope, 'Sign in')
const errors = []

function previousCode(key) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bytes = Buffer.alloc(20)
  let bits = 0
  let count = 0
  let cursor = 0
  for (const character of key) {
    bits = (bits << 5) | alphabet.indexOf(character)
    count += 5
    if (count < 8) continue
    count -= 8
    bytes[cursor++] = (bits >> count) & 255
  }
  assert.equal(cursor, bytes.length)
  const time = Buffer.alloc(8)
  time.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) - 1))
  const digest = createHmac('sha1', bytes).update(time).digest()
  const offset = digest.at(-1) & 15
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

async function credentials(page, account) {
  await page.goto(url + '/login')
  await page.getByLabel('Email or username').fill(account)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await signIn(page).click()
}

async function verificationSettings(page) {
  const account = button(page, 'Account')
  const drawer = button(page, 'Mailboxes')
  await account.or(drawer).first().waitFor()
  if (await drawer.isVisible()) await drawer.click()
  await account.click()
  const dialog = page.getByRole('dialog', { name: 'Account settings' })
  const section = dialog.getByRole('region', { name: 'Two-step verification' })
  await button(section, 'Manage two-step verification').click()
  return { dialog, section }
}

async function checkFocus(page, field) {
  await field.and(page.locator(':focus')).waitFor()
  assert(await field.evaluate(el => el.matches(':focus-visible')))
}

async function capture(page, name, mask = []) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await page.screenshot({ path: join(output, name + '.png'), mask, maskColor: '#7f8796', animations: 'disabled' })
}

await mkdir(output, { recursive: true })
const browser = await engines[engine].launch()
try {
  const options = { ignoreHTTPSErrors: true, viewport: { width: 1440, height: 940 } }
  const desktop = await browser.newPage(options)
  const phone = await browser.newPage({
    ...options, viewport: { width: 320, height: 844 }, hasTouch: true, isMobile: engine !== 'firefox',
    colorScheme: 'dark', deviceScaleFactor: 2,
  })
  for (const page of [desktop, phone]) {
    page.setDefaultTimeout(12_000)
    page.on('pageerror', problem => errors.push(problem.message))
  }

  await credentials(desktop, owner)
  await desktop.waitForURL(url + '/')
  const { dialog, section } = await verificationSettings(desktop)
  await section.getByLabel('Current mailbox password').fill(password)
  await button(section, 'Set up authenticator').press('Enter')
  const setupKey = section.getByLabel('Setup key')
  const confirmation = section.getByLabel('Authenticator code')
  await checkFocus(desktop, confirmation)
  await capture(desktop, 'desktop-setup', [setupKey])
  const code = previousCode(await setupKey.inputValue())
  await confirmation.fill(code)
  await button(section, 'Turn on verification').press('Enter')
  const recoveryHeading = section.getByRole('heading', { name: 'Save your recovery codes' })
  await recoveryHeading.and(desktop.locator(':focus')).waitFor()
  const recovery = section.getByRole('textbox', { name: 'Recovery codes', exact: true })
  const codes = (await recovery.inputValue()).split('\n')
  assert.equal(codes.length, 10)
  await capture(desktop, 'desktop-recovery-codes', [recovery])
  await button(section, 'Done').click()
  await recovery.waitFor({ state: 'hidden' })
  await button(dialog, 'Close').click()

  await credentials(phone, owner)
  const factor = codeField(phone)
  await checkFocus(phone, factor)
  await factor.fill('invalid')
  await button(phone, 'Verify and sign in').click()
  await phone.getByRole('alert').getByText('That code is invalid or was already used.').waitFor()
  await checkFocus(phone, factor)
  await capture(phone, 'phone-factor-error')
  await factor.fill(codes[0])
  await button(phone, 'Verify and sign in').click()
  await phone.waitForURL(url + '/')

  await credentials(phone, other)
  await phone.waitForURL(url + '/')
  await phone.goto(url + '/combined')
  await button(phone, 'Linked accounts').click()
  await button(phone, 'Link a mailbox').click()
  await phone.getByLabel('Mailbox username').fill(owner)
  await phone.getByLabel('Mailbox password').fill(password)
  await button(phone, 'Verify and link').click()
  await checkFocus(phone, codeField(phone))
  await capture(phone, 'phone-linked-factor')
  await codeField(phone).fill(codes[1])
  await button(phone, 'Verify and link').click()
  await phone.getByRole('button', { name: 'Remove ' + owner }).waitFor()

  const response = await fetch(privateUrl + '/provisioning/v1/webmail/sign-in', {
    method: 'POST', headers: { Authorization: token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ mailbox: owner, actor }),
  })
  assert.equal(response.status, 201)
  const { proof } = await response.json()
  assert.match(proof, /^[a-f0-9]{64}$/)
  await phone.route(origin + '/sign-in-fixture', route => route.fulfill({
    contentType: 'text/html',
    body: '<form method="post" action="' + url + '/webmail/auth/hosted"><input type="hidden" name="proof" value="' + proof + '"><button>Open Mail</button></form>',
  }))
  await phone.goto(origin + '/sign-in-fixture')
  await button(phone, 'Open Mail').click()
  await phone.waitForURL(url + '/login#hosted-factor')
  await checkFocus(phone, codeField(phone))
  await capture(phone, 'phone-hosted-factor')
  await codeField(phone).fill(codes[2])
  await button(phone, 'Verify and sign in').click()
  await phone.waitForURL(url + '/')
  const me = await phone.request.get(url + '/webmail/auth/me')
  assert.equal((await me.json()).user.username, owner)

  const mobile = await verificationSettings(phone)
  await button(mobile.section, 'Turn off two-step verification').click()
  await checkFocus(phone, codeField(mobile.section))
  await codeField(mobile.section).fill(codes[3])
  await button(mobile.section, 'Turn off verification').click()
  await mobile.section.getByText('Two-step verification is off.', { exact: true }).waitFor()
  assert.deepEqual(errors, [])
}
finally {
  await browser.close()
}
console.log(engine + ' passed desktop setup and phone login, linking, hosted handoff, and recovery.')
