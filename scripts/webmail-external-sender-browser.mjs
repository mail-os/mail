import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_BROWSER_URL: url, MAIL_BROWSER_OWNER: owner, MAIL_BROWSER_SENDER: address, MAIL_BROWSER_PASSWORD: password } = process.env
const [engine, output] = process.argv.slice(2)
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
const browser = await { chromium, firefox, webkit }[engine].launch()
const errors = []
let page
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
await mkdir(output, { recursive: true })

async function verifyReviewLayout(review) {
  await review.evaluate(element => {
    const panel = element.getBoundingClientRect()
    const composer = element.closest('.wm-composer')
    const header = composer.querySelector('.wm-composer-head').getBoundingClientRect()
    const footer = composer.querySelector('.wm-composer-foot').getBoundingClientRect()
    if (panel.top < header.bottom || panel.bottom > footer.top) throw new Error('The review must fit between the sticky header and footer')
  })
}

try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 940 }, ignoreHTTPSErrors: true })
  page = await context.newPage()
  page.setDefaultTimeout(12_000)
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(url + '/login')
  await page.getByLabel('Email or username').fill(owner)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await button(page, 'Sign in').click()
  await button(page, 'Account').click()
  const settings = page.getByRole('dialog', { name: 'Account settings' })
  const external = settings.getByRole('region', { name: 'External From addresses' })
  await external.getByLabel('Address', { exact: true }).waitFor()
  await button(external, 'Send verification code').click()

  const other = await browser.newContext({ ignoreHTTPSErrors: true })
  let code
  try {
    const login = await other.request.post(url + '/webmail/auth/login', { headers: { Origin: url }, data: { username: address, password } })
    assert(login.ok(), 'Verification mailbox login')
    for (let i = 0; i < 40 && !code; i++) {
      const list = await other.request.get(url + '/webmail/api/messages?conversations=false')
      const mail = (await list.json()).items.find(item => item.subject === 'Verify an external From address')
      if (mail) {
        const reader = await other.request.get(url + '/webmail/api/messages/' + mail.uid)
        code = (await reader.json()).text.match(/^[a-f0-9]{32}\s*$/m)?.[0]?.trim()
      }
      if (!code) await new Promise(resolve => setTimeout(resolve, 150))
    }
  }
  finally { await other.close() }
  assert(code, 'Verification code arrived in the addressed mailbox')
  await external.getByLabel('Code sent to this address').fill(code)
  await button(external, 'Verify address').click()
  await external.getByText('From address verified.', { exact: true }).waitFor()
  await external.screenshot({ path: join(output, 'external-from-settings.png'), animations: 'disabled' })
  await button(settings, 'Close').click()

  await button(page, 'Compose').click()
  const composer = page.getByRole('dialog', { name: 'Compose message' })
  await composer.getByLabel('From', { exact: true }).selectOption({ label: address })
  for (const [field, recipient] of Object.entries({ To: 'reader@destination.example', Cc: 'reviewer@destination.example', Bcc: 'blind@destination.example' })) {
    if (field !== 'To') await button(composer, 'Add ' + field).click()
    const input = composer.getByRole('combobox', { name: field, exact: true })
    await input.fill(recipient)
    await input.press('Enter')
  }
  await composer.getByLabel('Subject', { exact: true }).fill('Browser external SMTP review')
  await composer.getByLabel('Message body').fill('The signed-in Mail account is sending through an approved provider.')
  await button(composer, 'Review send').click()
  const review = composer.getByRole('region', { name: 'Review send' })
  await review.getByText(owner, { exact: true }).waitFor()
  await review.getByText(address, { exact: true }).waitFor()
  for (const recipient of ['reader@destination.example', 'reviewer@destination.example', 'blind@destination.example']) {
    await review.getByText(recipient, { exact: true }).waitFor()
  }
  const saved = await page.request.get(url + '/webmail/api/outbox')
  assert(saved.ok())
  assert.deepEqual(await saved.json(), [], 'Reviewing the envelope must leave Outbox empty')
  await verifyReviewLayout(review)
  await review.screenshot({ path: join(output, 'desktop-external-send-review.png'), animations: 'disabled' })

  await button(composer, 'Remove recipient blind@destination.example').click()
  const blindCopy = composer.getByRole('combobox', { name: 'Bcc', exact: true })
  await blindCopy.fill('updated@destination.example')
  await blindCopy.press('Enter')
  await review.waitFor({ state: 'hidden' })
  await page.setViewportSize({ width: 320, height: 844 })
  await page.emulateMedia({ colorScheme: 'dark' })
  await button(composer, 'Review send').click()
  await review.getByText('updated@destination.example', { exact: true }).waitFor()
  await verifyReviewLayout(review)
  await review.screenshot({ path: join(output, 'phone-external-send-review.png'), animations: 'disabled' })
  await composer.getByLabel('Undo Send delay').selectOption('0')
  await button(composer, 'Send').click()
  await composer.waitFor({ state: 'hidden' })
  assert.deepEqual(errors, [])
  process.stdout.write(engine + ' verified external From settings, recipient review, and sending.\n')
}
catch (cause) {
  if (errors.length) process.stderr.write(errors.join('\n') + '\n')
  await page?.screenshot({ path: join(output, 'external-sender-failure.png'), animations: 'disabled' }).catch(() => {})
  throw cause
}
finally {
  await browser.close()
}
