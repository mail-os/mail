import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { chromium, firefox, webkit } from 'playwright'

const { MAIL_CLIENT_PASSWORD_TEST_URL: url, MAIL_CLIENT_PASSWORD_TEST_OWNER: owner,
  MAIL_CLIENT_PASSWORD_TEST_PASSWORD: password, MAIL_CLIENT_PASSWORD_TEST_CERT: certificate } = process.env
const [name, output] = process.argv.slice(2)
const engines = { chromium, firefox, webkit }
assert(Object.hasOwn(engines, name) && output && owner && password && certificate)
assert.match(url, /^https:\/\/127\.0\.0\.1:\d+$/)
await mkdir(output, { recursive: true })

const options = {}
if (name === 'chromium') {
  const { publicKey } = new X509Certificate(await readFile(certificate))
  const pin = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
  options.args = [`--ignore-certificate-errors-spki-list=${pin}`]
}
const browser = await engines[name].launch(options)
try {
  for (const width of [1440, 320]) {
    const phone = width === 320
    const page = await browser.newPage({
      viewport: { width, height: 900 }, colorScheme: phone ? 'dark' : 'light',
      deviceScaleFactor: phone ? 2 : 1, hasTouch: phone, ignoreHTTPSErrors: name !== 'chromium',
    })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    page.setDefaultTimeout(15_000)
    await page.goto(url + '/login')
    await page.getByLabel('Email or username').fill(owner)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.waitForURL(url + '/')
    const accountButton = page.getByRole('button', { name: 'Account', exact: true })
    const mailboxes = page.getByRole('button', { name: 'Mailboxes', exact: true })
    if (phone) await mailboxes.click()
    await accountButton.click()
    const account = page.getByRole('dialog', { name: 'Account settings' })
    const passwords = account.getByRole('region', { name: 'App passwords' })
    await passwords.getByRole('button', { name: 'Manage app passwords' }).click()
    const type = passwords.getByLabel('Client type')
    await type.selectOption(phone ? 'dav' : 'exchange')
    assert(await type.evaluate((select) => {
      const style = getComputedStyle(select)
      const canvas = document.createElement('canvas').getContext('2d')
      canvas.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
      const room = select.clientWidth - Number.parseFloat(style.paddingLeft) - Number.parseFloat(style.paddingRight)
      return canvas.measureText(select.selectedOptions[0].text).width <= room
    }))
    assert(await account.evaluate(dialog => dialog.scrollWidth <= dialog.clientWidth + 1))
    const controls = await passwords.locator('form').evaluate(form => Array.from(form.querySelectorAll('input, select, button')).map((control) => {
      const style = getComputedStyle(control)
      return { height: control.getBoundingClientRect().height, color: style.borderTopColor, radius: style.borderTopLeftRadius }
    }))
    assert.equal(controls.length, 4)
    for (const control of controls) {
      assert(Math.abs(control.height - (phone ? 44 : 36)) < 0.05)
      assert.equal(control.color, controls[0].color)
      assert.equal(control.radius, controls[0].radius)
    }
    await passwords.screenshot({ path: join(output, `app-passwords-${name}-${width}.png`), animations: 'disabled' })
    const label = phone ? 'Phone calendar' : 'Office client'
    await passwords.getByLabel('App name').fill(label)
    await passwords.getByLabel('Mailbox password', { exact: true }).fill(password)
    await passwords.getByRole('button', { name: 'Create app password' }).click()
    const issued = passwords.getByLabel('Your app password')
    await issued.waitFor()
    assert.match(await issued.inputValue(), /^mailapp_[A-Za-z0-9_-]{32}$/)
    await account.getByRole('button', { name: 'Close', exact: true }).click()
    if (phone && !await accountButton.isVisible()) await mailboxes.click()
    await accountButton.click()
    await passwords.getByRole('button', { name: 'Manage app passwords' }).click()
    await passwords.getByRole('button', { name: 'Revoke ' + label, exact: true }).click()
    assert.equal(await issued.count(), 0)
    const confirmation = passwords.getByRole('group', { name: 'Confirm app password revocation' })
    await confirmation.getByRole('button', { name: 'Revoke app password' }).click()
    await passwords.getByText('App password revoked.', { exact: true }).waitFor()
    assert.equal(await passwords.getByRole('button', { name: 'Revoke ' + label, exact: true }).count(), 0)
    assert.deepEqual(errors, [])
    await page.close()
  }
}
finally { await browser.close() }
