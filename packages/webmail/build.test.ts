import { renderTemplate } from '@stacksjs/stx'
import { expect, test } from 'bun:test'
import { join } from 'node:path'
import { buildWebmail, stylesheetUrl } from './build'

test('deployments fingerprint styles so existing browsers fetch updated controls', async () => {
  const first = new TextEncoder().encode('.wm-folders { display: none; }')
  const second = new TextEncoder().encode('.wm-folders { display: grid; }')
  expect(stylesheetUrl(first)).toBe(stylesheetUrl(first))
  expect(stylesheetUrl(first)).not.toBe(stylesheetUrl(second))
  await buildWebmail()
  for (const page of ['index', 'login']) {
    const html = await Bun.file(join(import.meta.dir, `../zig/src/api/webmail_dist/${page}.html`)).text()
    expect(html).toMatch(/href="\/styles\.css\?v=[0-9a-f]{16}"/)
  }
})

for (const page of ['login', 'index']) {
  test(`${page} compiles with STX bindings and a self-contained runtime`, async () => {
    const path = join(import.meta.dir, `pages/${page}.stx`)
    const source = await Bun.file(path).text()
    const clientScript = source.match(/<script client>([\s\S]*?)<\/script>/)?.[1]
    expect(clientScript).toBeDefined()
    expect(clientScript).not.toMatch(/\b(?:document|window)\./)
    const html = await renderTemplate(path, { injectCSS: true })
    expect(html).toContain('data-stx')
    expect(html).toContain('data-stx-runtime')
    expect(html).not.toContain('<script client>')
    expect(html).not.toContain('type="module" src=')
    expect(html).toContain('text-indigo-600')
    if (page === 'index') {
      expect(html).toContain('sandbox=""')
      expect(html).toContain('/webmail/auth/password')
    }
  })
}
