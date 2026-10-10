import { renderTemplate } from '@stacksjs/stx'
import { expect, test } from 'bun:test'
import { join } from 'node:path'

for (const page of ['login', 'index']) {
  test(`${page} compiles with STX bindings and a self-contained runtime`, async () => {
    const path = join(import.meta.dir, `pages/${page}.stx`)
    const source = await Bun.file(path).text()
    expect(source).not.toMatch(/\b(?:document|window)\./)
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
