import { renderString, renderTemplate, transformAutoImports } from '@stacksjs/stx'
import { expect, test } from 'bun:test'
import { join } from 'node:path'
import { buildWebmail, stylesheetUrl, webmailAppAssets, webmailAppPages, webmailPages } from './build'

test('standalone stx script insertion preserves literal JavaScript replacement patterns', async () => {
  const text = '$&|$1|$$'
  const html = await renderString(`<!doctype html>
<html><head><title>Script fixture</title></head><body>
  <script client>const label = ${JSON.stringify(text)}</script>
  <p :text="label"></p>
</body></html>`)
  expect(html.includes(text)).toBe(true)
})

test('stx keeps dollar signs in minified runtime import aliases', () => {
  const source = 'import { derived as $$, state as $0 } from "@stacksjs/stx";\nconst value = $$(() => $0(1))'
  const transformed = transformAutoImports(source)
  expect(transformed.code).toContain('var $$ = derived, $0 = state;')
  expect(transformed.stxImports).toEqual(['derived', 'state'])
})

test('deployments fingerprint styles so existing browsers fetch updated controls', async () => {
  const first = new TextEncoder().encode('.wm-folders { display: none; }')
  const second = new TextEncoder().encode('.wm-folders { display: grid; }')
  expect(stylesheetUrl(first)).toBe(stylesheetUrl(first))
  expect(stylesheetUrl(first)).not.toBe(stylesheetUrl(second))
  await buildWebmail()
  for (const page of webmailPages) {
    const html = await Bun.file(join(import.meta.dir, `../zig/src/api/webmail_dist/${page}.html`)).text()
    expect(html).toMatch(/href="\/styles\.css\?v=[0-9a-f]{16}"/)
    expect(html.match(/<link\b[^>]*\brel="icon"[^>]*>/g)).toEqual([
      page === 'file-link'
        ? '<link rel="icon" href="data:,">'
        : '<link rel="icon" href="/mail-icon-192.png" sizes="192x192" type="image/png">',
    ])
    expect(html.includes('rel="manifest" href="/mail.webmanifest"')).toBe(webmailAppPages.has(page))
    expect(html.includes('rel="apple-touch-icon" href="/mail-icon-maskable.png"')).toBe(webmailAppPages.has(page))
  }
  for (const name of Object.keys(webmailAppAssets)) {
    const publicAsset = Bun.file(join(import.meta.dir, 'public', name))
    const embeddedAsset = Bun.file(join(import.meta.dir, '../zig/src/api/webmail_dist', name))
    expect(await embeddedAsset.bytes()).toEqual(await publicAsset.bytes())
  }
})

for (const page of webmailPages) {
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
    if (html.includes('__stxModules['))
      expect(html).toMatch(/<script\b[^>]*data-stx-modules/)
    expect(html).toContain('class="mail-icon"')
    if (page !== 'status')
      expect(html).toContain('class="mail-app-mark"')
    if (page === 'index') {
      expect(html).toContain('sandbox="allow-popups allow-popups-to-escape-sandbox"')
      expect(html).toContain('/webmail/auth/password')
      expect(html).toContain('/webmail/auth/recovery')
    }
    if (page === 'login')
      expect(html).toContain('href="/forgot"')
    if (page === 'recover') {
      expect(html).toContain('/webmail/auth/forgot')
      expect(html).toContain('/webmail/auth/reset/verify')
      expect(html).toContain('/webmail/auth/reset')
    }
  })
}
