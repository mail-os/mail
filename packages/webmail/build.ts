/** Compile STX pages and embed their runtime and Crosswind CSS in the mail binary. */
import { renderTemplate } from '@stacksjs/stx'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export function stylesheetUrl(styles: Uint8Array): string {
  const hash = new Bun.CryptoHasher('sha256').update(styles).digest('hex').slice(0, 16)
  return `/styles.css?v=${hash}`
}

export async function buildWebmail(): Promise<void> {
  const root = import.meta.dir
  const dist = join(root, '../zig/src/api/webmail_dist')
  const styles = await readFile(join(root, 'public/styles.css'))
  await mkdir(dist, { recursive: true })
  for (const page of ['index', 'login']) {
    const html = await renderTemplate(join(root, `pages/${page}.stx`), { injectCSS: true })
    if (!html.includes('data-stx') || html.includes('<script client>'))
      throw new Error(`STX did not compile ${page}`)
    await writeFile(join(dist, `${page}.html`), html.replace('href="/styles.css"', `href="${stylesheetUrl(styles)}"`))
  }
  await writeFile(join(dist, 'styles.css'), styles)
}

if (import.meta.main) {
  buildWebmail().catch((error) => {
    // eslint-disable-next-line no-console
    console.error(error)
    process.exitCode = 1
  })
}
