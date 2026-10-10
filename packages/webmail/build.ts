/** Compile STX pages and embed their runtime and Crosswind CSS in the mail binary. */
import { renderTemplate } from '@stacksjs/stx'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export async function buildWebmail(): Promise<void> {
  const root = import.meta.dir
  const dist = join(root, '../zig/src/api/webmail_dist')
  await mkdir(dist, { recursive: true })
  for (const page of ['index', 'login']) {
    const html = await renderTemplate(join(root, `pages/${page}.stx`), { injectCSS: true })
    if (!html.includes('data-stx') || html.includes('<script client>'))
      throw new Error(`STX did not compile ${page}`)
    await writeFile(join(dist, `${page}.html`), html)
  }
  await writeFile(join(dist, 'styles.css'), await readFile(join(root, 'public/styles.css')))
}

if (import.meta.main) {
  buildWebmail().catch((error) => {
    // eslint-disable-next-line no-console
    console.error(error)
    process.exitCode = 1
  })
}
