/** Compile stx pages and embed their runtime and ts-css in the mail binary. */
import { renderTemplate } from '@stacksjs/stx'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Script } from 'node:vm'
import { calendarTimeZoneCatalog } from './build-calendar-timezones'

export function stylesheetUrl(styles: Uint8Array): string {
  const hash = new Bun.CryptoHasher('sha256').update(styles).digest('hex').slice(0, 16)
  return `/styles.css?v=${hash}`
}

export const webmailPages = ['index', 'login', 'recover', 'status', 'calendar', 'shared', 'combined', 'snapshot', 'file-link'] as const

export async function buildWebmail(): Promise<void> {
  const root = import.meta.dir
  const dist = join(root, '../zig/src/api/webmail_dist')
  const styles = await readFile(join(root, 'public/styles.css'))
  await mkdir(dist, { recursive: true })
  for (const page of webmailPages) {
    const html = await renderTemplate(join(root, `pages/${page}.stx`), { injectCSS: true })
    if (!html.includes('data-stx') || html.includes('<script client>'))
      throw new Error(`STX did not compile ${page}`)
    if (html.includes('__stxModules[')) {
      const registry = html.match(/<script\b[^>]*data-stx-modules[^>]*>([\s\S]*?)<\/script>/)
      if (!registry)
        throw new Error(`STX did not bundle the client module registry for ${page}`)
      new Script(registry[1], { filename: `${page}.html (stx module registry)` })
    }
    await writeFile(join(dist, `${page}.html`), html.replace('href="/styles.css"', `href="${stylesheetUrl(styles)}"`))
  }
  await writeFile(join(dist, 'styles.css'), styles)
  await writeFile(join(dist, 'mail-notifications.js'), await readFile(join(root, 'public/mail-notifications.js')))
  await writeFile(join(dist, 'calendar_timezones.ics'), calendarTimeZoneCatalog())
}

if (import.meta.main) {
  buildWebmail().catch((error) => {
    // eslint-disable-next-line no-console
    console.error(error)
    process.exitCode = 1
  })
}
