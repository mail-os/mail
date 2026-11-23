/** Compile stx pages and embed their runtime and ts-css in the mail binary. */
import { renderTemplate } from '@stacksjs/stx'
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Script } from 'node:vm'
import { calendarTimeZoneCatalog } from './build-calendar-timezones'

export function stylesheetUrl(styles: Uint8Array): string {
  const hash = new Bun.CryptoHasher('sha256').update(styles).digest('hex').slice(0, 16)
  return `/styles.css?v=${hash}`
}

export const webmailPages = ['index', 'login', 'recover', 'status', 'calendar', 'shared', 'combined', 'snapshot', 'file-link'] as const
export const webmailAppPages = new Set(['index', 'login', 'calendar', 'shared', 'combined'])
export const webmailAppAssets: Record<string, string> = {
  'mail.webmanifest': 'application/manifest+json; charset=utf-8',
  'mail-icon-192.png': 'image/png',
  'mail-icon-512.png': 'image/png',
  'mail-icon-maskable.png': 'image/png',
}

const webmailAppHead = [
  '<link rel="manifest" href="/mail.webmanifest">',
  '<link rel="icon" href="/mail-icon-192.png" sizes="192x192" type="image/png">',
  '<link rel="apple-touch-icon" href="/mail-icon-maskable.png">',
  '<meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme: light)">',
  '<meta name="theme-color" content="#191a1e" media="(prefers-color-scheme: dark)">',
].join('\n  ')

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
    const styled = html.replace('href="/styles.css"', `href="${stylesheetUrl(styles)}"`)
    const compiled = webmailAppPages.has(page) ? styled.replace('</head>', `  ${webmailAppHead}\n</head>`) : styled
    await writeFile(join(dist, `${page}.html`), compiled)
  }
  await writeFile(join(dist, 'styles.css'), styles)
  for (const name of ['mail-notifications.js', ...Object.keys(webmailAppAssets)])
    await copyFile(join(root, 'public', name), join(dist, name))
  await writeFile(join(dist, 'calendar_timezones.ics'), calendarTimeZoneCatalog())
}

if (import.meta.main) {
  buildWebmail().catch((error) => {
    // eslint-disable-next-line no-console
    console.error(error)
    process.exitCode = 1
  })
}
