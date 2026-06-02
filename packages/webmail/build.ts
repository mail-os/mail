/**
 * Production build for the webmail frontend.
 *
 * The two pages (pages/index.stx, pages/login.stx) are self-contained HTML
 * documents — no @extends layouts, no stx directives, no {{ }} interpolation,
 * just inline <script>/<style> + an external /styles.css (see WEBMAIL.md and
 * the standalone-page note in each file). So the "build" is a faithful copy to
 * dist/ with .stx -> .html, NOT an stx render: we deliberately want the raw
 * HTML, free of the dev server's injected SEO/HMR/router scripts.
 *
 * Output goes INTO the Zig module so it can be embedded with @embedFile (which,
 * like @import, can't reach outside the module's directory):
 *   ../zig/src/api/webmail_dist/index.html   <- pages/index.stx
 *   ../zig/src/api/webmail_dist/login.html   <- pages/login.stx
 *   ../zig/src/api/webmail_dist/styles.css   <- public/styles.css
 *
 * The Zig build runs this automatically (see build.zig), so the embedded assets
 * are always fresh; the output dir is gitignored (generated, not source).
 *
 * Run directly: `bun run build` (from packages/webmail)
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
const dist = join(root, '..', 'zig', 'src', 'api', 'webmail_dist')

const copies: Array<[string, string]> = [
  [join(root, 'pages/index.stx'), join(dist, 'index.html')],
  [join(root, 'pages/login.stx'), join(dist, 'login.html')],
  [join(root, 'public/styles.css'), join(dist, 'styles.css')],
]

await mkdir(dist, { recursive: true })
for (const [src, out] of copies) {
  const body = await readFile(src, 'utf8')
  await writeFile(out, body)
  // eslint-disable-next-line no-console
  console.log(`built ${out}  (${body.length} bytes)`)
}
// eslint-disable-next-line no-console
console.log('webmail build complete → dist/')
