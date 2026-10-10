/** Development server uses the same STX build that ships in the mail binary. */
import { buildWebmail } from './build'

async function main(): Promise<void> {
  await buildWebmail()
  const dist = `${import.meta.dir}/../zig/src/api/webmail_dist`
  const target = process.env.API_TARGET ?? 'http://127.0.0.1:8080'
  Bun.serve({
    hostname: '127.0.0.1',
    port: Number(process.env.PORT ?? 5173),
    async fetch(request) {
      const url = new URL(request.url)
      if (url.pathname.startsWith('/webmail/api/') || url.pathname.startsWith('/webmail/auth/')) {
        try {
          return await fetch(new URL(url.pathname + url.search, target), {
            method: request.method,
            headers: request.headers,
            body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
            redirect: 'manual',
          })
        }
        catch { return Response.json({ message: 'Mail API is unavailable.' }, { status: 502 }) }
      }
      const assets: Record<string, string> = { '/': 'index.html', '/login': 'login.html', '/styles.css': 'styles.css' }
      const file = assets[url.pathname]
      return file ? new Response(Bun.file(`${dist}/${file}`)) : new Response('Not found', { status: 404 })
    },
  })
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error)
  process.exitCode = 1
})
