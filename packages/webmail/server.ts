/**
 * Webmail dev server.
 *
 * Uses bun-plugin-stx's programmatic `serve()` to render the .stx pages, and its
 * `onRequest` hook to proxy the JSON API (`/webmail/*`) to the Zig mail server.
 *
 * During development the Zig HTTP listener doesn't exist yet (see WEBMAIL.md
 * Phase 2), so proxied calls fall through to a labelled 502 — that's expected
 * until the backend is wired up. Everything else is handled by stx (file-based
 * routing over pages/, with layouts/ and partials/).
 *
 * Run: `bun run dev`
 */
import { serve } from 'bun-plugin-stx/serve'

const PORT = Number(process.env.PORT ?? 5173)
// Where the Zig server's HTTP API will live once Phase 2 lands.
const API_TARGET = process.env.API_TARGET ?? 'http://127.0.0.1:8080'

async function proxyToBackend(req: Request, url: URL): Promise<Response> {
  const target = new URL(url.pathname + url.search, API_TARGET)
  try {
    return await fetch(target, {
      method: req.method,
      headers: req.headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.arrayBuffer(),
      redirect: 'manual',
    })
  }
  catch {
    return Response.json(
      {
        error: 'backend_unreachable',
        message: `Zig mail API not reachable at ${API_TARGET}. Expected until WEBMAIL.md Phase 2 wires up the HTTP listener.`,
      },
      { status: 502 },
    )
  }
}

async function main(): Promise<void> {
  await serve({
    patterns: ['pages/'],
    port: PORT,
    partialsDir: 'partials',
    layoutsDir: 'layouts',
    publicDir: 'public',

    // Intercept the JSON API before stx handles routing; return null to let stx
    // render pages/static assets as normal.
    onRequest(req) {
      const url = new URL(req.url)
      if (url.pathname.startsWith('/webmail/api/') || url.pathname.startsWith('/webmail/auth/')) {
        return proxyToBackend(req, url)
      }
      return null
    },
  })

  // eslint-disable-next-line no-console
  console.log(`📬 webmail dev server on :${PORT}  →  proxying /webmail/* to ${API_TARGET}`)
}

main()
