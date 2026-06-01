/**
 * Production build placeholder.
 *
 * The serving model (embed in Zig binary vs. static assets vs. sidecar) is an
 * open decision — see WEBMAIL.md "Phase 9 — Production serving & deployment".
 * Until that's settled this just fails loudly rather than producing an
 * artifact nobody knows how to deploy.
 */
// eslint-disable-next-line no-console
console.error('webmail build: production build not implemented yet — see WEBMAIL.md Phase 9.')
process.exit(1)
