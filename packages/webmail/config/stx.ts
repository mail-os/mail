import process from 'node:process'

/**
 * stx configuration for the webmail frontend.
 *
 * Folder layout (convention over configuration — defaults are relative to this file):
 *   pages/       file-based routes        (index.stx -> /, login.stx -> /login)
 *   layouts/     shared page shells
 *   components/  auto-imported components  (<MessageList />, etc.)
 *   partials/    @include() fragments
 *   functions/   composables / API client (useMailbox, useAuth, ...)
 *   public/      static assets served as-is
 *
 * Typed as `StxOptions` from the stx package once it's installed; kept loose here
 * so the scaffold typechecks before `bun install` runs.
 */
const config = {
  // SEO
  skipDefaultSeoTags: false,
  defaultTitle: 'Webmail',
  defaultDescription: 'Webmail client for the mail server',

  // Directories (explicit, even where they match defaults, so the layout is self-documenting)
  pagesDir: './pages',
  layoutsDir: './layouts',
  componentsDir: './components',
  partialsDir: './partials',
  publicDir: './public',

  // Dev vs prod
  debug: process.env.NODE_ENV !== 'production',
  cache: process.env.NODE_ENV === 'production',
}

export default config
