interface MailEventLink {
  account: string
  reference: string
}

// Fragments keep private message references out of navigation requests.
export function mailEventLink(path: '/' | '/calendar', account: string, reference: string): string {
  return `${path}#${new URLSearchParams({ account, message: reference })}`
}

export function takeMailEventLink(path: '/' | '/calendar'): MailEventLink | null {
  if (!globalThis.location?.href) return null
  const page = new URL(globalThis.location.href)
  if (page.pathname !== path) return null
  const fragment = new URLSearchParams(page.hash.slice(1))
  const account = fragment.get('account')
  const reference = fragment.get('message')
  if (!account || !reference || !/^[\da-f]{32}$/i.test(reference)) return null
  page.hash = ''
  globalThis.history.replaceState(null, '', page.href)
  return { account, reference }
}
