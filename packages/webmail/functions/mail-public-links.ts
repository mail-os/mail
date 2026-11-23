export const linkLifetimes = [
  { seconds: 3600, label: '1 hour' }, { seconds: 86400, label: '24 hours' }, { seconds: 604800, label: '7 days' },
]

export interface SharedFile { filename: string, size: number, expires_at: number }

const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function linkDate(seconds: number): string {
  const time = new Date(seconds * 1000)
  return Number.isFinite(time.getTime()) ? formatter.format(time) : ''
}

export function reloadPublicLink(): void {
  globalThis.location.reload()
}

export async function openPublicLink<T>(path: string, token: string, signal: AbortSignal): Promise<T | null> {
  const response = await fetch(path, {
    method: 'POST', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
  })
  if (response.status === 404) return null
  if (!response.ok) throw new Error('Could not open this link.')
  return await response.json() as T
}

/** Promote only the file links Mail writes on their own lines in a message. */
export function linkedFilesInText(text: string): string[] {
  const links = new Set<string>()
  for (const line of text.split(/\r?\n/)) {
    const candidate = line.trim()
    if (!/^https?:\/\/\S+\/file-link#token=[a-f0-9]{64}$/.test(candidate)) continue
    try {
      const url = new URL(candidate)
      if (url.pathname === '/file-link' && !url.search && !url.username && !url.password) links.add(url.href)
    }
    catch { /* Leave malformed URLs as plain text. */ }
    if (links.size >= 20) break
  }
  return [...links]
}
