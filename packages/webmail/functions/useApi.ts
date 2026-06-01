/**
 * Tiny typed client for the webmail JSON API.
 *
 * Every call goes through here so CSRF handling, error shape, and the base path
 * live in one place. The endpoints it targets are defined in WEBMAIL.md
 * ("API Contract (draft)") and are implemented incrementally across phases.
 */

const BASE = '/webmail'

export interface ApiError {
  error: string
  message?: string
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    },
    ...init,
  })

  if (!res.ok) {
    let body: ApiError = { error: 'request_failed' }
    try {
      body = await res.json()
    }
    catch {
      // non-JSON error body; keep the default
    }
    throw Object.assign(new Error(body.message ?? body.error), { status: res.status, body })
  }

  return res.json() as Promise<T>
}

export const api = {
  // Auth (WEBMAIL.md Phase 1)
  me: () => request<{ user: { email: string, name?: string } }>('/auth/me'),
  login: (username: string, password: string) =>
    request<{ user: { email: string } }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),

  // Mailbox (WEBMAIL.md Phase 2)
  folders: () => request<Array<{ id: string, name: string, type: string, unread: number, total: number }>>('/api/folders'),
}
