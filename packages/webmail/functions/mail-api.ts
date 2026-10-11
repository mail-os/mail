import type { Upload } from './mail-types'

export class MailApiError extends Error {
  constructor(message: string, readonly status: number, readonly code: string) { super(message) }
}

export function createMailApi(account: () => string | undefined, onAuthError: (error: MailApiError) => void) {
  return async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers)
    const username = account()
    if (username) headers.set('X-Webmail-Account', encodeURIComponent(username))
    if (options.body && typeof options.body === 'string') headers.set('Content-Type', 'application/json')
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' })
    const result = await response.json().catch(() => ({}))
    if (!response.ok) {
      const error = new MailApiError(result.message || 'The request failed. Please try again.', response.status, result.code || result.error || 'request_failed')
      if (error.status === 401 || error.code === 'account_changed') onAuthError(error)
      throw error
    }
    return result as T
  }
}

/** Upload progress is distinct from the server acknowledgement at completion. */
export function uploadAttachment(file: File, account: string, progress: (value: number) => void, signal: AbortSignal, uploadId: string): Promise<Upload> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    const params = new URLSearchParams({ filename: file.name, contentType: file.type.split(';')[0].trim() || 'application/octet-stream', uploadId })
    request.open('POST', `/webmail/api/uploads?${params}`)
    request.withCredentials = true
    request.setRequestHeader('Content-Type', 'application/octet-stream')
    request.setRequestHeader('X-Webmail-Account', encodeURIComponent(account))
    request.upload.onprogress = event => { if (event.lengthComputable) progress(Math.min(100, Math.round(event.loaded / event.total * 100))) }
    const abort = () => request.abort()
    const cleanup = () => signal.removeEventListener('abort', abort)
    request.onload = () => {
      cleanup()
      let result: { message?: string, code?: string, error?: string } & Partial<Upload>
      try { result = JSON.parse(request.responseText) }
      catch { reject(new Error('The upload response could not be read. Retry this attachment.')); return }
      if (request.status < 200 || request.status >= 300) { reject(new MailApiError(result.message || 'Attachment upload failed.', request.status, result.code || result.error || 'upload_failed')); return }
      if (!result.uploadId || typeof result.size !== 'number') { reject(new Error('The server did not confirm this attachment.')); return }
      resolve(result as Upload)
    }
    request.onerror = () => { cleanup(); reject(new Error('Upload interrupted. Check your connection and retry.')) }
    request.onabort = () => { cleanup(); reject(new DOMException('Upload cancelled', 'AbortError')) }
    request.ontimeout = () => { cleanup(); reject(new Error('Upload timed out. Retry this attachment.')) }
    request.timeout = 180000
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) { cleanup(); reject(new DOMException('Upload cancelled', 'AbortError')); return }
    request.send(file)
  })
}
