/** The native test listener serves one request per connection. */
export function nativeFetch(url: URL, options: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...options, keepalive: false, cache: 'no-store' })
}
