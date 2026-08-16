import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { execSync } from 'node:child_process'

/**
 * Root of the sibling Zig mail package.
 */
export const ZIG_PROJECT_ROOT = resolve(import.meta.dir, '..', '..', 'zig')

/**
 * Directory containing pre-built binaries within this package
 */
export const BIN_DIR = join(import.meta.dir, '..', 'bin')

/**
 * Default SMTP server ports
 */
export const PORTS = {
  smtp: 25,
  smtps: 465,
  submission: 587,
  imap: 143,
  imaps: 993,
  pop3: 110,
  pop3s: 995,
} as const

export interface MailServerConfig {
  host?: string
  port?: number
  hostname?: string
  enableTls?: boolean
  tlsCert?: string
  tlsKey?: string
  enableAuth?: boolean
  dbPath?: string
  maxConnections?: number
  maxMessageSize?: number
  maxRecipients?: number
  rateLimitPerIp?: number
  rateLimitPerUser?: number
  logLevel?: 'debug' | 'info' | 'warn' | 'error'
  enableJsonLogging?: boolean
  mailboxPath?: string
  backupPath?: string
  profile?: 'development' | 'staging' | 'production'
}

type Platform = 'linux' | 'macos' | 'windows'
type Arch = 'x86_64' | 'aarch64'

function detectPlatform(): Platform {
  switch (process.platform) {
    case 'darwin': return 'macos'
    case 'win32': return 'windows'
    default: return 'linux'
  }
}

function detectArch(): Arch {
  return process.arch === 'arm64' ? 'aarch64' : 'x86_64'
}

/**
 * Get the path to the mail binary for a given platform/arch.
 * Checks the package's bin/ directory first, then falls back to zig-out/.
 */
export function getBinaryPath(platform?: Platform, arch?: Arch): string | null {
  const p = platform || detectPlatform()
  const a = arch || detectArch()
  const label = `${a}-${p}`

  // Check package bin/ directory first
  const packageBinary = join(BIN_DIR, `mail-${label}`)
  if (existsSync(packageBinary))
    return packageBinary

  // Fall back to zig-out directory
  const zigOutPaths = [
    join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', label, `mail-${label}`),
    join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', `mail-${label}`),
  ]

  // For native platform, also check the default binary
  if (p === detectPlatform() && a === detectArch()) {
    zigOutPaths.push(join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', 'mail'))
  }

  for (const path of zigOutPaths) {
    if (existsSync(path))
      return path
  }

  return null
}

/**
 * Get the path to the Linux binary for deployment to EC2.
 * This is the primary function used by the deploy script.
 */
export function getLinuxBinaryPath(arch: Arch = 'x86_64'): string | null {
  return getBinaryPath('linux', arch)
}

/**
 * Get the path to the Zig project source for building from source on the server.
 */
export function getSourcePath(): string {
  return ZIG_PROJECT_ROOT
}

/**
 * Build the mail binary for a specific target.
 * Returns the path to the built binary.
 */
export function buildForTarget(
  target: string = 'x86_64-linux-gnu',
  optimize: string = 'ReleaseFast',
): string | null {
  try {
    console.log(`Building mail for ${target}...`)
    execSync(`zig build -Doptimize=${optimize} -Dtarget=${target}`, {
      cwd: ZIG_PROJECT_ROOT,
      stdio: 'inherit',
    })

    // Determine the label from the target
    const parts = target.split('-')
    const arch = parts[0]
    const os = parts[1]
    const label = `${arch}-${os}`

    // Check possible output locations
    const possiblePaths = [
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', label, `mail-${label}`),
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', `mail-${label}`),
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', 'mail'),
    ]

    for (const path of possiblePaths) {
      if (existsSync(path))
        return path
    }

    return null
  }
  catch (error) {
    console.error(`Failed to build for ${target}:`, error)
    return null
  }
}

/**
 * Convert a MailServerConfig to environment variables.
 */
export function configToEnv(config: MailServerConfig): Record<string, string> {
  const env: Record<string, string> = {}

  if (config.host) env.SMTP_HOST = config.host
  if (config.port) env.SMTP_PORT = String(config.port)
  if (config.hostname) env.SMTP_HOSTNAME = config.hostname
  if (config.enableTls !== undefined) env.SMTP_ENABLE_TLS = String(config.enableTls)
  if (config.tlsCert) env.SMTP_TLS_CERT = config.tlsCert
  if (config.tlsKey) env.SMTP_TLS_KEY = config.tlsKey
  if (config.enableAuth !== undefined) env.SMTP_ENABLE_AUTH = String(config.enableAuth)
  if (config.dbPath) env.SMTP_DB_PATH = config.dbPath
  if (config.maxConnections) env.SMTP_MAX_CONNECTIONS = String(config.maxConnections)
  if (config.maxMessageSize) env.SMTP_MAX_MESSAGE_SIZE = String(config.maxMessageSize)
  if (config.maxRecipients) env.SMTP_MAX_RECIPIENTS = String(config.maxRecipients)
  if (config.rateLimitPerIp) env.SMTP_RATE_LIMIT_PER_IP = String(config.rateLimitPerIp)
  if (config.rateLimitPerUser) env.SMTP_RATE_LIMIT_PER_USER = String(config.rateLimitPerUser)
  if (config.logLevel) env.SMTP_LOG_LEVEL = config.logLevel
  if (config.enableJsonLogging !== undefined) env.SMTP_ENABLE_JSON_LOGGING = String(config.enableJsonLogging)
  if (config.mailboxPath) env.SMTP_MAILBOX_PATH = config.mailboxPath
  if (config.backupPath) env.SMTP_BACKUP_PATH = config.backupPath
  if (config.profile) env.SMTP_PROFILE = config.profile

  return env
}

export interface MailAdminClientOptions {
  baseUrl: string
  username?: string
  password?: string
  token?: string
  fetch?: typeof fetch
}

export interface MailboxUser {
  id?: number | string
  username: string
  email: string
  quota_mb?: number
  used_mb?: number
  enabled?: boolean
  created_at?: string
  last_login?: string
}

export interface CreateMailboxInput {
  username: string
  email: string
  password: string
  quota_mb?: number
}

export interface MailServerStats {
  messages_received?: number
  messages_sent?: number
  messages_queued?: number
  connections_active?: number
  [key: string]: unknown
}

export interface MailServerHealth {
  status: 'healthy' | 'degraded' | 'unhealthy'
  version?: string
  uptime?: number
  components?: Record<string, { status: string, message?: string }>
}

export class MailAdminError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message)
    this.name = 'MailAdminError'
  }
}

export class MailAdminClient {
  private baseUrl: string
  private username?: string
  private password?: string
  private token?: string
  private requestFetch: typeof fetch
  private csrfToken?: string

  constructor(options: MailAdminClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '')
    this.username = options.username
    this.password = options.password
    this.token = options.token
    this.requestFetch = options.fetch ?? fetch
  }

  private headers(mutating = false): Headers {
    const headers = new Headers({ Accept: 'application/json' })
    if (this.token) headers.set('Authorization', `Bearer ${this.token}`)
    else if (this.username && this.password) headers.set('Authorization', `Basic ${btoa(`${this.username}:${this.password}`)}`)
    if (mutating) headers.set('Content-Type', 'application/json')
    if (mutating && this.csrfToken) headers.set('X-CSRF-Token', this.csrfToken)
    return headers
  }

  private async csrf(): Promise<string> {
    if (this.csrfToken) return this.csrfToken
    const response = await this.requestFetch(`${this.baseUrl}/api/csrf-token`, { headers: this.headers() })
    const body = await this.readBody(response)
    if (!response.ok) throw new MailAdminError(response.status, 'Unable to acquire mail admin CSRF token', body)
    const record = body as Record<string, unknown>
    const token = String(record.csrf_token ?? record.token ?? '')
    if (!token) throw new MailAdminError(response.status, 'Mail admin returned an empty CSRF token', body)
    this.csrfToken = token
    return token
  }

  private async readBody(response: Response): Promise<unknown> {
    const text = await response.text()
    if (!text) return null
    try { return JSON.parse(text) }
    catch { return text }
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const method = String(init.method ?? 'GET').toUpperCase()
    const mutating = !['GET', 'HEAD'].includes(method)
    if (mutating) await this.csrf()
    const response = await this.requestFetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: this.headers(mutating),
    })
    const body = await this.readBody(response)
    if (!response.ok) {
      const message = typeof body === 'object' && body !== null && 'message' in body
        ? String((body as Record<string, unknown>).message)
        : `Mail admin request failed with HTTP ${response.status}`
      throw new MailAdminError(response.status, message, body)
    }
    return body as T
  }

  async listMailboxes(options: { offset?: number, limit?: number } = {}): Promise<{ users: MailboxUser[], total: number }> {
    const query = new URLSearchParams()
    if (options.offset !== undefined) query.set('offset', String(options.offset))
    if (options.limit !== undefined) query.set('limit', String(options.limit))
    const result = await this.request<{ users: MailboxUser[], total?: number, count?: number }>(`/api/users${query.size ? `?${query}` : ''}`)
    return { users: result.users, total: result.total ?? result.count ?? result.users.length }
  }

  async getMailbox(username: string): Promise<MailboxUser> {
    return this.request(`/api/users/${encodeURIComponent(username)}`)
  }

  async createMailbox(input: CreateMailboxInput): Promise<MailboxUser> {
    return this.request('/api/users', { method: 'POST', body: JSON.stringify(input) })
  }

  async updateMailbox(username: string, patch: Partial<Omit<CreateMailboxInput, 'username'>> & { enabled?: boolean }): Promise<MailboxUser> {
    return this.request(`/api/users/${encodeURIComponent(username)}`, { method: 'PUT', body: JSON.stringify(patch) })
  }

  async deleteMailbox(username: string): Promise<{ success: boolean, message?: string }> {
    return this.request(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' })
  }

  async ensureMailbox(input: CreateMailboxInput): Promise<{ mailbox: MailboxUser, created: boolean }> {
    try {
      return { mailbox: await this.getMailbox(input.username), created: false }
    }
    catch (error) {
      if (!(error instanceof MailAdminError) || error.status !== 404) throw error
      return { mailbox: await this.createMailbox(input), created: true }
    }
  }

  async stats(): Promise<MailServerStats> {
    return this.request('/api/stats')
  }

  async health(): Promise<MailServerHealth> {
    return this.request('/health')
  }

  async queue(options: { offset?: number, limit?: number, status?: string } = {}): Promise<unknown> {
    const query = new URLSearchParams(Object.entries(options).filter(([, value]) => value !== undefined).map(([key, value]) => [key, String(value)]))
    return this.request(`/api/queue${query.size ? `?${query}` : ''}`)
  }

  async getConfig(): Promise<Record<string, unknown>> {
    const result = await this.request<Record<string, unknown>>('/api/config')
    return typeof result.config === 'object' && result.config !== null
      ? result.config as Record<string, unknown>
      : result
  }

  async updateConfig(patch: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request('/api/config', { method: 'PUT', body: JSON.stringify(patch) })
  }

  async ensureDomain(domain: string): Promise<{ domain: string, configured: boolean }> {
    const normalized = domain.trim().toLowerCase()
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(normalized))
      throw new TypeError(`Invalid mail domain: ${domain}`)
    const config = await this.getConfig()
    const current = Array.isArray(config.extra_local_domains) ? config.extra_local_domains.map(String) : []
    if (current.includes(normalized)) return { domain: normalized, configured: false }
    await this.updateConfig({ extra_local_domains: [...current, normalized] })
    return { domain: normalized, configured: true }
  }
}

export function createMailAdminClient(options: MailAdminClientOptions): MailAdminClient {
  return new MailAdminClient(options)
}
