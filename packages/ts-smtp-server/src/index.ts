import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { execSync } from 'node:child_process'

/**
 * Root of the Zig mail project (two levels up from packages/ts-smtp-server/src/)
 */
export const ZIG_PROJECT_ROOT = resolve(dirname(import.meta.dir), '..', '..')

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

export interface SmtpServerConfig {
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
 * Get the path to the smtp-server binary for a given platform/arch.
 * Checks the package's bin/ directory first, then falls back to zig-out/.
 */
export function getBinaryPath(platform?: Platform, arch?: Arch): string | null {
  const p = platform || detectPlatform()
  const a = arch || detectArch()
  const label = `${a}-${p}`

  // Check package bin/ directory first
  const packageBinary = join(BIN_DIR, `smtp-server-${label}`)
  if (existsSync(packageBinary))
    return packageBinary

  // Fall back to zig-out directory
  const zigOutPaths = [
    join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', label, `smtp-server-${label}`),
    join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', `smtp-server-${label}`),
  ]

  // For native platform, also check the default binary
  if (p === detectPlatform() && a === detectArch()) {
    zigOutPaths.push(join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', 'smtp-server'))
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
 * Build the smtp-server binary for a specific target.
 * Returns the path to the built binary.
 */
export function buildForTarget(
  target: string = 'x86_64-linux-gnu',
  optimize: string = 'ReleaseFast',
): string | null {
  try {
    console.log(`Building smtp-server for ${target}...`)
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
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', label, `smtp-server-${label}`),
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', `smtp-server-${label}`),
      join(ZIG_PROJECT_ROOT, 'zig-out', 'bin', 'smtp-server'),
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
 * Convert a SmtpServerConfig to environment variables.
 */
export function configToEnv(config: SmtpServerConfig): Record<string, string> {
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
