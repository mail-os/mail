import { existsSync, mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { execSync } from 'node:child_process'

// packages/ts and packages/zig are sibling packages in the mail workspace.
const zigProjectRoot = resolve(import.meta.dir, '..', 'zig')
const binDir = join(import.meta.dir, 'bin')

interface BuildOptions {
  target?: string
  optimize?: 'Debug' | 'ReleaseFast' | 'ReleaseSafe' | 'ReleaseSmall'
  all?: boolean
}

const TARGETS = {
  'x86_64-linux-gnu': 'x86_64-linux',
  'aarch64-linux-gnu': 'aarch64-linux',
  'x86_64-macos': 'x86_64-macos',
  'aarch64-macos': 'aarch64-macos',
} as const

function build(options: BuildOptions = {}): void {
  const optimize = options.optimize || 'ReleaseFast'

  mkdirSync(binDir, { recursive: true })

  if (options.all) {
    for (const [target, label] of Object.entries(TARGETS)) {
      console.log(`Building for ${label}...`)
      buildTarget(target, optimize, label)
    }
    return
  }

  if (options.target) {
    const label = TARGETS[options.target as keyof typeof TARGETS] || options.target
    console.log(`Building for ${label}...`)
    buildTarget(options.target, optimize, label)
    return
  }

  // Default: build for native platform
  console.log('Building for native platform...')
  execSync(`zig build -Doptimize=${optimize}`, {
    cwd: zigProjectRoot,
    stdio: 'inherit',
  })

  const nativeBinary = join(zigProjectRoot, 'zig-out', 'bin', 'mail')
  if (existsSync(nativeBinary)) {
    const platform = process.platform === 'darwin' ? 'macos' : 'linux'
    const arch = process.arch === 'arm64' ? 'aarch64' : 'x86_64'
    const dest = join(binDir, `mail-${arch}-${platform}`)
    execSync(`cp "${nativeBinary}" "${dest}"`)
    execSync(`chmod +x "${dest}"`)
    console.log(`Installed: ${dest}`)
  }
}

function buildTarget(target: string, optimize: string, label: string): void {
  try {
    execSync(`zig build -Doptimize=${optimize} -Dtarget=${target}`, {
      cwd: zigProjectRoot,
      stdio: 'inherit',
    })

    // Find the output binary - Zig places cross-compiled binaries in target-specific dirs
    const possiblePaths = [
      join(zigProjectRoot, 'zig-out', 'bin', label, `mail-${label}`),
      join(zigProjectRoot, 'zig-out', 'bin', `mail-${label}`),
      join(zigProjectRoot, 'zig-out', 'bin', 'mail'),
    ]

    for (const src of possiblePaths) {
      if (existsSync(src)) {
        const dest = join(binDir, `mail-${label}`)
        execSync(`cp "${src}" "${dest}"`)
        execSync(`chmod +x "${dest}"`)
        console.log(`Installed: ${dest}`)
        return
      }
    }

    console.warn(`Warning: Could not find built binary for ${label}`)
  }
  catch (error: any) {
    console.error(`Failed to build for ${label}: ${error.message}`)
  }
}

// Parse CLI args
const args = process.argv.slice(2)
const options: BuildOptions = {}

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--target' && args[i + 1]) {
    options.target = args[++i]
  }
  else if (args[i] === '--all') {
    options.all = true
  }
  else if (args[i] === '--optimize' && args[i + 1]) {
    options.optimize = args[++i] as BuildOptions['optimize']
  }
}

build(options)
