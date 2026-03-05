import { serve } from 'bun'

const home = await Bun.file(new URL('./pages/home.stx', import.meta.url).pathname).text()

const LOCAL = process.env.LOCAL === '1' || process.env.LOCAL === 'true'
const INSTANCE_ID = process.env.INSTANCE_ID || 'i-0e365c6bd31da4678'
const DOMAIN = process.env.DOMAIN || 'mail.stacksjs.com'
const BASE_DOMAIN = DOMAIN.replace(/^[^.]*\./, '')
const DASH_USER = process.env.DASH_USER || 'admin'
const DASH_PASS = process.env.DASH_PASS || ''
const TLS_CERT = process.env.TLS_CERT || ''
const TLS_KEY = process.env.TLS_KEY || ''

function checkAuth(req: Request): Response | null {
  if (!DASH_PASS) return null // no password set = no auth required (local dev)

  const auth = req.headers.get('Authorization')
  if (!auth || !auth.startsWith('Basic ')) {
    return new Response('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Mail Dashboard"' },
    })
  }

  const decoded = atob(auth.slice(6))
  const [user, pass] = decoded.split(':')
  if (user !== DASH_USER || pass !== DASH_PASS) {
    return new Response('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Mail Dashboard"' },
    })
  }

  return null
}

async function shellRun(command: string): Promise<string> {
  const proc = Bun.spawn(['bash', '-c', command], { stdout: 'pipe', stderr: 'pipe' })
  const result = await new Response(proc.stdout).text()
  await proc.exited
  return result
}

async function ssmRun(commands: string[]): Promise<string> {
  if (LOCAL) {
    return shellRun(commands.join('\n'))
  }

  const proc = Bun.spawn([
    'aws', 'ssm', 'send-command',
    '--instance-ids', INSTANCE_ID,
    '--document-name', 'AWS-RunShellScript',
    '--parameters', JSON.stringify({ commands }),
    '--output', 'json',
    '--query', 'Command.CommandId',
  ], { stdout: 'pipe', stderr: 'pipe' })

  const cmdId = (await new Response(proc.stdout).text()).trim().replace(/"/g, '')
  await proc.exited

  for (let i = 0; i < 20; i++) {
    await Bun.sleep(1500)
    const check = Bun.spawn([
      'aws', 'ssm', 'get-command-invocation',
      '--command-id', cmdId,
      '--instance-id', INSTANCE_ID,
      '--query', '[Status,StandardOutputContent]',
      '--output', 'json',
    ], { stdout: 'pipe', stderr: 'pipe' })

    const raw = await new Response(check.stdout).text()
    await check.exited

    try {
      const [status, output] = JSON.parse(raw)
      if (status === 'Success') return output
      if (status === 'Failed') return `ERROR: Command failed`
    } catch {
      continue
    }
  }
  return 'ERROR: Timeout'
}

async function dnsLookup(type: string, name: string): Promise<string> {
  const proc = Bun.spawn(['dig', '+short', type, name, '@8.8.8.8'], { stdout: 'pipe', stderr: 'pipe' })
  const result = (await new Response(proc.stdout).text()).trim()
  await proc.exited
  return result
}

async function getServerStatus() {
  const output = await ssmRun([
    'echo "===SERVICE==="',
    'systemctl is-active mail 2>/dev/null || echo inactive',
    'echo "===UPTIME==="',
    'uptime -p 2>/dev/null || uptime',
    'echo "===UPTIME_SINCE==="',
    'systemctl show mail --property=ActiveEnterTimestamp --value 2>/dev/null',
    'echo "===USERS==="',
    'sqlite3 /opt/mail/smtp.db "SELECT username FROM users;" 2>/dev/null',
    'echo "===MAILBOXES==="',
    'ls -d /opt/mail/mail/*/ 2>/dev/null | grep -v "\\\\.$" | while read d; do echo "$(basename $d):$(find "$d" -name "*.eml" 2>/dev/null | wc -l)"; done',
    'echo "===DISK==="',
    'df -h / --output=pcent,size,used,avail | tail -1',
    'echo "===MEM==="',
    'free -m | grep Mem',
    'echo "===CPU==="',
    'top -bn1 | grep "Cpu(s)" | head -1',
    'echo "===PORTS==="',
    'ss -tlnp | grep mail-server',
    'echo "===SERVICES==="',
    'for s in mail fail2ban certbot-renew.timer mail-logrotate.timer; do echo "$s:$(systemctl is-active $s 2>/dev/null || echo inactive)"; done',
    'echo "===TLS==="',
    'certbot certificates 2>/dev/null | grep -E "Domains:|Expiry" || echo "no certbot"',
    'echo "===DB==="',
    'ls -lh /opt/mail/smtp.db 2>/dev/null | awk "{print \\\\$5}"',
    'sqlite3 /opt/mail/smtp.db "SELECT COUNT(*) FROM users;" 2>/dev/null',
  ])

  const sections: Record<string, string> = {}
  let currentKey = ''
  for (const line of output.split('\n')) {
    const match = line.match(/^===(\w+)===$/)
    if (match) {
      currentKey = match[1]
      sections[currentKey] = ''
    } else if (currentKey) {
      sections[currentKey] += (sections[currentKey] ? '\n' : '') + line
    }
  }

  const [mx, aRecord, spfRaw, dmarc, dkim] = await Promise.all([
    dnsLookup('MX', BASE_DOMAIN),
    dnsLookup('A', DOMAIN),
    dnsLookup('TXT', BASE_DOMAIN).then(r => r.split('\n').find(l => l.includes('spf')) || ''),
    dnsLookup('TXT', `_dmarc.${BASE_DOMAIN}`),
    dnsLookup('CNAME', `mail._domainkey.${BASE_DOMAIN}`).catch(() =>
      dnsLookup('CNAME', `*._domainkey.${BASE_DOMAIN}`).catch(() => '')
    ),
  ].map(p => p.catch(() => '')))

  const rdns = aRecord ? await dnsLookup('-x', aRecord).catch(() => '') : ''

  const users = (sections.USERS || '').split('\n').filter(Boolean)

  const mailboxLines = (sections.MAILBOXES || '').split('\n').filter(Boolean)
  let totalEmails = 0
  mailboxLines.forEach(l => {
    const count = parseInt(l.split(':')[1]) || 0
    totalEmails += count
  })

  const diskParts = (sections.DISK || '').trim().split(/\s+/)
  const diskPercent = diskParts[0]?.replace('%', '') || '0'
  const diskDetail = `${diskParts[2] || '?'} used / ${diskParts[1] || '?'} total (${diskParts[3] || '?'} free)`

  const memParts = (sections.MEM || '').trim().split(/\s+/)
  const memTotal = parseInt(memParts[1]) || 1
  const memUsed = parseInt(memParts[2]) || 0
  const memPercent = Math.round((memUsed / memTotal) * 100)

  const cpuMatch = (sections.CPU || '').match(/(\d+\.?\d*)\s*id/)
  const cpuIdle = parseFloat(cpuMatch?.[1] || '100')
  const cpuPercent = Math.round(100 - cpuIdle)

  const portMap: Record<number, string> = {
    25: 'SMTP', 465: 'SMTPS', 587: 'Submission',
    143: 'IMAP', 993: 'IMAPS',
    80: 'CalDAV', 443: 'CalDAV SSL',
  }
  const ports = (sections.PORTS || '').split('\n').filter(Boolean).map(line => {
    const portMatch = line.match(/:(\d+)\s/)
    const port = parseInt(portMatch?.[1] || '0')
    return { service: portMap[port] || `Port ${port}`, port, status: 'listening' }
  }).sort((a, b) => a.port - b.port)

  const services = (sections.SERVICES || '').split('\n').filter(Boolean).map(line => {
    const [name, status] = line.split(':')
    return { name: name?.replace('.timer', ''), active: status?.trim() === 'active' }
  })

  const tlsLines = (sections.TLS || '').split('\n').filter(Boolean)
  const tlsDomain = tlsLines.find(l => l.includes('Domains:'))?.replace(/.*Domains:\s*/, '').trim()
  const expiryLine = tlsLines.find(l => l.includes('Expiry'))
  const expiryMatch = expiryLine?.match(/(\d{4}-\d{2}-\d{2})/)
  const expiryDate = expiryMatch ? new Date(expiryMatch[1]) : null
  const daysLeft = expiryDate ? Math.ceil((expiryDate.getTime() - Date.now()) / 86400000) : 0

  const dbLines = (sections.DB || '').split('\n').filter(Boolean)
  const dbSize = dbLines[0] || '--'

  const deliverability = [
    { label: 'MX Record', pass: !!mx, warn: false },
    { label: 'A Record', pass: !!aRecord, warn: false },
    { label: 'Reverse DNS', pass: !!rdns, warn: !rdns },
    { label: 'SPF Record', pass: !!spfRaw, warn: false },
    { label: 'DMARC Policy', pass: !!dmarc, warn: false },
    { label: 'DKIM Signing', pass: !!dkim, warn: !dkim },
    { label: 'TLS Certificate', pass: daysLeft > 14, warn: daysLeft > 0 && daysLeft <= 14 },
  ]

  const uptimeRaw = (sections.UPTIME || '').trim()

  return {
    service: (sections.SERVICE || '').trim(),
    uptime: uptimeRaw.replace('up ', ''),
    uptimeSince: (sections.UPTIME_SINCE || '').trim(),
    userCount: users.length,
    users,
    mailboxCount: mailboxLines.length,
    emailCount: totalEmails,
    diskPercent,
    diskDetail,
    memPercent,
    memDetail: `${memUsed}MB / ${memTotal}MB`,
    cpuPercent,
    cpuDetail: `${cpuPercent}% utilized`,
    ports,
    services,
    tls: {
      valid: daysLeft > 0,
      domain: tlsDomain || DOMAIN,
      expiry: expiryMatch?.[1] || '--',
      daysLeft,
      issuer: "Let's Encrypt",
    },
    dns: {
      mx: mx || '--',
      a: aRecord || '--',
      rdns: rdns || '--',
      spf: spfRaw?.replace(/"/g, '') || '--',
      dmarc: dmarc?.replace(/"/g, '') || '--',
      dkim: dkim ? 'Configured (SES)' : '--',
    },
    deliverability,
    dbSize,
    dbDetail: `${dbLines[1] || '?'} users`,
  }
}

async function createAccount(username: string, password: string): Promise<{ ok: boolean, error?: string }> {
  if (!username || !password) return { ok: false, error: 'Username and password are required' }
  if (!/^[a-zA-Z0-9._-]+$/.test(username)) return { ok: false, error: 'Invalid username (alphanumeric, dots, hyphens, underscores only)' }
  if (password.length < 8) return { ok: false, error: 'Password must be at least 8 characters' }

  // Create user in database
  const email = `${username}@${BASE_DOMAIN}`
  const escapedPass = password.replace(/'/g, "'\\''")
  const userResult = await ssmRun([
    `cd /opt/mail && ./mail-server user:local create ${username} '${escapedPass}' ${email} 2>&1 || echo "FAIL"`,
  ])

  if (userResult.includes('FAIL') || userResult.includes('error') || userResult.includes('Error')) {
    return { ok: false, error: userResult.trim() || 'Failed to create user' }
  }

  // Create mailbox directories
  await ssmRun([
    `mkdir -p /opt/mail/mail/${username}/{INBOX,Sent,Drafts,Trash,Junk}/{cur,new,tmp}`,
    `chown -R mail-server:mail-server /opt/mail/mail/${username}`,
  ])

  return { ok: true }
}

let cache: { data: any, time: number } | null = null
const CACHE_TTL = 15000

const tlsOptions = TLS_CERT && TLS_KEY ? {
  tls: {
    cert: Bun.file(TLS_CERT),
    key: Bun.file(TLS_KEY),
  },
} : {}

const server = serve({
  port: parseInt(process.env.PORT || '3456'),
  ...tlsOptions,

  routes: {
    '/': {
      GET(req) {
        const denied = checkAuth(req)
        if (denied) return denied
        return new Response(home, { headers: { 'Content-Type': 'text/html' } })
      },
    },

    '/api/status': {
      async GET(req) {
        const denied = checkAuth(req)
        if (denied) return denied

        if (cache && Date.now() - cache.time < CACHE_TTL) {
          return Response.json(cache.data)
        }

        try {
          const data = await getServerStatus()
          cache = { data, time: Date.now() }
          return Response.json(data)
        } catch (e: any) {
          return Response.json({ error: e.message, service: 'unknown' }, { status: 500 })
        }
      },
    },

    '/api/account': {
      async POST(req) {
        const denied = checkAuth(req)
        if (denied) return denied

        try {
          const body = await req.json() as { username?: string, password?: string }
          const result = await createAccount(body.username || '', body.password || '')
          cache = null
          return Response.json(result, { status: result.ok ? 200 : 400 })
        } catch (e: any) {
          return Response.json({ ok: false, error: e.message }, { status: 500 })
        }
      },
    },
  },

  fetch(req) {
    const denied = checkAuth(req)
    if (denied) return denied
    return new Response('Not Found', { status: 404 })
  },
})

const proto = TLS_CERT ? 'https' : 'http'
console.log(`\n  Mail Server Dashboard`)
console.log(`  ${proto}://localhost:${server.port}/`)
console.log(`  Mode: ${LOCAL ? 'local' : 'remote (SSM)'}`)
console.log(`  Auth: ${DASH_PASS ? 'enabled' : 'disabled (no DASH_PASS set)'}`)
console.log(`  TLS:  ${TLS_CERT ? 'enabled' : 'disabled'}`)
console.log(`  Domain: ${DOMAIN}\n`)
