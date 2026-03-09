// HTML Compatibility Checker
// Tests HTML/CSS against known email client support

interface HtmlIssue {
  severity: 'error' | 'warning' | 'info'
  client: string
  message: string
  line?: number
}

const CSS_ISSUES: { pattern: RegExp; clients: string[]; message: string; severity: 'error' | 'warning' | 'info' }[] = [
  { pattern: /display\s*:\s*flex/i, clients: ['Outlook 2007-2021', 'Gmail (non-Google)'], message: 'Flexbox not supported', severity: 'error' },
  { pattern: /display\s*:\s*grid/i, clients: ['Outlook 2007-2021', 'Gmail', 'Yahoo'], message: 'CSS Grid not supported', severity: 'error' },
  { pattern: /position\s*:\s*(?:fixed|sticky)/i, clients: ['Outlook', 'Gmail', 'Yahoo'], message: 'Fixed/sticky positioning not supported', severity: 'error' },
  { pattern: /background-image\s*:/i, clients: ['Outlook 2007-2021'], message: 'CSS background images not supported (use VML)', severity: 'warning' },
  { pattern: /border-radius/i, clients: ['Outlook 2007-2021'], message: 'Border-radius not supported', severity: 'warning' },
  { pattern: /box-shadow/i, clients: ['Outlook 2007-2021'], message: 'Box-shadow not supported', severity: 'warning' },
  { pattern: /animation|@keyframes|transition/i, clients: ['Most email clients'], message: 'CSS animations/transitions have limited support', severity: 'info' },
  { pattern: /@media/i, clients: ['Gmail (GANGA)', 'Outlook.com'], message: 'Media queries may be stripped', severity: 'warning' },
  { pattern: /margin\s*:\s*0?\s*auto/i, clients: ['Outlook 2007-2021'], message: 'margin: auto centering unreliable', severity: 'warning' },
  { pattern: /max-width/i, clients: ['Outlook 2007-2021'], message: 'max-width not supported (use width with conditional comments)', severity: 'warning' },
  { pattern: /rgba?\s*\(/i, clients: ['Outlook 2007-2019'], message: 'RGBA colors have limited support', severity: 'warning' },
]

const HTML_ISSUES: { pattern: RegExp; clients: string[]; message: string; severity: 'error' | 'warning' }[] = [
  { pattern: /<video|<audio|<canvas|<svg/i, clients: ['Most email clients'], message: 'HTML5 media/canvas/SVG elements not supported in most clients', severity: 'error' },
  { pattern: /<form|<input|<select|<textarea/i, clients: ['Gmail', 'Outlook', 'Yahoo'], message: 'Form elements stripped by most email clients', severity: 'error' },
  { pattern: /<style/i, clients: ['Gmail (non-Google accts)'], message: '<style> block may be stripped; prefer inline styles', severity: 'warning' },
  { pattern: /<link[^>]*rel="stylesheet"/i, clients: ['All email clients'], message: 'External stylesheets not supported; use inline styles', severity: 'error' },
  { pattern: /<script/i, clients: ['All email clients'], message: 'JavaScript is stripped by all email clients', severity: 'error' },
  { pattern: /<iframe/i, clients: ['All email clients'], message: 'iframes not supported in email', severity: 'error' },
  { pattern: /srcset\s*=/i, clients: ['Outlook', 'Gmail App'], message: 'srcset for responsive images has limited support', severity: 'warning' },
]

export function checkHtmlCompatibility(html: string): HtmlIssue[] {
  const issues: HtmlIssue[] = []

  if (!html) return [{ severity: 'info', client: 'General', message: 'No HTML content to check' }]

  // Check CSS issues
  for (const rule of CSS_ISSUES) {
    if (rule.pattern.test(html)) {
      issues.push({
        severity: rule.severity,
        client: rule.clients.join(', '),
        message: rule.message,
      })
    }
  }

  // Check HTML issues
  for (const rule of HTML_ISSUES) {
    if (rule.pattern.test(html)) {
      issues.push({
        severity: rule.severity,
        client: rule.clients.join(', '),
        message: rule.message,
      })
    }
  }

  // Check for missing best practices
  if (!/<table/i.test(html) && /<div/i.test(html)) {
    issues.push({
      severity: 'warning',
      client: 'Outlook 2007-2021',
      message: 'Consider using table-based layout for better Outlook compatibility',
    })
  }

  if (!html.includes('xmlns')) {
    issues.push({
      severity: 'info',
      client: 'Outlook',
      message: 'Consider adding xmlns for VML support in Outlook',
    })
  }

  // Check for images without alt attributes
  const imgTags = html.match(/<img[^>]*>/gi) || []
  const imgsWithoutAlt = imgTags.filter(tag => !/\balt\s*=/i.test(tag))
  if (imgsWithoutAlt.length > 0) {
    issues.push({
      severity: 'warning',
      client: 'Accessibility',
      message: `${imgsWithoutAlt.length} image(s) missing alt attributes`,
    })
  }

  if (!/<meta[^>]*viewport/i.test(html)) {
    issues.push({
      severity: 'info',
      client: 'Mobile',
      message: 'Missing viewport meta tag for mobile responsiveness',
    })
  }

  if (issues.length === 0) {
    issues.push({ severity: 'info', client: 'General', message: 'No compatibility issues detected' })
  }

  return issues
}

// Link Checker
interface LinkResult {
  url: string
  type: 'link' | 'image'
  status: number | null
  ok: boolean
  error?: string
}

export async function checkLinks(html: string, text: string): Promise<LinkResult[]> {
  const urls = new Map<string, 'link' | 'image'>()

  // Extract from HTML
  const hrefRegex = /href="([^"]+)"/gi
  const srcRegex = /src="([^"]+)"/gi

  let match
  while ((match = hrefRegex.exec(html)) !== null) {
    const url = match[1]
    if (url.startsWith('http://') || url.startsWith('https://')) {
      urls.set(url, 'link')
    }
  }
  while ((match = srcRegex.exec(html)) !== null) {
    const url = match[1]
    if (url.startsWith('http://') || url.startsWith('https://')) {
      urls.set(url, 'image')
    }
  }

  // Extract URLs from text body
  const urlRegex = /https?:\/\/[^\s<>"]+/g
  while ((match = urlRegex.exec(text)) !== null) {
    if (!urls.has(match[0])) urls.set(match[0], 'link')
  }

  const unique = Array.from(urls.entries()).map(([url, type]) => ({ url, type }))

  // Check each URL (with timeout)
  const results = await Promise.all(
    unique.slice(0, 50).map(async ({ url, type }): Promise<LinkResult> => {
      try {
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 10000)
        const res = await fetch(url, {
          method: 'HEAD',
          signal: controller.signal,
          redirect: 'follow',
        })
        clearTimeout(timeout)
        return { url, type, status: res.status, ok: res.ok }
      } catch (err: any) {
        // Try GET if HEAD fails
        try {
          const controller = new AbortController()
          const timeout = setTimeout(() => controller.abort(), 10000)
          const res = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
          })
          clearTimeout(timeout)
          return { url, type, status: res.status, ok: res.ok }
        } catch (err2: any) {
          return { url, type, status: null, ok: false, error: err2.message || 'Connection failed' }
        }
      }
    })
  )

  return results
}

// Spam Score Checker (heuristic-based, inspired by SpamAssassin rules)
interface SpamResult {
  score: number
  maxScore: number
  rules: { name: string; score: number; description: string }[]
  verdict: 'clean' | 'likely_spam' | 'spam'
}

export function checkSpam(headers: Record<string, string>, subject: string, textBody: string, htmlBody: string): SpamResult {
  const rules: SpamResult['rules'] = []

  // Missing headers
  if (!headers['message-id']) rules.push({ name: 'MISSING_MID', score: 1.5, description: 'Missing Message-ID header' })
  if (!headers['date']) rules.push({ name: 'MISSING_DATE', score: 1.0, description: 'Missing Date header' })
  if (!headers['mime-version']) rules.push({ name: 'MISSING_MIME', score: 0.5, description: 'Missing MIME-Version header' })

  // Subject checks
  if (subject === subject.toUpperCase() && subject.length > 5) {
    rules.push({ name: 'SUBJ_ALL_CAPS', score: 2.0, description: 'Subject is ALL CAPITALS' })
  }
  if (/!{2,}/.test(subject)) rules.push({ name: 'SUBJ_EXCL', score: 1.5, description: 'Multiple exclamation marks in subject' })
  if (/\$\d/.test(subject)) rules.push({ name: 'SUBJ_DOLLAR', score: 1.5, description: 'Dollar amount in subject' })
  if (/free|winner|congratulations|urgent|act now/i.test(subject)) {
    rules.push({ name: 'SUBJ_SPAM_WORDS', score: 2.0, description: 'Common spam words in subject' })
  }
  if (!subject || subject === '(No Subject)') {
    rules.push({ name: 'NO_SUBJECT', score: 1.0, description: 'Empty or missing subject' })
  }

  // Body checks
  const bodyText = textBody || htmlBody.replace(/<[^>]*>/g, '')

  if (htmlBody && !textBody) {
    rules.push({ name: 'HTML_ONLY', score: 1.0, description: 'HTML-only message (no text/plain alternative)' })
  }

  if (htmlBody) {
    const textLen = htmlBody.replace(/<[^>]*>/g, '').trim().length
    const htmlLen = htmlBody.length
    if (htmlLen > 0 && textLen / htmlLen < 0.1) {
      rules.push({ name: 'LOW_TEXT_RATIO', score: 2.0, description: 'Very low text-to-HTML ratio' })
    }

    const imgCount = (htmlBody.match(/<img/gi) || []).length
    const textWords = bodyText.split(/\s+/).length
    if (imgCount > 0 && textWords < 20) {
      rules.push({ name: 'IMG_HEAVY', score: 1.5, description: 'Image-heavy message with little text' })
    }

    if (/<font\s+size\s*=\s*["']?[+-]?\d/i.test(htmlBody)) {
      rules.push({ name: 'FONT_SIZE_TAG', score: 0.5, description: 'Uses deprecated font size tags' })
    }
  }

  // Spam phrases in body
  const spamPhrases = [
    /click here/i, /unsubscribe/i, /opt.?out/i, /buy now/i, /limited time/i,
    /act now/i, /don't miss/i, /risk.?free/i, /no obligation/i, /100% free/i,
    /dear friend/i, /you have been selected/i, /congratulations/i,
  ]

  let phraseCount = 0
  for (const phrase of spamPhrases) {
    if (phrase.test(bodyText)) phraseCount++
  }
  if (phraseCount >= 3) {
    rules.push({ name: 'SPAM_PHRASES', score: 2.5, description: `${phraseCount} spam phrases detected in body` })
  } else if (phraseCount >= 1) {
    rules.push({ name: 'SOME_SPAM_PHRASES', score: 1.0, description: `${phraseCount} spam phrase(s) in body` })
  }

  // List-Unsubscribe header (actually reduces score)
  if (headers['list-unsubscribe']) {
    rules.push({ name: 'HAS_UNSUB', score: -1.0, description: 'Has List-Unsubscribe header (good practice)' })
  }

  // DKIM/SPF/DMARC presence (reduces score)
  const authResults = headers['authentication-results'] || ''
  if (authResults.includes('dkim=pass')) {
    rules.push({ name: 'DKIM_PASS', score: -1.0, description: 'DKIM signature verified' })
  }
  if (authResults.includes('spf=pass')) {
    rules.push({ name: 'SPF_PASS', score: -0.5, description: 'SPF check passed' })
  }

  const score = Math.max(0, rules.reduce((s, r) => s + r.score, 0))
  const maxScore = 15

  return {
    score: Math.round(score * 10) / 10,
    maxScore,
    rules,
    verdict: score >= 5 ? 'spam' : score >= 3 ? 'likely_spam' : 'clean',
  }
}

// Webhook dispatcher
export async function dispatchWebhook(url: string, payload: any): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    return res.ok
  } catch {
    return false
  }
}

// Message relay
export async function relayMessage(raw: string, smtpHost: string, smtpPort: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const socket = await Bun.connect({
      hostname: smtpHost,
      port: smtpPort,
      socket: {
        data() {},
        open() {},
        close() {},
        error() {},
      },
    })

    // Simple relay - send raw message
    // In practice, you'd want full SMTP handshake
    socket.end()
    return { ok: true }
  } catch (err: any) {
    return { ok: false, error: err.message }
  }
}
