export interface EmbeddedImage { id: string, source: string }

const elements = new Set('a abbr b blockquote br caption center code dd del div dl dt em figcaption figure h1 h2 h3 h4 h5 h6 hr i img li mark ol p pre s small span strong sub sup table tbody td th thead tfoot tr u ul'.split(' '))
const discard = new Set('applet audio base button canvas embed form frame frameset head iframe input link math meta noscript object script select source style svg template textarea title track video'.split(' '))
const styles = [
  'background-color', 'border', 'border-bottom', 'border-collapse', 'border-color', 'border-radius',
  'border-top', 'color', 'font-family', 'font-size', 'font-style', 'font-weight', 'height', 'letter-spacing',
  'line-height', 'margin', 'margin-bottom', 'margin-top', 'max-width', 'padding', 'padding-bottom',
  'padding-top', 'text-align', 'text-decoration', 'vertical-align', 'white-space', 'width',
]
const block = new Set('br caption dd div dt figcaption h1 h2 h3 h4 h5 h6 hr li p td th tr'.split(' '))
const dataImage = /^data:image\/(?:avif|gif|jpeg|png|webp);base64,[\da-z+/]+={0,2}$/i
const maxImageLength = 4 * 1024 * 1024

function readerURL(value: string): URL | null {
  try {
    return new URL(value)
  }
  catch { return null }
}

function cid(value: string): string | null {
  try { return decodeURIComponent(value.slice(4)).replace(/^<|>$/g, '') }
  catch { return null }
}

function copyMessage(html: string, images: EmbeddedImage[], loadRemote: boolean, preview: boolean) {
  // Parse in an inert template and construct a fresh fragment. No input
  // elements or attributes are mounted in the top-level document.
  const input = document.createElement('template')
  const output = document.createElement('template')
  const inert = output.content.ownerDocument
  input.innerHTML = html.slice(0, preview ? 32_768 : 4 * 1024 * 1024)
  const inline = new Map(images.map(image => [image.id, image.source]))
  let remoteImages = 0
  let budget = 40_000

  function visit(source: Node, destination: Node, depth: number): void {
    if (--budget < 0 || depth > 64) return
    if (source.nodeType === 3) {
      destination.appendChild(inert.createTextNode(source.textContent || ''))
      return
    }
    if (!(source instanceof Element) || source.namespaceURI !== 'http://www.w3.org/1999/xhtml') return
    const tag = source.localName
    if (discard.has(tag) || source.hasAttribute('hidden') || source.getAttribute('aria-hidden') === 'true') return
    const style = (source as HTMLElement).style
    if (style.display === 'none' || style.visibility === 'hidden') return

    if (tag === 'img') {
      if (preview) return
      const raw = source.getAttribute('src')?.trim() || ''
      const url = readerURL(raw)
      const remote = url && ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url : null
      if (remote) remoteImages += 1
      const local = /^cid:/i.test(raw) ? inline.get(cid(raw) || '') : raw
      const safeSource = local && local.length <= maxImageLength && dataImage.test(local)
        ? local
        : loadRemote ? remote?.href : null
      const alt = source.getAttribute('alt') || ''
      if (safeSource) {
        const image = inert.createElement('img')
        image.alt = alt
        image.referrerPolicy = 'no-referrer'
        image.src = safeSource
        for (const key of ['width', 'height']) {
          const size = source.getAttribute(key) || ''
          if (/^[1-9]\d{0,3}$/.test(size)) image.setAttribute(key, size)
        }
        destination.appendChild(image)
      }
      else if (alt) {
        destination.appendChild(inert.createTextNode(alt))
      }
      return
    }

    const element = !preview && elements.has(tag) ? inert.createElement(tag) : null
    if (element) {
      for (const name of styles) {
        const value = style.getPropertyValue(name)
        const color = /^(?:rgba?|hsla?)\([\d .,/%+-]+\)$/i.test(value)
        if (value && value.length < 250 && (color || !/[\\()]|@/.test(value)))
          element.style.setProperty(name, value)
      }
      for (const key of ['colspan', 'rowspan']) {
        const size = source.getAttribute(key) || ''
        if ((tag === 'td' || tag === 'th') && /^[1-9]\d?$/.test(size)) element.setAttribute(key, size)
      }
      if (tag === 'a') {
        const url = readerURL(source.getAttribute('href') || '')
        if (url && ['https:', 'http:', 'mailto:'].includes(url.protocol) && !url.username && !url.password) {
          element.setAttribute('href', url.href)
          element.setAttribute('target', '_blank')
          element.setAttribute('rel', 'noopener noreferrer')
          element.setAttribute('referrerpolicy', 'no-referrer')
        }
      }
      destination.appendChild(element)
    }
    for (const child of source.childNodes) visit(child, element || destination, depth + 1)
    if (preview && block.has(tag)) destination.appendChild(inert.createTextNode(' '))
  }

  for (const child of input.content.childNodes) visit(child, output.content, 0)
  return { output, remoteImages }
}

export function renderMailReader(html: string, images: EmbeddedImage[] = [], loadRemote = false) {
  if (!html) return { source: '', remoteImages: 0 }
  const { output, remoteImages } = copyMessage(html, images, loadRemote, false)
  const sources = loadRemote ? 'data: https: http:' : 'data:'
  const policy = "default-src 'none'; img-src " + sources + "; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
  const source = '<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
    + '<meta http-equiv="Content-Security-Policy" content="' + policy + '">'
    + '<style>body{margin:14px 16px;font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,sans-serif;color:#202126;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{max-width:100%}</style>'
    + output.innerHTML
  return { source, remoteImages }
}

export function receiptExcerpt(text: string, html: string): string {
  const plain = text.trim()
  if (plain || !html) return plain.slice(0, 320)
  const { output } = copyMessage(html, [], false, true)
  return (output.content.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 320)
}
