/**
 * Charset label resolution.
 *
 * Mail carries charset labels that the WHATWG Encoding Standard never listed, so a
 * label is tried as written, then normalized, then looked up in an alias table before
 * falling back to windows-1252. Resolved decoders are cached: a message with many
 * encoded words otherwise constructs a TextDecoder per word, and constructing one
 * costs far more than decoding the handful of bytes it is handed.
 */

// Charset labels the WHATWG Encoding Standard does not list, but that name an encoding
// TextDecoder can decode. Without an entry the TextDecoder constructor throws and
// getDecoder falls back to windows-1252, turning the body into mojibake with nothing to
// signal that the wrong decoder was used.
//
// Keys are normalized (see normalizeCharset), so one entry covers every spelling of a
// label, eg. `eucjp` also catches `euc_jp`, `x-eucjp` and `x-euc-jp`. Only labels that
// need real encoding knowledge belong here; anything that differs from a supported
// label by nothing but an `x-` prefix or a separator is handled by normalization alone.
const charsetAliases = new Map<string, string>([
  // Hebrew. The logical and explicit ordering variants share the iso-8859-8 index.
  ['iso88598i', 'iso-8859-8'],
  ['iso88598e', 'iso-8859-8'],

  // Japanese. WHATWG shift_jis is the Windows-31J index, so cp932 text decodes
  // identically, including the NEC and IBM extension rows.
  ['shiftjis', 'shift_jis'],
  ['windows31j', 'shift_jis'],
  ['mskanji', 'shift_jis'],
  ['eucjp', 'euc-jp'],

  // ISO-2022-JP, including the -1 / -2 supersets. Escape sequences outside plain
  // ISO-2022-JP decode to replacement characters, but the Japanese text around them
  // still comes out right.
  ['iso2022jp', 'iso-2022-jp'],
  ['iso2022jp1', 'iso-2022-jp'],
  ['iso2022jp2', 'iso-2022-jp'],
  ['junet', 'iso-2022-jp'],

  // Korean. The WHATWG euc-kr index is the extended cp949 / UHC index.
  ['euckr', 'euc-kr'],
  ['uhc', 'euc-kr'],

  // Thai.
  ['tis620', 'windows-874'],
])

// Windows and IBM code page numbers, as written in labels like cp932, windows-932, ms932
// or ibm932. An explicit allowlist rather than a derived one, because plenty of code
// pages that appear in mail (cp437, cp850, cp1361) have no equivalent to map onto and
// have to keep falling back.
const codePageAliases = new Map<string, string>([
  ['932', 'shift_jis'],
  ['936', 'gbk'],
  ['949', 'euc-kr'],
  ['950', 'big5'],
  ['874', 'windows-874'],
  // Microsoft's EUC-JP and ISO-2022-JP variants. euc-jp and iso-2022-jp cover
  // everything they can express.
  ['51932', 'euc-jp'],
  ['50220', 'iso-2022-jp'],
  ['50221', 'iso-2022-jp'],
  ['50222', 'iso-2022-jp'],
])

const codePagePattern = /^(?:cp|windows|ms|ibm)(\d+)$/

// Strip the decorations mail clients add to an otherwise standard label: an x- vendor
// prefix, the IANA cs- prefix, and any separators.
function normalizeCharset(charset: string): string {
  return charset.replace(/^(?:x-ms-|x-|cs)/, '').replace(/[\s._-]+/g, '')
}

function tryDecoder(charset: string): TextDecoder | null {
  try {
    return new TextDecoder(charset)
  }
  catch {
    return null
  }
}

const decoderCache = new Map<string, TextDecoder>()

// A message may name a different unsupported charset in every part, and each miss
// leaves an entry behind. Bounded so the cache can not grow without limit.
const MAX_CACHED_DECODERS = 64

/**
 * Resolves a charset label to a decoder, falling back to windows-1252 the way mail
 * clients do when the label names nothing they know.
 */
export function getDecoder(charset?: string | null): TextDecoder {
  // The label as it was written is a cache key of its own, so a part that repeats the
  // same spelling skips the trim and the case fold entirely
  if (charset) {
    const direct = decoderCache.get(charset)
    if (direct)
      return direct
  }

  const label = (charset || 'utf8').trim().toLowerCase()

  const cached = decoderCache.get(label)
  if (cached) {
    if (charset && charset !== label)
      decoderCache.set(charset, cached)
    return cached
  }

  // Try the label as written first, so the alias table only ever adds to what the
  // runtime already supports instead of shadowing it.
  let decoder = tryDecoder(label)

  if (!decoder) {
    const normalized = normalizeCharset(label)
    const codePage = normalized.match(codePagePattern)

    // The normalized label is itself the last candidate, which resolves everything that
    // differed from a supported label only by a prefix or a separator, eg. x-big5.
    const alias = (codePage && codePageAliases.get(codePage[1])) || charsetAliases.get(normalized) || normalized

    decoder = tryDecoder(alias) || new TextDecoder('windows-1252')
  }

  if (decoderCache.size >= MAX_CACHED_DECODERS)
    decoderCache.clear()

  decoderCache.set(label, decoder)
  if (charset && charset !== label)
    decoderCache.set(charset, decoder)

  return decoder
}
