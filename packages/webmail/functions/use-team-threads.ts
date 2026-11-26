import { state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface Grant {
  id: string
  team: string
  owner: string
  grantee: string
  searchAllowed: boolean
  commentsAllowed: boolean
  subject: string
  downloads: boolean
  followingAuthors: string[]
  followingSentReplies: boolean
  replyLimitReached: boolean
  collectionId: string | null
}
interface Attachment { index: number, filename: string, size: number }
interface Message {
  reference: string
  subject: string
  from: string
  timestamp: number
  text: string
  attachments: Attachment[]
  verifiedReply?: boolean
  sentReply?: boolean
  truncated?: boolean
}
interface Preview { messages: Message[], digest: string, followingAuthors: string[], collection?: { name: string }, next?: number | null }
interface Detail { grant: Grant, messages: Message[], comments: { author: string, writtenAt: number, text: string }[], next: number | null }
interface Team { id: string, name: string }
const endpoint = '/webmail/api/thread-shares'

export function teamThreadAttachment(grant: Grant, message: Message, part: Attachment) {
  return `${endpoint}/${encodeURIComponent(grant.id)}/attachments/${encodeURIComponent(message.reference)}/${part.index}`
}

export function useTeamThreads(api: ReturnType<typeof createMailApi>) {
  const teamThreadMode = state<'preview' | 'list' | 'detail' | null>(null)
  const teamThreadBusy = state(false)
  const teamThreadError = state('')
  const teamThreadNotice = state('')
  const teamThreadPreview = state<Preview | null>(null)
  const teamThreadGrants = state<Grant[]>([])
  const teamThreadDetail = state<Detail | null>(null)
  const teamThreadTeams = state<Team[]>([])
  const teamThreadTeam = state('')
  const teamThreadGrantee = state('')
  const teamThreadDownloads = state(false)
  const teamThreadFollowReplies = state(false)
  const teamThreadFollowSentReplies = state(false)
  const teamThreadSearch = state('')
  const teamThreadComment = state('')
  const teamThreadRevoking = state<Grant | null>(null)
  const teamThreadCollection = state('')
  const teamThreadPages = state<(number | null)[]>([null])
  let appliedSearch = ''
  let collectionScope = ''
  let references: string[] = []
  let request: AbortController | null = null

  function closeTeamThreads() {
    request?.abort()
    request = null
    references = []
    teamThreadMode.set(null)
    teamThreadBusy.set(false)
    teamThreadError.set('')
    teamThreadNotice.set('')
    teamThreadPreview.set(null)
    teamThreadDetail.set(null)
    teamThreadGrants.set([])
    teamThreadRevoking.set(null)
    teamThreadGrantee.set('')
    teamThreadDownloads.set(false)
    teamThreadFollowReplies.set(false)
    teamThreadFollowSentReplies.set(false)
    teamThreadSearch.set('')
    teamThreadComment.set('')
    teamThreadCollection.set('')
    teamThreadPages.set([null])
    appliedSearch = ''
    collectionScope = ''
  }

  async function run<T>(work: (signal: AbortSignal) => Promise<T>, apply: (value: T) => void) {
    if (teamThreadBusy()) return
    const pending = new AbortController()
    request = pending
    teamThreadBusy.set(true)
    teamThreadError.set('')
    try {
      const value = await work(pending.signal)
      if (request === pending) apply(value)
    }
    catch (cause) {
      if (request === pending) {
        teamThreadError.set(cause instanceof Error ? cause.message : 'Unable to load this share.')
        if (cause instanceof MailApiError && cause.status === 404) teamThreadDetail.set(null)
      }
    }
    finally {
      if (request === pending) {
        request = null
        teamThreadBusy.set(false)
      }
    }
  }

  function preview(signal: AbortSignal) {
    const collectionId = teamThreadCollection()
    return api<Preview>(`${endpoint}/preview`, {
      method: 'POST', signal, body: JSON.stringify({
        ...(collectionId ? { collectionId } : { references, followReplies: teamThreadFollowReplies(), followSentReplies: teamThreadFollowSentReplies() }),
        downloads: teamThreadDownloads(),
      }),
    })
  }

  function beginTeamThread(picked: (string | undefined)[], collectionId = '') {
    closeTeamThreads()
    teamThreadMode.set('preview')
    teamThreadTeams.set([])
    teamThreadTeam.set('')
    if (!collectionId && (picked.length === 0 || picked.length > 10 || picked.some(reference => !reference))) {
      teamThreadError.set('Choose up to ten messages with saved references.')
      return
    }
    references = picked as string[]
    teamThreadCollection.set(collectionId)
    void run(signal => Promise.all([api<Team[]>('/webmail/api/teams', { signal }), preview(signal)]), ([teams, prepared]) => {
      teamThreadTeams.set(teams)
      teamThreadTeam.set(teams[0]?.id ?? '')
      teamThreadPreview.set(prepared)
    })
  }

  function setTeamThreadDownloads(enabled: boolean) {
    teamThreadDownloads.set(enabled)
    teamThreadPreview.set(null)
    void run(preview, prepared => teamThreadPreview.set(prepared))
  }

  function setTeamThreadFollowReplies(enabled: boolean) {
    teamThreadFollowReplies.set(enabled)
    if (!enabled) teamThreadFollowSentReplies.set(false)
    teamThreadPreview.set(null)
    void run(preview, prepared => teamThreadPreview.set(prepared))
  }

  function setTeamThreadFollowSentReplies(enabled: boolean) {
    teamThreadFollowSentReplies.set(enabled)
    teamThreadPreview.set(null)
    void run(preview, prepared => teamThreadPreview.set(prepared))
  }

  async function shareTeamThread() {
    const prepared = teamThreadPreview()
    if (!prepared) return
    const collectionId = teamThreadCollection()
    const body = JSON.stringify({
      ...(collectionId ? { collectionId } : { references, followReplies: teamThreadFollowReplies(), followSentReplies: teamThreadFollowSentReplies() }),
      digest: prepared.digest, team: teamThreadTeam(), grantee: teamThreadGrantee().trim(), downloads: teamThreadDownloads(),
    })
    let issued: Grant | undefined
    await run(signal => api<Grant>(endpoint, { method: 'POST', body, signal }), grant => { issued = grant })
    if (issued) {
      openTeamThread(issued)
      teamThreadNotice.set(collectionId ? 'Collection shared.' : 'Conversation shared.')
    }
  }

  function listTeamThreads(collectionId = collectionScope) {
    if (teamThreadBusy()) return
    collectionScope = collectionId
    teamThreadMode.set('list')
    teamThreadNotice.set('')
    teamThreadDetail.set(null)
    teamThreadRevoking.set(null)
    teamThreadGrants.set([])
    void run(signal => api<{ grants: Grant[] }>(endpoint, { signal }), ({ grants }) => {
      teamThreadGrants.set(collectionId ? grants.filter(grant => grant.collectionId === collectionId) : grants)
    })
  }

  function read(grant: Grant, query: string, pages: (number | null)[]) {
    const params = new URLSearchParams()
    const before = pages.at(-1)
    if (query) params.set('q', query)
    if (before != null) params.set('before', String(before))
    const suffix = params.size ? `?${params}` : ''
    void run(signal => api<Detail>(`${endpoint}/${grant.id}${suffix}`, { signal }), (result) => {
      appliedSearch = query
      teamThreadPages.set(pages)
      teamThreadDetail.set(result)
    })
  }

  function openTeamThread(grant: Grant, preserveSearch = false) {
    teamThreadMode.set('detail')
    teamThreadNotice.set('')
    if (!preserveSearch) {
      teamThreadDetail.set(null)
      teamThreadSearch.set('')
      teamThreadComment.set('')
    }
    read(grant, teamThreadSearch().trim(), [null])
  }

  function turnTeamThreadPage(forward: boolean) {
    const detail = teamThreadDetail()
    if (!detail) return
    const pages = teamThreadPages()
    if (forward && detail.next != null) read(detail.grant, appliedSearch, [...pages, detail.next])
    if (!forward && pages.length > 1) read(detail.grant, appliedSearch, pages.slice(0, -1))
  }

  async function addTeamThreadComment() {
    const detail = teamThreadDetail()
    if (!detail || !teamThreadComment().trim()) return
    const body = JSON.stringify({ text: teamThreadComment().trim() })
    await run(signal => api(`${endpoint}/${detail.grant.id}/comments`, { method: 'POST', body, signal }),
      () => teamThreadComment.set(''))
    if (!teamThreadError() && teamThreadMode() === 'detail') read(detail.grant, appliedSearch, teamThreadPages())
  }

  async function setTeamThreadPermission(scope: 'search' | 'comments', allowed: boolean) {
    const grant = teamThreadDetail()?.grant
    if (!grant || teamThreadBusy()) return
    const body = JSON.stringify({ source: grant.owner, grantee: grant.grantee, scope, resource: grant.id, allowed })
    let saved = false
    await run(signal => api(`/webmail/api/teams/${encodeURIComponent(grant.team)}/grants`, { method: 'PUT', body, signal }),
      () => { saved = true })
    if (saved && teamThreadDetail()?.grant.id === grant.id) read(grant, appliedSearch, teamThreadPages())
  }

  async function revokeTeamThread() {
    const grant = teamThreadRevoking()
    if (!grant) return
    let revoked = false
    await run(signal => api(`${endpoint}/${grant.id}`, { method: 'DELETE', signal }), () => { revoked = true })
    if (revoked) {
      listTeamThreads()
      teamThreadNotice.set('Access revoked.')
    }
  }

  return {
    teamThreadMode, teamThreadBusy, teamThreadError, teamThreadNotice, teamThreadPreview, teamThreadGrants, teamThreadDetail,
    teamThreadTeams, teamThreadTeam, teamThreadGrantee, teamThreadDownloads, teamThreadFollowReplies, teamThreadFollowSentReplies, teamThreadSearch, teamThreadComment, teamThreadRevoking, teamThreadCollection, teamThreadPages,
    beginTeamThread, setTeamThreadDownloads, setTeamThreadFollowReplies, setTeamThreadFollowSentReplies, shareTeamThread, listTeamThreads, openTeamThread,
    addTeamThreadComment, setTeamThreadPermission, revokeTeamThread, closeTeamThreads, turnTeamThreadPage,
  }
}
