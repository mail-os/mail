import { state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface Grant {
  id: string
  team: string
  owner: string
  grantee: string
  subject: string
  downloads: boolean
  followingAuthors: string[]
  replyLimitReached: boolean
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
  truncated?: boolean
}
interface Preview { messages: Message[], digest: string, followingAuthors: string[] }
interface Detail { grant: Grant, messages: Message[], comments: { author: string, writtenAt: number, text: string }[] }
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
  const teamThreadSearch = state('')
  const teamThreadComment = state('')
  const teamThreadRevoking = state<Grant | null>(null)
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
    teamThreadSearch.set('')
    teamThreadComment.set('')
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
        teamThreadError.set(cause instanceof Error ? cause.message : 'Unable to load this conversation.')
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
    return api<Preview>(`${endpoint}/preview`, {
      method: 'POST', signal, body: JSON.stringify({
        references, downloads: teamThreadDownloads(), followReplies: teamThreadFollowReplies(),
      }),
    })
  }

  function beginTeamThread(picked: (string | undefined)[]) {
    closeTeamThreads()
    teamThreadMode.set('preview')
    teamThreadTeams.set([])
    teamThreadTeam.set('')
    if (picked.length === 0 || picked.length > 10 || picked.some(reference => !reference)) {
      teamThreadError.set('Choose up to ten messages with saved references.')
      return
    }
    references = picked as string[]
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
    teamThreadPreview.set(null)
    void run(preview, prepared => teamThreadPreview.set(prepared))
  }

  async function shareTeamThread() {
    const prepared = teamThreadPreview()
    if (!prepared) return
    const body = JSON.stringify({
      references, digest: prepared.digest, team: teamThreadTeam(), grantee: teamThreadGrantee().trim(),
      downloads: teamThreadDownloads(), followReplies: teamThreadFollowReplies(),
    })
    let issued: Grant | undefined
    await run(signal => api<Grant>(endpoint, { method: 'POST', body, signal }), grant => { issued = grant })
    if (issued) {
      openTeamThread(issued)
      teamThreadNotice.set('Conversation shared.')
    }
  }

  function listTeamThreads() {
    if (teamThreadBusy()) return
    teamThreadMode.set('list')
    teamThreadNotice.set('')
    teamThreadDetail.set(null)
    teamThreadRevoking.set(null)
    teamThreadGrants.set([])
    void run(signal => api<{ grants: Grant[] }>(endpoint, { signal }), result => teamThreadGrants.set(result.grants))
  }

  function read(grant: Grant, signal: AbortSignal) {
    const query = teamThreadSearch().trim()
    const search = query ? `?q=${encodeURIComponent(query)}` : ''
    return api<Detail>(`${endpoint}/${grant.id}${search}`, { signal })
  }

  function openTeamThread(grant: Grant, preserveSearch = false) {
    teamThreadMode.set('detail')
    teamThreadNotice.set('')
    if (!preserveSearch) {
      teamThreadDetail.set(null)
      teamThreadSearch.set('')
      teamThreadComment.set('')
    }
    void run(signal => read(grant, signal), result => teamThreadDetail.set(result))
  }

  async function addTeamThreadComment() {
    const detail = teamThreadDetail()
    if (!detail || !teamThreadComment().trim()) return
    const body = JSON.stringify({ text: teamThreadComment().trim() })
    await run(signal => api(`${endpoint}/${detail.grant.id}/comments`, { method: 'POST', body, signal }),
      () => teamThreadComment.set(''))
    if (!teamThreadError() && teamThreadMode() === 'detail') openTeamThread(detail.grant, true)
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
    teamThreadTeams, teamThreadTeam, teamThreadGrantee, teamThreadDownloads, teamThreadFollowReplies, teamThreadSearch, teamThreadComment, teamThreadRevoking,
    beginTeamThread, setTeamThreadDownloads, setTeamThreadFollowReplies, shareTeamThread, listTeamThreads, openTeamThread,
    addTeamThreadComment, revokeTeamThread, closeTeamThreads,
  }
}
