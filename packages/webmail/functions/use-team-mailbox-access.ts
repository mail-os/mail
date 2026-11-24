import type { createMailApi } from './mail-api'
import { derived, state } from '@stacksjs/stx'
import { MailApiError } from './mail-api'

type Scope = 'mailbox' | 'sender'
interface Team { id: string, name: string }
interface MailboxGrant { grantee: string, scope: Scope }
interface TeamDetails {
  grants: Array<{ source: string, grantee: string, scope: string }>
}

const teamsPath = '/webmail/api/teams'
export function mailboxAccessLabel(scope: Scope): string {
  return scope === 'mailbox' ? 'Inbox access' : 'Send-as access'
}

export function useTeamMailboxAccess(api: ReturnType<typeof createMailApi>, account: () => string) {
  const accessTeams = state<Team[]>([])
  const accessTeam = state('')
  const accessAddress = state('')
  const accessScope = state<Scope>('mailbox')
  const accessOpen = state(false)
  const accessLoading = state(false)
  const accessBusy = state(false)
  const accessLoadError = state('')
  const accessError = state('')
  const accessNotice = state('')
  const inviteForAddress = state('')
  const mailboxGrants = state<MailboxGrant[]>([])
  const canGrantAccess = derived(() => !!accessTeam() && !!accessAddress().trim() && !accessBusy() && !accessLoading() && !accessLoadError())
  let teamRequest = 0
  let grantRequest = 0
  let mutation = 0

  function clearAccessFeedback() {
    accessError.set('')
    accessNotice.set('')
    inviteForAddress.set('')
  }

  async function loadMailboxGrants() {
    const team = accessTeam()
    if (!accessOpen() || !team) return
    const request = ++grantRequest
    accessLoading.set(true)
    accessLoadError.set('')
    try {
      const { grants } = await api<TeamDetails>(`${teamsPath}/${encodeURIComponent(team)}`, { signal: AbortSignal.timeout(10_000) })
      if (request !== grantRequest) return
      mailboxGrants.set(grants.flatMap(({ source, grantee, scope }) => {
        return source === account() && (scope === 'mailbox' || scope === 'sender') ? [{ grantee, scope }] : []
      }))
    }
    catch {
      if (request !== grantRequest) return
      mailboxGrants.set([])
      accessLoadError.set('Could not load mailbox access. Try again.')
    }
    finally {
      if (request === grantRequest) accessLoading.set(false)
    }
  }

  function selectAccessTeam(team: string) {
    if (team === accessTeam()) return
    grantRequest++
    accessTeam.set(team)
    accessAddress.set('')
    accessScope.set('mailbox')
    mailboxGrants.set([])
    accessLoading.set(false)
    accessLoadError.set('')
    clearAccessFeedback()
    return loadMailboxGrants()
  }

  async function refreshMailboxAccess() {
    if (accessBusy()) return
    const request = ++teamRequest
    try {
      const teams = await api<Team[]>(teamsPath, { signal: AbortSignal.timeout(10_000) })
      if (request !== teamRequest || accessBusy()) return
      accessTeams.set(teams)
      if (!teams.some(team => team.id === accessTeam())) await selectAccessTeam(teams[0]?.id ?? '')
      else if (!accessLoading()) await loadMailboxGrants()
    }
    catch {
      if (request === teamRequest && accessOpen()) accessLoadError.set('Could not load teams. Try again.')
    }
  }

  function setAccessOpen(open: boolean) {
    accessOpen.set(open)
    if (open && !accessBusy()) return loadMailboxGrants()
  }

  async function changeMailboxAccess(grantee: string, scope: Scope, allowed: boolean) {
    const team = accessTeam()
    const source = account()
    if (accessBusy() || accessLoading() || accessLoadError() || !team || !source || !grantee) return
    clearAccessFeedback()
    if (grantee === source) {
      accessError.set('Enter a teammate’s mailbox address.')
      return
    }
    const request = ++mutation
    accessBusy.set(true)
    try {
      await api(`${teamsPath}/${encodeURIComponent(team)}/grants`, {
        method: 'PUT', body: JSON.stringify({ source, grantee, scope, allowed }), signal: AbortSignal.timeout(10_000),
      })
      if (request !== mutation) return
      accessNotice.set(allowed ? mailboxAccessLabel(scope) + ' granted.' : mailboxAccessLabel(scope) + ' revoked.')
    }
    catch (error) {
      if (request !== mutation) return
      if (allowed && error instanceof MailApiError && error.code === 'team_member_not_found') {
        inviteForAddress.set(grantee)
        accessError.set('Your teammate needs to join this team before you can grant access.')
      }
      else {
        accessError.set(error instanceof Error ? error.message : 'Could not change mailbox access.')
      }
    }
    finally {
      if (request === mutation) {
        await loadMailboxGrants()
        if (request === mutation) accessBusy.set(false)
      }
    }
  }

  return {
    accessTeams, accessTeam, accessAddress, accessScope, accessLoading, accessBusy, accessLoadError, accessError, accessNotice,
    inviteForAddress, mailboxGrants, canGrantAccess, refreshMailboxAccess, selectAccessTeam, setAccessOpen,
    grantMailboxAccess: () => changeMailboxAccess(accessAddress().trim(), accessScope(), true),
    revokeMailboxAccess: (grant: MailboxGrant) => changeMailboxAccess(grant.grantee, grant.scope, false),
    clearMailboxAccess() {
      teamRequest++
      grantRequest++
      mutation++
      accessOpen.set(false)
      accessTeams.set([])
      accessTeam.set('')
      accessAddress.set('')
      accessScope.set('mailbox')
      mailboxGrants.set([])
      accessLoading.set(false)
      accessBusy.set(false)
      accessLoadError.set('')
      clearAccessFeedback()
    },
  }
}
