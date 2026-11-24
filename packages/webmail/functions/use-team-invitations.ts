import { derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'

interface Invitation {
  id: string
  team_name: string
  inviter: string
  recipient: string
}

interface InvitationPanel {
  teams: Array<{ id: string, name: string }>
  incoming: Invitation[]
  sent: Invitation[]
}

type Decision = 'accept' | 'decline' | 'revoke'
const endpoint = '/webmail/api/team-invitations'

export function useTeamInvitations(api: ReturnType<typeof createMailApi>, onJoin: () => Promise<void>) {
  const invitationPanel = state<InvitationPanel>({ teams: [], incoming: [], sent: [] })
  const inviteTeam = state('')
  const inviteAddress = state('')
  const inviteBusy = state(false)
  const inviteError = state('')
  const inviteNotice = state('')
  const invitationLabel = derived(() => {
    const count = invitationPanel().incoming.length
    return count ? `Team invitations (${count})` : 'Team invitations'
  })
  let sequence = 0
  let loadFailed = false

  async function refreshInvitations() {
    if (inviteBusy()) return
    const current = ++sequence
    try {
      const panel = await api<InvitationPanel>(endpoint)
      if (current !== sequence) return
      if (loadFailed) inviteError.set('')
      loadFailed = false
      invitationPanel.set(panel)
      if (!panel.teams.some(team => team.id === inviteTeam())) inviteTeam.set(panel.teams[0]?.id ?? '')
    }
    catch (error) {
      if (current !== sequence || inviteError()) return
      loadFailed = true
      inviteError.set(error instanceof Error ? error.message : 'Could not load team invitations.')
    }
  }

  async function changeInvitation(input: { action: 'invite', team: string, recipient: string } | { action: Decision, id: string }) {
    if (inviteBusy()) return
    const current = ++sequence
    inviteBusy.set(true)
    loadFailed = false
    inviteError.set('')
    inviteNotice.set('')
    try {
      await api(endpoint, { method: 'POST', body: JSON.stringify(input), signal: AbortSignal.timeout(10_000) })
      if (current !== sequence) return
      if (input.action === 'invite') inviteAddress.set('')
      const notices = { invite: 'Invitation ready in your teammate’s webmail.', accept: 'You joined the team.', decline: 'Invitation declined.', revoke: 'Invitation revoked.' }
      inviteNotice.set(notices[input.action])
    }
    catch (error) {
      if (current === sequence) inviteError.set(error instanceof Error ? error.message : 'Could not update the invitation.')
    }
    finally {
      if (current === sequence) {
        inviteBusy.set(false)
        await refreshInvitations()
        if (input.action === 'accept' && inviteNotice()) await onJoin()
      }
    }
  }

  function sendInvite() {
    if (inviteTeam() && inviteAddress().trim()) return changeInvitation({ action: 'invite', team: inviteTeam(), recipient: inviteAddress().trim() })
  }

  return {
    invitationPanel, invitationLabel, inviteTeam, inviteAddress, inviteBusy, inviteError, inviteNotice, refreshInvitations, sendInvite,
    decideInvite: (id: string, action: Decision) => changeInvitation({ id, action }),
    clearInvitations() {
      sequence++
      loadFailed = false
      invitationPanel.set({ teams: [], incoming: [], sent: [] })
      inviteTeam.set('')
      inviteAddress.set('')
      inviteError.set('')
      inviteNotice.set('')
      inviteBusy.set(false)
    },
  }
}
