import { expect, test } from 'bun:test'

const workflow = Bun.YAML.parse(await Bun.file(new URL('../.github/workflows/public-mail-health.yml', import.meta.url)).text()) as any
const script = workflow.jobs['public-mail-health'].steps.find((step: any) => step.uses === 'actions/github-script@v8').with.script
const execute = new (Object.getPrototypeOf(async () => {}).constructor)('github', 'context', 'process', 'fetch', script)

test('off-host incidents deduplicate, retry failed alerts and close only after recovery notification succeeds', async () => {
  let issue: any = null
  let failTransport = false
  let sends = 0
  const github = {
    paginate: async () => issue?.state === 'open' ? [issue] : [],
    rest: { issues: {
      listForRepo: () => {},
      create: async ({ title, body }: any) => ({ data: issue = { number: 1, html_url: 'https://github.com/example/mail/issues/1', title, body, state: 'open' } }),
      update: async (changes: any) => { Object.assign(issue, changes) },
      createComment: async () => {},
    } },
  }
  const context = { repo: { owner: 'example', repo: 'mail' }, serverUrl: 'https://github.com', runId: 42 }
  const env = { PROBE_OUTCOME: 'success', MAIL_HEALTH_WEBHOOK: 'https://discord.com/api/webhooks/test-secret' }
  const transport = async () => {
    sends++
    if (failTransport) throw new Error('sensitive webhook URL must not escape')
    return { ok: true }
  }
  const run = () => execute(github, context, { env }, transport)
  await run()
  expect(issue).toBeNull()
  env.PROBE_OUTCOME = 'failure'
  failTransport = true
  await expect(run()).rejects.toThrow('Admin alert delivery failed; incident retained for retry')
  expect(issue.state).toBe('open')
  expect(issue.body).toContain('Alert delivery: pending')
  failTransport = false
  await run()
  expect(issue.body).toContain('Alert delivery: confirmed')
  const confirmedSends = sends
  await run()
  expect(sends).toBe(confirmedSends)
  env.PROBE_OUTCOME = 'success'
  failTransport = true
  await expect(run()).rejects.toThrow('Admin alert delivery failed; incident retained for retry')
  expect(issue.state).toBe('open')
  failTransport = false
  await run()
  expect(issue.state).toBe('closed')
  const recoverySends = sends
  await run()
  expect(sends).toBe(recoverySends)
})
