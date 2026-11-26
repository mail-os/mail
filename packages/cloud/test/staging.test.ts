import { expect, it } from 'bun:test'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { stagingInputs } from '../staging'

const cloudDir = dirname(dirname(fileURLToPath(import.meta.url)))
const stagingEnv = {
  STAGING_DOMAIN_NAME: 'mail.staging.example.test',
  STAGING_HOSTED_ZONE_ID: 'ZSTAGE0001',
  STAGING_ARTIFACT_S3_URI: 's3://mail-fixture-artifacts/staging/candidate.tar.gz',
  STAGING_ARTIFACT_SHA256: 'a'.repeat(64),
  DOMAIN_NAME: 'mail.example.test',
  HOSTED_ZONE_ID: 'ZPRODUCTION',
  DISCORD_WEBHOOK_URL: 'production-webhook-sentinel',
  CLOUD_ENV: 'staging',
}
const command = (script: string, env: NodeJS.ProcessEnv = {}) => Bun.spawnSync(
  [process.execPath, 'run', script],
  { cwd: cloudDir, env: { ...process.env, ...stagingEnv, ...env } },
)

it('emits the actual authenticated Mail bootstrap and isolates its resource access', () => {
  const result = command('generate:staging')
  expect(result.exitCode).toBe(0)
  const template = JSON.parse(result.stdout.toString())
  expect(result.stdout.toString()).not.toMatch(/production-webhook-sentinel|ZPRODUCTION|StacksServerPermissions|s3:PutObject|ses:|route53:/)
  const resources: Array<{ Type: string, Properties: any }> = Object.values(template.Resources)
  const instances = resources.filter(resource => resource.Type === 'AWS::EC2::Instance')
  expect(instances).toHaveLength(1)
  const [instance] = instances
  expect(instance.Properties.InstanceType).toBe('t3.medium')
  expect(instance.Properties.MetadataOptions.HttpTokens).toBe('required')
  expect(instance.Properties.BlockDeviceMappings[0].Ebs.Encrypted).toBe(true)
  const userdata = instance.Properties.UserData['Fn::Base64']
  expect(Bun.spawnSync(['bash', '-n'], { stdin: Buffer.from(userdata) }).exitCode).toBe(0)
  expect(userdata).toContain('sha256sum -c')
  expect(userdata).toContain("hostname='mail.staging.example.test'")
  expect(userdata).toContain('/mail-server/staging/$1')
  expect(userdata).toContain('SMTP_PROFILE=staging')
  expect(userdata).toContain('SMTP_PROVISIONING_PORT=8099')
  expect(userdata).toContain('SMTP_WEBMAIL_TLS=true')
  expect(userdata).toContain('SMTP_CLAMAV_TRANSPORT=unix:/run/clamav/clamd.ctl')
  expect(userdata).toContain('SMTP_CLAMAV_FAIL_MODE=closed')
  expect(userdata).toContain('SupplementaryGroups=clamav')
  expect(userdata).toContain('LocalSocketMode 660')
  expect(userdata).toMatch(/^apt-get install -y .*\bclamav-daemon clamav-freshclam\b/m)
  expect(userdata.indexOf('runuser -u mail-server')).toBeLessThan(userdata.indexOf('systemctl enable --now mail.service'))
  expect(userdata).toContain('CALDAV_ENABLED=true')
  expect(userdata).toContain('setup-mail-health.sh')
  expect(userdata).toContain('mail-sync-health.py')
  expect(userdata).toMatch(/^apt-get install -y .*\bnodejs\b/m)
  expect(userdata).not.toMatch(/^apt-get install -y .*\bawscli\b/m)
  expect(userdata).toContain('https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip')
  expect(userdata).not.toContain('mail-upgrade.timer')
  const securityGroup = resources.find(resource => resource.Type === 'AWS::EC2::SecurityGroup')!.Properties
  expect(securityGroup.SecurityGroupIngress.map((rule: { FromPort: number }) => rule.FromPort)).toEqual([25, 80, 143, 443, 465, 587, 993, 8443])
  expect(securityGroup.SecurityGroupEgress.map((rule: { FromPort: number }) => rule.FromPort)).toEqual([80, 443])
  const role = resources.find(resource => resource.Type === 'AWS::IAM::Role')!.Properties
  const [artifact, scopedParameters, denyOthers] = role.Policies[0].PolicyDocument.Statement
  expect(artifact.Resource['Fn::Sub']).toEndWith('mail-fixture-artifacts/staging/candidate.tar.gz')
  expect(scopedParameters.Resource.map((resource: Record<string, string>) => resource['Fn::Sub'].split(':parameter/')[1])).toEqual([
    'mail-server/staging/provisioning-token',
    'mail-server/staging/discord-webhook-url',
  ])
  expect(denyOthers).toMatchObject({ Effect: 'Deny', Action: scopedParameters.Action, NotResource: scopedParameters.Resource })
  expect(template.Resources.StagingHostRecord.Properties.HostedZoneId).toBe('ZSTAGE0001')
})

it('rejects production values and incomplete candidate coordinates', () => {
  for (const invalid of [
    { STAGING_DOMAIN_NAME: 'other.example.test' },
    { STAGING_DOMAIN_NAME: 'other.stacksjs.com', DOMAIN_NAME: undefined },
    { STAGING_DOMAIN_NAME: 'mail.hq.training', DOMAIN_NAME: undefined },
    { STAGING_HOSTED_ZONE_ID: stagingEnv.HOSTED_ZONE_ID },
    { STAGING_DOMAIN_NAME: '' },
    { STAGING_ARTIFACT_S3_URI: 's3://mail-fixture-artifacts/production/candidate.tar.gz' },
    { STAGING_ARTIFACT_SHA256: 'floating-release' },
    { CLOUD_ENV: 'production' },
  ]) {
    expect(() => stagingInputs({ ...stagingEnv, ...invalid })).toThrow()
  }
})

it('does not ask CloudFormation to create a stack in a shared or private zone', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mail-staging-test-'))
  try {
    const aws = join(directory, 'aws')
    writeFileSync(aws, `#!/bin/sh
case "$1 $2" in
  "route53 get-hosted-zone") printf '%s\\n' "$TEST_ZONE" ;;
  "cloudformation create-stack") printf '%s\\n' "$*" >> "$TEST_CALLS" ;;
  *) exit 1 ;;
esac
`)
    chmodSync(aws, 0o755)
    const calls = join(directory, 'calls')
    const env = { PATH: `${directory}:${process.env.PATH}`, TEST_CALLS: calls }
    for (const TEST_ZONE of ['["example.test.",false]', '["staging.example.test.",true]']) {
      const result = command('deploy:staging', { ...env, TEST_ZONE })
      expect(result.exitCode).toBe(1)
      expect(result.stderr.toString()).toContain('dedicated public Route 53 zone')
      expect(() => readFileSync(calls)).toThrow()
    }
    const accepted = command('deploy:staging', { ...env, TEST_ZONE: '["staging.example.test.",false]' })
    expect(accepted.exitCode).toBe(0)
    expect(readFileSync(calls, 'utf8')).toContain('create-stack --stack-name MailServerStagingStack')
  }
  finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
