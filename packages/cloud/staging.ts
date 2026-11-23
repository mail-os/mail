import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Compute } from '@stacksjs/ts-cloud'

const stackName = 'MailServerStagingStack'
const stagingPorts = [25, 80, 143, 443, 465, 587, 993, 8443]
const bootstrap = readFileSync(new URL('./staging-user-data.sh', import.meta.url), 'utf8')
const ref = (name: string) => ({ Ref: name })
const parameterNamespace = 'mail-server/staging'

function requireMatching(env: NodeJS.ProcessEnv, name: string, pattern: RegExp): string {
  const value = env[name]
  if (!value || !pattern.test(value))
    throw new Error(`Missing or invalid ${name} for the Mail staging stack`)
  return value
}

export function stagingInputs(env: NodeJS.ProcessEnv) {
  if (env.CLOUD_ENV && env.CLOUD_ENV !== 'staging')
    throw new Error('CLOUD_ENV must be staging when generating a staging stack')
  const hostname = requireMatching(env, 'STAGING_DOMAIN_NAME', /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,63}$/)
  const mailDomain = hostname.slice(hostname.indexOf('.') + 1)
  const zoneId = requireMatching(env, 'STAGING_HOSTED_ZONE_ID', /^Z[A-Z0-9]+$/)
  const productionHosts = ['mail.stacksjs.com', 'mail.hq.training', env.DOMAIN_NAME, env.WEBMAIL_DOMAIN, ...(env.WEBMAIL_ALIASES || '').split(',')]
  const sharesProductionDomain = productionHosts.some((host) => {
    const name = host?.trim().toLowerCase().replace(/\.$/, '')
    return name === hostname || name === mailDomain || name?.slice(name.indexOf('.') + 1) === mailDomain
  })
  const productionZone = env.HOSTED_ZONE_ID?.replace(/^\/hostedzone\//, '')
  if (sharesProductionDomain || zoneId === productionZone)
    throw new Error('Mail staging requires its own domain and Route 53 hosted zone')
  const artifact = requireMatching(env, 'STAGING_ARTIFACT_S3_URI', /^s3:\/\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\/staging\/[a-zA-Z0-9][a-zA-Z0-9._/-]*\.tar\.gz$/)
  const checksum = requireMatching(env, 'STAGING_ARTIFACT_SHA256', /^[a-f0-9]{64}$/)
  const region = requireMatching({ AWS_REGION: env.AWS_REGION || 'us-east-1' }, 'AWS_REGION', /^[a-z]{2}(?:-[a-z]+){1,3}-[0-9]{1,2}$/)
  return { hostname, mailDomain, zoneId, artifact, checksum, region }
}

export function stagingTemplate(inputs: ReturnType<typeof stagingInputs>) {
  const { hostname, mailDomain, zoneId, artifact, checksum, region } = inputs
  const userData = `#!/bin/bash
hostname='${hostname}'
mail_domain='${mailDomain}'
artifact='${artifact}'
artifact_sha='${checksum}'
region='${region}'
${bootstrap}`
  if (Buffer.byteLength(userData) > 16_384)
    throw new Error('Mail staging user data exceeds the EC2 limit')

  const server = Compute.createServerModeStack({
    slug: 'mail-server',
    environment: 'staging',
    vpcId: ref('VPC') as unknown as string,
    subnetId: ref('PublicSubnet') as unknown as string,
    imageId: ref('UbuntuAmi') as unknown as string,
    instanceType: 't3.medium',
    volumeSize: 50,
    domain: hostname,
    allowedPorts: stagingPorts,
    userData,
  })
  const { instanceLogicalId, eipLogicalId } = server.outputs
  const instance = server.resources[instanceLogicalId]
  instance.DependsOn = 'PublicSubnetRoute'
  instance.Properties.MetadataOptions = { HttpTokens: 'required' }
  // Ubuntu's root device differs from the Amazon Linux default in ts-cloud.
  instance.Properties.BlockDeviceMappings[0].DeviceName = '/dev/sda1'

  // Use the role and trust relationship from ts-cloud. Replace its generic
  // app permissions with the exact resources needed by this bootstrap.
  const role = server.resources[server.outputs.roleLogicalId]
  role.Properties.ManagedPolicyArns = [{ 'Fn::Sub': 'arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore' }]
  const parameterArn = 'arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/'
  const objectArn = 'arn:${AWS::Partition}:s3:::'
  const parameter = (name: string) => ({ 'Fn::Sub': `${parameterArn}${parameterNamespace}/${name}` })
  const readParameters = ['ssm:GetParameter', 'ssm:GetParameters']
  const parameters = [parameter('provisioning-token'), parameter('discord-webhook-url')]
  role.Properties.Policies = [{
    PolicyName: 'MailStagingBootstrap',
    PolicyDocument: {
      Version: '2012-10-17',
      Statement: [
        { Effect: 'Allow', Action: 's3:GetObject', Resource: { 'Fn::Sub': `${objectArn}${artifact.slice(5)}` } },
        { Effect: 'Allow', Action: readParameters, Resource: parameters },
        // AmazonSSMManagedInstanceCore otherwise grants parameter reads on *.
        { Effect: 'Deny', Action: readParameters, NotResource: parameters },
      ],
    },
  }]
  server.resources[server.outputs.securityGroupLogicalId].Properties.SecurityGroupEgress = [80, 443].map(port => ({
    IpProtocol: 'tcp', FromPort: port, ToPort: port, CidrIp: '0.0.0.0/0',
  }))

  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: 'Native Mail staging server',
    Parameters: {
      UbuntuAmi: {
        Type: 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>',
        Default: '/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id',
      },
    },
    Resources: {
      VPC: {
        Type: 'AWS::EC2::VPC',
        Properties: { CidrBlock: '10.61.0.0/16', EnableDnsSupport: true, EnableDnsHostnames: true },
      },
      InternetGateway: { Type: 'AWS::EC2::InternetGateway' },
      GatewayAttachment: {
        Type: 'AWS::EC2::VPCGatewayAttachment',
        Properties: { VpcId: ref('VPC'), InternetGatewayId: ref('InternetGateway') },
      },
      PublicSubnet: {
        Type: 'AWS::EC2::Subnet',
        Properties: { VpcId: ref('VPC'), CidrBlock: '10.61.0.0/24', MapPublicIpOnLaunch: true },
      },
      PublicRoutes: { Type: 'AWS::EC2::RouteTable', Properties: { VpcId: ref('VPC') } },
      InternetRoute: {
        Type: 'AWS::EC2::Route',
        DependsOn: 'GatewayAttachment',
        Properties: { RouteTableId: ref('PublicRoutes'), DestinationCidrBlock: '0.0.0.0/0', GatewayId: ref('InternetGateway') },
      },
      PublicSubnetRoute: {
        Type: 'AWS::EC2::SubnetRouteTableAssociation',
        DependsOn: 'InternetRoute',
        Properties: { SubnetId: ref('PublicSubnet'), RouteTableId: ref('PublicRoutes') },
      },
      ...server.resources,
      StagingHostRecord: {
        Type: 'AWS::Route53::RecordSet',
        Properties: { HostedZoneId: zoneId, Name: hostname, Type: 'A', TTL: '60', ResourceRecords: [ref(eipLogicalId)] },
      },
    },
    Outputs: {
      InstanceId: { Value: ref(instanceLogicalId) },
      WebmailURL: { Value: `https://${hostname}:8443` },
      ProtocolHostname: { Value: hostname },
    },
  }
}

if (import.meta.main) {
  const operation = process.argv[2] ?? 'generate'
  if (operation !== 'generate' && operation !== 'create' && operation !== 'diff')
    throw new Error('Expected generate, create, or diff')
  const inputs = stagingInputs(process.env)
  const template = JSON.stringify(stagingTemplate(inputs), null, 2) + '\n'
  if (operation === 'generate') {
    process.stdout.write(template)
  }
  else {
    const aws = (args: string[]) => {
      const result = Bun.spawnSync(['aws', ...args, '--region', inputs.region, '--no-cli-pager'], { stderr: 'inherit' })
      if (result.exitCode !== 0)
        throw new Error(`AWS ${args[0]} ${args[1]} failed`)
      return result.stdout.toString().trim()
    }
    const directory = mkdtempSync(join(tmpdir(), 'mail-staging-'))
    try {
      const path = join(directory, 'template.json')
      writeFileSync(path, template)
      if (operation === 'diff') {
        const existing = aws(['cloudformation', 'get-template', '--stack-name', stackName, '--query', 'TemplateBody', '--output', 'json'])
        const returned = JSON.parse(existing)
        const current = typeof returned === 'string' ? JSON.parse(returned) : returned
        const previous = join(directory, 'deployed.json')
        writeFileSync(previous, `${JSON.stringify(current, null, 2)}\n`)
        const result = Bun.spawnSync(['diff', '-u', previous, path], { stdout: 'inherit', stderr: 'inherit' })
        if (result.exitCode > 1)
          throw new Error('Could not compare the staging templates')
      }
      else {
        const zone = aws(['route53', 'get-hosted-zone', '--id', inputs.zoneId, '--query', 'HostedZone.[Name,Config.PrivateZone]', '--output', 'json'])
        const [zoneName, privateZone] = JSON.parse(zone)
        if (zoneName !== `${inputs.mailDomain}.` || privateZone !== false)
          throw new Error('Expected the dedicated public Route 53 zone for the staging mailbox domain')
        // create-stack rejects existing stacks and cannot replace their instance or disk.
        const created = aws(['cloudformation', 'create-stack', '--stack-name', stackName, '--template-body', `file://${path}`, '--capabilities', 'CAPABILITY_NAMED_IAM'])
        process.stdout.write(`${created}\n`)
      }
    }
    finally {
      rmSync(directory, { recursive: true, force: true })
    }
  }
}
