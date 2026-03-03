# Configuration Integration Guide

This document explains how the centralized configuration module (`config.ts`) has been integrated into the CDK stack.

## Overview

All hardcoded values in `lib/smtp-server-stack.ts` have been replaced with references to the centralized configuration module. This makes it easy to customize deployments without editing the stack code.

## Configuration Module Structure

The configuration is organized into several main sections:

### 1. Environment-Specific Settings (`config.environments`)

Each environment (dev, staging, production) has its own configuration:

```typescript
environments: {
  dev: {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    volumeSize: 30,
    enableMonitoring: false,
    enableBackups: false,
    logRetention: logs.RetentionDays.ONE_WEEK,
    maxAzs: 2,
    s3Lifecycle: { transitionToIA: 30, transitionToGlacier: 90 },
    alarms: { cpuThreshold: 90, evaluationPeriods: 3 },
  },
  // staging and production configs...
}
```

**Used in stack:**
- Instance type selection
- EBS volume size
- VPC maxAzs
- CloudWatch log retention
- S3 lifecycle policies
- CloudWatch alarm thresholds

### 2. Network Configuration (`config.vpcCidr`, `config.ports`)

```typescript
vpcCidr: '10.0.0.0/16',
ports: {
  ssh: 22,
  smtp: 25,
  smtps: 465,
  submission: 587,
  imap: 143,
  imaps: 993,
  pop3: 110,
  pop3s: 995,
  http: 80,
  https: 443,
  websocket: 8080,
  websocketSecure: 8443,
}
```

**Used in stack:**
- VPC CIDR block configuration
- Security group port rules for all protocols

### 3. SMTP Server Settings (`config.smtpServer`)

```typescript
smtpServer: {
  port: 2525,
  maxConnections: 1000,
  maxMessageSize: 52428800, // 50MB
  maxRecipients: 100,
  rateLimitPerIp: 100,
  rateLimitPerUser: 200,
}
```

**Used in stack:**
- User data environment file generation
- SMTP server runtime configuration

### 4. Security Configuration (`config.security`)

```typescript
security: {
  sshAllowedCidrs: {
    dev: ['0.0.0.0/0'],
    staging: ['0.0.0.0/0'],
    production: ['YOUR_OFFICE_IP/32'],
  },
  requireImdsv2: true,
  enableEbsEncryption: true,
  enableS3Versioning: true,
}
```

**Used in stack:**
- SSH security group rules
- EC2 IMDSv2 requirement
- EBS volume encryption
- S3 bucket versioning

### 5. Installation Paths (`config.paths`)

```typescript
paths: {
  installDir: '/opt/smtp-server',
  configDir: '/etc/smtp-server',
  dataDir: '/var/lib/smtp-server',
  logDir: '/var/log/smtp-server',
  mailDir: '/var/spool/mail',
  backupDir: '/var/lib/smtp-server/backups',
}
```

**Used in stack:**
- User data script directory creation
- SystemD service configuration
- CloudWatch Agent log paths
- Environment file paths

### 6. Software Configuration (`config.zigVersion`, `config.gitRepository`)

```typescript
zigVersion: '0.15.1',
gitRepository: 'https://github.com/yourusername/smtp-server.git',
```

**Used in stack:**
- Zig compiler installation version
- SMTP server repository cloning

### 7. User Data Configuration (`config.userData`)

```typescript
userData: {
  verboseLogging: true,
  installUtils: [
    'git', 'wget', 'curl', 'htop', 'vim',
    'amazon-cloudwatch-agent', 'python3', 'python3-pip',
    'openssl', 'sqlite', 'fail2ban',
  ],
}
```

**Used in stack:**
- Package installation list in user data script

## Stack Integration Points

### Constructor

```typescript
constructor(scope: Construct, id: string, props: SmtpServerStackProps) {
  super(scope, id, props);

  // Get environment-specific configuration
  const envConfig = getEnvironmentConfig(props.environment);

  const {
    environment,
    instanceType = envConfig.instanceType,  // ✓ From config
    volumeSize = envConfig.volumeSize,       // ✓ From config
    vpcCidr = config.vpcCidr,               // ✓ From config
    enableMonitoring = envConfig.enableMonitoring,  // ✓ From config
    enableBackups = envConfig.enableBackups,        // ✓ From config
    sshAllowedCidrs = getSshAllowedCidrs(props.environment),  // ✓ From config
  } = props;
```

### VPC Configuration

```typescript
this.vpc = new ec2.Vpc(this, 'SmtpVpc', {
  ipAddresses: ec2.IpAddresses.cidr(vpcCidr),  // ✓ From config.vpcCidr
  maxAzs: envConfig.maxAzs,                    // ✓ From config.environments[env].maxAzs
  // ...
});
```

### Security Groups

```typescript
// SSH
this.securityGroup.addIngressRule(
  ec2.Peer.ipv4(cidr),
  ec2.Port.tcp(config.ports.ssh),  // ✓ From config.ports.ssh
  `SSH access from ${cidr}`
);

// SMTP ports - all using config.ports.*
this.securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(config.ports.smtp), 'SMTP');
this.securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(config.ports.smtps), 'SMTPS');
this.securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(config.ports.submission), 'Submission');
// ... and so on for all protocols
```

### S3 Bucket

```typescript
this.bucket = new s3.Bucket(this, 'SmtpEmailBucket', {
  versioned: config.security.enableS3Versioning,  // ✓ From config
  lifecycleRules: [
    {
      transitions: [
        {
          storageClass: s3.StorageClass.INFREQUENT_ACCESS,
          transitionAfter: cdk.Duration.days(envConfig.s3Lifecycle.transitionToIA),  // ✓ From config
        },
        {
          storageClass: s3.StorageClass.GLACIER,
          transitionAfter: cdk.Duration.days(envConfig.s3Lifecycle.transitionToGlacier),  // ✓ From config
        },
      ],
    },
  ],
});
```

### CloudWatch Logs

```typescript
const logGroup = new logs.LogGroup(this, 'SmtpLogGroup', {
  logGroupName: `/aws/ec2/smtp-server-${environment}`,
  retention: envConfig.logRetention,  // ✓ From config.environments[env].logRetention
  // ...
});
```

### EC2 Instance

```typescript
this.instance = new ec2.Instance(this, 'SmtpInstance', {
  // ...
  blockDevices: [
    {
      deviceName: '/dev/xvda',
      volume: ec2.BlockDeviceVolume.ebs(volumeSize, {
        encrypted: config.security.enableEbsEncryption,  // ✓ From config
        // ...
      }),
    },
  ],
  requireImdsv2: config.security.requireImdsv2,  // ✓ From config
  // ...
});
```

### User Data Script

The user data script uses configuration extensively:

```typescript
// Zig installation
ZIG_VERSION="${config.zigVersion}"  // ✓ From config

// Package installation
dnf install -y \
  ${installUtils}  // ✓ From config.userData.installUtils

// Directory creation
mkdir -p ${config.paths.dataDir}      // ✓ From config
mkdir -p ${config.paths.logDir}       // ✓ From config
mkdir -p ${config.paths.mailDir}      // ✓ From config
mkdir -p ${config.paths.configDir}    // ✓ From config
mkdir -p ${config.paths.backupDir}    // ✓ From config

// Git repository
git clone ${config.gitRepository} .   // ✓ From config

// Environment file
SMTP_PORT=${config.smtpServer.port}                        // ✓ From config
SMTP_MAX_CONNECTIONS=${config.smtpServer.maxConnections}   // ✓ From config
SMTP_MAX_MESSAGE_SIZE=${config.smtpServer.maxMessageSize}  // ✓ From config
// ... all SMTP server settings from config
```

### CloudWatch Alarms

```typescript
private createCloudWatchAlarms(environment: string): void {
  const envConfig = getEnvironmentConfig(environment);

  const cpuAlarm = new cloudwatch.Alarm(this, 'CpuAlarm', {
    metric: this.instance.metricCPUUtilization(),
    threshold: envConfig.alarms.cpuThreshold,           // ✓ From config
    evaluationPeriods: envConfig.alarms.evaluationPeriods,  // ✓ From config
    // ...
  });
}
```

## How to Customize

### Example 1: Change Instance Type for Production

Edit `config.ts`:

```typescript
production: {
  instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.XLARGE),
  // ...
}
```

### Example 2: Change SMTP Server Port

Edit `config.ts`:

```typescript
smtpServer: {
  port: 25,  // Change from 2525 to 25
  // ...
}
```

### Example 3: Add More Utilities to Install

Edit `config.ts`:

```typescript
userData: {
  installUtils: [
    'git', 'wget', 'curl', 'htop', 'vim',
    'amazon-cloudwatch-agent', 'python3', 'python3-pip',
    'openssl', 'sqlite', 'fail2ban',
    'nginx',  // Add nginx
    'redis',  // Add redis
  ],
}
```

### Example 4: Restrict SSH Access for Production

Edit `config.ts`:

```typescript
security: {
  sshAllowedCidrs: {
    dev: ['0.0.0.0/0'],
    staging: ['0.0.0.0/0'],
    production: ['203.0.113.0/24'],  // Your office IP range
  },
  // ...
}
```

### Example 5: Use a Configuration Preset

```typescript
import { config, presets } from '../config';

// Override with cost-optimized preset
const envConfig = {
  ...getEnvironmentConfig('dev'),
  ...presets.costOptimized.dev
};
```

## Helper Functions

### `getEnvironmentConfig(env)`

Returns environment-specific configuration:

```typescript
const devConfig = getEnvironmentConfig('dev');
console.log(devConfig.instanceType);  // t3.small
console.log(devConfig.volumeSize);     // 30
```

### `getSshAllowedCidrs(env)`

Returns SSH allowed CIDRs for an environment:

```typescript
const prodCidrs = getSshAllowedCidrs('production');
console.log(prodCidrs);  // ['YOUR_OFFICE_IP/32']
```

### `validateConfig()`

Validates configuration and returns warnings:

```typescript
const validation = validateConfig();
if (!validation.valid) {
  validation.errors.forEach(error => console.warn(error));
}
```

## Configuration Validation

The config module includes validation that checks for:

1. **Production SSH Security**: Warns if SSH is open to 0.0.0.0/0
2. **Placeholder Values**: Detects if default placeholder values haven't been changed
3. **Git Repository**: Warns if using the example repository URL
4. **Volume Sizes**: Warns if volume sizes are too small

Run validation before deployment:

```bash
VALIDATE_CONFIG=true npm run deploy:prod
```

## Benefits

1. **Single Source of Truth**: All configuration in one place
2. **Easy Customization**: Change values without editing stack code
3. **Type Safety**: TypeScript interfaces ensure correct types
4. **Environment-Specific**: Different configs for dev/staging/production
5. **Reusable Presets**: Pre-configured settings for common scenarios
6. **Validation**: Built-in checks for common configuration issues

## Migration from Hardcoded Values

All previously hardcoded values have been migrated:

| Old (Hardcoded) | New (From Config) |
|----------------|------------------|
| `'0.15.1'` | `config.zigVersion` |
| `'10.0.0.0/16'` | `config.vpcCidr` |
| `22, 25, 465, 587...` | `config.ports.*` |
| `'/opt/smtp-server'` | `config.paths.installDir` |
| `1000` (max connections) | `config.smtpServer.maxConnections` |
| `52428800` (max size) | `config.smtpServer.maxMessageSize` |
| `80` (CPU threshold) | `envConfig.alarms.cpuThreshold` |
| `30` (S3 IA days) | `envConfig.s3Lifecycle.transitionToIA` |

## Next Steps

1. **Update Repository URL**: Change `config.gitRepository` to your actual repository
2. **Set Production SSH**: Update `config.security.sshAllowedCidrs.production`
3. **Review Instance Sizes**: Adjust `config.environments[env].instanceType` for your needs
4. **Customize Limits**: Modify `config.smtpServer` settings based on expected load
5. **Run Validation**: Use `validateConfig()` to check for configuration issues

## Example: Complete Customization

```typescript
// config.ts
export const config: SmtpServerConfig = {
  environments: {
    production: {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
      volumeSize: 200,
      enableMonitoring: true,
      enableBackups: true,
      logRetention: logs.RetentionDays.SIX_MONTHS,
      maxAzs: 3,
      s3Lifecycle: {
        transitionToIA: 7,
        transitionToGlacier: 30,
      },
      alarms: {
        cpuThreshold: 70,
        evaluationPeriods: 1,
      },
    },
  },
  vpcCidr: '172.16.0.0/16',
  zigVersion: '0.15.1',
  gitRepository: 'https://github.com/mycompany/smtp-server.git',
  smtpServer: {
    port: 25,
    maxConnections: 5000,
    maxMessageSize: 104857600, // 100MB
    maxRecipients: 500,
    rateLimitPerIp: 1000,
    rateLimitPerUser: 2000,
  },
  security: {
    sshAllowedCidrs: {
      production: ['10.0.0.0/8', '172.16.0.0/12'],
    },
    requireImdsv2: true,
    enableEbsEncryption: true,
    enableS3Versioning: true,
  },
};
```

Deploy with:

```bash
npm run deploy:prod
```

All customizations will be applied automatically!
