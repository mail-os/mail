# SMTP Server - AWS Infrastructure

Automated AWS infrastructure deployment for the SMTP server using [ts-cloud](https://github.com/stacksjs/ts-cloud) with TypeScript and Bun.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Cost Estimation](#cost-estimation)
- [Security](#security)

---

## Overview

This ts-cloud application deploys a complete SMTP server infrastructure on AWS, including:

- ✅ EC2 instance with optimized configuration
- ✅ VPC with public subnet
- ✅ Security groups for all mail protocols
- ✅ S3 bucket for email storage
- ✅ Secrets Manager for credentials
- ✅ CloudWatch monitoring and alarms
- ✅ IAM roles with least privilege
- ✅ Automatic SSL certificate generation
- ✅ CloudWatch Logs integration
- ✅ Optional Route53 DNS configuration

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Cloud                             │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    VPC (10.0.0.0/16)                   │  │
│  │                                                         │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │         Public Subnet (10.0.1.0/24)              │ │  │
│  │  │                                                   │ │  │
│  │  │  ┌────────────────────────────────────────────┐ │ │  │
│  │  │  │                                              │ │ │  │
│  │  │  │         EC2 Instance (SMTP Server)          │ │ │  │
│  │  │  │                                              │ │ │  │
│  │  │  │  Ports: 25, 465, 587 (SMTP)                │ │ │  │
│  │  │  │         143, 993 (IMAP)                      │ │ │  │
│  │  │  │         110, 995 (POP3)                      │ │ │  │
│  │  │  │         80, 443 (HTTP/S)                     │ │ │  │
│  │  │  │         8080, 8443 (WebSocket)              │ │ │  │
│  │  │  │                                              │ │ │  │
│  │  │  └──────────────┬───────────────────────────────┘ │ │  │
│  │  │                 │                                  │ │  │
│  │  └─────────────────┼──────────────────────────────────┘ │  │
│  │                    │                                    │  │
│  └────────────────────┼────────────────────────────────────┘  │
│                       │                                        │
│  ┌────────────────────┼────────────────────────────────────┐  │
│  │    AWS Services    │                                    │  │
│  │                    │                                    │  │
│  │  ┌─────────────┐   │   ┌──────────────┐               │  │
│  │  │ S3 Bucket   │◄──┴───┤ IAM Role     │               │  │
│  │  │ (Emails)    │       │              │               │  │
│  │  └─────────────┘       └──────────────┘               │  │
│  │                                                         │  │
│  │  ┌─────────────┐       ┌──────────────┐               │  │
│  │  │ Secrets     │       │ CloudWatch   │               │  │
│  │  │ Manager     │       │ Logs/Alarms  │               │  │
│  │  └─────────────┘       └──────────────┘               │  │
│  │                                                         │  │
│  │  ┌─────────────┐       ┌──────────────┐               │  │
│  │  │ Route53     │       │ Certificate  │               │  │
│  │  │ (Optional)  │       │ Manager      │               │  │
│  │  └─────────────┘       └──────────────┘               │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Required Tools

1. **Bun** (latest)
   ```bash
   bun --version  # Install from https://bun.sh
   ```

2. **AWS Credentials** configured in `~/.aws/credentials` or environment variables
   ```bash
   # Option 1: AWS CLI
   aws configure
   
   # Option 2: Environment variables
   export AWS_ACCESS_KEY_ID=your-key
   export AWS_SECRET_ACCESS_KEY=your-secret
   export AWS_REGION=us-east-1
   ```

### AWS Account Setup

1. **AWS Account**: Active AWS account with appropriate permissions
2. **AWS Credentials**: Configured via `aws configure` or environment variables
3. **EC2 Key Pair** (Optional but recommended):
   ```bash
   aws ec2 create-key-pair --key-name smtp-server --query 'KeyMaterial' --output text > ~/.ssh/smtp-server.pem
   chmod 400 ~/.ssh/smtp-server.pem
   ```

### Permissions Required

Your AWS user/role needs:
- EC2 full access
- VPC creation
- S3 bucket management
- IAM role creation
- Secrets Manager access
- CloudWatch Logs access
- Route53 access (if using custom domain)

---

## Quick Start

### 1. Install Dependencies

```bash
cd infra
bun install
```

### 2. Configure Environment

Create a `.env` file in the `infra` directory:

```bash
# AWS Configuration
AWS_ACCOUNT=123456789012
AWS_REGION=us-east-1

# Environment
ENVIRONMENT=dev

# EC2 Configuration
KEY_PAIR_NAME=smtp-server

# Optional: Domain Configuration
DOMAIN_NAME=mail.example.com
HOSTED_ZONE_ID=Z1234567890ABC
```

### 3. Deploy Development Environment

```bash
bun run deploy:dev
```

This will:
1. Create VPC and networking
2. Launch EC2 instance
3. Configure security groups
4. Create S3 bucket
5. Set up Secrets Manager
6. Install and configure SMTP server
7. Start all services

**Deployment Time:** ~10-15 minutes

---

## Configuration

**All configuration is centralized in [`config.ts`](config.ts)** - no need to edit stack code!

See [CONFIG_INTEGRATION.md](CONFIG_INTEGRATION.md) for complete documentation.

### Quick Configuration

Edit `infra/config.ts` to customize:

```typescript
export const config: SmtpServerConfig = {
  // Change Zig version
  zigVersion: '0.15.1',

  // Update your repository
  gitRepository: 'https://github.com/stacksjs/mail.git',

  // Environment-specific settings
  environments: {
    dev: {
      instanceType: 't3.small',
      volumeSize: 30,
      // ... more settings
    },
  },

  // SMTP server limits
  smtpServer: {
    port: 2525,
    maxConnections: 1000,
    maxMessageSize: 52428800, // 50MB
    // ... more settings
  },
}
```

### Environment-Specific Settings

#### Development

```bash
bun run deploy:dev
```

- Instance: t3.small (configurable in `config.environments.dev.instanceType`)
- Volume: 30 GB (configurable in `config.environments.dev.volumeSize`)
- Monitoring: Disabled
- Backups: Disabled
- Cost: ~$15-20/month

#### Staging

```bash
bun run deploy:staging
```

- Instance: t3.medium (configurable in `config.environments.staging.instanceType`)
- Volume: 50 GB (configurable in `config.environments.staging.volumeSize`)
- Monitoring: Enabled
- Backups: Enabled
- Cost: ~$40-50/month

#### Production

```bash
bun run deploy:prod
```
- Instance: t3.large (configurable in `config.environments.production.instanceType`)
- Volume: 100 GB (configurable in `config.environments.production.volumeSize`)
- Monitoring: Full
- Backups: Required
- Cost: ~$80-100/month

### Configuration Options

All settings are defined in `config.ts`:

- **Instance Types**: `config.environments[env].instanceType`
- **Volume Sizes**: `config.environments[env].volumeSize`
- **Network Ports**: `config.ports.*`
- **SMTP Settings**: `config.smtpServer.*`
- **Security**: `config.security.*`
- **Paths**: `config.paths.*`
- **Installation**: `config.zigVersion`, `config.gitRepository`

### Configuration Presets

Use pre-configured presets for common scenarios:

```typescript
import { presets } from './config';

// Cost-optimized (smaller instances)
const devConfig = { ...getEnvironmentConfig('dev'), ...presets.costOptimized.dev };

// High-performance (larger instances)
const prodConfig = { ...getEnvironmentConfig('production'), ...presets.highPerformance.production };
```

### Custom Configuration with CDK Context

You can still override settings using CDK context:

```bash
# Custom instance type
cdk deploy --context instanceType=t3.xlarge

# Custom key pair
cdk deploy --context keyPair=my-keypair

# Custom domain
cdk deploy --context domainName=smtp.mycompany.com --context hostedZoneId=Z123...
```

### Configuration Validation

Before deploying to production, validate your configuration:

```bash
VALIDATE_CONFIG=true npm run deploy:prod
```

This checks for:
- SSH security (warns if open to 0.0.0.0/0)
- Placeholder values that need updating
- Volume sizes that may be too small

---

## Deployment

### Deploy to Development

```bash
npm run deploy:dev
```

### Deploy to Staging

```bash
npm run deploy:staging
```

### Deploy to Production

```bash
# Review changes first
npm run diff:prod

# Deploy with manual approval
npm run deploy:prod
```

### View Deployment Plan

```bash
# See what will be created/changed
npm run synth:dev
npm run diff:dev
```

### Outputs

After deployment, you'll see:

```
Outputs:
SmtpServerDevStack.InstanceId = i-0123456789abcdef0
SmtpServerDevStack.PublicIp = 54.123.45.67
SmtpServerDevStack.PublicDnsName = ec2-54-123-45-67.compute-1.amazonaws.com
SmtpServerDevStack.BucketName = smtp-server-emails-dev-123456789012
SmtpServerDevStack.SecretArn = arn:aws:secretsmanager:...
SmtpServerDevStack.SshCommand = ssh -i ~/.ssh/smtp-server.pem ec2-user@54.123.45.67
SmtpServerDevStack.SecurityGroupId = sg-0123456789abcdef0
SmtpServerDevStack.LogGroupName = /aws/ec2/smtp-server-dev
```

### Access the Server

#### Via SSH (if key pair configured)

```bash
ssh -i ~/.ssh/smtp-server.pem ec2-user@<PUBLIC_IP>
```

#### Via AWS Systems Manager Session Manager (no key required)

```bash
aws ssm start-session --target <INSTANCE_ID>
```

### Check Server Status

```bash
# SSH into instance
ssh -i ~/.ssh/smtp-server.pem ec2-user@<PUBLIC_IP>

# Check SMTP service
sudo systemctl status smtp-server

# View logs
sudo journalctl -u smtp-server -f

# Check CloudWatch logs
aws logs tail /aws/ec2/smtp-server-dev --follow
```

---

## Monitoring

### CloudWatch Dashboards

View metrics in AWS Console:
- Navigate to CloudWatch > Dashboards
- Namespace: `SmtpServer/<environment>`

### Available Metrics

1. **CPU Usage**
   - Threshold: 80%
   - Alarm: CPU > 80% for 2 periods

2. **Memory Usage**
   - Monitored via CloudWatch Agent
   - Threshold: 80%

3. **Disk Usage**
   - Monitored per volume
   - Threshold: 85%

4. **Instance Health**
   - Status checks
   - Automatic recovery enabled

### View Logs

```bash
# Via AWS CLI
aws logs tail /aws/ec2/smtp-server-dev --follow

# Via CloudWatch Console
# Navigate to CloudWatch > Log Groups > /aws/ec2/smtp-server-<env>

# On instance
sudo tail -f /var/log/smtp-server/smtp-server.log
```

### Alarms

Configured alarms will send notifications when:
- CPU > 80% for 10 minutes
- Status check fails
- Disk usage > 85%

---

## Troubleshooting

### Common Issues

#### 1. Deployment Fails with "Key pair not found"

```bash
# Create key pair
aws ec2 create-key-pair --key-name smtp-server --query 'KeyMaterial' --output text > ~/.ssh/smtp-server.pem
chmod 400 ~/.ssh/smtp-server.pem

# Deploy without key pair (use SSM instead)
cdk deploy --context keyPair=""
```

#### 2. Cannot SSH to Instance

```bash
# Check security group rules
aws ec2 describe-security-groups --group-ids <SG_ID>

# Use SSM Session Manager instead
aws ssm start-session --target <INSTANCE_ID>
```

#### 3. SMTP Server Not Starting

```bash
# SSH to instance
ssh -i ~/.ssh/smtp-server.pem ec2-user@<PUBLIC_IP>

# Check service status
sudo systemctl status smtp-server

# View logs
sudo journalctl -u smtp-server -n 100

# Check user data execution
sudo cat /var/log/user-data.log

# Restart service
sudo systemctl restart smtp-server
```

#### 4. S3 Access Denied

```bash
# Check IAM role policies
aws iam list-role-policies --role-name <ROLE_NAME>

# Verify bucket policy
aws s3api get-bucket-policy --bucket <BUCKET_NAME>
```

#### 5. Out of Memory

```bash
# Check memory usage
free -h

# Upgrade instance type
cdk deploy --context instanceType=t3.large
```

### Debug Mode

```bash
# Enable CDK debug output
cdk deploy --debug

# Enable verbose AWS CLI output
aws --debug <command>
```

### Get Support

```bash
# View CloudFormation events
aws cloudformation describe-stack-events --stack-name smtp-server-dev

# View EC2 system logs
aws ec2 get-console-output --instance-id <INSTANCE_ID>
```

---

## Cost Estimation

### Development Environment (~$15-20/month)

| Resource | Cost |
|----------|------|
| EC2 t3.small | ~$15/month |
| EBS 30 GB | ~$3/month |
| S3 storage (1 GB) | ~$0.02/month |
| Data transfer (minimal) | ~$1/month |
| **Total** | **~$20/month** |

### Production Environment (~$80-100/month)

| Resource | Cost |
|----------|------|
| EC2 t3.large | ~$60/month |
| EBS 100 GB | ~$10/month |
| S3 storage (10 GB) | ~$0.23/month |
| CloudWatch Logs | ~$5/month |
| Data transfer | ~$10/month |
| **Total** | **~$85/month** |

### Cost Optimization

```bash
# Use Savings Plans
# - 1-year: Save 30%
# - 3-year: Save 50%

# Stop development instances when not in use
aws ec2 stop-instances --instance-ids <INSTANCE_ID>

# Use Spot Instances (dev/staging only)
# Modify instance market options in stack
```

---

## Security

### Security Features

✅ **Network Security**
- VPC with public/private subnets
- Security groups with least privilege
- IMDS v2 required

✅ **Data Security**
- EBS encryption enabled
- S3 bucket encryption (SSE-S3)
- Secrets Manager for credentials

✅ **Access Control**
- IAM roles with minimal permissions
- Systems Manager for SSH-less access
- Optional: Restrict SSH by IP

✅ **Monitoring**
- CloudWatch Logs enabled
- CloudWatch Alarms configured
- fail2ban for intrusion prevention

### Security Best Practices

#### 1. Restrict SSH Access

```typescript
// In cdk.json or via context
{
  "sshAllowedCidrs": ["YOUR_OFFICE_IP/32"]
}
```

#### 2. Enable MFA for AWS Console

```bash
aws iam enable-mfa-device --user-name <username> --serial-number <device-arn> --authentication-code1 <code1> --authentication-code2 <code2>
```

#### 3. Rotate Credentials Regularly

```bash
# Rotate Secrets Manager secret
aws secretsmanager rotate-secret --secret-id smtp-server-credentials-prod
```

#### 4. Review Security Groups

```bash
# List security group rules
aws ec2 describe-security-groups --group-ids <SG_ID>
```

#### 5. Enable GuardDuty

```bash
aws guardduty create-detector --enable
```

---

## Maintenance

### Update Stack

```bash
# Pull latest changes
git pull

# Update dependencies
npm update

# Review changes
npm run diff:prod

# Deploy updates
npm run deploy:prod
```

### Backup Strategy

#### Automated Backups (Production)

- S3 bucket versioning: Enabled
- EBS snapshots: Via AWS Backup (recommended)
- Database backups: Automatic via SMTP server

#### Manual Backup

```bash
# Create EBS snapshot
aws ec2 create-snapshot --volume-id <VOLUME_ID> --description "Manual backup"

# Export S3 bucket
aws s3 sync s3://<BUCKET_NAME> ./backup/
```

### Destroy Environment

```bash
# Development
npm run destroy:dev

# Staging
npm run destroy:staging

# Production (requires confirmation)
npm run destroy:prod
```

**⚠️ Warning:** This will delete all resources including S3 bucket (if not in production).

---

## Additional Resources

### Documentation
- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [SMTP Server Security Guide](../docs/SECURITY_GUIDE.md)
- [SMTP Server Configuration](../docs/CONFIGURATION.md)

### Support
- GitHub Issues: https://github.com/yourusername/smtp-server/issues
- AWS Support: https://console.aws.amazon.com/support

### License

MIT License - see [LICENSE](../LICENSE) file for details.

---

**Maintained by:** DevOps Team
**Last Updated:** 2025-10-24
**Version:** 1.0.0
