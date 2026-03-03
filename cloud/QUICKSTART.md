# Quick Start Guide - Deploy SMTP Server to AWS

Get your SMTP server running on AWS in 10 minutes!

## 🚀 Prerequisites (5 minutes)

### 1. Install Required Tools

```bash
# Install Node.js 18+ (if not installed)
# Download from: https://nodejs.org/

# Install AWS CLI
brew install awscli  # macOS
# or download from: https://aws.amazon.com/cli/

# Install AWS CDK
npm install -g aws-cdk

# Verify installations
node --version   # Should be >= 18.0.0
aws --version    # Should be 2.x
cdk --version    # Should be 2.x
```

### 2. Configure AWS Credentials

```bash
aws configure
# AWS Access Key ID: <YOUR_ACCESS_KEY>
# AWS Secret Access Key: <YOUR_SECRET_KEY>
# Default region name: us-east-1
# Default output format: json
```

### 3. Create EC2 Key Pair (Optional but Recommended)

```bash
aws ec2 create-key-pair --key-name smtp-server --query 'KeyMaterial' --output text > ~/.ssh/smtp-server.pem
chmod 400 ~/.ssh/smtp-server.pem
```

---

## ⚙️ Configure (Optional - 2 minutes)

Before deploying, you can customize settings in `infra/config.ts`:

```typescript
// Edit infra/config.ts
export const config: SmtpServerConfig = {
  // Update your Git repository
  gitRepository: 'https://github.com/yourusername/smtp-server.git',

  // Adjust SMTP settings
  smtpServer: {
    port: 2525,
    maxConnections: 1000,
    maxMessageSize: 52428800, // 50MB
  },

  // Security settings
  security: {
    sshAllowedCidrs: {
      dev: ['0.0.0.0/0'],  // Open for development
      production: ['YOUR_OFFICE_IP/32'],  // Restrict in production!
    },
  },
};
```

**Note:** Configuration is optional for development. Defaults work out of the box!

See [CONFIG_INTEGRATION.md](CONFIG_INTEGRATION.md) for all configuration options.

---

## 📦 Deploy to AWS (5 minutes)

### Option 1: Automated Deployment Script (Recommended)

```bash
cd infra
npm install
./scripts/deploy.sh -e dev -y
```

### Option 2: Manual Deployment

```bash
cd infra

# Install dependencies
npm install

# Bootstrap CDK (first time only)
npm run bootstrap

# Deploy to development
npm run deploy:dev
```

---

## ✅ Verify Deployment

### 1. Get Instance Information

The deployment will output:
```
SmtpServerDevStack.PublicIp = 54.123.45.67
SmtpServerDevStack.InstanceId = i-0123456789abcdef0
SmtpServerDevStack.SshCommand = ssh -i ~/.ssh/smtp-server.pem ec2-user@54.123.45.67
```

### 2. Wait for Initialization (~5-10 minutes)

The instance needs time to:
- Install Zig compiler
- Clone SMTP server code
- Build the application
- Configure services
- Start SMTP server

### 3. Connect to Instance

**Option A: SSH (if key pair configured)**
```bash
ssh -i ~/.ssh/smtp-server.pem ec2-user@<PUBLIC_IP>
```

**Option B: AWS Systems Manager (no key needed)**
```bash
aws ssm start-session --target <INSTANCE_ID>
```

### 4. Check Server Status

```bash
# Check if SMTP server is running
sudo systemctl status smtp-server

# View real-time logs
sudo journalctl -u smtp-server -f

# Check initialization progress
sudo tail -f /var/log/user-data.log
```

---

## 🧪 Test Your SMTP Server

### 1. Test SMTP Connection

```bash
# From your local machine
telnet <PUBLIC_IP> 2525
# You should see: 220 mail.example.com SMTP Server ready

# Test with openssl (TLS)
openssl s_client -connect <PUBLIC_IP>:465 -crlf
```

### 2. Send Test Email

```bash
# Using telnet
telnet <PUBLIC_IP> 2525
EHLO test.com
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email
From: sender@example.com
To: recipient@example.com

This is a test email.
.
QUIT
```

### 3. Check CloudWatch Logs

```bash
# View logs from AWS CLI
aws logs tail /aws/ec2/smtp-server-dev --follow

# Or open CloudWatch console
https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logsV2:log-groups/log-group/$252Faws$252Fec2$252Fsmtp-server-dev
```

---

## 🎯 Access Your Services

Once deployed, your services are available at:

- **SMTP**: `<PUBLIC_IP>:25` (standard), `<PUBLIC_IP>:587` (submission)
- **SMTPS**: `<PUBLIC_IP>:465` (TLS)
- **IMAP**: `<PUBLIC_IP>:143`, **IMAPS**: `<PUBLIC_IP>:993`
- **POP3**: `<PUBLIC_IP>:110`, **POP3S**: `<PUBLIC_IP>:995`
- **HTTP API**: `http://<PUBLIC_IP>:80`
- **WebSocket**: `ws://<PUBLIC_IP>:8080`

---

## 🔧 Common Tasks

### View All Resources

```bash
aws cloudformation describe-stacks --stack-name SmtpServerDevStack
```

### Check S3 Bucket

```bash
# Get bucket name from outputs
BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name SmtpServerDevStack --query 'Stacks[0].Outputs[?OutputKey==`BucketName`].OutputValue' --output text)

# List emails
aws s3 ls s3://$BUCKET_NAME/
```

### Get Admin Password

```bash
# Retrieve from Secrets Manager
SECRET_ARN=$(aws cloudformation describe-stacks --stack-name SmtpServerDevStack --query 'Stacks[0].Outputs[?OutputKey==`SecretArn`].OutputValue' --output text)

aws secretsmanager get-secret-value --secret-id $SECRET_ARN --query SecretString --output text | jq -r '.admin_password'
```

### Update Stack

```bash
cd infra
git pull
npm install
npm run deploy:dev
```

### Stop Instance (Save Money)

```bash
# Get instance ID
INSTANCE_ID=$(aws cloudformation describe-stacks --stack-name SmtpServerDevStack --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' --output text)

# Stop instance
aws ec2 stop-instances --instance-ids $INSTANCE_ID

# Start instance
aws ec2 start-instances --instance-ids $INSTANCE_ID
```

---

## 🧹 Cleanup (Remove Everything)

### Delete Stack

```bash
npm run destroy:dev
```

This will remove:
- EC2 instance
- VPC and networking
- Security groups
- S3 bucket (if empty)
- Secrets Manager secret
- CloudWatch logs

**Note:** S3 bucket must be empty before deletion. To force delete:

```bash
# Empty S3 bucket first
aws s3 rm s3://$BUCKET_NAME --recursive

# Then destroy stack
npm run destroy:dev
```

---

## 📊 Cost Estimate

### Development Environment

- **EC2 t3.small**: ~$15/month
- **EBS 30 GB**: ~$3/month
- **S3 storage**: ~$0.02/GB/month
- **Data transfer**: ~$1-5/month
- **Total**: ~$20/month

### Ways to Save Money

1. **Stop instances when not in use**
   ```bash
   aws ec2 stop-instances --instance-ids <INSTANCE_ID>
   ```

2. **Use Savings Plans**
   - 1-year: Save 30%
   - 3-year: Save 50%

3. **Delete development stacks when not needed**
   ```bash
   npm run destroy:dev
   ```

---

## 🆘 Troubleshooting

### Issue: Deployment Fails

```bash
# Check CloudFormation events
aws cloudformation describe-stack-events --stack-name SmtpServerDevStack --max-items 20

# View CDK debug output
cdk deploy --debug --context environment=dev
```

### Issue: Can't Connect to Instance

```bash
# Check if instance is running
aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query 'Reservations[0].Instances[0].State.Name'

# Check security group
aws ec2 describe-security-groups --group-ids <SG_ID>

# Use SSM instead of SSH
aws ssm start-session --target <INSTANCE_ID>
```

### Issue: SMTP Server Not Starting

```bash
# SSH to instance
aws ssm start-session --target <INSTANCE_ID>

# Check initialization log
sudo tail -f /var/log/user-data.log

# Check service status
sudo systemctl status smtp-server

# View service logs
sudo journalctl -u smtp-server -n 100

# Restart service
sudo systemctl restart smtp-server
```

### Issue: Out of Memory

```bash
# Check memory
free -h

# Upgrade instance type
cdk deploy --context instanceType=t3.medium --context environment=dev
```

---

## 📚 Next Steps

1. **Configure Domain**
   - Point your domain to the public IP
   - Update DNS MX records
   - Get SSL certificate from Let's Encrypt

2. **Enable Monitoring**
   - Set up CloudWatch dashboards
   - Configure SNS alerts
   - Enable GuardDuty

3. **Production Deployment**
   ```bash
   ./scripts/deploy.sh -e production
   ```

4. **Read Full Documentation**
   - [Complete README](README.md)
   - [Security Guide](../docs/SECURITY_GUIDE.md)
   - [SMTP Server Docs](../README.md)

---

## 🎉 Success!

Your SMTP server is now running on AWS!

**Useful Commands:**

```bash
# View logs
aws logs tail /aws/ec2/smtp-server-dev --follow

# SSH to server
ssh -i ~/.ssh/smtp-server.pem ec2-user@<PUBLIC_IP>

# Check status
sudo systemctl status smtp-server

# Update deployment
npm run deploy:dev

# Cleanup
npm run destroy:dev
```

---

**Need Help?** Check the [full documentation](README.md) or [open an issue](https://github.com/yourusername/smtp-server/issues).
