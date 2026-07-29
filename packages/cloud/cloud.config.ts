import type { CloudConfig } from 'ts-cloud'

/**
 * Mail Server Infrastructure Configuration
 *
 * This file defines the AWS infrastructure for the mail server.
 * Uses ts-cloud for zero-dependency CloudFormation deployments.
 *
 * Environment variables:
 * - CLOUD_ENV: Set the active environment (production, staging, dev)
 * - AWS_REGION: Override the default region
 * - DOMAIN_NAME: Custom domain for the mail server
 * - HOSTED_ZONE_ID: Route53 hosted zone ID
 * - KEY_PAIR_NAME: EC2 key pair for SSH access
 *
 * @see https://github.com/stacksjs/ts-cloud
 */

// Mail server specific configuration (not part of CloudConfig, used for user data script)
const mailConfig = {
  zigVersion: '0.17.0-dev.1471+ff10b90bc',
  zigSha256: '60d83e4295b7057a382ec8dbc416b0dc59918818c0b5010b0491cec65ccd994f',
  gitRepository: 'https://github.com/stacksjs/mail.git',

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
    dashboard: 3456,
  },

  server: {
    port: 2525,
    maxConnections: 1000,
    maxMessageSize: 52428800, // 50MB
    maxRecipients: 100,
    rateLimitPerIp: 100,
    rateLimitPerUser: 200,
  },

  paths: {
    installDir: '/opt/mail',
    configDir: '/etc/mail',
    dataDir: '/var/lib/mail',
    logDir: '/var/log/mail',
    mailDir: '/var/spool/mail',
    backupDir: '/var/lib/mail/backups',
  },

  discord: {
    webhookUrl: process.env.DISCORD_WEBHOOK_URL || 'https://discord.com/api/webhooks/1479364487294488596/4x1uwO_FvR-4PZ_bZ1ozkF3imltiNoZtEjM2CBFk30xXQkdF3pSJNsVYXtJ_kwEBQhqB',
  },

  installUtils: [
    'git',
    'wget',
    'curl',
    'htop',
    'vim',
    'amazon-cloudwatch-agent',
    'python3',
    'python3-pip',
    'openssl',
    'cryptsetup',
    'sqlite',
    'fail2ban',
    'bind-utils',
    'certbot',
  ],
}

const config: CloudConfig = {
  project: {
    name: 'Mail Server',
    slug: 'mail-server',
    region: process.env.AWS_REGION || 'us-east-1',
  },

  mode: 'server', // EC2-based deployment for mail server

  environments: {
    production: {
      type: 'production',
      region: process.env.AWS_REGION || 'us-east-1',
      variables: {
        NODE_ENV: 'production',
        LOG_LEVEL: 'info',
        SMTP_PROFILE: 'production',
      },
    },
    staging: {
      type: 'staging',
      region: process.env.AWS_REGION || 'us-east-1',
      variables: {
        NODE_ENV: 'staging',
        LOG_LEVEL: 'debug',
        SMTP_PROFILE: 'staging',
      },
    },
    dev: {
      type: 'development',
      region: process.env.AWS_REGION || 'us-east-1',
      variables: {
        NODE_ENV: 'development',
        LOG_LEVEL: 'debug',
        SMTP_PROFILE: 'dev',
      },
    },
  },

  infrastructure: {
    vpc: {
      cidr: '10.0.0.0/16',
      zones: 2,
      natGateway: false, // Cost savings - using public subnets
    },

    storage: {
      emails: {
        public: false,
        website: false,
        encryption: true,
        versioning: true,
        lifecycle: {
          transitionToIA: 30,
          transitionToGlacier: 90,
        },
      },
    },

    compute: {
      mode: 'server',

      server: {
        dev: {
          instanceType: 't3.small',
          volumeSize: 30,
          monitoring: false,
          backups: false,
        },
        staging: {
          instanceType: 't3.medium',
          volumeSize: 50,
          monitoring: true,
          backups: true,
        },
        production: {
          instanceType: 't3.large',
          volumeSize: 100,
          monitoring: true,
          backups: true,
        },
      },

      securityGroups: {
        smtp: {
          description: 'Security group for mail server',
          ingress: [
            // SSH access (configure sshAllowedCidrs per environment)
            { port: mailConfig.ports.ssh, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'SSH' },
            // SMTP ports
            { port: mailConfig.ports.smtp, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'SMTP' },
            { port: mailConfig.ports.smtps, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'SMTPS (implicit TLS)' },
            { port: mailConfig.ports.submission, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'SMTP Submission (STARTTLS)' },
            // IMAP ports
            { port: mailConfig.ports.imap, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'IMAP' },
            { port: mailConfig.ports.imaps, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'IMAPS' },
            // POP3 ports
            { port: mailConfig.ports.pop3, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'POP3' },
            { port: mailConfig.ports.pop3s, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'POP3S' },
            // HTTP/HTTPS for ActiveSync, CalDAV, API
            { port: mailConfig.ports.http, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'HTTP' },
            { port: mailConfig.ports.https, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'HTTPS' },
            // WebSocket
            { port: mailConfig.ports.websocket, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'WebSocket' },
            { port: mailConfig.ports.websocketSecure, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'WebSocket SSL' },
            // Dashboard
            { port: mailConfig.ports.dashboard, protocol: 'tcp', cidr: '0.0.0.0/0', description: 'Dashboard' },
          ],
          egress: [
            { port: 0, protocol: '-1', cidr: '0.0.0.0/0', description: 'Allow all outbound' },
          ],
        },
      },

      userData: generateUserDataScript(mailConfig),
    },

    secrets: {
      credentials: {
        description: 'Mail server database credentials and secrets',
        generatePassword: {
          length: 32,
          excludePunctuation: true,
        },
      },
    },

    email: {
      domain: process.env.DOMAIN_NAME?.replace(/^[^.]*\./, '') || 'example.com',
      hostedZoneId: process.env.HOSTED_ZONE_ID,
      enableDkim: true,
      dkimKeyLength: 'RSA_2048_BIT',
      configurationSet: true,
      dmarcReportingEmail: process.env.DMARC_EMAIL || `admin@${process.env.DOMAIN_NAME?.replace(/^[^.]*\./, '') || 'example.com'}`,
    },

    dns: {
      domain: process.env.DOMAIN_NAME || 'mail.example.com',
      hostedZoneId: process.env.HOSTED_ZONE_ID,
      records: {
        mx: {
          priority: 10,
        },
        // SPF and DMARC TXT records are also created via the user data script
        // since SPF needs the instance's public IP (not known at deploy time)
      },
    },

    security: {
      kms: true,
      imdsv2: true,
      ebsEncryption: true,
    },

    monitoring: {
      dashboards: true,
      logRetention: {
        dev: 7,
        staging: 14,
        production: 30,
      },
      alarms: [
        {
          name: 'HighCPU',
          metric: 'CPUUtilization',
          threshold: 80,
          evaluationPeriods: 2,
        },
        {
          name: 'StatusCheckFailed',
          metric: 'StatusCheckFailed',
          threshold: 1,
          evaluationPeriods: 2,
        },
      ],
    },
  },

  tags: {
    Project: 'Mail Server',
    ManagedBy: 'ts-cloud',
  },
}

/**
 * Generate the EC2 user data script for mail server installation
 */
function generateUserDataScript(cfg: typeof mailConfig): string {
  const installUtils = cfg.installUtils.join(' \\\n  ')

  return `#!/bin/bash
set -e

# Logging
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting mail server installation at $(date)"

# Update system
echo "Updating system packages..."
dnf update -y

# Install required packages
echo "Installing dependencies..."
dnf install -y \\
  ${installUtils}

# Install Zig
echo "Installing Zig..."
ZIG_VERSION="${cfg.zigVersion}"
ZIG_SHA256="${cfg.zigSha256}"
cd /tmp
wget https://ziglang.org/builds/zig-x86_64-linux-\${ZIG_VERSION}.tar.xz
echo "\${ZIG_SHA256}  zig-x86_64-linux-\${ZIG_VERSION}.tar.xz" | sha256sum -c -
tar -xf zig-x86_64-linux-\${ZIG_VERSION}.tar.xz
mv zig-x86_64-linux-\${ZIG_VERSION} /usr/local/zig
ln -sf /usr/local/zig/zig /usr/local/bin/zig
zig version

# Create mail user
echo "Creating mail-server user..."
useradd -r -s /sbin/nologin -d ${cfg.paths.installDir} -M mail-server

# Clone mail server repository
echo "Cloning mail server repository..."
cd ${cfg.paths.installDir}
git clone ${cfg.gitRepository} .
chown -R mail-server:mail-server ${cfg.paths.installDir}

# Build mail server
echo "Building mail server..."
cd ${cfg.paths.installDir}/packages/zig
sudo -u mail-server zig build -Doptimize=ReleaseFast

# Install binary (renamed to avoid conflict with mail/ directory)
cp ${cfg.paths.installDir}/packages/zig/zig-out/bin/mail ${cfg.paths.installDir}/mail-server
chmod +x ${cfg.paths.installDir}/mail-server

# Create directories
echo "Creating directories..."
mkdir -p ${cfg.paths.dataDir}
mkdir -p ${cfg.paths.logDir}
mkdir -p ${cfg.paths.mailDir}
mkdir -p ${cfg.paths.configDir}
mkdir -p ${cfg.paths.backupDir}
mkdir -p ${cfg.paths.installDir}/mail  # mailbox directory (IMAP uses mail/{user} relative to CWD)
chown -R mail-server:mail-server ${cfg.paths.dataDir}
chown -R mail-server:mail-server ${cfg.paths.logDir}
chown -R mail-server:mail-server ${cfg.paths.mailDir}
chown -R mail-server:mail-server ${cfg.paths.installDir}/mail

# Encrypt every persistent mail path by default. The LUKS2 volume key is
# machine-bound in systemd's encrypted credential store and is never exposed
# to the mail-server service as a persistent plaintext file.
chmod +x ${cfg.paths.installDir}/scripts/setup-encrypted-storage.sh
MAIL_ROOT=${cfg.paths.installDir} \
  MAIL_ENCRYPTED_IMAGE_SIZE="\${MAIL_ENCRYPTED_IMAGE_SIZE:-4G}" \
  ${cfg.paths.installDir}/scripts/setup-encrypted-storage.sh

# Get instance metadata
echo "Getting instance metadata..."
TOKEN=\$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IP=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
REGION=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
DOMAIN_NAME=\${DOMAIN_NAME:-\$(aws ssm get-parameter --name "/mail-server/domain" --region \$REGION --query 'Parameter.Value' --output text 2>/dev/null || echo "")}
HOSTED_ZONE_ID=\${HOSTED_ZONE_ID:-\$(aws ssm get-parameter --name "/mail-server/hosted-zone-id" --region \$REGION --query 'Parameter.Value' --output text 2>/dev/null || echo "")}
MAIL_HOSTNAME=\${DOMAIN_NAME:-mail.example.com}

echo "Public IP: \$PUBLIC_IP"
echo "Domain: \$MAIL_HOSTNAME"
echo "Hosted Zone: \$HOSTED_ZONE_ID"

# Resolve our own mail hostname over loopback. Co-located services (the mail
# server's own webmail/health checks, and any app sharing the box that wants to
# submit mail) otherwise have to reach \$MAIL_HOSTNAME via the public IP — which
# fails on providers that don't hairpin NAT a host back to itself. Clients must
# connect by NAME, not 127.0.0.1, for TLS to verify (the cert CN is
# \$MAIL_HOSTNAME), so this entry makes the name resolve locally while keeping
# the certificate valid. Idempotent.
if ! grep -qE "^127\\.0\\.0\\.1[[:space:]]+\$MAIL_HOSTNAME(\$|[[:space:]])" /etc/hosts; then
  echo "127.0.0.1 \$MAIL_HOSTNAME" >> /etc/hosts
  echo "Added loopback /etc/hosts entry for \$MAIL_HOSTNAME"
fi

# Set up TLS certificates
echo "Setting up TLS certificates..."
if [ -n "\$DOMAIN_NAME" ] && [ "\$DOMAIN_NAME" != "mail.example.com" ]; then
  # Use Let's Encrypt for real domains
  echo "Requesting Let's Encrypt certificate for \$MAIL_HOSTNAME..."
  certbot certonly --standalone --non-interactive --agree-tos \\
    --email admin@\$(echo \$MAIL_HOSTNAME | sed 's/^[^.]*\\.//') \\
    -d \$MAIL_HOSTNAME || {
    echo "Let's Encrypt failed, falling back to self-signed certificate"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
      -keyout ${cfg.paths.configDir}/mail.key \\
      -out ${cfg.paths.configDir}/mail.crt \\
      -subj "/CN=\$MAIL_HOSTNAME"
  }

  if [ -d "/etc/letsencrypt/live/\$MAIL_HOSTNAME" ]; then
    TLS_CERT="/etc/letsencrypt/live/\$MAIL_HOSTNAME/fullchain.pem"
    TLS_KEY="/etc/letsencrypt/live/\$MAIL_HOSTNAME/privkey.pem"
    # Make certs readable by mail-server user
    chmod 755 /etc/letsencrypt/live/ /etc/letsencrypt/archive/
    chmod 755 /etc/letsencrypt/archive/\$MAIL_HOSTNAME/
    chgrp mail-server /etc/letsencrypt/archive/\$MAIL_HOSTNAME/privkey*.pem
    chmod 640 /etc/letsencrypt/archive/\$MAIL_HOSTNAME/privkey*.pem
  else
    TLS_CERT="${cfg.paths.configDir}/mail.crt"
    TLS_KEY="${cfg.paths.configDir}/mail.key"
  fi
else
  # Self-signed for dev/testing
  echo "Generating self-signed certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
    -keyout ${cfg.paths.configDir}/mail.key \\
    -out ${cfg.paths.configDir}/mail.crt \\
    -subj "/CN=\$MAIL_HOSTNAME"
  chmod 600 ${cfg.paths.configDir}/mail.key
  chown mail-server:mail-server ${cfg.paths.configDir}/mail.*
  TLS_CERT="${cfg.paths.configDir}/mail.crt"
  TLS_KEY="${cfg.paths.configDir}/mail.key"
fi

# Set up SES for email delivery
echo "Configuring SES..."
DELIVERY_METHOD="direct"
if [ -n "\$DOMAIN_NAME" ] && [ "\$DOMAIN_NAME" != "mail.example.com" ]; then
  BASE_DOMAIN=\$(echo \$MAIL_HOSTNAME | sed 's/^[^.]*\\.//')

  # Verify domain identity in SES
  echo "Verifying domain \$BASE_DOMAIN in SES..."
  aws ses verify-domain-identity --domain \$BASE_DOMAIN --region \$REGION 2>/dev/null || true

  # Enable DKIM signing
  echo "Enabling DKIM for \$BASE_DOMAIN..."
  DKIM_TOKENS=\$(aws ses verify-domain-dkim --domain \$BASE_DOMAIN --region \$REGION --query 'DkimTokens' --output text 2>/dev/null || echo "")

  if [ -n "\$HOSTED_ZONE_ID" ] && [ -n "\$DKIM_TOKENS" ]; then
    # Add DKIM CNAME records to Route 53
    echo "Adding DKIM records to Route 53..."
    for DKIM_TOKEN in \$DKIM_TOKENS; do
      aws route53 change-resource-record-sets --hosted-zone-id \$HOSTED_ZONE_ID --change-batch "{
        \\"Changes\\": [{
          \\"Action\\": \\"UPSERT\\",
          \\"ResourceRecordSet\\": {
            \\"Name\\": \\"\${DKIM_TOKEN}._domainkey.\${BASE_DOMAIN}\\",
            \\"Type\\": \\"CNAME\\",
            \\"TTL\\": 300,
            \\"ResourceRecords\\": [{
              \\"Value\\": \\"\${DKIM_TOKEN}.dkim.amazonses.com\\"
            }]
          }
        }]
      }" 2>/dev/null || true
    done
  fi

  DELIVERY_METHOD="ses"
fi

# Set up DNS records (SPF, DMARC, MX, A, rDNS)
if [ -n "\$HOSTED_ZONE_ID" ] && [ -n "\$DOMAIN_NAME" ]; then
  BASE_DOMAIN=\$(echo \$MAIL_HOSTNAME | sed 's/^[^.]*\\.//')

  echo "Configuring DNS records in Route 53..."

  # Get existing TXT records for the base domain (to preserve them)
  EXISTING_TXT=\$(aws route53 list-resource-record-sets --hosted-zone-id \$HOSTED_ZONE_ID \\
    --query "ResourceRecordSets[?Name=='\${BASE_DOMAIN}.' && Type=='TXT'].ResourceRecords[].Value" \\
    --output text 2>/dev/null | grep -v spf || echo "")

  # Build TXT record values (SPF + any existing non-SPF records)
  TXT_RECORDS="{\\"Value\\": \\"\\\\\\\"v=spf1 ip4:\$PUBLIC_IP include:amazonses.com ~all\\\\\\\"\\"}"
  if [ -n "\$EXISTING_TXT" ]; then
    for txt in \$EXISTING_TXT; do
      TXT_RECORDS="\$TXT_RECORDS, {\\"Value\\": \\"\$txt\\"}"
    done
  fi

  # Upsert all email DNS records
  aws route53 change-resource-record-sets --hosted-zone-id \$HOSTED_ZONE_ID --change-batch "{
    \\"Changes\\": [
      {
        \\"Action\\": \\"UPSERT\\",
        \\"ResourceRecordSet\\": {
          \\"Name\\": \\"\$MAIL_HOSTNAME\\",
          \\"Type\\": \\"A\\",
          \\"TTL\\": 300,
          \\"ResourceRecords\\": [{\\"Value\\": \\"\$PUBLIC_IP\\"}]
        }
      },
      {
        \\"Action\\": \\"UPSERT\\",
        \\"ResourceRecordSet\\": {
          \\"Name\\": \\"\$BASE_DOMAIN\\",
          \\"Type\\": \\"MX\\",
          \\"TTL\\": 300,
          \\"ResourceRecords\\": [{\\"Value\\": \\"10 \$MAIL_HOSTNAME\\"}]
        }
      },
      {
        \\"Action\\": \\"UPSERT\\",
        \\"ResourceRecordSet\\": {
          \\"Name\\": \\"\$BASE_DOMAIN\\",
          \\"Type\\": \\"TXT\\",
          \\"TTL\\": 300,
          \\"ResourceRecords\\": [\$TXT_RECORDS]
        }
      },
      {
        \\"Action\\": \\"UPSERT\\",
        \\"ResourceRecordSet\\": {
          \\"Name\\": \\"_dmarc.\$BASE_DOMAIN\\",
          \\"Type\\": \\"TXT\\",
          \\"TTL\\": 300,
          \\"ResourceRecords\\": [{\\"Value\\": \\"\\\\\\\"v=DMARC1; p=quarantine; pct=100\\\\\\\"\\"  }]
        }
      },
      {
        \\"Action\\": \\"UPSERT\\",
        \\"ResourceRecordSet\\": {
          \\"Name\\": \\"_atproto.\$BASE_DOMAIN\\",
          \\"Type\\": \\"TXT\\",
          \\"TTL\\": 300,
          \\"ResourceRecords\\": [{\\"Value\\": \\"\\\\\\\"did=did:plc:ihvva6h2cjxbucgwspo7nubd\\\\\\\"\\"  }]
        }
      }
    ]
  }" 2>/dev/null && echo "DNS records configured successfully" || echo "Warning: DNS record configuration failed (may need manual setup)"

  # Autodiscovery SRV/TXT records (RFC 6764) so macOS "Internet Accounts" offers
  # Calendar (CalDAV) and Contacts (CardDAV) when an account is added, plus
  # IMAP/submission service discovery. CalDAV/CardDAV are served over TLS on 443.
  cat > /tmp/autodiscover-dns.json <<DNSEOF
{
  "Comment": "Autodiscovery SRV/TXT for CalDAV/CardDAV/IMAP",
  "Changes": [
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_caldavs._tcp.\$BASE_DOMAIN","Type":"SRV","TTL":3600,"ResourceRecords":[{"Value":"0 1 443 \$MAIL_HOSTNAME."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_caldavs._tcp.\$BASE_DOMAIN","Type":"TXT","TTL":3600,"ResourceRecords":[{"Value":"\\"path=/.well-known/caldav\\""}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_carddavs._tcp.\$BASE_DOMAIN","Type":"SRV","TTL":3600,"ResourceRecords":[{"Value":"0 1 443 \$MAIL_HOSTNAME."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_carddavs._tcp.\$BASE_DOMAIN","Type":"TXT","TTL":3600,"ResourceRecords":[{"Value":"\\"path=/.well-known/carddav\\""}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_imaps._tcp.\$BASE_DOMAIN","Type":"SRV","TTL":3600,"ResourceRecords":[{"Value":"0 1 993 \$MAIL_HOSTNAME."}]}},
    {"Action":"UPSERT","ResourceRecordSet":{"Name":"_submission._tcp.\$BASE_DOMAIN","Type":"SRV","TTL":3600,"ResourceRecords":[{"Value":"0 1 587 \$MAIL_HOSTNAME."}]}}
  ]
}
DNSEOF
  aws route53 change-resource-record-sets --hosted-zone-id \$HOSTED_ZONE_ID --change-batch file:///tmp/autodiscover-dns.json >/dev/null 2>&1 \\
    && echo "Autodiscovery SRV/TXT records configured" || echo "Warning: autodiscovery DNS records failed"

  # Request reverse DNS (rDNS) via SES for the EIP
  echo "Requesting reverse DNS for \$PUBLIC_IP -> \$MAIL_HOSTNAME..."
  # Note: AWS requires a support case for rDNS on EC2. SES handles it for SES-sent mail.
  # The user data script sets the SMTP_HOSTNAME which is used in EHLO/HELO
fi

# Create environment file
echo "Creating environment configuration..."
cat > ${cfg.paths.configDir}/mail.env << ENVEOF
# Mail Server Configuration
SMTP_HOST=0.0.0.0
SMTP_PORT=${cfg.server.port}
SMTP_HOSTNAME=\$MAIL_HOSTNAME

# TLS Configuration
SMTP_ENABLE_TLS=true
SMTP_TLS_CERT=\$TLS_CERT
SMTP_TLS_KEY=\$TLS_KEY

# Authentication
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=${cfg.paths.installDir}/smtp.db

# Delivery
SMTP_DELIVERY_METHOD=\$DELIVERY_METHOD

# Logging
SMTP_ENABLE_JSON_LOGGING=true
SMTP_LOG_LEVEL=info

# Paths
SMTP_MAILBOX_PATH=${cfg.paths.mailDir}
SMTP_BACKUP_PATH=${cfg.paths.backupDir}

# Limits
SMTP_MAX_CONNECTIONS=${cfg.server.maxConnections}
SMTP_MAX_MESSAGE_SIZE=${cfg.server.maxMessageSize}
SMTP_MAX_RECIPIENTS=${cfg.server.maxRecipients}
SMTP_RATE_LIMIT_PER_IP=${cfg.server.rateLimitPerIp}
SMTP_RATE_LIMIT_PER_USER=${cfg.server.rateLimitPerUser}

# Discord Health Monitoring
DISCORD_WEBHOOK_URL=${cfg.discord?.webhookUrl || ''}
ENVEOF

chmod 600 ${cfg.paths.configDir}/mail.env
chown mail-server:mail-server ${cfg.paths.configDir}/mail.env

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/mail.service << 'SVCEOF'
[Unit]
Description=Mail Server
After=network.target

[Service]
Type=simple
User=mail-server
Group=mail-server
WorkingDirectory=${cfg.paths.installDir}
EnvironmentFile=${cfg.paths.configDir}/mail.env
ExecStart=${cfg.paths.installDir}/mail-server serve
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mail

# Allow binding to privileged ports (25, 80, 143, etc.)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ReadWritePaths=${cfg.paths.installDir}

[Install]
WantedBy=multi-user.target
SVCEOF

# Configure fail2ban for mail server
echo "Configuring fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Open all mail + DAV ports in the host firewall. The base AMI enables firewalld
# with a restrictive default that omits 443; without 443 open, CalDAV/CardDAV is
# unreachable and macOS will not offer Calendar/Contacts when adding the account.
if systemctl is-active --quiet firewalld; then
  echo "Opening mail ports in firewalld..."
  for port in 25 80 110 143 443 465 587 993 995 ${cfg.ports.dashboard} ${cfg.ports.websocketSecure}; do
    firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1 || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Install the deploy swap helper used by .github/workflows/deploy.yml. It pulls
# the new binary from S3, swaps it, runs an IMAPS smoke test and rolls back to
# the previous binary automatically if the new one fails to serve.
cat > /opt/mail/deploy-swap.sh <<'SWAPEOF'
#!/bin/bash
set -uo pipefail
S3_BIN="s3://stacks-production-s3-email/deploy/mail-server"
BIN="/opt/mail/mail-server"
NEW="/opt/mail/mail-server-new"
OLD="/opt/mail/mail-server-old"
log() { echo "[deploy-swap] $*"; }
smoke() {
  systemctl is-active --quiet mail || return 1
  # Command substitution (not a bare pipe) so a SIGPIPE from head under
  # pipefail cannot turn a healthy server into a false smoke failure.
  local g
  g="$(printf '' | timeout 8 openssl s_client -connect localhost:993 -quiet 2>/dev/null | head -c 200 || true)"
  case "$g" in
    *OK*) return 0 ;;
    *) return 1 ;;
  esac
}
log "downloading new binary from S3"
aws s3 cp "$S3_BIN" "$NEW" || { log "download failed"; exit 1; }
chmod +x "$NEW"
log "stopping mail and swapping binary"
systemctl stop mail
cp -f "$BIN" "$OLD" 2>/dev/null || true
mv -f "$NEW" "$BIN"
chown mail-server:mail-server "$BIN" 2>/dev/null || true
systemctl start mail
sleep 3
if smoke; then
  log "smoke test passed; deploy ok"
  systemctl is-active mail
  exit 0
fi
log "SMOKE TEST FAILED; rolling back to previous binary"
systemctl stop mail
mv -f "$OLD" "$BIN"
chown mail-server:mail-server "$BIN" 2>/dev/null || true
systemctl start mail
sleep 3
if smoke; then log "rollback restored service"; else log "rollback FAILED; service down"; fi
exit 1
SWAPEOF
chmod +x /opt/mail/deploy-swap.sh

# Set up certbot auto-renewal with service restart.
# The mail server binds port 80 (for ACME HTTP-01 / ActiveSync), so the
# standalone authenticator cannot bind it during renewal. Stop mail in the
# pre-hook to free port 80 and restart it in the post-hook. certbot only runs
# these hooks when a certificate is actually due for renewal (~every 60 days),
# so this does not cause daily downtime. Re-fix key perms via deploy-hook so the
# mail-server user can read the freshly-rotated privkey.
echo "Configuring certbot renewal..."
cat > /etc/cron.d/certbot-renewal << 'CRONEOF'
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin
0 3 * * * root certbot renew --quiet --pre-hook "systemctl stop mail" --post-hook "systemctl start mail" --deploy-hook "chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive && chgrp mail-server /etc/letsencrypt/archive/*/privkey*.pem 2>/dev/null && chmod 640 /etc/letsencrypt/archive/*/privkey*.pem 2>/dev/null" >> /var/log/certbot-renewal.log 2>&1
CRONEOF
chmod 644 /etc/cron.d/certbot-renewal

# certbot's RPM ships a systemd timer that would also try the standalone
# authenticator and fail on port 80 without our hooks. Disable it so only the
# hook-aware cron job above runs.
systemctl disable --now certbot-renew.timer 2>/dev/null || true

# Ensure the cron daemon is installed and running (Amazon Linux 2023 does not
# install cronie by default), otherwise the renewal job never fires.
if ! systemctl is-enabled crond >/dev/null 2>&1; then
  dnf install -y cronie || yum install -y cronie || true
fi
systemctl enable --now crond 2>/dev/null || true

# Set up log rotation
echo "Configuring log rotation..."
cat > /etc/systemd/system/mail-logrotate.service << 'LOGEOF'
[Unit]
Description=Truncate mail server log

[Service]
Type=oneshot
ExecStart=/bin/sh -c "tail -n 10000 ${cfg.paths.installDir}/smtp-server.log > ${cfg.paths.installDir}/smtp-server.log.tmp && mv ${cfg.paths.installDir}/smtp-server.log.tmp ${cfg.paths.installDir}/smtp-server.log"
LOGEOF

cat > /etc/systemd/system/mail-logrotate.timer << 'TIMEREOF'
[Unit]
Description=Weekly mail log rotation

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

systemctl daemon-reload
systemctl enable --now mail-logrotate.timer

# Enable and start mail server
echo "Starting mail server..."
systemctl enable mail
systemctl start mail

# Wait for service to start
sleep 5

# Check service status
systemctl status mail

echo "Mail server installation completed at $(date)"
echo "Instance ready for use!"
`
}

export default config
export { mailConfig }
