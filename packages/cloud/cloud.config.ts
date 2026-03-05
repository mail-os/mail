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
  zigVersion: '0.16.0-dev',
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
    'sqlite',
    'fail2ban',
  ],
}

const config: CloudConfig = {
  project: {
    name: 'Mail Server',
    slug: 'smtp-server', // Keep existing slug to avoid breaking deployed CloudFormation stacks
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

    dns: {
      domain: process.env.DOMAIN_NAME || 'mail.example.com',
      hostedZoneId: process.env.HOSTED_ZONE_ID,
      records: {
        mx: {
          priority: 10,
        },
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
cd /tmp
wget https://ziglang.org/download/\${ZIG_VERSION}/zig-linux-x86_64-\${ZIG_VERSION}.tar.xz
tar -xf zig-linux-x86_64-\${ZIG_VERSION}.tar.xz
mv zig-linux-x86_64-\${ZIG_VERSION} /usr/local/zig
ln -sf /usr/local/zig/zig /usr/local/bin/zig
zig version

# Create mail user
echo "Creating mail-server user..."
useradd -r -s /bin/bash -d ${cfg.paths.installDir} -m mail-server

# Clone mail server repository
echo "Cloning mail server repository..."
cd ${cfg.paths.installDir}
git clone ${cfg.gitRepository} .
chown -R mail-server:mail-server ${cfg.paths.installDir}

# Build mail server
echo "Building mail server..."
cd ${cfg.paths.installDir}/packages/zig
sudo -u mail-server zig build -Doptimize=ReleaseFast

# Create directories
echo "Creating directories..."
mkdir -p ${cfg.paths.dataDir}
mkdir -p ${cfg.paths.logDir}
mkdir -p ${cfg.paths.mailDir}
mkdir -p ${cfg.paths.configDir}
mkdir -p ${cfg.paths.backupDir}
chown -R mail-server:mail-server ${cfg.paths.dataDir}
chown -R mail-server:mail-server ${cfg.paths.logDir}
chown -R mail-server:mail-server ${cfg.paths.mailDir}

# Generate TLS certificates
echo "Generating self-signed certificates..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
  -keyout ${cfg.paths.configDir}/mail.key \\
  -out ${cfg.paths.configDir}/mail.crt \\
  -subj "/C=US/ST=State/L=City/O=Organization/CN=\${SMTP_HOSTNAME:-localhost}"
chmod 600 ${cfg.paths.configDir}/mail.key
chown mail-server:mail-server ${cfg.paths.configDir}/mail.*

# Create environment file
echo "Creating environment configuration..."
cat > ${cfg.paths.configDir}/mail.env << 'ENVEOF'
# Mail Server Configuration
SMTP_HOST=0.0.0.0
SMTP_PORT=${cfg.server.port}

# TLS Configuration
SMTP_ENABLE_TLS=true
SMTP_TLS_CERT=${cfg.paths.configDir}/mail.crt
SMTP_TLS_KEY=${cfg.paths.configDir}/mail.key

# Authentication
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=${cfg.paths.dataDir}/mail.db

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
ExecStart=${cfg.paths.installDir}/packages/zig/zig-out/bin/mail serve
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mail

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${cfg.paths.dataDir} ${cfg.paths.logDir} ${cfg.paths.mailDir}

[Install]
WantedBy=multi-user.target
SVCEOF

# Configure fail2ban
echo "Configuring fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Enable and start mail server
echo "Starting mail server..."
systemctl daemon-reload
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
