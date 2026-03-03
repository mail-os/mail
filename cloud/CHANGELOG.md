# Infrastructure Changelog

## [1.1.0] - 2025-10-25

### Added - Centralized Configuration Module

#### New Files
- **`config.ts`** - Complete centralized configuration module
  - Environment-specific settings (dev, staging, production)
  - Network ports configuration
  - SMTP server settings
  - Security configuration
  - Installation paths
  - User data configuration
  - Helper functions: `getEnvironmentConfig()`, `getSshAllowedCidrs()`, `validateConfig()`
  - Configuration presets: `costOptimized`, `highPerformance`, `devOnly`

- **`CONFIG_INTEGRATION.md`** - Comprehensive documentation
  - Configuration structure explanation
  - Stack integration points
  - Customization examples
  - Migration guide from hardcoded values

#### Modified Files

**`lib/smtp-server-stack.ts`**
- Imported config module
- Replaced ALL hardcoded values with config references:
  - Zig version: `config.zigVersion`
  - VPC CIDR: `config.vpcCidr`
  - Network ports: `config.ports.*`
  - Installation paths: `config.paths.*`
  - SMTP settings: `config.smtpServer.*`
  - Security settings: `config.security.*`
  - Environment configs: `getEnvironmentConfig(env)`
- Updated user data script to use config values
- Updated CloudWatch alarms to use config thresholds
- Fixed variable name conflict (renamed local `config` to `scriptConfig`)

**`README.md`**
- Added configuration section with examples
- Documented centralized config approach
- Added links to CONFIG_INTEGRATION.md
- Updated configuration options section
- Added configuration validation instructions

**`QUICKSTART.md`**
- Added configuration section before deployment
- Provided quick customization examples
- Noted that configuration is optional for dev

### Benefits

1. **Single Source of Truth**
   - All configuration in one file
   - No need to edit stack code
   - Easy to review and maintain

2. **Type Safety**
   - TypeScript interfaces ensure correct types
   - IDE autocomplete support
   - Compile-time validation

3. **Environment-Specific**
   - Different settings for dev/staging/production
   - Easy to maintain consistency
   - Clear separation of concerns

4. **Reusable Presets**
   - Pre-configured settings for common scenarios
   - Cost-optimized vs. high-performance
   - Quick deployment without manual config

5. **Validation**
   - Built-in configuration validation
   - Warns about security issues
   - Detects placeholder values

### Configuration Options

All settings now configurable via `config.ts`:

```typescript
{
  // Software versions
  zigVersion: '0.15.1',
  gitRepository: 'https://github.com/yourusername/smtp-server.git',

  // Network
  vpcCidr: '10.0.0.0/16',
  ports: { ssh: 22, smtp: 25, smtps: 465, ... },

  // SMTP Server
  smtpServer: {
    port: 2525,
    maxConnections: 1000,
    maxMessageSize: 52428800,
    maxRecipients: 100,
    rateLimitPerIp: 100,
    rateLimitPerUser: 200,
  },

  // Security
  security: {
    sshAllowedCidrs: { dev: [...], staging: [...], production: [...] },
    requireImdsv2: true,
    enableEbsEncryption: true,
    enableS3Versioning: true,
  },

  // Paths
  paths: {
    installDir: '/opt/smtp-server',
    configDir: '/etc/smtp-server',
    dataDir: '/var/lib/smtp-server',
    logDir: '/var/log/smtp-server',
    mailDir: '/var/spool/mail',
    backupDir: '/var/lib/smtp-server/backups',
  },

  // User Data
  userData: {
    verboseLogging: true,
    installUtils: ['git', 'wget', 'curl', ...],
  },

  // Environment-specific
  environments: {
    dev: { instanceType, volumeSize, enableMonitoring, ... },
    staging: { ... },
    production: { ... },
  },
}
```

### Migration from Hardcoded Values

| Component | Old Value | New Value |
|-----------|-----------|-----------|
| Zig Version | `'0.15.1'` | `config.zigVersion` |
| VPC CIDR | `'10.0.0.0/16'` | `config.vpcCidr` |
| SSH Port | `22` | `config.ports.ssh` |
| SMTP Ports | `25, 465, 587` | `config.ports.smtp/smtps/submission` |
| Install Dir | `'/opt/smtp-server'` | `config.paths.installDir` |
| Config Dir | `'/etc/smtp-server'` | `config.paths.configDir` |
| Max Connections | `1000` | `config.smtpServer.maxConnections` |
| Max Message Size | `52428800` | `config.smtpServer.maxMessageSize` |
| CPU Threshold | `80` | `envConfig.alarms.cpuThreshold` |
| S3 IA Days | `30` | `envConfig.s3Lifecycle.transitionToIA` |
| Log Retention | hardcoded | `envConfig.logRetention` |
| Package List | inline | `config.userData.installUtils` |

### How to Use

#### 1. Basic Deployment (uses defaults)
```bash
npm run deploy:dev
```

#### 2. Custom Configuration
```bash
# Edit config.ts
vim config.ts

# Deploy with custom config
npm run deploy:prod
```

#### 3. Configuration Validation
```bash
VALIDATE_CONFIG=true npm run deploy:prod
```

#### 4. Using Presets
```typescript
import { presets } from './config';

const customConfig = {
  ...getEnvironmentConfig('dev'),
  ...presets.costOptimized.dev
};
```

### Breaking Changes

None - this is a non-breaking enhancement. All previous deployment methods continue to work.

### Upgrade Instructions

No action required. The stack will automatically use the new configuration system.

To customize:
1. Edit `infra/config.ts`
2. Review [CONFIG_INTEGRATION.md](CONFIG_INTEGRATION.md)
3. Run `npm run deploy:<env>`

### Security Improvements

1. **Centralized Security Settings**
   - All security configs in one place
   - Easy to audit and review
   - SSH CIDR restrictions per environment

2. **Configuration Validation**
   - Warns if production SSH is open
   - Detects placeholder values
   - Validates sensible defaults

3. **Environment Separation**
   - Different security policies per environment
   - Production defaults to strict settings
   - Development allows easier access

### Performance Considerations

No performance impact - configuration is loaded at deployment time, not runtime.

### Testing

Configuration integration tested with:
- All three environments (dev, staging, production)
- Helper functions validation
- Configuration presets
- TypeScript compilation

### Known Issues

None

### Future Enhancements

Potential future improvements:
1. Configuration schema validation with Zod
2. Environment variable overrides
3. Configuration templates for different use cases
4. Integration with AWS SSM Parameter Store
5. Multi-region configuration support

---

## [1.0.0] - 2025-10-24

### Initial Release

- AWS CDK stack for SMTP server infrastructure
- VPC with public subnets
- EC2 instance with Amazon Linux 2023
- Security groups for all mail protocols
- S3 bucket for email storage
- Secrets Manager integration
- CloudWatch logs and monitoring
- Automated user data script
- Multi-environment support (dev/staging/production)
- Route53 DNS integration (optional)
- Comprehensive documentation

---

## Version History

- **1.1.0** - Centralized configuration module (2025-10-25)
- **1.0.0** - Initial release (2025-10-24)
