import type { CloudConfig } from '@stacksjs/ts-cloud'

/** The existing mail executable's UI. Deployment and certificates belong to
 * ts-cloud; this project declares only its hostnames and listener settings. */
export default {
  project: { name: 'Mail', slug: 'mail', region: process.env.AWS_REGION || 'us-east-1' },
  environments: { production: { type: 'production' } },
  infrastructure: {
    compute: {
      managedServices: {
        mail: {
          mode: 'server',
          hostname: process.env.DOMAIN_NAME || 'mail.stacksjs.com',
          webmail: {
            port: Number(process.env.WEBMAIL_PORT || 8099),
            domain: process.env.WEBMAIL_DOMAIN || process.env.DOMAIN_NAME || 'mail.stacksjs.com',
            aliases: (process.env.WEBMAIL_ALIASES ?? 'mail.hq.training').split(',').map(value => value.trim()).filter(Boolean),
            attachments: {
              maxFileBytes: Number(process.env.WEBMAIL_ATTACHMENT_MAX_FILE || 20 * 1024 * 1024),
              maxTotalBytes: Number(process.env.WEBMAIL_ATTACHMENT_MAX_TOTAL || 20 * 1024 * 1024),
              maxCount: Number(process.env.WEBMAIL_ATTACHMENT_MAX_COUNT ?? 20),
            },
            undoSendSeconds: Number(process.env.WEBMAIL_UNDO_SEND_SECONDS ?? 10),
          },
        },
      },
      proxy: {
        engine: 'rpx',
        onDemandTlsEmail: process.env.WEBMAIL_ACME_EMAIL || 'chris@stacksjs.com',
      },
    },
  },
} satisfies CloudConfig
