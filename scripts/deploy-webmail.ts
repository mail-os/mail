import { deployMailWebmail } from '@stacksjs/ts-cloud/mail'
import config from '../packages/cloud/webmail.config'

const target = process.argv[2] || process.env.MAIL_DEPLOY_TARGET
if (!target)
  throw new Error('usage: bun scripts/deploy-webmail.ts root@HOST')

deployMailWebmail(config, {
  target,
  envFile: process.env.MAIL_SERVER_ENV_FILE,
  service: process.env.MAIL_SERVICE_UNIT,
}).catch((error) => {
  console.error(error)
  process.exitCode = 1
})
