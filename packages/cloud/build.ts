import { $ } from 'bun'

async function main() {
  await $`bun run typecheck`
  // eslint-disable-next-line no-console
  console.log('Build complete!')
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error)
  process.exitCode = 1
})
