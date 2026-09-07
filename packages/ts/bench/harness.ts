/* eslint-disable no-console */
/**
 * A small benchmark harness.
 *
 * Each candidate gets its own timed loop, repeated over several rounds, and the best
 * round wins. Best-of rather than mean, because the noise on a laptop is one sided: a
 * scheduler interruption can only ever make a round slower.
 */

export interface Candidate {
  name: string
  run: () => unknown | Promise<unknown>
}

export interface CandidateResult {
  name: string
  opsPerSecond: number
  nsPerOp: number
  iterations: number
}

export interface CaseResult {
  name: string
  /** Bytes processed per operation, for throughput reporting */
  bytes?: number
  candidates: CandidateResult[]
}

export interface BenchOptions {
  /** Minimum time for one measured round, in milliseconds */
  minTime?: number
  rounds?: number
  warmupTime?: number
}

const DEFAULTS: Required<BenchOptions> = {
  minTime: 400,
  rounds: 3,
  warmupTime: 150,
}

async function runFor(candidate: Candidate, minTime: number): Promise<{ iterations: number, elapsed: number }> {
  let iterations = 0
  const start = performance.now()
  let elapsed = 0

  // The batch grows so that a fast candidate does not spend the whole round reading the
  // clock, and a slow one still stops as soon as it has run long enough
  let batch = 1
  while (elapsed < minTime) {
    for (let i = 0; i < batch; i++)
      await candidate.run()

    iterations += batch
    elapsed = performance.now() - start

    if (elapsed < minTime / 4)
      batch *= 2
  }

  return { iterations, elapsed }
}

export async function benchCase(
  name: string,
  candidates: Candidate[],
  options: BenchOptions & { bytes?: number } = {},
): Promise<CaseResult> {
  const { minTime, rounds, warmupTime } = { ...DEFAULTS, ...options }

  for (const candidate of candidates)
    await runFor(candidate, warmupTime)

  const best = new Map<string, { opsPerSecond: number, iterations: number }>()

  for (let round = 0; round < rounds; round++) {
    for (const candidate of candidates) {
      const { iterations, elapsed } = await runFor(candidate, minTime)
      const opsPerSecond = (iterations / elapsed) * 1000

      const current = best.get(candidate.name)
      if (!current || opsPerSecond > current.opsPerSecond)
        best.set(candidate.name, { opsPerSecond, iterations })
    }
  }

  return {
    name,
    bytes: options.bytes,
    candidates: candidates.map((candidate) => {
      const result = best.get(candidate.name)!
      return {
        name: candidate.name,
        opsPerSecond: result.opsPerSecond,
        nsPerOp: 1e9 / result.opsPerSecond,
        iterations: result.iterations,
      }
    }),
  }
}

function formatOps(opsPerSecond: number): string {
  if (opsPerSecond >= 1000)
    return `${Math.round(opsPerSecond).toLocaleString('en-US')}/s`
  if (opsPerSecond >= 10)
    return `${opsPerSecond.toFixed(1)}/s`
  return `${opsPerSecond.toFixed(2)}/s`
}

function formatThroughput(opsPerSecond: number, bytes?: number): string {
  if (!bytes)
    return ''
  return `${((opsPerSecond * bytes) / (1024 * 1024)).toFixed(1)} MiB/s`
}

/**
 * Prints one row per case: the reference, this implementation, and the speedup.
 */
export function printResults(title: string, results: CaseResult[], baselineName: string, subjectName: string): void {
  const nameWidth = Math.max(...results.map(result => result.name.length), 'case'.length)

  const header = [
    'case'.padEnd(nameWidth),
    baselineName.padStart(14),
    subjectName.padStart(14),
    'throughput'.padStart(12),
    'speedup'.padStart(9),
  ].join('  ')

  console.log(`\n${title}`)
  console.log('-'.repeat(header.length))
  console.log(header)
  console.log('-'.repeat(header.length))

  for (const result of results) {
    const baseline = result.candidates.find(candidate => candidate.name === baselineName)!
    const subject = result.candidates.find(candidate => candidate.name === subjectName)!
    const speedup = subject.opsPerSecond / baseline.opsPerSecond

    console.log([
      result.name.padEnd(nameWidth),
      formatOps(baseline.opsPerSecond).padStart(14),
      formatOps(subject.opsPerSecond).padStart(14),
      formatThroughput(subject.opsPerSecond, result.bytes).padStart(12),
      `${speedup.toFixed(2)}x`.padStart(9),
    ].join('  '))
  }

  console.log('-'.repeat(header.length))

  const speedups = results.map((result) => {
    const baseline = result.candidates.find(candidate => candidate.name === baselineName)!
    const subject = result.candidates.find(candidate => candidate.name === subjectName)!
    return subject.opsPerSecond / baseline.opsPerSecond
  })

  const slowest = Math.min(...speedups)
  const fastest = Math.max(...speedups)
  const geomean = speedups.reduce((acc, value) => acc * value, 1) ** (1 / speedups.length)

  console.log(`${'geometric mean'.padEnd(nameWidth)}  ${''.padStart(14)}  ${''.padStart(14)}  ${''.padStart(12)}  ${`${geomean.toFixed(2)}x`.padStart(9)}`)
  console.log(`${'range'.padEnd(nameWidth)}  ${''.padStart(14)}  ${''.padStart(14)}  ${''.padStart(12)}  ${`${slowest.toFixed(2)}-${fastest.toFixed(2)}x`.padStart(9)}`)
}
