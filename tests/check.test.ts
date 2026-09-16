/**
 * signet-check tests - the checker's own conformance proof.
 *
 * The heavy runs go through spawned CLI processes rather than in-process
 * localTarget() calls on purpose: tests/setup.ts freezes tiny storage caps
 * the moment any server module loads in this shared process, and a signed
 * integrity manifest does not fit under them. The child gets its own env
 * with workable caps, which also exercises the real `bun run` entrypoint.
 *
 * In-process runs target the fault-injecting stub (tests/fixtures/), which
 * needs no server modules at all - each fault flag must make the checker
 * fail exactly the clauses that fault violates, and nothing else.
 */

import { describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checks } from '../src/check/clauses.ts'
import { loadRegistry, runCheck } from '../src/check/index.ts'
import {
  buildReport,
  type ConformanceReport,
  serializeReport,
  validateReport,
} from '../src/check/report.ts'
import { makeStubTarget, type StubFaults } from './fixtures/stub-target.ts'

const REPO = fileURLToPath(new URL('..', import.meta.url))
const BUN = process.execPath

const failedClauses = (r: ConformanceReport) =>
  r.results.filter(x => x.status === 'fail').map(x => x.clause)
const unsupportedClauses = (r: ConformanceReport) =>
  r.results.filter(x => x.status === 'unsupported').map(x => x.clause)

describe('registry agreement', () => {
  test('every registered check exists and every implemented check is registered', () => {
    const registry = loadRegistry()
    const ids = new Set<string>()
    const names = new Set<string>()
    for (const clause of registry.clauses) {
      expect(clause.id).toMatch(/^SN-[0-9]{3}$/)
      expect(ids.has(clause.id)).toBe(false)
      ids.add(clause.id)
      names.add(clause.check)
      expect(
        typeof (checks as Record<string, unknown>)[clause.check],
        `${clause.id} -> ${clause.check}`,
      ).toBe('function')
    }
    for (const name of Object.keys(checks)) {
      expect(names.has(name), `unregistered check ${name}`).toBe(true)
    }
  })
})

describe('the checker against a conformant stub', () => {
  test('every exercisable clause passes; startup-policy clauses are unsupported', async () => {
    const report = await runCheck(makeStubTarget())
    expect(validateReport(report)).toEqual([])
    expect(failedClauses(report)).toEqual([])
    expect(unsupportedClauses(report).sort()).toEqual(['SN-091', 'SN-092'])
  }, 120_000)

  test('the report is byte-identical across runs', async () => {
    const a = serializeReport(await runCheck(makeStubTarget()))
    const b = serializeReport(await runCheck(makeStubTarget()))
    expect(a).toBe(b)
  }, 120_000)
})

describe('fault stubs fail exactly the violated clauses', () => {
  const cases: { faults: StubFaults; expected: string[] }[] = [
    { faults: { skipAuth: true }, expected: ['SN-090'] },
    { faults: { acceptStaleBase: true }, expected: ['SN-081'] },
    { faults: { allowTraversal: true }, expected: ['SN-021'] },
    { faults: { leakAccessLog: true }, expected: ['SN-034'] },
    // Trusting any chain breaks both the verify-time rejection rules
    // (SN-051) and the authorization that follows from them (SN-052).
    { faults: { trustAnyChain: true }, expected: ['SN-051', 'SN-052'] },
  ]
  for (const { faults, expected } of cases) {
    test(`${JSON.stringify(faults)} fails ${expected.join(', ')}`, async () => {
      const report = await runCheck(makeStubTarget(faults))
      expect(validateReport(report)).toEqual([])
      expect(failedClauses(report).sort()).toEqual(expected)
    }, 120_000)
  }
})

describe('report shape', () => {
  test('a well-formed report validates; tampered reports do not', () => {
    const good = buildReport('signet-spec/0.1', 'stub', [
      { clause: 'SN-001', status: 'pass' },
      { clause: 'SN-090', status: 'fail', detail: 'x' },
      { clause: 'SN-091', status: 'unsupported', detail: 'y' },
    ])
    expect(validateReport(good)).toEqual([])
    expect(good.results.map(r => r.clause)).toEqual(['SN-001', 'SN-090', 'SN-091'])
    expect(good.summary).toEqual({ pass: 1, fail: 1, unsupported: 1 })

    expect(validateReport(null)).not.toEqual([])
    expect(
      validateReport({ ...good, results: [{ clause: 'SN-001', status: 'green' }], extra: 1 }),
    ).not.toEqual([])
    expect(
      validateReport({
        ...good,
        results: [
          { clause: 'SN-090', status: 'pass' },
          { clause: 'SN-001', status: 'pass' },
        ],
      }),
    ).not.toEqual([]) // out of order
    expect(validateReport({ ...good, summary: { pass: 9, fail: 0, unsupported: 0 } })).not.toEqual(
      [],
    )
  })
})

// ─── Spawned end-to-end runs ────────────────────────────────────────────

/** Env for a checker child process: fs store in a fresh dir, caps that fit
 *  real manifests but still let the SN-081 probes trip them cheaply. */
function childEnv(): Record<string, string> {
  return {
    ...process.env,
    STORE: 'fs',
    SIGNET_DATA_DIR: mkdtempSync(join(tmpdir(), 'signet-check-e2e-')),
    SIGNET_MODE: 'local',
    SIGNET_CAP_ENTRY: '4096',
    SIGNET_CAP_MEMORY: '8192',
    SIGNET_CAP_CONFIG: '8192',
    SIGNET_CAP_SESSIONS: '65536',
    SIGNET_CAP_GRANTS: '8192',
    SIGNET_CAP_IDENTITY: '65536',
    SIGNET_CAP_TOTAL: '262144',
    SIGNET_MAX_BODY_BYTES: '4194304',
  } as Record<string, string>
}

async function runCli(
  args: string[],
  env: Record<string, string>,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn([BUN, 'run', 'bin/signet-check.ts', ...args], {
    cwd: REPO,
    env,
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  return { code, stdout, stderr }
}

describe('the reference server end to end', () => {
  test('signet-check --target local exits 0 with no failed clauses', async () => {
    const { code, stdout, stderr } = await runCli(['--target', 'local'], childEnv())
    if (code !== 0) console.error(stderr)
    expect(code).toBe(0)
    const report = JSON.parse(stdout) as ConformanceReport
    expect(validateReport(report)).toEqual([])
    expect(report.generatedBy).toBe('signet-check')
    expect(report.target).toBe('local')
    expect(failedClauses(report)).toEqual([])
    // The local harness can reach everything: nothing is unsupported.
    expect(unsupportedClauses(report)).toEqual([])
    // Every registry clause produced a verdict.
    expect(report.results.length).toBe(loadRegistry().clauses.length)
  }, 300_000)

  test('repeated runs against the same target shape are byte-identical', async () => {
    const env = childEnv() // same values except a fresh data dir per child
    const a = await runCli(['--target', 'local'], env)
    const b = await runCli(['--target', 'local'], childEnv())
    expect(a.code).toBe(0)
    expect(a.stdout).toBe(b.stdout)
  }, 300_000)

  test('a fault-injecting target makes the CLI exit nonzero', async () => {
    const server = Bun.spawn([BUN, 'run', 'tests/fixtures/fault-server.ts', 'skipAuth', '0'], {
      cwd: REPO,
      stdout: 'pipe',
      stderr: 'pipe',
    })
    try {
      // Wait for the listening line, then parse the bound port.
      const reader = server.stdout.getReader()
      let banner = ''
      const deadline = Date.now() + 15_000
      while (!banner.includes('fault-server:') && Date.now() < deadline) {
        const { value, done } = await reader.read()
        if (done) break
        banner += new TextDecoder().decode(value)
      }
      reader.releaseLock()
      const port = /fault-server:(\d+)/.exec(banner)?.[1]
      expect(port).toBeTruthy()

      const { code, stdout } = await runCli(['--target', `http://127.0.0.1:${port}`], childEnv())
      expect(code).toBe(1)
      const report = JSON.parse(stdout) as ConformanceReport
      expect(validateReport(report)).toEqual([])
      const auth = report.results.find(r => r.clause === 'SN-090')
      expect(auth?.status).toBe('fail')
    } finally {
      server.kill()
    }
  }, 300_000)
})
