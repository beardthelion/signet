#!/usr/bin/env bun

/**
 * signet-check - the Signet conformance checker CLI (SPEC §8).
 *
 * Usage:
 *   signet-check --target local            check the reference server in-process
 *   signet-check --target http://host:port check a live store over the wire
 *
 * Prints the conformance report (spec/report-schema.json) to stdout and
 * exits 1 when any clause fails, 0 otherwise. `local` is the deepest check:
 * it can see the raw store and probe startup policy, so no clause reports
 * unsupported. A socket target cannot reach those internals, and the report
 * says so rather than faking a pass.
 *
 * The report carries no secrets, tokens, or host-dependent fields; the
 * `target` string is echoed verbatim from --target.
 */

import { httpTarget, localTarget, reportHasFailures, runCheck } from '../src/check/index.ts'
import { serializeReport, validateReport } from '../src/check/report.ts'

function usage(): never {
  console.log(
    'usage:\n' +
      '  signet-check --target local              check the reference server in-process\n' +
      '  signet-check --target http://host:port   check a live store over the wire',
  )
  process.exit(2)
}

const argv = process.argv.slice(2)
let targetArg = 'local'
for (let i = 0; i < argv.length; i++) {
  const a = argv[i]!
  if (a === '--target') {
    targetArg = argv[++i] ?? ''
  } else if (a.startsWith('--target=')) {
    targetArg = a.slice('--target='.length)
  } else {
    console.error(`unknown argument: ${a}`)
    usage()
  }
}

if (targetArg !== 'local' && !/^https?:\/\//.test(targetArg)) {
  console.error(`--target must be "local" or an http(s) URL, got "${targetArg}"`)
  usage()
}

const target = targetArg === 'local' ? await localTarget({ name: 'local' }) : httpTarget(targetArg)

const report = await runCheck(target)

// The artifact must satisfy its own schema; a malformed report is a checker
// bug, not a conformance verdict, so it exits 2 rather than printing it.
const problems = validateReport(report)
if (problems.length) {
  console.error(`signet-check produced an invalid report:\n${problems.join('\n')}`)
  process.exit(2)
}

process.stdout.write(serializeReport(report))
process.exit(reportHasFailures(report) ? 1 : 0)
