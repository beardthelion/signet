/**
 * Conformance report model — the deterministic JSON artifact passport-check
 * emits (SPEC §8, spec/report-schema.json).
 *
 * Two hard requirements shape this module:
 *   - Byte-identical output for identical target state: results are sorted by
 *     clause id, keys are written in a fixed order, and nothing here emits a
 *     timestamp, a random id, or a host-dependent value. The only
 *     caller-supplied string is `target`.
 *   - The report is a shareable artifact: it must not carry secrets, tokens,
 *     or target internals. Detail strings are fixed probe descriptions plus a
 *     sanitizer that strips DIDs, digests, and local paths (see index.ts).
 *
 * `validateReport` is a hand-rolled structural check of the same shape
 * spec/report-schema.json describes — no JSON-schema dependency. It also
 * checks the two contract properties the schema cannot express: sorted,
 * unique clause ids and a summary that matches the results.
 */

export type ClauseStatus = 'pass' | 'fail' | 'unsupported'

/** What a single check function returns. */
export type ClauseResult = { status: ClauseStatus; detail?: string }

/** One row of the report: a clause id and its verdict. */
export type ReportResult = { clause: string; status: ClauseStatus; detail?: string }

export type ConformanceReport = {
  specVersion: string
  target: string
  generatedBy: 'passport-check'
  results: ReportResult[]
  summary: { pass: number; fail: number; unsupported: number }
}

export const GENERATED_BY = 'passport-check' as const

const SPEC_VERSION_RE = /^passport-spec\/[0-9]+\.[0-9]+$/
const CLAUSE_RE = /^PS-[0-9]{3}$/
const STATUSES: readonly string[] = ['pass', 'fail', 'unsupported']

/**
 * Sort results by clause id and compute the summary. Detail strings are
 * included verbatim — callers sanitize before this point.
 */
export function buildReport(
  specVersion: string,
  target: string,
  results: ReportResult[],
): ConformanceReport {
  const sorted = [...results].sort((a, b) =>
    a.clause < b.clause ? -1 : a.clause > b.clause ? 1 : 0,
  )
  const summary = { pass: 0, fail: 0, unsupported: 0 }
  for (const r of sorted) summary[r.status]++
  return { specVersion, target, generatedBy: GENERATED_BY, results: sorted, summary }
}

/** The exact bytes written to stdout. Stable key order, trailing newline. */
export function serializeReport(report: ConformanceReport): string {
  return `${JSON.stringify(report, null, 2)}\n`
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function extraKeys(obj: Record<string, unknown>, allowed: string[]): string[] {
  return Object.keys(obj).filter(k => !allowed.includes(k))
}

/**
 * Structural validation against spec/report-schema.json, plus the contract's
 * sorted/unique/consistent-summary rules. Returns a list of violations; an
 * empty list means the report is well-formed.
 */
export function validateReport(report: unknown): string[] {
  const problems: string[] = []
  if (!isObject(report)) return ['report is not an object']
  for (const k of extraKeys(report, [
    'specVersion',
    'target',
    'generatedBy',
    'results',
    'summary',
  ])) {
    problems.push(`unexpected top-level key "${k}"`)
  }
  for (const k of ['specVersion', 'target', 'generatedBy', 'results', 'summary']) {
    if (!(k in report)) problems.push(`missing required key "${k}"`)
  }
  if (typeof report.specVersion !== 'string' || !SPEC_VERSION_RE.test(report.specVersion)) {
    problems.push('specVersion must match ^passport-spec/[0-9]+\\.[0-9]+$')
  }
  if (typeof report.target !== 'string') problems.push('target must be a string')
  if (typeof report.generatedBy !== 'string') problems.push('generatedBy must be a string')

  if (Array.isArray(report.results)) {
    let prev = ''
    const seen = new Set<string>()
    for (const [i, item] of report.results.entries()) {
      if (!isObject(item)) {
        problems.push(`results[${i}] is not an object`)
        continue
      }
      for (const k of extraKeys(item, ['clause', 'status', 'detail'])) {
        problems.push(`results[${i}] has unexpected key "${k}"`)
      }
      if (typeof item.clause !== 'string' || !CLAUSE_RE.test(item.clause)) {
        problems.push(`results[${i}].clause must match ^PS-[0-9]{3}$`)
        continue
      }
      if (seen.has(item.clause)) problems.push(`duplicate clause ${item.clause}`)
      seen.add(item.clause)
      if (item.clause < prev) problems.push(`results out of order at ${item.clause}`)
      prev = item.clause
      if (typeof item.status !== 'string' || !STATUSES.includes(item.status)) {
        problems.push(`results[${i}].status must be pass|fail|unsupported`)
      }
      if (item.detail !== undefined && typeof item.detail !== 'string') {
        problems.push(`results[${i}].detail must be a string`)
      }
    }
  } else {
    problems.push('results must be an array')
  }

  if (isObject(report.summary)) {
    for (const k of extraKeys(report.summary, ['pass', 'fail', 'unsupported'])) {
      problems.push(`summary has unexpected key "${k}"`)
    }
    for (const k of ['pass', 'fail', 'unsupported'] as const) {
      const v = report.summary[k]
      if (typeof v !== 'number' || !Number.isInteger(v)) {
        problems.push(`summary.${k} must be an integer`)
      }
    }
    if (Array.isArray(report.results)) {
      const counts = { pass: 0, fail: 0, unsupported: 0 }
      for (const item of report.results) {
        if (isObject(item) && STATUSES.includes(item.status as string)) {
          counts[item.status as ClauseStatus]++
        }
      }
      for (const k of ['pass', 'fail', 'unsupported'] as const) {
        if (report.summary[k] !== counts[k]) {
          problems.push(`summary.${k} (${report.summary[k]}) does not match results (${counts[k]})`)
        }
      }
    }
  } else {
    problems.push('summary must be an object')
  }
  return problems
}
