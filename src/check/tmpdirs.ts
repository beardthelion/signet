/**
 * Temp-dir tracking for the conformance harness. Checks and targets mkdtemp
 * store roots and custody dirs that are run scratch, not artifacts; every
 * one registers here so runCheck can remove them all once the run ends.
 * Kept in its own module so clauses.ts can register dirs without importing
 * the runner (which imports clauses.ts) in a cycle.
 */

import { rmSync } from 'node:fs'

const tmpDirs = new Set<string>()

/** Register a temp dir for removal at the end of the next run. */
export function trackTmpDir(dir: string): string {
  tmpDirs.add(dir)
  return dir
}

/** Remove every registered temp dir. Idempotent. */
export function cleanupTmpDirs(): void {
  for (const dir of tmpDirs) rmSync(dir, { recursive: true, force: true })
  tmpDirs.clear()
}
