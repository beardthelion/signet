/**
 * Runnable fault stub: serves makeStubTarget over a real socket so the
 * passport-check CLI can be exercised end to end against a non-conformant
 * target.
 *
 *   bun run tests/fixtures/fault-server.ts <fault> [port]
 *
 * Prints `fault-server:<port>` once listening.
 */

import { makeStubTarget, type StubFaults } from './stub-target.ts'

const fault = process.argv[2] ?? ''
const port = Number(process.argv[3] ?? '0')
const target = makeStubTarget({ [fault]: true } as StubFaults, `stub:${fault}`)

const server = Bun.serve({
  hostname: '127.0.0.1',
  port,
  fetch: req => target.fetch(req),
})
console.log(`fault-server:${server.port}`)
