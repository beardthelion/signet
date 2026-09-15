/**
 * passport-store server entrypoint — crypto-blind sync store.
 *
 * The server never decrypts anything. Clients encrypt entries before upload;
 * the data at rest here is ciphertext plus the bounded metadata of PS-034.
 * The request logic lives in handler.ts so it can be tested without a socket.
 *
 * Bind policy (PS-091/PS-092):
 *   - default is loopback only (PASSPORT_HOST=127.0.0.1)
 *   - PASSPORT_MODE=local (the default) is the single-machine self-host
 *     profile: it binds loopback, period — a non-loopback PASSPORT_HOST is a
 *     startup refusal, TLS or not
 *   - any other mode still refuses a non-loopback bind unless TLS is
 *     configured (PASSPORT_TLS_CERT + PASSPORT_TLS_KEY). DID authentication
 *     is not optional on this server — there is no open-auth mode — so the
 *     auth half of PS-091 always holds.
 */

import { readFileSync } from 'node:fs'
import { handleRequest } from './handler.ts'
import { caps } from './quota.ts'
import { getStore } from './store/blob.ts'

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  const n = Number(raw)
  return Number.isFinite(n) ? n : fallback
}

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '::1' || host === '[::1]' || host.startsWith('127.')
}

const mode = (process.env.PASSPORT_MODE ?? 'local').trim().toLowerCase()
const host = (process.env.PASSPORT_HOST ?? '127.0.0.1').trim()
const port = envInt('PORT', 8788)
const tlsCertPath = (process.env.PASSPORT_TLS_CERT ?? '').trim()
const tlsKeyPath = (process.env.PASSPORT_TLS_KEY ?? '').trim()

const fail = (msg: string): never => {
  process.stderr.write(`[passport] ${msg}\n`)
  process.exit(1)
}

if (!isLoopback(host)) {
  if (mode === 'local') {
    fail('local mode binds loopback only (PS-092); set PASSPORT_MODE=hosted to expose this store')
  }
  if (!tlsCertPath || !tlsKeyPath) {
    fail(
      'refusing non-loopback bind without TLS (PS-091): set PASSPORT_TLS_CERT and PASSPORT_TLS_KEY',
    )
  }
}

const server = Bun.serve({
  hostname: host,
  port,
  idleTimeout: 60,
  // Hard cap on request body size, enforced by the runtime even when a client
  // omits or lies about content-length (the handler's content-length check is
  // just a faster, friendlier early-out).
  maxRequestBodySize: caps.body,
  tls:
    tlsCertPath && tlsKeyPath
      ? { cert: readFileSync(tlsCertPath), key: readFileSync(tlsKeyPath) }
      : undefined,
  fetch: handleRequest,
})

console.log(
  `[passport] listening on ${host}:${server.port} • store=${getStore().describe()} • mode=${mode}`,
)
