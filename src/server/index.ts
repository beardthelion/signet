/**
 * signet-store server entrypoint - crypto-blind sync store.
 *
 * The server never decrypts anything. Clients encrypt entries before upload;
 * the data at rest here is ciphertext plus the bounded metadata of SN-034.
 * The request logic lives in handler.ts so it can be tested without a socket.
 *
 * Bind policy (SN-091/SN-092):
 *   - default is loopback only (SIGNET_HOST=127.0.0.1)
 *   - SIGNET_MODE=local (the default) is the single-machine self-host
 *     profile: it binds loopback, period - a non-loopback SIGNET_HOST is a
 *     startup refusal, TLS or not
 *   - any other mode still refuses a non-loopback bind unless TLS is
 *     configured (SIGNET_TLS_CERT + SIGNET_TLS_KEY). DID authentication
 *     is not optional on this server - there is no open-auth mode - so the
 *     auth half of SN-091 always holds.
 */

import { readFileSync } from 'node:fs'
import { DEFAULT_PORT } from '../types/defaults.ts'
import { envInt } from './env.ts'
import { handleRequest } from './handler.ts'
import { caps } from './quota.ts'
import { getStore } from './store/blob.ts'

function isLoopback(host: string): boolean {
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true
  // Only a numeric 127.x.y.z literal - a prefix test would admit names like
  // "127.evil.com" that resolve anywhere.
  if (!/^127(\.\d{1,3}){3}$/.test(host)) return false
  return host.split('.').every(octet => Number(octet) <= 255)
}

const mode = (process.env.SIGNET_MODE ?? 'local').trim().toLowerCase()
const host = (process.env.SIGNET_HOST ?? '127.0.0.1').trim()
const port = envInt('PORT', DEFAULT_PORT)
const tlsCertPath = (process.env.SIGNET_TLS_CERT ?? '').trim()
const tlsKeyPath = (process.env.SIGNET_TLS_KEY ?? '').trim()

const fail = (msg: string): never => {
  process.stderr.write(`[signet] ${msg}\n`)
  process.exit(1)
}

if (!isLoopback(host)) {
  if (mode === 'local') {
    fail('local mode binds loopback only (SN-092); set SIGNET_MODE=hosted to expose this store')
  }
  if (!tlsCertPath || !tlsKeyPath) {
    fail('refusing non-loopback bind without TLS (SN-091): set SIGNET_TLS_CERT and SIGNET_TLS_KEY')
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
  `[signet] listening on ${host}:${server.port} • store=${getStore().describe()} • mode=${mode}`,
)
