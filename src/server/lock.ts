/**
 * In-process keyed async lock - serializes read-modify-write critical sections
 * by string key (SN-082). Correct for a SINGLE server instance, which is the
 * deployment profile this store targets (local self-host, one machine). If a
 * multi-instance deployment ever ships, these invariants must move to a shared
 * store's conditional writes; do not scale out before that lands.
 *
 * Used by the namespace write path (`ns:<slug>`) so two concurrent PUTs cannot
 * clobber each other's manifest update, and by the attestation-chain
 * read-modify-write so two verifies cannot interleave a stored chain.
 */

const locks = new Map<string, Promise<unknown>>()

export async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve()
  let release!: () => void
  const next = new Promise<void>(r => (release = r))
  // The map holds the chained tail - the promise a later caller waits on -
  // so cleanup compares against the same value that was stored.
  const tail = prev.then(() => next)
  locks.set(key, tail)
  await prev.catch(() => {}) // wait our turn; ignore prior errors
  try {
    return await fn()
  } finally {
    release()
    // Clean up if we're the tail of the chain to avoid unbounded growth.
    if (locks.get(key) === tail) locks.delete(key)
  }
}
