/**
 * Signet tools, decoupled from the MCP transport so they can be unit tested
 * directly against a SignetClient. server.ts wraps each result into the MCP
 * content shape; everything substantive lives here.
 *
 * Trust boundary: all encryption/decryption happens inside the client in THIS
 * process, which holds the passphrase and the holder signing key. The remote
 * store only ever sees ciphertext (SN-034), so recall/search/config_get and
 * grant_list all run locally over pulled plaintext.
 *
 * Three spec rules are enforced HERE, at the tool layer, because the MCP
 * surface is where a consuming model could route around them:
 *   - SN-062: signet_grant_record is the only write path for grants. `save`
 *     and `delete` refuse `grants/` keys outright, and `grantRecord` refuses
 *     any grant the holder has not explicitly confirmed. There is no tool that
 *     applies a grant to the harness - grants port as records (SN-061).
 *   - SN-070: permission-affecting keys must not land under `config/` through
 *     any tool, so `save` applies the same isDeniedConfigKey check as
 *     `configSet`.
 *   - `identity/` entries are written by the client itself (did.json at init,
 *     rotations, the signed manifest); the tools refuse to write or delete
 *     under it rather than let a tool call clobber the signet's root of
 *     trust.
 */

import type { PullResult, PushResult } from '../client/client.ts'
import {
  MANIFEST_ENTRY_KEY,
  SignetDecryptError,
  SignetHttpError,
  SignetIntegrityError,
  SignetSkippedError,
  SignetTimeoutError,
} from '../client/client.ts'
import { SecretFoundError } from '../client/secretscan.ts'
import { EntryKey, Grant, isDeniedConfigKey, isKeySegment, type Section } from '../types/index.ts'
import { rankEntries } from './relevance.ts'

export type ToolResult = { text: string; isError?: boolean }

/**
 * The slice of SignetClient these tools actually use. Structural rather than
 * the concrete class so a test can drive a specific server refusal through the
 * tools without a live server; the real client still has to satisfy it.
 */
export type SignetToolClient = {
  push(entries: Record<string, string>, opts?: { deletions?: string[] }): Promise<PushResult>
  pull(): Promise<PullResult>
  hashes(): Promise<Record<string, string>>
  readEntry(entryKey: string): Promise<string | null>
  /**
   * Pull + decrypt only one section's entries against the verified manifest.
   * Optional: clients without it fall back to a full pull filtered locally.
   */
  pullSection?(section: Section): Promise<Record<string, string>>
  readonly namespace: string
}

export type ToolOptions = {
  /** DID recorded as `granted_by` when grant_record's caller does not say. */
  holderDid?: string
  /**
   * Called after every successful write so the host can persist the manifest
   * seq the client just published (SN-041 anti-rollback state lives in
   * custody, outside this process's memory).
   */
  onSync?: () => void | Promise<void>
}

const ok = (text: string): ToolResult => ({ text })
const fail = (text: string): ToolResult => ({ text, isError: true })

/**
 * What text the STORE chose is allowed to put into a model's context.
 *
 * A refusal message, error code, or detail field is read off a response body,
 * so a broken or hostile store writes straight into the conversation unless
 * it passes through here. Newlines and escapes are the sharp part: they let
 * that text forge turns or instructions rather than merely be long.
 */
function bounded(message: string, max = 300): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point.
  const clean = message.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim()
  return clean.length > max ? `${clean.slice(0, max)}...` : clean
}

function snippet(content: string, max = 200): string {
  const oneLine = content.replace(/\s+/g, ' ').trim()
  return oneLine.length > max ? `${oneLine.slice(0, max)}...` : oneLine
}

// Output bounds: a signet is holder data, but its size is unbounded from
// the model's perspective - an entry can be megabytes and a namespace can
// hold thousands of keys. Tool results are capped so one call cannot flood
// the context; truncation is always marked, never silent.
const RECALL_ENTRY_MAX = 4_000
const RECALL_TOTAL_MAX = 16_000
const SEARCH_HIT_MAX = 50
const LIST_KEY_MAX = 200
const GET_ENTRY_MAX = 16_000

/**
 * Render a failure as text a model can act on. Each typed error gets its own
 * wording and its own recovery move; anything unrecognized is bounded and
 * passed through rather than dressed up.
 */
function renderError(action: string, e: unknown, tail: string): string {
  if (e instanceof SecretFoundError) {
    return `${action} refused: the pre-encryption scan found what looks like a live credential, and secrets never enter a signet (SN-110). ${bounded(e.message, 500)} ${tail}`
  }
  if (e instanceof SignetIntegrityError) {
    return `${action} failed: the signet's signed integrity manifest did not verify, so nothing read or written here can be trusted (SN-041). ${bounded(e.message)} Do not retry the same call; tell the user the signet failed an integrity check. ${tail}`
  }
  if (e instanceof SignetDecryptError) {
    return `${action} failed: a stored entry did not decrypt with this passphrase (${bounded(e.entryKey, 120)}). The passphrase this process holds is probably not the one the signet was created with; tell the user rather than writing over the signet. ${tail}`
  }
  if (e instanceof SignetSkippedError) {
    const reasons = e.skipped
      .map(s => `${bounded(s.key, 120)} (${bounded(s.reason, 60)})`)
      .join(', ')
    return `${action} refused by the store: ${reasons}. Shorten or split the content and try again; oversized entries are skipped, never silently dropped (SN-081). ${tail}`
  }
  if (e instanceof SignetTimeoutError) {
    return `${action} failed: the store accepted the connection but did not answer within ${e.timeoutMs}ms. Retry once; if it keeps happening, tell the user the store is slow or stuck. ${tail}`
  }
  if (e instanceof SignetHttpError) {
    if (e.status === 401) {
      return `${action} refused: the store rejected this signet's identity (401 unauthorized). Retrying cannot succeed; tell the user the custody signing key is not being accepted. ${tail}`
    }
    if (e.status === 403) {
      return `${action} refused: this signing key is not authorized for the signet's namespace (403 forbidden). The namespace is bound to the genesis DID forever (SN-010); tell the user the custody does not match this signet. ${tail}`
    }
    if (e.status === 409) {
      return `${action} refused: the signet changed on the store after this session last read it, so the base this write was computed from is stale (409). Re-read with signet_recall, reapply the change on top of what is stored now, and try again. ${tail}`
    }
    if (e.status === 429) {
      return `${action} refused: the store is rate limiting (429). Do not retry in a loop; tell the user signet writes are paused. ${tail}`
    }
    return `${action} failed: the store answered ${e.status} (${bounded(e.code, 60)}). ${tail}`
  }
  return `${action} failed: ${bounded((e as Error).message ?? String(e))}. ${tail}`
}

/**
 * Entry keys a tool must not write through `save`/`delete`. Grants go through
 * grant_record only (SN-062); identity material is client-managed. Returns the
 * refusal text, or null when the key is writable through the general tools.
 */
function writeRefusal(key: string): string | null {
  const section = key.split('/')[0]
  if (section === 'grants') {
    return `"${key}" is under grants/: the only write path for grants is signet_grant_record, and it records only holder-confirmed grants (SN-062).`
  }
  if (section === 'identity') {
    return `"${key}" is under identity/: identity material (did.json, rotations, the signed manifest) is written by the client itself, never through a tool.`
  }
  if (section === 'config' && isDeniedConfigKey(key)) {
    return `"${key}" looks permission-affecting: keys matching the SN-070 denylist are never stored under config/. Record holder-confirmed permission state with signet_grant_record instead.`
  }
  return null
}

/** Validate a caller-supplied entry key before anything touches storage. */
function keyError(key: string): string | null {
  if (!EntryKey.safeParse(key).success) {
    return `"${bounded(key, 120)}" is not a valid entry key: use <section>/<path> where section is memory, config, sessions, grants, or identity, with no "..", no "//", no leading or trailing "/", and no backslash (SN-020/021).`
  }
  return null
}

/**
 * A grants/<id>.json entry key, or null when the id cannot form one. The id
 * must be a single flat segment: a nested grants/a/b.json would be a second,
 * shadow vocabulary for grant identity.
 */
function grantEntryKey(id: string): string | null {
  if (!isKeySegment(id)) return null
  const key = `grants/${id}.json`
  return EntryKey.safeParse(key).success ? key : null
}

export type SignetTools = ReturnType<typeof makeTools>

export function makeTools(client: SignetToolClient, opts: ToolOptions = {}) {
  const sync = () => opts.onSync?.()

  /** Pull and drop the client-managed manifest entry from the result set. */
  const pullUserEntries = async (): Promise<Record<string, string>> => {
    const { entries } = await client.pull()
    // A successful pull adopts the verified manifest's seq in memory; hand
    // it to the host so the SN-041 floor survives this process.
    await sync()
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(entries)) if (k !== MANIFEST_ENTRY_KEY) out[k] = v
    return out
  }

  /**
   * One section's plaintext entries. Uses the client's section-scoped pull
   * when it has one so grant_list/config_get don't download the whole
   * signet; otherwise a full pull filtered locally - identical results.
   */
  const pullSectionEntries = async (section: Section): Promise<Record<string, string>> => {
    if (client.pullSection) {
      const entries = await client.pullSection(section)
      await sync()
      return entries
    }
    const entries = await pullUserEntries()
    const prefix = `${section}/`
    return Object.fromEntries(Object.entries(entries).filter(([k]) => k.startsWith(prefix)))
  }

  return {
    /** Persist one entry (encrypted before upload, scanned first per SN-110). */
    async save(key: string, content: string): Promise<ToolResult> {
      const bad = keyError(key)
      if (bad) return fail(bad)
      const refusal = writeRefusal(key)
      if (refusal) return fail(`Refused to save: ${refusal}`)
      try {
        const r = await client.push({ [key]: content })
        await sync()
        if (r.tombstoned.includes(key)) {
          return ok(
            `not saved: "${key}" was deleted after this session last read the signet, and the deletion outranks this write (SN-084). Re-read the signet and save again to deliberately restore it.`,
          )
        }
        const status = r.uploaded.includes(key)
          ? 'saved'
          : r.unchanged.includes(key)
            ? 'unchanged'
            : 'recorded'
        return ok(`${status} "${key}" in ${r.namespace} (manifest seq ${r.seq})`)
      } catch (e) {
        return fail(renderError(`Saving "${bounded(key, 120)}"`, e, 'Nothing was stored.'))
      }
    },

    /** Rank stored entries by relevance to a natural-language query. */
    async recall(query: string, limit = 5): Promise<ToolResult> {
      try {
        const entries = await pullUserEntries()
        if (Object.keys(entries).length === 0) return ok('(the signet is empty)')
        const ranked = rankEntries(query, entries, limit)
        if (ranked.length === 0) {
          return ok(`(nothing in the signet looks relevant to "${bounded(query, 120)}")`)
        }
        // Entries can be arbitrarily large; each is capped and the whole
        // answer carries a total budget so recall cannot flood the context.
        const parts: string[] = []
        let budget = RECALL_TOTAL_MAX
        let dropped = 0
        for (const r of ranked) {
          const content = r.content.trim()
          const clipped =
            content.length > RECALL_ENTRY_MAX
              ? `${content.slice(0, RECALL_ENTRY_MAX)}... [truncated]`
              : content
          const block = `### ${r.key}\n${clipped}`
          if (block.length > budget) {
            dropped++
            continue
          }
          parts.push(block)
          budget -= block.length
        }
        const trailer =
          dropped > 0
            ? `\n\n(${dropped} more relevant entr${dropped === 1 ? 'y' : 'ies'} not shown)`
            : ''
        return ok(
          `${parts.length} relevant entr${parts.length === 1 ? 'y' : 'ies'}:\n\n${parts.join('\n\n')}${trailer}`,
        )
      } catch (e) {
        return fail(renderError('Recalling entries', e, 'Nothing was read.'))
      }
    },

    /**
     * Fetch one entry by exact key. The direct-fetch complement to
     * recall/search: when the caller already knows the key (from list or a
     * reference inside another entry) this avoids a full pull.
     */
    async get(key: string): Promise<ToolResult> {
      const bad = keyError(key)
      if (bad) return fail(bad)
      try {
        const content = await client.readEntry(key)
        await sync()
        if (content === null) return ok(`(no entry "${bounded(key, 120)}" is stored)`)
        const clipped =
          content.length > GET_ENTRY_MAX
            ? `${content.slice(0, GET_ENTRY_MAX)}... [truncated]`
            : content
        return ok(`${key}:\n${clipped}`)
      } catch (e) {
        return fail(renderError(`Reading "${bounded(key, 120)}"`, e, 'Nothing was read.'))
      }
    },

    /** Literal substring search over entry keys and decrypted content. */
    async search(query: string): Promise<ToolResult> {
      const needle = query.trim().toLowerCase()
      if (!needle) return fail('search needs a non-empty query')
      try {
        const entries = await pullUserEntries()
        const hits = Object.entries(entries).filter(
          ([key, content]) =>
            key.toLowerCase().includes(needle) || content.toLowerCase().includes(needle),
        )
        if (hits.length === 0) return ok(`no matches for "${bounded(query, 120)}"`)
        const shown = hits.slice(0, SEARCH_HIT_MAX)
        const body = shown.map(([key, content]) => `- ${key}: ${snippet(content)}`).join('\n')
        const trailer =
          hits.length > shown.length ? `\n(${hits.length - shown.length} more not shown)` : ''
        return ok(`${hits.length} match(es) for "${bounded(query, 120)}":\n${body}${trailer}`)
      } catch (e) {
        return fail(renderError('Searching entries', e, 'Nothing was read.'))
      }
    },

    /** List entry keys (no content downloaded). `section` narrows to one. */
    async list(section?: Section): Promise<ToolResult> {
      try {
        const hashes = await client.hashes()
        await sync() // keep seq persistence uniform across the read tools
        // The hashes view is unsigned store output: only keys that pass the
        // entry-key grammar may reach a model's context, and each passes
        // through the bounded renderer.
        let keys = Object.keys(hashes)
          .filter(k => EntryKey.safeParse(k).success)
          .sort()
        if (section) keys = keys.filter(k => k.split('/')[0] === section)
        if (keys.length === 0) {
          return ok(
            section ? `(no entries under ${bounded(section, 40)}/)` : '(the signet is empty)',
          )
        }
        const shown = keys.slice(0, LIST_KEY_MAX)
        const trailer =
          keys.length > shown.length ? `\n(${keys.length - shown.length} more not shown)` : ''
        return ok(
          `${keys.length} entr${keys.length === 1 ? 'y' : 'ies'}:\n${shown.map(k => `- ${bounded(k, 260)}`).join('\n')}${trailer}`,
        )
      } catch (e) {
        return fail(renderError('Listing entries', e, 'No entry keys were read.'))
      }
    },

    /**
     * Delete one entry. Destructive: the key must be named explicitly and
     * must be a valid entry key. identity/ and grants/ keys are refused.
     */
    async delete(key: string): Promise<ToolResult> {
      const bad = keyError(key)
      if (bad) return fail(bad)
      const section = key.split('/')[0]
      if (section === 'identity') {
        return fail(
          `Refused to delete "${key}": identity material is client-managed and deleting it would corrupt the signet's root of trust.`,
        )
      }
      if (section === 'grants') {
        return fail(
          `Refused to delete "${key}": grants are written only through signet_grant_record, and that tool never deletes (SN-062). A grant record cannot be removed through this tool.`,
        )
      }
      try {
        const r = await client.push({}, { deletions: [key] })
        await sync()
        if (!r.deleted.includes(key)) {
          return ok(`nothing named "${key}" is stored; the signet is unchanged`)
        }
        return ok(`deleted "${key}" (manifest seq ${r.seq})`)
      } catch (e) {
        return fail(renderError(`Deleting "${bounded(key, 120)}"`, e, `"${key}" is still stored.`))
      }
    },

    /**
     * Read config state. With `key`, reads the single `config/<key>` entry;
     * without it, returns every entry under config/.
     */
    async configGet(key?: string): Promise<ToolResult> {
      try {
        if (key !== undefined) {
          const entryKey = `config/${key}`
          const bad = keyError(entryKey)
          if (bad) return fail(bad)
          const content = await client.readEntry(entryKey)
          await sync() // the read verified a manifest; persist the seq
          if (content === null) return ok(`(no config entry "${bounded(key, 120)}" is stored)`)
          return ok(`config/${key}:\n${content}`)
        }
        const entries = await pullSectionEntries('config')
        const config = Object.entries(entries).sort(([a], [b]) => (a < b ? -1 : 1))
        if (config.length === 0) return ok('(no config entries stored)')
        const body = config.map(([k, v]) => `### ${k}\n${v.trim()}`).join('\n\n')
        return ok(`${config.length} config entr${config.length === 1 ? 'y' : 'ies'}:\n\n${body}`)
      } catch (e) {
        return fail(renderError('Reading config', e, 'Nothing was read.'))
      }
    },

    /**
     * Write one `config/<key>` entry. SN-070: permission-affecting keys are
     * refused - that state belongs in grants/, recorded holder-confirmed.
     */
    async configSet(key: string, value: string): Promise<ToolResult> {
      if (isDeniedConfigKey(key)) {
        return fail(
          `Refused to set config "${bounded(key, 120)}": the key matches the SN-070 denylist (permission/grant/allow/deny/trust/sandbox/exec/approve/policy). Permission state is never stored under config/; record a holder-confirmed grant with signet_grant_record instead.`,
        )
      }
      const entryKey = `config/${key}`
      const bad = keyError(entryKey)
      if (bad) return fail(bad)
      try {
        const r = await client.push({ [entryKey]: value })
        await sync()
        return ok(`saved "${entryKey}" in ${r.namespace} (manifest seq ${r.seq})`)
      } catch (e) {
        return fail(renderError(`Setting config "${bounded(key, 120)}"`, e, 'Nothing was stored.'))
      }
    },

    /** Read-only enumeration of recorded grants (SN-060/061). */
    async grantList(): Promise<ToolResult> {
      try {
        const entries = await pullSectionEntries('grants')
        const grants = Object.entries(entries).sort(([a], [b]) => (a < b ? -1 : 1))
        if (grants.length === 0) return ok('(no grants recorded)')
        const lines = grants.map(([k, v]) => {
          let parsedJson: unknown
          try {
            parsedJson = JSON.parse(v)
          } catch {
            return `- ${k}: (unparseable grant record)`
          }
          const parsed = Grant.safeParse(parsedJson)
          if (!parsed.success) return `- ${k}: (unparseable grant record)`
          const g = parsed.data
          return `- ${k}: ${g.action} on "${g.scope}" (by ${g.granted_by}, at ${g.granted_at}${g.expires_at ? `, expires ${g.expires_at}` : ''})`
        })
        return ok(
          `${grants.length} recorded grant${grants.length === 1 ? '' : 's'} (records only - a consuming harness must re-confirm before honoring any of them, SN-061):\n${lines.join('\n')}`,
        )
      } catch (e) {
        return fail(renderError('Listing grants', e, 'Nothing was read.'))
      }
    },

    /**
     * Record a holder-confirmed grant under grants/<id>.json (SN-062). The
     * `confirmed` flag must be explicitly true - a grant the holder did not
     * confirm is never written. Recording is all this does: nothing here or
     * anywhere applies the grant to the running harness (SN-061).
     */
    async grantRecord(input: {
      id: string
      action: unknown
      scope: string
      constraints?: Record<string, unknown>
      granted_by?: string
      granted_at?: string
      expires_at?: string
      confirmed?: boolean
    }): Promise<ToolResult> {
      if (input.confirmed !== true) {
        return fail(
          'Refused to record: signet_grant_record writes only grants the holder explicitly confirmed. Ask the holder, then call again with confirmed: true (SN-062).',
        )
      }
      const entryKey = grantEntryKey(input.id)
      if (entryKey === null) {
        return fail(
          `"${bounded(input.id, 120)}" cannot form a grants/<id>.json entry key: use letters, digits, ".", "_", "-" and start with a letter or digit.`,
        )
      }
      const candidate = {
        id: input.id,
        action: input.action,
        scope: input.scope,
        ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
        granted_by: input.granted_by ?? opts.holderDid ?? 'holder',
        granted_at: input.granted_at ?? new Date().toISOString(),
        ...(input.expires_at !== undefined ? { expires_at: input.expires_at } : {}),
      }
      const parsed = Grant.safeParse(candidate)
      if (!parsed.success) {
        const issues = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')
        return fail(
          `Refused to record: the grant fails the SN-060 vocabulary - ${bounded(issues, 300)}`,
        )
      }
      try {
        const r = await client.push({ [entryKey]: `${JSON.stringify(parsed.data, null, 2)}\n` })
        await sync()
        return ok(
          `recorded grant "${parsed.data.id}" at ${entryKey} (manifest seq ${r.seq}). This is a record only: no harness has applied it, and any consumer must re-confirm with the holder before honoring it (SN-061).`,
        )
      } catch (e) {
        return fail(
          renderError(`Recording grant "${bounded(input.id, 120)}"`, e, 'Nothing was stored.'),
        )
      }
    },
  }
}
