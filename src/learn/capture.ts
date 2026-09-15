/**
 * Learning capture: distilled learnings -> `memory/<type>/<slug>.md`
 * passport entries (suite U7; SPEC section 6 PS-120, section 5 PS-110,
 * plan KTD8).
 *
 * Every learned entry carries YAML frontmatter with `type:` (the KTD8
 * memory type) and `provenance: learned:<harness>` so a consuming harness
 * can label or down-weight non-self-authored content on recall. Entries
 * deliberately carry no timestamps or session ids: identical learned
 * content must render byte-identical plaintext so the client's
 * deterministic encryption (PS-033) produces the same ciphertext hash and
 * the manifest dedupes it — a re-learned fact is `unchanged`, never a
 * duplicate entry.
 *
 * Trust boundary: learned content is model-authored, so it is scanned
 * HERE, before the client sees it, and any entry the scan flags is
 * refused regardless of the client's scan mode — a `warn` client must not
 * soften the bar for content destined for long-term memory. Blocked
 * learnings are reported in the outcome, never silently written and never
 * silently dropped. The client push then applies its own PS-110 scan and
 * the manifest-hash delta, so capture inherits the same guarantees as
 * every other write path.
 */

import { createHash } from 'node:crypto'
import { MANIFEST_ENTRY_KEY, type PushResult } from '../client/client.ts'
import { scanEntry } from '../client/secretscan.ts'
import { EntryKey } from '../types/index.ts'
import { type DistillOptions, distillSession, type Learning } from './distill.ts'

/** The slice of the client capture needs: the encrypted push. */
export type LearnClient = {
  push(entries: Record<string, string>): Promise<PushResult>
}

export type BlockedLearning = {
  /** The entry key the learning would have been written under. */
  key: string
  /** Secret-scan rule ids that refused it. */
  rules: string[]
}

export type CaptureOutcome = {
  /** Entry keys the store accepted as new. */
  uploaded: string[]
  /** Entry keys whose ciphertext already matched the manifest (dedup). */
  unchanged: string[]
  /** Learnings the pre-push secret scan refused. */
  blocked: BlockedLearning[]
}

const MAX_SLUG_CHARS = 48

/** sha256 hex prefix used to disambiguate a slug collision. */
function shortHash(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 8)
}

/**
 * A URL-and-entry-key-safe slug from the learning title: lowercase alnum
 * words, hyphen-joined, bounded. The caller substitutes a hash when this
 * comes back empty.
 */
export function slugify(title: string): string {
  const words = title.toLowerCase().match(/[a-z0-9]+/g) ?? []
  return words.slice(0, 8).join('-').slice(0, MAX_SLUG_CHARS).replace(/-+$/, '')
}

/**
 * Render a learning as its entry key plus full entry content. The
 * frontmatter shape is fixed by PS-120/KTD8 and is deliberately free of
 * anything time- or session-varying so equal learnings dedupe.
 */
export function renderLearningEntry(
  learning: Learning,
  harness: string,
): { key: string; content: string } {
  const slug = slugify(learning.title) || `entry-${shortHash(learning.body)}`
  const key = `memory/${learning.type}/${slug}.md`
  const content =
    `---\n` +
    `type: ${learning.type}\n` +
    `provenance: learned:${harness}\n` +
    `description: ${learning.title.replace(/\s+/g, ' ').trim()}\n` +
    `---\n\n` +
    `${learning.body.trim()}\n`
  return { key, content }
}

/**
 * Distill + write learnings through the client's encrypted push.
 *
 * Returns immediately with an all-empty outcome when there is nothing to
 * write: no push means no HTTP and no manifest seq burn. Within one call,
 * identical learnings collapse to one entry; two different learnings that
 * slug-collide are disambiguated by a content-hash suffix so neither is
 * lost.
 */
export async function captureLearnings(
  client: LearnClient,
  learnings: Learning[],
  opts: { harness?: string } = {},
): Promise<CaptureOutcome> {
  const harness = opts.harness ?? 'suite'
  const entries: Record<string, string> = {}
  const blocked: BlockedLearning[] = []

  for (const learning of learnings) {
    const { key, content } = renderLearningEntry(learning, harness)
    let entryKey = key
    if (entries[entryKey] !== undefined && entries[entryKey] !== content) {
      entryKey = `${key.slice(0, -'.md'.length)}-${shortHash(content)}.md`
    }
    if (entries[entryKey] === content) continue
    if (!EntryKey.safeParse(entryKey).success) continue
    entries[entryKey] = content
  }

  const clean: Record<string, string> = {}
  for (const [key, content] of Object.entries(entries)) {
    const findings = scanEntry(key, content)
    if (findings.length > 0) {
      blocked.push({ key, rules: findings.map(f => f.rule) })
    } else {
      clean[key] = content
    }
  }
  if (Object.keys(clean).length === 0) return { uploaded: [], unchanged: [], blocked }

  const result = await client.push(clean)
  return {
    uploaded: result.uploaded.filter(k => k !== MANIFEST_ENTRY_KEY),
    unchanged: result.unchanged,
    blocked,
  }
}

/**
 * The session-end / explicit-save entry point: distill the session content
 * and capture whatever it yields. An empty distillation writes nothing.
 */
export async function captureSession(
  client: LearnClient,
  sessions: string | string[],
  opts: { harness?: string } & DistillOptions = {},
): Promise<CaptureOutcome> {
  return captureLearnings(client, distillSession(sessions, opts), opts)
}
