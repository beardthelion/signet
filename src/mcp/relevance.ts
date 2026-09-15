/**
 * Local relevance ranking for passport_recall.
 *
 * Recall happens entirely client-side: the store only ever holds ciphertext
 * (PS-034), so it cannot rank for us. The client pulls and decrypts, then each
 * entry is scored against the query with a small TF-style ranker tuned for
 * passport entries: matches in the YAML frontmatter (memory entries carry
 * `type:`/`provenance:` per PS-120) and in the entry key count for more than
 * matches buried in the body, and an entry must cover a decent share of the
 * query terms to rank at all.
 */

export type ScoredEntry = { key: string; score: number; content: string }

// Common words that shouldn't drive relevance.
const STOP = new Set(
  'the a an and or to of in is it for on with that this i you my your we our as at be are was were do does what how when which their them they me'.split(
    ' ',
  ),
)

function tokenize(s: string): string[] {
  return (s.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter(t => t.length > 1 && !STOP.has(t))
}

/** Pull the `description:` value out of YAML-ish frontmatter, if present. */
function frontmatterDescription(content: string): string {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(content)
  if (!m) return ''
  const d = /description:\s*(.+)/i.exec(m[1])
  return d ? d[1] : ''
}

/**
 * Rank entries (entryKey -> plaintext) against a query. Returns the top `limit`
 * by score, highest first; entries with no query-term overlap are dropped.
 */
export function rankEntries(
  query: string,
  entries: Record<string, string>,
  limit = 5,
): ScoredEntry[] {
  const qTerms = new Set(tokenize(query))
  if (qTerms.size === 0) return []

  const scored: ScoredEntry[] = []
  for (const [key, content] of Object.entries(entries)) {
    const keyTokens = new Set(tokenize(key))
    const descTokens = new Set(tokenize(frontmatterDescription(content)))
    const bodyTf = new Map<string, number>()
    for (const t of tokenize(content)) bodyTf.set(t, (bodyTf.get(t) ?? 0) + 1)

    let score = 0
    let covered = 0
    for (const t of qTerms) {
      let hit = false
      if (bodyTf.has(t)) {
        score += 1 + Math.log(bodyTf.get(t)!)
        hit = true
      }
      if (descTokens.has(t)) {
        score += 3
        hit = true
      }
      if (keyTokens.has(t)) {
        score += 2
        hit = true
      }
      if (hit) covered++
    }
    if (covered === 0) continue
    // Reward entries that cover more of the query, penalize one-term flukes.
    score *= covered / qTerms.size
    scored.push({ key, score, content })
  }

  scored.sort((a, b) => b.score - a.score || a.key.localeCompare(b.key))
  return scored.slice(0, limit)
}
