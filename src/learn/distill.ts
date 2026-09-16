/**
 * Distillation: raw session content -> typed learning candidates
 * (SPEC section 6 / SN-120).
 *
 * The input is whatever a harness calls "the session": transcript text,
 * pulled `sessions/<id>/<seq>` chunks, or a file the holder points at. The
 * output uses the SN-120 memory taxonomy, which is also the first path
 * segment of the entry key (`memory/<type>/<slug>.md`):
 *
 *   user      - holder preferences and standing facts about the user
 *   feedback  - corrections, solved problems, and "how to work" guidance
 *   project   - project decisions, conventions, and state
 *   reference - pointers to external material (docs, tickets, runbooks)
 *
 * This is a deterministic heuristic extractor, not a model call: it lifts
 * lines that carry a learnable signal and ignores everything else. It errs
 * toward missing a learning over writing noise, so an empty result is the
 * correct answer for a session with nothing worth keeping, and callers
 * MUST treat empty as "write nothing" - no entries, no manifest churn.
 */

const LEARNING_TYPES = ['user', 'feedback', 'project', 'reference'] as const
export type LearningType = (typeof LEARNING_TYPES)[number]

export type Learning = {
  /** SN-120 memory type; becomes the `memory/<type>/` segment and `type:` field. */
  type: LearningType
  /** One-line summary; becomes the frontmatter `description:` and slug source. */
  title: string
  /** The distilled content. */
  body: string
}

export type DistillOptions = {
  /** Max learnings per call. Default 16. */
  maxLearnings?: number
}

const DEFAULT_MAX_LEARNINGS = 16

// A candidate line needs enough substance to stand alone on recall later;
// a bare "fixed it" or "we decided" fragment teaches nothing.
const MIN_CANDIDATE_CHARS = 24
const MAX_CANDIDATE_CHARS = 2000
const MAX_TITLE_CHARS = 100

/**
 * Ordered rules: the first match wins, so more specific classes come
 * before broader ones. `reference` is checked first because a line that
 * points at external material is a pointer regardless of what else it
 * says; `feedback` covers both corrections and solved-problem fixes
 * ("root cause", "fixed by"); `project` covers decisions and conventions.
 */
const RULES: { type: LearningType; re: RegExp }[] = [
  {
    type: 'reference',
    re: /\bhttps?:\/\/|\b(?:docs?|documentation|runbook|spec|ticket|issue|pull request|pr)\s+(?:at|is at|lives at|for|#)\b/i,
  },
  {
    type: 'user',
    re: /\b(?:i|the user|we)\s+(?:prefer|prefers|like|likes|want|wants|always use|usually use)\b|\bplease (?:use|always|never|keep)\b|\bmy (?:preference|preferred)\b/i,
  },
  {
    type: 'feedback',
    re: /\b(?:do not|don't|never|stop|avoid|instead of|corrected|the fix|fix was|fixed by|root cause|solved|the solution|workaround|turns out|the problem was|the bug was)\b/i,
  },
  {
    type: 'project',
    re: /\b(?:we decided|decision|decided to|chose|chosen|going with|agreed to|the plan is|migrat\w+|deprecat\w+|deadline|roadmap|convention|renamed to)\b/i,
  },
]

// Transcript speaker labels and markdown list markers are framing, not
// content; strip them before classification so "user: I prefer vim" still
// reads as a preference.
const SPEAKER_RE = /^(?:user|human|assistant|agent|system|tool)\s*[:>]\s*/i
const LIST_MARKER_RE = /^[-*+]\s+/

function stripFraming(line: string): string {
  return line.replace(SPEAKER_RE, '').replace(LIST_MARKER_RE, '').trim()
}

/** The first sentence, or the line itself when it has no sentence break. */
function titleFor(text: string): string {
  const sentenceEnd = text.search(/[.!?](\s|$)/)
  const title = sentenceEnd > 0 ? text.slice(0, sentenceEnd + 1) : text
  return title.length > MAX_TITLE_CHARS ? `${title.slice(0, MAX_TITLE_CHARS)}...` : title
}

/** Whitespace- and case-normalized identity for dedup. */
function normalize(text: string): string {
  return text.toLowerCase().replace(/\s+/g, ' ').trim()
}

/**
 * Distill session content into typed learning candidates.
 *
 * Lines inside fenced code blocks are skipped: transcripts carry code, and
 * code full of words like "token" or "decision" is not a learning. Equal
 * content (after whitespace/case normalization) yields one candidate, so
 * the same fact repeated across chunks dedupes here before it can become
 * two entries.
 */
export function distillSession(sessions: string | string[], opts: DistillOptions = {}): Learning[] {
  const texts = typeof sessions === 'string' ? [sessions] : sessions
  const max = opts.maxLearnings ?? DEFAULT_MAX_LEARNINGS
  const out: Learning[] = []
  const seen = new Set<string>()
  let inFence = false

  for (const text of texts) {
    for (const rawLine of text.split('\n')) {
      const trimmed = rawLine.trim()
      if (trimmed.startsWith('```')) {
        inFence = !inFence
        continue
      }
      if (inFence) continue
      const line = stripFraming(trimmed)
      if (line.length < MIN_CANDIDATE_CHARS || line.length > MAX_CANDIDATE_CHARS) continue
      const rule = RULES.find(r => r.re.test(line))
      if (!rule) continue
      const norm = normalize(line)
      if (seen.has(norm)) continue
      seen.add(norm)
      out.push({ type: rule.type, title: titleFor(line), body: `${line}\n` })
      if (out.length >= max) return out
    }
  }
  return out
}
