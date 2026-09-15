/**
 * One stderr JSON-lines record, timestamped. The field set is a fixed
 * allowlist at every call site: on a crypto-blind server the space of
 * things that must never appear in a log (entry keys, raw namespaces,
 * ciphertext, tokens) is open-ended, so a fixed shape is the only safe one.
 */
export function logJsonLine(fields: Record<string, string | number>): void {
  process.stderr.write(`${JSON.stringify({ timestamp: new Date().toISOString(), ...fields })}\n`)
}
