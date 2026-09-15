/**
 * Numeric env reads shared by the server modules. Blank or unparseable
 * values fall back rather than turning a typo into NaN policy.
 */
export function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  const n = Number(raw)
  return Number.isFinite(n) ? n : fallback
}
