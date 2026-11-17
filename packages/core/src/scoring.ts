import { SEVERITY_RANK, SEVERITY_WEIGHT } from './types.ts';
import type { Finding, Verdict } from './types.ts';

export const LIKELY_MALICIOUS_SCORE = 60;
export const SUSPICIOUS_SCORE = 25;

/**
 * 0–100 risk score. Each rule contributes the sum of its findings' weights,
 * capped at twice the weight of its most severe finding, so one noisy rule
 * across many files cannot dominate the score.
 */
export function scoreFindings(findings: readonly Finding[]): number {
  const perRule = new Map<string, { sum: number; cap: number }>();
  for (const f of findings) {
    const w = SEVERITY_WEIGHT[f.severity];
    const e = perRule.get(f.ruleId) ?? { sum: 0, cap: 0 };
    e.sum += w;
    e.cap = Math.max(e.cap, 2 * w);
    perRule.set(f.ruleId, e);
  }
  let total = 0;
  for (const e of perRule.values()) total += Math.min(e.sum, e.cap);
  return Math.min(100, total);
}

/**
 * Any Critical finding means likely malicious; any High finding means at least
 * suspicious. Otherwise the score decides, so several Medium findings add up.
 */
export function verdictFor(score: number, findings: readonly Finding[]): Verdict {
  const top = findings.reduce((m, f) => Math.max(m, SEVERITY_RANK[f.severity]), -1);
  if (top >= SEVERITY_RANK.critical || score >= LIKELY_MALICIOUS_SCORE) return 'likely-malicious';
  if (top >= SEVERITY_RANK.high || score >= SUSPICIOUS_SCORE) return 'suspicious';
  return 'no-strong-signals';
}
