import { createHash } from 'node:crypto';
import type { EntryResult, ManifestEntry, ScannerReport, Severity } from './types.ts';
import type { ScanOutcome } from './scanner.ts';

export const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const FLAGGED = new Set(['suspicious', 'likely-malicious']);
/** Benign sets that count toward the false-alarm rate. Dual-use tools are reported separately. */
const FALSE_ALARM_SETS = new Set(['benign-popular', 'benign-random', 'benign-tricky']);
const SENSITIVE_SETS = new Set(['malicious', 'technique-copy']);

export interface RateStat {
  total: number;
  hits: number;
  rate: number | null;
}

export interface RuleStat {
  maliciousHits: number;
  benignHits: number;
  techniqueCopyHits: number;
  /** maliciousHits / (maliciousHits + benignHits); null when neither set hit it */
  precision: number | null;
}

export interface Scorecard {
  generatedAt: string;
  options: { cutoff?: string; limit?: number; seed?: string; redacted: boolean };
  scanner?: { tool: string; version: string };
  counts: {
    total: number;
    scanned: number;
    errors: number;
    bySet: Record<string, { total: number; scanned: number; errors: number }>;
  };
  errors: { id: string; set: string; error: string }[];
  /** Malicious repos rated suspicious or worse */
  detection: RateStat;
  detectionAfterCutoff: RateStat | null;
  /** Benign repos (excluding dual-use) with any High or Critical finding */
  falseAlarms: RateStat;
  /** Benign repos (excluding dual-use) rated suspicious or worse */
  benignSuspiciousOrWorse: RateStat;
  dualUseHighOrCritical: RateStat;
  techniqueCopies: { total: number; missed: { id: string; missing: string[] }[] };
  techniques: Record<string, RateStat>;
  rules: Record<string, RuleStat>;
  medianDurationMs: number | null;
}

const rate = (hits: number, total: number): RateStat => ({ hits, total, rate: total === 0 ? null : hits / total });

export function redactId(id: string): string {
  return `m-${createHash('sha256').update(id).digest('hex').slice(0, 12)}`;
}

export function maxSeverityByRule(report: ScannerReport): Record<string, Severity> {
  const out: Record<string, Severity> = {};
  for (const f of report.findings) {
    const prev = out[f.ruleId];
    if (prev === undefined || SEV_RANK[f.severity] > SEV_RANK[prev]) out[f.ruleId] = f.severity;
  }
  return out;
}

export function toResult(entry: ManifestEntry, outcome: ScanOutcome, redact: boolean): EntryResult {
  const id = redact && SENSITIVE_SETS.has(entry.set) ? redactId(entry.id) : entry.id;
  const base = {
    id,
    label: entry.label,
    set: entry.set,
    techniques: entry.techniques ?? [],
    date_found: entry.date_found,
    durationMs: outcome.durationMs,
  };
  if (!outcome.report) return { ...base, ok: false, error: outcome.error ?? 'unknown error', rules: {} };
  return {
    ...base,
    ok: true,
    verdict: outcome.report.verdict,
    score: outcome.report.score,
    rules: maxSeverityByRule(outcome.report),
  };
}

const hasHighOrCritical = (r: EntryResult): boolean =>
  Object.values(r.rules).some((s) => SEV_RANK[s] >= SEV_RANK.high);

export function buildScorecard(
  results: EntryResult[],
  opts: { cutoff?: string; limit?: number; seed?: string; redacted: boolean; scanner?: { tool: string; version: string } },
): Scorecard {
  const bySet: Scorecard['counts']['bySet'] = {};
  for (const r of results) {
    const s = (bySet[r.set] ??= { total: 0, scanned: 0, errors: 0 });
    s.total++;
    if (r.ok) s.scanned++;
    else s.errors++;
  }
  const ok = results.filter((r) => r.ok);

  const malicious = ok.filter((r) => r.set === 'malicious' && r.label === 'malicious');
  const flagged = (rs: EntryResult[]) => rs.filter((r) => r.verdict !== undefined && FLAGGED.has(r.verdict)).length;

  let detectionAfterCutoff: RateStat | null = null;
  if (opts.cutoff) {
    const cutoff = opts.cutoff;
    const late = malicious.filter((r) => r.date_found !== undefined && r.date_found >= cutoff);
    detectionAfterCutoff = rate(flagged(late), late.length);
  }

  const benign = ok.filter((r) => r.label === 'benign' && FALSE_ALARM_SETS.has(r.set));
  const dualUse = ok.filter((r) => r.label === 'benign' && r.set === 'benign-dualuse');

  const techniques: Record<string, RateStat> = {};
  for (const r of malicious) {
    for (const t of r.techniques) {
      const s = (techniques[t] ??= { hits: 0, total: 0, rate: null });
      s.total++;
      if (r.rules[t] !== undefined) s.hits++;
    }
  }
  for (const s of Object.values(techniques)) s.rate = s.total === 0 ? null : s.hits / s.total;

  const copies = results.filter((r) => r.set === 'technique-copy');
  const missed: Scorecard['techniqueCopies']['missed'] = [];
  for (const r of copies) {
    if (!r.ok) missed.push({ id: r.id, missing: ['(scan error)'] });
    else {
      const missing = r.techniques.filter((t) => r.rules[t] === undefined);
      if (missing.length > 0) missed.push({ id: r.id, missing });
    }
  }

  const rules: Record<string, RuleStat> = {};
  for (const r of ok) {
    for (const ruleId of Object.keys(r.rules)) {
      const s = (rules[ruleId] ??= { maliciousHits: 0, benignHits: 0, techniqueCopyHits: 0, precision: null });
      if (r.set === 'malicious' && r.label === 'malicious') s.maliciousHits++;
      else if (r.label === 'benign' && FALSE_ALARM_SETS.has(r.set)) s.benignHits++;
      else if (r.set === 'technique-copy') s.techniqueCopyHits++;
    }
  }
  for (const s of Object.values(rules)) {
    const n = s.maliciousHits + s.benignHits;
    s.precision = n === 0 ? null : s.maliciousHits / n;
  }

  const durations = ok.map((r) => r.durationMs).sort((a, b) => a - b);
  const medianDurationMs = durations.length === 0 ? null : durations[Math.floor(durations.length / 2)];

  return {
    generatedAt: new Date().toISOString(),
    options: { cutoff: opts.cutoff, limit: opts.limit, seed: opts.seed, redacted: opts.redacted },
    scanner: opts.scanner,
    counts: { total: results.length, scanned: ok.length, errors: results.length - ok.length, bySet },
    errors: results.filter((r) => !r.ok).map((r) => ({ id: r.id, set: r.set, error: r.error ?? 'unknown error' })),
    detection: rate(flagged(malicious), malicious.length),
    detectionAfterCutoff,
    falseAlarms: rate(benign.filter(hasHighOrCritical).length, benign.length),
    benignSuspiciousOrWorse: rate(flagged(benign), benign.length),
    dualUseHighOrCritical: rate(dualUse.filter(hasHighOrCritical).length, dualUse.length),
    techniqueCopies: { total: copies.length, missed },
    techniques,
    rules,
    medianDurationMs,
  };
}

export interface Tolerances {
  /** Max allowed absolute increase in false-alarm rate vs baseline */
  falseAlarmIncrease: number;
  /** Max allowed absolute drop in detection rate vs baseline */
  detectionDrop: number;
  /** A rule with at least minRuleHits hits must keep precision >= minPrecision */
  minPrecision: number;
  minRuleHits: number;
}

export const DEFAULT_TOLERANCES: Tolerances = {
  falseAlarmIncrease: 0.01,
  detectionDrop: 0.02,
  minPrecision: 0.9,
  minRuleHits: 5,
};

const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;

/** Regressions against a previous scorecard. Empty array = no regressions. */
export function compareScorecards(cur: Scorecard, base: Scorecard, tol: Tolerances = DEFAULT_TOLERANCES): string[] {
  const out: string[] = [];
  const c = cur.falseAlarms.rate;
  const b = base.falseAlarms.rate;
  if (c !== null && b !== null && c - b > tol.falseAlarmIncrease) {
    out.push(`False-alarm rate rose from ${pct(b)} to ${pct(c)}`);
  }
  const cd = cur.detection.rate;
  const bd = base.detection.rate;
  if (cd !== null && bd !== null && bd - cd > tol.detectionDrop) {
    out.push(`Detection rate fell from ${pct(bd)} to ${pct(cd)}`);
  }
  const baseMissed = new Set(base.techniqueCopies.missed.map((m) => m.id));
  for (const m of cur.techniqueCopies.missed) {
    if (!baseMissed.has(m.id)) out.push(`Technique copy ${m.id} newly missed: ${m.missing.join(', ')}`);
  }
  for (const [ruleId, s] of Object.entries(cur.rules)) {
    if (s.precision === null || s.maliciousHits + s.benignHits < tol.minRuleHits) continue;
    if (s.precision >= tol.minPrecision) continue;
    const prev = base.rules[ruleId];
    if (prev === undefined || prev.precision === null || prev.precision >= tol.minPrecision) {
      out.push(`Rule ${ruleId} precision dropped to ${pct(s.precision)} (${s.benignHits} benign hits)`);
    }
  }
  return out;
}

/** Absolute gates. Technique copies are regression tests, so any miss fails. */
export function checkGates(sc: Scorecard, gates: { maxFalseAlarmRate?: number; minDetection?: number }): string[] {
  const out: string[] = [];
  for (const m of sc.techniqueCopies.missed) out.push(`Technique copy ${m.id} missed: ${m.missing.join(', ')}`);
  const fa = sc.falseAlarms.rate;
  if (gates.maxFalseAlarmRate !== undefined && fa !== null && fa > gates.maxFalseAlarmRate) {
    out.push(`False-alarm rate ${pct(fa)} is above the ${pct(gates.maxFalseAlarmRate)} limit`);
  }
  const d = sc.detection.rate;
  if (gates.minDetection !== undefined && d !== null && d < gates.minDetection) {
    out.push(`Detection rate ${pct(d)} is below the ${pct(gates.minDetection)} target`);
  }
  return out;
}

const fmt = (r: RateStat | null): string => (r === null || r.rate === null ? 'n/a' : `${pct(r.rate)} (${r.hits}/${r.total})`);
const cell = (s: string): string => s.replace(/[|\r\n]/g, ' ');

export function renderMarkdown(sc: Scorecard, problems: string[] = []): string {
  const lines: string[] = [];
  lines.push('## repotrap benchmark scorecard', '');
  if (sc.scanner) lines.push(`Scanner: \`${cell(sc.scanner.tool)} ${cell(sc.scanner.version)}\` · ${sc.generatedAt}`, '');
  lines.push(problems.length === 0 ? '**Result: pass**' : `**Result: fail (${problems.length})**`, '');
  for (const p of problems) lines.push(`- ${cell(p)}`);
  if (problems.length > 0) lines.push('');

  lines.push('| Metric | Value | Target |', '|---|---|---|');
  lines.push(`| Detection (malicious rated suspicious or worse) | ${fmt(sc.detection)} | ≥ 80% |`);
  if (sc.detectionAfterCutoff) lines.push(`| Detection, found after ${cell(sc.options.cutoff ?? '')} | ${fmt(sc.detectionAfterCutoff)} | ≥ 80% |`);
  lines.push(`| False alarms (benign with High/Critical) | ${fmt(sc.falseAlarms)} | ≤ 5% |`);
  lines.push(`| Benign rated suspicious or worse | ${fmt(sc.benignSuspiciousOrWorse)} | |`);
  lines.push(`| Dual-use tools with High/Critical (informational) | ${fmt(sc.dualUseHighOrCritical)} | |`);
  lines.push(`| Technique copies missed | ${sc.techniqueCopies.missed.length}/${sc.techniqueCopies.total} | 0 |`);
  lines.push(`| Median scan time | ${sc.medianDurationMs === null ? 'n/a' : `${(sc.medianDurationMs / 1000).toFixed(1)} s`} | < 10 s |`);
  lines.push('');

  lines.push('| Set | Entries | Scanned | Errors |', '|---|---|---|---|');
  for (const [set, c] of Object.entries(sc.counts.bySet).sort()) lines.push(`| ${set} | ${c.total} | ${c.scanned} | ${c.errors} |`);
  lines.push('');

  const ruleIds = Object.keys(sc.rules).sort();
  if (ruleIds.length > 0) {
    lines.push('| Rule | Malicious hits | Benign hits | Technique-copy hits | Precision |', '|---|---|---|---|---|');
    for (const id of ruleIds) {
      const s = sc.rules[id];
      lines.push(`| ${cell(id)} | ${s.maliciousHits} | ${s.benignHits} | ${s.techniqueCopyHits} | ${s.precision === null ? 'n/a' : pct(s.precision)} |`);
    }
    lines.push('');
  }

  const techIds = Object.keys(sc.techniques).sort();
  if (techIds.length > 0) {
    lines.push('| Technique | Rule fired on tagged malicious repos |', '|---|---|');
    for (const t of techIds) lines.push(`| ${cell(t)} | ${fmt(sc.techniques[t])} |`);
    lines.push('');
  }

  if (sc.errors.length > 0) {
    lines.push(`<details><summary>${sc.errors.length} scan errors</summary>`, '');
    for (const e of sc.errors.slice(0, 50)) lines.push(`- \`${cell(e.id)}\` (${e.set}): ${cell(e.error)}`);
    if (sc.errors.length > 50) lines.push(`- …and ${sc.errors.length - 50} more`);
    lines.push('', '</details>', '');
  }
  return lines.join('\n');
}
