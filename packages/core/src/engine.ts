import { makeFileContext } from './text.ts';
import { ALL_RULES } from './rules/index.ts';
import { scoreFindings, verdictFor } from './scoring.ts';
import { SEVERITY_RANK } from './types.ts';
import type { Coverage, FileContext, Finding, RawFinding, RepoContext, Rule, ScanInput, ScanReport, Severity } from './types.ts';

export const VERSION = '0.1.0';

const DOWNGRADE: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

/** Rules that keep full severity even inside test/example/docs folders: traps don't get a pass for living there. */
const NO_PATH_DOWNGRADE = (f: Finding): boolean => f.category === 'EXEC' || f.category === 'CHAIN' || f.ruleId === 'BIN-002' || f.ruleId === 'BIN-008';

function toFinding(rule: Rule, raw: RawFinding, file?: string): Finding {
  const finding: Finding = {
    ruleId: rule.id,
    category: rule.category,
    severity: raw.severity ?? rule.severity,
    title: rule.title,
    message: raw.message,
    advice: rule.advice,
    count: 1,
  };
  const path = raw.file ?? file;
  if (path !== undefined) finding.file = path;
  if (raw.line !== undefined) finding.line = raw.line;
  if (raw.evidence !== undefined) finding.evidence = raw.evidence;
  if (raw.refs !== undefined && raw.refs.length > 0) finding.refs = raw.refs;
  return finding;
}

/** One finding per rule and file: the most severe, earliest occurrence, with a count of all matches. */
function dedupe(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.ruleId}\u0000${f.file ?? ''}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, { ...f });
      continue;
    }
    const count = prev.count + f.count;
    const refs = [...new Set([...(prev.refs ?? []), ...(f.refs ?? [])])];
    const better =
      SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev.severity] ||
      (f.severity === prev.severity && (f.line ?? Infinity) < (prev.line ?? Infinity));
    const merged = better ? { ...f } : prev;
    merged.count = count;
    if (refs.length > 0) merged.refs = refs;
    byKey.set(key, merged);
  }
  return [...byKey.values()];
}

function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export interface ScanResult {
  report: ScanReport;
  /** Full findings including internal fields (category, refs) */
  findings: Finding[];
}

/** Runs all rules over the input. Pure: no I/O, deterministic for a given input and clock. */
export function scan(input: ScanInput, rules: readonly Rule[] = ALL_RULES): ScanResult {
  const files: FileContext[] = input.files.map(makeFileContext);
  const ctx: RepoContext = {
    files,
    byPath: new Map(files.map((f) => [f.path, f])),
    now: input.now ?? new Date(),
  };
  if (input.repo) ctx.repo = input.repo;
  const diagnostics: string[] = [];

  let findings: Finding[] = [];
  for (const rule of rules) {
    if (rule.kind !== 'file') continue;
    for (const file of files) {
      try {
        if (!rule.appliesTo(file)) continue;
        for (const raw of rule.check(file)) findings.push(toFinding(rule, raw, file.path));
      } catch (e) {
        diagnostics.push(`${rule.id} failed on ${file.path}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  // Lower severity one step inside test/example/docs folders (except auto-run, chains, disguised files).
  for (const f of findings) {
    const file = f.file ? ctx.byPath.get(f.file) : undefined;
    if (file?.isTestPath && !NO_PATH_DOWNGRADE(f)) f.severity = DOWNGRADE[f.severity];
  }
  findings = dedupe(findings);

  const correlated: Finding[] = [];
  for (const rule of rules) {
    if (rule.kind !== 'correlation') continue;
    try {
      for (const raw of rule.check(ctx, findings)) correlated.push(toFinding(rule, raw));
    } catch (e) {
      diagnostics.push(`${rule.id} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  findings = sortFindings(dedupe([...findings, ...correlated]));

  const coverage: Coverage = input.coverage ?? {
    complete: true,
    filesListed: input.files.length,
    filesRead: input.files.length,
    filesSkipped: 0,
  };
  const score = scoreFindings(findings);
  const report: ScanReport = {
    tool: 'repotrap',
    version: VERSION,
    status: coverage.complete ? 'complete' : 'incomplete',
    verdict: verdictFor(score, findings),
    score,
    findings: findings.map((f) => {
      const r: ScanReport['findings'][number] = {
        ruleId: f.ruleId,
        severity: f.severity,
        title: f.title,
        message: f.message,
        advice: f.advice,
        count: f.count,
      };
      if (f.file !== undefined) r.file = f.file;
      if (f.line !== undefined) r.line = f.line;
      if (f.evidence !== undefined) r.evidence = f.evidence;
      return r;
    }),
    coverage,
    diagnostics,
  };
  if (input.target !== undefined) report.target = input.target;
  if (input.repo?.commit !== undefined) report.commit = input.repo.commit;
  return { report, findings };
}
