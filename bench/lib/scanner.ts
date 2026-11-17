import { execFile } from 'node:child_process';
import type { ManifestEntry, ScannerFinding, ScannerReport } from './types.ts';

const SEVERITIES: readonly string[] = ['info', 'low', 'medium', 'high', 'critical'];
const VERDICTS: readonly string[] = ['no-strong-signals', 'suspicious', 'likely-malicious'];
const RULE_RE = /^[A-Z]+-\d{3}$/;

export interface ScannerOptions {
  /** Executable to run, e.g. "node" */
  command: string;
  /** Arguments before the target, e.g. ["packages/cli/dist/repotrap.js", "scan"] */
  args: string[];
  timeoutMs: number;
}

export interface ScanOutcome {
  report?: ScannerReport;
  /** Short, content-free error description (never includes scanner output) */
  error?: string;
  durationMs: number;
}

export function targetFor(e: ManifestEntry): string {
  return e.path ?? `${e.url}/tree/${e.commit}`;
}

export function validateReport(x: unknown): ScannerReport {
  const bad = (msg: string): never => {
    throw new Error(`invalid report: ${msg}`);
  };
  if (typeof x !== 'object' || x === null) bad('not an object');
  const o = x as Record<string, unknown>;
  if (typeof o.tool !== 'string') bad('tool missing');
  if (typeof o.version !== 'string') bad('version missing');
  if (typeof o.verdict !== 'string' || !VERDICTS.includes(o.verdict)) bad('verdict invalid');
  if (typeof o.score !== 'number' || o.score < 0 || o.score > 100) bad('score must be 0-100');
  if (!Array.isArray(o.findings)) bad('findings must be an array');
  for (const f of o.findings as unknown[]) {
    const fo = f as Record<string, unknown>;
    if (typeof f !== 'object' || f === null) bad('finding not an object');
    if (typeof fo.ruleId !== 'string' || !RULE_RE.test(fo.ruleId)) bad('finding ruleId invalid');
    if (typeof fo.severity !== 'string' || !SEVERITIES.includes(fo.severity)) bad('finding severity invalid');
  }
  return {
    tool: o.tool as string,
    version: o.version as string,
    verdict: o.verdict as ScannerReport['verdict'],
    score: o.score as number,
    findings: (o.findings as ScannerFinding[]).map((f) => ({ ruleId: f.ruleId, severity: f.severity })),
  };
}

/**
 * Runs the scanner without a shell. Exit code 1 means "findings at or above
 * --fail-on" and still carries a valid report; anything else non-zero is an error.
 */
export function runScanner(opts: ScannerOptions, target: string): Promise<ScanOutcome> {
  const started = Date.now();
  return new Promise((resolve) => {
    execFile(
      opts.command,
      [...opts.args, target, '--format', 'json'],
      { timeout: opts.timeoutMs, maxBuffer: 32 * 1024 * 1024 },
      (err, stdout) => {
        const durationMs = Date.now() - started;
        if (err) {
          const e = err as Error & { killed?: boolean; code?: number | string };
          if (e.killed) return resolve({ error: 'timeout', durationMs });
          if (e.code !== 1) {
            const what = typeof e.code === 'number' ? `exit ${e.code}` : `spawn failed (${e.code ?? 'unknown'})`;
            return resolve({ error: what, durationMs });
          }
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(stdout);
        } catch {
          return resolve({ error: 'output was not JSON', durationMs });
        }
        try {
          resolve({ report: validateReport(parsed), durationMs });
        } catch (ve) {
          resolve({ error: (ve as Error).message, durationMs });
        }
      },
    );
  });
}
