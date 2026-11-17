// Shared types for the repotrap benchmark harness.
// Plain TypeScript with erasable syntax only, so Node 24+ runs it directly.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Verdict = 'no-strong-signals' | 'suspicious' | 'likely-malicious';
export type Label = 'malicious' | 'benign' | 'unclear';

export const SETS = [
  'benign-popular',
  'benign-random',
  'benign-tricky',
  'benign-dualuse',
  'malicious',
  'technique-copy',
] as const;
export type CorpusSet = (typeof SETS)[number];

/** One line of a corpus manifest (JSONL). See corpus/README.md. */
export interface ManifestEntry {
  id: string;
  label: Label;
  set: CorpusSet;
  /** https://github.com/<owner>/<repo> — remote entries only */
  url?: string;
  /** Full 40-character commit SHA the entry is pinned to — remote entries only */
  commit?: string;
  /** Local folder — isolated VM only, never on a workstation */
  path?: string;
  /** Rule IDs this entry is expected to trigger, e.g. ["EXEC-001"] */
  techniques?: string[];
  source?: string;
  labelled_by?: string[];
  /** YYYY-MM-DD the entry was found / added; used for the time-split test */
  date_found?: string;
  notes?: string;
}

/** The JSON contract the scanner must print with `--format json`. */
export interface ScannerFinding {
  ruleId: string;
  severity: Severity;
  file?: string;
  line?: number;
}

export interface ScannerReport {
  tool: string;
  version: string;
  verdict: Verdict;
  score: number;
  findings: ScannerFinding[];
}

/** Per-entry benchmark result. Contains no file paths, snippets or URLs. */
export interface EntryResult {
  id: string;
  label: Label;
  set: CorpusSet;
  techniques: string[];
  date_found?: string;
  ok: boolean;
  error?: string;
  verdict?: Verdict;
  score?: number;
  /** Highest severity each rule fired at */
  rules: Record<string, Severity>;
  durationMs: number;
}
