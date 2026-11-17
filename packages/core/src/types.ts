export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Verdict = 'no-strong-signals' | 'suspicious' | 'likely-malicious';
export type ScanStatus = 'complete' | 'incomplete';
export type Category = 'EXEC' | 'OBF' | 'NET' | 'STEAL' | 'BIN' | 'SYS' | 'META' | 'CHAIN';

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 2, medium: 8, high: 20, critical: 40 };

/** A file as delivered by a source (GitHub API or local folder). */
export interface ScannedFile {
  /** Repository-relative path using forward slashes */
  path: string;
  /** Size in bytes */
  size: number;
  /** Decoded text, absent for binary or unread files */
  text?: string;
  /** First bytes of the file (up to 64), used for format detection */
  head: Uint8Array;
}

/** Repository metadata, available for remote scans only. */
export interface RepoMeta {
  owner: string;
  name: string;
  description?: string;
  /** ISO timestamps */
  createdAt?: string;
  ownerCreatedAt?: string;
  stars?: number;
  fork?: boolean;
  commit?: string;
}

export interface Coverage {
  /** False when caps or rate limits stopped the scan before all relevant files were read */
  complete: boolean;
  filesListed: number;
  filesRead: number;
  filesSkipped: number;
  reason?: string;
}

export interface ScanInput {
  files: ScannedFile[];
  repo?: RepoMeta;
  coverage?: Coverage;
  /** Clock used for age-based rules; defaults to now */
  now?: Date;
  target?: string;
}

/** What a rule returns; the engine fills in rule metadata and the file. */
export interface RawFinding {
  severity?: Severity;
  message: string;
  file?: string;
  line?: number;
  evidence?: string;
  /** Repository paths the finding refers to (e.g. the file an auto-run task executes) */
  refs?: string[];
}

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  title: string;
  message: string;
  advice: string;
  file?: string;
  line?: number;
  evidence?: string;
  /** Number of matches merged into this finding */
  count: number;
  refs?: string[];
}

/** Per-file view handed to rules. */
export interface FileContext {
  path: string;
  /** Lower-cased path */
  lower: string;
  /** Lower-cased file name */
  base: string;
  /** Lower-cased extension without the dot, '' if none */
  ext: string;
  size: number;
  text?: string;
  head: Uint8Array;
  lines(): string[];
  isDoc: boolean;
  isCode: boolean;
  isTestPath: boolean;
  isWorkflow: boolean;
  /** Data files (JSON other than package/editor config, JSONL, CSV, lockfiles) that are never executed */
  isData: boolean;
}

export interface RepoContext {
  files: FileContext[];
  byPath: Map<string, FileContext>;
  repo?: RepoMeta;
  now: Date;
}

interface RuleBase {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  /** Plain-language guidance shown with every finding */
  advice: string;
}

export interface FileRule extends RuleBase {
  kind: 'file';
  appliesTo(file: FileContext): boolean;
  check(file: FileContext): RawFinding[];
}

/** Runs after all file rules, with their (deduplicated) findings. */
export interface CorrelationRule extends RuleBase {
  kind: 'correlation';
  check(ctx: RepoContext, findings: readonly Finding[]): RawFinding[];
}

export type Rule = FileRule | CorrelationRule;

export interface ReportFinding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  advice: string;
  file?: string;
  line?: number;
  evidence?: string;
  count: number;
}

export interface ScanReport {
  tool: 'repotrap';
  version: string;
  target?: string;
  commit?: string;
  status: ScanStatus;
  verdict: Verdict;
  score: number;
  findings: ReportFinding[];
  coverage: Coverage;
  /** Internal rule errors; a scan never fails because one rule threw */
  diagnostics: string[];
}
