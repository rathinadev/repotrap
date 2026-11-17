export { scan, VERSION } from './engine.ts';
export type { ScanResult } from './engine.ts';
export { ALL_RULES } from './rules/index.ts';
export { scoreFindings, verdictFor, LIKELY_MALICIOUS_SCORE, SUSPICIOUS_SCORE } from './scoring.ts';
export { toScannedFile, decodeText, sanitizeEvidence } from './text.ts';
export { SEVERITY_RANK, SEVERITY_WEIGHT } from './types.ts';
export type {
  Category,
  Coverage,
  Finding,
  ReportFinding,
  RepoMeta,
  Rule,
  ScanInput,
  ScanReport,
  ScanStatus,
  ScannedFile,
  Severity,
  Verdict,
} from './types.ts';
