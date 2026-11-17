import { scan, toScannedFile } from '../src/index.ts';
import type { RepoMeta, ScanInput, ScannedFile } from '../src/index.ts';
import type { Finding } from '../src/types.ts';

/**
 * Removes the § marker. Test inputs that resemble attack code are written with §
 * inside keywords (e.g. "cu§rl") so this source file never matches the rules
 * itself; the marker is stripped at runtime to build the real fixture.
 */
export const x = (s: string): string => s.replaceAll('§', '');

export const file = (path: string, text: string): ScannedFile => toScannedFile(path, new TextEncoder().encode(text));
export const bin = (path: string, bytes: number[]): ScannedFile => toScannedFile(path, Uint8Array.from(bytes));

export function run(files: ScannedFile[], extra: Partial<ScanInput> = {}): { findings: Finding[]; ids: string[]; report: ReturnType<typeof scan>['report'] } {
  const { findings, report } = scan({ files, now: new Date('2026-11-17T00:00:00Z'), ...extra });
  return { findings, report, ids: findings.map((f) => f.ruleId) };
}

export function only(files: ScannedFile[], ruleId: string, extra: Partial<ScanInput> = {}): Finding[] {
  return run(files, extra).findings.filter((f) => f.ruleId === ruleId);
}

export const repo = (overrides: Partial<RepoMeta> = {}): RepoMeta => ({
  owner: 'someone',
  name: 'project',
  createdAt: '2026-11-01T00:00:00Z',
  ownerCreatedAt: '2026-11-01T00:00:00Z',
  ...overrides,
});

export const tasksJson = (tasks: unknown[]): string => JSON.stringify({ version: '2.0.0', tasks }, null, 2);
