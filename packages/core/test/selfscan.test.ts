import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { scan, toScannedFile } from '../src/index.ts';

const root = fileURLToPath(new URL('../../../', import.meta.url));

test('self-scan: repotrap raises no High or Critical findings on its own tracked files', () => {
  const tracked = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
    .split('\n')
    .filter((p) => p.length > 0 && !p.startsWith('node_modules/'));
  const files = tracked
    .filter((p) => {
      try {
        return statSync(join(root, p)).isFile();
      } catch {
        return false;
      }
    })
    .map((p) => toScannedFile(p, readFileSync(join(root, p))));
  const { report } = scan({ files });
  const serious = report.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  assert.deepEqual(
    serious.map((f) => `${f.ruleId} ${f.file}:${f.line ?? ''} ${f.evidence ?? ''}`),
    [],
  );
  assert.equal(report.diagnostics.length, 0, report.diagnostics.join('\n'));
});
