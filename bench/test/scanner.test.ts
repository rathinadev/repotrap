import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runScanner, targetFor, validateReport } from '../lib/scanner.ts';

// A fake scanner whose behaviour depends on the target argument. It prints
// harmless JSON only; nothing here resembles real scanned content.
const FAKE = `
const target = process.argv[2];
const report = { tool: 'fake', version: '0.0.1', verdict: 'suspicious', score: 30,
  findings: [{ ruleId: 'EXEC-001', severity: 'high', file: 'a', line: 1 }] };
if (target === 'ok') { console.log(JSON.stringify(report)); }
else if (target === 'fail-on') { console.log(JSON.stringify(report)); process.exit(1); }
else if (target === 'crash') { console.error('boom'); process.exit(2); }
else if (target === 'notjson') { console.log('hello'); }
else if (target === 'badreport') { console.log(JSON.stringify({ ...report, score: 500 })); }
else if (target === 'slow') { setTimeout(() => {}, 60000); }
`;

let dir = '';
let fake = '';
before(() => {
  dir = mkdtempSync(join(tmpdir(), 'repotrap-bench-test-'));
  fake = join(dir, 'fake-scanner.mjs');
  writeFileSync(fake, FAKE);
});
after(() => rmSync(dir, { recursive: true, force: true }));

const opts = () => ({ command: process.execPath, args: [fake], timeoutMs: 5000 });

test('parses a valid report', async () => {
  const out = await runScanner(opts(), 'ok');
  assert.equal(out.error, undefined);
  assert.equal(out.report?.verdict, 'suspicious');
  assert.deepEqual(out.report?.findings, [{ ruleId: 'EXEC-001', severity: 'high' }]);
});

test('exit code 1 still carries a report', async () => {
  const out = await runScanner(opts(), 'fail-on');
  assert.equal(out.report?.score, 30);
});

test('other exit codes are errors without scanner output', async () => {
  const out = await runScanner(opts(), 'crash');
  assert.equal(out.error, 'exit 2');
});

test('non-JSON and invalid reports are errors', async () => {
  assert.equal((await runScanner(opts(), 'notjson')).error, 'output was not JSON');
  assert.match((await runScanner(opts(), 'badreport')).error ?? '', /score must be 0-100/);
});

test('slow scans time out', async () => {
  const out = await runScanner({ ...opts(), timeoutMs: 300 }, 'slow');
  assert.equal(out.error, 'timeout');
});

test('missing scanner executable is reported', async () => {
  const out = await runScanner({ command: join(dir, 'does-not-exist'), args: [], timeoutMs: 1000 }, 'ok');
  assert.match(out.error ?? '', /^spawn failed/);
});

test('targetFor prefers the local path, else url/tree/commit', () => {
  const sha = 'c'.repeat(40);
  assert.equal(targetFor({ id: 'a', label: 'benign', set: 'benign-popular', url: 'https://github.com/a/b', commit: sha }), `https://github.com/a/b/tree/${sha}`);
  assert.equal(targetFor({ id: 'a', label: 'malicious', set: 'malicious', path: '/srv/a' }), '/srv/a');
});

test('validateReport rejects bad rule IDs and severities', () => {
  const base = { tool: 't', version: '1', verdict: 'suspicious', score: 1 };
  assert.throws(() => validateReport({ ...base, findings: [{ ruleId: 'nope', severity: 'high' }] }), /ruleId/);
  assert.throws(() => validateReport({ ...base, findings: [{ ruleId: 'EXEC-001', severity: 'severe' }] }), /severity/);
});
