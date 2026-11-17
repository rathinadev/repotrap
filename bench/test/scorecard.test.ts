import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScorecard, checkGates, compareScorecards, redactId, renderMarkdown, toResult } from '../lib/scorecard.ts';
import { stratifiedSample } from '../lib/sample.ts';
import type { EntryResult, ManifestEntry, Severity } from '../lib/types.ts';

let n = 0;
function r(partial: Partial<EntryResult> & Pick<EntryResult, 'set' | 'label'>): EntryResult {
  n++;
  return { id: `e${n}`, techniques: [], ok: true, verdict: 'no-strong-signals', score: 0, rules: {}, durationMs: 1000, ...partial };
}
const rules = (o: Record<string, Severity>) => o;

test('detection counts malicious repos rated suspicious or worse', () => {
  const sc = buildScorecard(
    [
      r({ set: 'malicious', label: 'malicious', verdict: 'likely-malicious' }),
      r({ set: 'malicious', label: 'malicious', verdict: 'suspicious' }),
      r({ set: 'malicious', label: 'malicious', verdict: 'no-strong-signals' }),
      r({ set: 'malicious', label: 'malicious', ok: false, error: 'timeout' }),
    ],
    { redacted: false },
  );
  assert.deepEqual(sc.detection, { hits: 2, total: 3, rate: 2 / 3 });
  assert.equal(sc.counts.errors, 1);
});

test('false alarms exclude dual-use tools and count only High/Critical', () => {
  const sc = buildScorecard(
    [
      r({ set: 'benign-popular', label: 'benign', rules: rules({ 'EXEC-005': 'medium' }) }),
      r({ set: 'benign-tricky', label: 'benign', rules: rules({ 'NET-001': 'high' }) }),
      r({ set: 'benign-random', label: 'benign' }),
      r({ set: 'benign-dualuse', label: 'benign', rules: rules({ 'STEAL-001': 'critical' }) }),
    ],
    { redacted: false },
  );
  assert.deepEqual(sc.falseAlarms, { hits: 1, total: 3, rate: 1 / 3 });
  assert.deepEqual(sc.dualUseHighOrCritical, { hits: 1, total: 1, rate: 1 });
});

test('rule precision uses malicious vs benign hits', () => {
  const results = [
    ...Array.from({ length: 9 }, () => r({ set: 'malicious', label: 'malicious', rules: rules({ 'EXEC-001': 'high' }) })),
    r({ set: 'benign-popular', label: 'benign', rules: rules({ 'EXEC-001': 'high' }) }),
    r({ set: 'technique-copy', label: 'malicious', techniques: ['EXEC-001'], rules: rules({ 'EXEC-001': 'high' }) }),
  ];
  const sc = buildScorecard(results, { redacted: false });
  assert.deepEqual(sc.rules['EXEC-001'], { maliciousHits: 9, benignHits: 1, techniqueCopyHits: 1, precision: 0.9 });
});

test('technique copies report missing rules and scan errors', () => {
  const sc = buildScorecard(
    [
      r({ id: 'c1', set: 'technique-copy', label: 'malicious', techniques: ['EXEC-001', 'OBF-004'], rules: rules({ 'EXEC-001': 'high' }) }),
      r({ id: 'c2', set: 'technique-copy', label: 'malicious', techniques: ['NET-001'], ok: false, error: 'timeout' }),
      r({ id: 'c3', set: 'technique-copy', label: 'malicious', techniques: ['NET-001'], rules: rules({ 'NET-001': 'high' }) }),
    ],
    { redacted: false },
  );
  assert.deepEqual(sc.techniqueCopies.missed, [
    { id: 'c1', missing: ['OBF-004'] },
    { id: 'c2', missing: ['(scan error)'] },
  ]);
  assert.equal(checkGates(sc, {}).length, 2);
});

test('time split only counts entries found on or after the cutoff', () => {
  const sc = buildScorecard(
    [
      r({ set: 'malicious', label: 'malicious', date_found: '2025-01-01', verdict: 'suspicious' }),
      r({ set: 'malicious', label: 'malicious', date_found: '2026-06-01', verdict: 'no-strong-signals' }),
    ],
    { redacted: false, cutoff: '2026-01-01' },
  );
  assert.deepEqual(sc.detectionAfterCutoff, { hits: 0, total: 1, rate: 0 });
});

test('gates fail on false-alarm rate and detection targets', () => {
  const sc = buildScorecard(
    [
      r({ set: 'benign-popular', label: 'benign', rules: rules({ 'OBF-001': 'critical' }) }),
      r({ set: 'malicious', label: 'malicious' }),
    ],
    { redacted: false },
  );
  const problems = checkGates(sc, { maxFalseAlarmRate: 0.05, minDetection: 0.8 });
  assert.equal(problems.length, 2);
});

test('comparison flags regressions against a baseline', () => {
  const base = buildScorecard(
    [r({ set: 'benign-popular', label: 'benign' }), r({ set: 'malicious', label: 'malicious', verdict: 'suspicious' })],
    { redacted: false },
  );
  const cur = buildScorecard(
    [
      r({ set: 'benign-popular', label: 'benign', rules: rules({ 'NET-002': 'high' }) }),
      r({ set: 'malicious', label: 'malicious' }),
    ],
    { redacted: false },
  );
  const problems = compareScorecards(cur, base);
  assert.ok(problems.some((p) => p.startsWith('False-alarm rate rose')));
  assert.ok(problems.some((p) => p.startsWith('Detection rate fell')));
});

test('comparison flags rules whose precision newly drops below 90%', () => {
  const mk = (benignHits: number) =>
    buildScorecard(
      [
        ...Array.from({ length: 5 }, () => r({ set: 'malicious', label: 'malicious', rules: rules({ 'OBF-011': 'medium' }) })),
        ...Array.from({ length: benignHits }, () => r({ set: 'benign-random', label: 'benign', rules: rules({ 'OBF-011': 'medium' }) })),
      ],
      { redacted: false },
    );
  assert.deepEqual(compareScorecards(mk(0), mk(0)), []);
  assert.ok(compareScorecards(mk(3), mk(0)).some((p) => p.startsWith('Rule OBF-011 precision dropped')));
});

test('redaction hides malicious ids but keeps benign ids', () => {
  const mal: ManifestEntry = { id: 'evil/repo', label: 'malicious', set: 'malicious', path: '/srv/x' };
  const ben: ManifestEntry = { id: 'popular/a/b', label: 'benign', set: 'benign-popular', url: 'https://github.com/a/b', commit: 'b'.repeat(40) };
  const outcome = { report: { tool: 't', version: '1', verdict: 'suspicious' as const, score: 30, findings: [] }, durationMs: 1 };
  assert.equal(toResult(mal, outcome, true).id, redactId('evil/repo'));
  assert.match(toResult(mal, outcome, true).id, /^m-[0-9a-f]{12}$/);
  assert.equal(toResult(ben, outcome, true).id, 'popular/a/b');
  assert.equal(toResult(mal, outcome, false).id, 'evil/repo');
});

test('markdown output escapes table-breaking characters', () => {
  const sc = buildScorecard([r({ set: 'malicious', label: 'malicious', ok: false, error: 'bad | output\nline' })], { redacted: false });
  const md = renderMarkdown(sc, ['problem | with pipe']);
  assert.ok(!md.includes('bad | output'));
  assert.ok(md.includes('problem   with pipe'));
});

test('stratified sample is deterministic and keeps every set', () => {
  const items = [
    ...Array.from({ length: 90 }, (_, i) => ({ id: `p${String(i).padStart(3, '0')}`, set: 'benign-popular' })),
    ...Array.from({ length: 10 }, (_, i) => ({ id: `t${i}`, set: 'benign-tricky' })),
  ];
  const a = stratifiedSample(items, 20, 'seed');
  const b = stratifiedSample(items, 20, 'seed');
  assert.deepEqual(a, b);
  assert.equal(a.filter((x) => x.set === 'benign-tricky').length, 2);
  assert.equal(a.length, 20);
  assert.notDeepEqual(stratifiedSample(items, 20, 'other'), a);
  assert.equal(stratifiedSample(items, 0, 'seed').length, 100);
});
