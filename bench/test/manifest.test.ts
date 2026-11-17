import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest, validateEntry } from '../lib/manifest.ts';

const SHA = 'a'.repeat(40);
const good = { id: 'popular/acme/widget', label: 'benign', set: 'benign-popular', url: 'https://github.com/acme/widget', commit: SHA };

test('accepts a valid remote entry', () => {
  const e = validateEntry(good, 't');
  assert.equal(e.id, 'popular/acme/widget');
});

test('accepts a local-path entry for the VM', () => {
  const e = validateEntry({ id: 'm1', label: 'malicious', set: 'malicious', path: '/srv/corpus/m1', techniques: ['EXEC-001'] }, 't');
  assert.equal(e.path, '/srv/corpus/m1');
});

test('rejects short or uppercase commit SHAs', () => {
  assert.throws(() => validateEntry({ ...good, commit: 'abc123' }, 't'), /40-character/);
  assert.throws(() => validateEntry({ ...good, commit: 'A'.repeat(40) }, 't'), /40-character/);
});

test('rejects non-GitHub or malformed URLs', () => {
  assert.throws(() => validateEntry({ ...good, url: 'https://gitlab.com/acme/widget' }, 't'), /url must be/);
  assert.throws(() => validateEntry({ ...good, url: 'https://github.com/acme/widget/tree/main' }, 't'), /url must be/);
});

test('rejects label/set mismatches', () => {
  assert.throws(() => validateEntry({ ...good, label: 'malicious' }, 't'), /cannot have label malicious/);
  assert.throws(() => validateEntry({ ...good, set: 'malicious' }, 't'), /cannot have label benign/);
});

test('requires a target', () => {
  assert.throws(() => validateEntry({ id: 'x', label: 'benign', set: 'benign-popular' }, 't'), /needs url \+ commit, or path/);
});

test('rejects unknown fields and bad technique IDs', () => {
  assert.throws(() => validateEntry({ ...good, extra: 1 }, 't'), /unknown field/);
  assert.throws(() => validateEntry({ ...good, techniques: ['exec-1'] }, 't'), /rule IDs/);
});

test('technique copies must list techniques', () => {
  assert.throws(() => validateEntry({ id: 'c1', label: 'malicious', set: 'technique-copy', path: '/tmp/c1' }, 't'), /must list/);
});

test('parseManifest reports line numbers and duplicates', () => {
  const line = JSON.stringify(good);
  assert.equal(parseManifest(`${line}\n\n`).length, 1);
  assert.throws(() => parseManifest(`${line}\n${line}`, 'm.jsonl'), /m\.jsonl:2: duplicate id/);
  assert.throws(() => parseManifest(`${line}\n{oops`, 'm.jsonl'), /m\.jsonl:2: not valid JSON/);
});
