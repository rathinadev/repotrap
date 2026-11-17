import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeText, makeFileContext, parseJsonc, sanitizeEvidence, toScannedFile } from '../src/text.ts';

test('decodeText handles UTF-8, binary and UTF-16 with BOM', () => {
  assert.equal(decodeText(new TextEncoder().encode('hello')), 'hello');
  assert.equal(decodeText(Uint8Array.from([0x4d, 0x5a, 0x00, 0x01])), undefined);
  const utf16 = Uint8Array.from([0xff, 0xfe, 0x68, 0x00, 0x69, 0x00]);
  assert.equal(decodeText(utf16), 'hi');
});

test('toScannedFile keeps the first bytes as head', () => {
  const f = toScannedFile('a.bin', Uint8Array.from(Array.from({ length: 100 }, (_, i) => i + 1)));
  assert.equal(f.head.length, 64);
  assert.equal(f.size, 100);
});

test('parseJsonc accepts comments and trailing commas but keeps strings intact', () => {
  const v = parseJsonc('{\n // comment\n "a": "http://x//y", /* block */ "b": [1, 2,],\n}') as { a: string; b: number[] };
  assert.equal(v.a, 'http://x//y');
  assert.deepEqual(v.b, [1, 2]);
  assert.equal(parseJsonc('{ not json'), undefined);
});

test('sanitizeEvidence reveals hidden characters and truncates', () => {
  assert.equal(sanitizeEvidence('a‮b'), 'a<U+202E>b');
  assert.equal(sanitizeEvidence('a\u0007b'), 'a<U+0007>b');
  assert.equal(sanitizeEvidence('x'.repeat(500), 20).length, 20);
  assert.equal(sanitizeEvidence('a' + ' '.repeat(40) + 'b'), 'a … b');
});

test('makeFileContext classifies docs, code, tests and workflows', () => {
  const ctx = (p: string, t = '') => makeFileContext(toScannedFile(p, new TextEncoder().encode(t)));
  assert.equal(ctx('README.md').isDoc, true);
  assert.equal(ctx('src/app.ts').isCode, true);
  assert.equal(ctx('bin/tool', '#!/usr/bin/env node\n').isCode, true);
  assert.equal(ctx('tests/a.js').isTestPath, true);
  assert.equal(ctx('src/latest/a.js').isTestPath, false);
  assert.equal(ctx('.github/workflows/ci.yml').isWorkflow, true);
  assert.equal(ctx('.\\dir\\File.JS').path, 'dir/File.JS');
  assert.equal(ctx('dir/File.JS').ext, 'js');
});
