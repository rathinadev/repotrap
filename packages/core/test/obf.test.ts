import { test } from 'node:test';
import assert from 'node:assert/strict';
import { file, only, x } from './helpers.ts';

test('OBF-002: executing decoded data is flagged across languages', () => {
  const cases: [string, string][] = [
    ['a.js', x('ev§al(atob("ZWNobw=="))')],
    ['b.js', x("ev§al(Buffer.from(p, 'base64').toString())")],
    ['c.py', x('ex§ec(base64.b64decode(blob))')],
    ['d.py', x('ex§ec(zlib.decompress(data))')],
    ['e.ps1', x('IE§X ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))')],
    ['f.sh', x('echo aGk= | base64 -d | ba§sh')],
  ];
  for (const [path, text] of cases) assert.equal(only([file(path, text)], 'OBF-002').length, 1, path);
});

test('OBF-002: plain eval and documentation are not flagged', () => {
  assert.equal(only([file('a.js', 'const v = evaluate(input);')], 'OBF-002').length, 0);
  assert.equal(only([file('README.md', x('ev§al(atob("x"))'))], 'OBF-002').length, 0);
});

test('OBF-003: code hidden after a long whitespace run is flagged', () => {
  const line = 'const ok = 1;' + ' '.repeat(200) + x('require("child_process").ex§ec("id")');
  const f = only([file('index.js', line)], 'OBF-003');
  assert.equal(f.length, 1);
  assert.equal(f[0]?.severity, 'high');
});

test('OBF-003: long whitespace without code, or in non-code files, is ignored', () => {
  assert.equal(only([file('index.js', 'const a = 1;' + ' '.repeat(300) + '// note')], 'OBF-003').length, 0);
  assert.equal(only([file('notes.txt', 'a' + ' '.repeat(300) + 'require("x")')], 'OBF-003').length, 0);
});

test('OBF-004: bidi control characters are flagged', () => {
  const f = only([file('auth.js', 'if (isAdmin) { /* ‮ } ⁦ if (true) ⁩ */ }')], 'OBF-004');
  assert.equal(f.length, 1);
  assert.match(f[0]?.message ?? '', /Trojan Source/);
  assert.match(f[0]?.evidence ?? '', /<U\+202E>/);
});

test('OBF-004: runs of invisible characters are flagged', () => {
  const hidden = String.fromCodePoint(0xe0101, 0xe0102, 0xe0103, 0xe0104);
  assert.equal(only([file('ext.js', `const s = "${hidden}";`)], 'OBF-004').length, 1);
  const scattered = Array.from({ length: 12 }, (_, i) => `const v${i} = 1;​`).join('\n');
  assert.equal(only([file('ext2.js', scattered)], 'OBF-004').length, 1);
});

test('OBF-004: an emoji variation selector and a leading BOM are not flagged', () => {
  assert.equal(only([file('ui.js', 'const icon = "❤️";')], 'OBF-004').length, 0);
  assert.equal(only([file('mod.js', '﻿export const a = 1;')], 'OBF-004').length, 0);
});
