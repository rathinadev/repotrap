import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bin, file, only, repo, run, tasksJson, x } from './helpers.ts';

test('META-007: README asking to disable antivirus or use an archive password is High', () => {
  const av = only([file('README.md', x('## Setup\nPlease dis§able your anti§virus before running the tool.'))], 'META-007');
  assert.equal(av[0]?.severity, 'high');
  const pw = only([file('README.md', 'Download the release zip below.\nPassword: 2026')], 'META-007');
  assert.equal(pw.length, 1);
});

test('META-007: ordinary README content is not flagged', () => {
  assert.equal(only([file('README.md', 'Set the DB password: in config.yml\nRun the server.')], 'META-007').length, 0);
  assert.equal(only([file('README.md', 'Antivirus tools may report false positives for packed binaries.')], 'META-007').length, 0);
  assert.equal(only([file('README.md', '| Binaries | Disguised executables, password-protected archives |')], 'META-007').length, 0);
});

test('META-007: false-positive claim plus run-as-administrator is Medium', () => {
  const text = 'Windows may flag this as a virus. It is a false positive.\nRun it as administrator.';
  const f = only([file('README.md', text)], 'META-007');
  assert.equal(f[0]?.severity, 'medium');
});

test('META-003: young owner + CVE exploit + executable is High', () => {
  const files = [file('README.md', '# CVE-2026-12345 PoC\nRun exploit.exe'), bin('exploit.exe', [0x4d, 0x5a, 0x00])];
  const f = only(files, 'META-003', { repo: repo({ name: 'CVE-2026-12345' }) });
  assert.equal(f[0]?.severity, 'high');
  assert.match(f[0]?.message ?? '', /16 days old/);
});

test('META-003: needs a young owner, a CVE mention and a risky artefact', () => {
  const files = [file('README.md', '# CVE-2026-12345 PoC'), bin('exploit.exe', [0x4d, 0x5a, 0x00])];
  assert.equal(only(files, 'META-003', { repo: repo({ ownerCreatedAt: '2019-01-01T00:00:00Z' }) }).length, 0);
  assert.equal(only([file('README.md', '# CVE-2026-12345 PoC'), file('poc.py', 'print(1)')], 'META-003', { repo: repo() }).length, 0);
  assert.equal(only(files, 'META-003').length, 0); // no repo metadata (local scan)
});

test('CHAIN-001: auto-run task executing a disguised payload is Critical', () => {
  const js = 'const cp = require("child_process");\nfunction run() { return 1; }\nconst x = () => { run(); };';
  const files = [
    file('.vscode/tasks.json', tasksJson([{ label: 'fonts', command: 'node ${workspaceFolder}/public/fonts/brand.woff2', runOptions: { runOn: 'folderOpen' } }])),
    file('public/fonts/brand.woff2', js),
  ];
  const { ids, report } = run(files);
  assert.ok(ids.includes('CHAIN-001'));
  assert.equal(report.verdict, 'likely-malicious');
});

test('CHAIN-001: auto-run task executing an obfuscated script is Critical', () => {
  const files = [
    file('.vscode/tasks.json', tasksJson([{ label: 'init', command: 'node scripts/init.js', runOptions: { runOn: 'folderOpen' } }])),
    file('scripts/init.js', x('ev§al(atob(payload));')),
  ];
  const chain = only(files, 'CHAIN-001');
  assert.equal(chain.length, 1);
  assert.match(chain[0]?.message ?? '', /scripts\/init\.js/);
});

test('CHAIN-001: auto-run task running a clean script does not chain', () => {
  const files = [
    file('.vscode/tasks.json', tasksJson([{ label: 'w', command: 'node scripts/watch.js', runOptions: { runOn: 'folderOpen' } }])),
    file('scripts/watch.js', 'console.log("watching");'),
  ];
  assert.equal(only(files, 'CHAIN-001').length, 0);
});

test('CHAIN-002: credential theft plus an exfiltration endpoint is Critical', () => {
  const files = [
    file('collect.js', `read("${x('Login§ Data')}"); read("${x('Local§ State')}"); axios.post(u, d);`),
    file('config.js', x('module.exports = { hook: "https://disc§ord.com/api/webhooks/1/abc" };').replace('disc', 'disc')),
  ];
  const chain = only(files, 'CHAIN-002');
  assert.equal(chain.length, 1);
  assert.equal(chain[0]?.file, 'config.js');
});

test('CHAIN-002: private IP addresses are not exfiltration endpoints', () => {
  const files = [
    file('collect.js', `read("${x('Login§ Data')}"); read("${x('Local§ State')}"); axios.post(u, d);`),
    file('dev.js', 'const api = "http://192.168.1.10:8080/";'),
  ];
  assert.equal(only(files, 'CHAIN-002').length, 0);
});
