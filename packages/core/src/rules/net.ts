import { sanitizeEvidence } from '../text.ts';
import type { FileContext, FileRule, RawFinding } from '../types.ts';

const MAX_LINE = 50_000;

/** Files whose commands run on a developer's machine (not docs, not CI, not container builds). */
const runsLocally = (f: FileContext): boolean => f.text !== undefined && !f.isDoc && !f.isData && !f.isWorkflow;
const isContainerBuild = (f: FileContext): boolean => /^(dockerfile|containerfile)(\..+)?$/.test(f.base) || f.ext === 'dockerfile';

function matchLines(f: FileContext, patterns: RegExp[]): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  const lines = f.lines();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.length <= MAX_LINE && patterns.some((p) => p.test(line))) out.push({ line: i + 1, text: line });
  }
  return out;
}

const DOWNLOAD_EXEC: RegExp[] = [
  /\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/,
  /\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/,
  /\bsource\s+<\(\s*(?:curl|wget)\b/,
  /\b(?:curl|wget)\b[^\n]*\s(?:-o|-O|--output)\s+\S+[^\n]*(?:&&|;)\s*chmod\s+\+?[0-7]*x/,
  /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]*\|\s*(?:i[e]x|Invoke-Expressio[n])\b/i,
  /\b(?:Invoke-WebRequest|iwr|curl|wget)\b[^\n]*-OutFile\s+\S+[^\n]*(?:Start-Process|saps\b|&\s*["'$.])/i,
  /\bcertutil(?:\.exe)?\s+-urlcache\s+(?:-split\s+)?-f\s+https?:/i,
  /\bbitsadmin(?:\.exe)?\s+\/transfer\b/i,
  /\bmshta(?:\.exe)?\s+["']?https?:/i,
  /\bregsvr32(?:\.exe)?\b[^\n]*\/i:\s*https?:/i,
];

export const NET_001: FileRule = {
  kind: 'file',
  id: 'NET-001',
  title: 'Downloads and runs code from the internet',
  category: 'NET',
  severity: 'high',
  advice:
    'This command fetches code from a remote server and runs it immediately, so what runs can change at any time and is not in the repository. Check where the URL points before running anything here.',
  appliesTo: runsLocally,
  check(f) {
    const container = isContainerBuild(f);
    return matchLines(f, DOWNLOAD_EXEC).map(
      (m): RawFinding => ({
        severity: container ? 'medium' : undefined,
        line: m.line,
        evidence: sanitizeEvidence(m.text),
        message: container ? 'Container build downloads and runs remote code' : 'Remote code is downloaded and executed',
      }),
    );
  },
};

const FETCH_EVAL: RegExp[] = [
  // JavaScript
  /\b(?:eval|Function)\s*\([^\n]*\b(?:fetch\s*\(|axios\b|\.text\s*\(\s*\)|responseText\b)/,
  /\bnew\s+Function\s*\([^\n]*\b(?:res|response|resp)\.(?:data|body|text)\b/,
  /\bvm\.runIn(?:This|New)?Context\s*\([^\n]*\b(?:res|response|resp|body)\b/,
  // Python
  /\b(?:exec|eval)\s*\(\s*(?:requests\.get|urllib\.request\.urlopen|urlopen)\s*\(/,
  /\b(?:exec|eval)\s*\([^\n]*\b(?:requests\.get|urlopen)\s*\([^\n]*\)\s*\.(?:text|content|read\s*\(\s*\))/,
  // PowerShell
  /\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(?:System\.)?Net\.WebClient\s*\)?\s*\.DownloadString/i,
  /\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b/i,
  // Shell
  /\beval\s+["']?\$\(\s*(?:curl|wget)\b/,
];

export const NET_003: FileRule = {
  kind: 'file',
  id: 'NET-003',
  title: 'Downloads code and executes it in memory',
  category: 'NET',
  severity: 'critical',
  advice:
    'Code is fetched from a server and executed directly in memory, leaving nothing on disk to inspect. This is a common malware loader pattern. Do not run this repository.',
  appliesTo: runsLocally,
  check: (f) =>
    matchLines(f, FETCH_EVAL).map((m) => ({ line: m.line, evidence: sanitizeEvidence(m.text), message: 'Remote content is executed without being saved' })),
};

const REVERSE_SHELL_LINE: RegExp[] = [
  /\b(?:ba)?sh\s+-i\s*[>&]+\s*\/dev\/tcp\//,
  /\/dev\/tcp\/[\w.-]+\/\d+\s+0?[<>]&\s*1/,
  /\bnc(?:at)?(?:\.exe)?\b[^\n]*\s-e\s+["']?(?:\/bin\/(?:ba)?sh|cmd(?:\.exe)?|powershell)/i,
  /\bmkfifo\b[^\n]*\|\s*(?:\/bin\/)?(?:ba)?sh\b[^\n]*\bnc\b/,
  /\bsocat\b[^\n]*\bexec:\s*["']?(?:\/bin\/)?(?:ba)?sh/i,
];

export const NET_004: FileRule = {
  kind: 'file',
  id: 'NET-004',
  title: 'Reverse shell',
  category: 'NET',
  severity: 'critical',
  advice:
    'This code connects out to a remote machine and hands it a command shell, giving someone else control of your computer. Do not run it.',
  appliesTo: runsLocally,
  check(f) {
    const out: RawFinding[] = matchLines(f, REVERSE_SHELL_LINE).map((m) => ({
      line: m.line,
      evidence: sanitizeEvidence(m.text),
      message: 'A shell is connected to a remote host',
    }));
    const text = f.text ?? '';
    // Python: socket + dup2 + shell in one file
    if (/\bsocket\.socket\s*\(/.test(text) && /\bos\.dup2\s*\(/.test(text) && /\b(?:pty\.spawn|subprocess\.(?:call|Popen|run))\s*\(\s*\[?\s*["']\/bin\/(?:ba)?sh/.test(text)) {
      const idx = text.search(/\bos\.dup2\s*\(/);
      out.push({ line: text.slice(0, idx).split('\n').length, evidence: 'socket + os.dup2 + /bin/sh', message: 'Python reverse shell (socket redirected to a shell)' });
    }
    // PowerShell: TCP client + stream + IEX in one file
    if (/New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\(/i.test(text) && /\.GetStream\s*\(/i.test(text) && /\b(?:iex|Invoke-Expression)\b/i.test(text)) {
      const idx = text.search(/New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient/i);
      out.push({ line: text.slice(0, idx).split('\n').length, evidence: 'TCPClient + GetStream + Invoke-Expression', message: 'PowerShell reverse shell' });
    }
    return out;
  },
};

export const NET_RULES: FileRule[] = [NET_001, NET_003, NET_004];
