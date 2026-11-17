// Shared detection patterns. Every multi-word pattern uses \s+ between words so
// that this source file never matches its own patterns (keeps self-scans clean).

const DOWNLOAD: RegExp[] = [
  /\b(?:curl|wget)\b[^\n]*?https?:\/\//i,
  /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer)\b/i,
  /\bDownload(?:String|File|Data)\s*\(/i,
  /\bNet\.WebClient\b/i,
  /\bcertutil(?:\.exe)?\s+-urlcache\b/i,
  /\bbitsadmin(?:\.exe)?\s+\/transfer\b/i,
  /\bmshta(?:\.exe)?\s+["']?(?:https?|javascript|vbscript):/i,
  /\bfetch\s*\(\s*["'`]https?:/i,
];
const PIPE_TO_SHELL = /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:iex|Invoke-Expression)\b/i;
const DECODE =
  /\bbase64\s+(?:-d|--decode|-D)\b|FromBase64String|\batob\s*\(|\bb64decode\b|\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{24,}/i;
const INLINE_INTERPRETER = /\b(?:node|python3?|perl|ruby|php)(?:\.exe)?\s+-(?:e|c|r)\s/i;
const NON_SCRIPT_EXEC =
  /\b(?:node|python3?|bash|sh|pwsh|powershell|deno|bun|wscript|cscript)(?:\.exe)?\s+(?:-\S+\s+)*["']?[^\s"']+\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|bmp|webp|txt|md|csv|log|dat|bin|pdf|mp3|mp4|wav)(?=["'\s]|$)/i;
const HIDDEN_WINDOW = /\s-w(?:indowstyle)?\s+h(?:idden)?\b|\s-NoP(?:rofile)?\s+[^\n]*-NonI/i;

/**
 * Reasons a command line looks dangerous. Empty array = nothing notable.
 * Used to escalate auto-run triggers (tasks, devcontainer, build events).
 */
export function suspiciousCommand(cmd: string): string[] {
  const reasons: string[] = [];
  if (DOWNLOAD.some((r) => r.test(cmd))) reasons.push('downloads from the internet');
  if (PIPE_TO_SHELL.test(cmd)) reasons.push('pipes into a shell');
  if (DECODE.test(cmd)) reasons.push('decodes an encoded payload');
  if (INLINE_INTERPRETER.test(cmd)) reasons.push('runs inline interpreter code');
  if (NON_SCRIPT_EXEC.test(cmd)) reasons.push('executes a file disguised as a non-script type');
  if (HIDDEN_WINDOW.test(cmd)) reasons.push('hides its window');
  return reasons;
}

/** Network capability markers across common languages. */
export const NETWORK_RE =
  /\b(?:fetch|axios|XMLHttpRequest|WebSocket)\b|\bhttps?\.(?:request|get)\s*\(|\brequests\.(?:get|post|put|request)\s*\(|\burllib\b|\burlopen\s*\(|\bsocket\.(?:socket|connect|create_connection)\b|\bNet\.WebClient\b|\bInvoke-(?:WebRequest|RestMethod)\b|\bHttpClient\b|\bnet\.(?:connect|Socket|createConnection)\b|\b(?:curl|wget)\s+/;

const EXFIL_RE =
  /discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|pastebin\.com\/raw|paste\.ee\/r\/|hastebin\.com\/raw|transfer\.sh\/|ngrok(?:-free)?\.(?:io|app|dev)|webhook\.site\/|pipedream\.net|requestbin\.(?:net|com)/i;
const BARE_IP_URL_RE = /\bhttps?:\/\/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?(?:\/|\b)/g;

function isPublicIp(a: number, b: number): boolean {
  if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

/** Returns a description of the first exfiltration endpoint on a line, if any. */
export function exfilEndpoint(line: string): string | undefined {
  const m = EXFIL_RE.exec(line);
  if (m) return m[0];
  BARE_IP_URL_RE.lastIndex = 0;
  for (let ip = BARE_IP_URL_RE.exec(line); ip; ip = BARE_IP_URL_RE.exec(line)) {
    const a = Number(ip[1]);
    const b = Number(ip[2]);
    if (isPublicIp(a, b) && Number(ip[3]) <= 255 && Number(ip[4]) <= 255) return ip[0];
  }
  return undefined;
}

/**
 * Extracts repository-relative paths referenced by a command line, e.g.
 * `node ${workspaceFolder}/scripts/setup.js` → `scripts/setup.js`.
 */
export function extractPathRefs(cmd: string): string[] {
  const out = new Set<string>();
  for (const raw of cmd.split(/[\s"'`;&|()]+/)) {
    let t = raw
      .replace(/^\$\{workspace(?:Folder|Root)\}[\\/]/, '')
      .replace(/^%~dp0[\\/]?/i, '')
      .replace(/\\/g, '/')
      .replace(/^\.\//, '');
    if (t.length === 0 || t.length > 300 || t.includes('://') || t.startsWith('-') || t.startsWith('$')) continue;
    if (!/\.[A-Za-z0-9]{1,6}$/.test(t) && !t.includes('/')) continue;
    t = t.replace(/^\/+/, '');
    out.add(t);
  }
  return [...out];
}

/** Script-like content markers, used to spot code hiding in media files. */
const SCRIPT_MARKERS: RegExp[] = [
  /\brequire\s*\(/,
  /\bimport\s+[\w{*]/,
  /\bfunction\s*[\w$]*\s*\(/,
  /\b(?:const|let|var)\s+[\w$]+\s*=/,
  /\b(?:eval|exec)\s*\(/,
  /\bchild_process\b|\bsubprocess\b/,
  /^\s*def\s+\w+\s*\(/m,
  /^#!\s*\//,
  /\bpowershell\b|\bInvoke-Expression\b/i,
  /=>\s*\{/,
];

export function looksLikeScript(text: string): boolean {
  const sample = text.length > 200_000 ? text.slice(0, 200_000) : text;
  let hits = 0;
  for (const r of SCRIPT_MARKERS) if (r.test(sample) && ++hits >= 3) return true;
  return false;
}

export type Magic = 'pe' | 'elf' | 'macho' | 'zip' | 'unknown';

export function detectMagic(head: Uint8Array): Magic {
  const b = (i: number) => head[i] ?? -1;
  if (b(0) === 0x4d && b(1) === 0x5a) return 'pe';
  if (b(0) === 0x7f && b(1) === 0x45 && b(2) === 0x4c && b(3) === 0x46) return 'elf';
  const m = ((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)) >>> 0;
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m)) return 'macho';
  if (b(0) === 0x50 && b(1) === 0x4b && b(2) === 0x03 && b(3) === 0x04) return 'zip';
  return 'unknown';
}

/** True if a zip's first local file header has the "encrypted" flag set. */
export function zipFirstEntryEncrypted(head: Uint8Array): boolean {
  return detectMagic(head) === 'zip' && ((head[6] ?? 0) & 0x01) === 1;
}

export const EXECUTABLE_EXT = new Set(['exe', 'dll', 'scr', 'com', 'msi', 'sys', 'so', 'dylib', 'elf', 'bin', 'jar', 'lnk', 'pif']);
export const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'iso']);
