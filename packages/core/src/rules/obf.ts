import { isBidiControl, isInvisible, sanitizeEvidence } from '../text.ts';
import type { FileContext, FileRule, RawFinding } from '../types.ts';

const MAX_LINE = 50_000;

/** Line-by-line regex scan over a file, skipping pathological line lengths. */
export function scanLines(f: FileContext, patterns: RegExp[], message: string): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = f.lines();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.length > MAX_LINE) continue;
    if (patterns.some((p) => p.test(line))) out.push({ line: i + 1, evidence: sanitizeEvidence(line), message });
  }
  return out;
}

const EVAL_DECODED: RegExp[] = [
  // JavaScript: eval/Function/vm on decoded data
  /\b(?:eval|Function|setTimeout|setInterval|runInThisContext|runInNewContext)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|Buffer\.from)\b/,
  /\bnew\s+Function\s*\([^)\n]*\b(?:atob|Buffer\.from|String\.fromCharCode)\b/,
  /\beval\s*\([^)\n]*\bBuffer\.from\s*\([^)\n]*["']base64["']/,
  // Python: exec/eval on decoded or decompressed data
  /\b(?:exec|eval)\s*\(\s*(?:base64\.\w*b64decode|b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads|binascii\.unhexlify|__import__\s*\(\s*["'](?:base64|zlib|marshal|codecs)["']\s*\))/,
  /\bexec\s*\(\s*compile\s*\([^)\n]*(?:b64decode|decompress|unhexlify)/,
  // PowerShell: IEX on decoded text
  /\b(?:i[e]x|Invoke-Expressio[n])\b[^\n]*\b(?:FromBase64Strin[g]|GetStrin[g])\b/i,
  /\[ScriptBlock\]::Create\s*\([^\n]*\b(?:FromBase64String|GetString)\b/i,
  // Shell: decoded data piped into a shell
  /\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:ba|z|da)?sh\b/,
];

export const OBF_002: FileRule = {
  kind: 'file',
  id: 'OBF-002',
  title: 'Decoded data is executed',
  category: 'OBF',
  severity: 'high',
  advice:
    'Code that decodes a hidden string and then executes it is a classic way to hide malware. Decode the string (without running it) to see what it really does before trusting this repository.',
  appliesTo: (f) => f.text !== undefined && !f.isDoc && !f.isData,
  check: (f) => scanLines(f, EVAL_DECODED, 'Decoded or decompressed data is passed to an executing function'),
};

const OFFSCREEN_RUN = 150;
const CODE_TOKEN_RE = /[;(=]|\b(?:import|require|exec|eval|fetch|subprocess)\b/;

export const OBF_003: FileRule = {
  kind: 'file',
  id: 'OBF-003',
  title: 'Code hidden beyond the visible line width',
  category: 'OBF',
  severity: 'high',
  advice:
    'This line continues with code far to the right, after a long run of spaces, where editors and GitHub previews will not show it. Scroll right or view the raw file to see the hidden code.',
  appliesTo: (f) => f.text !== undefined && f.isCode,
  check(f) {
    const out: RawFinding[] = [];
    const lines = f.lines();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.length < OFFSCREEN_RUN + 2) continue;
      // Linear scan for a long whitespace run followed by more content.
      let run = 0;
      let runStart = -1;
      for (let j = 0; j < line.length; j++) {
        const c = line.charCodeAt(j);
        if (c === 32 || c === 9) {
          if (run === 0) runStart = j;
          run++;
          continue;
        }
        if (run >= OFFSCREEN_RUN) {
          const before = line.slice(0, runStart).trim();
          const after = line.slice(j);
          if ((before.length > 0 || run >= 2 * OFFSCREEN_RUN) && CODE_TOKEN_RE.test(after)) {
            out.push({
              line: i + 1,
              evidence: sanitizeEvidence(`${before} … ${after}`),
              message: `Code continues after ${run} whitespace characters on one line`,
            });
            break;
          }
        }
        run = 0;
      }
    }
    return out;
  },
};

const INVISIBLE_RUN = 3;
const INVISIBLE_TOTAL = 10;

export const OBF_004: FileRule = {
  kind: 'file',
  id: 'OBF-004',
  title: 'Invisible or text-reordering Unicode characters in code',
  category: 'OBF',
  severity: 'high',
  advice:
    'This file contains characters that are invisible or that change how code is displayed, so what you read is not what runs. View the file with a tool that reveals hidden characters before trusting it.',
  appliesTo: (f) => f.text !== undefined && (f.isCode || /(^|\/)\.vscode\/[^/]+\.json$/.test(f.lower)),
  check(f) {
    const out: RawFinding[] = [];
    const lines = f.lines();
    let total = 0;
    let firstInvisibleLine: number | undefined;
    let bidiReported = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      let run = 0;
      let longest = 0;
      let bidi = false;
      let idx = 0;
      for (const ch of line) {
        const cp = ch.codePointAt(0) ?? 0;
        // A lone BOM at the very start of a file is harmless.
        const invisible = isInvisible(cp) && !(cp === 0xfeff && i === 0 && idx === 0);
        // A single emoji variation selector (U+FE0F/FE0E) is normal text.
        const benignVs = (cp === 0xfe0f || cp === 0xfe0e) && run === 0;
        if (invisible && !benignVs) {
          run++;
          total++;
          longest = Math.max(longest, run);
          firstInvisibleLine ??= i + 1;
          if (isBidiControl(cp)) bidi = true;
        } else run = 0;
        idx++;
      }
      if (bidi && !bidiReported) {
        bidiReported = true;
        out.push({ line: i + 1, evidence: sanitizeEvidence(line), message: 'Bidirectional control characters can make code display differently from how it runs (Trojan Source)' });
      }
      if (longest >= INVISIBLE_RUN && !bidi) {
        out.push({ line: i + 1, evidence: sanitizeEvidence(line), message: `A run of ${longest} invisible characters is hidden in this line` });
        return out;
      }
    }
    if (out.length === 0 && total >= INVISIBLE_TOTAL && firstInvisibleLine !== undefined) {
      out.push({
        line: firstInvisibleLine,
        evidence: sanitizeEvidence(lines[firstInvisibleLine - 1] ?? ''),
        message: `${total} invisible characters are scattered through this file`,
      });
    }
    return out;
  },
};

export const OBF_RULES: FileRule[] = [OBF_002, OBF_003, OBF_004];
