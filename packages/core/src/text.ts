import type { FileContext, ScannedFile } from './types.ts';

const SNIFF_BYTES = 8192;
const HEAD_BYTES = 64;

/** Decodes file bytes to text, or returns undefined for binary content. Handles UTF-8/UTF-16 BOMs. */
export function decodeText(bytes: Uint8Array): string | undefined {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder('utf-16le').decode(bytes.subarray(2));
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return new TextDecoder('utf-16be').decode(bytes.subarray(2));
  }
  const sniff = Math.min(bytes.length, SNIFF_BYTES);
  for (let i = 0; i < sniff; i++) if (bytes[i] === 0) return undefined;
  return new TextDecoder('utf-8').decode(bytes);
}

/** Builds a ScannedFile from raw bytes. Sources should use this so every surface decodes identically. */
export function toScannedFile(path: string, bytes: Uint8Array): ScannedFile {
  const head = bytes.slice(0, HEAD_BYTES);
  const text = decodeText(bytes);
  return text === undefined ? { path, size: bytes.length, head } : { path, size: bytes.length, head, text };
}

const DOC_EXT = new Set(['md', 'markdown', 'mdx', 'rst', 'txt', 'adoc', 'asciidoc', 'html', 'htm', 'org', 'tex', 'rtf']);
const CODE_EXT = new Set([
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'astro', 'coffee',
  'py', 'pyw', 'sh', 'bash', 'zsh', 'fish', 'ksh', 'ps1', 'psm1', 'psd1', 'bat', 'cmd', 'vbs', 'vbe', 'wsf', 'hta',
  'rb', 'php', 'pl', 'pm', 'go', 'rs', 'java', 'kt', 'kts', 'scala', 'groovy', 'gradle', 'cs', 'vb', 'fs', 'fsx',
  'c', 'cc', 'cpp', 'cxx', 'h', 'hpp', 'm', 'mm', 'swift', 'lua', 'r', 'dart', 'ex', 'exs', 'erl', 'clj', 'nim', 'zig',
]);
/** Pure data formats that are never executed directly. */
const DATA_EXT = new Set(['jsonl', 'ndjson', 'csv', 'tsv', 'lock', 'sum', 'map']);
const TEST_DIR_RE = /(^|\/)(test|tests|__tests__|spec|specs|fixtures|__fixtures__|testdata|test-data|examples?|docs?)\//;

export function makeFileContext(f: ScannedFile): FileContext {
  const path = f.path.replace(/\\/g, '/').replace(/^\.\//, '');
  const lower = path.toLowerCase();
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  const ext = dot > 0 ? base.slice(dot + 1) : '';
  const text = f.text;
  let cached: string[] | undefined;
  const shebang = text !== undefined && text.startsWith('#!');
  return {
    path,
    lower,
    base,
    ext,
    size: f.size,
    text,
    head: f.head,
    lines: () => (cached ??= text === undefined ? [] : text.split(/\r?\n/)),
    isDoc: DOC_EXT.has(ext) || /^(readme|changelog|license|licence|notice|authors|contributing)(\.|$)/.test(base),
    isCode: CODE_EXT.has(ext) || (ext === '' && shebang),
    isTestPath: TEST_DIR_RE.test(lower),
    isWorkflow: /(^|\/)\.github\/workflows\//.test(lower),
    isData: DATA_EXT.has(ext) || (ext === 'json' && base !== 'package.json' && !/(^|\/)\.(vscode|devcontainer)\//.test(lower)),
  };
}

/** 1-based line number of a character offset. */
export function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Parses JSON with comments and trailing commas (the dialect VS Code accepts for
 * tasks.json, settings.json and devcontainer.json). Returns undefined if invalid.
 */
export function parseJsonc(text: string): unknown {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
    } else if (c === ',') {
      let j = i + 1;
      while (j < n && /\s/.test(text[j] ?? '')) j++;
      if (text[j] !== '}' && text[j] !== ']') out += c;
      i++;
    } else {
      out += c;
      i++;
    }
  }
  try {
    return JSON.parse(out.replace(/^﻿/, ''));
  } catch {
    return undefined;
  }
}

/** True for code points that render as nothing or reorder text. */
export function isInvisible(cp: number): boolean {
  return (
    (cp >= 0x200b && cp <= 0x200f) || // zero-width space/joiners, LRM/RLM
    (cp >= 0x202a && cp <= 0x202e) || // bidi embeddings/overrides
    (cp >= 0x2060 && cp <= 0x2064) || // word joiner, invisible operators
    (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
    cp === 0xfeff ||
    cp === 0x180e ||
    cp === 0x3164 || cp === 0xffa0 || cp === 0x115f || cp === 0x1160 || // Hangul fillers
    (cp >= 0xfe00 && cp <= 0xfe0f) || // variation selectors
    (cp >= 0xe0000 && cp <= 0xe007f) || // tag characters
    (cp >= 0xe0100 && cp <= 0xe01ef) // variation selectors supplement
  );
}

export function isBidiControl(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}

/**
 * Makes a snippet safe to display anywhere: control and invisible characters
 * become visible <U+XXXX> markers, long whitespace runs are collapsed, and the
 * result is truncated.
 */
export function sanitizeEvidence(s: string, max = 160): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 9) out += ' ';
    else if (cp < 32 || cp === 0x7f || isInvisible(cp) || (cp >= 0xe000 && cp <= 0xf8ff)) {
      out += `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
    } else out += ch;
    if (out.length > max * 4) break;
  }
  out = out.replace(/ {5,}/g, ' … ').trim();
  return out.length > max ? `${out.slice(0, max - 1)}…` : out;
}

/** Decodes the XML entities that appear in MSBuild command attributes. */
export function decodeXmlEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d: string) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}
