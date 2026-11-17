import { readFileSync } from 'node:fs';
import { SETS } from './types.ts';
import type { CorpusSet, Label, ManifestEntry } from './types.ts';

const ID_RE = /^[a-z0-9][a-z0-9._:/-]{0,199}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const GH_URL_RE = /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const RULE_RE = /^[A-Z]+-\d{3}$/;
const LABELS: readonly string[] = ['malicious', 'benign', 'unclear'];
const KNOWN_KEYS = new Set([
  'id', 'label', 'set', 'url', 'commit', 'path', 'techniques',
  'source', 'labelled_by', 'date_found', 'notes',
]);

function fail(where: string, msg: string): never {
  throw new Error(`${where}: ${msg}`);
}

const isStr = (v: unknown): v is string => typeof v === 'string';

export function validateEntry(raw: unknown, where: string): ManifestEntry {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) fail(where, 'entry must be a JSON object');
  const o = raw as Record<string, unknown>;

  for (const k of Object.keys(o)) if (!KNOWN_KEYS.has(k)) fail(where, `unknown field "${k}"`);
  if (!isStr(o.id) || !ID_RE.test(o.id)) fail(where, 'id must be lowercase letters, digits and . _ : / - (max 200)');
  if (!isStr(o.label) || !LABELS.includes(o.label)) fail(where, `label must be one of ${LABELS.join(', ')}`);
  if (!isStr(o.set) || !(SETS as readonly string[]).includes(o.set)) fail(where, `set must be one of ${SETS.join(', ')}`);

  const label = o.label as Label;
  const set = o.set as CorpusSet;
  if (set.startsWith('benign-') && label === 'malicious') fail(where, `set ${set} cannot have label malicious`);
  if ((set === 'malicious' || set === 'technique-copy') && label === 'benign') fail(where, `set ${set} cannot have label benign`);

  const hasRemote = o.url !== undefined || o.commit !== undefined;
  if (hasRemote) {
    if (!isStr(o.url) || !GH_URL_RE.test(o.url)) fail(where, 'url must be https://github.com/<owner>/<repo>');
    if (!isStr(o.commit) || !SHA_RE.test(o.commit)) fail(where, 'commit must be a full 40-character lowercase SHA');
  }
  if (o.path !== undefined && (!isStr(o.path) || o.path.length === 0)) fail(where, 'path must be a non-empty string');
  if (!hasRemote && o.path === undefined) fail(where, 'needs url + commit, or path');

  if (o.techniques !== undefined) {
    if (!Array.isArray(o.techniques) || !o.techniques.every((t) => isStr(t) && RULE_RE.test(t))) {
      fail(where, 'techniques must be an array of rule IDs like EXEC-001');
    }
  }
  if (set === 'technique-copy' && (!Array.isArray(o.techniques) || o.techniques.length === 0)) {
    fail(where, 'technique-copy entries must list the techniques they reproduce');
  }
  if (o.labelled_by !== undefined && (!Array.isArray(o.labelled_by) || !o.labelled_by.every(isStr))) {
    fail(where, 'labelled_by must be an array of strings');
  }
  if (o.date_found !== undefined && (!isStr(o.date_found) || !DATE_RE.test(o.date_found))) {
    fail(where, 'date_found must be YYYY-MM-DD');
  }
  for (const k of ['source', 'notes']) {
    if (o[k] !== undefined && !isStr(o[k])) fail(where, `${k} must be a string`);
  }
  return o as unknown as ManifestEntry;
}

export function parseManifest(text: string, name = 'manifest'): ManifestEntry[] {
  const out: ManifestEntry[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.trim() === '') continue;
    const where = `${name}:${i + 1}`;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      fail(where, 'not valid JSON');
    }
    const entry = validateEntry(raw, where);
    if (seen.has(entry.id)) fail(where, `duplicate id "${entry.id}"`);
    seen.add(entry.id);
    out.push(entry);
  }
  return out;
}

export function loadManifests(paths: string[]): ManifestEntry[] {
  const all: ManifestEntry[] = [];
  const seen = new Map<string, string>();
  for (const p of paths) {
    for (const e of parseManifest(readFileSync(p, 'utf8'), p)) {
      const prev = seen.get(e.id);
      if (prev) throw new Error(`${p}: id "${e.id}" also appears in ${prev}`);
      seen.set(e.id, p);
      all.push(e);
    }
  }
  return all;
}
