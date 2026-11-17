// Builds corpus/benign.jsonl from GitHub metadata only (search + commit SHAs).
// It never downloads repository contents.
//
//   GITHUB_TOKEN=... node bench/build-benign.ts [--per-language 72] [--random-per-language 29]
//
// Sets produced:
//   benign-popular  top repos by stars per language
//   benign-random   ordinary, recently active repos (5-100 stars), random pages
//   benign-tricky   curated legitimate repos that use risky-looking features
//   benign-dualuse  curated security tools (reported separately, not false alarms)

import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { validateEntry } from './lib/manifest.ts';
import { seededRandom, shuffle } from './lib/sample.ts';
import type { CorpusSet, ManifestEntry } from './lib/types.ts';

const API = 'https://api.github.com';
const LANGUAGES = ['JavaScript', 'TypeScript', 'Python', 'C#', 'Go', 'Rust', 'Java'];
const SHA_RE = /^[0-9a-f]{40}$/;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const { values } = parseArgs({
  options: {
    'per-language': { type: 'string', default: '72' },
    'random-per-language': { type: 'string', default: '29' },
    tricky: { type: 'string', default: 'bench/tricky-benign.json' },
    out: { type: 'string', default: 'corpus/benign.jsonl' },
    seed: { type: 'string', default: 'repotrap-benign' },
  },
});

const token = process.env.GITHUB_TOKEN;
if (!token) {
  console.error('GITHUB_TOKEN is required (search API needs authentication).');
  process.exit(2);
}

async function gh(path: string, accept = 'application/vnd.github+json'): Promise<Response> {
  for (let attempt = 0; attempt < 6; attempt++) {
    const res = await fetch(API + path, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: accept,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'repotrap-corpus-builder',
      },
    });
    const limited =
      (res.status === 403 || res.status === 429) &&
      (res.headers.get('x-ratelimit-remaining') === '0' || res.headers.has('retry-after'));
    if (!limited) return res;
    const resetMs = Number(res.headers.get('x-ratelimit-reset') ?? 0) * 1000 - Date.now();
    const retryMs = Number(res.headers.get('retry-after') ?? 0) * 1000;
    const wait = Math.max(resetMs, retryMs, 5000);
    if (wait > 20 * 60 * 1000) throw new Error(`Rate limited for ${Math.round(wait / 60000)} min; try later.`);
    console.log(`Rate limited; waiting ${Math.round(wait / 1000)} s…`);
    await sleep(wait + 1000);
  }
  throw new Error(`Gave up on ${path}`);
}

interface RepoInfo {
  full_name: string;
  default_branch: string;
  archived: boolean;
  fork: boolean;
}

async function search(q: string, page: number, sortByStars: boolean): Promise<RepoInfo[]> {
  const sort = sortByStars ? '&sort=stars&order=desc' : '';
  const res = await gh(`/search/repositories?q=${encodeURIComponent(q)}${sort}&per_page=100&page=${page}`);
  await sleep(2200); // search API: 30 requests/minute
  if (!res.ok) throw new Error(`search failed (${res.status}) for ${q}`);
  const body = (await res.json()) as { items: RepoInfo[] };
  return body.items;
}

async function repoInfo(full: string): Promise<RepoInfo | null> {
  const res = await gh(`/repos/${full}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`repo lookup failed (${res.status}) for ${full}`);
  return (await res.json()) as RepoInfo;
}

async function headSha(full: string, branch: string): Promise<string | null> {
  const res = await gh(`/repos/${full}/commits/${encodeURIComponent(branch)}`, 'application/vnd.github.sha');
  if (!res.ok) return null; // empty repo, blocked, etc.
  const sha = (await res.text()).trim();
  return SHA_RE.test(sha) ? sha : null;
}

interface Candidate {
  full: string;
  branch: string;
  set: CorpusSet;
  source: string;
  labelledBy: string;
  notes?: string;
}

async function main(): Promise<void> {
  const perLang = Number(values['per-language']);
  const randomPerLang = Number(values['random-per-language']);
  const rand = seededRandom(values.seed ?? 'repotrap-benign');
  const today = new Date().toISOString().slice(0, 10);
  const since = new Date(Date.now() - 180 * 864e5).toISOString().slice(0, 10);

  const chosen = new Map<string, Candidate>(); // key: lowercase full name; first set wins
  const add = (c: Candidate) => {
    const key = c.full.toLowerCase();
    if (!chosen.has(key)) chosen.set(key, c);
  };

  // 1. Curated tricky + dual-use first, so they keep their set.
  const curated = JSON.parse(readFileSync(values.tricky ?? 'bench/tricky-benign.json', 'utf8')) as {
    repo: string;
    set: CorpusSet;
    why: string;
  }[];
  for (const c of curated) {
    const info = await repoInfo(c.repo);
    if (!info) {
      console.warn(`skip curated ${c.repo}: not found`);
      continue;
    }
    add({ full: info.full_name, branch: info.default_branch, set: c.set, source: 'curated', labelledBy: 'curated', notes: c.why });
  }
  console.log(`curated: ${chosen.size}`);

  // 2. Popular repos per language.
  for (const lang of LANGUAGES) {
    const items = await search(`language:"${lang}" stars:>1000 fork:false archived:false`, 1, true);
    let n = 0;
    for (const it of items) {
      if (n >= perLang) break;
      if (chosen.has(it.full_name.toLowerCase())) continue;
      add({ full: it.full_name, branch: it.default_branch, set: 'benign-popular', source: 'github-search:popular', labelledBy: 'auto:popular' });
      n++;
    }
    console.log(`popular ${lang}: ${n}`);
  }

  // 3. Ordinary recently active repos, from random result pages.
  for (const lang of LANGUAGES) {
    const pages = shuffle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], rand).slice(0, 3);
    const pool: RepoInfo[] = [];
    for (const p of pages) {
      pool.push(...(await search(`language:"${lang}" stars:5..100 fork:false archived:false pushed:>${since}`, p, false)));
    }
    let n = 0;
    for (const it of shuffle(pool, rand)) {
      if (n >= randomPerLang) break;
      if (chosen.has(it.full_name.toLowerCase())) continue;
      add({ full: it.full_name, branch: it.default_branch, set: 'benign-random', source: 'github-search:random', labelledBy: 'auto:random' });
      n++;
    }
    console.log(`random ${lang}: ${n}`);
  }

  // 4. Pin every repo to its current default-branch commit.
  const candidates = [...chosen.values()];
  const entries: ManifestEntry[] = [];
  let idx = 0;
  const worker = async () => {
    while (idx < candidates.length) {
      const c = candidates[idx++];
      const sha = await headSha(c.full, c.branch);
      if (!sha) {
        console.warn(`skip ${c.full}: no commit`);
        continue;
      }
      const prefix = c.set.replace('benign-', '');
      const raw: Record<string, unknown> = {
        id: `${prefix}/${c.full.toLowerCase()}`,
        label: 'benign',
        set: c.set,
        url: `https://github.com/${c.full}`,
        commit: sha,
        source: c.source,
        labelled_by: [c.labelledBy],
        date_found: today,
      };
      if (c.notes) raw.notes = c.notes;
      entries.push(validateEntry(raw, c.full));
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));

  entries.sort((a, b) => a.id.localeCompare(b.id));
  writeFileSync(values.out ?? 'corpus/benign.jsonl', entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
  const counts = new Map<string, number>();
  for (const e of entries) counts.set(e.set, (counts.get(e.set) ?? 0) + 1);
  console.log(`wrote ${entries.length} entries to ${values.out}`, Object.fromEntries(counts));
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 1;
});
