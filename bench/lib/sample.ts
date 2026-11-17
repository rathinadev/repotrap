import { createHash } from 'node:crypto';

/** Deterministic PRNG (mulberry32) seeded from a string. */
export function seededRandom(seed: string): () => number {
  let a = createHash('sha256').update(seed).digest().readUInt32LE(0);
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function shuffle<T>(items: T[], rand: () => number): T[] {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = a[i] as T;
    a[i] = a[j] as T;
    a[j] = tmp;
  }
  return a;
}

/**
 * Takes about `limit` items, proportionally from each set (at least one per set),
 * the same items every time for the same seed. limit <= 0 means everything.
 */
export function stratifiedSample<T extends { set: string; id: string }>(items: T[], limit: number, seed: string): T[] {
  if (limit <= 0 || limit >= items.length) return [...items].sort((x, y) => x.id.localeCompare(y.id));
  const rand = seededRandom(seed);
  const bySet = new Map<string, T[]>();
  for (const it of items) {
    const list = bySet.get(it.set) ?? [];
    list.push(it);
    bySet.set(it.set, list);
  }
  const out: T[] = [];
  for (const set of [...bySet.keys()].sort()) {
    const list = (bySet.get(set) ?? []).sort((x, y) => x.id.localeCompare(y.id));
    const take = Math.max(1, Math.round((limit * list.length) / items.length));
    out.push(...shuffle(list, rand).slice(0, take));
  }
  return out.sort((x, y) => x.id.localeCompare(y.id));
}
