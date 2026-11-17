// Validates one or more corpus manifests and prints entry counts per set.
//   node bench/validate-manifest.ts corpus/benign.jsonl [...]

import { loadManifests } from './lib/manifest.ts';

const paths = process.argv.slice(2);
if (paths.length === 0) {
  console.error('Usage: node bench/validate-manifest.ts <manifest.jsonl> [...]');
  process.exitCode = 2;
} else {
  try {
    const entries = loadManifests(paths);
    const bySet = new Map<string, number>();
    for (const e of entries) bySet.set(e.set, (bySet.get(e.set) ?? 0) + 1);
    console.log(`${entries.length} valid entries`);
    for (const [set, n] of [...bySet.entries()].sort()) console.log(`  ${set}: ${n}`);
  } catch (e) {
    console.error((e as Error).message);
    process.exitCode = 1;
  }
}
