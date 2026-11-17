// Runs the repotrap scanner over corpus manifests and produces a scorecard.
//
//   node bench/run-bench.ts --manifest corpus/benign.jsonl \
//     --scanner node --scanner-arg packages/cli/dist/repotrap.js --scanner-arg scan
//
// Exit codes: 0 pass, 1 regression or gate failure, 2 usage/setup error.
// Outputs (in --out): scorecard.json, scorecard.md, results.jsonl. None of them
// contain file paths, code snippets or (with --redact) malicious repo names.

import { parseArgs } from 'node:util';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadManifests } from './lib/manifest.ts';
import { runScanner, targetFor } from './lib/scanner.ts';
import { stratifiedSample } from './lib/sample.ts';
import { buildScorecard, checkGates, compareScorecards, renderMarkdown, toResult } from './lib/scorecard.ts';
import type { Scorecard } from './lib/scorecard.ts';
import type { EntryResult } from './lib/types.ts';

const USAGE = `Usage: node bench/run-bench.ts --manifest <file.jsonl> [--manifest ...] --scanner <cmd> [--scanner-arg <arg> ...]
  --out <dir>             Output folder (default: bench-results)
  --baseline <file>       Previous scorecard.json to compare against (skipped if missing)
  --cutoff <YYYY-MM-DD>   Also report detection on malicious entries found on/after this date
  --limit <n>             Stratified sample of about n entries (0 = all, default 0)
  --seed <text>           Sample seed (default: repotrap)
  --set <name>            Only these sets (repeatable)
  --concurrency <n>       Parallel scans (default 4)
  --timeout <seconds>     Per-scan timeout (default 120)
  --max-false-alarm-rate <0-1>  Fail if the false-alarm rate is above this
  --min-detection <0-1>   Fail if the detection rate is below this
  --redact                Replace malicious/technique-copy ids with hashes in all outputs`;

function num(name: string, v: string | undefined, min: number, max: number): number | undefined {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) throw new Error(`--${name} must be a number between ${min} and ${max}`);
  return n;
}

async function main(): Promise<number> {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        manifest: { type: 'string', multiple: true },
        scanner: { type: 'string' },
        'scanner-arg': { type: 'string', multiple: true, default: [] },
        out: { type: 'string', default: 'bench-results' },
        baseline: { type: 'string' },
        cutoff: { type: 'string' },
        limit: { type: 'string', default: '0' },
        seed: { type: 'string', default: 'repotrap' },
        set: { type: 'string', multiple: true },
        concurrency: { type: 'string', default: '4' },
        timeout: { type: 'string', default: '120' },
        'max-false-alarm-rate': { type: 'string' },
        'min-detection': { type: 'string' },
        redact: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
    }));
  } catch (e) {
    console.error((e as Error).message);
    console.error(USAGE);
    return 2;
  }
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (!values.manifest?.length || !values.scanner) {
    console.error('--manifest and --scanner are required');
    console.error(USAGE);
    return 2;
  }
  if (values.cutoff !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(values.cutoff)) {
    console.error('--cutoff must be YYYY-MM-DD');
    return 2;
  }

  const limit = num('limit', values.limit, 0, 1e6) ?? 0;
  const concurrency = num('concurrency', values.concurrency, 1, 64) ?? 4;
  const timeoutMs = (num('timeout', values.timeout, 1, 3600) ?? 120) * 1000;
  const maxFalseAlarmRate = num('max-false-alarm-rate', values['max-false-alarm-rate'], 0, 1);
  const minDetection = num('min-detection', values['min-detection'], 0, 1);
  const redact = values.redact ?? false;

  let entries = loadManifests(values.manifest).filter((e) => e.label !== 'unclear');
  if (values.set?.length) {
    const wanted = new Set(values.set);
    entries = entries.filter((e) => wanted.has(e.set));
  }
  const selected = stratifiedSample(entries, limit, values.seed ?? 'repotrap');
  if (selected.length === 0) {
    console.error('No manifest entries selected.');
    return 2;
  }
  console.log(`Scanning ${selected.length} of ${entries.length} entries with concurrency ${concurrency}…`);

  const scannerOpts = { command: values.scanner, args: values['scanner-arg'] ?? [], timeoutMs };
  const results: EntryResult[] = new Array(selected.length);
  let next = 0;
  let done = 0;
  let scannerInfo: { tool: string; version: string } | undefined;
  const worker = async (): Promise<void> => {
    while (next < selected.length) {
      const i = next++;
      const entry = selected[i];
      if (!entry) break;
      const outcome = await runScanner(scannerOpts, targetFor(entry));
      if (outcome.report && !scannerInfo) scannerInfo = { tool: outcome.report.tool, version: outcome.report.version };
      const r = toResult(entry, outcome, redact);
      results[i] = r;
      done++;
      console.log(`[${done}/${selected.length}] ${r.id} → ${r.ok ? `${r.verdict} (${r.score})` : `error: ${r.error}`}`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, selected.length) }, worker));

  const scorecard = buildScorecard(results, {
    cutoff: values.cutoff,
    limit,
    seed: values.seed,
    redacted: redact,
    scanner: scannerInfo,
  });

  const problems = checkGates(scorecard, { maxFalseAlarmRate, minDetection });
  if (values.baseline) {
    if (existsSync(values.baseline)) {
      const base = JSON.parse(readFileSync(values.baseline, 'utf8')) as Scorecard;
      problems.push(...compareScorecards(scorecard, base));
    } else {
      console.log(`Baseline ${values.baseline} not found; skipping comparison.`);
    }
  }

  const outDir = values.out ?? 'bench-results';
  mkdirSync(outDir, { recursive: true });
  const md = renderMarkdown(scorecard, problems);
  writeFileSync(join(outDir, 'scorecard.json'), JSON.stringify(scorecard, null, 2) + '\n');
  writeFileSync(join(outDir, 'scorecard.md'), md);
  writeFileSync(join(outDir, 'results.jsonl'), results.map((r) => JSON.stringify(r)).join('\n') + '\n');
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');

  console.log('\n' + md);
  return problems.length > 0 ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 2;
  },
);
