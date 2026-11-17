# Benchmark harness

Measures repotrap's detection rate and false-alarm rate. Zero dependencies: plain TypeScript run directly by Node 24+.

| File | Purpose |
|---|---|
| `run-bench.ts` | Runs the scanner over manifests, writes `scorecard.json`, `scorecard.md`, `results.jsonl` |
| `build-benign.ts` | Builds `corpus/benign.jsonl` from GitHub search metadata (no repo contents downloaded) |
| `validate-manifest.ts` | Checks manifest files |
| `tricky-benign.json` | Curated legit repos that look risky, plus dual-use security tools |
| `vm/bench-malicious.yml` | Workflow template for the isolated VM's self-hosted runner |
| `lib/` | Manifest validation, scanner runner, sampling, scorecard maths |
| `test/` | Unit tests (`npm test`) |

## Where each part runs

| What | Where | Why |
|---|---|---|
| Unit tests | Anywhere, CI on every push/PR | Only harmless strings |
| Benign benchmark | GitHub-hosted runners (`.github/workflows/bench-benign.yml`) | Ordinary public repos |
| Malicious benchmark | **Isolated VM only**, via a self-hosted runner in a private repo | Real samples never leave the VM |

## Scanner contract

The scanner must accept `<target> --format json`, where the target is either `https://github.com/<owner>/<repo>/tree/<sha>` or a local folder, and print:

```json
{
  "tool": "repotrap",
  "version": "0.1.0",
  "verdict": "no-strong-signals | suspicious | likely-malicious",
  "score": 0,
  "findings": [{ "ruleId": "EXEC-001", "severity": "info | low | medium | high | critical", "file": "…", "line": 1 }]
}
```

Exit code `0` or `1` (findings at or above `--fail-on`) both count as a successful scan. Any other exit code, a timeout, or invalid JSON is recorded as a scan error. The harness never stores scanner stderr, file paths or snippets.

## Metrics

| Metric | Definition | Target |
|---|---|---|
| Detection | `malicious` entries rated suspicious or worse | ≥ 80% |
| Detection after cutoff | Same, only entries with `date_found` ≥ `--cutoff` (time-split test) | ≥ 80% |
| False alarms | `benign-popular` / `-random` / `-tricky` entries with any High or Critical finding | ≤ 5% |
| Rule precision | Malicious hits ÷ (malicious + benign hits), per rule | ≥ 90% once a rule has 5+ hits |
| Technique copies | Every listed technique must fire | 0 misses |

A run fails (exit 1) when a gate is missed or, given `--baseline`, when the false-alarm rate rises by more than 1 point, detection drops by more than 2 points, a technique copy is newly missed, or a rule's precision newly falls below 90%.

## Building the benign corpus

```bash
GITHUB_TOKEN=$(gh auth token) node bench/build-benign.ts
```

About 800 API calls; takes a few minutes. Re-run occasionally to refresh; commit the result.

## Setting up the isolated VM (malicious set)

1. Create a VM with no shared folders, clipboard or drag-and-drop with the host, and a clean snapshot.
2. Install Node 24 and register a self-hosted runner with the label `repotrap-bench-vm` to a **private** repo (e.g. `rathinadev/repotrap-bench`). Never attach it to the public repo.
3. Copy `bench/vm/bench-malicious.yml` into that private repo's `.github/workflows/`.
4. On the VM, put samples under `/srv/repotrap-corpus/samples/` (extracted from `infected`-password zips), and the manifests at `/srv/repotrap-corpus/malicious.jsonl` and `technique-copies.jsonl`.
5. Trigger the workflow from the private repo's Actions tab. Only the redacted scorecard is uploaded.
6. Revert the VM to its snapshot after each session.
