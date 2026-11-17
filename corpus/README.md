# Corpus manifests

The benchmark measures repotrap against two kinds of repos. Each is listed in a JSONL manifest: one JSON object per line.

| File | Where it lives | Contents |
|---|---|---|
| `corpus/benign.jsonl` | This public repo | Ordinary and "tricky but legitimate" repos, pinned to commits. Built by `bench/build-benign.ts` from GitHub metadata only. |
| `malicious.jsonl` | **Isolated VM only** | Real trap repos from public reports and live hunting. Never committed here. |
| `technique-copies.jsonl` | **Isolated VM only** (for now) | Harmless rebuilds of each technique, used as regression tests. |

`malicious.example.jsonl` in this folder shows the format with made-up values.

## Entry format

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique, lowercase: letters, digits, `. _ : / -` (e.g. `popular/facebook/react`) |
| `label` | yes | `malicious`, `benign` or `unclear` (unclear entries are skipped) |
| `set` | yes | `benign-popular`, `benign-random`, `benign-tricky`, `benign-dualuse`, `malicious`, `technique-copy` |
| `url` + `commit` | one target | `https://github.com/<owner>/<repo>` and the full 40-character SHA |
| `path` | one target | Local folder — **VM only** |
| `techniques` | for malicious / copies | Rule IDs the repo uses, e.g. `["EXEC-001","BIN-002"]` |
| `source` | recommended | Link to the report or how it was found |
| `labelled_by` | recommended | Who labelled it; malicious entries need two people |
| `date_found` | recommended | `YYYY-MM-DD`; used for the time-split detection test |
| `notes` | optional | Free text |

Validate with:

```bash
node bench/validate-manifest.ts corpus/benign.jsonl
```

## Sets and how they are scored

| Set | Counts toward | Notes |
|---|---|---|
| `benign-popular` | False-alarm rate | Top repos by stars, 7 languages |
| `benign-random` | False-alarm rate | Ordinary active repos; keeps the rate honest. **Presumed** benign: low-star repos can themselves be traps, so every High/Critical hit here is reviewed and relabelled (`malicious` or `unclear`) if needed |
| `benign-tricky` | False-alarm rate | Legit repos that use risky-looking features (postinstall, curl-pipe installers, devcontainers, MSBuild) |
| `benign-dualuse` | Reported separately | Security tools (Metasploit, YARA rule sets). Flagging them is expected, not a false alarm |
| `malicious` | Detection rate | Real traps |
| `technique-copy` | Regression gate | Any miss fails the run; never counted in the detection rate |

## Safety rules

- Real malicious samples and their manifest **never** go into this repo, onto a workstation, or onto GitHub-hosted runners.
- They are stored encrypted, as zips with the password `infected`, and only extracted inside the isolated VM.
- Do not open issues or PRs containing malware. Link to a public report instead.
