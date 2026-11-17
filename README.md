# repotrap

[![ci](https://github.com/rathinadev/repotrap/actions/workflows/ci.yml/badge.svg)](https://github.com/rathinadev/repotrap/actions/workflows/ci.yml)

repotrap is a static analysis tool that assesses whether a GitHub repository is designed to compromise the people who clone or open it. It inspects a repository before it reaches a developer's machine and reports the techniques attackers use to execute code on open, install or build.

The tool reads files only. It never executes, builds or installs anything from the repository under review.

## Project status

repotrap is in early development. The scanner is not yet implemented. The current repository contains:

- [bench/](bench/): the benchmark harness used to measure detection and false-alarm rates.
- [corpus/](corpus/): the benign evaluation corpus and the manifest format.

## What it detects

| Category | Examples |
|---|---|
| Execution on open, install or build | VS Code `folderOpen` tasks, devcontainer `initializeCommand`, MSBuild build events, npm lifecycle scripts, Gradle and Cargo configuration |
| Obfuscation | Encoded payloads passed to `eval`, invisible Unicode, code hidden beyond the visible line width |
| Network and data theft | Download-and-execute chains, reverse shells, credential and token harvesting, exfiltration endpoints |
| Binaries and files | Executables disguised by extension, password-protected archives, files that leak Windows credentials |
| Workflows and dependencies | Script injection in GitHub Actions, typosquatted and known-malicious dependencies |
| Repository signals | New owner accounts, inflated stars, fake proof-of-concept exploit patterns, lure instructions in README files |
## Planned interfaces

| Interface | Description |
|---|---|
| Web application | Hosted on GitHub Pages. Accepts a repository URL and runs the analysis entirely in the browser. |
| GitHub Action | Checks pull requests, or evaluates an external repository on demand. Reports via job summary and SARIF. |
| Command-line interface | `npx repotrap scan <github-url \| path>` with text, JSON and SARIF output. |
| Claude Code skill | Runs the scan and triages each finding. |

## Limitations

repotrap performs static analysis and can be evaded. A result of "no strong signals" indicates that no known technique was found; it does not establish that a repository is safe.

## Security

This repository contains no malware. Test fixtures are inert strings generated at test time. Samples used for benchmarking are held in isolated, private storage and are never committed.

Please do not submit live malware in issues or pull requests. Reference a public report instead.

## Development

Requires Node.js 24 or later.

```bash
npm test
```

## License

repotrap is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You may use, modify and share it for personal, research, educational and other noncommercial purposes. Commercial use, including selling it, offering it as a paid service, or using it within a for-profit business, is not permitted without a separate commercial license from the maintainer.

This is a source-available license, not an OSI-approved open-source license.
