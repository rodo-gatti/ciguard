# ciguard

Fast Rust CLI that audits GitHub Actions workflows for **security** and **CI-cost** problems.

## Install

```sh
cargo install ciguard   # or: cargo install --path .
```

## Usage

```sh
ciguard                          # scan ./.github/workflows
ciguard path/to/repo --format sarif > results.sarif
ciguard --fail-on medium         # CI gate (exit 1 on findings >= severity)
ciguard --fix                    # pin tag-referenced actions to commit SHAs
```

`--fix` queries the GitHub API (set `GITHUB_TOKEN` to avoid rate limits) and rewrites
`uses: actions/checkout@v4` to `uses: actions/checkout@<sha> # v4`.

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` error.

## Rules

| Rule | Severity | What it catches |
|---|---|---|
| `unpinned-action` | high | `uses:` not pinned to a full commit SHA |
| `script-injection` | high | untrusted `github.event.*` values interpolated in `run:` |
| `pwn-request` | high | `pull_request_target` checking out the PR head |
| `missing-permissions` | medium | no top-level `permissions` |
| `missing-timeout` | low | job without `timeout-minutes` |
| `missing-concurrency` | low | push/PR workflows without `concurrency` |
| `missing-cache` | low | `setup-node/python/java` without `cache` |
| `expensive-runner` | low | macOS/Windows runners (billed at a multiple of Linux) |
| `write-all-permissions` | high | `permissions: write-all` at workflow or job level |
| `secrets-inherit` | medium | reusable workflow called with `secrets: inherit` |
| `workflow-run-checkout` | high | `workflow_run` workflow checking out the triggering branch |
| `outdated-action` | medium | deprecated action versions (e.g. `upload-artifact@v3`); also reads `# vN` comments next to pinned SHAs |
| `deprecated-command` | medium | removed commands such as `::set-output` |

## Configuration

Create `.ciguard.toml` in the scanned directory (or pass `--config`):

```toml
disable = ["missing-timeout"]      # turn rules off

[severity]                         # override severities
missing-cache = "medium"
```

Suppress individual findings inline, on the same line or a comment line directly above:

```yaml
- uses: actions/checkout@v4  # ciguard:ignore unpinned-action
# ciguard:ignore missing-timeout, expensive-runner
build:
```

Use `# ciguard:ignore-file [rule,...]` anywhere in a file to silence rules for the whole file.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: rodo-gatti/ciguard@main
    with:
      fail-on: high
```

Results are uploaded to GitHub code scanning as SARIF.

## License

MIT
