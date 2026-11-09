# actionguard

Fast Rust CLI that audits GitHub Actions workflows for **security** and **CI-cost** problems.

## Install

```sh
cargo install actionguard   # or: cargo install --path .
```

## Usage

```sh
actionguard                          # scan ./.github/workflows
actionguard path/to/repo --format sarif > results.sarif
actionguard --fail-on medium         # CI gate (exit 1 on findings >= severity)
actionguard --fix                    # pin tag-referenced actions to commit SHAs
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

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: rodo-gatti/actionguard@main
    with:
      fail-on: high
```

Results are uploaded to GitHub code scanning as SARIF.

## License

MIT
