# ciguard

Fast Rust CLI that checks GitHub Actions workflows for common **security** and
**CI-cost** problems.

ciguard is a static heuristic checker, not a complete security audit. Treat its
findings as review input and continue to review workflow changes, permissions,
and third-party action provenance.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/rodo-gatti/ciguard/releases), verify it against `SHA256SUMS`, and put the `ciguard` binary on your `PATH`.

The crate is not published to crates.io yet. For a local development install:

```sh
cargo install --path .
```

## Example

```console
$ ciguard examples/vulnerable.yml
[Medium] examples/vulnerable.yml:1 missing-permissions - no `permissions` at workflow level or on every job; token defaults may be overly broad
[Low] examples/vulnerable.yml:4 missing-timeout - job `build` has no timeout-minutes (default 360 min can waste CI spend)
[Low] examples/vulnerable.yml:5 expensive-runner - job `build` runs on `macos-latest` (billed at a multiple of Linux)
[High] examples/vulnerable.yml:7 unpinned-action - job `build`: `actions/checkout@v3` is not pinned to a commit SHA
[Medium] examples/vulnerable.yml:7 outdated-action - job `build`: `actions/checkout` v3 is deprecated; use v4 or newer
[High] examples/vulnerable.yml:7 pwn-request - job `build`: pull_request_target checks out untrusted PR head
[High] examples/vulnerable.yml:10 script-injection - job `build`: `github.event.pull_request.title` interpolated into `run`; pass via env instead
7 finding(s)
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
It makes no changes if any action reference cannot be resolved.

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` error.

The supported minimum Rust version is 1.85.0. CI tests the current stable toolchain;
release builds use Rust 1.85.0 for reproducibility.

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

Create `.ciguard.toml` in the scanned directory (or pass `--config`). When scanning a
single workflow file, ciguard searches its parent directories and uses the nearest config:

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

Use `# ciguard:ignore-file [rule,...]` in a YAML comment to silence rules for the
whole file. Directives inside quoted or block-scalar values are ignored.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: rodo-gatti/ciguard@<full-commit-sha>
    with:
      fail-on: high
```

Replace `<full-commit-sha>` with an audited immutable release commit. Do not use a
branch or mutable tag. Results are uploaded to GitHub code scanning as SARIF. The
action installs Rust 1.85.0 itself; self-hosted runners need outbound access to
GitHub and crates.io while it builds ciguard, plus a Bash-capable shell.

## License

MIT
