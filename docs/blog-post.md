# I scanned popular open-source repos' CI pipelines. Here's what I found.

*Draft — re-run the scans before publishing; numbers are from shallow clones on the day of scanning.*

GitHub Actions workflows run with access to your secrets and your repo. Yet most pin third-party
actions to mutable tags, so a compromised tag (as in the `tj-actions/changed-files` incident)
runs attacker code in your pipeline.

I built [actionguard](https://github.com/rodo-gatti/actionguard), a Rust CLI that checks workflows
for security and cost problems, and ran it on a few well-known projects:

| Repo | unpinned actions | jobs without timeout | missing cache | expensive runners |
|---|---|---|---|---|
| tokio-rs/tokio | 183 | 55 | 1 | 0 |
| astral-sh/ruff | 46 | 45 | 10 | 3 |
| BurntSushi/ripgrep | 18 | 9 | 0 | 0 |
| denoland/deno | 0 | 10 | 23 | 11 |

## What it checks
Unpinned actions, script injection via `github.event.*`, `pull_request_target` "pwn requests",
missing `permissions`, and cost smells: no `timeout-minutes` (default 6 hours), no `concurrency`,
no dependency caching, and macOS/Windows runners.

## Why Rust
Single static binary, fast scans, SARIF output for GitHub code scanning, and `--fix` to pin
every action to a SHA automatically.

## Try it
```sh
cargo install actionguard
actionguard --fix
```

*Note: these are hygiene findings, not vulnerabilities. Don't open noisy issues; send small,
helpful PRs instead.*
