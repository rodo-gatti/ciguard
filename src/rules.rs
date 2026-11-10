use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub file: String,
    /// 1-based line, or 0 when it could not be located
    pub line: usize,
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
}

pub const RULES: &[(&str, &str)] = &[
    (
        "unpinned-action",
        "Action is not pinned to a full commit SHA",
    ),
    (
        "script-injection",
        "Untrusted event data interpolated into a shell script",
    ),
    (
        "pwn-request",
        "pull_request_target checks out untrusted PR code",
    ),
    (
        "missing-permissions",
        "Workflow does not restrict GITHUB_TOKEN permissions",
    ),
    ("missing-timeout", "Job has no timeout-minutes"),
    (
        "missing-concurrency",
        "Workflow can run redundant parallel runs",
    ),
    ("missing-cache", "Dependency setup action without caching"),
    (
        "expensive-runner",
        "macOS/Windows runner costs more per minute",
    ),
    (
        "write-all-permissions",
        "GITHUB_TOKEN granted write-all permissions",
    ),
    (
        "secrets-inherit",
        "Reusable workflow receives every secret via `secrets: inherit`",
    ),
    (
        "workflow-run-checkout",
        "workflow_run workflow checks out untrusted code",
    ),
    (
        "outdated-action",
        "Action version is deprecated or runs on an unsupported Node runtime",
    ),
    (
        "deprecated-command",
        "Uses removed workflow commands such as ::set-output",
    ),
];

/// (action, first supported major version)
const MIN_MAJOR: &[(&str, u32)] = &[
    ("actions/checkout", 4),
    ("actions/upload-artifact", 4),
    ("actions/download-artifact", 4),
    ("actions/cache", 4),
    ("actions/setup-node", 4),
    ("actions/setup-python", 5),
    ("actions/setup-go", 5),
    ("actions/setup-java", 4),
    ("actions/github-script", 7),
    ("docker/build-push-action", 5),
    ("docker/login-action", 3),
    ("docker/setup-buildx-action", 3),
    ("github/codeql-action/init", 3),
    ("github/codeql-action/analyze", 3),
];

const DEPRECATED_COMMANDS: &[&str] = &["::set-output", "::save-state", "::set-env", "::add-path"];

const CACHEABLE: &[&str] = &[
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-java",
];

pub fn is_sha(r: &str) -> bool {
    r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())
}

/// Finds the 1-based line containing `needle`, searching from 0-based line `from`.
fn locate(lines: &[&str], needle: &str, from: usize) -> usize {
    lines
        .iter()
        .enumerate()
        .skip(from)
        .find(|(_, l)| l.contains(needle))
        .map(|(i, _)| i + 1)
        .unwrap_or(0)
}

fn has_trigger(on: Option<&Value>, name: &str) -> bool {
    on.is_some_and(|o| match o {
        Value::String(s) => s == name,
        Value::Sequence(s) => s.iter().any(|x| x.as_str() == Some(name)),
        Value::Mapping(_) => o.get(name).is_some(),
        _ => false,
    })
}

/// Parses the major version out of `v4`, `v4.1.2` or `4`.
fn major(r: &str) -> Option<u32> {
    r.trim_start_matches('v').split('.').next()?.parse().ok()
}

/// Version for an action ref: the tag itself, or the `# vN` comment next to a pinned SHA.
fn version_of(r: &str, line: &str) -> Option<u32> {
    if is_sha(r) {
        let (_, c) = line.split_once('#')?;
        major(c.split_whitespace().next()?)
    } else {
        major(r)
    }
}

fn is_write_all(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str) == Some("write-all")
}

fn is_untrusted_pr_ref(ref_: &str) -> bool {
    [
        "github.head_ref",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.sha",
    ]
    .iter()
    .any(|marker| ref_.contains(marker))
}

/// Direct interpolation of any event payload is unsafe in shell and script source.
fn untrusted_expression(source: &str) -> Option<&str> {
    if source.contains("github.event.") {
        Some("github.event.")
    } else if source.contains("github.head_ref") {
        Some("github.head_ref")
    } else {
        None
    }
}

pub fn analyze(file: &str, text: &str) -> Result<Vec<Finding>> {
    let doc: Value = serde_yaml::from_str(text).with_context(|| format!("parsing {file}"))?;
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut add = |rule, severity, line, message: String| {
        out.push(Finding {
            file: file.to_string(),
            line,
            rule,
            severity,
            message,
        })
    };

    // Some YAML parsers read the `on` key as boolean true; accept both.
    let on = doc.get("on").or_else(|| doc.get(Value::Bool(true)));
    let prt = has_trigger(on, "pull_request_target");
    let wr = has_trigger(on, "workflow_run");

    let jobs = doc.get("jobs").and_then(Value::as_mapping);
    let jobs_all_scoped = jobs
        .is_some_and(|j| !j.is_empty() && j.values().all(|job| job.get("permissions").is_some()));
    if doc.get("permissions").is_none() && !jobs_all_scoped {
        add("missing-permissions", Severity::Medium, 1,
            "no `permissions` at workflow level or on every job; token defaults may be overly broad".into());
    }
    if is_write_all(doc.get("permissions")) {
        add(
            "write-all-permissions",
            Severity::High,
            locate(&lines, "write-all", 0),
            "workflow grants `write-all` to GITHUB_TOKEN; list only the scopes needed".into(),
        );
    }
    if doc.get("concurrency").is_none()
        && (has_trigger(on, "pull_request") || has_trigger(on, "push"))
    {
        add(
            "missing-concurrency",
            Severity::Low,
            1,
            "no `concurrency` group; superseded runs keep consuming minutes".into(),
        );
    }

    let Some(jobs) = jobs else {
        return Ok(out);
    };
    let jobs_line = locate(&lines, "jobs:", 0).saturating_sub(1);
    for (name, job) in jobs {
        let name = name.as_str().unwrap_or("?");
        let job_line = locate(&lines, &format!("{name}:"), jobs_line);
        let next = job_line.max(1) - 1;

        if is_write_all(job.get("permissions")) {
            add(
                "write-all-permissions",
                Severity::High,
                locate(&lines, "write-all", next),
                format!(
                    "job `{name}` grants `write-all` to GITHUB_TOKEN; list only the scopes needed"
                ),
            );
        }
        if job.get("secrets").and_then(Value::as_str) == Some("inherit") {
            add(
                "secrets-inherit",
                Severity::Medium,
                locate(&lines, "inherit", next),
                format!(
                    "job `{name}` passes all secrets with `secrets: inherit`; pass only what the callee needs"
                ),
            );
        }
        if job.get("timeout-minutes").is_none() && job.get("uses").is_none() {
            add(
                "missing-timeout",
                Severity::Low,
                job_line,
                format!("job `{name}` has no timeout-minutes (default 360 min can waste CI spend)"),
            );
        }
        if let Some(uses) = job.get("uses").and_then(Value::as_str) {
            let line = locate(&lines, uses, next);
            let (_, r) = uses.split_once('@').unwrap_or((uses, ""));
            if !uses.starts_with("./") && !is_sha(r) {
                add(
                    "unpinned-action",
                    Severity::High,
                    line,
                    format!("job `{name}`: `{uses}` is not pinned to a commit SHA"),
                );
            }
        }
        let runner = job.get("runs-on").and_then(Value::as_str).unwrap_or("");
        if runner.starts_with("macos") || runner.starts_with("windows") {
            add(
                "expensive-runner",
                Severity::Low,
                locate(&lines, "runs-on", next),
                format!("job `{name}` runs on `{runner}` (billed at a multiple of Linux)"),
            );
        }
        let Some(steps) = job.get("steps").and_then(Value::as_sequence) else {
            continue;
        };
        let uses_of = |s: &Value| s.get("uses").and_then(Value::as_str).map(str::to_lowercase);
        let job_caches = steps
            .iter()
            .filter_map(uses_of)
            .any(|u| u.contains("cache"));
        let mut step_from = next;
        for step in steps {
            let step_line = step
                .get("uses")
                .and_then(Value::as_str)
                .map(|uses| locate(&lines, uses, step_from))
                .or_else(|| {
                    step.get("run")
                        .and_then(Value::as_str)
                        .map(|_| locate(&lines, "run:", step_from))
                })
                .unwrap_or(0);
            if step_line > 0 {
                step_from = step_line;
            }

            if let Some(uses) = step.get("uses").and_then(Value::as_str) {
                let line = step_line;
                let (action, r) = uses.split_once('@').unwrap_or((uses, ""));
                if !uses.starts_with("./") && !uses.starts_with("docker://") {
                    if !is_sha(r) {
                        add(
                            "unpinned-action",
                            Severity::High,
                            line,
                            format!("job `{name}`: `{uses}` is not pinned to a commit SHA"),
                        );
                    }
                    let line_text = lines.get(line.wrapping_sub(1)).copied().unwrap_or("");
                    if let Some(min) = MIN_MAJOR.iter().find(|(a, _)| *a == action).map(|x| x.1)
                        && let Some(v) = version_of(r, line_text)
                        && v < min
                    {
                        add(
                            "outdated-action",
                            Severity::Medium,
                            line,
                            format!(
                                "job `{name}`: `{action}` v{v} is deprecated; use v{min} or newer"
                            ),
                        );
                    }
                }
                if action == "actions/checkout" {
                    let checkout_ref = step
                        .get("with")
                        .and_then(|w| w.get("ref"))
                        .and_then(Value::as_str);
                    if prt && checkout_ref.is_some_and(is_untrusted_pr_ref) {
                        add(
                            "pwn-request",
                            Severity::High,
                            line,
                            format!(
                                "job `{name}`: pull_request_target checks out untrusted PR head"
                            ),
                        );
                    }
                    if wr && checkout_ref.is_some_and(|r| r.contains("workflow_run.head")) {
                        add(
                            "workflow-run-checkout",
                            Severity::High,
                            line,
                            format!(
                                "job `{name}`: workflow_run checks out the triggering (possibly fork) branch with elevated privileges"
                            ),
                        );
                    }
                }
                if CACHEABLE.contains(&action)
                    && !job_caches
                    && step.get("with").and_then(|w| w.get("cache")).is_none()
                {
                    add(
                        "missing-cache",
                        Severity::Low,
                        line,
                        format!(
                            "job `{name}`: `{action}` without `cache`; dependencies are re-downloaded every run"
                        ),
                    );
                }
                if action == "actions/github-script"
                    && let Some(script) = step
                        .get("with")
                        .and_then(|w| w.get("script"))
                        .and_then(Value::as_str)
                    && let Some(bad) = untrusted_expression(script)
                {
                    add(
                        "script-injection",
                        Severity::High,
                        locate(&lines, bad, step_line.saturating_sub(1)),
                        format!(
                            "job `{name}`: `{bad}` interpolated into github-script; read it from `context` instead"
                        ),
                    );
                }
            }
            if let Some(run) = step.get("run").and_then(Value::as_str) {
                if let Some(bad) = untrusted_expression(run) {
                    add(
                        "script-injection",
                        Severity::High,
                        locate(&lines, bad, step_line.saturating_sub(1)),
                        format!(
                            "job `{name}`: `{bad}` interpolated into `run`; pass via env instead"
                        ),
                    );
                }
                if let Some(cmd) = DEPRECATED_COMMANDS.iter().find(|c| run.contains(*c)) {
                    add(
                        "deprecated-command",
                        Severity::Medium,
                        locate(&lines, cmd, step_line.saturating_sub(1)),
                        format!(
                            "job `{name}`: `{cmd}` is disabled; write to $GITHUB_OUTPUT / $GITHUB_STATE / $GITHUB_ENV / $GITHUB_PATH"
                        ),
                    );
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(y: &str) -> Vec<Finding> {
        analyze("t.yml", y).unwrap()
    }
    fn names(y: &str) -> Vec<&'static str> {
        found(y).iter().map(|f| f.rule).collect()
    }

    #[test]
    fn flags_common_issues() {
        let r = names(
            "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo ${{ github.event.pull_request.title }}\n",
        );
        for want in [
            "missing-permissions",
            "missing-timeout",
            "unpinned-action",
            "pwn-request",
            "script-injection",
        ] {
            assert!(r.contains(&want), "missing {want}: {r:?}");
        }
    }

    #[test]
    fn reports_line_numbers() {
        let y = "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n";
        let f = found(y);
        let u = f.iter().find(|f| f.rule == "unpinned-action").unwrap();
        assert_eq!(u.line, 5);
    }

    #[test]
    fn cost_rules() {
        let y = "on: push\npermissions: read-all\njobs:\n  a:\n    timeout-minutes: 5\n    runs-on: macos-latest\n    steps:\n      - uses: actions/setup-node@v4\n";
        let r = names(y);
        for want in ["missing-concurrency", "expensive-runner", "missing-cache"] {
            assert!(r.contains(&want), "missing {want}: {r:?}");
        }
    }

    #[test]
    fn new_security_rules() {
        let y = "on:\n  workflow_run:\n    workflows: [x]\npermissions: write-all\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@main\n    secrets: inherit\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n      - run: echo \"::set-output name=a::b\"\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')\n";
        let r = names(y);
        for want in [
            "write-all-permissions",
            "secrets-inherit",
            "workflow-run-checkout",
            "deprecated-command",
            "script-injection",
        ] {
            assert!(r.contains(&want), "missing {want}: {r:?}");
        }
    }

    #[test]
    fn outdated_actions_tag_and_sha_comment() {
        let sha = "c".repeat(40);
        let y = format!(
            "on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@v3\n      - uses: actions/cache@{sha} # v2.1.0\n      - uses: actions/checkout@v4\n"
        );
        let f = found(&y);
        let lines: Vec<_> = f
            .iter()
            .filter(|f| f.rule == "outdated-action")
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, vec![6, 7]);
    }

    #[test]
    fn checks_reusable_workflow_pins() {
        let sha = "a".repeat(40);
        let unpinned = format!(
            "on: workflow_dispatch\njobs:\n  deploy:\n    uses: acme/deploy/.github/workflows/release.yml@main\n  local:\n    uses: ./.github/workflows/local.yml\n  pinned:\n    uses: acme/deploy/.github/workflows/release.yml@{sha}\n"
        );
        let findings = found(&unpinned);
        let pins: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "unpinned-action")
            .collect();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].line, 4);
    }

    #[test]
    fn flags_all_supported_pull_request_head_refs() {
        for reference in [
            "github.head_ref",
            "github.event.pull_request.head.ref",
            "github.event.pull_request.head.sha",
        ] {
            let y = format!(
                "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{}\n        with:\n          ref: ${{{{ {reference} }}}}\n",
                "a".repeat(40)
            );
            assert!(
                names(&y).contains(&"pwn-request"),
                "missing pwn-request for {reference}"
            );
        }
    }

    #[test]
    fn reports_repeated_steps_at_their_own_lines() {
        let y = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n";
        let lines: Vec<_> = found(y)
            .iter()
            .filter(|f| f.rule == "unpinned-action")
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, vec![6, 7]);
    }

    #[test]
    fn flags_all_direct_event_expressions_in_shell_source() {
        let y = "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.labels.*.name }}\"\n";
        assert!(names(y).contains(&"script-injection"));
    }

    #[test]
    fn noise_reduction() {
        let y = "on: workflow_dispatch\njobs:\n  a:\n    permissions: read-all\n    timeout-minutes: 5\n    runs-on: ubuntu-latest\n    steps:\n      - uses: Swatinem/rust-cache@v2\n      - uses: actions/setup-node@v4\n";
        let r = names(y);
        assert!(!r.contains(&"missing-permissions"));
        assert!(!r.contains(&"missing-cache"));
    }

    #[test]
    fn clean_workflow_has_no_findings() {
        let sha = "a".repeat(40);
        let y = format!(
            "on: push\npermissions: read-all\nconcurrency: x\njobs:\n  a:\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"
        );
        assert!(names(&y).is_empty());
    }
}
