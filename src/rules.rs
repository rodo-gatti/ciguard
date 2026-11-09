use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use serde_yaml::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
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
    ("unpinned-action", "Action is not pinned to a full commit SHA"),
    ("script-injection", "Untrusted event data interpolated into a shell script"),
    ("pwn-request", "pull_request_target checks out untrusted PR code"),
    ("missing-permissions", "Workflow does not restrict GITHUB_TOKEN permissions"),
    ("missing-timeout", "Job has no timeout-minutes"),
    ("missing-concurrency", "Workflow can run redundant parallel runs"),
    ("missing-cache", "Dependency setup action without caching"),
    ("expensive-runner", "macOS/Windows runner costs more per minute"),
];

const UNTRUSTED: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.head_commit.message",
];

const CACHEABLE: &[&str] = &["actions/setup-node", "actions/setup-python", "actions/setup-java"];

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

pub fn analyze(file: &str, text: &str) -> Result<Vec<Finding>> {
    let doc: Value = serde_yaml::from_str(text).with_context(|| format!("parsing {file}"))?;
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut add = |rule, severity, line, message: String| {
        out.push(Finding { file: file.to_string(), line, rule, severity, message })
    };

    // Some YAML parsers read the `on` key as boolean true; accept both.
    let on = doc.get("on").or_else(|| doc.get(Value::Bool(true)));
    let prt = has_trigger(on, "pull_request_target");

    if doc.get("permissions").is_none() {
        add("missing-permissions", Severity::Medium, 1,
            "no top-level `permissions`; token defaults may be overly broad".into());
    }
    if doc.get("concurrency").is_none()
        && (has_trigger(on, "pull_request") || has_trigger(on, "push"))
    {
        add("missing-concurrency", Severity::Low, 1,
            "no `concurrency` group; superseded runs keep consuming minutes".into());
    }

    let Some(jobs) = doc.get("jobs").and_then(Value::as_mapping) else {
        return Ok(out);
    };
    let jobs_line = locate(&lines, "jobs:", 0).saturating_sub(1);
    for (name, job) in jobs {
        let name = name.as_str().unwrap_or("?");
        let job_line = locate(&lines, &format!("{name}:"), jobs_line);
        let next = job_line.max(1) - 1;

        if job.get("timeout-minutes").is_none() && job.get("uses").is_none() {
            add("missing-timeout", Severity::Low, job_line,
                format!("job `{name}` has no timeout-minutes (default 360 min can waste CI spend)"));
        }
        let runner = job.get("runs-on").and_then(Value::as_str).unwrap_or("");
        if runner.starts_with("macos") || runner.starts_with("windows") {
            add("expensive-runner", Severity::Low, locate(&lines, "runs-on", next),
                format!("job `{name}` runs on `{runner}` (billed at a multiple of Linux)"));
        }
        let Some(steps) = job.get("steps").and_then(Value::as_sequence) else { continue };
        for step in steps {
            if let Some(uses) = step.get("uses").and_then(Value::as_str) {
                let line = locate(&lines, uses, next);
                if !uses.starts_with("./") && !uses.starts_with("docker://") {
                    let r = uses.split_once('@').map(|x| x.1).unwrap_or("");
                    if !is_sha(r) {
                        add("unpinned-action", Severity::High, line,
                            format!("job `{name}`: `{uses}` is not pinned to a commit SHA"));
                    }
                }
                if prt && uses.starts_with("actions/checkout") {
                    let head = step.get("with").and_then(|w| w.get("ref")).and_then(Value::as_str)
                        .is_some_and(|r| r.contains("pull_request.head"));
                    if head {
                        add("pwn-request", Severity::High, line,
                            format!("job `{name}`: pull_request_target checks out untrusted PR head"));
                    }
                }
                let action = uses.split('@').next().unwrap_or("");
                if CACHEABLE.contains(&action)
                    && step.get("with").and_then(|w| w.get("cache")).is_none()
                {
                    add("missing-cache", Severity::Low, line,
                        format!("job `{name}`: `{action}` without `cache`; dependencies are re-downloaded every run"));
                }
            }
            if let Some(run) = step.get("run").and_then(Value::as_str)
                && let Some(bad) = UNTRUSTED.iter().find(|u| run.contains(*u))
            {
                add("script-injection", Severity::High, locate(&lines, bad, next),
                    format!("job `{name}`: `{bad}` interpolated into `run`; pass via env instead"));
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
        for want in ["missing-permissions", "missing-timeout", "unpinned-action", "pwn-request", "script-injection"] {
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
    fn clean_workflow_has_no_findings() {
        let sha = "a".repeat(40);
        let y = format!("on: push\npermissions: read-all\nconcurrency: x\njobs:\n  a:\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n");
        assert!(names(&y).is_empty());
    }
}
