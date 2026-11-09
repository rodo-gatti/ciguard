use crate::rules::{Finding, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Loaded from `.ciguard.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Rule ids to turn off entirely.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Per-rule severity overrides, e.g. `missing-timeout = "medium"`.
    #[serde(default)]
    pub severity: HashMap<String, Severity>,
}

impl Config {
    pub fn load(explicit: Option<&Path>, root: &Path) -> Result<Config> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let dir = if root.is_dir() { root } else { Path::new(".") };
                let p = dir.join(".ciguard.toml");
                if !p.exists() {
                    return Ok(Config::default());
                }
                p
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn apply(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| !self.disable.iter().any(|d| d == f.rule))
            .map(|mut f| {
                if let Some(s) = self.severity.get(f.rule) {
                    f.severity = *s;
                }
                f
            })
            .collect()
    }
}

/// Parses `# ciguard:ignore[-file] [rule[,rule...]]`; returns the rule list (empty = all).
fn directive<'a>(line: &'a str, tag: &str) -> Option<Vec<&'a str>> {
    let (_, rest) = line.split_once(tag)?;
    Some(
        rest.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn covers(rules: &[&str], rule: &str) -> bool {
    rules.is_empty() || rules.contains(&rule)
}

/// Drops findings silenced by inline comments: on the same line, on a comment-only
/// line directly above, or file-wide via `# ciguard:ignore-file`.
pub fn suppress(text: &str, findings: Vec<Finding>) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().collect();
    let file_wide: Vec<&str> = lines
        .iter()
        .filter_map(|l| directive(l, "ciguard:ignore-file"))
        .flatten()
        .collect();
    let file_all = lines.iter().any(|l| {
        directive(l, "ciguard:ignore-file").is_some_and(|r| r.is_empty())
    });

    findings
        .into_iter()
        .filter(|f| {
            if file_all || file_wide.contains(&f.rule) {
                return false;
            }
            let at = |i: usize| lines.get(i.wrapping_sub(1)).copied();
            let same = at(f.line).and_then(|l| directive(l, "ciguard:ignore"));
            let above = at(f.line.wrapping_sub(1))
                .filter(|l| l.trim_start().starts_with('#'))
                .and_then(|l| directive(l, "ciguard:ignore"));
            ![same, above]
                .into_iter()
                .flatten()
                .any(|r| covers(&r, f.rule))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &'static str, line: usize) -> Finding {
        Finding { file: "x".into(), line, rule, severity: Severity::Low, message: String::new() }
    }

    #[test]
    fn inline_and_file_ignores() {
        let text = "a: 1\n# ciguard:ignore missing-timeout\njob:\nuses: x # ciguard:ignore unpinned-action, outdated-action\nother:\n";
        let out = suppress(text, vec![
            f("missing-timeout", 3),
            f("missing-timeout", 5),
            f("unpinned-action", 4),
            f("missing-cache", 4),
        ]);
        let rules: Vec<_> = out.iter().map(|x| (x.rule, x.line)).collect();
        assert_eq!(rules, vec![("missing-timeout", 5), ("missing-cache", 4)]);

        let out = suppress("# ciguard:ignore-file missing-cache\n", vec![f("missing-cache", 9)]);
        assert!(out.is_empty());
    }

    #[test]
    fn config_disable_and_severity() {
        let c: Config = toml::from_str("disable=[\"a\"]\n[severity]\nmissing-timeout=\"high\"\n").unwrap();
        let out = c.apply(vec![f("a", 1), f("missing-timeout", 1)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }
}
