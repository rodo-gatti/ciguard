use crate::rules::{Finding, RULES, Severity};
use anyhow::{Context, Result, bail};
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
                let start = if root.is_dir() {
                    root
                } else {
                    root.parent().unwrap_or_else(|| Path::new("."))
                };
                let Some(p) = start
                    .ancestors()
                    .map(|dir| dir.join(".ciguard.toml"))
                    .find(|path| path.is_file())
                else {
                    return Ok(Config::default());
                };
                p
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let valid = RULES.iter().map(|(rule, _)| *rule).collect::<Vec<_>>();
        let invalid = self
            .disable
            .iter()
            .chain(self.severity.keys())
            .filter(|rule| !valid.contains(&rule.as_str()))
            .collect::<Vec<_>>();
        if invalid.is_empty() {
            return Ok(());
        }

        bail!(
            "unknown rule ID(s): {}; valid rule IDs: {}",
            invalid
                .iter()
                .map(|rule| rule.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            valid.join(", "),
        );
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

/// Returns the YAML comment portion of a line, excluding quoted scalar content.
fn comment(line: &str) -> Option<&str> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some(quote_character) if character == quote_character => quote = None,
            Some(_) => {}
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character == '#'
                && (index == 0
                    || line[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)) =>
            {
                return Some(&line[index..]);
            }
            None => {}
        }
    }
    None
}

fn block_scalar_header(line: &str) -> bool {
    let source = comment(line).map_or(line, |comment| &line[..line.len() - comment.len()]);
    let Some((_, value)) = source.split_once(':') else {
        return false;
    };
    let mut characters = value.trim().chars();
    matches!(characters.next(), Some('|' | '>'))
        && characters.all(|character| matches!(character, '+' | '-' | '1'..='9'))
}

pub(crate) fn is_block_scalar_content(lines: &[&str], target: usize) -> bool {
    let mut header_indent = None;
    for (index, line) in lines.iter().enumerate().take(target + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some(header) = header_indent {
            if indent > header {
                if index == target {
                    return true;
                }
                continue;
            }
            header_indent = None;
        }
        if block_scalar_header(line) {
            header_indent = Some(indent);
        }
    }
    false
}

/// Parses `# ciguard:ignore[-file] [rule[,rule...]]`; returns the rule list (empty = all).
fn directive<'a>(comment: &'a str, tag: &str) -> Option<Vec<&'a str>> {
    let (_, rest) = comment.split_once(tag)?;
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
        .enumerate()
        .filter(|(index, _)| !is_block_scalar_content(&lines, *index))
        .filter_map(|(_, line)| {
            comment(line).and_then(|comment| directive(comment, "ciguard:ignore-file"))
        })
        .flatten()
        .collect();
    let file_all = lines
        .iter()
        .enumerate()
        .filter(|(index, _)| !is_block_scalar_content(&lines, *index))
        .any(|(_, line)| {
            comment(line)
                .and_then(|comment| directive(comment, "ciguard:ignore-file"))
                .is_some_and(|rules| rules.is_empty())
        });

    findings
        .into_iter()
        .filter(|f| {
            if file_all || file_wide.contains(&f.rule) {
                return false;
            }
            let at = |line: usize| {
                line.checked_sub(1)
                    .filter(|index| !is_block_scalar_content(&lines, *index))
                    .and_then(|index| lines.get(index))
                    .and_then(|line| comment(line))
            };
            let same = at(f.line).and_then(|comment| directive(comment, "ciguard:ignore"));
            let above = f
                .line
                .checked_sub(1)
                .and_then(at)
                .filter(|comment| comment.trim_start().starts_with('#'))
                .and_then(|comment| directive(comment, "ciguard:ignore"));
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
        Finding {
            file: "x".into(),
            line,
            rule,
            severity: Severity::Low,
            message: String::new(),
        }
    }

    #[test]
    fn inline_and_file_ignores() {
        let text = "a: 1\n# ciguard:ignore missing-timeout\njob:\nuses: x # ciguard:ignore unpinned-action, outdated-action\nother:\n";
        let out = suppress(
            text,
            vec![
                f("missing-timeout", 3),
                f("missing-timeout", 5),
                f("unpinned-action", 4),
                f("missing-cache", 4),
            ],
        );
        let rules: Vec<_> = out.iter().map(|x| (x.rule, x.line)).collect();
        assert_eq!(rules, vec![("missing-timeout", 5), ("missing-cache", 4)]);

        let out = suppress(
            "# ciguard:ignore-file missing-cache\n",
            vec![f("missing-cache", 9)],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn ignores_are_not_read_from_scalars_or_quoted_values() {
        let text = "run: >-\n  echo ciguard:ignore-file\nname: \"# ciguard:ignore-file\"\nuses: actions/checkout@v4\n";
        let out = suppress(text, vec![f("unpinned-action", 4)]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn inline_ignore_targets_the_reported_occurrence() {
        let text = "uses: actions/checkout@v4\nuses: actions/checkout@v4 # ciguard:ignore unpinned-action\n";
        let out = suppress(text, vec![f("unpinned-action", 1), f("unpinned-action", 2)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].line, 1);
    }

    #[test]
    fn config_disable_and_severity() {
        let c: Config =
            toml::from_str("disable=[\"missing-cache\"]\n[severity]\nmissing-timeout=\"high\"\n")
                .unwrap();
        c.validate().unwrap();
        let out = c.apply(vec![f("missing-cache", 1), f("missing-timeout", 1)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn rejects_unknown_rule_ids() {
        let c: Config =
            toml::from_str("disable=[\"missing-cahce\"]\n[severity]\nunknown=\"high\"\n").unwrap();
        let error = c.validate().unwrap_err().to_string();
        assert!(error.contains("missing-cahce"));
        assert!(error.contains("unknown"));
    }
}
