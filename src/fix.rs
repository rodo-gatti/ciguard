use crate::rules::is_sha;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;

/// Resolves a tag or branch of `owner/repo` to a full commit SHA via the GitHub API.
fn resolve(repo: &str, git_ref: &str) -> Result<String> {
    let url = format!("https://api.github.com/repos/{repo}/commits/{git_ref}");
    let mut req = ureq::get(&url)
        .set("Accept", "application/vnd.github.sha")
        .set("User-Agent", "actionguard");
    if let Ok(t) = std::env::var("GITHUB_TOKEN") {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let sha = req.call().with_context(|| format!("resolving {repo}@{git_ref}"))?
        .into_string()?.trim().to_string();
    if !is_sha(&sha) {
        bail!("unexpected response resolving {repo}@{git_ref}");
    }
    Ok(sha)
}

/// Splits `owner/repo/sub@ref` into (`owner/repo`, ref); None for local/docker/pinned uses.
fn parse(uses: &str) -> Option<(String, String)> {
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return None;
    }
    let (path, r) = uses.split_once('@')?;
    if is_sha(r) {
        return None;
    }
    let repo: Vec<&str> = path.split('/').take(2).collect();
    (repo.len() == 2).then(|| (repo.join("/"), r.to_string()))
}

/// Rewrites unpinned `uses:` lines to `uses: x@<sha> # <ref>`. Returns new text and change count.
pub fn pin_actions(text: &str, resolver: &dyn Fn(&str, &str) -> Result<String>) -> (String, usize) {
    let mut cache: HashMap<(String, String), Option<String>> = HashMap::new();
    let mut changed = 0;
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let body = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let uses = body.strip_prefix("uses:").map(|u| u.split('#').next().unwrap_or("").trim().trim_matches(|c| c == '"' || c == '\''));
        if let Some((repo, r)) = uses.and_then(parse) {
            let sha = cache
                .entry((repo.clone(), r.clone()))
                .or_insert_with(|| resolver(&repo, &r).map_err(|e| eprintln!("warning: {e:#}")).ok())
                .clone();
            if let Some(sha) = sha {
                let old = format!("{}@{r}", uses.unwrap());
                let new = format!("{}@{sha} # {r}", old.split('@').next().unwrap());
                let idx = line.find("uses:").unwrap();
                let (head, _) = line.split_at(idx);
                out.push(format!("{head}uses: {new}"));
                changed += 1;
                continue;
            }
        }
        out.push(line.to_string());
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    (s, changed)
}

pub fn pin_actions_online(text: &str) -> (String, usize) {
    pin_actions(text, &resolve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_tags_and_keeps_formatting() {
        let sha = "b".repeat(40);
        let r = |_: &str, _: &str| Ok(sha.clone());
        let y = "steps:\n  - uses: actions/checkout@v4\n    with:\n      x: 1\n  - uses: ./local\n  - uses: a/b/sub@v1 # note\n";
        let (out, n) = pin_actions(y, &r);
        assert_eq!(n, 2);
        assert!(out.contains(&format!("  - uses: actions/checkout@{sha} # v4\n    with:")));
        assert!(out.contains("uses: ./local"));
        assert!(out.contains(&format!("uses: a/b/sub@{sha} # v1")));
    }
}
