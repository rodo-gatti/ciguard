use crate::{config::is_block_scalar_content, rules::is_sha};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Resolves a tag or branch of `owner/repo` to a full commit SHA via the GitHub API.
fn resolve(repo: &str, git_ref: &str) -> Result<String> {
    let url = format!("https://api.github.com/repos/{repo}/commits/{git_ref}");
    let mut req = ureq::get(&url)
        .set("Accept", "application/vnd.github.sha")
        .set("User-Agent", "ciguard");
    if let Ok(t) = std::env::var("GITHUB_TOKEN") {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let sha = req
        .call()
        .with_context(|| format!("resolving {repo}@{git_ref}"))?
        .into_string()?
        .trim()
        .to_string();
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
pub fn pin_actions(
    text: &str,
    resolver: &dyn Fn(&str, &str) -> Result<String>,
) -> Result<(String, usize)> {
    let mut cache: HashMap<(String, String), String> = HashMap::new();
    let mut changed = 0;
    let mut out: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.split('\n').collect();
    for (index, raw_line) in lines.iter().enumerate() {
        let raw_line = *raw_line;
        if is_block_scalar_content(&lines, index) {
            out.push(raw_line.to_string());
            continue;
        }
        let (line, ending) = raw_line
            .strip_suffix('\r')
            .map_or((raw_line, ""), |line| (line, "\r"));
        let trimmed = line.trim_start();
        let body = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let value = body.strip_prefix("uses:");
        let uses = value.map(|u| {
            u.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
        });
        if let Some((repo, r)) = uses.and_then(parse) {
            let sha = match cache.get(&(repo.clone(), r.clone())) {
                Some(sha) => sha.clone(),
                None => {
                    let sha =
                        resolver(&repo, &r).with_context(|| format!("resolving {repo}@{r}"))?;
                    if !is_sha(&sha) {
                        bail!("resolver returned an invalid SHA for {repo}@{r}");
                    }
                    cache.insert((repo.clone(), r.clone()), sha.clone());
                    sha
                }
            };
            let action = uses.unwrap().split_once('@').unwrap().0;
            let existing_comment = value
                .and_then(|u| u.split_once('#').map(|(_, comment)| comment.trim()))
                .filter(|comment| !comment.is_empty());
            let mut new = format!("{action}@{sha} # {r}");
            if let Some(comment) = existing_comment {
                new.push_str(" # ");
                new.push_str(comment);
            }
            let idx = line.find("uses:").unwrap();
            let (head, _) = line.split_at(idx);
            out.push(format!("{head}uses: {new}{ending}"));
            changed += 1;
            continue;
        }
        out.push(raw_line.to_string());
    }
    Ok((out.join("\n"), changed))
}

pub fn pin_actions_online(text: &str) -> Result<(String, usize)> {
    pin_actions(text, &resolve)
}

/// Replaces files only after all replacement data and rollback links are prepared.
pub fn replace_files_atomically(files: &[(PathBuf, String)]) -> Result<()> {
    replace_files_atomically_with(files, |from, to| fs::rename(from, to))
}

fn replace_files_atomically_with<F>(files: &[(PathBuf, String)], mut rename: F) -> Result<()>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    let mut staged = Vec::with_capacity(files.len());
    for (target, contents) in files {
        let metadata = match fs::metadata(target)
            .with_context(|| format!("reading metadata for {}", target.display()))
        {
            Ok(metadata) => metadata,
            Err(error) => return Err(after_cleanup(error, &staged, true)),
        };
        let replacement = match create_temporary_file(target, "replacement") {
            Ok(replacement) => replacement,
            Err(error) => return Err(after_cleanup(error, &staged, true)),
        };
        let file = StagedFile {
            target: target.clone(),
            replacement,
            backup: match temporary_path(target, "backup") {
                Ok(backup) => backup,
                Err(error) => return Err(after_cleanup(error, &staged, true)),
            },
            backup_created: false,
        };
        if let Err(error) = write_replacement(&file.replacement, contents, &metadata.permissions())
            .with_context(|| format!("preparing replacement for {}", target.display()))
        {
            staged.push(file);
            return Err(after_cleanup(error, &staged, true));
        }
        staged.push(file);
    }

    for file in &mut staged {
        if let Err(error) = fs::hard_link(&file.target, &file.backup)
            .with_context(|| format!("creating rollback copy for {}", file.target.display()))
        {
            return Err(after_cleanup(error, &staged, true));
        }
        file.backup_created = true;
    }

    for (index, file) in staged.iter().enumerate() {
        if let Err(error) = rename(&file.replacement, &file.target) {
            return match rollback(&staged[..index], &mut rename) {
                Ok(()) => Err(after_cleanup(
                    anyhow::Error::from(error).context(format!(
                        "replacing {} failed; all prior files were restored",
                        file.target.display()
                    )),
                    &staged,
                    true,
                )),
                Err(rollback_error) => {
                    let cleanup_error = cleanup_staged(&staged, false).err();
                    let recovery_paths = staged
                        .iter()
                        .filter(|file| file.backup_created)
                        .map(|file| file.backup.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let mut error = anyhow::Error::from(error).context(format!(
                        "replacing {} failed and rollback also failed: {rollback_error:#}; \
                         rollback copies were retained at {recovery_paths}",
                        file.target.display()
                    ));
                    if let Some(cleanup_error) = cleanup_error {
                        error = error.context(format!(
                            "also failed to remove replacement files: {cleanup_error:#}"
                        ));
                    }
                    Err(error)
                }
            };
        }
    }

    cleanup_staged(&staged, true)
}

struct StagedFile {
    target: PathBuf,
    replacement: PathBuf,
    backup: PathBuf,
    backup_created: bool,
}

fn write_replacement(path: &Path, contents: &str, permissions: &fs::Permissions) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, permissions.clone())
}

fn create_temporary_file(target: &Path, purpose: &str) -> Result<PathBuf> {
    let path = temporary_path(target, purpose)?;
    File::create_new(&path)
        .with_context(|| format!("creating temporary file {}", path.display()))?;
    Ok(path)
}

fn temporary_path(target: &Path, purpose: &str) -> Result<PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", target.display()))?;
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".ciguard-{purpose}-{}-{sequence}",
        std::process::id()
    )))
}

fn rollback<F>(files: &[StagedFile], rename: &mut F) -> Result<()>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    for file in files.iter().rev() {
        rename(&file.backup, &file.target)
            .with_context(|| format!("restoring {}", file.target.display()))?;
    }
    Ok(())
}

fn after_cleanup(
    error: anyhow::Error,
    files: &[StagedFile],
    remove_backups: bool,
) -> anyhow::Error {
    match cleanup_staged(files, remove_backups) {
        Ok(()) => error,
        Err(cleanup_error) => error.context(format!(
            "also failed to clean up temporary files: {cleanup_error:#}"
        )),
    }
}

fn cleanup_staged(files: &[StagedFile], remove_backups: bool) -> Result<()> {
    for file in files {
        remove_if_exists(&file.replacement)
            .with_context(|| format!("removing replacement file for {}", file.target.display()))?;
        if remove_backups && file.backup_created {
            remove_if_exists(&file.backup)
                .with_context(|| format!("removing rollback copy for {}", file.target.display()))?;
        }
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_tags_and_keeps_formatting() {
        let sha = "b".repeat(40);
        let r = |_: &str, _: &str| Ok(sha.clone());
        let y = "steps:\n  - uses: actions/checkout@v4\n    with:\n      x: 1\n  - uses: ./local\n  - uses: a/b/sub@v1 # ciguard:ignore unpinned-action\n";
        let (out, n) = pin_actions(y, &r).unwrap();
        assert_eq!(n, 2);
        assert!(out.contains(&format!("  - uses: actions/checkout@{sha} # v4\n    with:")));
        assert!(out.contains("uses: ./local"));
        assert!(out.contains(&format!(
            "uses: a/b/sub@{sha} # v1 # ciguard:ignore unpinned-action"
        )));
    }

    #[test]
    fn fails_without_returning_a_partial_fix() {
        let y = "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-node@v4\n";
        let r = |repo: &str, _: &str| {
            if repo == "actions/setup-node" {
                bail!("network unavailable");
            }
            Ok("b".repeat(40))
        };

        assert!(pin_actions(y, &r).is_err());
    }

    #[test]
    fn preserves_crlf_line_endings() {
        let sha = "b".repeat(40);
        let y = "steps:\r\n  - uses: actions/checkout@v4\r\n";
        let (out, n) = pin_actions(y, &|_, _| Ok(sha.clone())).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            out,
            format!("steps:\r\n  - uses: actions/checkout@{sha} # v4\r\n")
        );
    }

    #[test]
    fn does_not_pin_uses_text_in_block_scalars() {
        let sha = "b".repeat(40);
        let y =
            "steps:\n  - run: |\n      uses: actions/checkout@v4\n  - uses: actions/checkout@v4\n";
        let (out, n) = pin_actions(y, &|_, _| Ok(sha.clone())).unwrap();

        assert_eq!(n, 1);
        assert!(out.contains("      uses: actions/checkout@v4\n"));
        assert!(out.contains(&format!("  - uses: actions/checkout@{sha} # v4\n")));
    }

    #[test]
    fn restores_all_workflows_when_a_later_replacement_fails() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.yml");
        let second = dir.path().join("second.yml");
        fs::write(&first, "first original\n").unwrap();
        fs::write(&second, "second original\n").unwrap();
        let files = vec![
            (first.clone(), "first replacement\n".to_string()),
            (second.clone(), "second replacement\n".to_string()),
        ];
        let mut replacements = 0;

        let result = replace_files_atomically_with(&files, |from, to| {
            replacements += 1;
            if replacements == 2 {
                return Err(io::Error::other("simulated disk failure"));
            }
            fs::rename(from, to)
        });

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(first).unwrap(), "first original\n");
        assert_eq!(fs::read_to_string(second).unwrap(), "second original\n");
    }
}
