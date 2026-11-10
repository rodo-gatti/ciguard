mod config;
mod fix;
mod rules;
mod sarif;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use rules::Finding;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    version,
    about = "Check GitHub Actions workflows for common security and cost issues"
)]
struct Cli {
    /// Repository root or a single workflow file
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Exit non-zero when a finding at or above this severity exists
    #[arg(long, value_enum, default_value = "high")]
    fail_on: rules::Severity,
    /// Pin tag-referenced actions to commit SHAs in place (uses the GitHub API; honors GITHUB_TOKEN)
    #[arg(long)]
    fix: bool,
    /// Path to a config file (default: .ciguard.toml in the scanned directory)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

fn workflow_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!(
            "scan path does not exist or is not a directory: {}",
            path.display()
        );
    }

    let workflow_dir = path.join(".github/workflows");
    if !workflow_dir.is_dir() {
        bail!(
            "workflow directory does not exist: {}",
            workflow_dir.display()
        );
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(&workflow_dir) {
        let entry = entry.with_context(|| format!("walking {}", workflow_dir.display()))?;
        if entry
            .path()
            .extension()
            .is_some_and(|x| x == "yml" || x == "yaml")
        {
            files.push(entry.into_path());
        }
    }
    files.sort();
    if files.is_empty() {
        bail!("no workflow files found in {}", workflow_dir.display());
    }
    Ok(files)
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let mut all: Vec<Finding> = Vec::new();
    let files = workflow_files(&cli.path)?;
    let cfg = config::Config::load(cli.config.as_deref(), &cli.path)?;
    let mut pending_writes = Vec::new();
    for file in files {
        let mut text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        if cli.fix {
            let (fixed, n) = fix::pin_actions_online(&text)
                .with_context(|| format!("pinning actions in {}", file.display()))?;
            if n > 0 {
                pending_writes.push((file.clone(), fixed.clone(), n));
                text = fixed;
            }
        }
        let found = rules::analyze(&file.display().to_string(), &text)?;
        all.extend(config::suppress(&text, found));
    }
    let replacements = pending_writes
        .iter()
        .map(|(file, fixed, _)| (file.clone(), fixed.clone()))
        .collect::<Vec<_>>();
    fix::replace_files_atomically(&replacements)?;
    for (file, _, n) in pending_writes {
        eprintln!("fixed {n} action(s) in {}", file.display());
    }
    let all = cfg.apply(all);
    match cli.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&all)?),
        Format::Sarif => println!("{}", serde_json::to_string_pretty(&sarif::to_sarif(&all))?),
        Format::Text => {
            for f in &all {
                println!(
                    "[{:?}] {}:{} {} - {}",
                    f.severity, f.file, f.line, f.rule, f.message
                );
            }

            println!("{} finding(s)", all.len());
        }
    }
    Ok(all.iter().any(|f| f.severity >= cli.fail_on))
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_files_rejects_missing_paths_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert!(workflow_files(&dir.path().join("missing")).is_err());
        assert!(workflow_files(dir.path()).is_err());
    }

    #[test]
    fn workflow_files_finds_only_yaml_workflows() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github/workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("a.yaml"), "on: push\n").unwrap();
        std::fs::write(workflows.join("note.txt"), "not a workflow\n").unwrap();

        assert_eq!(
            workflow_files(dir.path()).unwrap(),
            vec![workflows.join("a.yaml")]
        );
    }
}
