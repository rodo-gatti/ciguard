mod config;
mod fix;
mod rules;
mod sarif;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rules::Finding;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(version, about = "Audit GitHub Actions workflows for security and cost issues")]
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

fn workflow_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    WalkDir::new(path.join(".github/workflows"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|e| e.into_path())
        .collect()
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let mut all: Vec<Finding> = Vec::new();
    let cfg = config::Config::load(cli.config.as_deref(), &cli.path)?;
    for file in workflow_files(&cli.path) {
        let mut text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        if cli.fix {
            let (fixed, n) = fix::pin_actions_online(&text);
            if n > 0 {
                std::fs::write(&file, &fixed)
                    .with_context(|| format!("writing {}", file.display()))?;
                eprintln!("fixed {n} action(s) in {}", file.display());
                text = fixed;
            }
        }
        let found = rules::analyze(&file.display().to_string(), &text)?;
        all.extend(config::suppress(&text, found));
    }
    let all = cfg.apply(all);
    match cli.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&all)?),
        Format::Sarif => println!("{}", serde_json::to_string_pretty(&sarif::to_sarif(&all))?),
        Format::Text => {
            for f in &all {
                println!("[{:?}] {}:{} {} - {}", f.severity, f.file, f.line, f.rule, f.message);
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
