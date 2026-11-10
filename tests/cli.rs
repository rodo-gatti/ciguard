use assert_cmd::Command;
use std::fs;

#[test]
fn sarif_output_and_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(
        wf.join("a.yml"),
        "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
    )
    .unwrap();
    let out = Command::cargo_bin("ciguard")
        .unwrap()
        .arg(dir.path())
        .args(["--format", "sarif"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "unpinned-action"));
}

#[test]
fn missing_scan_root_is_an_operational_error() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("ciguard")
        .unwrap()
        .arg(dir.path().join("missing"))
        .assert()
        .code(2);
}

#[test]
fn file_scan_discovers_ancestor_configuration() {
    let repo = tempfile::tempdir().unwrap();
    let workflows = repo.path().join(".github/workflows");
    fs::create_dir_all(&workflows).unwrap();
    fs::write(
        workflows.join("build.yml"),
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    )
    .unwrap();
    fs::write(
        repo.path().join(".ciguard.toml"),
        "disable = [\"unpinned-action\"]\n",
    )
    .unwrap();

    let output = Command::cargo_bin("ciguard")
        .unwrap()
        .arg(workflows.join("build.yml"))
        .arg("--format")
        .arg("json")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let findings: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        !findings
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule"] == "unpinned-action")
    );
}

#[test]
fn repeated_action_ignore_suppresses_only_its_own_occurrence() {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(
        wf.join("a.yml"),
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4 # ciguard:ignore unpinned-action\n",
    )
    .unwrap();

    let output = Command::cargo_bin("ciguard")
        .unwrap()
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let findings: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let unpinned: Vec<_> = findings
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["rule"] == "unpinned-action")
        .collect();
    assert_eq!(unpinned.len(), 1);
    assert_eq!(unpinned[0]["line"], 6);
}
