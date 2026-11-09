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
    let out = Command::cargo_bin("actionguard")
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
