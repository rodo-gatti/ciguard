use crate::rules::{Finding, RULES, Severity};
use serde_json::{Value, json};

fn level(s: Severity) -> &'static str {
    match s {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn to_sarif(findings: &[Finding]) -> Value {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|(id, desc)| json!({ "id": id, "shortDescription": { "text": desc } }))
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule,
                "level": level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file.trim_start_matches("./") },
                        "region": { "startLine": f.line.max(1) }
                    }
                }]
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "ciguard",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": env!("CARGO_PKG_REPOSITORY"),
                "rules": rules
            }},
            "results": results
        }]
    })
}
