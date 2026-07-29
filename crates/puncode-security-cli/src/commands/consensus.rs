//! Comparing several scans of the same target.
//!
//! Reads scan directories that already exist. Nothing is scanned here, so the
//! runs may come from anywhere — repeated runs of one model, or one run each
//! from several — and the comparison does not care which.

use std::path::{Path, PathBuf};

use puncode_security::benchmark::{ReportedFinding, ReportedLocation};
use puncode_security::consensus::{AgreedFinding, merge, summarise};
use serde_json::Value;

/// Compares the findings of several scan directories.
pub fn run(directories: &[PathBuf], minimum: Option<usize>) -> Result<String, String> {
    if directories.len() < 2 {
        return Err("Comparing runs needs at least two scan directories.".to_owned());
    }

    let mut runs = Vec::with_capacity(directories.len());
    for directory in directories {
        runs.push(read_findings(directory)?);
    }

    let merged = merge(&runs);
    Ok(render(&merged, directories, minimum))
}

/// The findings of one scan directory.
fn read_findings(directory: &Path) -> Result<Vec<ReportedFinding>, String> {
    let path = directory.join("findings.json");
    let body = std::fs::read_to_string(&path)
        .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
    let document: Value = serde_json::from_str(&body)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;

    Ok(document
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| ReportedFinding {
                    title: item
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("(untitled)")
                        .to_owned(),
                    severity: item
                        .get("severity")
                        .and_then(|severity| severity.get("level"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    locations: locations(item),
                })
                .collect()
        })
        .unwrap_or_default())
}

fn locations(item: &Value) -> Vec<ReportedLocation> {
    item.get("locations")
        .and_then(Value::as_array)
        .map(|found| {
            found
                .iter()
                .filter_map(|location| {
                    Some(ReportedLocation {
                        file: location.get("path").and_then(Value::as_str)?.to_owned(),
                        line: location
                            .get("startLine")
                            .or_else(|| location.get("line"))
                            .and_then(Value::as_u64)
                            .and_then(|line| u32::try_from(line).ok())
                            .unwrap_or(1),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The comparison, for a person.
fn render(merged: &[AgreedFinding], directories: &[PathBuf], minimum: Option<usize>) -> String {
    let total = directories.len();
    let summary = summarise(merged, total);
    let mut lines = vec![
        format!("Comparing {total} runs of the same target"),
        String::new(),
    ];

    let shown: Vec<&AgreedFinding> = merged
        .iter()
        .filter(|finding| minimum.is_none_or(|least| finding.agreement() >= least))
        .collect();

    for finding in &shown {
        let severity = if finding.severity_disputed() {
            format!("  severity disputed: {}", finding.severities.join(", "))
        } else {
            finding
                .severities
                .first()
                .map(|level| format!("  {level}"))
                .unwrap_or_default()
        };
        lines.push(format!(
            "  {} of {}   {}{}",
            finding.agreement(),
            finding.total_runs,
            finding.headline(),
            severity
        ));
        // Only when the runs called it different things — that disagreement is
        // information, and hiding it would flatten two views into one.
        if finding.titles.len() > 1 {
            for title in finding.titles.iter().filter(|t| *t != finding.headline()) {
                lines.push(format!("            also called: {title}"));
            }
        }
    }

    if shown.is_empty() {
        lines.push("  nothing met the agreement threshold".to_owned());
    }

    lines.push(String::new());
    lines.push(format!(
        "  {} distinct, {} in every run, {} in only one",
        summary.distinct, summary.unanimous, summary.solitary
    ));
    if summary.severity_disputes > 0 {
        lines.push(format!(
            "  {} disagreed on severity",
            summary.severity_disputes
        ));
    }
    if let Some(least) = minimum
        && shown.len() < merged.len()
    {
        // Never silently: a hidden finding is one nobody will look at.
        lines.push(format!(
            "  {} hidden by --min-agreement {least}",
            merged.len() - shown.len()
        ));
    }

    lines.push(String::new());
    // The caveat belongs in the output, not only in the documentation. Whoever
    // reads this is deciding where to spend attention.
    lines.push(
        "Agreement measures stability, not correctness. Runs sharing a blind spot agree just as"
            .to_owned(),
    );
    lines.push(
        "readily as runs being right, and a finding seen once may be the one that was looked at"
            .to_owned(),
    );
    lines.push("most carefully.".to_owned());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan_dir(findings: Value) -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("a directory");
        std::fs::write(
            directory.path().join("findings.json"),
            json!({ "findings": findings }).to_string(),
        )
        .expect("writes");
        directory
    }

    #[test]
    fn refuses_fewer_than_two_runs() {
        let one = scan_dir(json!([]));

        let refused = run(&[one.path().to_path_buf()], None);

        assert!(refused.expect_err("a refusal").contains("at least two"));
    }

    #[test]
    fn reports_how_many_runs_saw_each_finding() {
        let a = scan_dir(json!([
            { "title": "SQL injection", "locations": [{ "path": "app.py", "startLine": 10 }] },
            { "title": "Only in a", "locations": [{ "path": "app.py", "startLine": 90 }] },
        ]));
        let b = scan_dir(json!([
            { "title": "SQLi via name", "locations": [{ "path": "app.py", "startLine": 10 }] },
        ]));

        let rendered =
            run(&[a.path().to_path_buf(), b.path().to_path_buf()], None).expect("compares");

        assert!(rendered.contains("2 of 2"), "{rendered}");
        assert!(rendered.contains("1 of 2"), "{rendered}");
        assert!(rendered.contains("also called"), "{rendered}");
    }

    /// The caveat is part of the output because that is where the decision is
    /// made, not in documentation nobody has open.
    #[test]
    fn states_what_agreement_does_not_mean() {
        let a = scan_dir(json!([]));
        let b = scan_dir(json!([]));

        let rendered =
            run(&[a.path().to_path_buf(), b.path().to_path_buf()], None).expect("compares");

        assert!(
            rendered.contains("stability, not correctness"),
            "{rendered}"
        );
    }

    #[test]
    fn hiding_a_finding_is_said_out_loud() {
        let a = scan_dir(json!([
            { "title": "seen once", "locations": [{ "path": "app.py", "startLine": 10 }] },
        ]));
        let b = scan_dir(json!([]));

        let rendered =
            run(&[a.path().to_path_buf(), b.path().to_path_buf()], Some(2)).expect("compares");

        assert!(
            rendered.contains("1 hidden by --min-agreement"),
            "{rendered}"
        );
    }

    #[test]
    fn reports_a_disputed_severity() {
        let a = scan_dir(json!([
            { "title": "SQLi", "severity": { "level": "high" },
              "locations": [{ "path": "app.py", "startLine": 10 }] },
        ]));
        let b = scan_dir(json!([
            { "title": "SQLi", "severity": { "level": "critical" },
              "locations": [{ "path": "app.py", "startLine": 10 }] },
        ]));

        let rendered =
            run(&[a.path().to_path_buf(), b.path().to_path_buf()], None).expect("compares");

        assert!(rendered.contains("severity disputed"), "{rendered}");
    }

    #[test]
    fn names_a_directory_it_cannot_read() {
        let a = scan_dir(json!([]));

        let refused = run(
            &[a.path().to_path_buf(), PathBuf::from("/nowhere/at/all")],
            None,
        );

        assert!(refused.expect_err("a refusal").contains("/nowhere/at/all"));
    }
}
