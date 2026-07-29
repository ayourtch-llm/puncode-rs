//! Behavior tests for gathering a finished scan.
//!
//! Ported from the `collectResult` behavior in `tests-ts/api.test.ts`.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use puncode_security::api::collect_result;
use puncode_security::contract::ScanExpectation;
use puncode_security::result::TurnResultMetadata;
use puncode_security::targets::{NormalizedTarget, NormalizedTargetKind, ScanMode};
use serde_json::json;
use tempfile::TempDir;

fn plugin_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A complete scan directory: the bundled example plus its report.
fn completed_scan() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("temp dir");
    let scan = fs::canonicalize(root.path())
        .expect("canonical")
        .join("scan");
    fs::create_dir(&scan).expect("create scan directory");
    let source = plugin_root().join("completed-scan");
    for name in ["scan-manifest.json", "findings.json", "coverage.json"] {
        fs::copy(source.join(name), scan.join(name)).expect("copy document");
    }
    fs::write(scan.join("report.md"), b"# Scan report\n").expect("write report");
    (root, scan)
}

fn expectation() -> ScanExpectation {
    ScanExpectation {
        repository: PathBuf::from("/repo"),
        repository_revision: Some("deadbeef".to_owned()),
        target: NormalizedTarget {
            kind: Some(NormalizedTargetKind::Repository),
            ..NormalizedTarget::default()
        },
        mode: ScanMode::Standard,
        plugin_version: "0.1.0".to_owned(),
    }
}

fn turn() -> TurnResultMetadata {
    TurnResultMetadata {
        id: Some("turn".to_owned()),
        status: Some("completed".to_owned()),
        model: Some("gpt-5.6-sol".to_owned()),
        usage: Some(
            json!({ "input_tokens": 1_250, "cached_input_tokens": 200, "output_tokens": 30 }),
        ),
        ..TurnResultMetadata::default()
    }
}

fn collect(scan: &Path) -> puncode_security::Result<puncode_security::ScanResult> {
    collect_result(turn(), "thread-1", scan, &plugin_root(), &expectation())
}

#[test]
fn gathers_a_completed_scan() {
    let (_root, scan) = completed_scan();

    let result = collect(&scan).expect("collects");

    assert_eq!(result.thread_id, "thread-1");
    assert_eq!(result.scan_dir, scan);
    assert_eq!(result.plugin_version(), "0.1.0");
    assert_eq!(result.findings.findings.len(), 1);
    assert_eq!(result.cost.expect("priced").estimated_usd, 0.00625);
    assert_eq!(result.sarif_path, None, "the export is optional");
}

#[test]
fn finds_the_sarif_export_when_it_exists() {
    let (_root, scan) = completed_scan();
    fs::create_dir(scan.join("exports")).expect("create exports");
    fs::write(scan.join("exports/results.sarif"), b"{}\n").expect("write sarif");

    let result = collect(&scan).expect("collects");

    assert_eq!(
        result.sarif_path.as_deref(),
        Some(scan.join("exports/results.sarif").as_path())
    );
}

// All the missing artifacts are named at once, so a caller is not told about
// them one run at a time.
#[test]
fn names_every_missing_artifact_together() {
    let (_root, scan) = completed_scan();
    fs::remove_file(scan.join("coverage.json")).expect("remove");
    fs::remove_file(scan.join("report.md")).expect("remove");

    let error = collect(&scan).expect_err("an incomplete scan is refused");

    assert_eq!(
        error.to_string(),
        "Puncode Security scan completed without required artifacts: coverage.json, report.md"
    );
}

#[test]
fn requires_the_report() {
    let (_root, scan) = completed_scan();
    fs::remove_file(scan.join("report.md")).expect("remove");

    let error = collect(&scan).expect_err("a scan without a report is refused");

    assert!(error.to_string().ends_with("report.md"), "{error}");
}

// A directory is not an artifact.
#[test]
fn refuses_an_artifact_that_is_not_a_regular_file() {
    let (_root, scan) = completed_scan();
    fs::remove_file(scan.join("report.md")).expect("remove");
    fs::create_dir(scan.join("report.md")).expect("create a directory instead");

    let error = collect(&scan).expect_err("a directory is not an artifact");

    assert!(error.to_string().contains("report.md"), "{error}");
}

// The contract is still fully validated, so a scan that produced every file but
// disagrees with the request is refused.
#[test]
fn still_checks_the_contract_against_the_request() {
    let (_root, scan) = completed_scan();
    let mut expectation = expectation();
    expectation.plugin_version = "9.9.9".to_owned();

    let error = collect_result(turn(), "thread-1", &scan, &plugin_root(), &expectation)
        .expect_err("a mismatched expectation is refused");

    assert_eq!(
        error.to_string(),
        "Manifest producer version does not match the installed Codex Security plugin."
    );
}

#[test]
fn refuses_a_scan_directory_that_does_not_exist() {
    let root = TempDir::new().expect("temp dir");

    let error = collect(&root.path().join("absent")).expect_err("a missing directory is refused");

    assert!(error.to_string().contains("required artifacts"), "{error}");
}
