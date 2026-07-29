//! Behavior tests for `ScanResult`.
//!
//! Ported from `tests-ts/result.test.ts`.

use std::fs;
use std::path::{Path, PathBuf};

use codex_security::models::{CoverageDocument, FindingsDocument, ScanManifest};
use codex_security::result::{ScanResult, ScanResultOptions, TurnResultMetadata};
use serde_json::json;
use tempfile::TempDir;

fn manifest() -> ScanManifest {
    serde_json::from_str(include_str!("fixtures/completed-scan/scan-manifest.json"))
        .expect("parse manifest fixture")
}

fn findings() -> FindingsDocument {
    serde_json::from_str(include_str!("fixtures/completed-scan/findings.json"))
        .expect("parse findings fixture")
}

fn coverage() -> CoverageDocument {
    serde_json::from_str(include_str!("fixtures/completed-scan/coverage.json"))
        .expect("parse coverage fixture")
}

fn options(scan_dir: impl Into<PathBuf>, turn: TurnResultMetadata) -> ScanResultOptions {
    ScanResultOptions::new(manifest(), findings(), coverage(), scan_dir, "thread", turn)
}

fn completed_turn() -> TurnResultMetadata {
    TurnResultMetadata {
        id: Some("turn".to_owned()),
        status: Some("completed".to_owned()),
        ..TurnResultMetadata::default()
    }
}

/// Collects the top-level keys of a JSON object in the order written.
fn top_level_keys(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let bytes = json.as_bytes();
    let (mut depth, mut index, mut in_string, mut escaped) = (0_i32, 0, false, false);
    let mut key_start = None;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                if depth == 1
                    && let Some(start) = key_start.take()
                {
                    // A string at depth 1 is a key only if a colon follows.
                    let rest = &json[index + 1..];
                    if rest.trim_start().starts_with(':') {
                        keys.push(json[start..index].to_owned());
                    }
                }
            }
        } else {
            match byte {
                b'"' => {
                    in_string = true;
                    key_start = Some(index + 1);
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }
        }
        index += 1;
    }
    keys
}

#[test]
fn exposes_canonical_paths() {
    let result = ScanResult::new(options("/scan", completed_turn()));

    assert_eq!(result.report_path(), Path::new("/scan/report.md"));
    assert_eq!(
        result.manifest_path(),
        Path::new("/scan/scan-manifest.json")
    );
    assert_eq!(result.findings_path(), Path::new("/scan/findings.json"));
    assert_eq!(result.coverage_path(), Path::new("/scan/coverage.json"));
    assert_eq!(result.artifacts_dir(), Path::new("/scan/artifacts"));
}

// Reports the producer version recorded in the scanned manifest, which is not
// necessarily the plugin version this build ships: results are read back long
// after they were produced.
#[test]
fn reports_the_plugin_version_from_the_manifest() {
    let result = ScanResult::new(options("/scan", completed_turn()));

    assert_eq!(result.plugin_version(), "0.1.0");
    assert_ne!(
        result.plugin_version(),
        codex_security::BUNDLED_PLUGIN_VERSION,
        "fixture deliberately differs from the shipped plugin version"
    );
}

#[test]
fn has_no_cost_without_a_model_or_usage() {
    let result = ScanResult::new(options("/scan", completed_turn()));

    assert_eq!(result.cost, None);
}

#[test]
fn estimates_cost_from_the_turn_metadata() {
    let turn = TurnResultMetadata {
        model: Some("gpt-5.6-sol".to_owned()),
        usage: Some(json!({
            "input_tokens": 1_250,
            "cached_input_tokens": 200,
            "output_tokens": 30
        })),
        ..TurnResultMetadata::default()
    };

    let result = ScanResult::new(options("/scan", turn));

    assert_eq!(result.cost.as_ref().expect("cost").estimated_usd, 0.00625);
}

#[test]
fn discovers_sarif_at_its_canonical_path() {
    let scan_dir = TempDir::new().expect("temp dir");
    let exports = scan_dir.path().join("exports");
    fs::create_dir(&exports).expect("create exports");
    let sarif = exports.join("results.sarif");
    fs::write(&sarif, "{}\n").expect("write sarif");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()));

    assert_eq!(result.sarif_path.as_deref(), Some(sarif.as_path()));
}

#[test]
fn does_not_discover_a_directory_named_results_sarif() {
    let scan_dir = TempDir::new().expect("temp dir");
    fs::create_dir_all(scan_dir.path().join("exports").join("results.sarif"))
        .expect("create directory");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()));

    assert_eq!(result.sarif_path, None);
}

#[test]
fn reports_no_sarif_when_the_scan_directory_is_empty() {
    let scan_dir = TempDir::new().expect("temp dir");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()));

    assert_eq!(result.sarif_path, None);
}

#[cfg(unix)]
#[test]
fn survives_a_symlink_loop_during_discovery() {
    let scan_dir = TempDir::new().expect("temp dir");
    let exports = scan_dir.path().join("exports");
    fs::create_dir(&exports).expect("create exports");
    std::os::unix::fs::symlink("loop", exports.join("loop")).expect("create symlink loop");

    let result = ScanResult::new(options(exports.join("loop"), completed_turn()));

    assert_eq!(result.sarif_path, None);
}

// A symlink pointing at a real file still counts: upstream stats through links.
#[cfg(unix)]
#[test]
fn follows_a_symlink_to_a_real_sarif_file() {
    let scan_dir = TempDir::new().expect("temp dir");
    let exports = scan_dir.path().join("exports");
    fs::create_dir(&exports).expect("create exports");
    let real = scan_dir.path().join("real.sarif");
    fs::write(&real, "{}\n").expect("write sarif");
    let link = exports.join("results.sarif");
    std::os::unix::fs::symlink(&real, &link).expect("create symlink");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()));

    assert_eq!(result.sarif_path.as_deref(), Some(link.as_path()));
}

#[cfg(unix)]
#[test]
fn ignores_a_broken_symlink() {
    let scan_dir = TempDir::new().expect("temp dir");
    let exports = scan_dir.path().join("exports");
    fs::create_dir(&exports).expect("create exports");
    std::os::unix::fs::symlink(
        scan_dir.path().join("missing"),
        exports.join("results.sarif"),
    )
    .expect("create broken symlink");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()));

    assert_eq!(result.sarif_path, None);
}

#[test]
fn an_explicit_sarif_path_overrides_discovery() {
    let result = ScanResult::new(
        options("/scan", completed_turn()).with_sarif_path(Some("/elsewhere/x.sarif".into())),
    );

    assert_eq!(
        result.sarif_path.as_deref(),
        Some(Path::new("/elsewhere/x.sarif"))
    );
}

// Adversarial: passing an explicit `None` means "there is no SARIF", and must
// suppress discovery even when the canonical file exists.
#[test]
fn an_explicit_absent_sarif_path_suppresses_discovery() {
    let scan_dir = TempDir::new().expect("temp dir");
    let exports = scan_dir.path().join("exports");
    fs::create_dir(&exports).expect("create exports");
    fs::write(exports.join("results.sarif"), "{}\n").expect("write sarif");

    let result = ScanResult::new(options(scan_dir.path(), completed_turn()).with_sarif_path(None));

    assert_eq!(result.sarif_path, None);
}

#[test]
fn serializes_the_machine_readable_shape() {
    let result = ScanResult::new(options("/scan", completed_turn()));

    let value = serde_json::to_value(&result).expect("serialize");

    assert_eq!(value["scanDir"], json!("/scan"));
    assert_eq!(value["threadId"], json!("thread"));
    assert_eq!(value["cost"], json!(null));
    assert_eq!(value["sarifPath"], json!(null));
    assert_eq!(value["reportPath"], json!("/scan/report.md"));
    assert_eq!(value["artifactsDir"], json!("/scan/artifacts"));
    assert_eq!(value["turn"]["id"], json!("turn"));
    assert_eq!(
        value["manifest"]["scan"]["producer"]["version"],
        json!("0.1.0")
    );
}

// Key order is observable in CLI JSON output, so it matches upstream's
// `toJSON` insertion order.
#[test]
fn serializes_keys_in_the_upstream_order() {
    let result = ScanResult::new(options("/scan", completed_turn()));

    let json = serde_json::to_string(&result).expect("serialize");

    assert_eq!(
        top_level_keys(&json),
        [
            "manifest",
            "findings",
            "coverage",
            "scanDir",
            "threadId",
            "reportPath",
            "artifactsDir",
            "sarifPath",
            "cost",
            "turn",
        ]
    );
}

// Turn metadata is passed through opaquely, including keys the SDK does not model.
#[test]
fn preserves_unmodeled_turn_metadata() {
    let turn = TurnResultMetadata {
        id: Some("turn".to_owned()),
        extra: [("customKey".to_owned(), json!("kept"))]
            .into_iter()
            .collect(),
        ..TurnResultMetadata::default()
    };

    let result = ScanResult::new(options("/scan", turn));
    let value = serde_json::to_value(&result).expect("serialize");

    assert_eq!(value["turn"]["customKey"], json!("kept"));
}
