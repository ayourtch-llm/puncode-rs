//! Behavior tests for exporting a finished scan.
//!
//! The export itself is produced by the vendored plugin; what is checked here
//! is where the CLI will and will not let it be written, because a scan
//! directory is a sealed contract and an export landing on an artifact would
//! invalidate the scan it came from.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../puncode-security/tests/fixtures")
}

/// A directory holding the artifacts a finished scan leaves behind.
fn completed_scan() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("root");
    let path = std::fs::canonicalize(root.path()).expect("canonicalize");
    let scan = path.join("scan");
    std::fs::create_dir(&scan).expect("create scan");
    let source = fixtures().join("completed-scan");
    for name in ["scan-manifest.json", "findings.json", "coverage.json"] {
        std::fs::copy(source.join(name), scan.join(name)).expect("copy artifact");
    }
    std::fs::write(scan.join("report.md"), "# Scan report\n").expect("write report");
    (root, scan)
}

fn run(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(arguments)
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The failure an export reports.
fn refuse(arguments: &[&str]) -> String {
    let (code, _, stderr) = run(arguments);
    assert_eq!(code, Some(2), "expected a refusal: {stderr}");
    stderr
}

// A scan directory is a sealed contract: writing over an artifact would
// quietly invalidate the scan the export came from.
#[test]
fn refuses_to_overwrite_a_scan_artifact() {
    let (_root, scan) = completed_scan();

    for artifact in ["findings.json", "scan-manifest.json", "report.md"] {
        let stderr = refuse(&[
            "export",
            &scan.display().to_string(),
            "--output",
            &scan.join(artifact).display().to_string(),
        ]);
        assert!(
            stderr.contains("cannot overwrite a scan artifact"),
            "{artifact}: {stderr}"
        );
        // The artifact is still there, unchanged.
        assert!(scan.join(artifact).is_file(), "{artifact} was removed");
    }
}

// Anywhere else inside the scan is refused too, not only the artifacts
// themselves — the contract covers the directory.
#[test]
fn refuses_an_arbitrary_path_inside_the_scan() {
    let (_root, scan) = completed_scan();

    let stderr = refuse(&[
        "export",
        &scan.display().to_string(),
        "--output",
        &scan.join("somewhere/else.sarif").display().to_string(),
    ]);

    assert!(
        stderr.contains("cannot overwrite a scan artifact"),
        "{stderr}"
    );
}

// A missing directory is a typo worth reporting plainly, rather than a
// half-written export or a created tree nobody asked for.
#[test]
fn refuses_an_output_directory_that_is_not_there() {
    let (root, scan) = completed_scan();
    let missing = root.path().join("not-created/findings.sarif");

    let stderr = refuse(&[
        "export",
        &scan.display().to_string(),
        "--output",
        &missing.display().to_string(),
    ]);

    assert!(
        stderr.contains("Export output directory does not exist"),
        "{stderr}"
    );
    assert!(
        !missing.parent().expect("parent").exists(),
        "the directory should not have been created"
    );
}

#[test]
fn refuses_a_scan_directory_that_is_not_there() {
    let stderr = refuse(&["export", "/definitely/missing/scan"]);

    assert!(stderr.contains("puncode-security:"), "{stderr}");
}

// The fingerprints a source root feeds are a SARIF concept, so pairing it with
// another format is a mistake rather than a silently ignored flag.
#[test]
fn refuses_a_source_root_for_another_format() {
    let (_root, scan) = completed_scan();

    let stderr = refuse(&[
        "export",
        &scan.display().to_string(),
        "--export-format",
        "csv",
        "--source-root",
        &scan.display().to_string(),
    ]);

    assert!(
        stderr.contains("only supported with --export-format sarif"),
        "{stderr}"
    );
}

// Both would be written to the same stream, interleaved.
#[test]
fn refuses_csv_on_standard_output_alongside_json() {
    let (_root, scan) = completed_scan();

    let stderr = refuse(&[
        "export",
        &scan.display().to_string(),
        "--export-format",
        "csv",
        "--output",
        "-",
        "--json",
    ]);

    assert!(stderr.contains("CSV stdout cannot be combined"), "{stderr}");
}

// The export's own location inside a scan is the one place it may go.
#[test]
fn allows_the_scans_own_export_location() {
    let (_root, scan) = completed_scan();
    let permitted = scan.join("exports/results.sarif");

    let (_, _, stderr) = run(&[
        "export",
        &scan.display().to_string(),
        "--output",
        &permitted.display().to_string(),
    ]);

    // The exporter may still fail on the example's contents; what matters is
    // that the path itself was not the reason.
    assert!(
        !stderr.contains("cannot overwrite a scan artifact"),
        "{stderr}"
    );
}

/// A real scan directory, with the SARIF the plugin itself wrote.
///
/// Every other test in this file checks that `export` refuses something. None
/// checked what it produces, and the SARIF projection is a port of the
/// plugin's — so the two could drift apart and nothing would notice.
fn plugin_written_scan() -> (TempDir, PathBuf) {
    let source = fixtures().join("plugin-sarif");
    let temp = TempDir::new().expect("temp dir");
    let scan = temp.path().join("scan");
    copy_tree(&source, &scan);
    (temp, scan)
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("creates");
    for entry in std::fs::read_dir(from).expect("reads").flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copies");
        }
    }
}

/// What this command produces is what the plugin produces.
///
/// Checked against a scan the plugin actually finalised, not against a shape
/// invented here. Confirmed byte-identical across three real scans before being
/// pinned as a fixture.
#[test]
fn the_sarif_export_matches_the_one_the_plugin_wrote() {
    let (_temp, scan) = plugin_written_scan();
    let theirs: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(scan.join("exports/results.sarif")).expect("the plugin's SARIF"),
    )
    .expect("valid JSON");
    let output = scan.parent().expect("a parent").join("ours.sarif");

    let (code, _, stderr) = run(&[
        "export",
        &scan.to_string_lossy(),
        "--export-format",
        "sarif",
        "--output",
        &output.to_string_lossy(),
    ]);

    assert_eq!(code, Some(0), "{stderr}");
    let ours: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("our SARIF"))
            .expect("valid JSON");
    assert_eq!(
        ours, theirs,
        "the SARIF projection has drifted from the plugin's"
    );
}

/// And it says what a SARIF consumer needs, rather than merely parsing.
#[test]
fn the_sarif_export_carries_what_a_consumer_reads() {
    let (_temp, scan) = plugin_written_scan();
    let findings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(scan.join("findings.json")).expect("findings"),
    )
    .expect("valid JSON");
    let expected = findings["findings"].as_array().expect("findings").len();
    let output = scan.parent().expect("a parent").join("ours.sarif");

    run(&[
        "export",
        &scan.to_string_lossy(),
        "--export-format",
        "sarif",
        "--output",
        &output.to_string_lossy(),
    ]);

    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("our SARIF"))
            .expect("valid JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let run_zero = &sarif["runs"][0];
    assert_eq!(
        run_zero["results"].as_array().expect("results").len(),
        expected,
        "every finding must reach the export"
    );
    // A result nobody can open is not a result.
    for result in run_zero["results"].as_array().expect("results") {
        let location = &result["locations"][0]["physicalLocation"];
        assert!(location["artifactLocation"]["uri"].is_string(), "{result}");
        assert!(location["region"]["startLine"].is_number(), "{result}");
    }
}
