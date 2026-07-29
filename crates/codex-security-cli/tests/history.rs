//! Behavior tests for the saved-scan commands.
//!
//! These run the real binary against the real vendored plugin and a real
//! Python, in an isolated state directory, so what is checked is the whole path
//! from arguments to the workbench and back.

#![cfg(unix)]

use std::process::Command;

use tempfile::TempDir;

/// Runs the binary with an empty scan history of its own.
fn run(arguments: &[&str], state: &TempDir) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-security"))
        .args(arguments)
        .env("CODEX_SECURITY_STATE_DIR", state.path())
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn state() -> TempDir {
    TempDir::new().expect("state directory")
}

#[test]
fn lists_an_empty_history() {
    let state = state();

    let (code, stdout, stderr) = run(&["scans", "list"], &state);

    assert_eq!(code, Some(0), "{stderr}");
    let record: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(record["scans"], serde_json::json!([]));
}

// Output that is not going to a terminal stays machine readable whether or not
// anyone remembered a flag, so a piped run is never a drawn report.
#[test]
fn answers_with_json_when_it_is_not_writing_to_a_terminal() {
    let state = state();

    let (_, stdout, _) = run(&["scans", "list"], &state);

    serde_json::from_str::<serde_json::Value>(&stdout).expect("valid JSON");
    assert!(
        !stdout.contains('\u{1b}'),
        "a piped run should carry no escape sequences"
    );
}

#[test]
fn answers_with_json_when_asked_for_it() {
    let state = state();

    for arguments in [
        vec!["scans", "list", "--json"],
        vec!["scans", "list", "--format", "json"],
    ] {
        let (code, stdout, stderr) = run(&arguments, &state);
        assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
        serde_json::from_str::<serde_json::Value>(&stdout).expect("valid JSON");
    }
}

#[test]
fn answers_with_one_line_for_jsonl() {
    let state = state();

    let (code, stdout, stderr) = run(&["scans", "list", "--format", "jsonl"], &state);

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout.trim().lines().count(), 1, "{stdout}");
}

// The scan root names where output lives rather than what was scanned.
#[test]
fn lists_scans_under_a_scan_root() {
    let state = state();
    let root = TempDir::new().expect("scan root");

    let (code, stdout, stderr) = run(
        &[
            "scans",
            "list",
            "--scan-root",
            &root.path().display().to_string(),
        ],
        &state,
    );

    assert_eq!(code, Some(0), "{stderr}");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("valid JSON");
}

// Asking for a scan that was never saved is a failure, not an empty answer.
#[test]
fn reports_an_unknown_scan_as_a_failure() {
    let state = state();

    let (code, _, stderr) = run(&["scans", "show", "definitely-not-a-scan"], &state);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("codex-security:"), "{stderr}");
}

// The history lives under the state directory, so two callers with different
// state directories never see each other's scans.
#[test]
fn keeps_each_state_directory_separate() {
    let first = state();
    let second = state();

    run(&["scans", "list"], &first);
    let (code, stdout, stderr) = run(&["scans", "list"], &second);

    assert_eq!(code, Some(0), "{stderr}");
    let record: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(record["scans"], serde_json::json!([]));
}

// The workbench is the plugin's own script, so this exercises the vendored
// plugin actually running rather than only being unpacked.
#[test]
fn runs_the_bundled_plugins_workbench() {
    let state = state();

    let (code, stdout, stderr) = run(&["scans", "list"], &state);

    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.contains("scans"),
        "the workbench did not answer: {stdout}"
    );
    // A database is created under the state directory it was given.
    assert!(
        std::fs::read_dir(state.path())
            .expect("read state")
            .next()
            .is_some(),
        "the workbench left no state behind"
    );
}

// ---------------------------------------------------------------------------
// scans match
// ---------------------------------------------------------------------------

// Matching two scans that were never saved is a failure, not an empty answer.
#[test]
fn reports_unknown_scans_as_a_failure() {
    let state = state();

    let (code, _, stderr) = run(&["scans", "match", "not-a-scan", "also-not-a-scan"], &state);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("codex-security:"), "{stderr}");
}

// Comparing two scans that were never saved likewise fails rather than
// reporting nothing changed.
#[test]
fn reports_an_unknown_comparison_as_a_failure() {
    let state = state();

    let (code, _, stderr) = run(&["scans", "compare", "not-a-scan", "also-not"], &state);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("codex-security:"), "{stderr}");
}

// Matching a whole history with nothing saved reports nothing matched, rather
// than failing: an empty history is a legitimate state.
#[test]
fn matches_an_empty_history_without_failing() {
    let state = state();

    let (code, stdout, stderr) = run(&["scans", "match", "--all", "--json"], &state);

    assert_eq!(code, Some(0), "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(report["matchedPairs"], 0);
    assert_eq!(report["findingMatches"], 0);
}

// ---------------------------------------------------------------------------
// scans rerun
// ---------------------------------------------------------------------------

// A recipe that cannot be read is a different failure from a scan that failed:
// nothing was attempted.
#[test]
fn reports_an_unknown_scan_as_a_failure_before_rerunning() {
    let state = state();

    let (code, _, stderr) = run(&["scans", "rerun", "not-a-scan"], &state);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("codex-security:"), "{stderr}");
    // Nothing was scanned, so nothing about a scan should be reported.
    assert!(!stderr.contains("Findings:"), "{stderr}");
}
