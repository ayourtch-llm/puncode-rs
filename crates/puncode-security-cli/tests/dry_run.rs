//! Behavior tests for `scan --dry-run`.
//!
//! A dry run answers without spending anything, so these drive the real binary
//! against real repositories and assert on what it says it would do.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// A git repository with one commit.
fn repository() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("root");
    let path = std::fs::canonicalize(root.path()).expect("canonicalize");
    std::fs::create_dir_all(path.join("src")).expect("create source");
    std::fs::write(path.join("src/main.rs"), "fn main() {}").expect("write");
    for arguments in [
        vec!["init", "--quiet"],
        vec!["add", "."],
        vec!["commit", "--quiet", "-m", "initial"],
    ] {
        let status = Command::new("git")
            .args(&arguments)
            .current_dir(&path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Scan")
            .env("GIT_AUTHOR_EMAIL", "scan@example.com")
            .env("GIT_COMMITTER_NAME", "Scan")
            .env("GIT_COMMITTER_EMAIL", "scan@example.com")
            .status()
            .expect("run git");
        assert!(status.success(), "git {arguments:?} failed");
    }
    (root, path)
}

/// Runs the binary with no ambient credentials.
fn run(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(arguments)
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_API_KEY")
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The JSON a successful dry run reports.
fn report(arguments: &[&str]) -> serde_json::Value {
    let mut full: Vec<&str> = arguments.to_vec();
    full.push("--json");
    let (code, stdout, stderr) = run(&full);
    assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
    serde_json::from_str(&stdout).expect("valid JSON")
}

#[test]
fn reports_what_a_repository_scan_would_do() {
    let (_root, path) = repository();

    let record = report(&["scan", &path.display().to_string(), "--dry-run"]);

    assert_eq!(record["dryRun"], true);
    assert_eq!(record["repository"], path.display().to_string());
    assert_eq!(record["target"]["kind"], "repository");
    assert_eq!(record["mode"], "standard");
    assert_eq!(record["model"], "gpt-5.6-sol");
}

// Nothing is created, which is the whole point of asking first.
#[test]
fn creates_nothing() {
    let (_root, path) = repository();
    let output = path.parent().expect("parent").join("scan-output");

    run(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--output-dir",
        &output.display().to_string(),
    ]);

    assert!(!output.exists(), "the dry run created its output directory");
}

#[test]
fn reports_a_scoped_target() {
    let (_root, path) = repository();

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--path",
        "src",
    ]);

    assert_eq!(record["target"]["kind"], "paths");
    assert_eq!(record["target"]["paths"], serde_json::json!(["src"]));
}

#[test]
fn reports_the_requested_mode_and_output() {
    let (_root, path) = repository();
    let output = path.parent().expect("parent").join("results");

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--mode",
        "deep",
        "--output-dir",
        &output.display().to_string(),
    ]);

    assert_eq!(record["mode"], "deep");
    assert_eq!(record["outputDir"], output.display().to_string());
}

#[test]
fn reports_a_cost_limit_when_one_is_set() {
    let (_root, path) = repository();

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--max-cost",
        "5",
    ]);

    assert_eq!(record["maxCostUsd"], 5.0);
}

// Absent rather than null, so the shape says what applies.
#[test]
fn omits_what_was_not_asked_for() {
    let (_root, path) = repository();

    let record = report(&["scan", &path.display().to_string(), "--dry-run"]);

    assert!(record.get("maxCostUsd").is_none(), "{record}");
    assert!(record.get("archiveDir").is_none(), "{record}");
    assert!(record.get("knowledgeBasePaths").is_none(), "{record}");
}

// An environment key is what would be used, so the dry run says so — that is
// how someone finds out they are about to bill the wrong account.
#[test]
fn reports_which_credentials_would_be_used() {
    let (_root, path) = repository();

    let with_key = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(["scan", &path.display().to_string(), "--dry-run", "--json"])
        .env("OPENAI_API_KEY", "sk-one")
        .output()
        .expect("run the binary");
    let record: serde_json::Value = serde_json::from_slice(&with_key.stdout).expect("valid JSON");
    assert_eq!(record["authentication"]["method"], "api_key");
    assert_eq!(record["authentication"]["source"], "OPENAI_API_KEY");

    // Without one, the stored credentials would be used instead.
    let record = report(&["scan", &path.display().to_string(), "--dry-run"]);
    assert_eq!(record["authentication"]["method"], "stored_credentials");
}

// A local mistake should cost nothing to find.
#[test]
fn refuses_a_repository_that_is_not_there() {
    let (code, _, stderr) = run(&["scan", "/definitely/missing/repository", "--dry-run"]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("puncode-security:"), "{stderr}");
}

// Results quote source and reproduction steps, so writing them into the tree
// under review would contaminate the very thing being reviewed.
#[test]
fn refuses_output_inside_the_repository() {
    let (_root, path) = repository();

    let (code, _, stderr) = run(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--output-dir",
        &path.join("results").display().to_string(),
    ]);

    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("protected scan root") || stderr.contains("outside"),
        "{stderr}"
    );
}

#[test]
fn reports_the_same_facts_as_text() {
    let (_root, path) = repository();

    let (code, stdout, stderr) = run(&["scan", &path.display().to_string(), "--dry-run"]);

    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("nothing was scanned"), "{stdout}");
    assert!(stdout.contains(&path.display().to_string()), "{stdout}");
    assert!(stdout.contains("gpt-5.6-sol"), "{stdout}");
}

// The dry run reads the repository but never the plugin runtime, so it works
// before anything has been installed or signed in to.
#[test]
fn answers_without_preparing_a_runtime() {
    let (_root, path) = repository();
    let home = TempDir::new().expect("home");

    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(["scan", &path.display().to_string(), "--dry-run", "--json"])
        .env("HOME", home.path())
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_API_KEY")
        .output()
        .expect("run the binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Nothing was unpacked or installed into the empty home.
    assert!(
        !Path::new(&home.path().join(".codex-security")).exists(),
        "the dry run prepared a runtime"
    );
}

// ---------------------------------------------------------------------------
// --codex overrides
// ---------------------------------------------------------------------------

#[test]
fn applies_a_model_override() {
    let (_root, path) = repository();

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--codex",
        "model=\"configured-model\"",
    ]);

    assert_eq!(record["model"], "configured-model");
}

#[test]
fn applies_the_model_flag() {
    let (_root, path) = repository();

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--model",
        "flag-model",
    ]);

    assert_eq!(record["model"], "flag-model");
}

// Saying the same thing two ways is a contradiction, not a preference.
#[test]
fn refuses_a_model_given_two_ways() {
    let (_root, path) = repository();

    let (code, _, stderr) = run(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--model",
        "one",
        "--codex",
        "model=\"two\"",
    ]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("conflicts with"), "{stderr}");
}

// The value is TOML, so a malformed one is reported before anything runs.
#[test]
fn refuses_a_malformed_override() {
    let (_root, path) = repository();

    for override_ in ["model", "=value", "model=", "a=not valid toml"] {
        let (code, _, stderr) = run(&[
            "scan",
            &path.display().to_string(),
            "--dry-run",
            "--codex",
            override_,
        ]);
        assert_eq!(code, Some(2), "{override_}: {stderr}");
        assert!(
            stderr.contains("--codex expects KEY=VALUE")
                || stderr.contains("Invalid --codex TOML value"),
            "{override_}: {stderr}"
        );
    }
}

// A key naming an object's machinery is refused whatever it would have done.
#[test]
fn refuses_an_override_reaching_object_machinery() {
    let (_root, path) = repository();

    let (code, _, stderr) = run(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--codex",
        "__proto__.polluted=true",
    ]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("Invalid --codex key"), "{stderr}");
}

#[test]
fn applies_a_nested_override() {
    let (_root, path) = repository();

    let record = report(&[
        "scan",
        &path.display().to_string(),
        "--dry-run",
        "--codex",
        "model_reasoning_effort=\"low\"",
    ]);

    assert_eq!(record["reasoningEffort"], "low");
}
