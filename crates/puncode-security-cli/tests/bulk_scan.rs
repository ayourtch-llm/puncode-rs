//! Behavior tests for scanning many repositories from an inventory.
//!
//! The campaign itself is covered in the library; what is checked here is the
//! CLI's own behaviour — reading the inventory, refusing what it cannot run,
//! and reporting what happened.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

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

fn refuse(arguments: &[&str]) -> String {
    let (code, _, stderr) = run(arguments);
    assert_eq!(code, Some(2), "expected a refusal: {stderr}");
    stderr
}

/// An inventory file holding `contents`.
fn inventory(contents: &str) -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("root");
    let path = std::fs::canonicalize(root.path()).expect("canonicalize");
    let file = path.join("repositories.csv");
    std::fs::write(&file, contents).expect("write inventory");
    (root, file)
}

// Discovery asks questions, so with no terminal to ask through it says so and
// points at the form that needs no answers.
#[test]
fn refuses_to_discover_without_a_terminal() {
    let stderr = refuse(&["bulk-scan"]);

    assert!(
        stderr.contains("requires a terminal") || stderr.contains("GitHub"),
        "{stderr}"
    );
}

// Without somewhere to write, a campaign has nowhere to keep its ledger, and
// a resumable run depends on that ledger.
#[test]
fn requires_somewhere_to_write() {
    let (_root, file) = inventory(&format!("id,repository,revision\npay,/repos/pay,{SHA}\n"));

    let stderr = refuse(&["bulk-scan", &file.display().to_string()]);

    assert!(stderr.contains("--output-dir is required"), "{stderr}");
}

#[test]
fn refuses_an_inventory_that_is_not_there() {
    let root = TempDir::new().expect("root");

    let stderr = refuse(&[
        "bulk-scan",
        &root.path().join("missing.csv").display().to_string(),
        "--output-dir",
        &root.path().join("out").display().to_string(),
    ]);

    assert!(stderr.contains("Could not read"), "{stderr}");
}

// The whole file is rejected rather than partially started, so a mistake on
// the last row does not leave half a campaign behind.
#[test]
fn refuses_a_malformed_inventory_before_scanning_anything() {
    let (root, file) = inventory("id,repository,revision\npay,/repos/pay\n");
    let output = root.path().join("out");

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &output.display().to_string(),
    ]);

    assert!(
        stderr.contains("must match their header columns"),
        "{stderr}"
    );
}

// A branch could move between reading the inventory and cloning, so only a
// full commit identifies what was scanned.
#[test]
fn refuses_a_revision_that_is_not_a_full_sha() {
    let (root, file) = inventory("id,repository,revision\npay,/repos/pay,main\n");

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &root.path().join("out").display().to_string(),
    ]);

    assert!(stderr.contains("full immutable Git SHAs"), "{stderr}");
}

// An empty inventory is a mistake worth reporting, not a campaign with nothing
// to do.
#[test]
fn refuses_an_inventory_with_no_repositories() {
    let (root, file) = inventory("id,repository,revision\n");

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &root.path().join("out").display().to_string(),
    ]);

    assert!(stderr.contains("at least one repository"), "{stderr}");
}

#[test]
fn refuses_a_worker_count_of_zero() {
    let (root, file) = inventory(&format!("id,repository,revision\npay,/repos/pay,{SHA}\n"));

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &root.path().join("out").display().to_string(),
        "--workers",
        "0",
    ]);

    assert!(stderr.contains("positive integer"), "{stderr}");
}

// Two supervisors writing one ledger would corrupt it.
#[test]
fn refuses_a_second_campaign_over_the_same_output() {
    let (root, file) = inventory(&format!("id,repository,revision\npay,/repos/pay,{SHA}\n"));
    let output = root.path().join("out");
    std::fs::create_dir_all(output.join(".lock")).expect("create a claim");
    std::fs::write(
        output.join(".lock/owner.json"),
        format!("{{\"pid\":{}}}\n", std::process::id()),
    )
    .expect("write owner");

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &output.display().to_string(),
    ]);

    assert!(stderr.contains("already running"), "{stderr}");
}

#[test]
fn refuses_a_malformed_codex_override() {
    let (root, file) = inventory(&format!("id,repository,revision\npay,/repos/pay,{SHA}\n"));

    let stderr = refuse(&[
        "bulk-scan",
        &file.display().to_string(),
        "--output-dir",
        &root.path().join("out").display().to_string(),
        "--codex",
        "model=unquoted",
    ]);

    assert!(stderr.contains("Invalid --codex TOML value"), "{stderr}");
}
