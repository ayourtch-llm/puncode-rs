//! Behavior tests for installing the pre-commit hook.
//!
//! These run the real binary against real Git repositories: where the hook
//! belongs is Git's answer, not an assumption, so it has to be asked.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// A Git repository.
fn repository() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("root");
    let path = std::fs::canonicalize(root.path()).expect("canonicalize");
    let status = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .expect("run git");
    assert!(status.success());
    (root, path)
}

fn run(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn installs_a_hook_that_scans_before_committing() {
    let (_root, path) = repository();

    let (code, stdout, stderr) = run(&["install-hook", &path.display().to_string()]);

    assert_eq!(code, Some(0), "{stderr}");
    let hook = path.join(".git/hooks/pre-commit");
    assert!(hook.is_file(), "{stdout}");
    let contents = std::fs::read_to_string(&hook).expect("read the hook");
    assert!(contents.contains("scan . --working-tree"), "{contents}");
    assert!(
        contents.contains("--fail-on-severity high"),
        "the default threshold should be high: {contents}"
    );
}

// A hook Git will not run is not installed.
#[test]
fn installs_the_hook_executable() {
    let (_root, path) = repository();

    run(&["install-hook", &path.display().to_string()]);

    let mode = std::fs::metadata(path.join(".git/hooks/pre-commit"))
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "the hook must be executable");
}

// A hook runs with whatever PATH Git gives it, so a bare name could silently
// stop resolving.
#[test]
fn names_the_scanner_by_its_absolute_path() {
    let (_root, path) = repository();

    run(&["install-hook", &path.display().to_string()]);

    let contents =
        std::fs::read_to_string(path.join(".git/hooks/pre-commit")).expect("read the hook");
    assert!(
        contents.contains(&format!("'{}'", env!("CARGO_BIN_EXE_puncode-security"))),
        "{contents}"
    );
}

#[test]
fn honours_the_requested_threshold() {
    let (_root, path) = repository();

    run(&[
        "install-hook",
        &path.display().to_string(),
        "--fail-on-severity",
        "critical",
    ]);

    let contents =
        std::fs::read_to_string(path.join(".git/hooks/pre-commit")).expect("read the hook");
    assert!(
        contents.contains("--fail-on-severity critical"),
        "{contents}"
    );
}

// Installing twice is how someone re-runs setup; it must not fail.
#[test]
fn installing_the_same_hook_twice_is_not_a_failure() {
    let (_root, path) = repository();

    run(&["install-hook", &path.display().to_string()]);
    let (code, _, stderr) = run(&["install-hook", &path.display().to_string()]);

    assert_eq!(code, Some(0), "{stderr}");
}

// Overwriting someone's own hook would silently remove whatever checks it was
// doing.
#[test]
fn refuses_to_replace_a_hook_it_did_not_write() {
    let (_root, path) = repository();
    let hook = path.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().expect("hooks")).expect("create hooks");
    std::fs::write(&hook, "#!/bin/sh\necho mine\n").expect("write");

    let (code, _, stderr) = run(&["install-hook", &path.display().to_string()]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(&hook).expect("read"),
        "#!/bin/sh\necho mine\n",
        "the existing hook must be left alone"
    );
}

// A changed threshold is a different hook, so it is refused rather than
// silently rewritten.
#[test]
fn refuses_to_change_the_threshold_of_an_installed_hook() {
    let (_root, path) = repository();
    run(&["install-hook", &path.display().to_string()]);

    let (code, _, stderr) = run(&[
        "install-hook",
        &path.display().to_string(),
        "--fail-on-severity",
        "low",
    ]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("already exists"), "{stderr}");
}

#[test]
fn refuses_a_directory_that_is_not_a_repository() {
    let root = TempDir::new().expect("root");

    let (code, _, stderr) = run(&["install-hook", &root.path().display().to_string()]);

    assert_eq!(code, Some(2));
    assert!(stderr.contains("Not a Git repository"), "{stderr}");
}

#[test]
fn reports_where_it_installed_the_hook() {
    let (_root, path) = repository();

    let (code, stdout, stderr) = run(&["install-hook", &path.display().to_string(), "--json"]);

    assert_eq!(code, Some(0), "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(
        report["hook"],
        path.join(".git/hooks/pre-commit").display().to_string()
    );
    assert_eq!(report["failOnSeverity"], "high");
}
