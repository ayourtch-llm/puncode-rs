//! Behavior tests for scan target normalization.
//!
//! Ported from `tests-ts/targets.test.ts`. These drive real `git`, so they are
//! skipped when git is unavailable.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use codex_security::targets::{
    DiffTarget, NormalizedTargetKind, ProcessEnvironment, ScanMode, ScanTarget,
    enclosing_git_worktree_root, normalize_repository, normalize_target, process_environment,
    repository_revision, resolve_repository_path, validate_mode, validated_git_environment,
};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(output.status.success(), "git {args:?} failed: {output:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A committed repository, plus the temp dir keeping it alive.
fn repository() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("temp dir");
    let repo = fs::canonicalize(root.path())
        .expect("canonical root")
        .join("repo");
    fs::create_dir_all(repo.join("src")).expect("create src");
    fs::write(repo.join("src").join("app.ts"), "export const ok = true;\n").expect("write file");
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "initial"]);
    (root, repo)
}

fn env() -> ProcessEnvironment {
    process_environment()
}

fn paths(values: &[&str]) -> ScanTarget {
    ScanTarget::Paths(values.iter().map(|value| (*value).to_owned()).collect())
}

#[test]
fn normalizes_a_repository_target() {
    let (_root, repo) = repository();

    let normalized = normalize_target(&repo.to_string_lossy(), &ScanTarget::Repository, &env())
        .expect("normalize");

    assert_eq!(normalized.kind, Some(NormalizedTargetKind::Repository));
    assert!(normalized.paths.is_empty());
}

#[test]
fn normalizes_relative_and_absolute_path_targets() {
    let (_root, repo) = repository();
    let absolute = repo.join("src").join("app.ts");

    let normalized = normalize_target(
        &repo.to_string_lossy(),
        &paths(&["src", &absolute.to_string_lossy()]),
        &env(),
    )
    .expect("normalize");

    assert_eq!(normalized.kind, Some(NormalizedTargetKind::Paths));
    assert_eq!(normalized.paths, vec!["src", "src/app.ts"]);
}

#[test]
fn deduplicates_repeated_paths() {
    let (_root, repo) = repository();
    let absolute = repo.join("src");

    let normalized = normalize_target(
        &repo.to_string_lossy(),
        &paths(&["src", &absolute.to_string_lossy(), "./src"]),
        &env(),
    )
    .expect("normalize");

    assert_eq!(normalized.paths, vec!["src"]);
}

#[test]
fn normalizes_the_repository_root_as_a_path_target() {
    let (_root, repo) = repository();

    let normalized =
        normalize_target(&repo.to_string_lossy(), &paths(&["."]), &env()).expect("normalize");

    assert_eq!(normalized.paths, vec!["."]);
}

#[test]
fn rejects_an_empty_path() {
    let (_root, repo) = repository();

    let error = normalize_target(&repo.to_string_lossy(), &paths(&[""]), &env())
        .expect_err("empty path is rejected");

    assert!(error.to_string().contains("empty path"), "{error}");
}

#[test]
fn rejects_an_empty_path_list() {
    let (_root, repo) = repository();

    let error = normalize_target(
        &repo.to_string_lossy(),
        &ScanTarget::Paths(Vec::new()),
        &env(),
    )
    .expect_err("an empty list is rejected");

    assert!(error.to_string().contains("at least one path"), "{error}");
}

#[test]
fn rejects_a_path_outside_the_repository() {
    let (_root, repo) = repository();
    let outside = repo.join("..");

    let error = normalize_target(
        &repo.to_string_lossy(),
        &paths(&[&outside.to_string_lossy()]),
        &env(),
    )
    .expect_err("escaping path is rejected");

    assert!(
        error.to_string().contains("outside the repository"),
        "{error}"
    );
}

// A symlink that leaves the repository is resolved before the containment
// check, so it cannot be used to smuggle a path in.
#[test]
fn rejects_a_symlink_escaping_the_repository() {
    let (root, repo) = repository();
    let outside = fs::canonicalize(root.path())
        .expect("canonical")
        .join("outside");
    fs::create_dir(&outside).expect("create outside");
    std::os::unix::fs::symlink(&outside, repo.join("escape")).expect("symlink");

    let error = normalize_target(&repo.to_string_lossy(), &paths(&["escape"]), &env())
        .expect_err("escaping symlink is rejected");

    assert!(
        error.to_string().contains("outside the repository"),
        "{error}"
    );
}

#[test]
fn rejects_a_missing_path() {
    let (_root, repo) = repository();

    let error = normalize_target(&repo.to_string_lossy(), &paths(&["nope.ts"]), &env())
        .expect_err("missing path is rejected");

    assert!(error.to_string().contains("does not exist"), "{error}");
}

#[test]
fn rejects_a_repository_that_is_not_a_directory() {
    let (_root, repo) = repository();
    let file = repo.join("src").join("app.ts");

    let error = normalize_repository(&file.to_string_lossy(), &env())
        .expect_err("a file is not a repository");

    assert!(
        error.to_string().contains("Repository is not a directory"),
        "{error}"
    );
}

#[test]
fn binds_ref_targets_to_commit_ids() {
    let (_root, repo) = repository();
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    let target = ScanTarget::Diff(DiffTarget::refs("HEAD", None).expect("refs target"));

    let normalized = normalize_target(&repo.to_string_lossy(), &target, &env()).expect("normalize");

    assert_eq!(normalized.kind, Some(NormalizedTargetKind::Refs));
    assert_eq!(normalized.base.as_deref(), Some(revision.as_str()));
    assert_eq!(normalized.head.as_deref(), Some(revision.as_str()));
    assert_eq!(normalized.base_ref.as_deref(), Some("HEAD"));
    assert_eq!(normalized.head_ref.as_deref(), Some("HEAD"));
}

#[test]
fn binds_working_tree_targets_to_commit_ids() {
    let (_root, repo) = repository();
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    let target = ScanTarget::Diff(DiffTarget::working_tree(None).expect("working tree target"));

    let normalized = normalize_target(&repo.to_string_lossy(), &target, &env()).expect("normalize");

    assert_eq!(normalized.kind, Some(NormalizedTargetKind::WorkingTree));
    assert_eq!(normalized.base.as_deref(), Some(revision.as_str()));
    assert_eq!(normalized.head.as_deref(), Some(revision.as_str()));
    assert_eq!(normalized.head_ref.as_deref(), Some("HEAD"));
}

#[test]
fn rejects_an_unknown_ref() {
    let (_root, repo) = repository();
    let target = ScanTarget::Diff(
        DiffTarget::refs("missing", Some("HEAD".to_owned())).expect("refs target"),
    );

    let error = normalize_target(&repo.to_string_lossy(), &target, &env())
        .expect_err("unknown ref is rejected");

    assert!(
        error.to_string().contains("unknown Git ref: missing"),
        "{error}"
    );
}

#[test]
fn keeps_the_requested_base_and_head_when_refs_diverge() {
    let (_root, repo) = repository();
    git(&repo, &["checkout", "-b", "feature"]);
    fs::write(
        repo.join("src").join("feature.ts"),
        "export const feature = true;\n",
    )
    .expect("write");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "feature"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    git(&repo, &["checkout", "main"]);
    fs::write(
        repo.join("src").join("upstream.ts"),
        "export const upstream = true;\n",
    )
    .expect("write");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "upstream"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);

    let target = ScanTarget::Diff(
        DiffTarget::refs("main", Some("feature".to_owned())).expect("refs target"),
    );
    let normalized = normalize_target(&repo.to_string_lossy(), &target, &env()).expect("normalize");

    assert_eq!(normalized.base.as_deref(), Some(base.as_str()));
    assert_eq!(normalized.head.as_deref(), Some(head.as_str()));
    assert_eq!(normalized.base_ref.as_deref(), Some("main"));
    assert_eq!(normalized.head_ref.as_deref(), Some("feature"));
}

// A diff resolved from a subdirectory would silently widen to the whole
// worktree, so it must be refused.
#[test]
fn requires_the_git_worktree_root_for_diffs() {
    let (_root, repo) = repository();
    let subdirectory = repo.join("src");
    let target = ScanTarget::Diff(DiffTarget::refs("HEAD", None).expect("refs target"));

    let error = normalize_target(&subdirectory.to_string_lossy(), &target, &env())
        .expect_err("a subdirectory is rejected");

    assert!(error.to_string().contains("Git worktree root"), "{error}");
}

#[test]
fn rejects_a_diff_outside_a_git_repository() {
    let root = TempDir::new().expect("temp dir");
    let target = ScanTarget::Diff(DiffTarget::refs("HEAD", None).expect("refs target"));

    let error = normalize_target(&root.path().to_string_lossy(), &target, &env())
        .expect_err("a non-repository is rejected");

    assert!(
        error.to_string().contains("require a Git repository"),
        "{error}"
    );
}

#[test]
fn validates_diff_target_construction() {
    assert!(
        DiffTarget::refs("", None)
            .expect_err("empty base")
            .to_string()
            .contains("base ref")
    );
    assert!(
        DiffTarget::refs("HEAD", Some(String::new()))
            .expect_err("empty head")
            .to_string()
            .contains("head ref")
    );
    assert!(
        DiffTarget::working_tree(Some(String::new()))
            .expect_err("empty base")
            .to_string()
            .contains("base ref")
    );
    // Defaults match upstream.
    assert_eq!(
        DiffTarget::refs("main", None).expect("refs").head(),
        Some("HEAD")
    );
    assert_eq!(
        DiffTarget::working_tree(None).expect("working tree").base(),
        "HEAD"
    );
    assert_eq!(
        DiffTarget::working_tree(None).expect("working tree").head(),
        None
    );
}

#[test]
fn rejects_deep_mode_for_diff_targets() {
    let (_root, repo) = repository();
    let target = ScanTarget::Diff(DiffTarget::refs("HEAD", None).expect("refs target"));
    let normalized = normalize_target(&repo.to_string_lossy(), &target, &env()).expect("normalize");

    let error = validate_mode(&normalized, ScanMode::Deep).expect_err("deep is rejected");

    assert!(
        error
            .to_string()
            .contains("Deep mode supports repository and path targets only")
    );
    assert!(validate_mode(&normalized, ScanMode::Standard).is_ok());
}

#[test]
fn allows_deep_mode_for_repository_and_path_targets() {
    let (_root, repo) = repository();
    let repository_target =
        normalize_target(&repo.to_string_lossy(), &ScanTarget::Repository, &env())
            .expect("normalize");
    let path_target =
        normalize_target(&repo.to_string_lossy(), &paths(&["src"]), &env()).expect("normalize");

    assert!(validate_mode(&repository_target, ScanMode::Deep).is_ok());
    assert!(validate_mode(&path_target, ScanMode::Deep).is_ok());
}

#[test]
fn reports_the_repository_revision() {
    let (_root, repo) = repository();
    let expected = git(&repo, &["rev-parse", "HEAD"]);

    assert_eq!(repository_revision(&repo, &env()), Some(expected));
}

#[test]
fn reports_no_revision_outside_a_repository() {
    let root = TempDir::new().expect("temp dir");

    assert_eq!(repository_revision(root.path(), &env()), None);
}

#[test]
fn finds_the_enclosing_worktree_root_from_a_subdirectory() {
    let (_root, repo) = repository();

    let found = enclosing_git_worktree_root(&repo.join("src"), &env());

    assert_eq!(found, Some(repo.clone()));
}

#[test]
fn finds_no_worktree_root_outside_a_repository() {
    let root = TempDir::new().expect("temp dir");

    assert_eq!(enclosing_git_worktree_root(root.path(), &env()), None);
}

#[test]
fn rejects_redirecting_git_environment_variables() {
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_REPLACE_REF_BASE",
    ] {
        let environment = ProcessEnvironment::from([(name.to_owned(), "/elsewhere".to_owned())]);

        let error = validated_git_environment(&environment).expect_err("{name} is rejected");

        assert!(error.to_string().contains(name), "{error}");
    }
}

#[test]
fn accepts_blank_and_unrelated_git_environment_variables() {
    let environment = ProcessEnvironment::from([
        ("GIT_DIR".to_owned(), "   ".to_owned()),
        ("GIT_AUTHOR_NAME".to_owned(), "Test".to_owned()),
        ("PATH".to_owned(), "/usr/bin".to_owned()),
    ]);

    assert!(validated_git_environment(&environment).is_ok());
}

#[test]
fn expands_a_home_relative_repository_path() {
    let root = TempDir::new().expect("temp dir");
    let home = fs::canonicalize(root.path()).expect("canonical");
    let project = home.join("project");
    fs::create_dir(&project).expect("create project");
    let environment =
        ProcessEnvironment::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);

    for value in ["~/project", "~//project", "~///project"] {
        assert_eq!(
            normalize_repository(value, &environment).expect("normalize"),
            project,
            "{value} should anchor under the home directory"
        );
    }
    assert_eq!(
        normalize_repository("~", &environment).expect("normalize"),
        home
    );
}

#[test]
fn resolves_a_relative_repository_path_against_the_current_directory() {
    let environment = env();

    let resolved = resolve_repository_path("./somewhere/../elsewhere", &environment);

    assert!(resolved.is_absolute());
    assert!(resolved.ends_with("elsewhere"), "{resolved:?}");
}

// The security property carried over from trusted-executable: a `git` shim
// committed inside the repository must never be executed, even when it is
// first on PATH.
#[test]
fn does_not_execute_a_repository_local_git_shim() {
    let (root, repo) = repository();
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    let marker = fs::canonicalize(root.path())
        .expect("canonical")
        .join("git-executed");
    let unsafe_bin = repo.join("node_modules").join(".bin");
    fs::create_dir_all(&unsafe_bin).expect("create shim directory");
    let shim = unsafe_bin.join("git");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\nprintf 'executed\\n' > '{}'\nprintf 'malicious\\n'\n",
            marker.display()
        ),
    )
    .expect("write shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("chmod");
    let linked_bin = fs::canonicalize(root.path())
        .expect("canonical")
        .join("linked-bin");
    std::os::unix::fs::symlink(&unsafe_bin, &linked_bin).expect("symlink shim directory");

    let mut environment = env();
    let inherited = environment.get("PATH").cloned().unwrap_or_default();
    environment.insert(
        "PATH".to_owned(),
        format!(
            "{}:{}:node_modules/.bin::{inherited}",
            unsafe_bin.to_string_lossy(),
            linked_bin.to_string_lossy()
        ),
    );

    let reported = repository_revision(&repo, &environment);

    assert_eq!(reported, Some(revision), "the real git must be used");
    assert!(!marker.exists(), "the repository shim must never run");
}

// Even when scanning a subdirectory, the whole worktree is untrusted.
#[test]
fn does_not_execute_a_worktree_local_shim_when_scanning_a_subdirectory() {
    let (_root, repo) = repository();
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    let marker = repo.join("git-executed");
    let unsafe_bin = repo.join("node_modules").join(".bin");
    fs::create_dir_all(&unsafe_bin).expect("create shim directory");
    let shim = unsafe_bin.join("git");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\nprintf 'executed\\n' > '{}'\nprintf 'malicious\\n'\n",
            marker.display()
        ),
    )
    .expect("write shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("chmod");

    let mut environment = env();
    let inherited = environment.get("PATH").cloned().unwrap_or_default();
    environment.insert(
        "PATH".to_owned(),
        format!("{}:{inherited}", unsafe_bin.to_string_lossy()),
    );

    let target = repo.join("src");
    assert_eq!(
        enclosing_git_worktree_root(&target, &environment),
        Some(repo.clone())
    );
    assert_eq!(repository_revision(&target, &environment), Some(revision));
    assert!(!marker.exists(), "the worktree shim must never run");
}

// Git variables must not leak into the subprocess, or they would redirect it
// away from the repository under scan.
#[test]
fn strips_git_variables_before_running_git() {
    let (_root, repo) = repository();
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    let mut environment = env();
    environment.insert("GIT_DIR".to_owned(), "/nonexistent/git-dir".to_owned());
    environment.insert(
        "GIT_WORK_TREE".to_owned(),
        "/nonexistent/worktree".to_owned(),
    );

    assert_eq!(repository_revision(&repo, &environment), Some(revision));
}

#[test]
fn reports_no_revision_when_git_is_unavailable() {
    let (_root, repo) = repository();
    let environment = ProcessEnvironment::from([("PATH".to_owned(), String::new())]);

    assert_eq!(repository_revision(&repo, &environment), None);
}

#[test]
fn environment_snapshot_is_not_empty() {
    let environment = process_environment();

    assert!(!environment.is_empty());
    assert!(environment.contains_key("PATH"), "PATH should be present");
}

#[test]
fn scan_mode_and_kind_render_their_wire_values() {
    assert_eq!(ScanMode::Standard.as_str(), "standard");
    assert_eq!(ScanMode::Deep.as_str(), "deep");
    assert_eq!(NormalizedTargetKind::WorkingTree.as_str(), "working_tree");
    assert_eq!(NormalizedTargetKind::Repository.as_str(), "repository");
}
