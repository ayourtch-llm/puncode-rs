//! Behavior tests for trusted executable resolution.
//!
//! Upstream's `tests-ts/trusted-executable.test.ts` covers only the Windows
//! branch (it re-spawns Node with `process.platform` faked), so the Unix
//! behavior — the branch that actually runs here — is tested from scratch.
//!
//! The security property under test: nothing the scanned repository controls
//! may be selected or left on `PATH`.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use codex_security::trusted_executable::{TrustedExecutable, resolve_trusted_executable};
use tempfile::TempDir;

fn executable_file(dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("create directory");
    let path = dir.join(name);
    fs::write(&path, "#!/bin/sh\ntrue\n").expect("write file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

fn plain_file(dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("create directory");
    let path = dir.join(name);
    fs::write(&path, "not executable\n").expect("write file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    path
}

fn environment(path_entries: &[&Path]) -> BTreeMap<String, String> {
    let joined = path_entries
        .iter()
        .map(|entry| entry.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    BTreeMap::from([
        ("PATH".to_owned(), joined),
        ("KEEP".to_owned(), "ok".to_owned()),
    ])
}

fn resolved_path(resolved: &TrustedExecutable) -> Vec<PathBuf> {
    resolved.environment["PATH"]
        .split(':')
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[test]
fn resolves_a_candidate_from_the_path() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    let git = executable_file(&bin, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&bin]), &repository)
        .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&git).expect("canonical")
    );
    assert_eq!(resolved.environment["KEEP"], "ok");
}

#[test]
fn prefers_the_first_matching_path_entry() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let first = root.path().join("first");
    let second = root.path().join("second");
    let preferred = executable_file(&first, "git");
    executable_file(&second, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&first, &second]), &repository)
        .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&preferred).expect("canonical")
    );
}

// The core security property: a binary inside the repository is never chosen.
#[test]
fn refuses_an_executable_inside_the_protected_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    let hostile = repository.join("bin");
    executable_file(&hostile, "git");
    let trusted = root.path().join("trusted");
    let real = executable_file(&trusted, "git");

    let resolved =
        resolve_trusted_executable("git", &environment(&[&hostile, &trusted]), &repository)
            .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&real).expect("canonical")
    );
    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&trusted).expect("canonical")],
        "a repository directory must not survive on PATH"
    );
}

#[test]
fn returns_nothing_when_only_the_repository_provides_the_candidate() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    let hostile = repository.join("bin");
    executable_file(&hostile, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&hostile]), &repository);

    assert!(resolved.is_none());
}

// A directory outside the repository is still untrustworthy if it links back
// into it, so the whole entry is dropped from the sanitized PATH.
#[test]
fn drops_path_entries_whose_candidate_links_into_the_protected_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    let hostile = executable_file(&repository, "evil");
    let shimmed = root.path().join("shimmed");
    fs::create_dir(&shimmed).expect("create shimmed");
    std::os::unix::fs::symlink(&hostile, shimmed.join("git")).expect("symlink into repository");
    let trusted = root.path().join("trusted");
    let real = executable_file(&trusted, "git");

    let resolved =
        resolve_trusted_executable("git", &environment(&[&shimmed, &trusted]), &repository)
            .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&real).expect("canonical")
    );
    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&trusted).expect("canonical")],
        "the shimmed directory must be stripped from PATH"
    );
}

// A PATH entry that is itself a symlink into the repository is excluded.
#[test]
fn excludes_a_path_entry_symlinked_into_the_protected_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    let hostile = repository.join("bin");
    executable_file(&hostile, "git");
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&hostile, &linked).expect("symlink directory");
    let trusted = root.path().join("trusted");
    executable_file(&trusted, "git");

    let resolved =
        resolve_trusted_executable("git", &environment(&[&linked, &trusted]), &repository)
            .expect("git resolves");

    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&trusted).expect("canonical")]
    );
}

#[test]
fn skips_relative_and_empty_path_entries() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    executable_file(&bin, "git");
    let mut env = environment(&[&bin]);
    env.insert(
        "PATH".to_owned(),
        format!("::relative/bin:{}", bin.to_string_lossy()),
    );

    let resolved = resolve_trusted_executable("git", &env, &repository).expect("git resolves");

    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&bin).expect("canonical")],
        "relative and empty entries must not survive"
    );
}

#[test]
fn skips_files_without_an_execute_bit() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let first = root.path().join("first");
    plain_file(&first, "git");
    let second = root.path().join("second");
    let real = executable_file(&second, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&first, &second]), &repository)
        .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&real).expect("canonical")
    );
}

#[test]
fn skips_a_directory_named_like_the_candidate() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let first = root.path().join("first");
    fs::create_dir_all(first.join("git")).expect("create directory named git");
    let second = root.path().join("second");
    let real = executable_file(&second, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&first, &second]), &repository)
        .expect("git resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&real).expect("canonical")
    );
}

#[test]
fn resolves_a_path_like_candidate_without_searching_path() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    let git = executable_file(&bin, "git");

    let resolved = resolve_trusted_executable(
        &git.to_string_lossy(),
        &environment(&[Path::new("/nonexistent")]),
        &repository,
    )
    .expect("an explicit path resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&git).expect("canonical")
    );
}

#[test]
fn refuses_a_path_like_candidate_inside_the_protected_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    let hostile = executable_file(&repository, "git");

    let resolved =
        resolve_trusted_executable(&hostile.to_string_lossy(), &environment(&[]), &repository);

    assert!(
        resolved.is_none(),
        "an explicit repository path must be refused"
    );
}

#[test]
fn returns_nothing_when_the_candidate_is_missing() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    fs::create_dir(&bin).expect("create bin");

    assert!(resolve_trusted_executable("git", &environment(&[&bin]), &repository).is_none());
}

// The sanitized environment must carry exactly one PATH, whatever case the
// caller used.
#[test]
fn replaces_the_path_variable_regardless_of_case() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    executable_file(&bin, "git");
    let env = BTreeMap::from([
        ("Path".to_owned(), bin.to_string_lossy().into_owned()),
        ("KEEP".to_owned(), "ok".to_owned()),
    ]);

    let resolved = resolve_trusted_executable("git", &env, &repository).expect("git resolves");

    assert!(
        !resolved.environment.contains_key("Path"),
        "original casing must be dropped"
    );
    assert_eq!(resolved.environment["KEEP"], "ok");
    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&bin).expect("canonical")]
    );
}

#[test]
fn deduplicates_repeated_path_entries() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repository");
    fs::create_dir(&repository).expect("create repository");
    let bin = root.path().join("bin");
    executable_file(&bin, "git");
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&bin, &linked).expect("symlink");

    let resolved =
        resolve_trusted_executable("git", &environment(&[&bin, &linked, &bin]), &repository)
            .expect("git resolves");

    assert_eq!(
        resolved_path(&resolved),
        vec![fs::canonicalize(&bin).expect("canonical")],
        "entries resolving to the same directory collapse"
    );
}

#[test]
fn resolves_when_the_protected_root_does_not_exist() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("missing-repository");
    let bin = root.path().join("bin");
    let git = executable_file(&bin, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&bin]), &repository)
        .expect("a missing protected root still resolves");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&git).expect("canonical")
    );
}

// A sibling directory sharing a name prefix with the repository is not inside
// it: containment is by path component, not string prefix.
#[test]
fn does_not_treat_a_name_prefixed_sibling_as_inside_the_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repo");
    fs::create_dir(&repository).expect("create repository");
    let sibling = root.path().join("repo-tools");
    let git = executable_file(&sibling, "git");

    let resolved = resolve_trusted_executable("git", &environment(&[&sibling]), &repository)
        .expect("sibling directory is trustworthy");

    assert_eq!(
        resolved.executable,
        fs::canonicalize(&git).expect("canonical")
    );
}

// A nonexistent protected root must still exclude what it names. `..` has to
// be collapsed, or a root like `/a/b/../c` would fail to match paths under
// `/a/c` and everything there would look trustworthy.
#[test]
fn collapses_parent_segments_in_a_missing_protected_root() {
    let root = TempDir::new().expect("temp dir");
    let repository = root.path().join("repo");
    let hostile = repository.join("bin");
    executable_file(&hostile, "git");
    // Names the same directory by an indirect route that does not exist as
    // written, forcing the lexical fallback.
    let indirect = root.path().join("missing").join("..").join("repo");

    let resolved = resolve_trusted_executable("git", &environment(&[&hostile]), &indirect);

    assert!(
        resolved.is_none(),
        "an indirectly named repository must still be refused"
    );
}
