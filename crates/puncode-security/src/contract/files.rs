//! Opening scan files without letting the scan directory change underneath.
//!
//! Ported from the file-access half of `src/contract.ts`.
//!
//! A scan directory is written by a plugin operating on an untrusted
//! repository, and it is read after the fact. Between checking a path and
//! reading it, anything could swap a component for a symlink pointing
//! elsewhere. Every read here therefore:
//!
//! * resolves and pins the scan root by device and inode,
//! * refuses any symlink among the path's components,
//! * opens with `O_NOFOLLOW`, and
//! * re-verifies the opened file and every parent against the identities
//!   recorded before the open.
//!
//! The path itself must also be a plain scan-relative POSIX path, so a
//! manifest cannot name something outside the directory in the first place.

#![allow(dead_code)]

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// A scan directory, pinned to the identity it had when it was checked.
#[derive(Debug)]
pub(crate) struct ScanRoot {
    pub(crate) path: PathBuf,
    pub(crate) metadata: Metadata,
}

/// A file verified to live inside the scan directory, with the identities of
/// every directory leading to it.
#[derive(Debug)]
pub(crate) struct CheckedScanFile {
    pub(crate) path: PathBuf,
    pub(crate) metadata: Metadata,
    pub(crate) parents: Vec<(PathBuf, Metadata)>,
}

/// Whether two metadata snapshots describe the same filesystem object.
#[cfg(unix)]
pub(crate) fn same_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Without inode identity there is nothing to compare, so only the type checks
/// apply.
#[cfg(not(unix))]
pub(crate) fn same_object(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

fn is_plain_directory(metadata: &Metadata) -> bool {
    metadata.is_dir() && !metadata.is_symlink()
}

fn is_plain_file(metadata: &Metadata) -> bool {
    metadata.is_file() && !metadata.is_symlink()
}

/// Resolves `scan_directory` and pins it, refusing a symlinked directory.
///
/// The directory is stat'd before and after resolution, and the resolved path
/// is stat'd too: all three must describe the same plain directory.
pub(crate) fn require_scan_root(scan_directory: &Path) -> Result<ScanRoot> {
    let unusable =
        || Error::contract_validation("Scan directory must be an existing non-symlink directory.");

    let absolute = std::path::absolute(scan_directory).map_err(|_| unusable())?;
    let metadata = std::fs::symlink_metadata(&absolute).map_err(|_| unusable())?;
    let canonical = std::fs::canonicalize(&absolute).map_err(|_| unusable())?;
    let current = std::fs::symlink_metadata(&absolute).map_err(|_| unusable())?;
    let returned = std::fs::symlink_metadata(&canonical).map_err(|_| unusable())?;

    if !is_plain_directory(&metadata)
        || !is_plain_directory(&current)
        || !is_plain_directory(&returned)
        || !same_object(&metadata, &current)
        || !same_object(&metadata, &returned)
    {
        return Err(unusable());
    }

    Ok(ScanRoot {
        path: canonical,
        metadata: returned,
    })
}

/// Confirms the scan directory is still the one that was pinned.
pub(crate) fn verify_scan_root(root: &ScanRoot) -> Result<()> {
    let changed = || {
        Error::contract_validation("Scan directory changed while reading the canonical contract.")
    };
    let current = std::fs::symlink_metadata(&root.path).map_err(|_| changed())?;
    if !is_plain_directory(&current) || !same_object(&current, &root.metadata) {
        return Err(changed());
    }
    Ok(())
}

/// Accepts only a plain scan-relative POSIX path.
///
/// Absolute paths, drive letters, backslashes, `..` segments, embedded NULs and
/// colons are all refused before any filesystem access happens.
pub(crate) fn safe_relative_path(value: &str, context: &str) -> Result<String> {
    let unsafe_path = || {
        Error::contract_validation(format!(
            "{context}: expected a safe scan-relative POSIX path."
        ))
    };

    let parts: Vec<&str> = value.split('/').collect();
    let drive_letter = {
        let mut characters = value.chars();
        matches!(characters.next(), Some(first) if first.is_ascii_alphabetic())
            && characters.next() == Some(':')
    };
    if value.is_empty()
        || value == "."
        || value.starts_with('/')
        || drive_letter
        || parts.contains(&"..")
        || value.contains('\\')
        || value.contains('\0')
        || parts.iter().any(|part| part.contains(':'))
    {
        return Err(unsafe_path());
    }

    // Collapse `.` and repeated separators, matching `posix.normalize`.
    let normalized = parts
        .iter()
        .filter(|part| !part.is_empty() && **part != ".")
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() || normalized.starts_with("../") || normalized.starts_with('/') {
        return Err(unsafe_path());
    }
    Ok(normalized)
}

/// Scope paths may name the repository root, which is otherwise not a legal
/// relative path.
pub(crate) fn safe_scope_path(value: &str) -> Result<String> {
    if value == "." {
        return Ok(value.to_owned());
    }
    safe_relative_path(value, "manifest scope include path")
}

/// Resolves `relative_path` inside the scan directory, refusing symlinks
/// anywhere along the way.
pub(crate) fn require_checked_scan_file(
    scan_directory: &Path,
    relative_path: &str,
    context: &str,
    expected_root: Option<&ScanRoot>,
) -> Result<CheckedScanFile> {
    let outside = || {
        Error::contract_validation(format!(
            "{context}: expected a file inside the scan directory."
        ))
    };

    let checked_root = require_scan_root(scan_directory).map_err(|_| outside())?;
    let safe_path = safe_relative_path(relative_path, context)?;

    // A caller reading several documents pins the root once; a directory that
    // changed identity between reads invalidates the whole contract.
    if let Some(expected) = expected_root
        && (checked_root.path != expected.path
            || !same_object(&checked_root.metadata, &expected.metadata))
    {
        return Err(outside());
    }
    if !is_plain_directory(&checked_root.metadata) {
        return Err(outside());
    }

    let parts: Vec<&str> = safe_path.split('/').collect();
    let mut parents = vec![(checked_root.path.clone(), checked_root.metadata)];
    let mut current = checked_root.path.clone();
    for part in &parts[..parts.len() - 1] {
        current = current.join(part);
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| outside())?;
        if !is_plain_directory(&metadata) {
            return Err(outside());
        }
        parents.push((current.clone(), metadata));
    }

    let path = checked_root.path.join(&safe_path);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| outside())?;
    if !is_plain_file(&metadata) {
        return Err(Error::contract_validation(format!(
            "{context}: expected a regular non-symlink file."
        )));
    }
    let canonical = std::fs::canonicalize(&path).map_err(|_| outside())?;
    if !canonical.starts_with(&checked_root.path) {
        return Err(outside());
    }

    Ok(CheckedScanFile {
        path,
        metadata,
        parents,
    })
}

/// Opens a checked file, confirming nothing was swapped between the check and
/// the open.
pub(crate) fn open_checked_scan_file(
    scan_directory: &Path,
    relative_path: &str,
    context: &str,
    expected_root: Option<&ScanRoot>,
) -> Result<File> {
    let checked = require_checked_scan_file(scan_directory, relative_path, context, expected_root)?;

    let file = open_no_follow(&checked.path).map_err(|error| {
        Error::contract_validation(format!(
            "{context}: unable to open the checked regular file."
        ))
        .with_source(error)
    })?;

    let opened = file.metadata().map_err(|error| {
        Error::contract_validation(format!(
            "{context}: unable to open the checked regular file."
        ))
        .with_source(error)
    })?;
    if !opened.is_file() || !same_object(&opened, &checked.metadata) {
        return Err(Error::contract_validation(format!(
            "{context}: expected the checked regular file."
        )));
    }

    for (path, metadata) in &checked.parents {
        let current = std::fs::symlink_metadata(path).map_err(|error| {
            Error::contract_validation(format!(
                "{context}: checked parent changed before opening the file."
            ))
            .with_source(error)
        })?;
        if !is_plain_directory(&current) || !same_object(&current, metadata) {
            return Err(Error::contract_validation(format!(
                "{context}: checked parent changed before opening the file."
            )));
        }
    }

    let current = std::fs::symlink_metadata(&checked.path).map_err(|error| {
        Error::contract_validation(format!("{context}: checked file changed before reading."))
            .with_source(error)
    })?;
    if !is_plain_file(&current) || !same_object(&current, &checked.metadata) {
        return Err(Error::contract_validation(format!(
            "{context}: checked file changed before reading."
        )));
    }

    Ok(file)
}

/// Opens a file without following a final symlink.
#[cfg(unix)]
pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    Ok(File::from(fd))
}

/// Windows has no `O_NOFOLLOW`; the preceding `lstat` checks carry the weight.
#[cfg(not(unix))]
pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// The SHA-256 of a checked scan file, as lowercase hex.
pub(crate) fn sha256_scan_file(
    scan_directory: &Path,
    relative_path: &str,
    context: &str,
    expected_root: Option<&ScanRoot>,
) -> Result<String> {
    let mut file = open_checked_scan_file(scan_directory, relative_path, context, expected_root)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1_024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Error::contract_validation(format!("{context}: unable to read the checked file."))
                .with_source(error)
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

/// The SHA-256 of raw bytes, as lowercase hex.
pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex(&digest.finalize())
}

/// The SHA-256 of a string, as lowercase hex.
pub(crate) fn sha256_text(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    hex(&digest.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn scan_directory() -> (TempDir, PathBuf) {
        let root = TempDir::new().expect("temp dir");
        let scan = std::fs::canonicalize(root.path())
            .expect("canonical")
            .join("scan");
        std::fs::create_dir(&scan).expect("create scan directory");
        std::fs::write(scan.join("findings.json"), b"{}\n").expect("write findings");
        (root, scan)
    }

    #[test]
    fn pins_a_plain_scan_directory() {
        let (_root, scan) = scan_directory();

        let pinned = require_scan_root(&scan).expect("root is usable");

        assert_eq!(pinned.path, scan);
        assert!(verify_scan_root(&pinned).is_ok());
    }

    // Upstream accepts this: only the scan directory itself may not be a
    // symlink, and resolution through a symlinked parent is expected.
    #[test]
    fn accepts_a_scan_directory_beneath_a_symlinked_parent() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let parent = base.join("actual-parent");
        std::fs::create_dir(&parent).expect("create parent");
        std::fs::create_dir(parent.join("scan")).expect("create scan");
        std::os::unix::fs::symlink(&parent, base.join("linked-parent")).expect("symlink parent");

        let pinned = require_scan_root(&base.join("linked-parent").join("scan"))
            .expect("a symlinked parent is fine");

        assert_eq!(pinned.path, parent.join("scan"));
    }

    #[test]
    fn refuses_a_symlinked_scan_directory() {
        let (_root, scan) = scan_directory();
        let linked = scan.parent().expect("parent").join("linked-scan");
        std::os::unix::fs::symlink(&scan, &linked).expect("symlink scan");

        let error = require_scan_root(&linked).expect_err("a symlinked scan root is refused");

        assert_eq!(
            error.to_string(),
            "Scan directory must be an existing non-symlink directory."
        );
    }

    #[test]
    fn refuses_a_missing_or_non_directory_scan_root() {
        let (_root, scan) = scan_directory();

        assert!(require_scan_root(&scan.join("missing")).is_err());
        assert!(require_scan_root(&scan.join("findings.json")).is_err());
    }

    #[test]
    fn notices_a_scan_directory_replaced_after_pinning() {
        let (_root, scan) = scan_directory();
        let pinned = require_scan_root(&scan).expect("root is usable");

        // Build the replacement while the original still exists, so the two
        // cannot share an inode number through reuse.
        let replacement = scan.parent().expect("parent").join("replacement");
        std::fs::create_dir(&replacement).expect("create replacement");
        std::fs::remove_dir_all(&scan).expect("remove");
        std::fs::rename(&replacement, &scan).expect("swap in the replacement");

        let error = verify_scan_root(&pinned).expect_err("a replaced directory is detected");
        assert_eq!(
            error.to_string(),
            "Scan directory changed while reading the canonical contract."
        );
    }

    #[test]
    fn opens_a_checked_file() {
        let (_root, scan) = scan_directory();

        let file =
            open_checked_scan_file(&scan, "findings.json", "findings.json", None).expect("opens");

        assert!(file.metadata().expect("metadata").is_file());
    }

    #[test]
    fn refuses_a_symlinked_document() {
        let (_root, scan) = scan_directory();
        let outside = scan.parent().expect("parent").join("elsewhere.json");
        std::fs::write(&outside, b"{}\n").expect("write outside");
        std::os::unix::fs::symlink(&outside, scan.join("coverage.json")).expect("symlink");

        let error = open_checked_scan_file(&scan, "coverage.json", "coverage.json", None)
            .expect_err("a symlinked document is refused");

        assert_eq!(
            error.to_string(),
            "coverage.json: expected a regular non-symlink file."
        );
    }

    // A symlinked directory component would let a manifest reach outside the
    // scan directory without the leaf itself being a link.
    #[test]
    fn refuses_a_symlinked_parent_component() {
        let (_root, scan) = scan_directory();
        let outside = scan.parent().expect("parent").join("outside");
        std::fs::create_dir(&outside).expect("create outside");
        std::fs::write(outside.join("report.md"), b"# outside\n").expect("write");
        std::os::unix::fs::symlink(&outside, scan.join("artifacts")).expect("symlink directory");

        let error = open_checked_scan_file(&scan, "artifacts/report.md", "artifact", None)
            .expect_err("a symlinked parent is refused");

        assert_eq!(
            error.to_string(),
            "artifact: expected a file inside the scan directory."
        );
    }

    #[test]
    fn refuses_a_document_that_escapes_the_scan_directory() {
        let (_root, scan) = scan_directory();

        for path in ["../outside.json", "/etc/passwd", "a/../../outside.json"] {
            let error = open_checked_scan_file(&scan, path, "artifact", None)
                .expect_err("escaping path is refused");
            assert_eq!(
                error.to_string(),
                "artifact: expected a safe scan-relative POSIX path.",
                "{path}"
            );
        }
    }

    #[test]
    fn refuses_a_root_that_changed_since_it_was_pinned() {
        let (_root, scan) = scan_directory();
        let pinned = require_scan_root(&scan).expect("root is usable");
        // Built alongside the original so inode reuse cannot mask the swap.
        let replacement = scan.parent().expect("parent").join("replacement");
        std::fs::create_dir(&replacement).expect("create replacement");
        std::fs::write(replacement.join("findings.json"), b"{}\n").expect("write");
        std::fs::remove_dir_all(&scan).expect("remove");
        std::fs::rename(&replacement, &scan).expect("swap in the replacement");

        let error = open_checked_scan_file(&scan, "findings.json", "findings.json", Some(&pinned))
            .expect_err("a replaced root is refused");

        assert_eq!(
            error.to_string(),
            "findings.json: expected a file inside the scan directory."
        );
    }

    #[test]
    fn accepts_safe_relative_paths() {
        assert_eq!(
            safe_relative_path("findings.json", "c").expect("ok"),
            "findings.json"
        );
        assert_eq!(
            safe_relative_path("artifacts/a.md", "c").expect("ok"),
            "artifacts/a.md"
        );
        assert_eq!(
            safe_relative_path("artifacts//a.md", "c").expect("ok"),
            "artifacts/a.md"
        );
        assert_eq!(
            safe_relative_path("./artifacts/a.md", "c").expect("ok"),
            "artifacts/a.md"
        );
        assert_eq!(
            safe_relative_path("artifacts/a.md/", "c").expect("ok"),
            "artifacts/a.md"
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        for value in [
            "",
            ".",
            "/absolute",
            "C:/windows",
            "c:relative",
            "../escape",
            "a/../b",
            "a\\b",
            "a:b",
            "artifacts/../../escape",
            "./",
        ] {
            assert!(
                safe_relative_path(value, "context").is_err(),
                "{value:?} should be refused"
            );
        }
        assert!(safe_relative_path("a\0b", "context").is_err());
    }

    #[test]
    fn scope_paths_may_name_the_repository_root() {
        assert_eq!(safe_scope_path(".").expect("ok"), ".");
        assert_eq!(safe_scope_path("src").expect("ok"), "src");
        assert!(safe_scope_path("../src").is_err());
    }

    #[test]
    fn digests_a_checked_file() {
        let (_root, scan) = scan_directory();
        std::fs::write(scan.join("findings.json"), b"abc").expect("write");

        let digest =
            sha256_scan_file(&scan, "findings.json", "findings.json", None).expect("digest");

        // Well-known SHA-256 of "abc".
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digests_text() {
        assert_eq!(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_text(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn refuses_a_directory_where_a_document_is_expected() {
        let (_root, scan) = scan_directory();
        std::fs::create_dir(scan.join("coverage.json")).expect("create directory");

        let error = open_checked_scan_file(&scan, "coverage.json", "coverage.json", None)
            .expect_err("a directory is refused");

        assert_eq!(
            error.to_string(),
            "coverage.json: expected a regular non-symlink file."
        );
    }

    #[test]
    fn refuses_an_unreadable_document() {
        let (_root, scan) = scan_directory();
        let path = scan.join("findings.json");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let opened = open_checked_scan_file(&scan, "findings.json", "findings.json", None);

        // Running as root bypasses the permission bits entirely.
        if !opened.is_ok() {
            assert_eq!(
                opened.expect_err("unreadable").to_string(),
                "findings.json: unable to open the checked regular file."
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("restore");
    }
}
