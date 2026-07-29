//! Unpacking and identifying the Codex Security plugin.
//!
//! Ported from the plugin half of `src/runtime.ts`.
//!
//! The archive is untrusted input, so extraction is bounded in every direction
//! a crafted archive could push: how many members it declares, how large any
//! one of them expands to, how large they expand to together, and where each
//! one is allowed to land. Every extracted file is then checked against the
//! CRC the archive claimed for it, by re-reading it from disk.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::contract::files::{open_no_follow, same_object};
use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, expand_home, lexical_absolute};
use crate::version::BUNDLED_PLUGIN_VERSION;

/// The plugin this SDK drives.
pub const PLUGIN_NAME: &str = "codex-security";

/// The marketplace name the SDK registers the plugin under.
pub const MARKETPLACE_NAME: &str = "codex-security-sdk";

/// Members an archive may declare.
const MAX_ZIP_ENTRIES: usize = 4_096;
/// How large any single member may expand to.
const MAX_ZIP_ENTRY_SIZE: u64 = 128 * 1024 * 1024;
/// How large all members may expand to together.
const MAX_ZIP_EXPANDED_SIZE: u64 = 512 * 1024 * 1024;
/// How large the plugin manifest may be.
const MAX_PLUGIN_MANIFEST_SIZE: u64 = 1024 * 1024;

/// The file-type bits of a Unix mode, and the two types that matter here.
const FILE_TYPE_MASK: u32 = 0o170000;
const FILE_TYPE_SYMLINK: u32 = 0o120000;
const FILE_TYPE_DIRECTORY: u32 = 0o040000;

/// What the plugin says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
}

/// Whether an archive member becomes a directory or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Directory,
    File,
}

/// Accepts only a plain relative POSIX path, and returns it normalized.
///
/// Absolute paths, drive letters, `..` segments, backslashes, NULs and colons
/// are all refused, so no member can be written outside the staging directory.
pub(crate) fn safe_archive_path(value: &str) -> Result<String> {
    let parts: Vec<&str> = value.split('/').collect();
    let normalized = parts
        .iter()
        .filter(|part| !part.is_empty() && **part != ".")
        .copied()
        .collect::<Vec<_>>()
        .join("/");

    let drive_letter = {
        let mut characters = value.chars();
        matches!(characters.next(), Some(first) if first.is_ascii_alphabetic())
            && characters.next() == Some(':')
    };
    if value.is_empty()
        || value.starts_with('/')
        || drive_letter
        || parts.contains(&"..")
        || value.contains('\\')
        || value.contains('\0')
        || parts.iter().any(|part| part.contains(':'))
        || normalized.is_empty()
    {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP contains an unsafe path: {value}"
        )));
    }
    Ok(normalized)
}

/// Applies the per-member limits, recording what has been seen so far.
///
/// Kept separate from extraction so the size limits can be exercised without
/// building a half-gigabyte archive.
pub(crate) fn admit_entry(
    name: &str,
    unix_mode: Option<u32>,
    uncompressed_size: u64,
    seen: &mut BTreeSet<String>,
    expanded_size: &mut u64,
) -> Result<(String, EntryKind)> {
    let path = safe_archive_path(name)?;

    // Case-insensitive, because a filesystem that ignores case would otherwise
    // let one member silently overwrite another.
    if !seen.insert(path.to_lowercase()) {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP contains a duplicate path: {name}"
        )));
    }

    let file_type = unix_mode.map(|mode| mode & FILE_TYPE_MASK);
    if file_type == Some(FILE_TYPE_SYMLINK) {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP contains an unsafe path: {name}"
        )));
    }
    if uncompressed_size > MAX_ZIP_ENTRY_SIZE {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP entry exceeds the safety limit: {name}"
        )));
    }
    *expanded_size += uncompressed_size;
    if *expanded_size > MAX_ZIP_EXPANDED_SIZE {
        return Err(Error::plugin_bootstrap(
            "Plugin ZIP expanded size exceeds the safety limit.",
        ));
    }

    let kind = if name.ends_with('/') || file_type == Some(FILE_TYPE_DIRECTORY) {
        EntryKind::Directory
    } else {
        EntryKind::File
    };
    Ok((path, kind))
}

/// Extracts `archive` into `destination`, returning the plugin root inside it.
///
/// Extraction happens in a staging directory beside the destination and is
/// moved into place only once every member has been checked, so a rejected
/// archive never leaves a partial plugin behind.
pub fn extract_plugin_zip(archive: &Path, destination: &Path) -> Result<PathBuf> {
    let invalid = || Error::plugin_bootstrap(format!("Invalid plugin ZIP: {}", archive.display()));

    super::archive::reject_backslash_zip_names(archive)?;

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".codex-security-plugin-")
        .tempdir_in(parent)
        .map_err(|error| invalid().with_source(error))?
        .keep();
    let staging = std::fs::canonicalize(&staging).map_err(|error| invalid().with_source(error))?;

    let outcome = extract_into(archive, &staging);
    match outcome {
        Ok(relative_root) => {
            std::fs::rename(&staging, destination).map_err(|error| {
                let _ = std::fs::remove_dir_all(&staging);
                invalid().with_source(error)
            })?;
            validate_plugin_root(&destination.join(relative_root))
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

/// Extracts every member into `staging` and returns the plugin root relative
/// to it.
fn extract_into(archive: &Path, staging: &Path) -> Result<PathBuf> {
    let invalid = || Error::plugin_bootstrap(format!("Invalid plugin ZIP: {}", archive.display()));

    let file = std::fs::File::open(archive).map_err(|error| invalid().with_source(error))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|error| invalid().with_source(error))?;
    if zip.len() > MAX_ZIP_ENTRIES {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP contains too many entries: {}.",
            zip.len()
        )));
    }

    let mut seen = BTreeSet::new();
    let mut expanded_size = 0_u64;
    let mut checksums: Vec<(String, u32)> = Vec::new();

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| invalid().with_source(error))?;
        let name = entry.name().to_owned();
        let (path, kind) = admit_entry(
            &name,
            entry.unix_mode(),
            entry.size(),
            &mut seen,
            &mut expanded_size,
        )?;
        let target = staging.join(&path);

        match kind {
            EntryKind::Directory => create_private_dir(&target)?,
            EntryKind::File => {
                if let Some(parent) = target.parent() {
                    create_private_dir(parent)?;
                }
                let mut contents = Vec::new();
                // The reader verifies the CRC as it goes, so a corrupt member
                // fails here rather than at the explicit check below.
                entry.read_to_end(&mut contents).map_err(|error| {
                    if error.to_string().contains("Invalid checksum") {
                        return Error::plugin_bootstrap(format!(
                            "Plugin ZIP entry failed CRC-32 validation: {path}"
                        ));
                    }
                    invalid().with_source(error)
                })?;
                write_private_file(&target, &contents)?;
                checksums.push((path, entry.crc32()));
            }
        }
    }

    // Re-read from disk as well: this covers what was actually written, not
    // just what passed through the reader, and catches a file changed between
    // the write and now.
    for (path, expected) in &checksums {
        let contents =
            std::fs::read(staging.join(path)).map_err(|error| invalid().with_source(error))?;
        if crc32fast::hash(&contents) != *expected {
            return Err(Error::plugin_bootstrap(format!(
                "Plugin ZIP entry failed CRC-32 validation: {path}"
            )));
        }
    }

    let plugin_root = discover_plugin_root(staging)?;
    plugin_root
        .strip_prefix(staging)
        .map(Path::to_path_buf)
        .map_err(|_| invalid())
}

/// Finds the plugin at the archive root, or in its single top-level directory.
fn discover_plugin_root(root: &Path) -> Result<PathBuf> {
    if has_plugin_manifest(root) {
        return validate_plugin_root(root);
    }
    let directories: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|error| {
            Error::plugin_bootstrap("Invalid plugin ZIP: unreadable staging directory.")
                .with_source(error)
        })?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect();
    if directories.len() == 1 && has_plugin_manifest(&directories[0]) {
        return validate_plugin_root(&directories[0]);
    }
    Err(Error::plugin_bootstrap(
        "Plugin ZIP must contain Codex Security at its root or in one top-level directory.",
    ))
}

fn has_plugin_manifest(root: &Path) -> bool {
    root.join(".codex-plugin").join("plugin.json").is_file()
}

/// The plugin shipped with this build, if it ships one.
///
/// Upstream reads the plugin out of its own npm package, which always carries
/// it. This build does not embed the plugin, so a plugin directory or archive
/// must be supplied explicitly; see [`resolve_plugin_path`].
/// The plugin this build ships, unpacked and ready to run.
///
/// The tree under `plugin/` is OpenAI's, redistributed verbatim under the same
/// Apache-2.0 licence and recorded in `NOTICE`; embedding it is what lets a
/// scan run without a separate install step.
pub fn bundled_plugin_root() -> Result<PathBuf> {
    static PLUGIN: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/plugin");

    // Unpacked once per version, beside the rest of Codex Security's state, so
    // repeated commands do not each pay to write 94 files. The version is in
    // the path, so upgrading never reads a stale tree.
    let root = plugin_cache_root()?.join(format!("plugin-{BUNDLED_PLUGIN_VERSION}"));
    let ready = root.join(".unpacked");
    if ready.is_file() {
        return validate_plugin_root(&root);
    }

    // Unpacked beside the destination and moved into place, so a command
    // interrupted halfway through cannot leave a partial tree that a later
    // command would trust.
    let staging = root.with_extension(format!("staging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    create_private_dir(&staging)?;
    PLUGIN.extract(&staging).map_err(|error| {
        let _ = std::fs::remove_dir_all(&staging);
        Error::plugin_bootstrap("Unable to unpack the bundled Codex Security plugin")
            .with_source(error)
    })?;
    std::fs::write(staging.join(".unpacked"), BUNDLED_PLUGIN_VERSION).map_err(|error| {
        Error::plugin_bootstrap("Unable to unpack the bundled Codex Security plugin")
            .with_source(error)
    })?;

    match std::fs::rename(&staging, &root) {
        Ok(()) => {}
        // Another command unpacked it first, which is the same outcome.
        Err(_) if ready.is_file() => {
            let _ = std::fs::remove_dir_all(&staging);
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(Error::plugin_bootstrap(
                "Unable to unpack the bundled Codex Security plugin",
            )
            .with_source(error));
        }
    }
    validate_plugin_root(&root)
}

/// Where the unpacked plugin is kept between commands.
fn plugin_cache_root() -> Result<PathBuf> {
    let base = std::env::home_dir()
        .map(|home| home.join(".codex-security"))
        .unwrap_or_else(std::env::temp_dir)
        .join("bundled");
    create_private_dir(&base)?;
    Ok(base)
}

/// Resolves where the plugin to run actually lives.
///
/// A directory is validated in place; an archive is extracted into the
/// workspace first. Anything else — a symlinked directory, a non-archive file,
/// a missing path — is refused rather than guessed at.
pub fn resolve_plugin_path(
    plugin_path: Option<&str>,
    workspace: &Path,
    environment: &ProcessEnvironment,
) -> Result<PathBuf> {
    let Some(plugin_path) = plugin_path else {
        return bundled_plugin_root();
    };

    let path = lexical_absolute(&expand_home(plugin_path, environment));
    let metadata = std::fs::symlink_metadata(&path).ok();

    if let Some(metadata) = &metadata
        && metadata.is_file()
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        return extract_plugin_zip(&path, &workspace.join("extracted-plugin"));
    }
    if let Some(metadata) = &metadata
        && metadata.is_dir()
        && !metadata.is_symlink()
    {
        return validate_plugin_root(&path);
    }
    Err(Error::plugin_bootstrap(format!(
        "Plugin path must be a directory or ZIP: {}",
        path.display()
    )))
}

/// Confirms a directory really is the plugin, and returns its canonical path.
pub fn validate_plugin_root(root: &Path) -> Result<PathBuf> {
    plugin_metadata(root)?;
    std::fs::canonicalize(root).map_err(|error| {
        Error::plugin_bootstrap(format!(
            "Invalid Codex plugin directory: {}",
            root.display()
        ))
        .with_source(error)
    })
}

/// Reads the plugin manifest, refusing anything that changes while it is read.
pub fn plugin_metadata(root: &Path) -> Result<PluginMetadata> {
    let manifest_path = root.join(".codex-plugin").join("plugin.json");
    let invalid = || {
        Error::plugin_bootstrap(format!(
            "Invalid Codex plugin directory: {}",
            root.display()
        ))
    };

    let expected = std::fs::symlink_metadata(&manifest_path).map_err(|_| invalid())?;
    if !expected.is_file() || expected.is_symlink() || expected.len() > MAX_PLUGIN_MANIFEST_SIZE {
        return Err(invalid());
    }

    let mut input = open_no_follow(&manifest_path).map_err(|_| invalid())?;
    let opened = input.metadata().map_err(|_| invalid())?;
    if !same_object(&expected, &opened) {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).map_err(|_| invalid())?;
    let after = input.metadata().map_err(|_| invalid())?;
    if !same_object(&expected, &after) {
        return Err(invalid());
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    let manifest: serde_json::Value = serde_json::from_str(text).map_err(|_| invalid())?;

    if manifest.get("name").and_then(serde_json::Value::as_str) != Some(PLUGIN_NAME) {
        return Err(Error::plugin_bootstrap(
            "Plugin manifest must have name 'codex-security'.",
        ));
    }
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| Error::plugin_bootstrap("Plugin manifest must have a non-empty version."))?;

    Ok(PluginMetadata {
        name: PLUGIN_NAME.to_owned(),
        version: version.to_owned(),
    })
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to create {}", path.display())).with_source(error)
    })
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to write {}", path.display())).with_source(error)
    })?;
    use std::io::Write;
    file.write_all(contents).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to write {}", path.display())).with_source(error)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    /// Builds an archive from `(name, contents)` pairs.
    fn archive(root: &Path, entries: &[(&str, &str)]) -> PathBuf {
        let path = root.join("plugin.zip");
        let file = std::fs::File::create(&path).expect("create archive");
        let mut writer = zip::ZipWriter::new(file);
        for (name, contents) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .expect("start entry");
            writer.write_all(contents.as_bytes()).expect("write entry");
        }
        writer.finish().expect("finish archive");
        path
    }

    const MANIFEST: &str = r#"{"name":"codex-security","version":"0.1.14"}"#;

    #[test]
    fn extracts_a_plugin_at_the_archive_root() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = archive(
            &base,
            &[
                (".codex-plugin/plugin.json", MANIFEST),
                ("schemas/findings.schema.json", "{}"),
            ],
        );

        let plugin_root = extract_plugin_zip(&path, &base.join("installed")).expect("extracts");

        assert_eq!(plugin_root, base.join("installed"));
        assert!(plugin_root.join("schemas/findings.schema.json").is_file());
        assert_eq!(
            plugin_metadata(&plugin_root).expect("metadata").version,
            "0.1.14"
        );
    }

    #[test]
    fn extracts_a_plugin_nested_in_one_top_level_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = archive(
            &base,
            &[
                ("codex-security/.codex-plugin/plugin.json", MANIFEST),
                ("codex-security/schemas/a.json", "{}"),
            ],
        );

        let plugin_root = extract_plugin_zip(&path, &base.join("installed")).expect("extracts");

        assert_eq!(plugin_root, base.join("installed").join("codex-security"));
    }

    #[test]
    fn refuses_an_archive_without_a_plugin_manifest() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = archive(&base, &[("readme.txt", "nothing here")]);

        let error = extract_plugin_zip(&path, &base.join("installed"))
            .expect_err("an archive without a plugin is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP must contain Codex Security at its root or in one top-level directory."
        );
    }

    // A rejected archive must not leave a partial install behind.
    #[test]
    fn leaves_nothing_behind_when_extraction_fails() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = archive(&base, &[("readme.txt", "nothing here")]);

        let _ = extract_plugin_zip(&path, &base.join("installed"));

        assert!(
            !base.join("installed").exists(),
            "no destination is created"
        );
        let leftovers: Vec<String> = std::fs::read_dir(&base)
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".codex-security-plugin-"))
            .collect();
        assert!(leftovers.is_empty(), "staging remained: {leftovers:?}");
    }

    #[test]
    fn refuses_a_manifest_naming_another_plugin() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = archive(
            &base,
            &[(
                ".codex-plugin/plugin.json",
                r#"{"name":"other","version":"1.0"}"#,
            )],
        );

        let error = extract_plugin_zip(&path, &base.join("installed"))
            .expect_err("a foreign plugin is refused");

        assert_eq!(
            error.to_string(),
            "Plugin manifest must have name 'codex-security'."
        );
    }

    #[test]
    fn refuses_a_manifest_without_a_version() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        for manifest in [
            r#"{"name":"codex-security"}"#,
            r#"{"name":"codex-security","version":""}"#,
            r#"{"name":"codex-security","version":"   "}"#,
            r#"{"name":"codex-security","version":7}"#,
        ] {
            let path = archive(&base, &[(".codex-plugin/plugin.json", manifest)]);
            let destination = base.join(format!("installed-{}", manifest.len()));

            let error = extract_plugin_zip(&path, &destination)
                .expect_err("a versionless manifest is refused");

            assert_eq!(
                error.to_string(),
                "Plugin manifest must have a non-empty version.",
                "{manifest}"
            );
        }
    }

    #[test]
    fn refuses_a_missing_or_unreadable_plugin_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");

        let error = plugin_metadata(&base.join("absent")).expect_err("missing plugin is refused");
        assert!(
            error
                .to_string()
                .starts_with("Invalid Codex plugin directory:")
        );

        // A symlinked manifest is refused even when it points somewhere valid.
        let plugin = base.join("plugin");
        std::fs::create_dir_all(plugin.join(".codex-plugin")).expect("create");
        let real = base.join("real.json");
        std::fs::write(&real, MANIFEST).expect("write");
        std::os::unix::fs::symlink(&real, plugin.join(".codex-plugin/plugin.json"))
            .expect("symlink");

        let error = plugin_metadata(&plugin).expect_err("a symlinked manifest is refused");
        assert!(
            error
                .to_string()
                .starts_with("Invalid Codex plugin directory:")
        );
    }

    // A corrupt member must be named as a checksum failure, not a generic
    // "invalid archive".
    #[test]
    fn reports_a_corrupt_member_as_a_crc_failure() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let path = base.join("plugin.zip");
        {
            let file = std::fs::File::create(&path).expect("create archive");
            let mut writer = zip::ZipWriter::new(file);
            let stored =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer
                .start_file(".codex-plugin/plugin.json", stored)
                .expect("start entry");
            writer.write_all(MANIFEST.as_bytes()).expect("write entry");
            writer.finish().expect("finish archive");
        }
        // Flip a byte of the stored contents so it no longer matches its CRC.
        let mut bytes = std::fs::read(&path).expect("read");
        let position = bytes
            .windows(MANIFEST.len())
            .position(|window| window == MANIFEST.as_bytes())
            .expect("stored contents are present");
        bytes[position + 2] = b'X';
        std::fs::write(&path, &bytes).expect("write");

        let error = extract_plugin_zip(&path, &base.join("installed"))
            .expect_err("a corrupt member is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP entry failed CRC-32 validation: .codex-plugin/plugin.json"
        );
    }

    // --- per-member policy ---

    fn admit(name: &str, mode: Option<u32>, size: u64) -> Result<(String, EntryKind)> {
        let mut seen = BTreeSet::new();
        let mut expanded = 0;
        admit_entry(name, mode, size, &mut seen, &mut expanded)
    }

    #[test]
    fn accepts_ordinary_member_paths() {
        assert_eq!(safe_archive_path("a/b.txt").expect("ok"), "a/b.txt");
        assert_eq!(safe_archive_path("./a//b.txt").expect("ok"), "a/b.txt");
        assert_eq!(safe_archive_path("a/").expect("ok"), "a");
    }

    #[test]
    fn refuses_member_paths_that_could_escape() {
        for name in [
            "",
            "/absolute",
            "//server/share",
            "C:/windows",
            "../escape",
            "a/../b",
            r"a\b",
            "a:b",
            "./",
            ".",
        ] {
            assert!(
                safe_archive_path(name).is_err(),
                "{name:?} should be refused"
            );
        }
        assert!(safe_archive_path("a\0b").is_err());
    }

    #[test]
    fn refuses_a_symlink_member() {
        let error = admit("link", Some(0o120777), 10).expect_err("a symlink is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP contains an unsafe path: link"
        );
    }

    // A case-insensitive filesystem would let one member overwrite another.
    #[test]
    fn refuses_duplicate_members_ignoring_case() {
        let mut seen = BTreeSet::new();
        let mut expanded = 0;
        admit_entry("a/File.txt", None, 1, &mut seen, &mut expanded).expect("first is admitted");

        let error = admit_entry("a/file.txt", None, 1, &mut seen, &mut expanded)
            .expect_err("a case-insensitive duplicate is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP contains a duplicate path: a/file.txt"
        );
    }

    #[test]
    fn refuses_a_member_beyond_the_entry_limit() {
        let error = admit("big.bin", None, MAX_ZIP_ENTRY_SIZE + 1)
            .expect_err("an oversized member is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP entry exceeds the safety limit: big.bin"
        );
        assert!(
            admit("ok.bin", None, MAX_ZIP_ENTRY_SIZE).is_ok(),
            "the limit itself is fine"
        );
    }

    // Individually admissible members must not add up to an unbounded install.
    #[test]
    fn refuses_members_that_expand_too_far_together() {
        let mut seen = BTreeSet::new();
        let mut expanded = 0;
        for index in 0..4 {
            admit_entry(
                &format!("part{index}.bin"),
                None,
                MAX_ZIP_ENTRY_SIZE,
                &mut seen,
                &mut expanded,
            )
            .expect("each part is individually admissible");
        }

        let error = admit_entry(
            "part4.bin",
            None,
            MAX_ZIP_ENTRY_SIZE,
            &mut seen,
            &mut expanded,
        )
        .expect_err("the total is refused");

        assert_eq!(
            error.to_string(),
            "Plugin ZIP expanded size exceeds the safety limit."
        );
    }

    #[test]
    fn classifies_directories_by_name_or_mode() {
        assert_eq!(admit("a/", None, 0).expect("ok").1, EntryKind::Directory);
        assert_eq!(
            admit("b", Some(0o040755), 0).expect("ok").1,
            EntryKind::Directory
        );
        assert_eq!(
            admit("c.txt", Some(0o100644), 5).expect("ok").1,
            EntryKind::File
        );
        assert_eq!(admit("d.txt", None, 5).expect("ok").1, EntryKind::File);
    }
}

#[cfg(all(test, unix))]
mod resolution_tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    const MANIFEST: &str = r#"{"name":"codex-security","version":"0.1.14"}"#;

    fn environment() -> ProcessEnvironment {
        ProcessEnvironment::new()
    }

    fn plugin_directory(base: &Path, name: &str) -> PathBuf {
        let root = base.join(name);
        std::fs::create_dir_all(root.join(".codex-plugin")).expect("create");
        std::fs::write(root.join(".codex-plugin").join("plugin.json"), MANIFEST).expect("write");
        root
    }

    #[test]
    fn resolves_a_plugin_directory() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_directory(&base, "plugin");

        let resolved = resolve_plugin_path(Some(&plugin.to_string_lossy()), &base, &environment())
            .expect("resolves");

        assert_eq!(resolved, plugin);
    }

    #[test]
    fn extracts_a_plugin_archive_into_the_workspace() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let archive = base.join("plugin.zip");
        let file = std::fs::File::create(&archive).expect("create");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(".codex-plugin/plugin.json", SimpleFileOptions::default())
            .expect("start");
        writer.write_all(MANIFEST.as_bytes()).expect("write");
        writer.finish().expect("finish");
        let workspace = base.join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        let resolved =
            resolve_plugin_path(Some(&archive.to_string_lossy()), &workspace, &environment())
                .expect("resolves");

        assert_eq!(resolved, workspace.join("extracted-plugin"));
        assert!(resolved.join(".codex-plugin").join("plugin.json").is_file());
    }

    #[test]
    fn recognizes_an_archive_regardless_of_extension_case() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let archive = base.join("plugin.ZIP");
        let file = std::fs::File::create(&archive).expect("create");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(".codex-plugin/plugin.json", SimpleFileOptions::default())
            .expect("start");
        writer.write_all(MANIFEST.as_bytes()).expect("write");
        writer.finish().expect("finish");
        let workspace = base.join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        assert!(
            resolve_plugin_path(Some(&archive.to_string_lossy()), &workspace, &environment())
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_symlinked_plugin_directory() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_directory(&base, "plugin");
        let linked = base.join("linked");
        std::os::unix::fs::symlink(&plugin, &linked).expect("symlink");

        let error = resolve_plugin_path(Some(&linked.to_string_lossy()), &base, &environment())
            .expect_err("a symlinked plugin directory is refused");

        assert!(
            error
                .to_string()
                .starts_with("Plugin path must be a directory or ZIP:"),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_missing_or_unsupported_plugin_path() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plain = base.join("plugin.tar");
        std::fs::write(&plain, b"not a zip\n").expect("write");

        for candidate in [base.join("absent"), plain] {
            let error =
                resolve_plugin_path(Some(&candidate.to_string_lossy()), &base, &environment())
                    .expect_err("unsupported plugin path");
            assert!(
                error
                    .to_string()
                    .starts_with("Plugin path must be a directory or ZIP:"),
                "{error}"
            );
        }
    }

    #[test]
    fn expands_a_home_relative_plugin_path() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");
        let plugin = plugin_directory(&home, "plugin");
        let environment =
            ProcessEnvironment::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);

        let resolved =
            resolve_plugin_path(Some("~/plugin"), &base, &environment).expect("resolves");

        assert_eq!(resolved, plugin);
    }

    // Until a plugin is bundled, one must be supplied explicitly, and the
    // A caller that names no plugin gets the one this build ships, so an
    // ordinary scan needs no configuration at all.
    #[test]
    fn falls_back_to_the_bundled_plugin() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");

        let root =
            resolve_plugin_path(None, &base, &environment()).expect("this build ships a plugin");

        assert!(root.join(".codex-plugin/plugin.json").is_file());
        assert_eq!(
            plugin_metadata(&root).expect("metadata").version,
            BUNDLED_PLUGIN_VERSION
        );
    }
}
