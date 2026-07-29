//! Publishing the plugin into a private marketplace Codex can install from.
//!
//! Ported from `createMarketplace` and `copyPluginTree` in `src/runtime.ts`.
//!
//! Codex installs plugins from a marketplace directory, so the plugin is copied
//! into one inside the isolated home. The copy is defensive because the source
//! may be a directory the caller pointed at rather than the bundled plugin:
//! symlinks are refused outright, the tree is bounded in entries and bytes, and
//! every directory on the path is re-checked before and after each file is read
//! so the tree cannot be rearranged mid-copy.
//!
//! Upstream has a second path here, `copyExternalPayload`, taken only when the
//! source is the bundled plugin *and* carries an internal projection contract.
//! The published bundle has no such contract — it is already the projected
//! result — so that branch is unreachable outside OpenAI's own build and is not
//! ported.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::contract::files::{open_no_follow, same_object};
use crate::error::{Error, Result};

use super::plugin::{MARKETPLACE_NAME, PLUGIN_NAME};

/// Files and directories the plugin tree may contain.
const MAX_PLUGIN_COPY_ENTRIES: usize = 4_096;
/// How large any one plugin file may be.
const MAX_PLUGIN_COPY_FILE_SIZE: u64 = 128 * 1024 * 1024;
/// How large the plugin tree may be in total.
const MAX_PLUGIN_COPY_SIZE: u64 = 512 * 1024 * 1024;

/// Copies `plugin_root` into a marketplace under `codex_home` and writes its
/// manifest, returning the marketplace directory.
pub fn create_marketplace(codex_home: &Path, plugin_root: &Path) -> Result<PathBuf> {
    let root = std::fs::canonicalize(plugin_root).map_err(|error| {
        Error::plugin_bootstrap(format!(
            "Invalid Codex plugin directory: {}",
            plugin_root.display()
        ))
        .with_source(error)
    })?;

    let marketplace = codex_home.join("sdk-marketplace");
    let plugin_destination = marketplace.join("plugins").join(PLUGIN_NAME);
    copy_plugin_tree(&root, &plugin_destination)?;

    let manifest = serde_json::json!({
        "name": MARKETPLACE_NAME,
        "interface": { "displayName": "Codex Security SDK" },
        "plugins": [{
            "name": PLUGIN_NAME,
            "source": { "source": "local", "path": format!("./plugins/{PLUGIN_NAME}") },
            "policy": { "installation": "AVAILABLE", "authentication": "ON_INSTALL" },
            "category": "Security",
        }],
    });

    let manifest_path = marketplace
        .join(".agents")
        .join("plugins")
        .join("marketplace.json");
    create_private_dir(manifest_path.parent().unwrap_or(&marketplace))?;
    write_new_private_file(
        &manifest_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).map_err(|error| {
                Error::plugin_bootstrap("Unable to write the SDK marketplace manifest.")
                    .with_source(error)
            })?
        )
        .as_bytes(),
    )?;

    Ok(marketplace)
}

/// Copies a plugin tree, refusing anything that is not a plain file or
/// directory and undoing the copy if any part of it fails.
pub(crate) fn copy_plugin_tree(source: &Path, destination: &Path) -> Result<()> {
    let outcome = copy_tree(source, destination);
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(destination);
    }
    outcome
}

fn copy_tree(source_root: &Path, destination_root: &Path) -> Result<()> {
    if let Some(parent) = destination_root.parent() {
        create_private_dir(parent)?;
    }

    let mut pending = vec![(source_root.to_path_buf(), destination_root.to_path_buf())];
    // Directory identities recorded as the walk descends, so a directory that
    // is swapped after it was read is noticed.
    let mut directories: BTreeMap<PathBuf, Metadata> = BTreeMap::new();
    let mut entries = 0_usize;
    let mut total_size = 0_u64;

    while let Some((source, destination)) = pending.pop() {
        require_plugin_ancestors(source_root, &source, &directories)?;
        let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
            Error::plugin_bootstrap(format!("Unable to read {}", source.display()))
                .with_source(error)
        })?;

        entries += 1;
        if entries > MAX_PLUGIN_COPY_ENTRIES {
            return Err(Error::plugin_bootstrap(format!(
                "Plugin source exceeds the copy entry limit: {}",
                source.display()
            )));
        }
        if metadata.is_symlink() {
            return Err(Error::plugin_bootstrap(format!(
                "Plugin contains an unsafe source path: {}",
                source.display()
            )));
        }

        if metadata.is_dir() {
            let children: Vec<PathBuf> = std::fs::read_dir(&source)
                .map_err(|error| {
                    Error::plugin_bootstrap(format!("Unable to read {}", source.display()))
                        .with_source(error)
                })?
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.file_name().into())
                .collect();
            let after_read = std::fs::symlink_metadata(&source).map_err(|error| {
                Error::plugin_bootstrap(format!("Unable to read {}", source.display()))
                    .with_source(error)
            })?;
            if !same_object(&metadata, &after_read) {
                return Err(Error::plugin_bootstrap(format!(
                    "Plugin directory changed while it was being copied: {}",
                    source.display()
                )));
            }
            directories.insert(source.clone(), after_read);
            create_private_dir(&destination)?;
            for child in children {
                pending.push((source.join(&child), destination.join(&child)));
            }
            continue;
        }

        if !metadata.is_file() {
            return Err(Error::plugin_bootstrap(format!(
                "Plugin contains a non-regular file: {}",
                source.display()
            )));
        }
        if metadata.len() > MAX_PLUGIN_COPY_FILE_SIZE {
            return Err(Error::plugin_bootstrap(format!(
                "Plugin source exceeds the per-file safety limit: {}",
                source.display()
            )));
        }
        total_size += metadata.len();
        if total_size > MAX_PLUGIN_COPY_SIZE {
            return Err(Error::plugin_bootstrap(
                "Plugin source exceeds the copy safety limit.",
            ));
        }

        copy_plugin_file(source_root, &source, &destination, &metadata, &directories)?;
    }
    Ok(())
}

/// Copies one file, confirming it and its ancestors are unchanged either side
/// of the read.
fn copy_plugin_file(
    source_root: &Path,
    source: &Path,
    destination: &Path,
    expected: &Metadata,
    directories: &BTreeMap<PathBuf, Metadata>,
) -> Result<()> {
    let changed = |when: &str| {
        Error::plugin_bootstrap(format!(
            "Plugin source changed {when} it could be copied: {}",
            source.display()
        ))
    };

    let mut input = open_no_follow(source).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to read {}", source.display())).with_source(error)
    })?;
    let opened = input
        .metadata()
        .map_err(|error| changed("before").with_source(error))?;
    if !same_object(expected, &opened) {
        return Err(changed("before"));
    }
    require_plugin_ancestors(source_root, source, directories)?;

    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .map_err(|error| changed("while").with_source(error))?;
    let after = input
        .metadata()
        .map_err(|error| changed("while").with_source(error))?;
    if !same_object(expected, &after) {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin source changed while it was being copied: {}",
            source.display()
        )));
    }
    require_plugin_ancestors(source_root, source, directories)?;

    write_new_private_file(destination, &bytes)?;
    // Executable bits matter: the plugin ships scripts the scan runs.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        std::fs::set_permissions(
            destination,
            std::fs::Permissions::from_mode(expected.mode() & 0o777),
        )
        .map_err(|error| {
            Error::plugin_bootstrap(format!("Unable to write {}", destination.display()))
                .with_source(error)
        })?;
    }
    Ok(())
}

/// Confirms every recorded directory between `root` and `path` still has the
/// identity it had when the walk descended through it.
fn require_plugin_ancestors(
    root: &Path,
    path: &Path,
    directories: &BTreeMap<PathBuf, Metadata>,
) -> Result<()> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if let Some(expected) = directories.get(ancestor) {
            let now = std::fs::symlink_metadata(ancestor).map_err(|error| {
                Error::plugin_bootstrap(format!(
                    "Plugin directory changed while it was being copied: {}",
                    ancestor.display()
                ))
                .with_source(error)
            })?;
            if !now.is_dir() || now.is_symlink() || !same_object(expected, &now) {
                return Err(Error::plugin_bootstrap(format!(
                    "Plugin directory changed while it was being copied: {}",
                    ancestor.display()
                )));
            }
        }
        if ancestor == root {
            break;
        }
        current = ancestor.parent();
    }
    Ok(())
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

/// Writes a file that must not already exist, owner-only.
fn write_new_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to write {}", path.display())).with_source(error)
    })?;
    file.write_all(contents).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to write {}", path.display())).with_source(error)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// A minimal plugin tree, including an executable script.
    fn plugin_tree(base: &Path) -> PathBuf {
        let root = base.join("plugin");
        std::fs::create_dir_all(root.join(".codex-plugin")).expect("create");
        std::fs::write(
            root.join(".codex-plugin").join("plugin.json"),
            br#"{"name":"codex-security","version":"0.1.14"}"#,
        )
        .expect("write manifest");
        std::fs::create_dir_all(root.join("scripts")).expect("create scripts");
        let script = root.join("scripts").join("run.py");
        std::fs::write(&script, b"#!/usr/bin/env python3\nprint('scan')\n").expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(root.join("schemas.json"), b"{}\n").expect("write");
        root
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn publishes_a_plugin_into_a_marketplace() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");

        let marketplace = create_marketplace(&home, &plugin).expect("published");

        assert_eq!(marketplace, home.join("sdk-marketplace"));
        let installed = marketplace.join("plugins").join("codex-security");
        assert!(
            installed
                .join(".codex-plugin")
                .join("plugin.json")
                .is_file()
        );
        assert!(installed.join("schemas.json").is_file());

        let manifest_path = marketplace.join(".agents/plugins/marketplace.json");
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("read"))
                .expect("parse");
        assert_eq!(manifest["name"], "codex-security-sdk");
        assert_eq!(manifest["plugins"][0]["name"], "codex-security");
        assert_eq!(
            manifest["plugins"][0]["source"]["path"],
            "./plugins/codex-security"
        );
        assert_eq!(mode_of(&manifest_path), 0o600, "the manifest is private");
    }

    // The plugin ships scripts the scan executes, so the executable bit has to
    // survive the copy.
    #[test]
    fn preserves_executable_permissions() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");

        let marketplace = create_marketplace(&home, &plugin).expect("published");

        let script = marketplace.join("plugins/codex-security/scripts/run.py");
        assert_eq!(mode_of(&script), 0o755, "scripts stay executable");
        // Compared against the source rather than a constant: an ordinary
        // file's mode depends on the umask that created it.
        assert_eq!(
            mode_of(&marketplace.join("plugins/codex-security/schemas.json")),
            mode_of(&plugin.join("schemas.json")),
            "ordinary files keep their mode"
        );
    }

    // A symlink in the source could point anywhere; the copy refuses rather
    // than following or recreating it.
    #[test]
    fn refuses_a_symlink_in_the_plugin_tree() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        let outside = base.join("outside.txt");
        std::fs::write(&outside, b"elsewhere\n").expect("write");
        std::os::unix::fs::symlink(&outside, plugin.join("link.txt")).expect("symlink");
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");

        let error = create_marketplace(&home, &plugin).expect_err("a symlink is refused");

        assert!(
            error
                .to_string()
                .starts_with("Plugin contains an unsafe source path:"),
            "{error}"
        );
    }

    // A failed copy must not leave a partial plugin installed.
    #[test]
    fn removes_a_partial_copy_when_it_fails() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        std::os::unix::fs::symlink(base.join("outside.txt"), plugin.join("link.txt"))
            .expect("symlink");
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");

        let _ = create_marketplace(&home, &plugin);

        assert!(
            !home.join("sdk-marketplace/plugins/codex-security").exists(),
            "no partial plugin remains"
        );
    }

    #[test]
    fn refuses_to_overwrite_an_existing_marketplace_manifest() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");
        create_marketplace(&home, &plugin).expect("first publish");

        let error = create_marketplace(&home, &plugin).expect_err("publishing twice is refused");

        assert!(error.is_plugin_bootstrap(), "{error}");
    }

    #[test]
    fn refuses_a_missing_plugin_directory() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");

        let error = create_marketplace(&home, &base.join("absent"))
            .expect_err("a missing plugin is refused");

        assert!(
            error
                .to_string()
                .starts_with("Invalid Codex plugin directory:"),
            "{error}"
        );
    }

    #[test]
    fn copies_a_nested_tree_in_full() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let source = base.join("source");
        std::fs::create_dir_all(source.join("a").join("b").join("c")).expect("create");
        std::fs::write(source.join("a/b/c/deep.txt"), b"deep\n").expect("write");
        std::fs::write(source.join("a/top.txt"), b"top\n").expect("write");

        copy_plugin_tree(&source, &base.join("destination")).expect("copies");

        assert_eq!(
            std::fs::read_to_string(base.join("destination/a/b/c/deep.txt")).expect("read"),
            "deep\n"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("destination/a/top.txt")).expect("read"),
            "top\n"
        );
    }
}
