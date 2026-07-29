//! Behavior tests for the bundled plugin.
//!
//! The plugin is embedded in the binary and unpacked on first use, so what is
//! checked here is that what comes out is a complete, usable plugin tree — the
//! scan prompt names skills inside it, and the contract validates against its
//! schemas.

#![cfg(unix)]

use puncode_security::runtime::bundled_plugin_root;

#[test]
fn unpacks_a_complete_plugin_tree() {
    let root = bundled_plugin_root().expect("the bundled plugin is available");

    assert!(root.join(".codex-plugin/plugin.json").is_file());
    assert!(root.join("scripts/workbench_db.py").is_file());
    for schema in [
        "scan-manifest.schema.json",
        "findings.schema.json",
        "coverage.schema.json",
    ] {
        assert!(root.join("schemas").join(schema).is_file(), "{schema}");
    }
    // The skills the scan prompt can name.
    for skill in ["security-scan", "deep-security-scan", "security-diff-scan"] {
        assert!(
            root.join("skills").join(skill).join("SKILL.md").is_file(),
            "{skill}"
        );
    }
}

#[test]
fn reports_the_version_this_build_ships() {
    let root = bundled_plugin_root().expect("the bundled plugin is available");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".codex-plugin/plugin.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert_eq!(manifest["name"], "codex-security");
    assert_eq!(
        manifest["version"],
        puncode_security::version::BUNDLED_PLUGIN_VERSION
    );
}

// Unpacking happens once and is reused, so a second call is cheap and returns
// the same tree.
#[test]
fn reuses_what_it_already_unpacked() {
    let first = bundled_plugin_root().expect("first");
    let second = bundled_plugin_root().expect("second");

    assert_eq!(first, second);
}

// A command interrupted midway must not leave a partial tree that a later
// command trusts, which is what the completion marker is for.
#[test]
fn marks_the_tree_complete_only_when_it_is() {
    let root = bundled_plugin_root().expect("the bundled plugin is available");

    let marker = std::fs::read_to_string(root.join(".unpacked")).expect("a completion marker");
    assert_eq!(marker, puncode_security::version::BUNDLED_PLUGIN_VERSION);
}

// The plugin is the caller's by default; nothing else should be able to read
// the credentials-adjacent state directory it lives beside.
#[test]
fn keeps_the_unpacked_tree_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = bundled_plugin_root().expect("the bundled plugin is available");
    let parent = root.parent().expect("a cache directory");

    let mode = std::fs::metadata(parent)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

/// Checking a destination without committing to it.
///
/// Upstream exports `validateOutputDir` from its public surface. This test
/// lives outside the crate, so it fails to compile if the function stops being
/// reachable by a library consumer.
#[test]
fn a_destination_can_be_checked_without_being_created() {
    use puncode_security::runtime::validate_output_dir;

    let temporary = tempfile::tempdir().expect("a temporary directory");
    let destination = temporary.path().join("not-yet-there");
    let environment = std::collections::BTreeMap::new();

    let resolved = validate_output_dir(Some(&destination.to_string_lossy()), false, &environment)
        .expect("an acceptable destination");

    assert_eq!(resolved.as_deref(), Some(destination.as_path()));
    // Checking must not be the same as making.
    assert!(!destination.exists());
}

/// Asking about nothing means a temporary directory should be made instead.
#[test]
fn no_destination_asked_for_means_no_answer() {
    use puncode_security::runtime::validate_output_dir;

    let environment = std::collections::BTreeMap::new();

    assert_eq!(
        validate_output_dir(None, false, &environment).expect("no destination"),
        None
    );
}
