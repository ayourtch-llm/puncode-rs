//! Tests for the version constants.

use puncode_security::version::{BUNDLED_PLUGIN_VERSION, CODEX_EXECUTABLE_VERSION, VERSION};

#[test]
fn version_tracks_the_crate_manifest() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

/// The plugin is loaded by version, so a stale constant would bootstrap the
/// wrong plugin. Task: cross-check against the vendored plugin manifest once
/// the plugin ships as a build asset.
#[test]
fn bundled_plugin_version_is_pinned() {
    assert_eq!(BUNDLED_PLUGIN_VERSION, "0.1.14");
}

#[test]
fn versions_are_semver_shaped() {
    for version in [VERSION, BUNDLED_PLUGIN_VERSION, CODEX_EXECUTABLE_VERSION] {
        let components: Vec<&str> = version.split('.').collect();
        assert_eq!(
            components.len(),
            3,
            "{version} should have three components"
        );
        for component in components {
            assert!(
                !component.is_empty() && component.chars().all(|c| c.is_ascii_digit()),
                "{version} has a non-numeric component"
            );
        }
    }
}
