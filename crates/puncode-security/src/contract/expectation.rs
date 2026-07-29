//! Checking that a scan describes the scan that was actually requested.
//!
//! Ported from `validateExpectation` in `src/contract.ts`.
//!
//! A well-formed, correctly sealed contract can still be the wrong contract —
//! produced by a different plugin version, or describing a different revision,
//! or covering paths that were never asked for. These checks bind the result
//! back to the request that produced it.

#![allow(dead_code)]

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::models::{CoverageDocument, CoverageMode, ScanManifest, TargetKind};
use crate::targets::{NormalizedTarget, NormalizedTargetKind, ScanMode};

use super::files::safe_scope_path;

/// The plugin permitted to produce a contract.
const PRODUCER_NAME: &str = "codex-security-plugin";

/// What the caller asked for, to check the result against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanExpectation {
    pub repository: PathBuf,
    /// `None` when the repository is not version controlled.
    pub repository_revision: Option<String>,
    pub target: NormalizedTarget,
    pub mode: ScanMode,
    pub plugin_version: String,
}

/// Checks a contract against the request that produced it.
pub(crate) fn validate_expectation(
    manifest: &ScanManifest,
    coverage: &CoverageDocument,
    expectation: &ScanExpectation,
) -> Result<()> {
    let scan = &manifest.scan;
    if scan.producer.name != PRODUCER_NAME {
        return Err(Error::contract_validation(format!(
            "Manifest producer must be {PRODUCER_NAME}, got {}.",
            scan.producer.name
        )));
    }
    if scan.producer.version != expectation.plugin_version {
        return Err(Error::contract_validation(
            "Manifest producer version does not match the installed Codex Security plugin.",
        ));
    }

    let expected_mode = expected_coverage_mode(&expectation.target, expectation.mode);
    if coverage.mode != expected_mode {
        return Err(Error::contract_validation(format!(
            "Coverage mode must be {}, got {}.",
            expected_mode.as_str(),
            coverage.mode.as_str()
        )));
    }

    let target = &scan.target;
    match expectation.target.kind {
        Some(NormalizedTargetKind::Refs | NormalizedTargetKind::WorkingTree) => {
            if target.kind != TargetKind::GitDiff {
                return Err(Error::contract_validation(
                    "Diff scan manifest target must be git_diff.",
                ));
            }
            if target.base_revision != expectation.target.base {
                return Err(Error::contract_validation(
                    "Diff scan base revision does not match the request.",
                ));
            }
            if target.head_revision != expectation.target.head {
                return Err(Error::contract_validation(
                    "Diff scan head revision does not match the request.",
                ));
            }
        }
        _ if expectation.repository_revision.is_none() => {
            if target.kind != TargetKind::DirectorySnapshot {
                return Err(Error::contract_validation(
                    "Unversioned scan manifest target must be directory_snapshot.",
                ));
            }
        }
        _ => {
            if target.kind != TargetKind::GitRevision && target.kind != TargetKind::GitWorktree {
                return Err(Error::contract_validation(
                    "Repository scan manifest target must be Git-backed.",
                ));
            }
            if target.revision != expectation.repository_revision {
                return Err(Error::contract_validation(
                    "Scan target revision does not match the repository.",
                ));
            }
        }
    }

    if expectation.target.kind == Some(NormalizedTargetKind::Paths) {
        let actual = scan
            .scope
            .include_paths
            .iter()
            .map(|path| safe_scope_path(path))
            .collect::<Result<Vec<_>>>()?;
        let unique: std::collections::BTreeSet<&String> = actual.iter().collect();
        let requested: std::collections::BTreeSet<&String> =
            expectation.target.paths.iter().collect();
        if unique.len() != actual.len() || unique != requested {
            return Err(Error::contract_validation(
                "Manifest include paths do not match the requested path target.",
            ));
        }
    }
    Ok(())
}

/// The coverage mode a request implies.
pub(crate) fn expected_coverage_mode(target: &NormalizedTarget, mode: ScanMode) -> CoverageMode {
    match target.kind {
        Some(NormalizedTargetKind::Paths) => CoverageMode::ScopedPath,
        Some(NormalizedTargetKind::Refs) => CoverageMode::BranchDiff,
        Some(NormalizedTargetKind::WorkingTree) => CoverageMode::WorkingTree,
        _ if mode == ScanMode::Deep => CoverageMode::DeepRepository,
        _ => CoverageMode::Repository,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::NormalizedTargetKind;
    use serde_json::{Value, json};

    const MANIFEST_JSON: &str =
        include_str!("../../tests/fixtures/completed-scan/scan-manifest.json");
    const COVERAGE_JSON: &str = include_str!("../../tests/fixtures/completed-scan/coverage.json");

    fn documents() -> (ScanManifest, CoverageDocument) {
        (
            serde_json::from_str(MANIFEST_JSON).expect("manifest"),
            serde_json::from_str(COVERAGE_JSON).expect("coverage"),
        )
    }

    fn target(kind: NormalizedTargetKind) -> NormalizedTarget {
        NormalizedTarget {
            kind: Some(kind),
            ..NormalizedTarget::default()
        }
    }

    fn expectation() -> ScanExpectation {
        ScanExpectation {
            repository: PathBuf::from("/repo"),
            repository_revision: Some("deadbeef".to_owned()),
            target: target(NormalizedTargetKind::Repository),
            mode: ScanMode::Standard,
            plugin_version: "0.1.0".to_owned(),
        }
    }

    #[test]
    fn accepts_a_matching_expectation() {
        let (manifest, coverage) = documents();

        validate_expectation(&manifest, &coverage, &expectation()).expect("matches the request");
    }

    #[test]
    fn rejects_a_foreign_producer() {
        let (_, coverage) = documents();
        let mut altered: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        altered["scan"]["producer"]["name"] = json!("someone-elses-plugin");
        let manifest: ScanManifest = serde_json::from_value(altered).expect("manifest parses");

        let error = validate_expectation(&manifest, &coverage, &expectation())
            .expect_err("a foreign producer is refused");

        assert_eq!(
            error.to_string(),
            "Manifest producer must be codex-security-plugin, got someone-elses-plugin."
        );
    }

    #[test]
    fn rejects_a_plugin_version_mismatch() {
        let (manifest, coverage) = documents();
        let mut expectation = expectation();
        expectation.plugin_version = "0.1.14".to_owned();

        let error = validate_expectation(&manifest, &coverage, &expectation)
            .expect_err("a version mismatch is refused");

        assert_eq!(
            error.to_string(),
            "Manifest producer version does not match the installed Codex Security plugin."
        );
    }

    #[test]
    fn rejects_a_revision_mismatch() {
        let (manifest, coverage) = documents();
        let mut expectation = expectation();
        expectation.repository_revision = Some("cafebabe".to_owned());

        let error = validate_expectation(&manifest, &coverage, &expectation)
            .expect_err("a revision mismatch is refused");

        assert_eq!(
            error.to_string(),
            "Scan target revision does not match the repository."
        );
    }

    // An unversioned repository must be recorded as a snapshot, not as a
    // Git-backed target.
    #[test]
    fn requires_a_snapshot_target_without_a_revision() {
        let (manifest, coverage) = documents();
        let mut expectation = expectation();
        expectation.repository_revision = None;

        let error = validate_expectation(&manifest, &coverage, &expectation)
            .expect_err("a Git target without a revision is refused");

        assert_eq!(
            error.to_string(),
            "Unversioned scan manifest target must be directory_snapshot."
        );
    }

    #[test]
    fn requires_a_diff_target_for_a_diff_request() {
        let (manifest, coverage) = documents();
        let mut expectation = expectation();
        expectation.target = NormalizedTarget {
            kind: Some(NormalizedTargetKind::Refs),
            base: Some("aaa".to_owned()),
            head: Some("bbb".to_owned()),
            ..NormalizedTarget::default()
        };

        let error = validate_expectation(&manifest, &coverage, &expectation)
            .expect_err("a repository manifest cannot answer a diff request");

        // The coverage mode is checked before the target kind.
        assert_eq!(
            error.to_string(),
            "Coverage mode must be branch_diff, got repository."
        );
    }

    #[test]
    fn rejects_include_paths_that_do_not_match_a_path_request() {
        let (manifest, _) = documents();
        let mut altered: Value = serde_json::from_str(COVERAGE_JSON).expect("parses");
        altered["mode"] = json!("scoped_path");
        let coverage: CoverageDocument = serde_json::from_value(altered).expect("coverage parses");
        let mut expectation = expectation();
        expectation.target = NormalizedTarget {
            kind: Some(NormalizedTargetKind::Paths),
            paths: vec!["docs".to_owned()],
            ..NormalizedTarget::default()
        };

        let error = validate_expectation(&manifest, &coverage, &expectation)
            .expect_err("mismatched include paths are refused");

        assert_eq!(
            error.to_string(),
            "Manifest include paths do not match the requested path target."
        );
    }

    // The manifest records "src/"; a request for "src" is the same scope.
    #[test]
    fn matches_include_paths_after_normalization() {
        let (manifest, _) = documents();
        let mut altered: Value = serde_json::from_str(COVERAGE_JSON).expect("parses");
        altered["mode"] = json!("scoped_path");
        let coverage: CoverageDocument = serde_json::from_value(altered).expect("coverage parses");
        let mut expectation = expectation();
        expectation.target = NormalizedTarget {
            kind: Some(NormalizedTargetKind::Paths),
            paths: vec!["src".to_owned()],
            ..NormalizedTarget::default()
        };

        assert!(validate_expectation(&manifest, &coverage, &expectation).is_ok());
    }

    #[test]
    fn derives_the_expected_coverage_mode() {
        assert_eq!(
            expected_coverage_mode(&target(NormalizedTargetKind::Paths), ScanMode::Standard),
            CoverageMode::ScopedPath
        );
        assert_eq!(
            expected_coverage_mode(&target(NormalizedTargetKind::Refs), ScanMode::Standard),
            CoverageMode::BranchDiff
        );
        assert_eq!(
            expected_coverage_mode(
                &target(NormalizedTargetKind::WorkingTree),
                ScanMode::Standard
            ),
            CoverageMode::WorkingTree
        );
        assert_eq!(
            expected_coverage_mode(
                &target(NormalizedTargetKind::Repository),
                ScanMode::Standard
            ),
            CoverageMode::Repository
        );
        assert_eq!(
            expected_coverage_mode(&target(NormalizedTargetKind::Repository), ScanMode::Deep),
            CoverageMode::DeepRepository
        );
        // Deep mode only widens a repository scan; a path scan stays scoped.
        assert_eq!(
            expected_coverage_mode(&target(NormalizedTargetKind::Paths), ScanMode::Deep),
            CoverageMode::ScopedPath
        );
    }
}
