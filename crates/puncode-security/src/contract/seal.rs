//! Verifying that a completed scan is still the scan that was sealed.
//!
//! Ported from `validateSeal` in `src/contract.ts`.
//!
//! The manifest records a digest for every artifact the scan produced. Checking
//! them here is what makes the rest of the contract meaningful: without it, a
//! report could be edited after the fact and still load. Coverage receipts must
//! point at sealed artifacts, and every referenced write-up must actually exist
//! as a regular file inside the scan directory.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::{Error, Result};
use crate::models::{CoverageDocument, FindingsDocument, ScanManifest};

use super::files::{ScanRoot, open_checked_scan_file, safe_relative_path, sha256_scan_file};

/// Where coverage receipts must live.
const RECEIPT_PREFIX: &str = "artifacts/";

/// Checks the manifest seal against what is on disk.
///
/// `document_digests` carries the digests of the contract documents themselves,
/// computed while they were read, so a document listed as its own artifact is
/// verified against the bytes that were parsed rather than a second read that
/// could see different content.
pub(crate) fn validate_seal(
    scan_dir: &Path,
    manifest: &ScanManifest,
    findings: &FindingsDocument,
    coverage: &CoverageDocument,
    document_digests: &BTreeMap<String, String>,
    expected_root: Option<&ScanRoot>,
) -> Result<()> {
    let scan = &manifest.scan;
    if scan.sealed_at != scan.completed_at {
        return Err(Error::contract_validation(
            "Manifest sealedAt must match completedAt.",
        ));
    }

    let mut artifact_paths: BTreeSet<String> = BTreeSet::new();
    for (index, artifact) in scan.artifacts.iter().enumerate() {
        let context = format!("manifest.scan.artifacts[{index}]");
        let normalized = safe_relative_path(&artifact.path, &format!("{context}.path"))?;
        if !artifact_paths.insert(normalized.clone()) {
            return Err(Error::contract_validation(format!(
                "{context}.path: duplicate artifact path."
            )));
        }

        let digest = match document_digests.get(&normalized) {
            Some(digest) => digest.clone(),
            None => sha256_scan_file(scan_dir, &normalized, &context, expected_root)?,
        };
        if digest != artifact.sha256 {
            return Err(Error::contract_validation(format!(
                "{context}: sealed artifact changed or is missing."
            )));
        }
    }

    for surface in &coverage.surfaces {
        for receipt in &surface.receipt_refs {
            let normalized = safe_relative_path(receipt, "coverage receipt")?;
            if !normalized.starts_with(RECEIPT_PREFIX) {
                return Err(Error::contract_validation(format!(
                    "Coverage receipt must be under artifacts/: {receipt}"
                )));
            }
            if !artifact_paths.contains(&normalized) {
                return Err(Error::contract_validation(format!(
                    "Coverage receipt is missing from sealed artifacts: {receipt}"
                )));
            }
        }
    }

    // Every referenced write-up must exist as a regular file; opening it runs
    // the same symlink and containment checks as any other scan file.
    for (index, finding) in findings.findings.iter().enumerate() {
        let Some(writeup) = &finding.writeup else {
            continue;
        };
        open_checked_scan_file(
            scan_dir,
            &writeup.report_path,
            &format!("findings[{index}].writeup.reportPath"),
            expected_root,
        )?;
    }
    if let Some(hardening) = &scan.hardening {
        open_checked_scan_file(
            scan_dir,
            &hardening.portfolio_path,
            "manifest.scan.hardening.portfolioPath",
            expected_root,
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::files::sha256_text;
    use super::*;
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use tempfile::TempDir;

    const MANIFEST_JSON: &str =
        include_str!("../../tests/fixtures/completed-scan/scan-manifest.json");
    const FINDINGS_JSON: &str = include_str!("../../tests/fixtures/completed-scan/findings.json");
    const COVERAGE_JSON: &str = include_str!("../../tests/fixtures/completed-scan/coverage.json");

    /// A scan directory holding the shipped example, with the document digests
    /// the reader would have computed.
    fn example() -> (TempDir, PathBuf, BTreeMap<String, String>) {
        let root = TempDir::new().expect("temp dir");
        let scan = std::fs::canonicalize(root.path())
            .expect("canonical")
            .join("scan");
        std::fs::create_dir(&scan).expect("create scan");
        let mut digests = BTreeMap::new();
        for (name, source) in [
            ("scan-manifest.json", MANIFEST_JSON),
            ("findings.json", FINDINGS_JSON),
            ("coverage.json", COVERAGE_JSON),
        ] {
            std::fs::write(scan.join(name), source).expect("write document");
            digests.insert(name.to_owned(), sha256_text(source));
        }
        (root, scan, digests)
    }

    fn manifest_from(value: &Value) -> ScanManifest {
        serde_json::from_value(value.clone()).expect("manifest parses")
    }

    fn documents() -> (ScanManifest, FindingsDocument, CoverageDocument) {
        (
            serde_json::from_str(MANIFEST_JSON).expect("manifest"),
            serde_json::from_str(FINDINGS_JSON).expect("findings"),
            serde_json::from_str(COVERAGE_JSON).expect("coverage"),
        )
    }

    /// The shipped example's digests were produced by the original
    /// implementation, so accepting it proves the digesting agrees.
    #[test]
    fn accepts_the_bundled_example_seal() {
        let (_root, scan, digests) = example();
        let (manifest, findings, coverage) = documents();

        validate_seal(&scan, &manifest, &findings, &coverage, &digests, None)
            .expect("the example is correctly sealed");
    }

    #[test]
    fn rejects_a_seal_timestamp_mismatch() {
        let (_root, scan, digests) = example();
        let (_, findings, coverage) = documents();
        let mut altered: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        altered["scan"]["sealedAt"] = json!("2026-01-01T00:00:02Z");

        let error = validate_seal(
            &scan,
            &manifest_from(&altered),
            &findings,
            &coverage,
            &digests,
            None,
        )
        .expect_err("a mismatched seal time is refused");

        assert_eq!(
            error.to_string(),
            "Manifest sealedAt must match completedAt."
        );
    }

    // The point of the seal: an artifact edited after the scan must not load.
    #[test]
    fn rejects_an_artifact_changed_after_sealing() {
        let (_root, scan, mut digests) = example();
        let (manifest, findings, coverage) = documents();
        let tampered = COVERAGE_JSON.replace("repository", "repository ");
        std::fs::write(scan.join("coverage.json"), &tampered).expect("write");
        digests.insert("coverage.json".to_owned(), sha256_text(&tampered));

        let error = validate_seal(&scan, &manifest, &findings, &coverage, &digests, None)
            .expect_err("a changed artifact is refused");

        assert!(
            error
                .to_string()
                .ends_with(": sealed artifact changed or is missing."),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_missing_artifact() {
        let (_root, scan, _) = example();
        let (manifest, findings, coverage) = documents();

        // No document digests, so every artifact is read from disk; remove one.
        std::fs::remove_file(scan.join("coverage.json")).expect("remove");
        let error = validate_seal(
            &scan,
            &manifest,
            &findings,
            &coverage,
            &BTreeMap::new(),
            None,
        )
        .expect_err("a missing artifact is refused");

        assert!(
            error.to_string().contains("manifest.scan.artifacts["),
            "{error}"
        );
    }

    #[test]
    fn rejects_duplicate_artifact_paths() {
        let (_root, scan, digests) = example();
        let (_, findings, coverage) = documents();
        let mut altered: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        let duplicate = altered["scan"]["artifacts"][0].clone();
        altered["scan"]["artifacts"]
            .as_array_mut()
            .expect("array")
            .push(duplicate);

        let error = validate_seal(
            &scan,
            &manifest_from(&altered),
            &findings,
            &coverage,
            &digests,
            None,
        )
        .expect_err("a duplicate artifact is refused");

        assert_eq!(
            error.to_string(),
            "manifest.scan.artifacts[2].path: duplicate artifact path."
        );
    }

    #[test]
    fn rejects_a_receipt_outside_artifacts() {
        let (_root, scan, digests) = example();
        let (manifest, findings, _) = documents();
        let mut altered: Value = serde_json::from_str(COVERAGE_JSON).expect("parses");
        altered["surfaces"][0]["receiptRefs"] = json!(["notes/receipt.md"]);
        let coverage: CoverageDocument = serde_json::from_value(altered).expect("coverage parses");

        let error = validate_seal(&scan, &manifest, &findings, &coverage, &digests, None)
            .expect_err("a receipt outside artifacts/ is refused");

        assert_eq!(
            error.to_string(),
            "Coverage receipt must be under artifacts/: notes/receipt.md"
        );
    }

    #[test]
    fn rejects_a_receipt_missing_from_the_seal() {
        let (_root, scan, digests) = example();
        let (manifest, findings, _) = documents();
        let mut altered: Value = serde_json::from_str(COVERAGE_JSON).expect("parses");
        altered["surfaces"][0]["receiptRefs"] = json!(["artifacts/unsealed.md"]);
        let coverage: CoverageDocument = serde_json::from_value(altered).expect("coverage parses");

        let error = validate_seal(&scan, &manifest, &findings, &coverage, &digests, None)
            .expect_err("an unsealed receipt is refused");

        assert_eq!(
            error.to_string(),
            "Coverage receipt is missing from sealed artifacts: artifacts/unsealed.md"
        );
    }

    #[test]
    fn requires_a_referenced_writeup_to_exist() {
        let (_root, scan, digests) = example();
        let (manifest, _, coverage) = documents();
        let mut altered: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        altered["findings"][0]["writeup"] = json!({ "reportPath": "findings/missing/missing.md" });
        let findings: FindingsDocument = serde_json::from_value(altered).expect("findings parse");

        let error = validate_seal(&scan, &manifest, &findings, &coverage, &digests, None)
            .expect_err("a missing write-up is refused");

        assert!(error.to_string().contains("writeup.reportPath"), "{error}");
    }

    #[test]
    fn accepts_a_writeup_that_exists() {
        let (_root, scan, digests) = example();
        let (manifest, _, coverage) = documents();
        std::fs::create_dir_all(scan.join("findings").join("present")).expect("create");
        std::fs::write(scan.join("findings/present/present.md"), b"# present\n").expect("write");
        let mut altered: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        altered["findings"][0]["writeup"] = json!({ "reportPath": "findings/present/present.md" });
        let findings: FindingsDocument = serde_json::from_value(altered).expect("findings parse");

        assert!(validate_seal(&scan, &manifest, &findings, &coverage, &digests, None).is_ok());
    }
}
