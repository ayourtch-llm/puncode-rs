//! Turning a finished scan directory into a validated result.
//!
//! Ported from `collectResult` in `src/api.ts`.
//!
//! The agent writes the scan artifacts; nothing about the turn completing means
//! they are all there. Every required artifact is checked first, and all of the
//! missing ones are reported together — finding out about them one run at a
//! time would be needlessly slow. Only then is the contract loaded and checked
//! against what the caller asked for.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::contract::{LoadContractOptions, ScanExpectation, load_contract, require_scan_file};
use crate::error::{Error, Result};
use crate::result::{ScanResult, ScanResultOptions, TurnResultMetadata};

/// Artifacts a completed scan must have produced.
const REQUIRED_ARTIFACTS: [&str; 4] = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
];

/// The SARIF export, which is optional.
const SARIF_ARTIFACT: &str = "exports/results.sarif";

/// Gathers and validates everything a finished scan produced.
pub fn collect_result(
    turn_result: TurnResultMetadata,
    thread_id: &str,
    scan_dir: &Path,
    plugin_root: &Path,
    expectation: &ScanExpectation,
) -> Result<ScanResult> {
    // Reported together rather than one per run.
    let missing: Vec<&str> = REQUIRED_ARTIFACTS
        .iter()
        .filter(|name| require_scan_file(scan_dir, name, name).is_err())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(Error::incomplete_scan(format!(
            "Puncode Security scan completed without required artifacts: {}",
            missing.join(", ")
        )));
    }

    let contract = load_contract(
        scan_dir,
        &LoadContractOptions::new(plugin_root).with_expectation(expectation),
    )?;

    // Absent is an ordinary outcome; the export is not required.
    let sarif_path: Option<PathBuf> =
        require_scan_file(scan_dir, SARIF_ARTIFACT, SARIF_ARTIFACT).ok();

    Ok(ScanResult::new(
        ScanResultOptions::new(
            contract.manifest,
            contract.findings,
            contract.coverage,
            scan_dir,
            thread_id,
            turn_result,
        )
        // Passed explicitly, including when absent, so the result does not
        // re-discover it.
        .with_sarif_path(sarif_path),
    ))
}
