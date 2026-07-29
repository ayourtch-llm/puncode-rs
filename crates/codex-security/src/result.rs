//! The result of a completed scan.
//!
//! Ported from `src/result.ts`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::cost::{ScanCost, estimate_scan_cost};
use crate::models::{CoverageDocument, Extra, FindingsDocument, ScanManifest, present};

/// Metadata about the agent turn that produced a scan.
///
/// Extra keys are preserved: upstream types this as an open record and passes
/// it through to callers untouched.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnResultMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub status: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub model: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub duration_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub final_response: Option<String>,
    /// Token usage as reported by the turn, passed through verbatim.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub usage: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Inputs for [`ScanResult::new`].
#[derive(Debug, Clone)]
pub struct ScanResultOptions {
    manifest: ScanManifest,
    findings: FindingsDocument,
    coverage: CoverageDocument,
    scan_dir: PathBuf,
    thread_id: String,
    turn_result: TurnResultMetadata,
    /// `None` discovers the SARIF report; `Some(value)` uses `value` as given,
    /// including `Some(None)` to record that there is no report.
    sarif_path: Option<Option<PathBuf>>,
}

impl ScanResultOptions {
    pub fn new(
        manifest: ScanManifest,
        findings: FindingsDocument,
        coverage: CoverageDocument,
        scan_dir: impl Into<PathBuf>,
        thread_id: impl Into<String>,
        turn_result: TurnResultMetadata,
    ) -> Self {
        Self {
            manifest,
            findings,
            coverage,
            scan_dir: scan_dir.into(),
            thread_id: thread_id.into(),
            turn_result,
            sarif_path: None,
        }
    }

    /// Sets the SARIF report path explicitly, suppressing discovery.
    ///
    /// Passing `None` records that the scan produced no SARIF report, which is
    /// distinct from leaving this unset and letting the report be discovered.
    #[must_use]
    pub fn with_sarif_path(mut self, sarif_path: Option<PathBuf>) -> Self {
        self.sarif_path = Some(sarif_path);
        self
    }
}

/// A completed scan: its documents, where they live, and what it cost.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub manifest: ScanManifest,
    pub findings: FindingsDocument,
    pub coverage: CoverageDocument,
    pub scan_dir: PathBuf,
    pub thread_id: String,
    pub turn_result: TurnResultMetadata,
    pub cost: Option<ScanCost>,
    pub sarif_path: Option<PathBuf>,
}

impl ScanResult {
    #[must_use]
    pub fn new(options: ScanResultOptions) -> Self {
        let cost = estimate_scan_cost(
            options.turn_result.model.as_deref(),
            options.turn_result.usage.as_ref().unwrap_or(&Value::Null),
        );
        let sarif_path = options
            .sarif_path
            .unwrap_or_else(|| discover_sarif(&options.scan_dir));

        Self {
            manifest: options.manifest,
            findings: options.findings,
            coverage: options.coverage,
            scan_dir: options.scan_dir,
            thread_id: options.thread_id,
            turn_result: options.turn_result,
            cost,
            sarif_path,
        }
    }

    /// The human-readable report.
    #[must_use]
    pub fn report_path(&self) -> PathBuf {
        self.scan_dir.join("report.md")
    }

    /// The version of the plugin that produced this scan.
    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.manifest.scan.producer.version
    }

    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.scan_dir.join("scan-manifest.json")
    }

    #[must_use]
    pub fn findings_path(&self) -> PathBuf {
        self.scan_dir.join("findings.json")
    }

    #[must_use]
    pub fn coverage_path(&self) -> PathBuf {
        self.scan_dir.join("coverage.json")
    }

    #[must_use]
    pub fn artifacts_dir(&self) -> PathBuf {
        self.scan_dir.join("artifacts")
    }
}

/// Looks for the SARIF report at its canonical path.
///
/// Anything other than an existing regular file yields `None`: a directory of
/// that name, a broken link, a symlink loop, or an unreadable parent. Upstream
/// stats through symlinks and swallows every error the same way.
fn discover_sarif(scan_dir: &Path) -> Option<PathBuf> {
    let candidate = scan_dir.join("exports").join("results.sarif");
    fs::metadata(&candidate)
        .is_ok_and(|metadata| metadata.is_file())
        .then_some(candidate)
}

/// Serialized with upstream's `toJSON` key order, which is observable in CLI
/// output.
impl Serialize for ScanResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ScanResult", 10)?;
        state.serialize_field("manifest", &self.manifest)?;
        state.serialize_field("findings", &self.findings)?;
        state.serialize_field("coverage", &self.coverage)?;
        state.serialize_field("scanDir", &self.scan_dir)?;
        state.serialize_field("threadId", &self.thread_id)?;
        state.serialize_field("reportPath", &self.report_path())?;
        state.serialize_field("artifactsDir", &self.artifacts_dir())?;
        state.serialize_field("sarifPath", &self.sarif_path)?;
        state.serialize_field("cost", &self.cost)?;
        state.serialize_field("turn", &self.turn_result)?;
        state.end()
    }
}
