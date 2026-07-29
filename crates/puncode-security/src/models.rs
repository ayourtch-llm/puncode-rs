//! Scan document types.
//!
//! Ported from `src/models.ts`, which upstream generates from the plugin JSON
//! Schemas with `json-schema-to-typescript`. These are hand-written because the
//! three schemas are self-contained and a code generator would buy little.
//! `tests/models.rs` round-trips the bundled example documents, which catches
//! drift the way upstream's `generate:models:check` does.
//!
//! Two properties matter for fidelity:
//!
//! * Every schema object permits additional properties, so each type keeps an
//!   `extra` map and round-trips unknown keys untouched.
//! * Parsing is deliberately permissive. Upstream's types are erased at
//!   runtime, and schema conformance is enforced separately by the contract
//!   loader; a document that violates the schema still parses in TypeScript.
//!   Enum-valued fields therefore accept unknown values rather than failing.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Properties outside the schema, preserved verbatim.
pub type Extra = Map<String, Value>;

/// Reads an optional field so that an explicit `null` stays distinct from an
/// absent key.
///
/// A plain `Option` folds both into `None`, which would silently rewrite
/// `"validation": null` as an absent field.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Defines a string-valued enum that keeps unrecognized values instead of
/// failing to parse.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($variant:ident => $text:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(from = "String", into = "String")]
        pub enum $name {
            $($variant,)+
            /// A value this build does not know, preserved as written.
            Other(String),
        }

        impl $name {
            /// The value as it appears in the document.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Other(value) => value.as_str(),
                }
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                match value.as_str() {
                    $($text => Self::$variant,)+
                    _ => Self::Other(value),
                }
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.as_str().to_owned()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

string_enum! {
    /// How serious a finding is.
    SeverityLevel {
        Critical => "critical",
        High => "high",
        Medium => "medium",
        Low => "low",
        Informational => "informational",
    }
}

string_enum! {
    /// How sure the scan is about a finding.
    ConfidenceLevel {
        High => "high",
        Medium => "medium",
        Low => "low",
    }
}

string_enum! {
    /// What the scan was pointed at.
    TargetKind {
        GitRevision => "git_revision",
        GitWorktree => "git_worktree",
        GitDiff => "git_diff",
        DirectorySnapshot => "directory_snapshot",
    }
}

string_enum! {
    /// How the scan enumerated its inputs.
    CoverageMode {
        Repository => "repository",
        ScopedPath => "scoped_path",
        Diff => "diff",
        Commit => "commit",
        BranchDiff => "branch_diff",
        WorkingTree => "working_tree",
        DeepRepository => "deep_repository",
    }
}

string_enum! {
    /// Whether the scan covered everything it set out to.
    Completeness {
        Complete => "complete",
        Partial => "partial",
        Unknown => "unknown",
    }
}

string_enum! {
    /// The strategy used to build the file inventory.
    InventoryStrategy {
        Repository => "repository",
        ScopedPath => "scoped_path",
        Diff => "diff",
        Directory => "directory",
        Custom => "custom",
    }
}

string_enum! {
    /// The outcome recorded for a reviewed surface.
    SurfaceDisposition {
        Reported => "reported",
        NoIssueFound => "no_issue_found",
        Rejected => "rejected",
        NotApplicable => "not_applicable",
        NeedsFollowUp => "needs_follow_up",
    }
}

// ---------------------------------------------------------------------------
// scan-manifest.schema.json
// ---------------------------------------------------------------------------

/// The sealed record of a completed scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanManifest {
    pub document_type: String,
    pub schema_version: String,
    pub scan: ManifestScan,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestScan {
    pub id: String,
    pub producer: Producer,
    pub status: String,
    pub started_at: String,
    pub completed_at: String,
    pub sealed_at: String,
    pub target: ManifestTarget,
    pub scope: ManifestScope,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub threat_model: Option<ThreatModel>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub hardening: Option<Hardening>,
    pub coverage_ref: String,
    pub findings_ref: String,
    pub artifacts: Vec<Artifact>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The plugin that produced a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Producer {
    pub name: String,
    pub version: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestTarget {
    pub kind: TargetKind,
    pub target_id: String,
    pub display_name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub remote: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub revision: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub base_revision: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub head_revision: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub snapshot_digest: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestScope {
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub summary: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub artifacts_reviewed: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub runtime_status: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub validation_mode: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub context: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub limitations: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatModel {
    pub summary: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub assets: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub trust_boundaries: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub attacker_capabilities: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub security_objectives: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub assumptions: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hardening {
    pub portfolio_path: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A file recorded in the manifest, with its digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub media_type: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---------------------------------------------------------------------------
// findings.schema.json
// ---------------------------------------------------------------------------

/// The findings a scan reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingsDocument {
    pub document_type: String,
    pub schema_version: String,
    pub scan_id: String,
    pub findings: Vec<Finding>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A single reported issue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub finding_id: String,
    pub occurrence_id: String,
    pub rule_id: String,
    pub identity: FindingIdentity,
    pub fingerprints: FindingFingerprints,
    pub title: String,
    pub summary: String,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub taxonomy: FindingTaxonomy,
    pub locations: Vec<FindingLocation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub writeup: Option<FindingWriteup>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub code_evidence: Option<Vec<CodeEvidence>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub root_cause: Option<FindingRootCause>,
    pub remediation: String,
    /// `object | null`; an explicit null is distinct from an absent key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub validation: Option<Value>,
    /// `object | null`; an explicit null is distinct from an absent key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub attack_path: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub remediation_tests: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub preventive_controls: Option<Vec<String>>,
    pub provenance: FindingProvenance,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub extensions: Option<FindingExtensions>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingIdentity {
    pub anchor: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub instance: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingFingerprints {
    pub algorithm: String,
    pub primary: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSeverity {
    pub level: SeverityLevel,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub score: Option<f64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub scoring_system: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub vector: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rationale: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub change_conditions: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingConfidence {
    pub level: ConfidenceLevel,
    pub rationale: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingTaxonomy {
    pub category: String,
    pub cwe: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Where a finding lives in the source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingLocation {
    pub path: String,
    pub start_line: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub end_line: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub role: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingWriteup {
    pub report_path: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeEvidence {
    pub id: String,
    pub label: String,
    pub path: String,
    pub start_line: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub end_line: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub language: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub role: Option<String>,
    pub code: String,
    pub explanation: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The schema allows either a structured cause or a bare string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FindingRootCause {
    Detailed(RootCauseDetail),
    Text(String),
    /// Anything else, kept so an off-schema document still round-trips.
    Other(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootCauseDetail {
    pub summary: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub code: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub language: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingProvenance {
    pub source: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingExtensions {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub candidate_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ledger_row_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub report_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---------------------------------------------------------------------------
// coverage.schema.json
// ---------------------------------------------------------------------------

/// What the scan looked at, and what it did not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageDocument {
    pub document_type: String,
    pub schema_version: String,
    pub scan_id: String,
    pub mode: CoverageMode,
    pub completeness: Completeness,
    pub inventory_strategy: InventoryStrategy,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub surfaces: Vec<CoverageSurface>,
    pub explicit_exclusions: Vec<ExplicitExclusion>,
    pub deferred: Vec<DeferredItem>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub open_questions: Option<Vec<OpenQuestion>>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// An area of the target that was reviewed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSurface {
    pub id: String,
    pub label: String,
    pub disposition: SurfaceDisposition,
    pub receipt_refs: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub risk_area: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplicitExclusion {
    pub pattern: String,
    pub reason: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Something the scan knowingly did not cover.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeferredItem {
    pub id: String,
    pub reason: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub paths: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub surface_ids: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenQuestion {
    pub question: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub follow_up_prompt: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
