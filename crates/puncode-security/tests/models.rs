//! Fidelity tests for the scan document types.
//!
//! Ported from `src/models.ts`, which upstream generates from the plugin JSON
//! Schemas. The fixtures are the bundled `examples/completed-scan` documents,
//! so a round-trip failure means the types have drifted from the schemas.

use puncode_security::models::{
    CoverageDocument, FindingRootCause, FindingsDocument, ScanManifest, SeverityLevel,
};
use serde_json::{Value, json};

const MANIFEST_JSON: &str = include_str!("fixtures/completed-scan/scan-manifest.json");
const FINDINGS_JSON: &str = include_str!("fixtures/completed-scan/findings.json");
const COVERAGE_JSON: &str = include_str!("fixtures/completed-scan/coverage.json");

/// Parses into `T`, re-serializes, and asserts nothing was lost or invented.
fn assert_round_trips<T>(source: &str, label: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let original: Value = serde_json::from_str(source).expect("fixture is valid JSON");
    let typed: T = serde_json::from_str(source)
        .unwrap_or_else(|error| panic!("{label} should parse into its type: {error}"));
    let round_tripped = serde_json::to_value(&typed).expect("serializes");

    assert_eq!(round_tripped, original, "{label} lost or invented data");
}

#[test]
fn round_trips_the_bundled_scan_manifest() {
    assert_round_trips::<ScanManifest>(MANIFEST_JSON, "scan-manifest.json");
}

#[test]
fn round_trips_the_bundled_findings_document() {
    assert_round_trips::<FindingsDocument>(FINDINGS_JSON, "findings.json");
}

#[test]
fn round_trips_the_bundled_coverage_document() {
    assert_round_trips::<CoverageDocument>(COVERAGE_JSON, "coverage.json");
}

#[test]
fn exposes_the_producer_version() {
    let manifest: ScanManifest = serde_json::from_str(MANIFEST_JSON).expect("parse manifest");

    assert!(!manifest.scan.producer.version.is_empty());
}

#[test]
fn parses_findings_with_typed_severity() {
    let document: FindingsDocument = serde_json::from_str(FINDINGS_JSON).expect("parse findings");
    let finding = document.findings.first().expect("one finding");

    assert_eq!(finding.severity.level, SeverityLevel::High);
    assert_eq!(finding.locations.first().expect("location").start_line, 41);
}

// Every schema object allows additional properties, so unknown keys written by
// a newer plugin must survive a parse/serialize cycle untouched.
#[test]
fn preserves_keys_outside_the_schema() {
    let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parse");
    document["futureTopLevel"] = json!("kept");
    document["findings"][0]["futureFindingKey"] = json!({ "nested": [1, 2] });
    document["findings"][0]["severity"]["futureSeverityKey"] = json!(true);
    let source = document.to_string();

    let typed: FindingsDocument = serde_json::from_str(&source).expect("parse with unknown keys");
    let round_tripped = serde_json::to_value(&typed).expect("serialize");

    assert_eq!(round_tripped, document);
}

// `validation` and `attackPath` are `object | null`, and the example carries
// explicit nulls. An absent key and a null one are different documents, so a
// plain `Option` (which folds null into `None`) would silently rewrite them.
#[test]
fn distinguishes_explicit_null_from_an_absent_field() {
    let with_null: FindingsDocument = serde_json::from_str(FINDINGS_JSON).expect("parse");
    assert_eq!(
        serde_json::to_value(&with_null).expect("serialize")["findings"][0]["validation"],
        Value::Null,
        "explicit null must survive"
    );

    let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parse");
    let finding = document["findings"][0]
        .as_object_mut()
        .expect("finding object");
    finding.remove("validation");
    finding.remove("attackPath");
    let source = document.to_string();

    let typed: FindingsDocument = serde_json::from_str(&source).expect("parse");
    let round_tripped = serde_json::to_value(&typed).expect("serialize");

    assert_eq!(round_tripped, document, "absent fields must stay absent");
    assert!(
        round_tripped["findings"][0].get("validation").is_none(),
        "an absent field must not reappear as null"
    );
}

// `rootCause` is `object | string` in the schema.
#[test]
fn accepts_both_root_cause_forms() {
    let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parse");
    document["findings"][0]["rootCause"] = json!("a plain string cause");
    let text: FindingsDocument =
        serde_json::from_str(&document.to_string()).expect("parse string rootCause");
    assert!(matches!(
        text.findings[0].root_cause.as_ref().expect("root cause"),
        FindingRootCause::Text(value) if value == "a plain string cause"
    ));
    assert_eq!(
        serde_json::to_value(&text).expect("serialize")["findings"][0]["rootCause"],
        json!("a plain string cause")
    );

    document["findings"][0]["rootCause"] = json!({
        "summary": "missing containment check",
        "evidenceRefs": ["artifacts/trace.md"],
    });
    let detailed: FindingsDocument =
        serde_json::from_str(&document.to_string()).expect("parse object rootCause");
    assert!(matches!(
        detailed.findings[0].root_cause.as_ref().expect("root cause"),
        FindingRootCause::Detailed(cause) if cause.summary == "missing containment check"
    ));
    assert_eq!(
        serde_json::to_value(&detailed).expect("serialize")["findings"][0]["rootCause"],
        document["findings"][0]["rootCause"]
    );
}

// Enum-valued fields must not turn a newer plugin's document into a parse
// error: upstream types are compile-time only, and schema conformance is
// checked separately by the contract loader.
#[test]
fn tolerates_enum_values_this_build_does_not_know() {
    let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parse");
    document["findings"][0]["severity"]["level"] = json!("catastrophic");
    let source = document.to_string();

    let typed: FindingsDocument =
        serde_json::from_str(&source).expect("unknown level still parses");

    assert_eq!(
        typed.findings[0].severity.level,
        SeverityLevel::Other("catastrophic".to_owned())
    );
    assert_eq!(serde_json::to_value(&typed).expect("serialize"), document);
}

// Adversarial: a round-trip alone cannot catch a misspelled optional field,
// because the key would land in `extra` and be written back out unchanged while
// the typed field stayed `None`. Populating every optional field and asserting
// each `extra` is empty proves the names actually bind.
#[test]
fn every_documented_field_binds_to_a_typed_field() {
    let source = json!({
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": "scan",
        "findings": [{
            "findingId": "csf_000000000000000000000000",
            "occurrenceId": "occ_000000000000000000000000",
            "ruleId": "rule.id",
            "identity": { "anchor": "a", "instance": "i" },
            "fingerprints": { "algorithm": "codex-security/v1", "primary": "p" },
            "title": "t",
            "summary": "s",
            "severity": {
                "level": "low",
                "score": 1.5,
                "scoringSystem": "CVSS:3.1",
                "vector": "v",
                "rationale": "r",
                "changeConditions": "c",
            },
            "confidence": { "level": "low", "rationale": "r" },
            "taxonomy": { "category": "c", "cwe": ["CWE-1"] },
            "locations": [{ "path": "p", "startLine": 1, "endLine": 2, "role": "sink" }],
            "writeup": { "reportPath": "findings/x/x.md" },
            "codeEvidence": [{
                "id": "e", "label": "l", "path": "p", "startLine": 1, "endLine": 2,
                "language": "rust", "role": "sink", "code": "x", "explanation": "y",
            }],
            "rootCause": {
                "summary": "s", "evidenceRefs": ["artifacts/a.md"],
                "code": "c", "language": "rust",
            },
            "remediation": "fix it",
            "validation": { "state": "confirmed" },
            "attackPath": { "steps": [] },
            "remediationTests": ["t"],
            "preventiveControls": ["c"],
            "provenance": { "source": "local_plugin" },
            "extensions": { "candidateId": "c", "ledgerRowId": "l", "reportId": "r" },
        }],
    });

    let document: FindingsDocument =
        serde_json::from_str(&source.to_string()).expect("parse fully populated document");
    let finding = &document.findings[0];

    assert!(
        document.extra.is_empty(),
        "unbound top-level keys: {:?}",
        document.extra
    );
    assert!(
        finding.extra.is_empty(),
        "unbound finding keys: {:?}",
        finding.extra
    );
    assert!(finding.severity.extra.is_empty(), "unbound severity keys");
    assert!(finding.identity.extra.is_empty(), "unbound identity keys");
    assert!(
        finding.locations[0].extra.is_empty(),
        "unbound location keys"
    );
    assert!(
        finding.code_evidence.as_ref().expect("code evidence")[0]
            .extra
            .is_empty(),
        "unbound code evidence keys"
    );
    assert!(
        finding
            .extensions
            .as_ref()
            .expect("extensions")
            .extra
            .is_empty(),
        "unbound extension keys"
    );
    let FindingRootCause::Detailed(cause) = finding.root_cause.as_ref().expect("root cause") else {
        panic!("expected a detailed root cause");
    };
    assert!(
        cause.extra.is_empty(),
        "unbound root cause keys: {:?}",
        cause.extra
    );

    // Spot-check that the values landed where they belong, not just that
    // `extra` is empty.
    assert_eq!(finding.severity.score, Some(1.5));
    assert_eq!(
        finding.writeup.as_ref().expect("writeup").report_path,
        "findings/x/x.md"
    );
    assert_eq!(
        finding.preventive_controls.as_deref(),
        Some(["c".to_owned()].as_slice())
    );
}

#[test]
fn every_documented_manifest_field_binds_to_a_typed_field() {
    let source = json!({
        "documentType": "codex-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": "scan",
            "producer": { "name": "codex-security-plugin", "version": "0.1.14" },
            "status": "completed",
            "startedAt": "2026-01-01T00:00:00Z",
            "completedAt": "2026-01-01T00:00:01Z",
            "sealedAt": "2026-01-01T00:00:01Z",
            "target": {
                "kind": "git_diff", "targetId": "id", "displayName": "repo",
                "remote": "origin", "revision": "r", "baseRevision": "b",
                "headRevision": "h", "snapshotDigest": "d",
            },
            "scope": {
                "includePaths": ["."], "excludePaths": [], "summary": "s",
                "artifactsReviewed": ["a"], "runtimeStatus": "ok",
                "validationMode": "strict", "context": "c", "limitations": ["l"],
            },
            "threatModel": {
                "summary": "s", "assets": ["a"], "trustBoundaries": ["t"],
                "attackerCapabilities": ["c"], "securityObjectives": ["o"],
                "assumptions": ["x"],
            },
            "hardening": { "portfolioPath": "hardening/hardening.md" },
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
            "artifacts": [{ "path": "p", "sha256": "s", "mediaType": "text/markdown" }],
        },
    });

    let manifest: ScanManifest =
        serde_json::from_str(&source.to_string()).expect("parse fully populated manifest");

    assert!(
        manifest.extra.is_empty(),
        "unbound top-level keys: {:?}",
        manifest.extra
    );
    assert!(
        manifest.scan.extra.is_empty(),
        "unbound scan keys: {:?}",
        manifest.scan.extra
    );
    assert!(
        manifest.scan.target.extra.is_empty(),
        "unbound target keys: {:?}",
        manifest.scan.target.extra
    );
    assert!(
        manifest.scan.scope.extra.is_empty(),
        "unbound scope keys: {:?}",
        manifest.scan.scope.extra
    );
    assert!(
        manifest
            .scan
            .threat_model
            .as_ref()
            .expect("threat model")
            .extra
            .is_empty(),
        "unbound threat model keys"
    );
    assert!(
        manifest.scan.artifacts[0].extra.is_empty(),
        "unbound artifact keys"
    );
    assert_eq!(manifest.scan.producer.version, "0.1.14");
}

// Deviation worth recording: upstream's types are erased at runtime, so a
// document missing a required field still parses in TypeScript and is rejected
// later by the schema validator. Here parsing enforces required fields, so the
// contract loader must validate against the schema *before* deserializing to
// keep error messages equivalent.
#[test]
fn parsing_enforces_required_fields() {
    let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parse");
    document["findings"][0]
        .as_object_mut()
        .expect("finding")
        .remove("remediation");

    let parsed = serde_json::from_str::<FindingsDocument>(&document.to_string());

    assert!(parsed.is_err(), "a missing required field must not parse");
}

#[test]
fn severity_levels_render_as_their_schema_values() {
    assert_eq!(SeverityLevel::Critical.as_str(), "critical");
    assert_eq!(SeverityLevel::Informational.as_str(), "informational");
    assert_eq!(
        SeverityLevel::Other("weird".to_owned()).to_string(),
        "weird"
    );
}

#[test]
fn parses_coverage_surfaces_and_paths() {
    let coverage: CoverageDocument = serde_json::from_str(COVERAGE_JSON).expect("parse coverage");

    assert!(!coverage.scan_id.is_empty());
    assert!(!coverage.include_paths.is_empty());
}
