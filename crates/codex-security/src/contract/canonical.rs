//! Cross-document invariants the schemas cannot express.
//!
//! Ported from `validateCanonicalContract` in `src/contract.ts`.
//!
//! A schema can say a finding has an id; it cannot say the id is *the right
//! one*. Each finding's identifiers are derived by hashing the scan target,
//! rule, and anchor, so a finding cannot be renamed, moved between scans, or
//! invented without the identifiers disagreeing. The remote URL and every
//! repository-relative path are re-checked here too, because a document that
//! satisfies the schema can still name something outside the repository.

#![allow(dead_code)]

use url::Url;

use crate::error::{Error, Result};
use crate::models::{FindingsDocument, ScanManifest};

use super::files::{safe_relative_path, safe_scope_path, sha256_text};

/// The prefix every fingerprint carries, naming the derivation it used.
const FINGERPRINT_ALGORITHM: &str = "codex-security/v1";

/// Identifiers keep this many hex characters of their digest.
const IDENTIFIER_DIGEST_LENGTH: usize = 24;

/// Checks the invariants that span the manifest and findings documents.
pub(crate) fn validate_canonical_contract(
    manifest: &ScanManifest,
    findings: &FindingsDocument,
) -> Result<()> {
    if let Some(remote) = &manifest.scan.target.remote {
        validate_remote(remote)?;
    }

    for (field, values) in [
        ("includePaths", &manifest.scan.scope.include_paths),
        ("excludePaths", &manifest.scan.scope.exclude_paths),
    ] {
        for (index, value) in values.iter().enumerate() {
            safe_scope_path(value).map_err(|error| {
                Error::contract_validation(format!(
                    "manifest.scan.scope.{field}[{index}]: expected a safe repository-relative POSIX path."
                ))
                .with_source(error)
            })?;
        }
    }

    for (finding_index, finding) in findings.findings.iter().enumerate() {
        let context = format!("findings.findings[{finding_index}]");

        for (location_index, location) in finding.locations.iter().enumerate() {
            let location_context = format!("{context}.locations[{location_index}]");
            safe_relative_path(&location.path, &format!("{location_context}.path")).map_err(
                |error| {
                    Error::contract_validation(format!(
                        "{location_context}.path: expected a safe repository-relative POSIX path."
                    ))
                    .with_source(error)
                },
            )?;
        }

        let identity = derived_identity(manifest, finding);
        if finding.finding_id != identity.finding_id {
            return Err(Error::contract_validation(format!(
                "{context}.findingId: does not match derived fingerprint identity."
            )));
        }
        if finding.occurrence_id != identity.occurrence_id {
            return Err(Error::contract_validation(format!(
                "{context}.occurrenceId: does not match scan occurrence identity."
            )));
        }
        if finding.fingerprints.primary != identity.fingerprint {
            return Err(Error::contract_validation(format!(
                "{context}.fingerprints: does not match derived fingerprint."
            )));
        }
    }
    Ok(())
}

/// The identifiers a finding must carry, derived from what it describes.
pub(crate) struct DerivedIdentity {
    pub(crate) fingerprint: String,
    pub(crate) finding_id: String,
    pub(crate) occurrence_id: String,
}

/// Derives a finding's identity.
///
/// The parts are joined with NUL, which cannot appear in any of them, so no
/// combination of values can be made to collide with a different one.
pub(crate) fn derived_identity(
    manifest: &ScanManifest,
    finding: &crate::models::Finding,
) -> DerivedIdentity {
    let parts = [
        FINGERPRINT_ALGORITHM,
        &manifest.scan.target.target_id,
        &finding.rule_id,
        &finding.identity.anchor,
        finding.identity.instance.as_deref().unwrap_or(""),
    ];
    let fingerprint = format!(
        "{FINGERPRINT_ALGORITHM}:sha256:{}",
        sha256_text(&parts.join("\0"))
    );
    let finding_id = format!(
        "csf_{}",
        &sha256_text(&fingerprint)[..IDENTIFIER_DIGEST_LENGTH]
    );
    let occurrence_id = format!(
        "occ_{}",
        &sha256_text(&[manifest.scan.id.as_str(), fingerprint.as_str()].join("\0"))
            [..IDENTIFIER_DIGEST_LENGTH]
    );

    DerivedIdentity {
        fingerprint,
        finding_id,
        occurrence_id,
    }
}

/// Requires a plain absolute URL: no credentials, no query, no fragment.
///
/// Credentials in a recorded remote would be a leak; a query or fragment would
/// make the recorded origin ambiguous.
fn validate_remote(remote: &str) -> Result<()> {
    let malformed = || {
        Error::contract_validation(
            "scan.target.remote: expected a sanitized canonical absolute URL.",
        )
    };
    let unsanitized = || {
        Error::contract_validation(
            "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
        )
    };

    let Some(authority) = scheme_authority(remote) else {
        return Err(malformed());
    };
    if remote.contains('\\') {
        return Err(malformed());
    }
    if authority.contains('@') {
        return Err(unsanitized());
    }

    let parsed = Url::parse(remote).map_err(|_| malformed())?;
    if parsed.scheme().is_empty() || parsed.host_str().is_none_or(str::is_empty) {
        return Err(malformed());
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(unsanitized());
    }
    Ok(())
}

/// The authority of `value`, if it starts with `scheme://`.
///
/// Mirrors `^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]+)`.
fn scheme_authority(value: &str) -> Option<&str> {
    let separator = value.find("://")?;
    let scheme = &value[..separator];
    let mut characters = scheme.chars();
    if !characters.next()?.is_ascii_alphabetic() {
        return None;
    }
    if !characters
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-'))
    {
        return None;
    }

    let rest = &value[separator + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty()).then_some(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CoverageDocument, FindingsDocument, ScanManifest};
    use serde_json::{Value, json};

    const MANIFEST_JSON: &str =
        include_str!("../../tests/fixtures/completed-scan/scan-manifest.json");
    const FINDINGS_JSON: &str = include_str!("../../tests/fixtures/completed-scan/findings.json");

    fn manifest() -> ScanManifest {
        serde_json::from_str(MANIFEST_JSON).expect("manifest fixture parses")
    }

    fn findings() -> FindingsDocument {
        serde_json::from_str(FINDINGS_JSON).expect("findings fixture parses")
    }

    fn findings_from(value: &Value) -> FindingsDocument {
        serde_json::from_value(value.clone()).expect("findings parse")
    }

    /// The shipped example carries genuinely derived identifiers, so this
    /// exercises the whole derivation against known-good data.
    #[test]
    fn accepts_the_bundled_example() {
        validate_canonical_contract(&manifest(), &findings()).expect("example is canonical");
    }

    #[test]
    fn rejects_a_renamed_finding_id() {
        let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        document["findings"][0]["findingId"] = json!("csf_000000000000000000000000");

        let error = validate_canonical_contract(&manifest(), &findings_from(&document))
            .expect_err("a forged id is refused");

        assert_eq!(
            error.to_string(),
            "findings.findings[0].findingId: does not match derived fingerprint identity."
        );
    }

    #[test]
    fn rejects_a_mismatched_occurrence_id() {
        let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        document["findings"][0]["occurrenceId"] = json!("occ_000000000000000000000000");

        let error = validate_canonical_contract(&manifest(), &findings_from(&document))
            .expect_err("a forged occurrence is refused");

        assert_eq!(
            error.to_string(),
            "findings.findings[0].occurrenceId: does not match scan occurrence identity."
        );
    }

    #[test]
    fn rejects_a_mismatched_fingerprint() {
        let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        document["findings"][0]["fingerprints"]["primary"] = json!(
            "codex-security/v1:sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );

        let error = validate_canonical_contract(&manifest(), &findings_from(&document))
            .expect_err("a forged fingerprint is refused");

        assert_eq!(
            error.to_string(),
            "findings.findings[0].fingerprints: does not match derived fingerprint."
        );
    }

    // The identity binds the rule and anchor: editing either must invalidate
    // the recorded identifiers.
    #[test]
    fn identity_is_bound_to_the_rule_and_anchor() {
        for field in ["ruleId", "anchor"] {
            let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
            if field == "ruleId" {
                document["findings"][0]["ruleId"] = json!("some.other.rule");
            } else {
                document["findings"][0]["identity"]["anchor"] = json!("some-other-anchor");
            }

            assert!(
                validate_canonical_contract(&manifest(), &findings_from(&document)).is_err(),
                "changing {field} must invalidate the identity"
            );
        }
    }

    // The occurrence binds the scan, so a finding cannot be lifted from one
    // scan into another.
    #[test]
    fn occurrence_is_bound_to_the_scan() {
        let mut altered: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        altered["scan"]["id"] = json!("some_other_scan");
        let altered: ScanManifest = serde_json::from_value(altered).expect("manifest parses");

        let error = validate_canonical_contract(&altered, &findings())
            .expect_err("a finding from another scan is refused");

        assert!(error.to_string().contains("occurrenceId"), "{error}");
    }

    #[test]
    fn rejects_a_finding_location_outside_the_repository() {
        let mut document: Value = serde_json::from_str(FINDINGS_JSON).expect("parses");
        document["findings"][0]["locations"][0]["path"] = json!("../outside.py");

        let error = validate_canonical_contract(&manifest(), &findings_from(&document))
            .expect_err("an escaping path is refused");

        assert_eq!(
            error.to_string(),
            "findings.findings[0].locations[0].path: expected a safe repository-relative POSIX path."
        );
    }

    #[test]
    fn rejects_an_unsafe_scope_path() {
        let mut document: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        document["scan"]["scope"]["includePaths"] = json!(["src", "../escape"]);
        let altered: ScanManifest = serde_json::from_value(document).expect("manifest parses");

        let error = validate_canonical_contract(&altered, &findings())
            .expect_err("an escaping scope path is refused");

        assert_eq!(
            error.to_string(),
            "manifest.scan.scope.includePaths[1]: expected a safe repository-relative POSIX path."
        );
    }

    // A scope may name the repository root even though "." is not otherwise a
    // legal relative path.
    #[test]
    fn accepts_the_repository_root_as_a_scope_path() {
        let mut document: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        document["scan"]["scope"]["includePaths"] = json!(["."]);
        let altered: ScanManifest = serde_json::from_value(document).expect("manifest parses");

        assert!(validate_canonical_contract(&altered, &findings()).is_ok());
    }

    fn remote_error(remote: &str) -> String {
        let mut document: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        document["scan"]["target"]["remote"] = json!(remote);
        let altered: ScanManifest = serde_json::from_value(document).expect("manifest parses");
        validate_canonical_contract(&altered, &findings())
            .expect_err("remote should be refused")
            .to_string()
    }

    fn accepts_remote(remote: &str) -> bool {
        let mut document: Value = serde_json::from_str(MANIFEST_JSON).expect("parses");
        document["scan"]["target"]["remote"] = json!(remote);
        let altered: ScanManifest = serde_json::from_value(document).expect("manifest parses");
        validate_canonical_contract(&altered, &findings()).is_ok()
    }

    #[test]
    fn accepts_a_plain_remote_url() {
        assert!(accepts_remote("https://github.com/openai/codex-security"));
        assert!(accepts_remote("ssh://example.com/repo.git"));
        assert!(accepts_remote("https://example.com:8443/repo.git"));
    }

    // Credentials in a recorded remote would be a leak.
    #[test]
    fn rejects_remote_credentials_query_and_fragment() {
        for remote in [
            "https://user:token@github.com/openai/codex-security",
            "https://token@github.com/openai/codex-security",
            "https://github.com/openai/codex-security?token=secret",
            "https://github.com/openai/codex-security#fragment",
        ] {
            assert_eq!(
                remote_error(remote),
                "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
                "{remote}"
            );
        }
    }

    #[test]
    fn rejects_a_remote_that_is_not_an_absolute_url() {
        for remote in [
            "github.com/openai/codex-security",
            "/srv/git/repo.git",
            "https://",
            "1https://example.com",
            r"https://example.com\repo",
        ] {
            assert_eq!(
                remote_error(remote),
                "scan.target.remote: expected a sanitized canonical absolute URL.",
                "{remote}"
            );
        }
    }

    #[test]
    fn derives_identifiers_with_the_documented_shape() {
        let manifest = manifest();
        let findings = findings();
        let identity = derived_identity(&manifest, &findings.findings[0]);

        assert!(
            identity
                .fingerprint
                .starts_with("codex-security/v1:sha256:")
        );
        assert_eq!(
            identity.fingerprint.len(),
            "codex-security/v1:sha256:".len() + 64
        );
        assert!(identity.finding_id.starts_with("csf_"));
        assert_eq!(identity.finding_id.len(), 4 + IDENTIFIER_DIGEST_LENGTH);
        assert!(identity.occurrence_id.starts_with("occ_"));
        assert_eq!(identity.occurrence_id.len(), 4 + IDENTIFIER_DIGEST_LENGTH);
    }

    #[test]
    fn coverage_documents_parse_for_later_layers() {
        let _: CoverageDocument = serde_json::from_str(include_str!(
            "../../tests/fixtures/completed-scan/coverage.json"
        ))
        .expect("coverage fixture parses");
    }
}
