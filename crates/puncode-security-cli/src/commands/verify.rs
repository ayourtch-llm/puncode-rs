//! Checking that a scan's results are what the scan produced.
//!
//! Scan results get passed around — attached to a ticket, copied into a report,
//! handed to someone who was not there when they were made. Whoever receives
//! them has two questions the files do not answer on their own: are these
//! internally consistent and unmodified, and what produced them.
//!
//! Nothing here re-runs a scan or contacts anything. It reads what is on disk
//! and checks it against itself.

use std::path::Path;

use puncode_security::contract::{LoadContractOptions, load_contract};
use puncode_security::provenance::Provenance;
use puncode_security::runtime::bundled_plugin_root;

/// What was checked, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Why the contract does not hold, when it does not.
    pub contract_failure: Option<String>,
    /// How many findings the documents agree on.
    pub finding_count: Option<usize>,
    /// How the scan was produced, when it said.
    pub provenance: Option<Provenance>,
}

impl Verification {
    #[must_use]
    pub fn holds(&self) -> bool {
        self.contract_failure.is_none()
    }
}

/// Checks a scan directory against itself.
pub fn run(scan_dir: &Path) -> Result<Verification, String> {
    if !scan_dir.is_dir() {
        return Err(format!("Not a scan directory: {}", scan_dir.display()));
    }

    let plugin_root = bundled_plugin_root().map_err(|error| error.to_string())?;
    let options = LoadContractOptions::new(&plugin_root);

    let (contract_failure, finding_count) = match load_contract(scan_dir, &options) {
        Ok(contract) => (None, Some(contract.findings.findings.len())),
        Err(error) => (Some(error.to_string()), None),
    };

    Ok(Verification {
        contract_failure,
        finding_count,
        // Absent is an ordinary answer: provenance is written by this tool, and
        // a scan made by another version or another implementation will not
        // have one.
        provenance: Provenance::read(scan_dir).ok(),
    })
}

/// The verification, for a person.
#[must_use]
pub fn render(verification: &Verification, scan_dir: &Path) -> String {
    let mut lines = vec![format!("Checking {}", scan_dir.display()), String::new()];

    match &verification.contract_failure {
        None => {
            lines.push(
                "  ok       documents agree with each other and with their digests".to_owned(),
            );
            if let Some(count) = verification.finding_count {
                lines.push(format!(
                    "  ok       {count} finding(s), each matching its fingerprint"
                ));
            }
        }
        Some(failure) => {
            lines.push(format!("  BROKEN   {failure}"));
            lines.push(
                "           These results are not what a scan produced, or not all of them."
                    .to_owned(),
            );
        }
    }

    match &verification.provenance {
        Some(provenance) => {
            lines.push(format!("  produced by  {}", provenance.summary()));
            if provenance.sandbox_disabled {
                // Repeated deliberately. It is the single fact that most
                // changes how much weight these findings deserve, and someone
                // reading a verification is deciding exactly that.
                lines.push(
                    "           The agent ran shell commands unsandboxed over the scanned code."
                        .to_owned(),
                );
            }
        }
        None => lines.push(
            "  unknown  no provenance record, so what produced this cannot be told".to_owned(),
        ),
    }

    lines.push(String::new());
    lines.push(if verification.holds() {
        "These results are internally consistent.".to_owned()
    } else {
        "These results do not hold together.".to_owned()
    });
    // Said plainly and without overclaiming. The seals are digests, not
    // signatures: they catch a document edited without also updating them,
    // which is what accident and casual tampering look like. Someone holding
    // this tool could reseal a changed document and it would verify.
    lines.push(
        "The seals are digests, not signatures. They catch a document changed without".to_owned(),
    );
    lines.push(
        "resealing it; they cannot detect someone who changed it and resealed. And".to_owned(),
    );
    lines.push(
        "consistency is not correctness: nothing here says the findings are right.".to_owned(),
    );

    lines.join("\n")
}

/// The same, for another program.
#[must_use]
pub fn render_json(verification: &Verification) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "holds": verification.holds(),
        "contractFailure": verification.contract_failure,
        "findingCount": verification.finding_count,
        "provenance": verification.provenance,
        "note": "Seals are digests, not signatures: they catch a document changed without resealing, not someone who changed it and resealed. Consistency is also not correctness.",
    }))
    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_something_that_is_not_a_directory() {
        let refused = run(Path::new("/does/not/exist"));

        assert!(refused.expect_err("a refusal").contains("Not a scan"));
    }

    #[test]
    fn an_empty_directory_does_not_hold() {
        let directory = tempfile::tempdir().expect("a directory");

        let verification = run(directory.path()).expect("checks");

        assert!(!verification.holds());
    }

    /// A reader deciding how much to trust a report needs this said, not
    /// buried in a field.
    #[test]
    fn says_when_a_scan_ran_without_a_sandbox() {
        let verification = Verification {
            contract_failure: None,
            finding_count: Some(2),
            provenance: Some(Provenance {
                sandbox_disabled: true,
                tool: "puncode-security".to_owned(),
                tool_version: "0.1.0".to_owned(),
                ..Provenance::default()
            }),
        };

        let rendered = render(&verification, Path::new("/scan"));

        assert!(rendered.contains("unsandboxed"), "{rendered}");
    }

    /// Absent provenance is reported as unknown, never as fine.
    #[test]
    fn says_when_it_cannot_tell_what_produced_a_scan() {
        let verification = Verification {
            contract_failure: None,
            finding_count: Some(0),
            provenance: None,
        };

        let rendered = render(&verification, Path::new("/scan"));

        assert!(rendered.contains("no provenance record"), "{rendered}");
    }

    /// The distinction the whole command turns on.
    #[test]
    fn does_not_claim_the_findings_are_correct() {
        let verification = Verification {
            contract_failure: None,
            finding_count: Some(3),
            provenance: None,
        };

        let rendered = render(&verification, Path::new("/scan"));

        assert!(
            rendered.contains("consistency is not correctness"),
            "{rendered}"
        );
        // And it must not claim more than a digest can support.
        assert!(rendered.contains("not signatures"), "{rendered}");
        let structured = render_json(&verification);
        assert!(structured.contains("not correctness"), "{structured}");
    }

    #[test]
    fn a_broken_contract_is_reported_as_broken() {
        let verification = Verification {
            contract_failure: Some("findings.json: digest does not match".to_owned()),
            finding_count: None,
            provenance: None,
        };

        assert!(!verification.holds());
        let rendered = render(&verification, Path::new("/scan"));
        assert!(rendered.contains("BROKEN"), "{rendered}");
        assert!(rendered.contains("not what a scan produced"), "{rendered}");
    }
}
