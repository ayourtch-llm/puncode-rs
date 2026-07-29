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
use puncode_security::manifest_form::{ManifestForm, inspect_manifest_file};
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
    /// Whether the plugin that produced this is the one installed now.
    ///
    /// `None` when the scan did not record a digest, or when this build cannot
    /// read its own. Not a failure either way: a scan made by an older version
    /// is still a valid scan, but somebody trying to reproduce it should know
    /// they would be running different code.
    pub same_plugin: Option<bool>,
    /// Whether the manifest looks like the plugin's own writer produced it.
    ///
    /// The seal covers every artifact the manifest lists, and the manifest is
    /// not one of them, so a replaced manifest verifies as fully consistent —
    /// replacing it leaves every artifact digest it records untouched. This is
    /// the only thing that looks at the root of the chain.
    ///
    /// `None` when there is no manifest file at all, which the contract failure
    /// will already have said.
    pub manifest_form: Option<ManifestForm>,
}

impl Verification {
    /// Whether these results hold together.
    ///
    /// Deliberately unaffected by [`Verification::manifest_form`]. A document
    /// the plugin's writer did not produce is worth knowing about and is not
    /// evidence the results are wrong: three real scans in that state published
    /// perfectly well. Failing verification on it would be crying wolf, and a
    /// check nobody believes protects nothing.
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

    // Inspected on disk rather than through the parsed manifest: the question
    // is about the file, and a parsed-and-reserialised copy has already lost
    // both the key order and the permission bits that answer it.
    let manifest_path = scan_dir.join("scan-manifest.json");
    let manifest_form = manifest_path
        .is_file()
        .then(|| inspect_manifest_file(&manifest_path));

    let provenance = Provenance::read(scan_dir).ok();
    let same_plugin = provenance
        .as_ref()
        .and_then(|record| record.plugin_digest.as_deref())
        .and_then(|recorded| installed_plugin_digest().map(|installed| installed == recorded));

    Ok(Verification {
        contract_failure,
        finding_count,
        // Absent is an ordinary answer: provenance is written by this tool, and
        // a scan made by another version or another implementation will not
        // have one.
        provenance,
        same_plugin,
        manifest_form,
    })
}

/// The digest of the plugin this build has unpacked.
fn installed_plugin_digest() -> Option<String> {
    let root = bundled_plugin_root().ok()?;
    std::fs::read_to_string(root.join(".unpacked"))
        .ok()
        .map(|digest| digest.trim().to_owned())
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

    match &verification.manifest_form {
        None | Some(ManifestForm::FromTheWriter) => {}
        Some(ManifestForm::NotFromTheWriter {
            how,
            content_parses,
        }) => {
            lines.push(
                "  note     the scan manifest was not written by the plugin's own writer"
                    .to_owned(),
            );
            for reason in how {
                lines.push(format!("           {reason}"));
            }
            if *content_parses {
                lines.push(
                    "           The content parses and the artifact digests above still match, so"
                        .to_owned(),
                );
                lines.push(
                    "           the findings themselves are readable and unchanged.".to_owned(),
                );
            }
            // Said plainly, because the obvious reading of the line above is
            // worse than the truth and would send someone to rerun a scan that
            // was fine. Of eleven real scans in this state, three published.
            lines.push(
                "           Scans in this state have both failed to publish and published"
                    .to_owned(),
            );
            lines.push(
                "           normally, so this is a reason to look rather than a verdict."
                    .to_owned(),
            );
        }
        Some(ManifestForm::Unreadable { why }) => {
            lines.push(format!("  BROKEN   the scan manifest is unreadable: {why}"));
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

    match verification.same_plugin {
        Some(true) => lines.push("  ok       produced by the plugin installed here".to_owned()),
        Some(false) => {
            // Not a failure. Worth saying because reproducing this scan here
            // would run different code than produced it.
            lines.push(
                "  differs  produced by a different plugin than the one installed here".to_owned(),
            );
            lines.push(
                "           Rerunning here would not be rerunning what made these results."
                    .to_owned(),
            );
        }
        None => {}
    }

    lines.push(String::new());
    lines.push(if verification.holds() {
        "These results are internally consistent.".to_owned()
    } else {
        "These results do not hold together.".to_owned()
    });
    if let Some(advice) = verification
        .manifest_form
        .as_ref()
        .and_then(ManifestForm::advice)
    {
        lines.push(advice.to_owned());
    }
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
        "samePlugin": verification.same_plugin,
        "manifestForm": match &verification.manifest_form {
            None => serde_json::Value::Null,
            Some(ManifestForm::FromTheWriter) => serde_json::json!({ "fromTheWriter": true }),
            Some(ManifestForm::NotFromTheWriter { how, content_parses }) => serde_json::json!({
                "fromTheWriter": false,
                "how": how,
                "contentParses": content_parses,
                // Stated in the payload as well as the prose: a machine reading
                // this must not treat it as a failure either.
                "note": "Not a verdict on the results. Scans in this state have both failed to publish and published normally.",
            }),
            Some(ManifestForm::Unreadable { why }) => serde_json::json!({
                "fromTheWriter": false,
                "unreadable": why,
            }),
        },
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
            same_plugin: None,
            manifest_form: None,
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
            same_plugin: None,
            manifest_form: None,
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
            same_plugin: None,
            manifest_form: None,
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
            same_plugin: None,
            manifest_form: None,
        };

        assert!(!verification.holds());
        let rendered = render(&verification, Path::new("/scan"));
        assert!(rendered.contains("BROKEN"), "{rendered}");
        assert!(rendered.contains("not what a scan produced"), "{rendered}");
    }
}

#[cfg(test)]
mod plugin_tests {
    use super::*;

    fn checked(same_plugin: Option<bool>) -> Verification {
        Verification {
            contract_failure: None,
            finding_count: Some(1),
            provenance: None,
            same_plugin,
            manifest_form: None,
        }
    }

    /// Somebody trying to reproduce a result needs to know they would be
    /// running different code than produced it.
    #[test]
    fn says_when_a_scan_came_from_a_different_plugin() {
        let rendered = render(&checked(Some(false)), Path::new("/scan"));

        assert!(rendered.contains("different plugin"), "{rendered}");
        assert!(rendered.contains("would not be rerunning"), "{rendered}");
    }

    #[test]
    fn says_when_the_plugin_matches() {
        let rendered = render(&checked(Some(true)), Path::new("/scan"));

        assert!(
            rendered.contains("produced by the plugin installed here"),
            "{rendered}"
        );
    }

    /// A differing plugin is information, not a failure: a scan made by an
    /// older version is still a valid scan.
    #[test]
    fn a_different_plugin_does_not_make_results_invalid() {
        assert!(checked(Some(false)).holds());
    }

    /// Nothing is claimed when there is nothing to compare.
    #[test]
    fn says_nothing_about_a_plugin_it_cannot_compare() {
        let rendered = render(&checked(None), Path::new("/scan"));

        assert!(!rendered.contains("plugin installed here"), "{rendered}");
        assert!(!rendered.contains("different plugin"), "{rendered}");
    }
}

#[cfg(test)]
mod manifest_form_tests {
    use super::*;

    fn checked(manifest_form: Option<ManifestForm>) -> Verification {
        Verification {
            contract_failure: None,
            finding_count: Some(3),
            provenance: None,
            same_plugin: None,
            manifest_form,
        }
    }

    /// The correction that matters. An earlier version failed verification on
    /// this and told the reader the workbench had refused the scan; three real
    /// scans in this state had published perfectly well.
    #[test]
    fn a_foreign_writer_does_not_fail_the_verdict() {
        let verification = checked(Some(ManifestForm::NotFromTheWriter {
            how: vec!["keys are not in sorted order at the top level".to_owned()],
            content_parses: true,
        }));

        assert!(verification.holds());
        let rendered = render(&verification, Path::new("/scan"));
        assert!(rendered.contains("These results are internally consistent."));
    }

    /// And it must still be said, prominently enough to act on.
    #[test]
    fn a_foreign_writer_is_reported_with_its_evidence() {
        let rendered = render(
            &checked(Some(ManifestForm::NotFromTheWriter {
                how: vec![
                    "keys are not in sorted order at the top level".to_owned(),
                    "the file is mode 664, and the writer creates 600".to_owned(),
                ],
                content_parses: true,
            })),
            Path::new("/scan"),
        );

        assert!(
            rendered.contains("not written by the plugin's own writer"),
            "{rendered}"
        );
        assert!(rendered.contains("mode 664"), "{rendered}");
        // The reading a person would otherwise take from it, corrected.
        assert!(
            rendered.contains("reason to look rather than a verdict"),
            "{rendered}"
        );
        assert!(
            rendered.contains("findings themselves are readable"),
            "{rendered}"
        );
    }

    /// A machine reading this must not treat it as a failure either.
    #[test]
    fn the_structured_form_says_it_is_not_a_verdict() {
        let structured = render_json(&checked(Some(ManifestForm::NotFromTheWriter {
            how: vec!["the file does not end with a newline".to_owned()],
            content_parses: true,
        })));

        assert!(structured.contains("\"holds\": true"), "{structured}");
        assert!(structured.contains("Not a verdict"), "{structured}");
        assert!(
            structured.contains("\"fromTheWriter\": false"),
            "{structured}"
        );
    }

    #[test]
    fn a_manifest_from_the_writer_is_not_remarked_on() {
        let rendered = render(
            &checked(Some(ManifestForm::FromTheWriter)),
            Path::new("/scan"),
        );

        assert!(!rendered.contains("writer"), "{rendered}");
    }

    /// End to end over a real directory: the two captured manifests, read from
    /// disk with the permission check live.
    #[test]
    fn reads_a_real_manifest_from_a_real_directory() {
        for (name, expected_foreign) in [
            ("manifest-rewritten.json", true),
            ("manifest-sealed.json", false),
        ] {
            let directory = tempfile::tempdir().expect("a directory");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../puncode-security/tests/data")
                .join(name);
            let target = directory.path().join("scan-manifest.json");
            std::fs::copy(&source, &target).expect("copies");
            // The writer's own mode, so only the document's form can decide it.
            std::fs::set_permissions(
                &target,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .expect("chmod");

            let verification = run(directory.path()).expect("checks");

            let form = verification.manifest_form.expect("a form");
            assert_eq!(
                !form.from_the_writer(),
                expected_foreign,
                "{name}: {form:?}"
            );
            // Either way the contract itself is broken — there is only a
            // manifest here — and that is a separate answer from this one.
            assert!(verification.contract_failure.is_some(), "{name}");
        }
    }
}
