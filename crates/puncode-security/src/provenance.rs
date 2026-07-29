//! Recording how a scan was produced.
//!
//! Not a port: upstream runs one way, against hosted Codex, so there is nothing
//! to distinguish.
//!
//! A `findings.json` says what was found and nothing about what found it. Hand
//! one to somebody a month later and they cannot tell which model produced it,
//! whether it ran against a hosted service or a box under a desk, or whether
//! the agent's commands were sandboxed at the time. Those bear directly on how
//! much weight the findings deserve.
//!
//! The sandbox is the one that matters most. Findings produced with the sandbox
//! disabled came from an agent running shell commands unconfined over code that
//! was being scanned precisely because nobody trusted it. A reader deciding what
//! to do about a report should not have to guess whether that happened.
//!
//! This is written beside the artifacts rather than into `scan-manifest.json`,
//! which the workbench validates against its own record and which would refuse
//! an unexpected field.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// What produced a scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// The tool and version that ran the scan.
    pub tool: String,
    pub tool_version: String,
    /// The plugin whose workflow was followed.
    pub plugin_version: String,
    /// The content digest of the plugin tree that was used.
    ///
    /// Two scans naming the same plugin version could still have run different
    /// code; this says whether they did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_digest: Option<String>,
    /// The model asked for, when one was named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The endpoint, with any credentials removed. Absent means hosted Codex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The request shape used against that endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_api: Option<String>,
    /// Adaptations applied to requests on the way out.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoint_adaptations: Vec<String>,
    /// Whether the agent's commands ran without a sandbox.
    pub sandbox_disabled: bool,
    /// How thoroughly the scan was asked to look.
    pub mode: String,
    /// When it ran.
    pub started_at: String,
    pub completed_at: String,
}

impl Provenance {
    /// Writes the record beside a scan's artifacts.
    pub fn write(&self, scan_dir: &Path) -> std::io::Result<()> {
        let body = serde_json::to_string_pretty(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        std::fs::write(scan_dir.join("provenance.json"), body + "\n")
    }

    /// Reads a record a scan left behind.
    pub fn read(scan_dir: &Path) -> std::io::Result<Self> {
        let body = std::fs::read_to_string(scan_dir.join("provenance.json"))?;
        serde_json::from_str(&body)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    /// A sentence a person can read.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("{} {}", self.tool, self.tool_version)];
        if let Some(model) = &self.model {
            parts.push(format!("model {model}"));
        }
        match &self.endpoint {
            Some(endpoint) => parts.push(format!("endpoint {endpoint}")),
            None => parts.push("hosted Codex".to_owned()),
        }
        if self.sandbox_disabled {
            // Said in the summary, not left to a field somebody has to look
            // for: it is the part that most changes how a report should be read.
            parts.push("SANDBOX DISABLED".to_owned());
        }
        parts.join(", ")
    }
}

/// An endpoint URL with any credentials removed.
///
/// A URL may carry a username and password before the host, and a scan record
/// is exactly the kind of file that ends up attached to a ticket. Anything that
/// cannot be parsed is reported as unusable rather than passed through, because
/// the point of this function is that nothing secret survives it.
#[must_use]
pub fn redact_endpoint(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return "(unparseable endpoint)".to_owned();
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
    }
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Provenance {
        Provenance {
            tool: "puncode-security".to_owned(),
            tool_version: "0.1.0".to_owned(),
            plugin_version: "0.1.14".to_owned(),
            plugin_digest: Some("d8fd28b6".to_owned()),
            model: Some("a-model".to_owned()),
            endpoint: Some("http://host:8080/v1".to_owned()),
            wire_api: Some("responses".to_owned()),
            endpoint_adaptations: vec!["merge-system".to_owned()],
            sandbox_disabled: false,
            mode: "standard".to_owned(),
            started_at: "2026-07-29T00:00:00Z".to_owned(),
            completed_at: "2026-07-29T00:05:00Z".to_owned(),
        }
    }

    /// A scan record is the kind of file that ends up attached to a ticket.
    #[test]
    fn strips_credentials_from_an_endpoint() {
        for url in [
            "http://user:token@host:8080/v1",
            "http://token@host:8080/v1",
        ] {
            let redacted = redact_endpoint(url);
            assert!(!redacted.contains("token"), "{url} -> {redacted}");
            assert!(!redacted.contains("user:"), "{url} -> {redacted}");
            assert!(redacted.contains("host:8080"), "{url} -> {redacted}");
        }
    }

    #[test]
    fn leaves_an_endpoint_without_credentials_alone() {
        assert_eq!(
            redact_endpoint("http://host:8080/v1"),
            "http://host:8080/v1"
        );
    }

    /// Passing something through unparsed could carry anything, including the
    /// thing this exists to remove.
    #[test]
    fn refuses_to_pass_through_something_it_cannot_parse() {
        let redacted = redact_endpoint("not a url with token=secret in it");

        assert!(!redacted.contains("secret"), "{redacted}");
    }

    /// The field that most changes how a report should be read.
    #[test]
    fn says_in_the_summary_when_the_sandbox_was_off() {
        let mut unsandboxed = record();
        unsandboxed.sandbox_disabled = true;

        assert!(unsandboxed.summary().contains("SANDBOX DISABLED"));
        assert!(!record().summary().contains("SANDBOX"));
    }

    #[test]
    fn names_hosted_codex_when_there_was_no_endpoint() {
        let mut hosted = record();
        hosted.endpoint = None;

        assert!(hosted.summary().contains("hosted Codex"));
    }

    #[test]
    fn survives_a_round_trip_through_a_scan_directory() {
        let directory = tempfile::tempdir().expect("a directory");
        let original = record();

        original.write(directory.path()).expect("writes");
        let read = Provenance::read(directory.path()).expect("reads");

        assert_eq!(read, original);
    }

    /// Two scans naming one plugin version could still have run different code.
    #[test]
    fn records_which_plugin_contents_were_used() {
        let directory = tempfile::tempdir().expect("a directory");
        record().write(directory.path()).expect("writes");

        let body =
            std::fs::read_to_string(directory.path().join("provenance.json")).expect("reads");

        assert!(body.contains("pluginDigest"), "{body}");
        assert!(body.contains("sandboxDisabled"), "{body}");
    }

    /// Absent rather than null, so the shape says what applied.
    #[test]
    fn leaves_out_what_did_not_apply() {
        let directory = tempfile::tempdir().expect("a directory");
        let hosted = Provenance {
            endpoint: None,
            model: None,
            wire_api: None,
            endpoint_adaptations: Vec::new(),
            plugin_digest: None,
            ..record()
        };

        hosted.write(directory.path()).expect("writes");
        let body =
            std::fs::read_to_string(directory.path().join("provenance.json")).expect("reads");

        for absent in ["endpoint", "model", "wireApi", "endpointAdaptations"] {
            assert!(!body.contains(absent), "{absent} should be absent: {body}");
        }
    }
}
