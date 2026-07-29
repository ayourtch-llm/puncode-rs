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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_digest: Option<String>,
    /// The model asked for, when one was named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The endpoint, with any credentials removed. Absent means hosted Codex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The request shape used against that endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_api: Option<String>,
    /// Adaptations applied to requests on the way out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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

/// An endpoint address, which may carry credentials.
///
/// Printing one is safe: `Display` shows the address with any username and
/// password removed. The form that still carries them is reachable only through
/// [`Endpoint::for_request`], which is named so that its use is visible when
/// reading a call site and findable when auditing.
///
/// This exists because the plain string was not safe and looked it. The same
/// credential leaked into the provenance record, then into `doctor` and both
/// dry-run renderings — three sites, fixed one at a time, because nothing at
/// the call site distinguished the safe use from the unsafe one.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    raw: String,
}

/// Redacted, like `Display`.
///
/// `Debug` reaches people too — through a panic message, a log line, or a
/// derived `Debug` on any struct that holds one. Leaving it derived would have
/// meant the type protected the careful path and not the careless one.
impl std::fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Endpoint")
            .field(&redact_endpoint(&self.raw))
            .finish()
    }
}

impl Endpoint {
    /// Takes an address as given.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    /// The address as given, credentials and all.
    ///
    /// For handing to a request. Anything that reaches a person should use
    /// `Display` instead.
    #[must_use]
    pub fn for_request(&self) -> &str {
        &self.raw
    }

    /// Whether this address carries credentials at all.
    #[must_use]
    pub fn carries_credentials(&self) -> bool {
        url::Url::parse(&self.raw)
            .is_ok_and(|parsed| !parsed.username().is_empty() || parsed.password().is_some())
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&redact_endpoint(&self.raw))
    }
}

impl std::str::FromStr for Endpoint {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::new(value))
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

    /// The record this tool actually writes leaves out whatever did not apply,
    /// and it must still be readable. An earlier round-trip test used a record
    /// with every field populated and so proved nothing: a real scan against a
    /// hosted service names no model and no adaptations, and reading its own
    /// record back failed.
    #[test]
    fn survives_a_round_trip_with_fields_left_out() {
        let directory = tempfile::tempdir().expect("a directory");
        let sparse = Provenance {
            model: None,
            endpoint: None,
            wire_api: None,
            plugin_digest: None,
            endpoint_adaptations: Vec::new(),
            ..record()
        };

        sparse.write(directory.path()).expect("writes");
        let read = Provenance::read(directory.path()).expect("reads its own record back");

        assert_eq!(read, sparse);
    }

    /// The minimum a record could contain and still be worth reading.
    #[test]
    fn reads_a_record_holding_only_what_always_applies() {
        let directory = tempfile::tempdir().expect("a directory");
        std::fs::write(
            directory.path().join("provenance.json"),
            r#"{"tool":"puncode-security","toolVersion":"0.1.0","pluginVersion":"0.1.14",
                "sandboxDisabled":true,"mode":"standard","startedAt":"a","completedAt":"b"}"#,
        )
        .expect("writes");

        let read = Provenance::read(directory.path()).expect("reads");

        assert!(read.sandbox_disabled);
        assert_eq!(read.model, None);
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

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    /// The point of the type: the obvious way to print one is the safe way.
    #[test]
    fn printing_an_endpoint_does_not_show_its_credentials() {
        let endpoint = Endpoint::new("http://someone:supersecret@host:8080/v1");

        let printed = format!("{endpoint}");

        assert!(!printed.contains("supersecret"), "{printed}");
        assert!(!printed.contains("someone"), "{printed}");
        assert!(printed.contains("host:8080"), "{printed}");
    }

    /// Debug is printed too — in a panic, a log line, a derived Debug on a
    /// struct that holds one — so it must not be the leak that Display is not.
    #[test]
    fn debugging_an_endpoint_does_not_show_its_credentials() {
        let endpoint = Endpoint::new("http://someone:supersecret@host:8080/v1");

        let shown = format!("{endpoint:?}");

        assert!(!shown.contains("supersecret"), "{shown}");
    }

    /// The request still needs the real thing, and the name says so.
    #[test]
    fn the_request_form_keeps_what_the_request_needs() {
        let endpoint = Endpoint::new("http://someone:supersecret@host:8080/v1");

        assert_eq!(
            endpoint.for_request(),
            "http://someone:supersecret@host:8080/v1"
        );
    }

    #[test]
    fn an_address_without_credentials_prints_unchanged() {
        let endpoint = Endpoint::new("http://host:8080/v1");

        assert_eq!(format!("{endpoint}"), "http://host:8080/v1");
        assert!(!endpoint.carries_credentials());
    }

    #[test]
    fn notices_when_an_address_carries_credentials() {
        assert!(Endpoint::new("http://u:p@host/v1").carries_credentials());
        assert!(Endpoint::new("http://u@host/v1").carries_credentials());
        assert!(!Endpoint::new("http://host/v1").carries_credentials());
    }
}

/// How a whole run was produced, across every scan in it.
///
/// Two runs of a corpus are only worth comparing if they were produced the same
/// way. `bench --baseline` names what moved between them, and a flaw that stops
/// being found reads as a regression — but swap the model, the endpoint or the
/// plugin and the same output means nothing of the sort. The scans record all
/// of it and nothing was reading it.
///
/// Sets rather than single values: a run is several scans, and they are only
/// supposed to have been produced identically. When they were not, that is
/// itself worth seeing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunProvenance {
    pub models: std::collections::BTreeSet<String>,
    pub endpoints: std::collections::BTreeSet<String>,
    pub tool_versions: std::collections::BTreeSet<String>,
    pub plugin_digests: std::collections::BTreeSet<String>,
    /// Whether any scan in the run ran without a sandbox.
    pub sandbox_disabled: bool,
    /// Scans that left no record at all.
    pub unrecorded: usize,
}

/// What an absent endpoint means, said rather than left blank.
const HOSTED: &str = "hosted Codex";

impl RunProvenance {
    /// Reads what every scan in a run recorded about itself.
    #[must_use]
    pub fn collect<'a>(scan_dirs: impl IntoIterator<Item = &'a Path>) -> Self {
        let mut run = Self::default();
        for scan_dir in scan_dirs {
            let Ok(record) = Provenance::read(scan_dir) else {
                // Counted, not skipped. A comparison resting on records that
                // are not there should say how much it could not see.
                run.unrecorded += 1;
                continue;
            };
            if let Some(model) = record.model {
                run.models.insert(model);
            }
            run.endpoints
                .insert(record.endpoint.unwrap_or_else(|| HOSTED.to_owned()));
            run.tool_versions
                .insert(format!("{} {}", record.tool, record.tool_version));
            if let Some(digest) = record.plugin_digest {
                run.plugin_digests.insert(digest);
            }
            run.sandbox_disabled |= record.sandbox_disabled;
        }
        run
    }

    /// Whether nothing at all is known about how this run was produced.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.models.is_empty()
            && self.endpoints.is_empty()
            && self.tool_versions.is_empty()
            && self.plugin_digests.is_empty()
    }

    /// Every way two runs were produced differently.
    ///
    /// Phrased as facts rather than as a verdict. A different model is not a
    /// mistake; it just means a flaw that stopped being found says nothing
    /// about the code.
    #[must_use]
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut found = Vec::new();
        for (label, before, after) in [
            ("model", &self.models, &other.models),
            ("endpoint", &self.endpoints, &other.endpoints),
            ("tool", &self.tool_versions, &other.tool_versions),
        ] {
            if before != after {
                found.push(format!(
                    "{label}: {} then, {} now",
                    describe_set(before),
                    describe_set(after)
                ));
            }
        }
        // Digests are long and saying them twice helps nobody; that they differ
        // is the whole content.
        if self.plugin_digests != other.plugin_digests {
            found.push(
                "plugin: a different tree, so the two runs did not execute the same code"
                    .to_owned(),
            );
        }
        if self.sandbox_disabled != other.sandbox_disabled {
            found.push(format!(
                "sandbox: {} then, {} now",
                if self.sandbox_disabled { "off" } else { "on" },
                if other.sandbox_disabled { "off" } else { "on" }
            ));
        }
        for (label, count) in [("earlier", self.unrecorded), ("this", other.unrecorded)] {
            if count > 0 {
                found.push(format!(
                    "{count} scan(s) in the {label} run left no record, so this comparison cannot \
                     see how they were produced"
                ));
            }
        }
        found
    }
}

/// A set of values, for a person.
fn describe_set(values: &std::collections::BTreeSet<String>) -> String {
    if values.is_empty() {
        return "not recorded".to_owned();
    }
    values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod run_provenance_tests {
    use super::*;

    fn scan(directory: &Path, name: &str, record: &Provenance) -> std::path::PathBuf {
        let path = directory.join(name);
        std::fs::create_dir_all(&path).expect("creates");
        record.write(&path).expect("writes");
        path
    }

    fn record(model: &str) -> Provenance {
        Provenance {
            tool: "puncode-security".to_owned(),
            tool_version: "0.1.0".to_owned(),
            plugin_version: "0.1.14".to_owned(),
            plugin_digest: Some("abc".to_owned()),
            model: Some(model.to_owned()),
            endpoint: Some("http://host/v1".to_owned()),
            sandbox_disabled: true,
            mode: "repository".to_owned(),
            ..Provenance::default()
        }
    }

    #[test]
    fn reads_what_a_run_recorded_about_itself() {
        let directory = tempfile::tempdir().expect("a directory");
        let first = scan(directory.path(), "a", &record("m1"));
        let second = scan(directory.path(), "b", &record("m1"));

        let run = RunProvenance::collect([first.as_path(), second.as_path()]);

        assert_eq!(run.models.len(), 1);
        assert!(run.sandbox_disabled);
        assert_eq!(run.unrecorded, 0);
        assert!(!run.is_unknown());
    }

    /// The reason this exists: a flaw that stops being found across a model
    /// change is not a regression, and nothing was saying so.
    #[test]
    fn names_a_change_of_model() {
        let directory = tempfile::tempdir().expect("a directory");
        let before = RunProvenance::collect([scan(directory.path(), "a", &record("m1")).as_path()]);
        let after = RunProvenance::collect([scan(directory.path(), "b", &record("m2")).as_path()]);

        let differences = before.differences(&after);

        assert_eq!(differences, vec!["model: m1 then, m2 now"]);
    }

    #[test]
    fn says_nothing_when_two_runs_match() {
        let directory = tempfile::tempdir().expect("a directory");
        let before = RunProvenance::collect([scan(directory.path(), "a", &record("m")).as_path()]);
        let after = RunProvenance::collect([scan(directory.path(), "b", &record("m")).as_path()]);

        assert_eq!(before.differences(&after), Vec::<String>::new());
    }

    /// A hosted run and a local one are not the same run, and an absent
    /// endpoint must not read as "same as the other one".
    #[test]
    fn a_hosted_run_differs_from_a_local_one() {
        let directory = tempfile::tempdir().expect("a directory");
        let mut hosted = record("m");
        hosted.endpoint = None;
        let before = RunProvenance::collect([scan(directory.path(), "a", &hosted).as_path()]);
        let after = RunProvenance::collect([scan(directory.path(), "b", &record("m")).as_path()]);

        let differences = before.differences(&after);

        assert_eq!(differences.len(), 1, "{differences:?}");
        assert!(differences[0].contains(HOSTED), "{differences:?}");
    }

    #[test]
    fn names_a_different_plugin_tree() {
        let directory = tempfile::tempdir().expect("a directory");
        let mut other = record("m");
        other.plugin_digest = Some("def".to_owned());
        let before = RunProvenance::collect([scan(directory.path(), "a", &record("m")).as_path()]);
        let after = RunProvenance::collect([scan(directory.path(), "b", &other).as_path()]);

        let differences = before.differences(&after);

        assert!(
            differences[0].contains("did not execute the same code"),
            "{differences:?}"
        );
        // The digest itself says nothing to a reader and is not repeated.
        assert!(!differences[0].contains("abc"), "{differences:?}");
    }

    /// A run whose scans disagree with each other is worth seeing too.
    #[test]
    fn a_run_that_used_two_models_reports_both() {
        let directory = tempfile::tempdir().expect("a directory");
        let mixed = RunProvenance::collect([
            scan(directory.path(), "a", &record("m1")).as_path(),
            scan(directory.path(), "b", &record("m2")).as_path(),
        ]);
        let single = RunProvenance::collect([scan(directory.path(), "c", &record("m1")).as_path()]);

        let differences = mixed.differences(&single);

        assert!(differences[0].contains("m1, m2 then"), "{differences:?}");
    }

    /// Missing records are counted rather than quietly treated as matching.
    #[test]
    fn counts_scans_that_left_no_record() {
        let directory = tempfile::tempdir().expect("a directory");
        let empty = directory.path().join("nothing");
        std::fs::create_dir_all(&empty).expect("creates");

        let run = RunProvenance::collect([empty.as_path()]);

        assert_eq!(run.unrecorded, 1);
        assert!(run.is_unknown());
        let differences = RunProvenance::default().differences(&run);
        assert!(
            differences
                .iter()
                .any(|line| line.contains("left no record")),
            "{differences:?}"
        );
    }
}
