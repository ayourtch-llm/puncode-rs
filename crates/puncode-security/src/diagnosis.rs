//! Explaining failures whose own message points somewhere unhelpful.
//!
//! Not a port: upstream talks only to hosted Codex in an environment it
//! controls, so these failures do not arise there.
//!
//! Some failures report themselves accurately and still mislead. A scan whose
//! every shell command was refused ends with "completed without required
//! artifacts", which reads as though the model did not do its work. A server
//! whose template permits one system message says "System message must be at
//! the beginning", which reads as though something is out of order. In both
//! cases the obvious next step is the wrong one, and someone can lose a long
//! time to it.
//!
//! What is recognised here is recorded as a cause, never as the text that
//! revealed it: that text is the prompt and the source under review, and this
//! module has no business holding on to it.

use std::collections::BTreeSet;

use crate::codex::ThreadEvent;
use serde_json::Value;

/// Something that explains a failure better than the failure does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cause {
    /// Commands could not run because the sandbox would not start.
    SandboxUnavailable,
    /// The server's template accepts a single system message.
    OneSystemMessageOnly,
    /// The server was asked for a request shape Codex no longer sends.
    WireApiUnsupported,
    /// Nothing answered at the endpoint address.
    EndpointUnreachable,
    /// The endpoint refused the credentials.
    EndpointRejectedKey,
    /// The endpoint does not serve the model asked for.
    ModelNotServed,
    /// A scan is already recorded against this output directory.
    OutputDirectoryAlreadyScanned,
    /// Something wrote into the scanned tree while the scan was running.
    WorkingTreeChanged,
    /// The manifest on disk is not the one the plugin serialised.
    ManifestNotAsSerialised,
}

impl Cause {
    /// What to do about it.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::SandboxUnavailable => {
                "Commands could not run: the Codex sandbox (bwrap) could not start in this \
                 environment, so the scan could not read files or run its scripts. This is not a \
                 problem with the model. Run the scan where bubblewrap works — an unprivileged \
                 container with an idmapped root filesystem is a common cause. If this host is \
                 already confined and the repository is trusted, --dangerously-disable-sandbox \
                 (--yolo) runs without it."
            }
            Self::OneSystemMessageOnly => {
                "The endpoint's chat template accepts only one system message, and Codex sends \
                 several. The order is not the problem, so reordering will not help. Retry with \
                 --endpoint-compat merge-system, which sends them as one."
            }
            Self::WireApiUnsupported => {
                "The endpoint was configured for a request shape this Codex no longer sends. \
                 Retry with --wire-api responses."
            }
            Self::EndpointUnreachable => {
                "Nothing answered at the endpoint address. Check --base-url, and that the server \
                 is running and reachable from this machine."
            }
            Self::EndpointRejectedKey => {
                "The endpoint refused the credentials. The key is read from the environment \
                 variable named by --api-key-env (default OPENAI_API_KEY), not from the \
                 configuration."
            }
            Self::ModelNotServed => {
                "The endpoint does not serve the model that was asked for. Check --model against \
                 what the server lists."
            }
            Self::WorkingTreeChanged => {
                "Something wrote into the scanned code while the scan was running, so the \
                 workbench refused to record it — the results no longer describe a state that \
                 existed. The findings are still on disk. In practice the writer is usually the \
                 agent itself: asked to confirm a memory-safety flaw it will compile the code, \
                 and the object files land in the tree it is scanning. Check for build output \
                 next to the source. Scan a copy of the repository rather than the working tree, \
                 or arrange for builds to write somewhere else."
            }
            Self::ManifestNotAsSerialised => {
                "The scan manifest on disk is not byte-for-byte what the plugin serialised, so \
                 the workbench refused to publish it. The wording suggests a race and it is \
                 usually not one: the agent writes the manifest itself instead of letting the \
                 plugin's own writer produce it, and the result parses identically while \
                 differing in key order or a trailing newline. The findings are intact — run \
                 `puncode-security verify` on the partial output to see exactly what differs. \
                 Do not rewrite the file to match: resealing a document by hand is what a seal \
                 exists to prevent."
            }
            Self::OutputDirectoryAlreadyScanned => {
                "A scan is already recorded against this output directory, and the workbench \
                 keeps one scan per directory. Emptying it is not enough — the record survives \
                 the files, so deleting them or using --archive-existing will not help. Scan \
                 again with a different --output-dir."
            }
        }
    }
}

/// Where some text came from, which decides what it can be read as.
///
/// A security scan's own output discusses authentication, status codes and
/// invalid keys, because that is what it is reviewing. Read as diagnostics,
/// that vocabulary is indistinguishable from an endpoint refusing a request —
/// so what a command printed is not read for endpoint failures at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Something the scan itself reported as going wrong.
    Failure,
    /// Output of a command the agent ran. Its content is the repository's, not
    /// the endpoint's.
    CommandOutput,
}

/// The cause some text reveals, if it reveals one.
///
/// `origin` decides which causes are even considered; see [`Origin`].
#[must_use]
pub fn recognise_from(text: &str, origin: Origin) -> Option<Cause> {
    let lowered = text.to_ascii_lowercase();

    // A sandbox that will not start is reported by the command that could not
    // run, so this is the one cause worth reading command output for — and that
    // makes it the one that can match the repository's own text. Scanning a
    // codebase that merely mentions bwrap, such as this one, must not look like
    // a sandbox failure, so the failure's shape is required and not just the
    // word: bwrap reports as "bwrap: <what failed>".
    let bwrap_failure = lowered.contains("bwrap:")
        && (lowered.contains("permission denied")
            || lowered.contains("failed to")
            || lowered.contains("operation not permitted"));
    if bwrap_failure
        || (lowered.contains("failed to make") && lowered.contains("slave"))
        || lowered.contains("sandbox could not be initialized")
    {
        return Some(Cause::SandboxUnavailable);
    }
    if origin == Origin::CommandOutput {
        return None;
    }
    // Matched on the workbench's own wording. Both halves are required: a scan
    // of a codebase that discusses working trees must not look like this.
    if lowered.contains("working-tree contents changed")
        || (lowered.contains("working tree") && lowered.contains("changed while the scan"))
    {
        return Some(Cause::WorkingTreeChanged);
    }
    // The workbench's own wording, which reads like a race and is not one.
    if lowered.contains("sealed scan manifest changed") {
        return Some(Cause::ManifestNotAsSerialised);
    }
    if lowered.contains("system message must be at the beginning")
        || (lowered.contains("system message") && lowered.contains("only one"))
    {
        return Some(Cause::OneSystemMessageOnly);
    }
    if lowered.contains("wire_api") && lowered.contains("no longer supported") {
        return Some(Cause::WireApiUnsupported);
    }
    if lowered.contains("connection refused")
        || lowered.contains("endpoint unreachable")
        || lowered.contains("name or service not known")
        || lowered.contains("failed to lookup address")
        // What Codex actually reports when nothing answers: the wording says
        // the request could not be sent, never "refused".
        || lowered.contains("error sending request")
    {
        return Some(Cause::EndpointUnreachable);
    }
    if lowered.contains("invalid_api_key")
        || lowered.contains("incorrect api key")
        // Said as a status rather than as a bare number: "401" alone appears in
        // hashes, paths and any discussion of HTTP.
        || lowered.contains("status 401")
        || lowered.contains("status 403")
        || lowered.contains("401 unauthorized")
        || lowered.contains("403 forbidden")
    {
        return Some(Cause::EndpointRejectedKey);
    }
    // The plugin reports this as a raw sqlite traceback, which reads as a bug in
    // the tool rather than a directory that has been used before.
    if lowered.contains("unique constraint failed: scans.scan_dir") {
        return Some(Cause::OutputDirectoryAlreadyScanned);
    }
    if lowered.contains("model_not_found")
        || lowered.contains("unknown model")
        || lowered.contains("does not exist")
    {
        return Some(Cause::ModelNotServed);
    }
    None
}

/// The cause a reported failure reveals, if it reveals one.
#[must_use]
pub fn recognise(text: &str) -> Option<Cause> {
    recognise_from(text, Origin::Failure)
}

/// Watches a scan for signs that something other than the model is at fault.
///
/// Holds only the causes it recognised. The text that revealed them is read and
/// discarded.
#[derive(Debug, Default)]
pub struct FailureWatch {
    seen: BTreeSet<Cause>,
}

impl FailureWatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads what an event carries.
    pub fn observe(&mut self, event: &ThreadEvent) {
        match event {
            ThreadEvent::ItemStarted { item }
            | ThreadEvent::ItemUpdated { item }
            | ThreadEvent::ItemCompleted { item } => {
                let Some(item) = item else { return };
                for value in item.fields.values() {
                    self.read(value, Origin::CommandOutput);
                }
            }
            ThreadEvent::TurnFailed { error } => {
                if let Some(message) = error.as_ref().and_then(|error| error.message.as_deref()) {
                    self.note(message);
                }
            }
            _ => {}
        }
    }

    /// Reads a message that is not part of an event, such as a failure string.
    pub fn note(&mut self, text: &str) {
        if let Some(cause) = recognise(text) {
            self.seen.insert(cause);
        }
    }

    /// Reads text whose origin decides how it may be interpreted.
    fn note_from(&mut self, text: &str, origin: Origin) {
        if let Some(cause) = recognise_from(text, origin) {
            self.seen.insert(cause);
        }
    }

    /// Everything recognised, in a stable order.
    #[must_use]
    pub fn causes(&self) -> Vec<Cause> {
        self.seen.iter().copied().collect()
    }

    /// What to tell someone whose scan just failed.
    #[must_use]
    pub fn explanations(&self) -> Vec<&'static str> {
        self.seen.iter().map(|cause| cause.explanation()).collect()
    }

    /// Reads any string a value contains, however deeply.
    fn read(&mut self, value: &Value, origin: Origin) {
        match value {
            Value::String(text) => self.note_from(text, origin),
            Value::Array(items) => {
                for item in items {
                    self.read(item, origin);
                }
            }
            Value::Object(fields) => {
                for field in fields.values() {
                    self.read(field, origin);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::{ThreadError, ThreadItem};
    use serde_json::json;

    fn item(fields: Value) -> ThreadItem {
        ThreadItem {
            id: None,
            item_type: "command_execution".to_owned(),
            fields: fields.as_object().expect("an object").clone(),
        }
    }

    /// The failure that cost the most time: every command refused, reported as
    /// though the model had simply not done its work.
    #[test]
    fn recognises_a_sandbox_that_would_not_start() {
        assert_eq!(
            recognise("bwrap: Failed to make / slave: Permission denied"),
            Some(Cause::SandboxUnavailable)
        );
    }

    /// Naming a blocker without a way past it leaves the reader stuck, which is
    /// what the original message already did.
    #[test]
    fn offers_a_way_past_a_sandbox_that_will_not_start() {
        let explanation = Cause::SandboxUnavailable.explanation();

        assert!(explanation.contains("idmapped"), "{explanation}");
        assert!(explanation.contains("--yolo"), "{explanation}");
    }

    /// It must not be mistaken for a credentials problem, which is what
    /// "Permission denied" on its own suggests.
    #[test]
    fn does_not_read_a_sandbox_failure_as_a_rejected_key() {
        let cause = recognise("bwrap: Failed to make / slave: Permission denied");

        assert_ne!(cause, Some(Cause::EndpointRejectedKey));
    }

    /// The provider's own wording sends people to reorder something, which
    /// cannot help. The explanation has to say so.
    #[test]
    fn explains_that_order_is_not_the_problem() {
        let explanation = Cause::OneSystemMessageOnly.explanation();

        assert!(
            explanation.contains("order is not the problem"),
            "{explanation}"
        );
        assert!(explanation.contains("merge-system"), "{explanation}");
    }

    #[test]
    fn recognises_the_template_refusal_as_the_server_sends_it() {
        assert_eq!(
            recognise("Jinja Exception: System message must be at the beginning."),
            Some(Cause::OneSystemMessageOnly)
        );
    }

    #[test]
    fn recognises_a_removed_request_shape() {
        assert_eq!(
            recognise("`wire_api = \"chat\"` is no longer supported."),
            Some(Cause::WireApiUnsupported)
        );
    }

    #[test]
    fn recognises_an_endpoint_that_did_not_answer() {
        for text in [
            "endpoint unreachable: Connection refused",
            "failed to lookup address information",
            // Observed verbatim from a scan against a dead address.
            "stream disconnected before completion: error sending request for url \
             (http://127.0.0.1:1/v1/responses)",
        ] {
            assert_eq!(recognise(text), Some(Cause::EndpointUnreachable), "{text}");
        }
    }

    #[test]
    fn recognises_refused_credentials_and_an_absent_model() {
        assert_eq!(
            recognise(r#"{"error":{"code":"invalid_api_key"}}"#),
            Some(Cause::EndpointRejectedKey)
        );
        assert_eq!(
            recognise(r#"{"error":{"code":"model_not_found"}}"#),
            Some(Cause::ModelNotServed)
        );
    }

    /// Ordinary output must not be diagnosed as a failure.
    /// The plugin reports a reused output directory as a sqlite traceback, which
    /// reads as a defect in the tool. Emptying the directory does not help,
    /// because the record outlives the files — so the explanation has to say so.
    #[test]
    fn explains_an_output_directory_that_has_already_been_scanned() {
        let cause = recognise(
            "Traceback (most recent call last):\n  sqlite3.IntegrityError: \
             UNIQUE constraint failed: scans.scan_dir",
        );

        assert_eq!(cause, Some(Cause::OutputDirectoryAlreadyScanned));
        let explanation = Cause::OutputDirectoryAlreadyScanned.explanation();
        assert!(
            explanation.contains("Emptying it is not enough"),
            "{explanation}"
        );
        assert!(explanation.contains("--output-dir"), "{explanation}");
    }

    #[test]
    fn says_nothing_about_text_that_reveals_nothing() {
        for text in [
            "",
            "Reviewing src/app.py for injection risks",
            "wrote findings.json",
        ] {
            assert_eq!(recognise(text), None, "{text}");
        }
    }

    /// A scan reviewing authentication code discusses exactly the vocabulary
    /// these recognisers look for. Reading its findings as diagnostics told a
    /// real run "the endpoint refused the credentials" when the endpoint had
    /// answered every request and the save had failed on a schema mismatch.
    #[test]
    fn does_not_read_the_scans_own_security_analysis_as_a_failure() {
        let mut watch = FailureWatch::new();

        watch.observe(&ThreadEvent::ItemCompleted {
            item: Some(item(json!({
                "output": "The /admin route returns 401 Unauthorized without a session; \
                           an invalid_api_key is rejected with 403 Forbidden.",
            }))),
        });

        assert!(watch.causes().is_empty(), "{:?}", watch.causes());
    }

    /// The same words in a reported failure are still read, because there they
    /// are the endpoint talking rather than the repository.
    #[test]
    fn still_reads_those_words_when_the_scan_itself_reports_them() {
        let mut watch = FailureWatch::new();

        watch.note(r#"{"error":{"code":"invalid_api_key"}}"#);

        assert_eq!(watch.causes(), [Cause::EndpointRejectedKey]);
    }

    /// A bare status number appears in hashes and paths; it is not evidence.
    #[test]
    fn does_not_treat_a_bare_number_as_a_status() {
        assert_eq!(recognise("digest sha256:9f401403ab and scope 401403"), None);
        assert_eq!(
            recognise("endpoint returned status 401"),
            Some(Cause::EndpointRejectedKey)
        );
    }

    /// A sandbox failure is reported by the command that could not run, so it
    /// must still be recognised there.
    /// Scanning a codebase that discusses sandboxing must not look like a
    /// sandbox failure. This tool's own source mentions bwrap throughout, and a
    /// scan of it reported the sandbox as broken while running with the sandbox
    /// deliberately off.
    #[test]
    fn does_not_read_source_that_mentions_bwrap_as_a_sandbox_failure() {
        for text in [
            "let bwrap = find_bundled_bwrap();",
            "// Codex ships its own bubblewrap; running bwrap is the only check",
            "the bwrap binary lives under codex-resources",
            "puncode-security scan . --dangerously-disable-sandbox   # alias: --yolo",
        ] {
            assert_eq!(recognise(text), None, "{text}");
        }
    }

    #[test]
    fn still_reads_a_sandbox_failure_from_command_output() {
        let mut watch = FailureWatch::new();

        watch.observe(&ThreadEvent::ItemCompleted {
            item: Some(item(json!({ "output": "bwrap: permission denied" }))),
        });

        assert_eq!(watch.causes(), [Cause::SandboxUnavailable]);
    }

    /// The evidence arrives inside command output, which is a nested field.
    #[test]
    fn finds_evidence_nested_in_an_event() {
        let mut watch = FailureWatch::new();

        watch.observe(&ThreadEvent::ItemCompleted {
            item: Some(item(json!({
                "command": "ls",
                "result": { "output": "bwrap: Failed to make / slave: Permission denied" },
            }))),
        });

        assert_eq!(watch.causes(), [Cause::SandboxUnavailable]);
    }

    #[test]
    fn reads_a_failed_turn() {
        let mut watch = FailureWatch::new();

        watch.observe(&ThreadEvent::TurnFailed {
            error: Some(ThreadError {
                message: Some("System message must be at the beginning.".to_owned()),
            }),
        });

        assert_eq!(watch.causes(), [Cause::OneSystemMessageOnly]);
    }

    /// The same failure repeats on every command; it should be said once.
    #[test]
    fn reports_a_repeated_cause_once() {
        let mut watch = FailureWatch::new();

        for _ in 0..5 {
            watch.observe(&ThreadEvent::ItemCompleted {
                item: Some(item(json!({ "output": "bwrap: permission denied" }))),
            });
        }

        assert_eq!(watch.explanations().len(), 1);
    }

    #[test]
    fn says_nothing_when_nothing_was_recognised() {
        let mut watch = FailureWatch::new();

        watch.observe(&ThreadEvent::TurnStarted);
        watch.note("scanning");

        assert!(watch.explanations().is_empty());
    }

    /// The text that revealed a cause is not kept: it is the prompt and the
    /// source under review.
    #[test]
    fn keeps_the_cause_and_not_the_evidence() {
        let mut watch = FailureWatch::new();

        watch.note("bwrap failed while running: SECRET_SOURCE_LINE");

        let held = format!("{watch:?}");
        assert!(!held.contains("SECRET_SOURCE_LINE"), "{held}");
    }
}

#[cfg(test)]
mod working_tree_tests {
    use super::*;

    /// The exact message a real run produced, after the agent compiled the C it
    /// was scanning and left the binary in the tree.
    #[test]
    fn recognises_the_message_a_real_run_produced() {
        let failure = "Could not save the Puncode Security scan: Working-tree contents changed \
                       while the scan was running. Start a new scan.";

        assert_eq!(recognise(failure), Some(Cause::WorkingTreeChanged));
    }

    /// The explanation has to name the likely writer, because the message does
    /// not and the obvious reading — "somebody edited my code" — sends you
    /// looking in the wrong place.
    #[test]
    fn the_explanation_names_the_agent_as_the_usual_writer() {
        let explanation = Cause::WorkingTreeChanged.explanation();

        assert!(explanation.contains("agent itself"), "{explanation}");
        assert!(explanation.contains("compile"), "{explanation}");
        assert!(explanation.contains("build output"), "{explanation}");
        // And says the work is not lost, which the workbench's message does not.
        assert!(explanation.contains("still on disk"), "{explanation}");
    }

    /// A scan of a codebase that discusses working trees — this one — must not
    /// look like this failure.
    #[test]
    fn does_not_fire_on_prose_about_working_trees() {
        for text in [
            "the working tree is clean",
            "compare the working tree against HEAD",
            "Working-tree contents are hashed for the snapshot digest",
        ] {
            assert_eq!(recognise(text), None, "{text}");
        }
    }

    /// And never from the repository's own output, like every other cause but
    /// the sandbox.
    #[test]
    fn is_not_read_out_of_command_output() {
        let failure = "Working-tree contents changed while the scan was running.";

        assert_eq!(recognise_from(failure, Origin::CommandOutput), None);
    }

    /// It must not be confused with the HEAD failure, which has a different
    /// cause and a different fix.
    #[test]
    fn is_distinct_from_the_head_failure() {
        let head = "Repository HEAD changed while the scan was running. Start a new scan.";

        assert_ne!(recognise(head), Some(Cause::WorkingTreeChanged));
    }
}

/// Files in a repository that differ from what is committed.
///
/// Only meaningful for [`Cause::WorkingTreeChanged`], and it is the difference
/// between a diagnosis and evidence: the workbench says the tree changed and
/// cannot say what changed, while the answer is usually one obvious build
/// artefact sitting next to the source.
///
/// Best effort by design. Not a git repository, no `git` on the path, a slow
/// filesystem — all of them return nothing rather than delaying a failure that
/// has already happened.
#[must_use]
pub fn changed_paths(repository: &std::path::Path) -> Vec<String> {
    /// Enough to recognise the culprit; a longer list is a different problem.
    const MOST: usize = 10;

    let Ok(output) = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (status, path) = line.split_at(line.char_indices().nth(3)?.0);
            Some(format!("{} {path}", status.trim()))
        })
        .take(MOST)
        .collect()
}

#[cfg(test)]
mod changed_paths_tests {
    use super::*;

    fn repository() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("a directory");
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(directory.path())
                .args(args)
                .output()
                .expect("git runs");
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@example.com"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(directory.path().join("a.c"), "int main(void){return 0;}\n")
            .expect("writes");
        run(&["add", "-A"]);
        run(&["commit", "-qm", "one"]);
        directory
    }

    /// The real shape of the failure: a compiled binary left beside the source.
    #[test]
    fn names_a_build_artefact_left_in_the_tree() {
        let directory = repository();
        std::fs::write(directory.path().join("a.out"), [0x7f, b'E', b'L', b'F']).expect("writes");

        let changed = changed_paths(directory.path());

        assert_eq!(changed, vec!["?? a.out"]);
    }

    #[test]
    fn names_an_edited_file() {
        let directory = repository();
        std::fs::write(directory.path().join("a.c"), "int main(void){return 1;}\n")
            .expect("writes");

        assert_eq!(changed_paths(directory.path()), vec!["M a.c"]);
    }

    #[test]
    fn says_nothing_about_a_clean_tree() {
        assert!(changed_paths(repository().path()).is_empty());
    }

    /// A failure that has already happened must not be delayed by this, so
    /// anything that does not work returns nothing.
    #[test]
    fn says_nothing_when_there_is_no_repository() {
        let directory = tempfile::tempdir().expect("a directory");

        assert!(changed_paths(directory.path()).is_empty());
        assert!(changed_paths(std::path::Path::new("/does/not/exist")).is_empty());
    }

    /// Bounded: a tree with hundreds of changes is a different problem, and a
    /// wall of paths buries the one line that matters.
    #[test]
    fn keeps_the_list_short() {
        let directory = repository();
        for index in 0..40 {
            std::fs::write(directory.path().join(format!("f{index}.o")), "x").expect("writes");
        }

        assert_eq!(changed_paths(directory.path()).len(), 10);
    }
}

#[cfg(test)]
mod manifest_publication_tests {
    use super::*;

    /// The exact message three real runs produced on 2026-07-29.
    #[test]
    fn recognises_the_message_real_runs_produced() {
        for failure in [
            "Could not save the Puncode Security scan: The sealed scan manifest changed while it \
             was being published.",
            "The sealed scan manifest changed after completion.",
        ] {
            assert_eq!(
                recognise(failure),
                Some(Cause::ManifestNotAsSerialised),
                "{failure}"
            );
        }
    }

    /// The message names a race. It is not one, and saying so is most of the
    /// value: somebody told to retry a race will retry, and it will happen
    /// again.
    #[test]
    fn the_explanation_says_it_is_not_a_race() {
        let explanation = Cause::ManifestNotAsSerialised.explanation();

        assert!(explanation.contains("usually not one"), "{explanation}");
        assert!(
            explanation.contains("agent writes the manifest"),
            "{explanation}"
        );
        // And that the work survives, which the workbench's message does not say.
        assert!(explanation.contains("findings are intact"), "{explanation}");
        // And what not to do about it.
        assert!(explanation.contains("Do not rewrite"), "{explanation}");
    }

    #[test]
    fn is_not_read_out_of_command_output() {
        let failure = "The sealed scan manifest changed while it was being published.";

        assert_eq!(recognise_from(failure, Origin::CommandOutput), None);
    }

    /// It must stay distinct from the other two save failures, which have
    /// different causes and different answers.
    #[test]
    fn is_distinct_from_the_other_save_failures() {
        for other in [
            "Repository HEAD changed while the scan was running.",
            "Working-tree contents changed while the scan was running.",
        ] {
            assert_ne!(
                recognise(other),
                Some(Cause::ManifestNotAsSerialised),
                "{other}"
            );
        }
    }
}
