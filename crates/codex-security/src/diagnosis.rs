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
        }
    }
}

/// The cause some text reveals, if it reveals one.
#[must_use]
pub fn recognise(text: &str) -> Option<Cause> {
    let lowered = text.to_ascii_lowercase();

    // Checked before the generic refusals below: a sandbox that will not start
    // reports a permission problem that is not about credentials.
    if lowered.contains("bwrap")
        || (lowered.contains("failed to make") && lowered.contains("slave"))
        || lowered.contains("sandbox could not be initialized")
    {
        return Some(Cause::SandboxUnavailable);
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
        || lowered.contains("unauthorized")
        || lowered.contains("401")
        || lowered.contains("403")
    {
        return Some(Cause::EndpointRejectedKey);
    }
    if lowered.contains("model_not_found")
        || lowered.contains("unknown model")
        || lowered.contains("does not exist")
    {
        return Some(Cause::ModelNotServed);
    }
    None
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
                    self.read(value);
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
    fn read(&mut self, value: &Value) {
        match value {
            Value::String(text) => self.note(text),
            Value::Array(items) => {
                for item in items {
                    self.read(item);
                }
            }
            Value::Object(fields) => {
                for field in fields.values() {
                    self.read(field);
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
