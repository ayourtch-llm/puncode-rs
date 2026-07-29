//! Differential tests for connection failure classification.
//!
//! Every expectation was produced by running the TypeScript implementation over
//! the same message. Regenerate with `probe-conn.ts`.

use codex_security::api::{
    ConnectionFailure, ReconnectReason, classify_connection_failure, reconnect_attempt,
    reconnect_details,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    message: String,
    classification: String,
    /// `[attempt, max]`, or absent when the message is not a reconnection.
    attempt: Option<(u32, u32)>,
    details: Option<Details>,
}

#[derive(Deserialize)]
struct Details {
    reason: String,
    #[serde(rename = "retryAfterSeconds")]
    retry_after_seconds: Option<f64>,
}

fn cases() -> Vec<Case> {
    serde_json::from_str(include_str!("fixtures/connection-failures.json")).expect("fixture parses")
}

#[test]
fn classifies_failures_identically_to_the_typescript_implementation() {
    let cases = cases();
    assert!(
        cases.len() > 50,
        "fixture should be broad, got {}",
        cases.len()
    );

    let mut mismatches = Vec::new();
    for case in &cases {
        let actual = classify_connection_failure(&case.message).as_str();
        if actual != case.classification {
            mismatches.push(format!(
                "{:?}: expected {}, got {actual}",
                case.message, case.classification
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn reads_reconnection_attempts_identically() {
    let mut mismatches = Vec::new();
    for case in &cases() {
        let actual = reconnect_attempt(&case.message);
        if actual != case.attempt {
            mismatches.push(format!(
                "{:?}: expected {:?}, got {actual:?}",
                case.message, case.attempt
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn describes_reconnections_identically() {
    let mut mismatches = Vec::new();
    for case in &cases() {
        let actual = reconnect_details(&case.message);
        let expected_reason = case.details.as_ref().map(|details| details.reason.as_str());
        let actual_reason = actual.map(|details| details.reason.as_str());
        if actual_reason != expected_reason {
            mismatches.push(format!(
                "{:?}: expected reason {expected_reason:?}, got {actual_reason:?}",
                case.message
            ));
            continue;
        }
        let expected_delay = case
            .details
            .as_ref()
            .and_then(|details| details.retry_after_seconds);
        let actual_delay = actual.and_then(|details| details.retry_after_seconds);
        if actual_delay != expected_delay {
            mismatches.push(format!(
                "{:?}: expected delay {expected_delay:?}, got {actual_delay:?}",
                case.message
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

// The classification order matters: a message can mention several things, and
// the most specific one has to win.
#[test]
fn prefers_the_most_specific_classification() {
    assert_eq!(
        classify_connection_failure("429 rate limit; connection will retry"),
        ConnectionFailure::RateLimited,
        "a rate limit outranks the connection mention"
    );
    assert_eq!(
        classify_connection_failure("unauthorized network failure"),
        ConnectionFailure::Unauthorized,
        "credentials outrank the network mention"
    );
}

// An implausible delay is dropped rather than passed on.
#[test]
fn ignores_an_out_of_range_retry_delay() {
    let hour = reconnect_details("rate limited; try again in 3600 seconds")
        .expect("rate limited")
        .retry_after_seconds;
    assert_eq!(hour, Some(3600.0), "an hour is the largest delay reported");

    let beyond = reconnect_details("rate limited; try again in 3601 seconds")
        .expect("rate limited")
        .retry_after_seconds;
    assert_eq!(beyond, None, "beyond an hour is treated as noise");

    let zero = reconnect_details("rate limited; try again in 0 seconds")
        .expect("rate limited")
        .retry_after_seconds;
    assert_eq!(zero, None);
}

#[test]
fn reports_no_details_for_unclassifiable_messages() {
    assert_eq!(reconnect_details("request timed out"), None);
    assert_eq!(reconnect_details("something else entirely"), None);
    assert_eq!(reconnect_details(""), None);
}

#[test]
fn requires_a_coherent_attempt_count() {
    assert_eq!(reconnect_attempt("Reconnecting... 5/5"), Some((5, 5)));
    assert_eq!(
        reconnect_attempt("Reconnecting... 6/5"),
        None,
        "an attempt beyond the maximum is not a progress report"
    );
    assert_eq!(reconnect_attempt("Reconnecting... 0/5"), None);
}

#[test]
fn renders_wire_values() {
    assert_eq!(ConnectionFailure::RateLimited.as_str(), "rate_limited");
    assert_eq!(ConnectionFailure::NetworkError.as_str(), "network_error");
    assert_eq!(ReconnectReason::RateLimit.as_str(), "rate_limit");
    assert_eq!(ReconnectReason::Authorization.as_str(), "authorization");
}
