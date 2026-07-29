//! Behavior tests for the error hierarchy.
//!
//! Ported from `src/errors.ts`. Upstream has no dedicated test file, so the
//! expectations here were pinned by probing the TypeScript classes directly.

use std::path::Path;

use codex_security::ScanCost;
use codex_security::error::{Error, ProtectedScanPathKind};

fn cost() -> ScanCost {
    ScanCost {
        model: "gpt-5.6-sol".to_owned(),
        input_tokens: 1_000,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 10,
        estimated_usd: 1.234_567_89,
    }
}

#[test]
fn output_inside_protected_root_message_names_the_path_kind() {
    let cases = [
        (ProtectedScanPathKind::Output, "output"),
        (ProtectedScanPathKind::Temporary, "temporary"),
        (ProtectedScanPathKind::Runtime, "runtime"),
    ];

    for (kind, label) in cases {
        let error = Error::output_inside_protected_root("/out/dir", "/protected", kind);
        assert_eq!(
            error.to_string(),
            format!("Scan {label} directory must be outside the protected scan root: /out/dir")
        );
    }
}

#[test]
fn output_inside_protected_root_defaults_to_the_output_kind() {
    let error = Error::output_inside_protected_root(
        "/out/dir",
        "/protected",
        ProtectedScanPathKind::default(),
    );

    assert_eq!(
        error.to_string(),
        "Scan output directory must be outside the protected scan root: /out/dir"
    );
}

#[test]
fn scan_cost_limit_message_formats_both_amounts() {
    let error = Error::scan_cost_limit_exceeded(0.5, cost(), "/scan/dir");

    assert_eq!(
        error.to_string(),
        "Scan stopped: estimated cost $1.23456789 exceeded the $0.50 limit; \
         partial output remains at /scan/dir."
    );
}

#[test]
fn cost_limit_is_also_a_scan_interruption() {
    let error = Error::scan_cost_limit_exceeded(0.5, cost(), "/scan/dir");

    assert!(error.is_scan_cost_limit_exceeded());
    assert!(
        error.is_scan_interrupted(),
        "must satisfy `instanceof ScanInterruptedError`"
    );
}

#[test]
fn protected_root_is_also_an_output_directory_error() {
    let error = Error::output_inside_protected_root(
        "/out/dir",
        "/protected",
        ProtectedScanPathKind::Output,
    );

    assert!(error.is_output_inside_protected_root());
    assert!(
        error.is_output_directory(),
        "must satisfy `instanceof OutputDirectoryError`"
    );
}

#[test]
fn python_unavailable_is_also_a_plugin_bootstrap_error() {
    let error = Error::plugin_python_unavailable("no python");

    assert!(
        error.is_plugin_bootstrap(),
        "must satisfy `instanceof PluginBootstrapError`"
    );
}

#[test]
fn plain_output_directory_error_is_not_a_protected_root_error() {
    let error = Error::output_directory("bad output");

    assert!(error.is_output_directory());
    assert!(!error.is_output_inside_protected_root());
}

#[test]
fn plain_interruption_is_not_a_cost_limit_error() {
    let error = Error::scan_interrupted("stopped", "/scan/dir");

    assert!(error.is_scan_interrupted());
    assert!(!error.is_scan_cost_limit_exceeded());
}

#[test]
fn exposes_scan_dir_for_both_interruption_kinds() {
    let interrupted = Error::scan_interrupted("stopped", "/scan/dir");
    let limit = Error::scan_cost_limit_exceeded(0.5, cost(), "/scan/dir");

    assert_eq!(interrupted.scan_dir(), Some(Path::new("/scan/dir")));
    assert_eq!(limit.scan_dir(), Some(Path::new("/scan/dir")));
    assert_eq!(Error::configuration("nope").scan_dir(), None);
}

#[test]
fn exposes_the_cost_limit_payload() {
    let error = Error::scan_cost_limit_exceeded(0.5, cost(), "/scan/dir");

    assert_eq!(error.max_cost_usd(), Some(0.5));
    assert_eq!(error.cost(), Some(&cost()));
}

#[test]
fn exposes_the_protected_root_payload() {
    let error = Error::output_inside_protected_root(
        "/out/dir",
        "/protected",
        ProtectedScanPathKind::Temporary,
    );

    // Named `_path` because `Error::output_directory` is the constructor.
    assert_eq!(error.output_directory_path(), Some(Path::new("/out/dir")));
    assert_eq!(error.protected_root(), Some(Path::new("/protected")));
    assert_eq!(error.path_kind(), Some(ProtectedScanPathKind::Temporary));
}

#[test]
fn class_names_match_the_typescript_hierarchy() {
    let cases: Vec<(Error, &str)> = vec![
        (Error::codex_security("x"), "CodexSecurityError"),
        (Error::configuration("x"), "ConfigurationError"),
        (
            Error::authentication_required("x"),
            "AuthenticationRequiredError",
        ),
        (Error::plugin_bootstrap("x"), "PluginBootstrapError"),
        (
            Error::plugin_python_unavailable("x"),
            "PluginPythonUnavailableError",
        ),
        (Error::invalid_target("x"), "InvalidTargetError"),
        (Error::output_directory("x"), "OutputDirectoryError"),
        (
            Error::output_inside_protected_root("/a", "/b", ProtectedScanPathKind::Output),
            "OutputInsideProtectedRootError",
        ),
        (Error::incomplete_scan("x"), "IncompleteScanError"),
        (Error::contract_validation("x"), "ContractValidationError"),
        (Error::scan_interrupted("x", "/s"), "ScanInterruptedError"),
        (
            Error::scan_cost_limit_exceeded(1.0, cost(), "/s"),
            "ScanCostLimitExceededError",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.class_name(), expected);
    }
}

#[test]
fn preserves_a_source_error() {
    let source = std::io::Error::new(std::io::ErrorKind::NotFound, "root cause");
    let error = Error::invalid_target("unknown Git ref: bad").with_source(source);

    assert_eq!(error.to_string(), "unknown Git ref: bad");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("root cause".to_owned())
    );
}

#[test]
fn messages_pass_through_unchanged() {
    assert_eq!(Error::configuration("a message").to_string(), "a message");
}

// Upstream aggregates a preparation failure with any cleanup failures into one
// `AggregateError`, so no failure is lost when both happen at once.
#[test]
fn aggregates_several_failures_under_one_message() {
    let error = Error::aggregate(
        [
            Error::plugin_bootstrap("Plugin path must be a directory or ZIP"),
            Error::codex_security("SYNTHETIC_PREPARATION_CLEANUP_FAILED"),
        ],
        "Codex Security runtime preparation failed and its isolated runtime \
         could not be cleaned up.",
    );

    assert_eq!(error.class_name(), "AggregateError");
    assert_eq!(
        error.to_string(),
        "Codex Security runtime preparation failed and its isolated runtime \
         could not be cleaned up."
    );
    let messages: Vec<String> = error.errors().iter().map(ToString::to_string).collect();
    assert_eq!(
        messages,
        [
            "Plugin path must be a directory or ZIP",
            "SYNTHETIC_PREPARATION_CLEANUP_FAILED"
        ]
    );
}

// Upstream sets `cause` to the originating error, so the first is also the
// source; predicates must still read the aggregate itself, not the cause.
#[test]
fn exposes_the_first_failure_as_the_cause() {
    let error = Error::aggregate(
        [Error::scan_interrupted("stopped", Path::new("/scan"))],
        "several failures",
    );

    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("stopped".to_owned())
    );
    assert!(
        !error.is_scan_interrupted(),
        "an aggregate is not itself an interruption"
    );
}

#[test]
fn reports_no_aggregated_failures_for_an_ordinary_error() {
    assert!(Error::configuration("plain").errors().is_empty());
}
