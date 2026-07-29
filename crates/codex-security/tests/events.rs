//! Behavior tests for the scan event loop.
//!
//! Ported from the `runScanEvents` behavior in `tests-ts/api.test.ts`. Streams
//! are canned, so every branch is reachable without running a scan.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use codex_security::api::{
    ReconnectReason, ScanCancellation, ScanEventOptions, ScanObserver, ScanReconnectDetails,
    run_scan_events,
};
use codex_security::codex::ThreadEvent;
use codex_security::contract::ScanExpectation;
use codex_security::targets::{NormalizedTarget, NormalizedTargetKind, ScanMode};
use codex_security::worker_progress::ScanWorkerStatus;
use serde_json::{Value, json};
use tempfile::TempDir;

fn plugin_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn completed_scan() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("temp dir");
    let scan = fs::canonicalize(root.path())
        .expect("canonical")
        .join("scan");
    fs::create_dir(&scan).expect("create scan directory");
    let source = plugin_root().join("completed-scan");
    for name in ["scan-manifest.json", "findings.json", "coverage.json"] {
        fs::copy(source.join(name), scan.join(name)).expect("copy document");
    }
    fs::write(scan.join("report.md"), b"# Scan report\n").expect("write report");
    (root, scan)
}

fn expectation() -> ScanExpectation {
    ScanExpectation {
        repository: PathBuf::from("/repo"),
        repository_revision: Some("deadbeef".to_owned()),
        target: NormalizedTarget {
            kind: Some(NormalizedTargetKind::Repository),
            ..NormalizedTarget::default()
        },
        mode: ScanMode::Standard,
        plugin_version: "0.1.0".to_owned(),
    }
}

fn event(value: Value) -> codex_security::Result<ThreadEvent> {
    Ok(serde_json::from_value(value).expect("event parses"))
}

/// The stream a successful scan produces.
fn successful_stream() -> Vec<codex_security::Result<ThreadEvent>> {
    vec![
        event(json!({ "type": "thread.started", "thread_id": "thread-1" })),
        event(json!({ "type": "turn.started" })),
        event(json!({
            "type": "item.completed",
            "item": { "id": "m1", "type": "agent_message", "text": "scan complete" }
        })),
        event(json!({
            "type": "turn.completed",
            "usage": { "input_tokens": 1_250, "cached_input_tokens": 200, "output_tokens": 30 }
        })),
    ]
}

/// Records everything the loop reports.
#[derive(Default)]
struct Recorder {
    thread_ids: Vec<String>,
    scan_started: usize,
    worker_statuses: Vec<ScanWorkerStatus>,
    reconnects: Vec<(u32, u32, Option<ScanReconnectDetails>)>,
    finalize_saw: Option<Option<Value>>,
    finalize_returns: Option<Value>,
}

impl ScanObserver for Recorder {
    fn on_thread_started(&mut self, thread_id: &str) {
        self.thread_ids.push(thread_id.to_owned());
    }
    fn on_scan_started(&mut self) {
        self.scan_started += 1;
    }
    fn on_worker_status(&mut self, status: &ScanWorkerStatus) {
        self.worker_statuses.push(status.clone());
    }
    fn on_reconnect(
        &mut self,
        attempt: u32,
        max_attempts: u32,
        details: Option<ScanReconnectDetails>,
    ) {
        self.reconnects.push((attempt, max_attempts, details));
    }
    fn finalize(&mut self, usage: Option<&Value>) -> codex_security::Result<Option<Value>> {
        self.finalize_saw = Some(usage.cloned());
        Ok(self.finalize_returns.clone())
    }
}

fn options<'a>(
    scan_dir: &'a std::path::Path,
    expectation: &'a ScanExpectation,
    cancellation: &'a ScanCancellation,
) -> ScanEventOptions<'a> {
    ScanEventOptions {
        scan_dir,
        plugin_root: Box::leak(plugin_root().into_boxed_path()),
        expectation,
        model: Some("gpt-5.6-sol"),
        thread_id: None,
        cancellation,
    }
}

#[test]
fn drives_a_successful_scan_to_a_result() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();

    let result = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect("scan completes");

    assert_eq!(result.thread_id, "thread-1");
    assert_eq!(result.turn_result.status.as_deref(), Some("completed"));
    assert_eq!(
        result.turn_result.final_response.as_deref(),
        Some("scan complete")
    );
    assert_eq!(result.cost.expect("priced").estimated_usd, 0.00625);
    assert_eq!(recorder.thread_ids, ["thread-1"]);
    assert_eq!(recorder.scan_started, 1);
}

#[test]
fn reports_worker_progress_as_it_happens() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let mut stream = successful_stream();
    stream.insert(
        2,
        event(json!({
            "type": "item.completed",
            "item": { "id": "m2", "type": "agent_message",
                      "text": "CODEX_SECURITY_WORKER_STATUS {\"phase\":\"ranking\",\"planned\":6,\"started\":2}" }
        })),
    );

    run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect("scan completes");

    assert_eq!(recorder.worker_statuses.len(), 1);
    assert!(matches!(
        recorder.worker_statuses[0],
        ScanWorkerStatus::Dispatch {
            planned: 6,
            started: 2,
            ..
        }
    ));
}

// A retry Codex is already handling is progress, not a failure.
#[test]
fn treats_a_retried_transport_failure_as_progress() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let mut stream = successful_stream();
    stream.insert(
        2,
        event(json!({
            "type": "error",
            "message": "Reconnecting... 2/5 rate limited; try again in 30 seconds"
        })),
    );

    run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect("the scan continues past a retry");

    assert_eq!(recorder.reconnects.len(), 1);
    let (attempt, max_attempts, details) = recorder.reconnects[0];
    assert_eq!((attempt, max_attempts), (2, 5));
    assert_eq!(
        details,
        Some(ScanReconnectDetails {
            reason: ReconnectReason::RateLimit,
            retry_after_seconds: Some(30.0)
        })
    );
}

// An error Codex is not retrying ends the scan.
#[test]
fn stops_on_an_error_that_is_not_a_retry() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![
        event(json!({ "type": "thread.started", "thread_id": "thread-1" })),
        event(json!({ "type": "error", "message": "stream disconnected permanently" })),
    ];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("an unretried error stops the scan");

    assert_eq!(error.to_string(), "stream disconnected permanently");
}

#[test]
fn stops_on_a_failed_turn() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![
        event(json!({ "type": "thread.started", "thread_id": "thread-1" })),
        event(json!({ "type": "turn.failed", "error": { "message": "model refused" } })),
    ];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("a failed turn stops the scan");

    assert_eq!(error.to_string(), "model refused");
}

// A stream that simply stops is not a completed scan.
#[test]
fn refuses_a_stream_that_ends_before_the_turn_completes() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![event(
        json!({ "type": "thread.started", "thread_id": "thread-1" }),
    )];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("an unfinished turn is refused");

    assert_eq!(
        error.to_string(),
        "Codex Security event stream ended before the turn completed."
    );
}

// The last retry message explains the silence better than a generic message.
#[test]
fn blames_the_last_retry_when_the_stream_dies_mid_reconnect() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![
        event(json!({ "type": "thread.started", "thread_id": "thread-1" })),
        event(json!({ "type": "error", "message": "Reconnecting... 5/5 ECONNRESET" })),
    ];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("an unfinished turn is refused");

    assert_eq!(error.to_string(), "Reconnecting... 5/5 ECONNRESET");
}

#[test]
fn refuses_a_scan_that_never_reported_a_thread() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![event(json!({ "type": "turn.completed", "usage": {} }))];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("a scan without a thread is refused");

    assert_eq!(
        error.to_string(),
        "Codex Security did not report a thread ID."
    );
}

#[test]
fn reports_cancellation_as_an_interruption_naming_the_partial_output() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    cancellation.cancel();
    let mut recorder = Recorder::default();

    let error = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("a cancelled scan is interrupted");

    assert!(error.is_scan_interrupted(), "{error}");
    assert_eq!(error.scan_dir(), Some(scan.as_path()));
    assert!(
        error.to_string().contains("partial output remains at"),
        "{error}"
    );
}

// A budget stop must be distinguishable from a plain cancellation.
#[test]
fn reports_a_cost_limit_stop_as_itself() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let cost = codex_security::ScanCost {
        model: "gpt-5.6-sol".to_owned(),
        input_tokens: 1_000_000,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 1_000_000,
        estimated_usd: 35.0,
    };
    cancellation.cancel_with(codex_security::Error::scan_cost_limit_exceeded(
        10.0, cost, &scan,
    ));
    let mut recorder = Recorder::default();

    let error = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("a cost limit stops the scan");

    assert!(error.is_scan_cost_limit_exceeded(), "{error}");
    assert_eq!(error.max_cost_usd(), Some(10.0));
    assert!(
        error
            .to_string()
            .starts_with("Scan stopped: estimated cost"),
        "{error}"
    );
}

// The turn reports usage, but a cost tracker may have measured more.
#[test]
fn lets_the_observer_replace_the_reported_usage() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder {
        finalize_returns: Some(json!({
            "input_tokens": 1_000_000, "output_tokens": 1_000_000
        })),
        ..Recorder::default()
    };

    let result = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect("scan completes");

    assert_eq!(
        recorder.finalize_saw,
        Some(Some(
            json!({ "input_tokens": 1_250, "cached_input_tokens": 200, "output_tokens": 30 })
        )),
        "the observer sees what the turn reported"
    );
    assert_eq!(
        result.cost.expect("priced").estimated_usd,
        35.0,
        "the measured usage is what gets priced"
    );
}

#[test]
fn propagates_a_failure_from_the_observer() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();

    struct FailingFinalize;
    impl ScanObserver for FailingFinalize {
        fn finalize(&mut self, _usage: Option<&Value>) -> codex_security::Result<Option<Value>> {
            Err(codex_security::Error::codex_security(
                "Cannot evaluate the cost limit: model pricing or token usage is unavailable.",
            ))
        }
    }

    let error = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut FailingFinalize,
    )
    .expect_err("the failure propagates");

    assert!(
        error
            .to_string()
            .starts_with("Cannot evaluate the cost limit"),
        "{error}"
    );
}

#[test]
fn propagates_a_stream_failure() {
    let (_root, scan) = completed_scan();
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();
    let stream = vec![
        event(json!({ "type": "thread.started", "thread_id": "thread-1" })),
        Err(codex_security::Error::codex_security(
            "Failed to parse item: not json",
        )),
    ];

    let error = run_scan_events(
        stream,
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("a stream failure propagates");

    assert_eq!(error.to_string(), "Failed to parse item: not json");
}

// An incomplete scan directory is still reported as such.
#[test]
fn reports_missing_artifacts_after_a_completed_turn() {
    let (_root, scan) = completed_scan();
    fs::remove_file(scan.join("report.md")).expect("remove");
    let expectation = expectation();
    let cancellation = ScanCancellation::new();
    let mut recorder = Recorder::default();

    let error = run_scan_events(
        successful_stream(),
        &options(&scan, &expectation, &cancellation),
        &mut recorder,
    )
    .expect_err("missing artifacts are reported");

    assert!(
        error.to_string().contains("without required artifacts"),
        "{error}"
    );
}
