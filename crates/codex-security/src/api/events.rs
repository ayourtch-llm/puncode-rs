//! Driving a scan from the event stream to a result.
//!
//! Ported from `runScanEvents` in `src/api.ts`.
//!
//! The loop watches the turn go by, reporting progress as it happens, and then
//! insists the turn actually finished before gathering anything. Two failures
//! look similar on the stream and must not be confused: a transport hiccup that
//! Codex is already retrying is progress, while an error it is not retrying
//! ends the scan.

#![allow(dead_code)]

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

use crate::codex::ThreadEvent;
use crate::contract::ScanExpectation;
use crate::cost::ScanCost;
use crate::error::{Error, Result};
use crate::result::{ScanResult, TurnResultMetadata};
use crate::worker_progress::{ScanWorkerStatus, worker_status_from_event};

use super::environment::ScanAuthentication;

use super::collect::collect_result;
use super::connection::{ScanReconnectDetails, reconnect_attempt, reconnect_details};

/// Stops a scan, remembering why.
///
/// This replaces upstream's `AbortSignal`. The reason matters: a scan stopped
/// because it reached its cost limit must report that, not a generic
/// interruption, or the caller cannot tell a budget stop from a cancellation.
#[derive(Debug, Default)]
pub struct ScanCancellation {
    cancelled: AtomicBool,
    reason: Mutex<Option<Error>>,
}

impl ScanCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stops the scan without a specific reason.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Stops the scan, and reports `reason` instead of a generic interruption.
    pub fn cancel_with(&self, reason: Error) {
        if let Ok(mut current) = self.reason.lock() {
            *current = Some(reason);
        }
        self.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Takes the recorded reason, if one was given.
    pub fn take_reason(&self) -> Option<Error> {
        self.reason.lock().ok().and_then(|mut reason| reason.take())
    }
}

/// Watches a scan happen.
///
/// Upstream routes observer failures to an `onObserverError` callback because
/// its observers are asynchronous and can reject. These cannot fail, so a
/// failing observer cannot disturb the scan at all.
pub trait ScanObserver {
    /// The scan's thread identifier, once Codex reports it.
    fn on_thread_started(&mut self, thread_id: &str) {
        let _ = thread_id;
    }

    /// The scan has begun.
    fn on_scan_started(&mut self) {}

    /// How the scan will authenticate, before anything has been checked.
    fn on_authentication(&mut self, authentication: ScanAuthentication) {
        let _ = authentication;
    }

    /// Existing output was moved aside.
    fn on_output_archived(&mut self, archive_dir: &Path) {
        let _ = archive_dir;
    }

    /// The scan directory exists and is about to be written into.
    fn on_output_dir_ready(&mut self, scan_dir: &Path) {
        let _ = scan_dir;
    }

    /// The running cost changed.
    fn on_cost(&mut self, cost: &ScanCost) {
        let _ = cost;
    }

    /// Every event on the stream, before it is interpreted.
    ///
    /// This is where a cost tracker re-reads what the scan has spent, so a
    /// budget can stop the scan while it is still running rather than after.
    fn on_event(&mut self, event: &ThreadEvent) -> Result<()> {
        let _ = event;
        Ok(())
    }

    /// Delegation capacity or dispatch counts changed.
    fn on_worker_status(&mut self, status: &ScanWorkerStatus) {
        let _ = status;
    }

    /// Codex is retrying a transport failure.
    fn on_reconnect(
        &mut self,
        attempt: u32,
        max_attempts: u32,
        details: Option<ScanReconnectDetails>,
    ) {
        let _ = (attempt, max_attempts, details);
    }

    /// Called once the turn completes, before artifacts are gathered.
    ///
    /// Returning usage replaces what the turn reported, which is how a cost
    /// tracker contributes the totals it measured.
    fn finalize(&mut self, usage: Option<&Value>) -> Result<Option<Value>> {
        let _ = usage;
        Ok(None)
    }
}

/// An observer that does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct IgnoreScanEvents;

impl ScanObserver for IgnoreScanEvents {}

/// What the loop needs in order to turn a stream into a result.
pub struct ScanEventOptions<'a> {
    pub scan_dir: &'a Path,
    pub plugin_root: &'a Path,
    pub expectation: &'a ScanExpectation,
    /// Recorded on the result so the cost can be priced.
    pub model: Option<&'a str>,
    /// The thread identifier already known, if any.
    pub thread_id: Option<String>,
    pub cancellation: &'a ScanCancellation,
}

/// Consumes the event stream and gathers the scan it describes.
pub fn run_scan_events(
    events: impl IntoIterator<Item = Result<ThreadEvent>>,
    options: &ScanEventOptions<'_>,
    observer: &mut dyn ScanObserver,
) -> Result<ScanResult> {
    let outcome = drive(events, options, observer);
    let Err(error) = outcome else {
        return outcome;
    };

    // A recorded reason — a cost limit, say — describes the stop better than
    // whatever error the interruption produced downstream.
    if let Some(reason) = options.cancellation.take_reason() {
        return Err(reason);
    }
    if options.cancellation.is_cancelled() && !error.is_scan_interrupted() {
        return Err(interrupted(options.scan_dir).with_source(error));
    }
    Err(error)
}

fn drive(
    events: impl IntoIterator<Item = Result<ThreadEvent>>,
    options: &ScanEventOptions<'_>,
    observer: &mut dyn ScanObserver,
) -> Result<ScanResult> {
    let mut thread_id = options.thread_id.clone();
    let mut scan_started = false;
    let mut completed = false;
    let mut final_response = String::new();
    let mut usage: Option<Value> = None;
    let mut last_stream_error: Option<String> = None;

    for event in events {
        let event = event?;
        observer.on_event(&event)?;
        if let Some(status) = worker_status_from_event(&event) {
            observer.on_worker_status(&status);
        }

        match &event {
            ThreadEvent::ThreadStarted { thread_id: started } => {
                if let Some(started) = started {
                    thread_id = Some(started.clone());
                    observer.on_thread_started(started);
                }
                if !scan_started {
                    scan_started = true;
                    observer.on_scan_started();
                }
            }
            ThreadEvent::ItemCompleted { item: Some(item) }
                if item.item_type == "agent_message" =>
            {
                if let Some(text) = item.text() {
                    final_response = text.to_owned();
                }
            }
            ThreadEvent::TurnCompleted { usage: reported } => {
                completed = true;
                usage = (!reported.is_null()).then(|| reported.clone());
            }
            ThreadEvent::TurnFailed {
                error: Some(failure),
            } => {
                if let Some(message) = &failure.message {
                    return Err(Error::codex_security(message.clone()));
                }
            }
            ThreadEvent::Error {
                message: Some(message),
            } => {
                // A retry is progress; anything else ends the scan.
                let Some((attempt, max_attempts)) = reconnect_attempt(message) else {
                    return Err(Error::codex_security(message.clone()));
                };
                last_stream_error = Some(message.clone());
                observer.on_reconnect(attempt, max_attempts, reconnect_details(message));
            }
            _ => {}
        }
    }

    if options.cancellation.is_cancelled() {
        return Err(interrupted(options.scan_dir));
    }
    if !completed {
        // The last retry message explains the silence better than a generic
        // "ended early" would.
        return Err(Error::incomplete_scan(last_stream_error.unwrap_or_else(
            || "Codex Security event stream ended before the turn completed.".to_owned(),
        )));
    }
    let Some(thread_id) = thread_id else {
        return Err(Error::incomplete_scan(
            "Codex Security did not report a thread ID.",
        ));
    };

    if let Some(measured) = observer.finalize(usage.as_ref())? {
        usage = Some(measured);
    }

    let turn = TurnResultMetadata {
        status: Some("completed".to_owned()),
        final_response: Some(final_response),
        usage,
        model: options.model.map(str::to_owned),
        ..TurnResultMetadata::default()
    };
    let result = collect_result(
        turn,
        &thread_id,
        options.scan_dir,
        options.plugin_root,
        options.expectation,
    )?;

    // Gathering takes time of its own; a stop during it still stops the scan.
    if options.cancellation.is_cancelled() {
        return Err(interrupted(options.scan_dir));
    }
    Ok(result)
}

fn interrupted(scan_dir: &Path) -> Error {
    Error::scan_interrupted(
        format!(
            "Codex Security scan was interrupted; partial output remains at {}.",
            scan_dir.display()
        ),
        scan_dir,
    )
}
