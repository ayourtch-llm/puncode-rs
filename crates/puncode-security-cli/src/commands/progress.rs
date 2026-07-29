//! Reporting a scan's progress while it runs.
//!
//! Ported from the `Progress` handling in `src/cli.ts`.
//!
//! A scan takes minutes, so silence is indistinguishable from a hang. Progress
//! goes to standard error, never standard output: the report on stdout has to
//! stay parseable when it is redirected, and progress is not part of it.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use puncode_security::api::{ScanAuthentication, ScanCancellation, ScanObserver};
use puncode_security::cost::{ScanCost, format_usd};
use puncode_security::diagnosis::FailureWatch;
use puncode_security::worker_progress::ScanWorkerStatus;

/// Tells a person what a scan is doing.
pub struct ScanProgress {
    /// Stops reporting once the scan is being torn down.
    quiet: bool,
    /// The cost ceiling, when one was set.
    max_cost_usd: Option<f64>,
    /// Where results are being written, once that is known.
    pub scan_dir: Option<std::path::PathBuf>,
    /// Signs that something other than the model is at fault.
    watch: FailureWatch,
}

impl ScanProgress {
    #[must_use]
    pub fn new(quiet: bool, max_cost_usd: Option<f64>) -> Self {
        Self {
            quiet,
            max_cost_usd,
            scan_dir: None,
            watch: FailureWatch::new(),
        }
    }

    /// What better explains a failure than the failure itself.
    ///
    /// `problem` is read too: an endpoint's own refusal arrives as the error
    /// rather than as an event.
    pub fn explanations(&mut self, problem: &str) -> Vec<&'static str> {
        self.watch.note(problem);
        self.watch.explanations()
    }

    fn say(&self, message: &str) {
        if self.quiet {
            return;
        }
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "puncode-security: {message}");
        let _ = stderr.flush();
    }
}

impl ScanObserver for ScanProgress {
    fn on_authentication(&mut self, authentication: ScanAuthentication) {
        self.say(match authentication {
            ScanAuthentication::ApiKey { .. } => "Authentication: API key.",
            ScanAuthentication::StoredCredentials { .. } => {
                "Authentication: stored Codex credentials."
            }
        });
    }

    fn on_output_archived(&mut self, archive_dir: &std::path::Path) {
        self.say(&format!(
            "Moved existing results to: {}",
            archive_dir.display()
        ));
    }

    fn on_output_dir_ready(&mut self, scan_dir: &std::path::Path) {
        // Remembered so an interrupted scan can say where its partial output
        // was left.
        self.scan_dir = Some(scan_dir.to_path_buf());
        self.say(&format!("Results: {}", scan_dir.display()));
    }

    fn on_scan_started(&mut self) {
        self.say("Scanning.");
    }

    fn on_worker_status(&mut self, status: &ScanWorkerStatus) {
        if let ScanWorkerStatus::Dispatch {
            phase,
            planned,
            started,
        } = status
        {
            self.say(&format!(
                "Workers: {started} of {planned} ({}).",
                phase.as_str()
            ));
        }
    }

    fn on_reconnect(
        &mut self,
        attempt: u32,
        max_attempts: u32,
        _details: Option<puncode_security::api::ScanReconnectDetails>,
    ) {
        self.say(&format!("Reconnecting ({attempt}/{max_attempts}).",));
    }

    fn on_cost(&mut self, cost: &ScanCost) {
        let Some(limit) = self.max_cost_usd else {
            return;
        };
        self.say(&format!(
            "Estimated cost: {} of {} limit",
            format_usd(cost.estimated_usd),
            format_usd(limit)
        ));
    }

    fn on_event(
        &mut self,
        event: &puncode_security::codex::ThreadEvent,
    ) -> puncode_security::Result<()> {
        // Read for signs of an environment failure. Only the cause is kept.
        self.watch.observe(event);
        Ok(())
    }
}

/// A termination signal this command answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// Ctrl-C.
    Interrupt,
    /// A request to terminate, usually from a supervisor.
    Terminate,
}

impl Termination {
    /// The conventional exit code for dying to this signal.
    ///
    /// 128 plus the signal number, which is what shells and CI report.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Interrupt => 130,
            Self::Terminate => 143,
        }
    }

    /// How the scan's ending is described to the person.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Interrupt => "canceled by Ctrl-C",
            Self::Terminate => "terminated by SIGTERM",
        }
    }

    /// The signal an exit code stands for, if it stands for one.
    #[must_use]
    pub fn from_exit_code(code: u8) -> Option<Self> {
        match code {
            130 => Some(Self::Interrupt),
            143 => Some(Self::Terminate),
            _ => None,
        }
    }

    fn from_raw(signal: i32) -> Option<Self> {
        match signal {
            signal_hook::consts::SIGINT => Some(Self::Interrupt),
            signal_hook::consts::SIGTERM => Some(Self::Terminate),
            _ => None,
        }
    }
}

/// What to do about a signal that just arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Ask the scan to stop, keeping whatever it has produced.
    Cancel,
    /// A duplicate delivery of the signal already being acted on.
    Ignore,
    /// Leave now, with this code.
    ForceExit(u8),
}

/// How long after the first signal a repeat of it is treated as an echo.
const DUPLICATE_WINDOW_MS: i64 = 500;

/// Decides what each arriving signal means.
///
/// Launchers and terminals can deliver the same signal twice for one keypress,
/// so a repeat of the *same* signal shortly after the first is an echo rather
/// than a second request — acting on it would kill a scan the person only asked
/// once to stop, throwing away partial output. A repeat after that window, or a
/// different signal at any time, is a genuine second request and restores the
/// conventional escape hatch: a scan that will not stop must still be stoppable.
#[derive(Debug, Default)]
pub struct SignalTracker {
    requested: Option<Termination>,
    first_seen_ms: i64,
}

impl SignalTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a signal and says what should happen.
    pub fn observe(&mut self, signal: Termination, now_ms: i64) -> SignalAction {
        let Some(already) = self.requested else {
            self.requested = Some(signal);
            self.first_seen_ms = now_ms;
            return SignalAction::Cancel;
        };

        if signal == already && now_ms.saturating_sub(self.first_seen_ms) < DUPLICATE_WINDOW_MS {
            return SignalAction::Ignore;
        }

        self.requested = Some(signal);
        SignalAction::ForceExit(signal.exit_code())
    }
}

/// Whether the scan was asked to stop, and what for.
///
/// A scan that stopped because it was asked to is a different outcome from one
/// that failed, and a CI job acts on the difference, so the reason has to
/// survive the scan returning.
#[derive(Clone, Default)]
pub struct InterruptReport(Arc<AtomicU8>);

impl InterruptReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The signal the scan was asked to stop for, if it was.
    #[must_use]
    pub fn requested(&self) -> Option<Termination> {
        Termination::from_exit_code(self.0.load(Ordering::SeqCst))
    }

    fn record(&self, signal: Termination) {
        self.0.store(signal.exit_code(), Ordering::SeqCst);
    }
}

/// Asks the scan to stop when the person interrupts it.
///
/// The first interrupt asks the scan to stop so partial output is kept and the
/// workbench is told what happened. A later one leaves immediately. See
/// [`SignalTracker`] for which arrivals count as "later".
pub fn install_interrupt_handler(cancellation: &Arc<ScanCancellation>) -> InterruptReport {
    let requested = InterruptReport::new();
    let seen = requested.clone();
    let cancellation = Arc::clone(cancellation);

    // Signals are delivered to a dedicated thread rather than a handler, so
    // the work it does is ordinary safe code.
    if let Ok(mut signals) = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ]) {
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            let mut tracker = SignalTracker::new();
            for raw in signals.forever() {
                let Some(signal) = Termination::from_raw(raw) else {
                    continue;
                };
                let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
                match tracker.observe(signal, elapsed_ms) {
                    SignalAction::Ignore => {}
                    SignalAction::Cancel => {
                        seen.record(signal);
                        cancellation.cancel();
                        let mut stderr = std::io::stderr();
                        let _ = writeln!(
                            stderr,
                            "puncode-security: Stopping; press again to exit immediately."
                        );
                        let _ = stderr.flush();
                    }
                    SignalAction::ForceExit(code) => {
                        // Restoring the cursor is best-effort; the escape must
                        // still win even if the terminal will not cooperate.
                        let mut stderr = std::io::stderr();
                        let _ = write!(stderr, "\u{1b}[?25h");
                        let _ = stderr.flush();
                        std::process::exit(i32::from(code));
                    }
                }
            }
        });
    }
    requested
}

#[cfg(test)]
mod signal_tests {
    use super::*;

    /// The conventional codes a shell or CI job reports for these deaths.
    #[test]
    fn reports_the_conventional_code_for_each_signal() {
        assert_eq!(Termination::Interrupt.exit_code(), 130);
        assert_eq!(Termination::Terminate.exit_code(), 143);
    }

    #[test]
    fn the_first_signal_asks_the_scan_to_stop() {
        let mut tracker = SignalTracker::new();

        assert_eq!(
            tracker.observe(Termination::Interrupt, 0),
            SignalAction::Cancel
        );
        // It recorded the request: an immediate repeat is now an echo.
        assert_eq!(
            tracker.observe(Termination::Interrupt, 0),
            SignalAction::Ignore
        );
    }

    /// A terminal can deliver one keypress twice. Treating the echo as a second
    /// request would kill a scan the person asked once to stop, discarding the
    /// partial output that stopping gracefully exists to keep.
    #[test]
    fn ignores_an_echo_of_the_signal_it_is_already_acting_on() {
        let mut tracker = SignalTracker::new();
        tracker.observe(Termination::Interrupt, 1_000);

        assert_eq!(
            tracker.observe(Termination::Interrupt, 1_100),
            SignalAction::Ignore
        );
    }

    /// Past the window it is a person pressing again, and they mean it.
    #[test]
    fn a_later_repeat_is_a_second_request() {
        let mut tracker = SignalTracker::new();
        tracker.observe(Termination::Interrupt, 1_000);

        assert_eq!(
            tracker.observe(Termination::Interrupt, 1_500),
            SignalAction::ForceExit(130)
        );
    }

    /// The window is for duplicate delivery of one signal, so a different
    /// signal is never an echo however fast it arrives.
    #[test]
    fn does_not_treat_a_different_signal_as_an_echo() {
        let mut tracker = SignalTracker::new();
        tracker.observe(Termination::Interrupt, 1_000);

        assert_eq!(
            tracker.observe(Termination::Terminate, 1_001),
            SignalAction::ForceExit(143)
        );
    }

    /// The code reports the signal that actually ended it, not the first one.
    #[test]
    fn leaves_with_the_code_of_the_signal_that_ended_it() {
        let mut tracker = SignalTracker::new();
        tracker.observe(Termination::Terminate, 0);

        assert_eq!(
            tracker.observe(Termination::Interrupt, 10),
            SignalAction::ForceExit(130)
        );
    }

    /// Nothing was asked for until something is.
    #[test]
    fn reports_no_interruption_until_one_happens() {
        let report = InterruptReport::new();
        assert_eq!(report.requested(), None);

        report.record(Termination::Terminate);
        assert_eq!(report.requested(), Some(Termination::Terminate));
    }

    /// The report is shared with the signal thread, so a clone must see it.
    #[test]
    fn a_shared_report_sees_what_the_signal_thread_recorded() {
        let report = InterruptReport::new();
        let thread_side = report.clone();

        thread_side.record(Termination::Interrupt);

        assert_eq!(report.requested(), Some(Termination::Interrupt));
    }

    #[test]
    fn describes_how_the_scan_ended() {
        assert_eq!(Termination::Interrupt.description(), "canceled by Ctrl-C");
        assert_eq!(
            Termination::Terminate.description(),
            "terminated by SIGTERM"
        );
    }

    #[test]
    fn recognizes_only_the_signals_it_answers_to() {
        assert_eq!(
            Termination::from_raw(signal_hook::consts::SIGINT),
            Some(Termination::Interrupt)
        );
        assert_eq!(
            Termination::from_raw(signal_hook::consts::SIGTERM),
            Some(Termination::Terminate)
        );
        assert_eq!(Termination::from_raw(signal_hook::consts::SIGHUP), None);
    }

    /// A clock that does not advance must not make every repeat an echo
    /// forever, nor panic on the subtraction.
    #[test]
    fn survives_a_clock_that_does_not_move() {
        let mut tracker = SignalTracker::new();
        tracker.observe(Termination::Interrupt, 0);

        assert_eq!(
            tracker.observe(Termination::Interrupt, 0),
            SignalAction::Ignore
        );
        assert_eq!(
            tracker.observe(Termination::Terminate, 0),
            SignalAction::ForceExit(143)
        );
    }
}
