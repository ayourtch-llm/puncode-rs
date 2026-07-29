//! A native client for the `codex` executable.
//!
//! This module replaces the `@openai/codex-sdk` dependency. That SDK is a thin
//! driver around the codex binary: it spawns `codex exec --json`, writes the
//! prompt to stdin, and reads JSONL events from stdout. The binary is itself
//! Rust, so the port drives it directly instead of going through Node.
//!
//! Upstream consumes the stream through a deliberately narrow interface, which
//! [`CodexClient`] and [`CodexThread`] mirror so that tests can substitute a
//! canned stream for a real process.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::targets::ProcessEnvironment;

/// Codex reads this to attribute API traffic to a client.
const ORIGINATOR_ENV: &str = "CODEX_INTERNAL_ORIGINATOR_OVERRIDE";

/// Upstream drives codex through the TypeScript SDK, which reports
/// `codex_sdk_ts`. The port keeps that value so server-side behavior is
/// unchanged; use [`ProcessCodexClient::with_originator`] to report otherwise.
const DEFAULT_ORIGINATOR: &str = "codex_sdk_ts";

/// Which JSONL flag to pass to `codex exec`.
///
/// The flag was renamed: codex 0.144 (the version upstream pins) accepts only
/// `--experimental-json`, while 0.145 renamed it to `--json` and kept the old
/// spelling as a hidden alias. The port resolves codex from `PATH`, so the
/// spelling is configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JsonFlag {
    #[default]
    Json,
    ExperimentalJson,
}

impl JsonFlag {
    #[must_use]
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::Json => "--json",
            Self::ExperimentalJson => "--experimental-json",
        }
    }
}

/// An item attached to a thread event.
///
/// Only `id` and `type` are modeled; every other key is preserved verbatim
/// because consumers read fields outside the SDK's documented union (worker
/// progress inspects `command` and `aggregated_output`, for example).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadItem {
    #[serde(default, deserialize_with = "lenient")]
    pub id: Option<String>,
    /// Defaults to empty rather than failing: upstream reads `item.type` with a
    /// runtime check and ignores items that lack it, instead of erroring.
    #[serde(rename = "type", default)]
    pub item_type: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl ThreadItem {
    /// The `text` field of an `agent_message` item.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.field("text").and_then(Value::as_str)
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }
}

/// A fatal error reported by a failed turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadError {
    pub message: Option<String>,
}

/// A top-level JSONL event emitted by `codex exec`.
///
/// Payload fields are optional because upstream guards each one with a runtime
/// type check rather than requiring it, and ignores events that fail the check.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type")]
pub enum ThreadEvent {
    #[serde(rename = "thread.started")]
    ThreadStarted {
        #[serde(default, deserialize_with = "lenient")]
        thread_id: Option<String>,
    },
    #[serde(rename = "turn.started")]
    TurnStarted,
    #[serde(rename = "turn.completed")]
    TurnCompleted {
        #[serde(default)]
        usage: Value,
    },
    #[serde(rename = "turn.failed")]
    TurnFailed {
        #[serde(default, deserialize_with = "lenient")]
        error: Option<ThreadError>,
    },
    #[serde(rename = "item.started")]
    ItemStarted {
        #[serde(default, deserialize_with = "lenient")]
        item: Option<ThreadItem>,
    },
    #[serde(rename = "item.updated")]
    ItemUpdated {
        #[serde(default, deserialize_with = "lenient")]
        item: Option<ThreadItem>,
    },
    #[serde(rename = "item.completed")]
    ItemCompleted {
        #[serde(default, deserialize_with = "lenient")]
        item: Option<ThreadItem>,
    },
    #[serde(rename = "error")]
    Error {
        #[serde(default, deserialize_with = "lenient")]
        message: Option<String>,
    },
    /// An event type this build does not know; ignored, as upstream does.
    #[serde(other)]
    Unknown,
}

/// Reads an optional field without letting a wrong-typed value fail the whole
/// event.
///
/// Upstream guards every payload field with a runtime check (`typeof x ===
/// "string"`, `isRecord(x)`) and ignores the field when it does not match, so a
/// malformed payload must not turn into a stream-ending parse error here.
fn lenient<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// Options for a single codex thread.
#[derive(Debug, Clone, Default)]
pub struct ThreadOptions {
    pub working_directory: Option<PathBuf>,
    pub skip_git_repo_check: bool,
    pub approval_policy: Option<String>,
    pub model: Option<String>,
    pub sandbox_mode: Option<String>,
    /// Run commands with no sandbox at all.
    ///
    /// Codex calls this "dangerously bypass approvals and sandbox" and means
    /// it: the agent's commands run with this process's own access. Only for a
    /// host that is already confined by something else.
    pub bypass_sandbox: bool,
    pub additional_directories: Vec<PathBuf>,
    pub config_overrides: Vec<String>,
    /// Resume an existing thread instead of starting a new one.
    pub resume_thread_id: Option<String>,
    /// A JSON Schema the model's final response must satisfy.
    pub output_schema_path: Option<PathBuf>,
}

impl ThreadOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Constrains the model's final response to a JSON Schema on disk.
    #[must_use]
    pub fn output_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_schema_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn working_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(directory.into());
        self
    }

    #[must_use]
    pub fn skip_git_repo_check(mut self, skip: bool) -> Self {
        self.skip_git_repo_check = skip;
        self
    }

    #[must_use]
    pub fn approval_policy(mut self, policy: impl Into<String>) -> Self {
        self.approval_policy = Some(policy.into());
        self
    }

    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    #[must_use]
    pub fn sandbox_mode(mut self, mode: impl Into<String>) -> Self {
        self.sandbox_mode = Some(mode.into());
        self
    }

    /// Runs commands unsandboxed. See [`ThreadOptions::bypass_sandbox`].
    #[must_use]
    pub fn bypass_sandbox(mut self, bypass: bool) -> Self {
        self.bypass_sandbox = bypass;
        self
    }

    #[must_use]
    pub fn config_override(mut self, override_: impl Into<String>) -> Self {
        self.config_overrides.push(override_.into());
        self
    }
}

/// Cancels a running stream, terminating the underlying process.
///
/// This replaces the `AbortSignal` upstream threads through `runStreamed`.
#[derive(Debug, Clone)]
pub struct CancelHandle {
    cancelled: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl CancelHandle {
    /// Stops the stream and kills the codex process.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut child) = self.child.lock()
            && let Some(child) = child.as_mut()
        {
            let _ = child.kill();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// A stream of thread events.
///
/// Yields each parsed event, then—if codex exited non-zero—one final error.
/// A line that is not valid JSON ends the stream with an error, matching the
/// TypeScript SDK.
pub struct EventStream {
    lines: Option<BufReader<ChildStdout>>,
    child: Arc<Mutex<Option<Child>>>,
    cancelled: Arc<AtomicBool>,
    thread_id: Arc<Mutex<Option<String>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    /// Set instead of `lines` when the stream serves canned events.
    canned: Option<std::vec::IntoIter<Result<ThreadEvent>>>,
    finished: bool,
}

impl EventStream {
    /// A handle that stops this stream from another thread.
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            cancelled: Arc::clone(&self.cancelled),
            child: Arc::clone(&self.child),
        }
    }

    /// Builds a stream over canned events, for tests and fakes.
    #[must_use]
    pub fn from_events(events: Vec<Result<ThreadEvent>>) -> Self {
        Self {
            lines: None,
            child: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
            thread_id: Arc::new(Mutex::new(None)),
            stderr: None,
            canned: Some(events.into_iter()),
            finished: false,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Reaps the process once stdout closes, reporting a non-zero exit the way
    /// the TypeScript SDK does.
    fn finish(&mut self) -> Option<Result<ThreadEvent>> {
        self.finished = true;
        let stderr = self
            .stderr
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default();

        // A cancelled stream ends quietly; the kill is not a codex failure.
        if self.is_cancelled() {
            return None;
        }

        let mut child = self.child.lock().ok()?.take()?;
        let status = child.wait().ok()?;
        if status.success() {
            return None;
        }

        let detail = match status.code() {
            Some(code) => format!("code {code}"),
            None => signal_detail(&status),
        };
        Some(Err(Error::codex_security(format!(
            "Codex Exec exited with {detail}: {}",
            String::from_utf8_lossy(&stderr)
        ))))
    }
}

#[cfg(unix)]
fn signal_detail(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map_or_else(|| "code 1".to_owned(), |signal| format!("signal {signal}"))
}

#[cfg(not(unix))]
fn signal_detail(_status: &std::process::ExitStatus) -> String {
    "code 1".to_owned()
}

impl Iterator for EventStream {
    type Item = Result<ThreadEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(canned) = self.canned.as_mut() {
            return canned.next();
        }
        if self.is_cancelled() {
            self.finished = true;
            return None;
        }

        // Read bytes rather than `Lines`: codex output is decoded leniently by
        // Node, so invalid UTF-8 must degrade to a parse error on a replacement
        // string, not silently truncate the stream.
        let read = {
            let reader = self.lines.as_mut()?;
            let mut buffer = Vec::new();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(buffer),
            }
        };
        // stdout closed: reap the process.
        let Some(mut buffer) = read else {
            return self.finish();
        };
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
            // `crlfDelay: Infinity` upstream folds CRLF into a single break.
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
        }
        let line = String::from_utf8_lossy(&buffer).into_owned();
        if self.is_cancelled() {
            self.finished = true;
            return None;
        }

        match serde_json::from_str::<ThreadEvent>(&line) {
            Ok(event) => {
                if let ThreadEvent::ThreadStarted {
                    thread_id: Some(id),
                } = &event
                    && let Ok(mut current) = self.thread_id.lock()
                {
                    *current = Some(id.clone());
                }
                Some(Ok(event))
            }
            Err(_) => {
                self.finished = true;
                Some(Err(Error::codex_security(format!(
                    "Failed to parse item: {line}"
                ))))
            }
        }
    }
}

impl Drop for EventStream {
    /// Terminates codex if the stream is abandoned before it ends, mirroring
    /// the `finally { child.kill() }` in the TypeScript SDK. Without this an
    /// undrained stream would leave the process running.
    fn drop(&mut self) {
        let Ok(mut child) = self.child.lock() else {
            return;
        };
        if let Some(child) = child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A conversation with the agent.
pub trait CodexThread: Send {
    /// The thread identifier, known once the stream reports `thread.started`.
    fn id(&self) -> Option<String>;

    /// Sends `input` to the agent and streams the resulting events.
    fn run_streamed(&mut self, input: &str) -> Result<EventStream>;
}

/// Starts codex threads.
pub trait CodexClient {
    fn start_thread(&self, options: ThreadOptions) -> Box<dyn CodexThread>;
}

/// A [`CodexClient`] backed by the real `codex` executable.
#[derive(Debug, Clone)]
pub struct ProcessCodexClient {
    executable: PathBuf,
    json_flag: JsonFlag,
    originator: String,
    /// Replaces the inherited environment when set.
    environment: Option<ProcessEnvironment>,
}

impl ProcessCodexClient {
    #[must_use]
    pub fn new(executable: impl AsRef<Path>) -> Self {
        Self {
            executable: executable.as_ref().to_path_buf(),
            json_flag: JsonFlag::default(),
            originator: DEFAULT_ORIGINATOR.to_owned(),
            environment: None,
        }
    }

    #[must_use]
    pub fn with_json_flag(mut self, json_flag: JsonFlag) -> Self {
        self.json_flag = json_flag;
        self
    }

    /// Overrides the client identity reported to codex.
    #[must_use]
    pub fn with_originator(mut self, originator: impl Into<String>) -> Self {
        self.originator = originator.into();
        self
    }

    /// Runs codex in exactly `environment` instead of the inherited one.
    ///
    /// A scan must reach its isolated `CODEX_HOME` and nothing else, so the
    /// supplied environment replaces the ambient one rather than adding to it:
    /// an inherited variable would otherwise point the scan at the user's real
    /// Codex home and credentials.
    #[must_use]
    pub fn with_environment(mut self, environment: ProcessEnvironment) -> Self {
        self.environment = Some(environment);
        self
    }
}

impl CodexClient for ProcessCodexClient {
    fn start_thread(&self, options: ThreadOptions) -> Box<dyn CodexThread> {
        Box::new(ProcessCodexThread {
            client: self.clone(),
            options,
            thread_id: Arc::new(Mutex::new(None)),
        })
    }
}

struct ProcessCodexThread {
    client: ProcessCodexClient,
    options: ThreadOptions,
    thread_id: Arc<Mutex<Option<String>>>,
}

impl ProcessCodexThread {
    /// Builds the argument list in the same order as the TypeScript SDK.
    fn command(&self) -> Command {
        let options = &self.options;
        let mut command = Command::new(&self.client.executable);
        command.arg("exec").arg(self.client.json_flag.as_flag());

        for override_ in &options.config_overrides {
            command.arg("--config").arg(override_);
        }
        if let Some(model) = &options.model {
            command.arg("--model").arg(model);
        }
        if options.bypass_sandbox {
            // Codex refuses a sandbox mode alongside this, and it would be
            // meaningless anyway.
            command.arg("--dangerously-bypass-approvals-and-sandbox");
        } else if let Some(sandbox) = &options.sandbox_mode {
            command.arg("--sandbox").arg(sandbox);
        }
        if let Some(directory) = &options.working_directory {
            command.arg("--cd").arg(directory);
        }
        for directory in &options.additional_directories {
            command.arg("--add-dir").arg(directory);
        }
        if let Some(schema) = &options.output_schema_path {
            command.arg("--output-schema").arg(schema);
        }
        if options.skip_git_repo_check {
            command.arg("--skip-git-repo-check");
        }
        if let Some(policy) = &options.approval_policy {
            command
                .arg("--config")
                .arg(format!("approval_policy=\"{policy}\""));
        }
        if let Some(thread_id) = &options.resume_thread_id {
            command.arg("resume").arg(thread_id);
        }

        // The originator is only supplied when nothing already names one,
        // whether that is the caller's environment or the ambient one.
        let originator_set = match &self.client.environment {
            Some(environment) => {
                command.env_clear().envs(environment);
                environment.contains_key(ORIGINATOR_ENV)
            }
            None => std::env::var_os(ORIGINATOR_ENV).is_some(),
        };
        if !originator_set {
            command.env(ORIGINATOR_ENV, &self.client.originator);
        }
        command
    }
}

impl CodexThread for ProcessCodexThread {
    fn id(&self) -> Option<String> {
        self.thread_id.lock().ok()?.clone()
    }

    fn run_streamed(&mut self, input: &str) -> Result<EventStream> {
        let mut command = self.command();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|error| {
            let message = format!(
                "Failed to start codex at {}: {error}",
                self.client.executable.display()
            );
            Error::codex_security(message).with_source(error)
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::codex_security("Child process has no stdout"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::codex_security("Child process has no stdin"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::codex_security("Child process has no stderr"))?;

        // Write the prompt off-thread: a prompt larger than the pipe buffer
        // would otherwise deadlock against a child that has not started
        // reading yet.
        let prompt = input.to_owned();
        std::thread::spawn(move || {
            let _ = stdin.write_all(prompt.as_bytes());
        });
        // Drain stderr concurrently so a chatty child cannot block on a full pipe.
        let stderr_reader = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = stderr.read_to_end(&mut buffer);
            buffer
        });

        Ok(EventStream {
            lines: Some(BufReader::new(stdout)),
            child: Arc::new(Mutex::new(Some(child))),
            cancelled: Arc::new(AtomicBool::new(false)),
            thread_id: Arc::clone(&self.thread_id),
            stderr: Some(stderr_reader),
            canned: None,
            finished: false,
        })
    }
}
