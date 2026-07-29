//! The Codex Security client.
//!
//! Ported from `CodexSecurity` in `src/api.ts`.
//!
//! A client owns one isolated runtime, prepared on first use and shared by
//! every operation that follows, then removed when the client closes. Only one
//! operation runs at a time: they all drive the same runtime and the same
//! credentials, so overlapping them would let one scan's login change another
//! scan's identity mid-run.
//!
//! Closing is what makes the isolation temporary rather than permanent, so it
//! must work even while an operation is in flight: closing cancels first, waits
//! for the operation to notice, and only then removes the directories.
//!
//! Upstream takes roughly ten `onXxx` callbacks per scan and an options bag of
//! dependencies. Here observers are a [`ScanObserver`] trait and dependencies
//! are a struct built with `with_` methods, so a caller overrides only what it
//! needs.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use crate::auth::{
    AccountStatus, CodexLoginHandle, LoginCanceller, account_status, login_api_key, logout,
};
use crate::codex::{CodexClient, ProcessCodexClient};
use crate::config::{CodexSecurityConfig, merged_codex_config, scan_model_configuration};
use crate::error::{Error, ProtectedScanPathKind, Result};
use crate::result::ScanResult;
use crate::runtime::{
    CodexCommand, CodexRunner, LocationCheck, ProcessCodexRunner, plan_output_archive,
    resolve_codex_command, validate_output_dir,
};
use crate::targets::{
    NormalizedTarget, ProcessEnvironment, ScanMode, ScanTarget, enclosing_git_worktree_root,
    normalize_repository, normalize_target, process_environment, resolve_repository_path,
    validate_mode, validated_git_environment,
};
use crate::version::{CODEX_EXECUTABLE_VERSION, VERSION};

use super::environment::{ScanAuthentication, environment_api_key, scan_authentication};
use super::events::{ScanCancellation, ScanObserver};
use super::prompt::{require_output_outside_repository, validate_scan_cost_limit};
use super::runtime_prep::{PreparedRuntime, RuntimePreparation, prepare_runtime};
use super::scan::ScanRun;

/// What produced a scan, recorded on its results.
///
/// Upstream names the TypeScript SDK it drives; this port drives `codex`
/// directly, so it names itself instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodexSecurityMetadata {
    pub sdk: &'static str,
    pub sdk_version: &'static str,
    pub executable: &'static str,
    pub executable_version: &'static str,
}

impl Default for CodexSecurityMetadata {
    fn default() -> Self {
        Self {
            sdk: "codex-security",
            sdk_version: VERSION,
            executable: "codex",
            executable_version: CODEX_EXECUTABLE_VERSION,
        }
    }
}

/// Builds the codex client a scan talks to.
pub type CreateCodexClient =
    Box<dyn Fn(&ProcessEnvironment, &CodexCommand) -> Box<dyn CodexClient> + Send + Sync>;

/// Finds the `codex` executable, refusing one inside the protected root.
pub type ResolveCodexCommand =
    Box<dyn Fn(&ProcessEnvironment, &Path) -> Result<CodexCommand> + Send + Sync>;

/// Prepares the isolated runtime, replacing the built-in preparation entirely.
pub type PrepareRuntimeFn =
    Box<dyn Fn(&CodexSecurityConfig, &ScanCancellation) -> Result<PreparedRuntime> + Send + Sync>;

/// The collaborators a client uses, each replaceable for testing.
///
/// Ported from upstream's `ClientDependencies`.
pub struct ClientDependencies {
    /// The environment the client inherited.
    pub environment: ProcessEnvironment,
    pub create_codex: CreateCodexClient,
    pub runner: Box<dyn CodexRunner + Send + Sync>,
    pub resolve_command: ResolveCodexCommand,
    /// Replaces runtime preparation wholesale when supplied.
    pub prepare_runtime: Option<PrepareRuntimeFn>,
    /// Where isolated directories are created; the system temporary directory
    /// unless a caller needs them somewhere specific.
    pub temporary_root: Option<PathBuf>,
}

impl Default for ClientDependencies {
    fn default() -> Self {
        Self {
            environment: process_environment(),
            create_codex: Box::new(|environment, command| {
                Box::new(
                    ProcessCodexClient::new(&command.command).with_environment(environment.clone()),
                )
            }),
            runner: Box::new(ProcessCodexRunner),
            resolve_command: Box::new(resolve_codex_command),
            prepare_runtime: None,
            temporary_root: None,
        }
    }
}

impl ClientDependencies {
    #[must_use]
    pub fn with_environment(mut self, environment: ProcessEnvironment) -> Self {
        self.environment = environment;
        self
    }

    #[must_use]
    pub fn with_create_codex(mut self, create: CreateCodexClient) -> Self {
        self.create_codex = create;
        self
    }

    #[must_use]
    pub fn with_runner(mut self, runner: Box<dyn CodexRunner + Send + Sync>) -> Self {
        self.runner = runner;
        self
    }

    #[must_use]
    pub fn with_resolve_command(mut self, resolve: ResolveCodexCommand) -> Self {
        self.resolve_command = resolve;
        self
    }

    #[must_use]
    pub fn with_prepare_runtime(mut self, prepare: PrepareRuntimeFn) -> Self {
        self.prepare_runtime = Some(prepare);
        self
    }

    #[must_use]
    pub fn with_temporary_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.temporary_root = Some(root.into());
        self
    }
}

/// What a scan should look at, and how.
///
/// Upstream's `ScanOptions` also carries roughly ten `onXxx` callbacks and an
/// `AbortSignal`; here those are a [`ScanObserver`] and a [`ScanCancellation`]
/// passed alongside, so this describes only the scan itself.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// What to scan; the whole repository unless given.
    pub target: Option<ScanTarget>,
    /// How thoroughly; [`ScanMode::Standard`] unless given.
    pub mode: Option<ScanMode>,
    /// Documents the scan should treat as authoritative context.
    pub knowledge_base_paths: Vec<String>,
    /// Where results land; a temporary directory unless given.
    pub output_dir: Option<String>,
    /// Move existing output aside rather than refusing to overwrite it.
    pub archive_existing: bool,
    /// The scan this one re-runs, recorded in the workbench.
    pub parent_scan_id: Option<String>,
    /// Refuses to run against a different plugin than the original scan used.
    pub expected_plugin_version: Option<String>,
    /// The severity at or above which the scan reports failure.
    pub failure_severity: Option<String>,
    /// Stops the scan once the estimated spend passes this many dollars.
    pub max_cost_usd: Option<f64>,
    /// Run the agent's commands with no sandbox.
    ///
    /// The scan's own sandbox cannot be weakened by configuration, on purpose.
    /// This is the one way past it, and it is not a configuration value: a
    /// caller has to ask for it in as many words. Only for a host already
    /// confined by something else, such as a container or a throwaway VM.
    pub bypass_sandbox: bool,
}

impl ScanOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_target(mut self, target: ScanTarget) -> Self {
        self.target = Some(target);
        self
    }

    #[must_use]
    pub fn with_mode(mut self, mode: ScanMode) -> Self {
        self.mode = Some(mode);
        self
    }

    #[must_use]
    pub fn with_output_dir(mut self, output_dir: impl Into<String>) -> Self {
        self.output_dir = Some(output_dir.into());
        self
    }

    #[must_use]
    pub fn with_knowledge_base_paths(
        mut self,
        paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.knowledge_base_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_archive_existing(mut self, archive_existing: bool) -> Self {
        self.archive_existing = archive_existing;
        self
    }

    #[must_use]
    pub fn with_max_cost_usd(mut self, max_cost_usd: f64) -> Self {
        self.max_cost_usd = Some(max_cost_usd);
        self
    }

    /// Runs the agent's commands unsandboxed. See [`ScanOptions::bypass_sandbox`].
    #[must_use]
    pub fn with_bypass_sandbox(mut self, bypass: bool) -> Self {
        self.bypass_sandbox = bypass;
        self
    }

    #[must_use]
    pub fn with_expected_plugin_version(mut self, version: impl Into<String>) -> Self {
        self.expected_plugin_version = Some(version.into());
        self
    }

    #[must_use]
    pub fn with_parent_scan_id(mut self, scan_id: impl Into<String>) -> Self {
        self.parent_scan_id = Some(scan_id.into());
        self
    }

    #[must_use]
    pub fn with_failure_severity(mut self, severity: impl Into<String>) -> Self {
        self.failure_severity = Some(severity.into());
        self
    }
}

/// What a scan would do, worked out without touching the network or a runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanPreflight {
    pub repository: PathBuf,
    pub target: NormalizedTarget,
    pub mode: ScanMode,
    pub knowledge_base_paths: Vec<String>,
    /// Where results would land, or `None` for a temporary directory.
    pub output_dir: Option<PathBuf>,
    /// Where existing output would be moved to, when archiving was asked for.
    pub archive_dir: Option<PathBuf>,
    pub authentication: ScanAuthentication,
    pub model: String,
    pub reasoning_effort: String,
    pub max_cost_usd: Option<f64>,
}

/// The locally-checked inputs a scan starts from.
#[derive(Debug, Clone)]
pub(crate) struct LocalScanInputs {
    repository: PathBuf,
    target: NormalizedTarget,
    mode: ScanMode,
    output_dir: Option<PathBuf>,
    /// The tree a scan must not write into: the enclosing worktree if there is
    /// one, otherwise the repository itself.
    protected_root: PathBuf,
}

impl LocalScanInputs {
    pub(crate) fn repository(&self) -> &Path {
        &self.repository
    }

    pub(crate) fn target(&self) -> &NormalizedTarget {
        &self.target
    }

    pub(crate) fn mode(&self) -> ScanMode {
        self.mode
    }

    pub(crate) fn output_dir(&self) -> Option<&Path> {
        self.output_dir.as_deref()
    }

    pub(crate) fn protected_root(&self) -> &Path {
        &self.protected_root
    }
}

/// A Codex Security client, owning one isolated runtime.
pub struct CodexSecurity {
    config: CodexSecurityConfig,
    metadata: CodexSecurityMetadata,
    dependencies: ClientDependencies,
    /// Stops whatever the client is doing; closing cancels through it.
    cancellation: ScanCancellation,
    closed: AtomicBool,
    /// Held for the whole of an operation, so a second one is refused and
    /// closing can wait for the first to finish.
    operation: Mutex<()>,
    runtime: Mutex<Option<PreparedRuntime>>,
    /// Set once the runtime has been removed, so closing is idempotent.
    cleaned: AtomicBool,
    /// Interactive logins this client started, so closing can stop them.
    logins: Mutex<Vec<LoginCanceller>>,
}

impl CodexSecurity {
    /// A client with the real Codex, the real runtime, and the real environment.
    #[must_use]
    pub fn new(config: CodexSecurityConfig) -> Self {
        Self::with_dependencies(config, ClientDependencies::default())
    }

    #[must_use]
    pub fn with_dependencies(
        config: CodexSecurityConfig,
        dependencies: ClientDependencies,
    ) -> Self {
        Self {
            config,
            metadata: CodexSecurityMetadata::default(),
            dependencies,
            cancellation: ScanCancellation::new(),
            closed: AtomicBool::new(false),
            operation: Mutex::new(()),
            runtime: Mutex::new(None),
            cleaned: AtomicBool::new(false),
            logins: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn config(&self) -> &CodexSecurityConfig {
        &self.config
    }

    #[must_use]
    pub fn metadata(&self) -> CodexSecurityMetadata {
        self.metadata
    }

    /// Stops whatever the client is doing, without closing it.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Runs a scan and returns its validated results.
    ///
    /// The order here is deliberate and load-bearing. Everything that can be
    /// checked locally is checked before a runtime is prepared, so a bad
    /// request costs nothing. Every directory the scan will touch is confirmed
    /// to be outside the repository before anything is created, because results
    /// carry source excerpts and writing them into the tree under review would
    /// contaminate the very thing being reviewed. The scan is registered with
    /// the workbench before the agent starts, so a scan that dies partway
    /// through is still recorded as having failed rather than vanishing.
    pub fn run(
        &self,
        repository: &str,
        options: &ScanOptions,
        observer: &mut dyn ScanObserver,
        cancellation: &ScanCancellation,
    ) -> Result<ScanResult> {
        let _guard = self.begin_operation()?;
        let scan = ScanRun {
            client: self,
            options,
            cancellation,
        };
        scan.execute(repository, observer)
    }

    /// Works out what a scan would do, without preparing a runtime.
    ///
    /// Every check here is local: no credentials are used, no plugin is
    /// installed, and no output directory is created. That is the point — a
    /// caller can show what is about to happen, and a mistake in the request
    /// surfaces before anything has been set up.
    pub fn preflight(&self, repository: &str, options: &ScanOptions) -> Result<ScanPreflight> {
        self.require_open()?;
        let inputs = self.validate_local_inputs(repository, options)?;

        // The temporary directory is where a scan without an explicit output
        // directory would write, so it is checked now rather than mid-scan.
        let temporary_root = self.temporary_root()?;
        require_output_outside_repository(
            &inputs.protected_root,
            &temporary_root,
            ProtectedScanPathKind::Temporary,
        )?;

        let configuration = merged_codex_config(&self.config)?;
        let model = scan_model_configuration(&configuration)?;
        validate_scan_cost_limit(options.max_cost_usd, &model.model)?;

        // Planning an archive only reports where output would move to; nothing
        // is moved until the scan itself runs.
        let archive_dir = match (options.archive_existing, inputs.output_dir.as_ref()) {
            (true, Some(output_dir)) => plan_output_archive(output_dir)?,
            _ => None,
        };

        self.require_open()?;
        Ok(ScanPreflight {
            repository: inputs.repository,
            target: inputs.target,
            mode: inputs.mode,
            knowledge_base_paths: options.knowledge_base_paths.clone(),
            output_dir: inputs.output_dir,
            archive_dir,
            authentication: scan_authentication(&self.dependencies.environment),
            model: model.model,
            reasoning_effort: model.reasoning_effort,
            max_cost_usd: options.max_cost_usd,
        })
    }

    /// Checks everything about a request that can be checked locally.
    ///
    /// Ported from `#validateLocalInputs`. This runs before any runtime work so
    /// a bad request fails immediately, rather than after a plugin install.
    pub(crate) fn validate_local_inputs(
        &self,
        repository: &str,
        options: &ScanOptions,
    ) -> Result<LocalScanInputs> {
        if let Some(max_cost_usd) = options.max_cost_usd
            && (!max_cost_usd.is_finite() || max_cost_usd <= 0.0)
        {
            return Err(Error::codex_security(
                "The scan cost limit must be a positive USD amount.",
            ));
        }
        let environment = &self.dependencies.environment;
        let repository_path = resolve_repository_path(repository, environment);
        let repository = normalize_repository(&repository_path.to_string_lossy(), environment)?;

        // Checked before the target is resolved: these variables would send git
        // somewhere other than the repository being scanned.
        validated_git_environment(environment)?;
        let target = options.target.clone().unwrap_or(ScanTarget::Repository);
        let target = normalize_target(&repository.to_string_lossy(), &target, environment)?;
        let mode = options.mode.unwrap_or(ScanMode::Standard);
        validate_mode(&target, mode)?;

        // A repository inside a larger worktree must not be written into
        // either, so the whole worktree is protected.
        let protected_root = enclosing_git_worktree_root(&repository, environment)
            .unwrap_or_else(|| repository.clone());
        let output_dir = validate_output_dir(
            options.output_dir.as_deref(),
            options.archive_existing,
            environment,
        )?;
        if let Some(output_dir) = &output_dir {
            require_output_outside_repository(
                &protected_root,
                output_dir,
                ProtectedScanPathKind::Output,
            )?;
        }

        Ok(LocalScanInputs {
            repository,
            target,
            mode,
            output_dir,
            protected_root,
        })
    }

    /// Where isolated and temporary directories are created.
    pub(crate) fn temporary_root(&self) -> Result<PathBuf> {
        match &self.dependencies.temporary_root {
            Some(root) => Ok(root.clone()),
            None => std::fs::canonicalize(std::env::temp_dir()).map_err(|error| {
                Error::plugin_bootstrap("Unable to resolve the system temporary directory")
                    .with_source(error)
            }),
        }
    }

    /// Stores an API key in the isolated runtime's credentials.
    pub fn login_api_key(&self, api_key: &str) -> Result<()> {
        self.run_operation(|client, runtime| {
            let command = client.codex_command()?;
            let result = login_api_key(&command, &runtime.environment, api_key)?;
            if !result.success {
                let detail = first_nonempty(&[result.stderr.trim(), result.stdout.trim()])
                    .unwrap_or("unknown error");
                return Err(Error::codex_security(format!(
                    "Codex API-key login failed: {detail}"
                )));
            }
            Ok(true)
        })
        .map(|credentials_available| self.set_credentials_available(credentials_available))
    }

    /// Starts an interactive ChatGPT sign-in.
    ///
    /// Returns once Codex has printed a URL to open, so a caller can show it
    /// immediately; the returned handle reports when the sign-in finishes.
    pub fn login_chatgpt(&self) -> Result<CodexLoginHandle> {
        self.start_login(&["login"], false)
    }

    /// Starts an interactive device-code sign-in, for a machine with no browser.
    ///
    /// Returns once both the URL and the code are available, since neither is
    /// useful to show without the other.
    pub fn login_chatgpt_device_code(&self) -> Result<CodexLoginHandle> {
        self.start_login(&["login", "--device-auth"], true)
    }

    /// Starts a login and waits for the instructions a caller must show.
    fn start_login(&self, args: &[&str], device_code: bool) -> Result<CodexLoginHandle> {
        let runtime = {
            let _guard = self.begin_operation()?;
            self.ensure_runtime()?
        };
        self.require_open()?;
        let command = self.codex_command()?;
        let handle = CodexLoginHandle::start(&command, args, &runtime.environment)?;

        // Tracked before waiting: closing must be able to stop a login that is
        // still waiting for a person to finish in their browser.
        self.track_login(handle.canceller());
        handle.wait_for_instructions(device_code)?;
        self.require_open()?;
        Ok(handle)
    }

    /// Remembers a login so closing can cancel it.
    fn track_login(&self, canceller: LoginCanceller) {
        let mut logins = self
            .logins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logins.retain(|login| !login.is_finished());
        logins.push(canceller);
    }

    /// Reports whether the runtime can authenticate, and how.
    pub fn account(&self) -> Result<AccountStatus> {
        self.run_operation(|client, runtime| {
            // An environment key authenticates without asking Codex, and
            // upstream reports it without a subprocess.
            if environment_api_key(&client.dependencies.environment).is_some() {
                return Ok(AccountStatus {
                    authenticated: true,
                    details: "Authenticated with an API key.".to_owned(),
                });
            }
            let command = client.codex_command()?;
            account_status(&command, &runtime.environment)
        })
    }

    /// Discards the runtime's stored credentials.
    pub fn logout(&self) -> Result<()> {
        self.run_operation(|client, runtime| {
            let command = client.codex_command()?;
            logout(&command, &runtime.environment)
        })?;
        self.set_credentials_available(false);
        Ok(())
    }

    /// Removes the isolated runtime, stopping anything still running.
    ///
    /// Idempotent: closing twice is not a failure, and a client that never
    /// prepared a runtime has nothing to remove.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        // Cancel before waiting: an operation that is mid-scan will not finish
        // on its own, and closing must not block on it. An interactive login is
        // waiting on a person, so it never finishes on its own either.
        self.cancellation.cancel();
        for login in self
            .logins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            login.cancel();
        }

        // Waits for any in-flight operation to notice the cancellation.
        let _operation = self.operation.lock().unwrap_or_else(|poisoned| {
            // A panicking operation still leaves a runtime to clean up.
            poisoned.into_inner()
        });
        if self.cleaned.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match runtime {
            Some(runtime) => runtime.cleanup(),
            None => Ok(()),
        }
    }

    /// The runtime, preparing it on first use.
    ///
    /// Preparation happens once per client: every scan shares one isolated home
    /// so a login in one is visible to the next.
    fn ensure_runtime(&self) -> Result<PreparedRuntime> {
        self.require_open()?;
        let mut slot = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(runtime) = slot.as_ref() {
            return Ok(runtime.clone());
        }
        let prepared = self.prepare()?;
        // Closing during preparation must not leave the new runtime behind.
        if self.closed.load(Ordering::SeqCst) {
            let _ = prepared.cleanup();
            return Err(closed());
        }
        *slot = Some(prepared.clone());
        Ok(prepared)
    }

    fn prepare(&self) -> Result<PreparedRuntime> {
        let temporary_root = self.temporary_root()?;
        self.prepare_within(&temporary_root, None)
    }

    fn prepare_within(
        &self,
        temporary_root: &Path,
        validate_location: Option<LocationCheck<'_>>,
    ) -> Result<PreparedRuntime> {
        if let Some(prepare) = &self.dependencies.prepare_runtime {
            return prepare(&self.config, &self.cancellation);
        }
        let command = self.codex_command_for(temporary_root)?;
        let mut preparation = RuntimePreparation::new(
            &self.config,
            &self.dependencies.environment,
            &command,
            self.dependencies.runner.as_ref(),
            temporary_root,
            &self.cancellation,
        );
        preparation.validate_location = validate_location;
        prepare_runtime(&preparation)
    }

    /// The collaborators this client was built with.
    pub(crate) fn dependencies(&self) -> &ClientDependencies {
        &self.dependencies
    }

    /// Finds `codex`, refusing one inside `protected_root`.
    pub(crate) fn codex_command_for(&self, protected_root: &Path) -> Result<CodexCommand> {
        (self.dependencies.resolve_command)(&self.dependencies.environment, protected_root)
    }

    /// Records that credentials did or did not become available.
    pub(crate) fn record_credentials_available(&self, available: bool) {
        self.set_credentials_available(available);
    }

    /// The runtime, preparing it under `temporary_root` if it is not ready.
    pub(crate) fn ensure_runtime_within(
        &self,
        temporary_root: &Path,
        validate_location: LocationCheck<'_>,
    ) -> Result<PreparedRuntime> {
        self.require_open()?;
        let mut slot = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(runtime) = slot.as_ref() {
            return Ok(runtime.clone());
        }
        let prepared = self.prepare_within(temporary_root, Some(validate_location))?;
        if self.closed.load(Ordering::SeqCst) {
            let _ = prepared.cleanup();
            return Err(closed());
        }
        *slot = Some(prepared.clone());
        Ok(prepared)
    }

    /// Finds `codex` for an operation that is not scanning a repository.
    ///
    /// There is no repository to protect, so the working directory stands in:
    /// a `codex` sitting in it is still not something to run.
    fn codex_command(&self) -> Result<CodexCommand> {
        let protected_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        (self.dependencies.resolve_command)(&self.dependencies.environment, &protected_root)
    }

    /// Records that credentials did or did not become available.
    fn set_credentials_available(&self, available: bool) {
        if let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            runtime.credentials_available = available;
        }
    }

    /// Runs `operation` against the runtime, refusing to overlap another.
    fn run_operation<T>(
        &self,
        operation: impl FnOnce(&Self, &PreparedRuntime) -> Result<T>,
    ) -> Result<T> {
        let _guard = self.begin_operation()?;
        let runtime = self.ensure_runtime()?;
        self.require_open()?;
        let outcome = operation(self, &runtime)?;
        // A client closed mid-operation has had its runtime removed, so the
        // result describes a runtime that no longer exists.
        self.require_open()?;
        Ok(outcome)
    }

    /// Claims the right to be the client's one running operation.
    fn begin_operation(&self) -> Result<MutexGuard<'_, ()>> {
        self.require_open()?;
        match self.operation.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(Error::codex_security(
                "A Codex Security operation is already in progress.",
            )),
            // An operation that panicked should not disable the client for
            // good; the next one starts from the same shared runtime.
            Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
        }
    }

    pub(crate) fn require_open(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(closed());
        }
        Ok(())
    }
}

/// Closing removes the runtime, so a dropped client leaves nothing behind.
impl Drop for CodexSecurity {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn closed() -> Error {
    Error::codex_security("CodexSecurity is closed.")
}

/// The first value that is not blank.
fn first_nonempty<'a>(candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|candidate| !candidate.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::PluginInstall;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;

    /// A runtime that owns two real directories, so cleanup is observable.
    fn prepared(root: &Path) -> PreparedRuntime {
        let codex_home = root.join("codex-home");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&codex_home).expect("create home");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        PreparedRuntime {
            codex_home: codex_home.clone(),
            bootstrap_workspace: Some(workspace),
            config_path: None,
            plugin: PluginInstall {
                plugin_root: root.join("plugin"),
                marketplace_root: root.join("marketplace"),
                installed_root: root.join("installed"),
                marketplace_name: "codex-security-sdk".to_owned(),
                name: "codex-security".to_owned(),
                version: "0.1.14".to_owned(),
            },
            environment: [("CODEX_HOME".to_owned(), codex_home.display().to_string())]
                .into_iter()
                .collect(),
            credentials_available: false,
            effective_config: None,
        }
    }

    /// A client whose runtime is supplied rather than prepared.
    fn client_with(root: &Path, environment: &[(&str, &str)]) -> (CodexSecurity, Arc<AtomicUsize>) {
        let preparations = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&preparations);
        let runtime = prepared(root);
        let dependencies = ClientDependencies::default()
            .with_environment(
                environment
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            )
            .with_prepare_runtime(Box::new(move |_, _| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(runtime.clone())
            }));
        (
            CodexSecurity::with_dependencies(CodexSecurityConfig::default(), dependencies),
            preparations,
        )
    }

    #[test]
    fn reports_what_produced_a_scan() {
        let metadata = CodexSecurity::new(CodexSecurityConfig::default()).metadata();

        assert_eq!(metadata.sdk, "codex-security");
        assert_eq!(metadata.executable, "codex");
        assert_eq!(metadata.executable_version, CODEX_EXECUTABLE_VERSION);
    }

    // An environment key authenticates without asking Codex at all.
    #[test]
    fn reports_an_environment_api_key_without_running_codex() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);

        let status = client.account().expect("reports an account");

        assert!(status.authenticated);
        assert_eq!(status.details, "Authenticated with an API key.");
    }

    // One runtime per client: a login in one operation must be visible to the
    // next, which only holds if they share the same isolated home.
    #[test]
    fn prepares_its_runtime_only_once() {
        let root = TempDir::new().expect("root");
        let (client, preparations) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);

        client.account().expect("first");
        client.account().expect("second");

        assert_eq!(preparations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn removes_its_runtime_when_closed() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        client.account().expect("prepares a runtime");

        client.close().expect("closes");

        assert!(!root.path().join("codex-home").exists());
        assert!(!root.path().join("workspace").exists());
    }

    #[test]
    fn closing_twice_is_not_a_failure() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        client.account().expect("prepares a runtime");

        client.close().expect("closes");
        client.close().expect("closing again is fine");
    }

    #[test]
    fn closing_a_client_that_never_ran_has_nothing_to_remove() {
        let root = TempDir::new().expect("root");
        let (client, preparations) = client_with(root.path(), &[]);

        client.close().expect("closes");

        assert_eq!(preparations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refuses_to_work_once_closed() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        client.close().expect("closes");

        let error = client.account().expect_err("refused");

        assert_eq!(error.to_string(), "CodexSecurity is closed.");
    }

    // Two operations share one runtime and one set of credentials, so a login
    // in one would change the identity the other is running under.
    #[test]
    fn refuses_a_second_operation_while_one_is_running() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        let client = Arc::new(client);

        let held = client.begin_operation().expect("claims the operation");
        let error = client.account().expect_err("the second is refused");
        drop(held);

        assert_eq!(
            error.to_string(),
            "A Codex Security operation is already in progress."
        );
        client.account().expect("the next one succeeds");
    }

    // Closing must not block on a scan that will never finish on its own.
    #[test]
    fn closing_cancels_before_waiting_for_the_operation() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        let client = Arc::new(client);
        let running = Arc::new(std::sync::Barrier::new(2));

        let worker = {
            let client = Arc::clone(&client);
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                client.run_operation(|client, _| {
                    running.wait();
                    // Stands in for a scan that only stops when cancelled.
                    while !client.cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    Ok(())
                })
            })
        };

        running.wait();
        client.close().expect("closes");

        let outcome = worker.join().expect("the operation finished");
        assert!(
            outcome.is_err(),
            "an operation interrupted by close does not report success"
        );
        assert!(!root.path().join("codex-home").exists());
    }

    /// Reports the credential state the stored runtime currently has.
    fn stored_credentials(client: &CodexSecurity) -> bool {
        client
            .runtime
            .lock()
            .expect("runtime")
            .as_ref()
            .expect("a prepared runtime")
            .credentials_available
    }

    // Operations hand out copies of the runtime, so a login must be recorded on
    // the shared one: otherwise the next scan would still believe it has no
    // credentials and refuse to start.
    #[test]
    fn a_login_is_visible_to_later_operations() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        client.account().expect("prepares a runtime");
        assert!(!stored_credentials(&client));

        client.set_credentials_available(true);

        assert!(stored_credentials(&client));
        assert!(
            client
                .ensure_runtime()
                .expect("runtime")
                .credentials_available,
            "a later operation sees the login"
        );
    }

    // Logging out must be just as visible, or a scan would start against
    // credentials that are no longer there.
    #[test]
    fn a_logout_is_visible_to_later_operations() {
        let root = TempDir::new().expect("root");
        let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
        client.account().expect("prepares a runtime");
        client.set_credentials_available(true);

        client.set_credentials_available(false);

        assert!(
            !client
                .ensure_runtime()
                .expect("runtime")
                .credentials_available
        );
    }

    /// A git repository with one commit, so targets resolve.
    fn repository(root: &Path) -> PathBuf {
        let repository = root.join("repository");
        std::fs::create_dir_all(repository.join("src")).expect("create source");
        std::fs::write(repository.join("src/main.rs"), "fn main() {}").expect("write");
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.email", "scan@example.com"],
            vec!["config", "user.name", "Scan"],
            vec!["add", "."],
            vec!["commit", "--quiet", "-m", "initial"],
        ] {
            let status = std::process::Command::new("git")
                .args(&arguments)
                .current_dir(&repository)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("run git");
            assert!(status.success(), "git {arguments:?} failed");
        }
        std::fs::canonicalize(&repository).expect("canonicalize")
    }

    /// A client whose runtime preparation fails loudly if it is ever reached.
    fn local_only_client(environment: &[(&str, &str)]) -> CodexSecurity {
        let dependencies = ClientDependencies::default()
            .with_environment(
                environment
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            )
            .with_prepare_runtime(Box::new(|_, _| {
                panic!("preflight must not prepare a runtime")
            }));
        CodexSecurity::with_dependencies(CodexSecurityConfig::default(), dependencies)
    }

    // Preflight is local: it uses no credentials, installs no plugin, and
    // creates nothing, so a caller can show what is about to happen.
    #[test]
    fn preflights_without_preparing_a_runtime() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let output = root.path().join("scan");
        let client = local_only_client(&[("OPENAI_API_KEY", "must-not-be-used")]);

        let preflight = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new()
                    .with_target(ScanTarget::Paths(vec!["src".to_owned()]))
                    .with_mode(ScanMode::Deep)
                    .with_output_dir(output.display().to_string()),
            )
            .expect("preflights");

        assert_eq!(preflight.repository, repository);
        assert_eq!(preflight.mode, ScanMode::Deep);
        assert_eq!(preflight.model, "gpt-5.6-sol");
        assert_eq!(preflight.reasoning_effort, "xhigh");
        assert_eq!(
            preflight.authentication,
            ScanAuthentication::ApiKey {
                source: crate::api::ApiKeySource::OpenAiApiKey,
                verified: false,
            }
        );
        // Nothing was created on the way.
        assert!(!output.exists());
    }

    #[test]
    fn reports_the_configured_model_and_reasoning() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let config = CodexSecurityConfig {
            codex_overrides: serde_json::json!({
                "model": "configured-model",
                "model_reasoning_effort": "high",
            })
            .as_object()
            .cloned(),
            ..CodexSecurityConfig::default()
        };
        let dependencies = ClientDependencies::default()
            .with_environment(ProcessEnvironment::new())
            .with_prepare_runtime(Box::new(|_, _| {
                panic!("preflight must not prepare a runtime")
            }));
        let client = CodexSecurity::with_dependencies(config, dependencies);

        let preflight = client
            .preflight(&repository.display().to_string(), &ScanOptions::new())
            .expect("preflights");

        assert_eq!(preflight.model, "configured-model");
        assert_eq!(preflight.reasoning_effort, "high");
    }

    // Results carry source excerpts; writing them into the tree under review
    // would mix them into the very thing being reviewed.
    #[test]
    fn refuses_output_inside_the_repository() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);

        let error = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new().with_output_dir(repository.join("scan").display().to_string()),
            )
            .expect_err("refused");

        assert_eq!(error.class_name(), "OutputInsideProtectedRootError");
        assert_eq!(
            error.output_directory_path(),
            Some(repository.join("scan").as_path())
        );
        assert_eq!(error.protected_root(), Some(repository.as_path()));
        assert_eq!(error.path_kind(), Some(ProtectedScanPathKind::Output));
    }

    #[test]
    fn refuses_configuration_that_takes_over_plugin_loading() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let config = CodexSecurityConfig {
            codex_overrides: serde_json::json!({ "plugins": { "unexpected": true } })
                .as_object()
                .cloned(),
            ..CodexSecurityConfig::default()
        };
        let client = CodexSecurity::with_dependencies(
            config,
            ClientDependencies::default().with_environment(ProcessEnvironment::new()),
        );

        let error = client
            .preflight(&repository.display().to_string(), &ScanOptions::new())
            .expect_err("refused");

        assert!(
            error
                .to_string()
                .contains("Codex Security owns plugin loading configuration"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn refuses_a_repository_that_is_not_there() {
        let client = local_only_client(&[]);

        let error = client
            .preflight("/definitely/missing/repository", &ScanOptions::new())
            .expect_err("refused");

        assert_eq!(error.class_name(), "InvalidTargetError");
    }

    #[test]
    fn refuses_a_cost_limit_that_is_not_a_positive_amount() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);

        for limit in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let error = client
                .preflight(
                    &repository.display().to_string(),
                    &ScanOptions::new().with_max_cost_usd(limit),
                )
                .expect_err("refused");
            assert!(
                error.to_string().contains("must be a positive USD amount"),
                "{limit} was accepted: {error}"
            );
        }
    }

    // Deep mode reads the whole tree, which a diff target cannot describe.
    #[test]
    fn refuses_deep_mode_against_a_diff_target() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);

        let error = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new()
                    .with_target(ScanTarget::Diff(
                        crate::targets::DiffTarget::working_tree(None).expect("a diff target"),
                    ))
                    .with_mode(ScanMode::Deep),
            )
            .expect_err("refused");

        assert_eq!(error.class_name(), "InvalidTargetError");
    }

    // These would send git somewhere other than the repository under scan.
    #[test]
    fn refuses_git_environment_overrides() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[("GIT_DIR", "/elsewhere/.git")]);

        let error = client
            .preflight(&repository.display().to_string(), &ScanOptions::new())
            .expect_err("refused");

        assert!(
            error.to_string().contains("GIT_DIR is not supported"),
            "unexpected: {error}"
        );
    }

    /// Creates an output directory a scan will accept: private to its owner.
    fn create_private_output(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path).expect("create output");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("make the output private");
    }

    // Preflight only reports where output would move to; nothing is moved
    // until the scan itself runs.
    #[test]
    fn previews_an_archive_without_moving_anything() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let output = root.path().join("scan");
        create_private_output(&output);
        std::fs::write(output.join("previous.txt"), "previous scan\n").expect("write");
        let client = local_only_client(&[]);

        let preflight = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new()
                    .with_output_dir(output.display().to_string())
                    .with_archive_existing(true),
            )
            .expect("preflights");

        let archive_dir = preflight.archive_dir.expect("an archive is planned");
        assert!(
            archive_dir
                .display()
                .to_string()
                .starts_with(&format!("{}.previous-", output.display())),
            "unexpected archive: {}",
            archive_dir.display()
        );
        // The existing output is untouched, and the archive does not yet exist.
        assert_eq!(
            std::fs::read_to_string(output.join("previous.txt")).expect("read"),
            "previous scan\n"
        );
        assert!(!archive_dir.exists());
    }

    // Nothing to move aside means nothing to report.
    #[test]
    fn plans_no_archive_for_an_empty_output_directory() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let output = root.path().join("scan");
        create_private_output(&output);
        let client = local_only_client(&[]);

        let preflight = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new()
                    .with_output_dir(output.display().to_string())
                    .with_archive_existing(true),
            )
            .expect("preflights");

        assert_eq!(preflight.archive_dir, None);
    }

    // A scan into a temporary directory has nothing to archive.
    #[test]
    fn plans_no_archive_without_an_output_directory() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);

        let preflight = client
            .preflight(
                &repository.display().to_string(),
                &ScanOptions::new().with_archive_existing(true),
            )
            .expect("preflights");

        assert_eq!(preflight.output_dir, None);
        assert_eq!(preflight.archive_dir, None);
    }

    #[test]
    fn refuses_to_preflight_once_closed() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);
        client.close().expect("closes");

        let error = client
            .preflight(&repository.display().to_string(), &ScanOptions::new())
            .expect_err("refused");

        assert_eq!(error.to_string(), "CodexSecurity is closed.");
    }

    /// Records what a scan reported, so tests can assert on it.
    #[derive(Default)]
    struct RecordingObserver {
        authentications: Vec<ScanAuthentication>,
        output_dirs: Vec<PathBuf>,
        scan_started: bool,
    }

    impl ScanObserver for RecordingObserver {
        fn on_scan_started(&mut self) {
            self.scan_started = true;
        }

        fn on_authentication(&mut self, authentication: ScanAuthentication) {
            self.authentications.push(authentication);
        }

        fn on_output_dir_ready(&mut self, scan_dir: &Path) {
            self.output_dirs.push(scan_dir.to_path_buf());
        }
    }

    // A request that cannot be satisfied costs nothing: the failure arrives
    // before a runtime is prepared and before the agent is told anything.
    #[test]
    fn refuses_a_scan_of_a_repository_that_is_not_there() {
        let client = local_only_client(&[]);
        let mut observer = RecordingObserver::default();

        let error = client
            .run(
                "/definitely/missing/repository",
                &ScanOptions::new(),
                &mut observer,
                &ScanCancellation::new(),
            )
            .expect_err("refused");

        assert_eq!(error.class_name(), "InvalidTargetError");
        assert!(!observer.scan_started, "the scan must not have started");
    }

    #[test]
    fn refuses_to_scan_once_closed() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);
        client.close().expect("closes");

        let error = client
            .run(
                &repository.display().to_string(),
                &ScanOptions::new(),
                &mut RecordingObserver::default(),
                &ScanCancellation::new(),
            )
            .expect_err("refused");

        assert_eq!(error.to_string(), "CodexSecurity is closed.");
    }

    // A scan holds the client's one operation slot for its whole duration.
    #[test]
    fn refuses_a_scan_while_another_operation_runs() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[("OPENAI_API_KEY", "sk-one")]);

        let held = client.begin_operation().expect("claims the operation");
        let error = client
            .run(
                &repository.display().to_string(),
                &ScanOptions::new(),
                &mut RecordingObserver::default(),
                &ScanCancellation::new(),
            )
            .expect_err("refused");
        drop(held);

        assert_eq!(
            error.to_string(),
            "A Codex Security operation is already in progress."
        );
    }

    // The same local checks preflight makes, made again before any work.
    #[test]
    fn refuses_a_scan_writing_into_the_repository() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let client = local_only_client(&[]);

        let error = client
            .run(
                &repository.display().to_string(),
                &ScanOptions::new().with_output_dir(repository.join("scan").display().to_string()),
                &mut RecordingObserver::default(),
                &ScanCancellation::new(),
            )
            .expect_err("refused");

        assert_eq!(error.class_name(), "OutputInsideProtectedRootError");
    }

    // A cancelled scan stops while preparing its knowledge base, before a
    // runtime exists.
    #[test]
    fn stops_a_scan_that_was_cancelled_before_it_began() {
        let root = TempDir::new().expect("root");
        let repository = repository(root.path());
        let documents = root.path().join("documents");
        std::fs::create_dir_all(&documents).expect("create documents");
        std::fs::write(documents.join("scope.md"), "Scope").expect("write");
        let client = local_only_client(&[]);
        let cancellation = ScanCancellation::new();
        cancellation.cancel();

        let error = client
            .run(
                &repository.display().to_string(),
                &ScanOptions::new().with_knowledge_base_paths([documents.display().to_string()]),
                &mut RecordingObserver::default(),
                &cancellation,
            )
            .expect_err("cancelled");

        assert!(
            error.to_string().contains("interrupted"),
            "unexpected: {error}"
        );
    }

    /// A client whose codex prints `lines`, then waits to be cancelled.
    ///
    /// Each line is written by `/bin/echo` rather than the shell's `printf`:
    /// a builtin writing down a pipe is block-buffered, so its output would not
    /// appear until the process exited, and the login would look silent for as
    /// long as it ran. The real `codex` flushes as it prints.
    fn login_client(root: &Path, lines: &[&str]) -> CodexSecurity {
        use std::os::unix::fs::PermissionsExt;
        let codex = root.join("codex");
        let printed: String = lines
            .iter()
            .map(|line| format!("/bin/echo '{line}'\n"))
            .collect();
        std::fs::write(&codex, format!("#!/bin/sh\n{printed}exec sleep 30\n")).expect("write stub");
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");

        let runtime = prepared(root);
        let command = codex.clone();
        let dependencies = ClientDependencies::default()
            .with_environment(ProcessEnvironment::new())
            .with_prepare_runtime(Box::new(move |_, _| Ok(runtime.clone())))
            .with_resolve_command(Box::new(move |_, _| {
                Ok(CodexCommand {
                    command: command.clone(),
                    prefix_args: Vec::new(),
                })
            }));
        CodexSecurity::with_dependencies(CodexSecurityConfig::default(), dependencies)
    }

    // The URL is available long before the person finishes signing in, which is
    // the whole point of returning a handle.
    #[test]
    fn returns_a_login_handle_once_the_url_is_available() {
        let root = TempDir::new().expect("root");
        let client = login_client(root.path(), &["Open https://auth.openai.com/activate"]);

        let handle = client.login_chatgpt().expect("the login starts");

        assert_eq!(
            handle.auth_url().as_deref(),
            Some("https://auth.openai.com/activate")
        );
        handle.cancel();
    }

    #[test]
    fn returns_a_device_code_login_handle_with_both_instructions() {
        let root = TempDir::new().expect("root");
        let client = login_client(
            root.path(),
            &["Visit https://auth.openai.com/activate", "code: ABCD-1234"],
        );

        let handle = client
            .login_chatgpt_device_code()
            .expect("the login starts");

        assert_eq!(
            handle.verification_url().as_deref(),
            Some("https://auth.openai.com/activate")
        );
        assert_eq!(handle.user_code().as_deref(), Some("ABCD-1234"));
        handle.cancel();
    }

    // A login waits on a person, so it never ends on its own; closing the
    // client must stop it rather than leave it running.
    #[test]
    fn closing_cancels_an_interactive_login() {
        let root = TempDir::new().expect("root");
        let client = login_client(root.path(), &["Open https://auth.openai.com/activate"]);
        let handle = client.login_chatgpt().expect("the login starts");

        client.close().expect("closes");

        let result = handle.wait().expect("the login finishes");
        assert!(
            !result.success,
            "a cancelled login is not a success: {result:?}"
        );
    }

    #[test]
    fn refuses_to_start_a_login_once_closed() {
        let root = TempDir::new().expect("root");
        let client = login_client(root.path(), &["Open https://auth.openai.com/activate"]);
        client.close().expect("closes");

        let error = client.login_chatgpt().expect_err("refused");

        assert_eq!(error.to_string(), "CodexSecurity is closed.");
    }

    // A dropped client must not leave its isolated directories behind.
    #[test]
    fn removes_its_runtime_when_dropped() {
        let root = TempDir::new().expect("root");
        {
            let (client, _) = client_with(root.path(), &[("OPENAI_API_KEY", "sk-one")]);
            client.account().expect("prepares a runtime");
        }

        assert!(!root.path().join("codex-home").exists());
    }
}
