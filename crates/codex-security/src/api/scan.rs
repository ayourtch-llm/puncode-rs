//! Running one scan, from a validated request to a checked result.
//!
//! Ported from `CodexSecurity#run` in `src/api.ts`.
//!
//! The sequence matters more than any individual step:
//!
//! 1. Everything checkable locally is checked, so a bad request costs nothing.
//! 2. Every directory the scan will touch is confirmed to be outside the
//!    repository, before it is created. Results quote source and reproduction
//!    steps, so writing them into the tree under review would contaminate it.
//! 3. Credentials are established, and a scan with none stops here rather than
//!    starting an agent that cannot work.
//! 4. The scan is registered with the workbench *before* the agent starts, so a
//!    scan that dies partway through is recorded as failed instead of vanishing.
//! 5. The agent runs; its cost is tracked as it goes, and a budget stops it
//!    mid-flight rather than after the money is spent.
//! 6. Whatever happens, the knowledge base and the scoped target file are
//!    removed, and the workbench is told how the scan ended.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::codex::ThreadOptions;
use crate::config::{merged_codex_config, scan_model_configuration};
use crate::contract::ScanExpectation;
use crate::contract::datetime::utc_rfc3339_now;
use crate::cost::{ScanCost, ScanCostTracker};
use crate::error::{Error, ProtectedScanPathKind, Result};
use crate::knowledge_base::{PreparedKnowledgeBase, prepare_knowledge_base_in};
use crate::models::SeverityLevel;
use crate::result::ScanResult;
use crate::runtime::{
    PluginPythonOptions, PrepareOutputOptions, WorkbenchCommandOptions,
    codex_security_state_directory, plugin_execution_environment, prepare_output_dir,
    prepare_persistent_scan_root, require_model_safe_output_dir, resolve_plugin_python,
    run_workbench,
};
use crate::targets::{NormalizedTargetKind, ProcessEnvironment, repository_revision};

use super::client::{CodexSecurity, ScanOptions};
use super::environment::{environment_api_key, scan_authentication, without_codex_home};
use super::events::{ScanCancellation, ScanEventOptions, ScanObserver, run_scan_events};
use super::prompt::{
    ScanRecipeOptions, require_output_outside_repository, scan_prompt, scan_recipe,
    validate_scan_cost_limit,
};
use super::runtime_prep::PreparedRuntime;

/// The permission profile the agent runs under.
const SCAN_PERMISSION_PROFILE: &str = "codex_security_scan";

/// One scan in progress.
pub(crate) struct ScanRun<'a> {
    pub(crate) client: &'a CodexSecurity,
    pub(crate) options: &'a ScanOptions,
    pub(crate) cancellation: &'a ScanCancellation,
}

/// Things a scan creates that must be removed however it ends.
#[derive(Default)]
struct ScanScratch {
    knowledge_base: Option<PreparedKnowledgeBase>,
    /// The file naming the paths a scoped scan may read.
    target_paths_file: Option<PathBuf>,
}

impl ScanScratch {
    fn discard(&self) {
        if let Some(knowledge_base) = &self.knowledge_base {
            let _ = knowledge_base.cleanup();
        }
        if let Some(path) = &self.target_paths_file {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl ScanRun<'_> {
    /// Runs the scan, cleaning up whatever it created.
    pub(crate) fn execute(
        &self,
        repository: &str,
        observer: &mut dyn ScanObserver,
    ) -> Result<ScanResult> {
        let mut scratch = ScanScratch::default();
        let outcome = self.drive(repository, observer, &mut scratch);
        scratch.discard();
        outcome
    }

    fn drive(
        &self,
        repository: &str,
        observer: &mut dyn ScanObserver,
        scratch: &mut ScanScratch,
    ) -> Result<ScanResult> {
        let client = self.client;
        let environment = &client.dependencies().environment;
        let inputs = client.validate_local_inputs(repository, self.options)?;
        let protected_root = inputs.protected_root().to_path_buf();
        let protect = |path: &Path, kind: ProtectedScanPathKind| -> Result<()> {
            require_output_outside_repository(&protected_root, path, kind)
        };

        // State outlives the scan, so it must not live in the tree either.
        let state_directory = codex_security_state_directory(environment);
        protect(&state_directory, ProtectedScanPathKind::Output)?;
        self.check_open()?;

        let temporary_root = client.temporary_root()?;
        protect(&temporary_root, ProtectedScanPathKind::Temporary)?;

        if !self.options.knowledge_base_paths.is_empty() {
            scratch.knowledge_base = Some(prepare_knowledge_base_in(
                &temporary_root,
                &self.options.knowledge_base_paths,
                self.cancellation,
            )?);
        }
        self.check_open()?;

        let runtime = client.ensure_runtime_within(&temporary_root, &|path| {
            protect(path, ProtectedScanPathKind::Runtime)
        })?;
        let runtime_home = std::fs::canonicalize(&runtime.codex_home).map_err(|error| {
            Error::plugin_bootstrap("Unable to inspect the isolated Codex home").with_source(error)
        })?;
        protect(&runtime_home, ProtectedScanPathKind::Runtime)?;

        // A re-run must reproduce the original scan, which a different plugin
        // version would not.
        if let Some(expected) = &self.options.expected_plugin_version
            && &runtime.plugin.version != expected
        {
            return Err(Error::codex_security(format!(
                "The original scan used plugin version {expected}, but the installed version is {}.",
                runtime.plugin.version
            )));
        }
        self.check_open()?;

        let credentials_available = self.establish_credentials(&runtime, observer)?;
        if !credentials_available {
            return Err(Error::authentication_required(
                "No credentials were found. Run 'codex-security login', use \
                 'codex-security login --device-auth' on a remote or headless machine, or set \
                 OPENAI_API_KEY or CODEX_API_KEY for CI.",
            ));
        }
        observer.on_authentication(scan_authentication(environment));

        let python = resolve_plugin_python(&PluginPythonOptions {
            configured_path: client
                .config()
                .python_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            environment: environment.clone(),
            protected_root: protected_root.clone(),
            home_directory: None,
            managed_runtime_roots: None,
        })?;
        self.check_open()?;

        let scan_dir = self.prepare_scan_directory(
            &inputs,
            &state_directory,
            &temporary_root,
            &protect,
            observer,
        )?;
        self.check_open()?;

        let plugin_root = self.shell_visible_plugin_root(&runtime, &runtime_home)?;
        let prompt = scan_prompt(
            &plugin_root,
            inputs.target(),
            inputs.mode(),
            runtime.config_path.is_some(),
            scratch.knowledge_base.is_some(),
        )?;
        self.check_open()?;

        let revision = repository_revision(inputs.repository(), environment);
        let expectation = ScanExpectation {
            repository: inputs.repository().to_path_buf(),
            repository_revision: revision.clone(),
            target: inputs.target().clone(),
            mode: inputs.mode(),
            plugin_version: runtime.plugin.version.clone(),
        };

        let effective_config = match &runtime.effective_config {
            Some(config) => config.clone(),
            None => merged_codex_config(client.config())?,
        };
        let model = scan_model_configuration(&effective_config)?.model;
        validate_scan_cost_limit(self.options.max_cost_usd, &model)?;

        let workbench_environment = {
            let mut environment = runtime.environment.clone();
            environment.insert(
                "CODEX_SECURITY_STATE_DIR".to_owned(),
                state_directory.to_string_lossy().into_owned(),
            );
            environment
        };
        let workbench = WorkbenchCommandOptions {
            python: &python,
            plugin_root: &runtime.plugin.plugin_root,
            environment: &workbench_environment,
            failure_message: Some("Could not save the Codex Security scan"),
        };

        let recipe = scan_recipe(&ScanRecipeOptions {
            repository: &inputs.repository().to_string_lossy(),
            target: inputs.target(),
            mode: inputs.mode(),
            repository_revision: revision.as_deref(),
            plugin_version: &runtime.plugin.version,
            effective_config: &effective_config,
            fail_on_severity: self.failure_severity().as_ref(),
            knowledge_base_paths: self.knowledge_base_sources(scratch).as_deref(),
            max_cost_usd: self.options.max_cost_usd,
        })?;

        // Registered before the agent starts: a scan that dies partway through
        // is then recorded as failed rather than disappearing.
        let registration = self.register(&workbench, inputs.repository(), &scan_dir, &recipe)?;
        self.check_open()?;

        let placement = ScanPlacement {
            runtime: &runtime,
            python: &python,
            state_directory: &state_directory,
            scan_dir: &scan_dir,
            plugin_root: &plugin_root,
            repository: inputs.repository(),
            registration: &registration,
        };
        let outcome = self.run_agent(
            &placement,
            &prompt,
            &expectation,
            &model,
            &workbench,
            &inputs,
            scratch,
            observer,
        );

        match outcome {
            Ok(result) => Ok(result),
            Err(failure) => {
                // The workbench is told how the scan ended even when the
                // failure is what stopped it.
                self.fail_scan(&workbench, &registration.scan_id, &failure);
                Err(self.explain(failure, &scan_dir))
            }
        }
    }

    /// Stores an environment API key in the runtime, and reports whether the
    /// scan has credentials at all.
    fn establish_credentials(
        &self,
        runtime: &PreparedRuntime,
        _observer: &mut dyn ScanObserver,
    ) -> Result<bool> {
        let client = self.client;
        let environment = &client.dependencies().environment;
        let Some(api_key) = environment_api_key(environment) else {
            return Ok(runtime.credentials_available);
        };
        // An environment key is authoritative and may have been rotated, so it
        // is stored on every run rather than trusted from a previous one.
        let command = client.codex_command_for(&client.temporary_root()?)?;
        let login = crate::auth::login_api_key(&command, &runtime.environment, &api_key)?;
        if !login.success {
            let detail = [login.stderr.trim(), login.stdout.trim()]
                .into_iter()
                .find(|candidate| !candidate.is_empty())
                .unwrap_or("unknown error");
            return Err(Error::codex_security(format!(
                "Codex API-key login failed: {detail}"
            )));
        }
        client.record_credentials_available(true);
        Ok(true)
    }

    /// Creates the directory the scan writes into.
    fn prepare_scan_directory(
        &self,
        inputs: &super::client::LocalScanInputs,
        state_directory: &Path,
        temporary_root: &Path,
        protect: &dyn Fn(&Path, ProtectedScanPathKind) -> Result<()>,
        observer: &mut dyn ScanObserver,
    ) -> Result<PathBuf> {
        let client = self.client;
        let repository_name = inputs
            .repository()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        // Output the caller did not place goes under persistent state, so a
        // scan's results survive the temporary directory being cleared.
        let output_root = if inputs.output_dir().is_none() {
            prepare_persistent_scan_root(state_directory, &repository_name)?
        } else {
            temporary_root.to_path_buf()
        };
        protect(&output_root, ProtectedScanPathKind::Output)?;

        let archived = std::cell::RefCell::new(None);
        let note_archive = |archive_dir: &Path| {
            *archived.borrow_mut() = Some(archive_dir.to_path_buf());
        };
        let requested = inputs
            .output_dir()
            .map(|path| path.to_string_lossy().into_owned());
        let location = |path: &Path| protect(path, ProtectedScanPathKind::Output);
        let scan_dir = prepare_output_dir(&PrepareOutputOptions {
            output_directory: requested.as_deref(),
            repository_name: &repository_name,
            temporary_root: output_root,
            validate_location: Some(&location),
            archive_existing: self.options.archive_existing,
            on_output_archived: Some(&note_archive),
            environment: &client.dependencies().environment,
        })?;

        if let Some(archive_dir) = archived.borrow().as_ref() {
            observer.on_output_archived(archive_dir);
        }
        protect(&scan_dir, ProtectedScanPathKind::Output)?;
        require_model_safe_output_dir(&scan_dir.to_string_lossy())?;
        observer.on_output_dir_ready(&scan_dir);
        Ok(scan_dir)
    }

    /// The plugin directory the agent's shell may see.
    ///
    /// It must be outside `CODEX_HOME`: the agent can read what it runs, and
    /// the credential home sits next to nothing it should reach.
    fn shell_visible_plugin_root(
        &self,
        runtime: &PreparedRuntime,
        runtime_home: &Path,
    ) -> Result<PathBuf> {
        let plugin_root = std::fs::canonicalize(&runtime.plugin.plugin_root).map_err(|error| {
            Error::plugin_bootstrap("Unable to inspect the Codex Security plugin root")
                .with_source(error)
        })?;
        if plugin_root.starts_with(runtime_home) {
            return Err(Error::output_directory(format!(
                "Shell-visible plugin root must be outside CODEX_HOME: {}",
                plugin_root.display()
            )));
        }
        Ok(plugin_root)
    }

    /// Registers the scan with the workbench.
    fn register(
        &self,
        workbench: &WorkbenchCommandOptions<'_>,
        repository: &Path,
        scan_dir: &Path,
        recipe: &Map<String, Value>,
    ) -> Result<Registration> {
        let repository = repository.to_string_lossy().into_owned();
        let scan_dir_text = scan_dir.to_string_lossy().into_owned();
        let recipe_json = serde_json::to_string(recipe).map_err(|error| {
            Error::codex_security("Unable to serialize the Codex Security scan recipe")
                .with_source(error)
        })?;
        let mut arguments = vec![
            "register-cli-scan",
            "--repository",
            &repository,
            "--scan-dir",
            &scan_dir_text,
            "--recipe-json",
            &recipe_json,
        ];
        if let Some(parent) = &self.options.parent_scan_id {
            arguments.push("--parent-scan-id");
            arguments.push(parent);
        }

        let registration = run_workbench(workbench, &arguments)?;
        let scan_id = registration.get("scanId").and_then(Value::as_str);
        let target_id = registration.get("targetId").and_then(Value::as_str);
        let registered_dir = registration.get("scanDir").and_then(Value::as_str);
        let (Some(scan_id), Some(target_id)) = (scan_id, target_id) else {
            return Err(invalid_registration());
        };
        if registered_dir != Some(scan_dir_text.as_str()) {
            return Err(invalid_registration());
        }
        Ok(Registration {
            scan_id: scan_id.to_owned(),
            target_id: target_id.to_owned(),
        })
    }

    /// Tells the workbench a scan failed, without masking the original failure.
    fn fail_scan(&self, workbench: &WorkbenchCommandOptions<'_>, scan_id: &str, failure: &Error) {
        // Truncated because a workbench argument is not the place for an
        // unbounded message.
        let message: String = failure.to_string().chars().take(2400).collect();
        let _ = run_workbench(
            workbench,
            &["fail-scan", "--scan-id", scan_id, "--message", &message],
        );
    }

    /// Replaces a downstream failure with the interruption that caused it.
    fn explain(&self, failure: Error, scan_dir: &Path) -> Error {
        if let Some(reason) = self.cancellation.take_reason() {
            return reason;
        }
        if self.cancellation.is_cancelled() && !failure.is_scan_interrupted() {
            return Error::scan_interrupted(
                format!(
                    "Codex Security scan was interrupted; partial output remains at {}.",
                    scan_dir.display()
                ),
                scan_dir,
            )
            .with_source(failure);
        }
        failure
    }

    fn failure_severity(&self) -> Option<SeverityLevel> {
        self.options
            .failure_severity
            .clone()
            .map(SeverityLevel::from)
    }

    fn knowledge_base_sources(&self, scratch: &ScanScratch) -> Option<Vec<String>> {
        let knowledge_base = scratch.knowledge_base.as_ref()?;
        Some(
            knowledge_base
                .sources
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        )
    }

    fn check_open(&self) -> Result<()> {
        self.client.require_open()
    }
}

/// Where one scan's pieces live, as the agent needs to see them.
struct ScanPlacement<'a> {
    runtime: &'a PreparedRuntime,
    python: &'a Path,
    state_directory: &'a Path,
    scan_dir: &'a Path,
    /// The plugin directory the agent's shell may read.
    plugin_root: &'a Path,
    repository: &'a Path,
    registration: &'a Registration,
}

/// What the workbench recorded for a scan.
struct Registration {
    scan_id: String,
    target_id: String,
}

fn invalid_registration() -> Error {
    Error::codex_security("The Codex Security workbench returned an invalid scan registration.")
}

/// Watches a scan on behalf of the caller, tracking what it spends.
///
/// Upstream keeps the cost tracker beside the event loop and aborts from its
/// `onCost` callback; here the tracker rides along as the observer, so the
/// budget is re-checked on every event the stream produces.
struct TrackingObserver<'a> {
    inner: &'a mut dyn ScanObserver,
    tracker: ScanCostTracker,
    cancellation: &'a ScanCancellation,
    scan_dir: PathBuf,
    max_cost_usd: Option<f64>,
    /// The last cost reported, so an unchanged one is not reported twice.
    reported: Option<ScanCost>,
    /// Set once the turn finished and the cost was settled.
    completed: bool,
    /// What the scan turned out to cost, once known.
    final_cost: Option<ScanCost>,
    workbench_failure: Option<Error>,
}

impl TrackingObserver<'_> {
    /// Re-reads what the scan has spent and stops it if that is too much.
    fn refresh_cost(&mut self) -> Result<()> {
        let Ok(snapshot) = self.tracker.refresh() else {
            // A missing or unreadable session log is not a scan failure; the
            // cost simply is not known yet.
            return Ok(());
        };
        let Some(cost) = snapshot.cost else {
            return Ok(());
        };
        if self.reported.as_ref() == Some(&cost) {
            return Ok(());
        }
        self.inner.on_cost(&cost);
        self.reported = Some(cost.clone());

        if let Some(limit) = self.max_cost_usd
            && cost.estimated_usd > limit
        {
            // Recorded as the reason so the caller learns it was the budget,
            // not a generic interruption, that stopped the scan.
            self.cancellation
                .cancel_with(Error::scan_cost_limit_exceeded(
                    limit,
                    cost.clone(),
                    &self.scan_dir,
                ));
            return Err(Error::scan_cost_limit_exceeded(limit, cost, &self.scan_dir));
        }
        Ok(())
    }
}

impl ScanObserver for TrackingObserver<'_> {
    fn on_thread_started(&mut self, thread_id: &str) {
        self.tracker.start(thread_id);
        self.inner.on_thread_started(thread_id);
    }

    fn on_scan_started(&mut self) {
        self.inner.on_scan_started();
    }

    fn on_worker_status(&mut self, status: &crate::worker_progress::ScanWorkerStatus) {
        self.inner.on_worker_status(status);
    }

    fn on_reconnect(
        &mut self,
        attempt: u32,
        max_attempts: u32,
        details: Option<super::connection::ScanReconnectDetails>,
    ) {
        self.inner.on_reconnect(attempt, max_attempts, details);
    }

    fn on_event(&mut self, event: &crate::codex::ThreadEvent) -> Result<()> {
        self.inner.on_event(event)?;
        self.refresh_cost()
    }

    fn finalize(&mut self, usage: Option<&Value>) -> Result<Option<Value>> {
        let snapshot = self.tracker.stop(usage.cloned()).map_err(|error| {
            Error::codex_security("Unable to read what the Codex Security scan spent")
                .with_source(error)
        })?;
        if self.cancellation.is_cancelled() {
            if let Some(reason) = self.cancellation.take_reason() {
                return Err(reason);
            }
            return Err(Error::scan_interrupted(
                format!(
                    "Codex Security scan was interrupted; partial output remains at {}.",
                    self.scan_dir.display()
                ),
                &self.scan_dir,
            ));
        }
        // A budget that cannot be evaluated is not a budget; saying the scan
        // stayed within it would be a guess.
        if self.max_cost_usd.is_some() && snapshot.cost.is_none() {
            return Err(Error::codex_security(
                "Cannot evaluate the cost limit: model pricing or token usage is unavailable.",
            ));
        }
        self.completed = true;
        self.final_cost = snapshot.cost.clone();
        let measured = self.inner.finalize(snapshot.usage.as_ref())?;
        Ok(measured.or(snapshot.usage))
    }
}

impl ScanRun<'_> {
    /// Starts the agent and drives its event stream to a result.
    #[allow(clippy::too_many_arguments)]
    fn run_agent(
        &self,
        placement: &ScanPlacement<'_>,
        prompt: &str,
        expectation: &ScanExpectation,
        model: &str,
        workbench: &WorkbenchCommandOptions<'_>,
        inputs: &super::client::LocalScanInputs,
        scratch: &mut ScanScratch,
        observer: &mut dyn ScanObserver,
    ) -> Result<ScanResult> {
        let runtime = placement.runtime;
        let scan_dir = placement.scan_dir;
        let registration = placement.registration;

        // A scoped scan names its paths in a file rather than on the command
        // line, so the list cannot be seen in the process table.
        if inputs.target().kind == Some(NormalizedTargetKind::Paths) {
            let path = runtime
                .codex_home
                .parent()
                .unwrap_or(&runtime.codex_home)
                .join(format!(
                    "codex-security-target-paths-{}.json",
                    registration.scan_id
                ));
            write_target_paths(&path, &inputs.target().paths)?;
            scratch.target_paths_file = Some(path);
        }

        let environment = self.scan_environment(placement, scratch);
        self.check_open()?;

        let codex = (self.client.dependencies().create_codex)(
            &environment,
            &self
                .client
                .codex_command_for(&self.client.temporary_root()?)?,
        );
        let mut thread = codex.start_thread(
            ThreadOptions::new()
                .working_directory(scan_dir)
                .skip_git_repo_check(true)
                .approval_policy("never")
                .config_override(format!("default_permissions=\"{SCAN_PERMISSION_PROFILE}\""))
                .config_override("allow_login_shell=false")
                .bypass_sandbox(self.options.bypass_sandbox),
        );

        let tracker = {
            let mut tracker = ScanCostTracker::new(&runtime.codex_home, model);
            if let Some(limit) = self.options.max_cost_usd {
                tracker = tracker.with_max_cost_usd(limit);
            }
            tracker
        };
        let mut tracking = TrackingObserver {
            inner: observer,
            tracker,
            cancellation: self.cancellation,
            scan_dir: scan_dir.to_path_buf(),
            max_cost_usd: self.options.max_cost_usd,
            reported: None,
            completed: false,
            final_cost: None,
            workbench_failure: None,
        };

        let events = thread.run_streamed(prompt)?;
        let result = run_scan_events(
            events,
            &ScanEventOptions {
                scan_dir,
                plugin_root: &runtime.plugin.installed_root,
                expectation,
                model: Some(model),
                thread_id: thread.id(),
                cancellation: self.cancellation,
            },
            &mut tracking,
        );

        let final_cost = tracking.final_cost.clone();
        let completed = tracking.completed;
        let result = result?;
        if completed {
            self.complete_scan(workbench, &registration.scan_id, final_cost.as_ref())?;
        }
        self.check_open()?;
        Ok(result)
    }

    /// The environment the agent runs in.
    ///
    /// The plugin reads these to know what it is scanning and where to write.
    fn scan_environment(
        &self,
        placement: &ScanPlacement<'_>,
        scratch: &ScanScratch,
    ) -> ProcessEnvironment {
        let runtime = placement.runtime;
        let mut environment = plugin_execution_environment(
            placement.python,
            &without_codex_home(&runtime.environment),
        );
        let repository = placement.repository;
        let mut set = |name: &str, value: String| {
            environment.insert(name.to_owned(), value);
        };

        set(
            "CODEX_HOME",
            runtime.codex_home.to_string_lossy().into_owned(),
        );
        set("CODEX_SECURITY_STARTED_AT", utc_rfc3339_now());
        set(
            "CODEX_SECURITY_REPOSITORY",
            repository.to_string_lossy().into_owned(),
        );
        set(
            "CODEX_SECURITY_SCAN_DIR",
            placement.scan_dir.to_string_lossy().into_owned(),
        );
        set(
            "CODEX_SECURITY_PLUGIN_ROOT",
            placement.plugin_root.to_string_lossy().into_owned(),
        );
        set(
            "CODEX_SECURITY_STATE_DIR",
            placement.state_directory.to_string_lossy().into_owned(),
        );
        set(
            "CODEX_SECURITY_SCAN_ID",
            placement.registration.scan_id.clone(),
        );
        set(
            "CODEX_SECURITY_TARGET_ID",
            placement.registration.target_id.clone(),
        );
        set(
            "CODEX_SECURITY_TARGET_DISPLAY_NAME",
            repository
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
        if let Some(knowledge_base) = &scratch.knowledge_base {
            set(
                "CODEX_SECURITY_KNOWLEDGE_BASE",
                knowledge_base.path.to_string_lossy().into_owned(),
            );
        }
        if let Some(config_path) = &runtime.config_path {
            set(
                "CODEX_SECURITY_CONFIG_PATH",
                config_path.to_string_lossy().into_owned(),
            );
        }
        if let Some(target_paths) = &scratch.target_paths_file {
            set(
                "CODEX_SECURITY_TARGET_PATHS_FILE",
                target_paths.to_string_lossy().into_owned(),
            );
        }
        environment
    }

    /// Records a finished scan, with what it cost.
    fn complete_scan(
        &self,
        workbench: &WorkbenchCommandOptions<'_>,
        scan_id: &str,
        cost: Option<&ScanCost>,
    ) -> Result<()> {
        let cost_json = match cost {
            Some(cost) => Some(serde_json::to_string(cost).map_err(|error| {
                Error::codex_security("Unable to serialize the Codex Security scan cost")
                    .with_source(error)
            })?),
            None => None,
        };
        let mut arguments = vec!["complete-scan", "--scan-id", scan_id];
        if let Some(cost_json) = &cost_json {
            arguments.push("--cost-json");
            arguments.push(cost_json);
        }
        run_workbench(workbench, &arguments)?;
        Ok(())
    }
}

/// Writes the paths a scoped scan may read, readable only by its owner.
///
/// The separators JSON leaves unescaped would end a line in some readers, so
/// they are escaped explicitly, matching upstream.
fn write_target_paths(path: &Path, paths: &[String]) -> Result<()> {
    use std::io::Write;
    let serialized = serde_json::to_string(paths)
        .map_err(|error| {
            Error::codex_security("Unable to serialize the scan target paths").with_source(error)
        })?
        .replace('\u{85}', "\\u0085")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::codex_security(format!(
            "Unable to write the scan target paths to {}",
            path.display()
        ))
        .with_source(error)
    })?;
    writeln!(file, "{serialized}").map_err(|error| {
        Error::codex_security(format!(
            "Unable to write the scan target paths to {}",
            path.display()
        ))
        .with_source(error)
    })
}
