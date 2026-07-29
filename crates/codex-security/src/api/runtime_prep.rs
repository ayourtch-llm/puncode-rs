//! Building the isolated runtime a scan executes in.
//!
//! Ported from `PreparedRuntime` and `CodexSecurity#prepareRuntime` in
//! `src/api.ts`.
//!
//! Two private directories are created, not one. The credential home holds the
//! isolated `CODEX_HOME`, and the bootstrap workspace holds everything the
//! model's shell is allowed to see — the plugin it runs and the readable
//! preflight snapshot. Keeping them apart is what lets the plugin root be
//! shell-visible without exposing the credentials next to it.
//!
//! Preparation is all-or-nothing: if any step fails, both directories are
//! removed. Cleanup is attempted for both even when the first removal fails,
//! and every failure is reported together — a directory left behind is exactly
//! what the caller needs to hear about.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::config::{CodexSecurityConfig, JsonObject, merged_codex_config, write_codex_config};
use crate::error::{Error, Result};
use crate::runtime::{
    CodexCommand, CodexRunner, LocationCheck, PluginInstall, bootstrap_plugin,
    cleanup_sdk_directory, codex_security_state_directory, create_isolated_home,
    import_ambient_auth, resolve_plugin_path,
};
use crate::targets::ProcessEnvironment;

use super::config_projection::{scan_preflight_codex_config, scan_runtime_codex_config};
use super::environment::{environment_value, initial_credentials_available, without_codex_home};
use super::events::ScanCancellation;

/// An isolated Codex installation, ready to run one client's scans.
#[derive(Debug, Clone)]
pub struct PreparedRuntime {
    /// The private `CODEX_HOME`, holding credentials and the installed plugin.
    pub codex_home: PathBuf,
    /// The shell-visible workspace: the plugin source and preflight snapshot.
    ///
    /// Absent when a caller supplied a runtime that has no workspace of its own.
    pub bootstrap_workspace: Option<PathBuf>,
    /// The readable preflight configuration, when one was written.
    pub config_path: Option<PathBuf>,
    pub plugin: PluginInstall,
    /// The environment subprocesses inherit, with `CODEX_HOME` pointed here.
    pub environment: ProcessEnvironment,
    /// Whether the runtime already holds credentials a scan could use.
    pub credentials_available: bool,
    /// The merged configuration, kept so a scan need not merge it again.
    pub effective_config: Option<JsonObject>,
}

impl PreparedRuntime {
    /// The directories preparation created, which closing must remove.
    fn owned_directories(&self) -> Vec<&Path> {
        let mut directories = vec![self.codex_home.as_path()];
        if let Some(workspace) = &self.bootstrap_workspace {
            directories.push(workspace.as_path());
        }
        directories
    }

    /// Removes both private directories.
    ///
    /// Every directory is attempted even after one fails, so a failure to
    /// remove the credential home does not leave the workspace behind too.
    pub fn cleanup(&self) -> Result<()> {
        let failures = cleanup_all(&self.owned_directories());
        into_single_failure(failures)
    }
}

/// Removes each directory, collecting rather than short-circuiting on failures.
fn cleanup_all(directories: &[&Path]) -> Vec<Error> {
    directories
        .iter()
        .filter_map(|path| cleanup_sdk_directory(path).err())
        .collect()
}

/// Reports the first failure, keeping any others attached to it.
///
/// Upstream's `close` rejects with the first cleanup failure, so that is what
/// callers see here too. The rest are attached rather than dropped: each names
/// a directory that was left behind.
fn into_single_failure(mut failures: Vec<Error>) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    let primary = failures.remove(0);
    Err(primary.with_aggregated(failures))
}

/// What preparing a runtime needs from its caller.
pub struct RuntimePreparation<'a> {
    pub config: &'a CodexSecurityConfig,
    /// The environment the client inherited, before isolation.
    pub environment: &'a ProcessEnvironment,
    pub command: &'a CodexCommand,
    pub runner: &'a dyn CodexRunner,
    /// Where the private directories are created.
    pub temporary_root: &'a Path,
    /// A caller's check that each created directory is somewhere acceptable.
    pub validate_location: Option<LocationCheck<'a>>,
    pub cancellation: &'a ScanCancellation,
    /// Copies the user's ambient credentials in; injectable for testing.
    pub import_ambient: &'a dyn Fn(&str, &Path, &ProcessEnvironment) -> Result<bool>,
}

impl<'a> RuntimePreparation<'a> {
    /// A preparation with the real Codex and the real credential import.
    pub fn new(
        config: &'a CodexSecurityConfig,
        environment: &'a ProcessEnvironment,
        command: &'a CodexCommand,
        runner: &'a dyn CodexRunner,
        temporary_root: &'a Path,
        cancellation: &'a ScanCancellation,
    ) -> Self {
        Self {
            config,
            environment,
            command,
            runner,
            temporary_root,
            validate_location: None,
            cancellation,
            import_ambient: &import_ambient_auth,
        }
    }

    #[must_use]
    pub fn with_validate_location(mut self, check: LocationCheck<'a>) -> Self {
        self.validate_location = Some(check);
        self
    }
}

/// Creates the isolated runtime, cleaning up completely if anything fails.
pub fn prepare_runtime(preparation: &RuntimePreparation<'_>) -> Result<PreparedRuntime> {
    let codex_home =
        create_isolated_home(preparation.temporary_root, preparation.validate_location)?;

    // From here on every failure must take both directories with it.
    let mut workspace: Option<PathBuf> = None;
    let outcome = prepare_within(preparation, &codex_home, &mut workspace);
    let Err(failure) = outcome else {
        return outcome;
    };

    // The workspace is removed first: it is created second, and removing the
    // credential home first would strand it if that removal fails.
    let mut directories: Vec<&Path> = Vec::new();
    if let Some(workspace) = &workspace {
        directories.push(workspace.as_path());
    }
    directories.push(codex_home.as_path());
    let cleanup_failures = cleanup_all(&directories);
    if cleanup_failures.is_empty() {
        return Err(failure);
    }
    Err(Error::aggregate(
        std::iter::once(failure).chain(cleanup_failures),
        "Codex Security runtime preparation failed and its isolated runtime \
         could not be cleaned up.",
    ))
}

/// The preparation proper, with the credential home already created.
///
/// `workspace` is written as soon as the bootstrap workspace exists so the
/// caller can clean it up even if a later step fails.
fn prepare_within(
    preparation: &RuntimePreparation<'_>,
    codex_home: &Path,
    workspace: &mut Option<PathBuf>,
) -> Result<PreparedRuntime> {
    stop_if_cancelled(preparation.cancellation)?;

    // Beside the credential home rather than inside it: the model's shell sees
    // the workspace, and must never see the credentials.
    let workspace_root = codex_home.parent().ok_or_else(|| {
        Error::plugin_bootstrap(format!(
            "Isolated Codex home has no parent directory: {}",
            codex_home.display()
        ))
    })?;
    let bootstrap_workspace = create_isolated_home(workspace_root, preparation.validate_location)?;
    *workspace = Some(bootstrap_workspace.clone());

    let plugin_root = resolve_plugin_path(
        preparation
            .config
            .plugin_path
            .as_deref()
            .and_then(Path::to_str),
        &bootstrap_workspace,
        preparation.environment,
    )?;

    // A configured CODEX_HOME names where the user's real credentials live;
    // without one they are in the conventional place.
    let ambient_home = environment_value(preparation.environment, "CODEX_HOME")
        .map(str::to_owned)
        .unwrap_or_else(default_ambient_home);

    let merged = merged_codex_config(preparation.config)?;
    write_codex_config(
        &codex_home.join("config.toml"),
        &scan_runtime_codex_config(&merged),
    )?;
    let config_path = bootstrap_workspace.join("config-preflight.toml");
    write_codex_config(&config_path, &scan_preflight_codex_config(&merged)?)?;
    stop_if_cancelled(preparation.cancellation)?;

    let inherited = without_codex_home(preparation.environment);
    let plugin = bootstrap_plugin(
        codex_home,
        &plugin_root,
        preparation.command,
        preparation.runner,
        &inherited,
    )?;
    let credentials_available = initial_credentials_available(
        preparation.environment,
        &ambient_home,
        codex_home,
        preparation.import_ambient,
    )?;

    let mut environment = inherited;
    environment.insert(
        "CODEX_HOME".to_owned(),
        codex_home.to_string_lossy().into_owned(),
    );
    environment.insert(
        "CODEX_SECURITY_STATE_DIR".to_owned(),
        codex_security_state_directory(preparation.environment)
            .to_string_lossy()
            .into_owned(),
    );

    Ok(PreparedRuntime {
        codex_home: codex_home.to_path_buf(),
        bootstrap_workspace: Some(bootstrap_workspace),
        config_path: Some(config_path),
        plugin,
        environment,
        credentials_available,
        effective_config: Some(merged),
    })
}

/// The conventional location of a user's Codex credentials.
fn default_ambient_home() -> String {
    std::env::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".codex")
        .to_string_lossy()
        .into_owned()
}

fn stop_if_cancelled(cancellation: &ScanCancellation) -> Result<()> {
    if !cancellation.is_cancelled() {
        return Ok(());
    }
    if let Some(reason) = cancellation.take_reason() {
        return Err(reason);
    }
    Err(Error::codex_security(
        "Codex Security runtime preparation was interrupted.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::TempDir;

    const MANIFEST: &str = r#"{"name":"codex-security","version":"0.1.14"}"#;

    /// Stands in for Codex, performing the side effects a real install has.
    struct FakeCodex {
        installed: RefCell<Vec<Vec<String>>>,
        fail: bool,
        /// Made unwritable as the failure is raised, so cleanup cannot succeed.
        seal_on_failure: Option<PathBuf>,
    }

    impl FakeCodex {
        fn new() -> Self {
            Self {
                installed: RefCell::new(Vec::new()),
                fail: false,
                seal_on_failure: None,
            }
        }
    }

    impl CodexRunner for FakeCodex {
        fn run(
            &self,
            _command: &CodexCommand,
            args: &[&str],
            environment: &ProcessEnvironment,
        ) -> Result<String> {
            self.installed
                .borrow_mut()
                .push(args.iter().map(|value| (*value).to_owned()).collect());
            if self.fail {
                if let Some(path) = &self.seal_on_failure {
                    seal(path);
                }
                return Err(Error::plugin_bootstrap("SYNTHETIC_BOOTSTRAP_FAILED"));
            }
            let codex_home = Path::new(&environment["CODEX_HOME"]);
            if args.first() == Some(&"plugin") && args.get(1) == Some(&"add") {
                let installed = codex_home
                    .join("plugins/cache/codex-security-sdk/codex-security/0.1.14/.codex-plugin");
                std::fs::create_dir_all(&installed).expect("create installed plugin");
                std::fs::write(installed.join("plugin.json"), MANIFEST).expect("write manifest");
                let config = format!(
                    "[marketplaces.\"codex-security-sdk\"]\nsource = \"{}\"\n\n\
                     [plugins.\"codex-security@codex-security-sdk\"]\n\
                     enabled = true\n",
                    codex_home.join("sdk-marketplace").display()
                );
                std::fs::write(codex_home.join("config.toml"), config).expect("write config");
            }
            Ok(String::new())
        }
    }

    fn plugin_tree(base: &Path) -> PathBuf {
        let root = base.join("plugin");
        std::fs::create_dir_all(root.join(".codex-plugin")).expect("create");
        std::fs::write(root.join(".codex-plugin").join("plugin.json"), MANIFEST).expect("write");
        root
    }

    fn command() -> CodexCommand {
        CodexCommand {
            command: PathBuf::from("/usr/bin/codex"),
            prefix_args: Vec::new(),
        }
    }

    fn environment(pairs: &[(&str, &str)]) -> ProcessEnvironment {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// A preparation whose plugin comes from `plugin_root` and whose ambient
    /// credential import is recorded rather than performed.
    struct Harness {
        temporary: TempDir,
        plugin_root: PathBuf,
        config: CodexSecurityConfig,
        environment: ProcessEnvironment,
        command: CodexCommand,
        cancellation: ScanCancellation,
        imported: RefCell<Vec<String>>,
    }

    impl Harness {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let temporary = TempDir::new().expect("temporary root");
            let plugin_root = plugin_tree(temporary.path());
            let config = CodexSecurityConfig {
                plugin_path: Some(plugin_root.clone()),
                ..CodexSecurityConfig::default()
            };
            Self {
                temporary,
                plugin_root,
                config,
                environment: environment(pairs),
                command: command(),
                cancellation: ScanCancellation::new(),
                imported: RefCell::new(Vec::new()),
            }
        }

        fn prepare(&self, runner: &dyn CodexRunner) -> Result<PreparedRuntime> {
            let importer = |ambient: &str, _: &Path, _: &ProcessEnvironment| -> Result<bool> {
                self.imported.borrow_mut().push(ambient.to_owned());
                Ok(true)
            };
            let mut preparation = RuntimePreparation::new(
                &self.config,
                &self.environment,
                &self.command,
                runner,
                self.temporary.path(),
                &self.cancellation,
            );
            preparation.import_ambient = &importer;
            prepare_runtime(&preparation)
        }
    }

    #[test]
    fn creates_a_credential_home_and_a_separate_shell_workspace() {
        let harness = Harness::new(&[]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        let workspace = runtime.bootstrap_workspace.as_ref().expect("a workspace");
        assert!(runtime.codex_home.is_dir());
        assert!(workspace.is_dir());
        assert_ne!(&runtime.codex_home, workspace);
        // The shell sees the workspace; it must not reach the credentials.
        assert!(
            !workspace.starts_with(&runtime.codex_home),
            "the shell workspace must live outside CODEX_HOME"
        );
        runtime.cleanup().expect("cleans up");
    }

    #[test]
    fn writes_the_runtime_config_into_the_credential_home() {
        let harness = Harness::new(&[]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        assert!(runtime.codex_home.join("config.toml").is_file());
        runtime.cleanup().expect("cleans up");
    }

    // The preflight snapshot is readable by the model, so it lives in the
    // workspace rather than beside the credentials.
    #[test]
    fn writes_the_preflight_snapshot_into_the_workspace() {
        let harness = Harness::new(&[]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        let config_path = runtime.config_path.as_ref().expect("a preflight snapshot");
        assert_eq!(
            config_path,
            &runtime
                .bootstrap_workspace
                .as_ref()
                .expect("a workspace")
                .join("config-preflight.toml")
        );
        assert!(config_path.is_file());
        runtime.cleanup().expect("cleans up");
    }

    // An inherited CODEX_HOME would send subprocesses to the user's real home.
    #[test]
    fn points_the_environment_at_the_isolated_home() {
        let harness = Harness::new(&[("CODEX_HOME", "/real/home"), ("KEEP", "yes")]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        assert_eq!(
            runtime.environment["CODEX_HOME"],
            runtime.codex_home.to_string_lossy()
        );
        assert_eq!(runtime.environment["KEEP"], "yes");
        assert!(runtime.environment.contains_key("CODEX_SECURITY_STATE_DIR"));
        runtime.cleanup().expect("cleans up");
    }

    // A configured CODEX_HOME names where the user's real credentials are.
    #[test]
    fn imports_credentials_from_the_configured_ambient_home() {
        let harness = Harness::new(&[("CODEX_HOME", "/real/home")]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        assert_eq!(harness.imported.borrow().as_slice(), ["/real/home"]);
        assert!(runtime.credentials_available);
        runtime.cleanup().expect("cleans up");
    }

    #[test]
    fn falls_back_to_the_conventional_ambient_home() {
        let harness = Harness::new(&[]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        assert!(
            harness.imported.borrow()[0].ends_with(".codex"),
            "expected the conventional home, got {:?}",
            harness.imported.borrow()[0]
        );
        runtime.cleanup().expect("cleans up");
    }

    #[test]
    fn keeps_the_merged_configuration_for_the_scan_to_reuse() {
        let harness = Harness::new(&[]);

        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        assert!(runtime.effective_config.is_some());
        assert_eq!(runtime.plugin.version, "0.1.14");
        runtime.cleanup().expect("cleans up");
    }

    // Preparation is all-or-nothing: a half-built runtime leaves nothing behind.
    #[test]
    fn removes_both_directories_when_preparation_fails() {
        let harness = Harness::new(&[]);
        let mut runner = FakeCodex::new();
        runner.fail = true;

        let error = harness.prepare(&runner).expect_err("preparation fails");

        assert!(error.to_string().contains("SYNTHETIC_BOOTSTRAP_FAILED"));
        let leftovers: Vec<_> = std::fs::read_dir(harness.temporary.path())
            .expect("read temporary root")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| {
                name.to_string_lossy()
                    .starts_with("openai-codex-security-home-")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "expected no isolated directories to survive, found {leftovers:?}"
        );
    }

    /// Makes `path` unwritable so its children cannot be unlinked.
    fn seal(path: &Path) {
        set_mode(path, 0o555);
    }

    /// Restores a sealed directory so the temporary root can be removed again.
    fn unseal(path: &Path) {
        set_mode(path, 0o700);
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path).expect("read mode").permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(path, permissions).expect("set mode");
    }

    // Losing either failure would leave the other unexplained: the preparation
    // failure says why the scan cannot run, and the cleanup failure says which
    // directory was left behind.
    #[test]
    fn reports_the_preparation_and_cleanup_failures_together() {
        let harness = Harness::new(&[]);
        let mut runner = FakeCodex::new();
        runner.fail = true;
        // Sealed as bootstrap fails, so both removals are refused.
        runner.seal_on_failure = Some(harness.temporary.path().to_path_buf());

        let error = harness.prepare(&runner).expect_err("preparation fails");
        unseal(harness.temporary.path());

        assert_eq!(error.class_name(), "AggregateError");
        assert_eq!(
            error.to_string(),
            "Codex Security runtime preparation failed and its isolated runtime \
             could not be cleaned up."
        );
        let messages: Vec<String> = error.errors().iter().map(ToString::to_string).collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("SYNTHETIC_BOOTSTRAP_FAILED")),
            "the preparation failure must survive: {messages:?}"
        );
        assert_eq!(
            messages.len(),
            3,
            "both directories are attempted, so both cleanup failures are kept: {messages:?}"
        );
    }

    #[test]
    fn reports_a_missing_plugin_without_leaving_directories_behind() {
        let mut harness = Harness::new(&[]);
        harness.config.plugin_path = Some(harness.temporary.path().join("missing-plugin"));

        let error = harness.prepare(&FakeCodex::new()).expect_err("no plugin");

        assert!(
            error.to_string().contains("Plugin path"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn stops_before_bootstrapping_when_already_cancelled() {
        let harness = Harness::new(&[]);
        harness.cancellation.cancel();
        let runner = FakeCodex::new();

        let error = harness.prepare(&runner).expect_err("cancelled");

        assert!(error.to_string().contains("interrupted"));
        assert!(
            runner.installed.borrow().is_empty(),
            "Codex must not be invoked once the scan is cancelled"
        );
    }

    // A cost limit stop must report itself, not a generic interruption.
    #[test]
    fn reports_the_recorded_cancellation_reason() {
        let harness = Harness::new(&[]);
        harness
            .cancellation
            .cancel_with(Error::codex_security("stopped for a reason"));

        let error = harness.prepare(&FakeCodex::new()).expect_err("cancelled");

        assert_eq!(error.to_string(), "stopped for a reason");
    }

    // Cleanup attempts every directory, so one failure cannot strand the other.
    #[test]
    fn cleans_up_every_directory_it_owns() {
        let harness = Harness::new(&[]);
        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");
        let workspace = runtime.bootstrap_workspace.clone().expect("a workspace");

        runtime.cleanup().expect("cleans up");

        assert!(!runtime.codex_home.exists());
        assert!(!workspace.exists());
    }

    // Upstream rejects with the first cleanup failure; the caller branches on
    // it, so it must keep its own message rather than becoming an aggregate.
    #[test]
    fn reports_the_first_cleanup_failure_and_keeps_the_rest() {
        let harness = Harness::new(&[]);
        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");
        seal(harness.temporary.path());

        let error = runtime.cleanup().expect_err("cleanup is refused");
        unseal(harness.temporary.path());

        assert_eq!(error.class_name(), "PluginBootstrapError");
        assert!(
            error
                .to_string()
                .contains(&runtime.codex_home.display().to_string()),
            "the credential home is reported first: {error}"
        );
        assert_eq!(
            error.errors().len(),
            1,
            "the workspace failure stays reachable"
        );
    }

    #[test]
    fn ignores_a_runtime_that_was_already_cleaned_up() {
        let harness = Harness::new(&[]);
        let runtime = harness.prepare(&FakeCodex::new()).expect("prepares");

        runtime.cleanup().expect("cleans up");

        runtime
            .cleanup()
            .expect("a second cleanup is not a failure");
    }
}
