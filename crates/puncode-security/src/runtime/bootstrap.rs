//! Installing the plugin into an isolated Codex home.
//!
//! Ported from `bootstrapPlugin`, `verifyPluginRegistration` and
//! `findInstalledPlugin` in `src/runtime.ts`.
//!
//! Bootstrap asks Codex to register a marketplace and install the plugin from
//! it, then checks that it actually happened: the configuration Codex wrote is
//! re-read, the registered marketplace is confirmed to be the very directory
//! that was published, and the installed plugin's own manifest is compared with
//! the one that was selected. A scan that ran against a different plugin than
//! the caller chose would produce results attributed to the wrong thing.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::contract::files::same_object;
use crate::error::{Error, Result};
use crate::targets::ProcessEnvironment;

use super::isolated::CodexCommand;
use super::marketplace::create_marketplace;
use super::plugin::{MARKETPLACE_NAME, PLUGIN_NAME, plugin_metadata};

/// Where a plugin ended up, and what it turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInstall {
    pub plugin_root: PathBuf,
    pub marketplace_root: PathBuf,
    pub installed_root: PathBuf,
    pub marketplace_name: String,
    pub name: String,
    pub version: String,
}

/// How Codex is invoked.
///
/// Injectable for the same reason upstream takes a `runCodex` option: bootstrap
/// can then be exercised without a real Codex installation.
pub trait CodexRunner {
    /// Runs `codex` with `args`, returning its standard output.
    fn run(
        &self,
        command: &CodexCommand,
        args: &[&str],
        environment: &ProcessEnvironment,
    ) -> Result<String>;
}

/// Runs the real `codex` executable.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCodexRunner;

impl CodexRunner for ProcessCodexRunner {
    fn run(
        &self,
        command: &CodexCommand,
        args: &[&str],
        environment: &ProcessEnvironment,
    ) -> Result<String> {
        let output = Command::new(&command.command)
            .args(&command.prefix_args)
            .args(args)
            .env_clear()
            .envs(environment)
            .output()
            .map_err(|error| {
                Error::plugin_bootstrap(format!("Codex plugin bootstrap failed: {error}"))
                    .with_source(error)
            })?;

        if !output.status.success() {
            // Prefer whichever stream carries a message, as upstream does.
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            return Err(Error::plugin_bootstrap(format!(
                "Codex plugin bootstrap failed: {detail}"
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Publishes the plugin, installs it, and confirms the installation is the one
/// that was asked for.
pub fn bootstrap_plugin(
    codex_home: &Path,
    plugin_root: &Path,
    command: &CodexCommand,
    runner: &dyn CodexRunner,
    environment: &ProcessEnvironment,
) -> Result<PluginInstall> {
    let root = std::fs::canonicalize(plugin_root).map_err(|error| {
        Error::plugin_bootstrap(format!(
            "Invalid Codex plugin directory: {}",
            plugin_root.display()
        ))
        .with_source(error)
    })?;
    let selected = plugin_metadata(&root)?;
    let marketplace = create_marketplace(codex_home, &root)?;

    let mut environment = environment.clone();
    environment.insert(
        "CODEX_HOME".to_owned(),
        codex_home.to_string_lossy().into_owned(),
    );

    let marketplace_argument = marketplace.to_string_lossy().into_owned();
    runner.run(
        command,
        &["plugin", "marketplace", "add", &marketplace_argument],
        &environment,
    )?;
    let plugin_argument = format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}");
    runner.run(command, &["plugin", "add", &plugin_argument], &environment)?;

    verify_plugin_registration(codex_home, &marketplace)?;

    let installed_root = find_installed_plugin(codex_home)?;
    let installed = plugin_metadata(&installed_root)?;
    if installed.name != selected.name || installed.version != selected.version {
        return Err(Error::plugin_bootstrap(
            "Installed Codex Security plugin metadata does not match the selected plugin.",
        ));
    }

    Ok(PluginInstall {
        plugin_root: root,
        marketplace_root: marketplace,
        installed_root,
        marketplace_name: MARKETPLACE_NAME.to_owned(),
        name: selected.name,
        version: selected.version,
    })
}

/// Re-reads the configuration Codex wrote and confirms the registration is
/// what it should be.
pub(crate) fn verify_plugin_registration(codex_home: &Path, marketplace: &Path) -> Result<()> {
    let config_path = codex_home.join("config.toml");
    let config: toml::Value = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .ok_or_else(|| {
            Error::plugin_bootstrap("Codex plugin bootstrap produced an unreadable config.toml.")
        })?;

    let marketplace_config = config
        .get("marketplaces")
        .and_then(|value| value.get(MARKETPLACE_NAME))
        .filter(|value| value.is_table());
    let plugin_config = config
        .get("plugins")
        .and_then(|value| value.get(format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}")))
        .filter(|value| value.is_table());
    let (Some(marketplace_config), Some(plugin_config)) = (marketplace_config, plugin_config)
    else {
        return Err(Error::plugin_bootstrap(
            "Codex plugin bootstrap did not preserve plugin registration.",
        ));
    };

    // Compared by identity rather than by string: the registered path may be
    // spelled differently and still be the directory that was published.
    let registered = marketplace_config
        .get("source")
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    if !same_file(Path::new(registered), marketplace) {
        return Err(Error::plugin_bootstrap(
            "Codex plugin marketplace registration has the wrong source.",
        ));
    }
    if plugin_config.get("enabled").and_then(toml::Value::as_bool) != Some(true) {
        return Err(Error::plugin_bootstrap(
            "Codex Security plugin is not enabled after bootstrap.",
        ));
    }
    Ok(())
}

/// Whether two paths name the same directory.
fn same_file(left: &Path, right: &Path) -> bool {
    let (Ok(left), Ok(right)) = (
        std::fs::symlink_metadata(left),
        std::fs::symlink_metadata(right),
    ) else {
        return false;
    };
    same_object(&left, &right)
}

/// Finds the plugin Codex installed, refusing anything but exactly one.
pub(crate) fn find_installed_plugin(codex_home: &Path) -> Result<PathBuf> {
    let root = codex_home
        .join("plugins")
        .join("cache")
        .join(MARKETPLACE_NAME)
        .join(PLUGIN_NAME);

    let candidates: Vec<PathBuf> = std::fs::read_dir(&root)
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| path.join(".codex-plugin").join("plugin.json").is_file())
        .collect();

    // Zero means the install did not happen; more than one means the version
    // that would be run is ambiguous.
    if candidates.len() != 1 {
        return Err(Error::plugin_bootstrap(
            "Codex plugin install did not produce one installed Codex Security plugin.",
        ));
    }
    std::fs::canonicalize(&candidates[0]).map_err(|error| {
        Error::plugin_bootstrap(
            "Codex plugin install did not produce one installed Codex Security plugin.",
        )
        .with_source(error)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::TempDir;

    const MANIFEST: &str = r#"{"name":"codex-security","version":"0.1.14"}"#;

    fn plugin_tree(base: &Path) -> PathBuf {
        let root = base.join("plugin");
        std::fs::create_dir_all(root.join(".codex-plugin")).expect("create");
        std::fs::write(root.join(".codex-plugin").join("plugin.json"), MANIFEST).expect("write");
        root
    }

    /// Stands in for Codex: records the commands it was given and performs the
    /// side effects a successful install would have.
    struct FakeCodex {
        codex_home: PathBuf,
        calls: RefCell<Vec<Vec<String>>>,
        installed_manifest: String,
        installed_versions: Vec<String>,
        write_config: bool,
        enabled: bool,
        source_override: Option<PathBuf>,
    }

    impl FakeCodex {
        fn new(codex_home: &Path) -> Self {
            Self {
                codex_home: codex_home.to_path_buf(),
                calls: RefCell::new(Vec::new()),
                installed_manifest: MANIFEST.to_owned(),
                installed_versions: vec!["0.1.14".to_owned()],
                write_config: true,
                enabled: true,
                source_override: None,
            }
        }
    }

    impl CodexRunner for FakeCodex {
        fn run(
            &self,
            _command: &CodexCommand,
            args: &[&str],
            _environment: &ProcessEnvironment,
        ) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|value| (*value).to_owned()).collect());

            if args.first() == Some(&"plugin") && args.get(1) == Some(&"add") {
                for version in &self.installed_versions {
                    let installed = self
                        .codex_home
                        .join("plugins/cache")
                        .join(MARKETPLACE_NAME)
                        .join(PLUGIN_NAME)
                        .join(version)
                        .join(".codex-plugin");
                    std::fs::create_dir_all(&installed).expect("create installed plugin");
                    std::fs::write(installed.join("plugin.json"), &self.installed_manifest)
                        .expect("write installed manifest");
                }
                if self.write_config {
                    let source = self
                        .source_override
                        .clone()
                        .unwrap_or_else(|| self.codex_home.join("sdk-marketplace"));
                    let config = format!(
                        "[marketplaces.\"{MARKETPLACE_NAME}\"]\nsource = \"{}\"\n\n\
                         [plugins.\"{PLUGIN_NAME}@{MARKETPLACE_NAME}\"]\nenabled = {}\n",
                        source.display(),
                        self.enabled
                    );
                    std::fs::write(self.codex_home.join("config.toml"), config)
                        .expect("write config");
                }
            }
            Ok(String::new())
        }
    }

    fn command() -> CodexCommand {
        CodexCommand {
            command: PathBuf::from("/usr/bin/true"),
            prefix_args: Vec::new(),
        }
    }

    fn environment() -> ProcessEnvironment {
        ProcessEnvironment::new()
    }

    fn setup() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_tree(&base);
        let home = base.join("home");
        std::fs::create_dir(&home).expect("create home");
        (temp, plugin, home)
    }

    #[test]
    fn installs_and_verifies_the_selected_plugin() {
        let (_temp, plugin, home) = setup();
        let codex = FakeCodex::new(&home);

        let install = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect("bootstraps");

        assert_eq!(install.name, "codex-security");
        assert_eq!(install.version, "0.1.14");
        assert_eq!(install.marketplace_name, MARKETPLACE_NAME);
        assert_eq!(install.marketplace_root, home.join("sdk-marketplace"));
        assert!(
            install
                .installed_root
                .join(".codex-plugin/plugin.json")
                .is_file()
        );

        let calls = codex.calls.borrow();
        assert_eq!(calls[0][..3], ["plugin", "marketplace", "add"]);
        assert_eq!(
            calls[1],
            [
                "plugin",
                "add",
                &format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}")
            ]
        );
    }

    #[test]
    fn passes_the_isolated_home_to_codex() {
        let (_temp, plugin, home) = setup();
        struct CapturingCodex {
            inner: FakeCodex,
            homes: RefCell<Vec<String>>,
        }
        impl CodexRunner for CapturingCodex {
            fn run(
                &self,
                command: &CodexCommand,
                args: &[&str],
                environment: &ProcessEnvironment,
            ) -> Result<String> {
                self.homes
                    .borrow_mut()
                    .push(environment.get("CODEX_HOME").cloned().unwrap_or_default());
                self.inner.run(command, args, environment)
            }
        }
        let codex = CapturingCodex {
            inner: FakeCodex::new(&home),
            homes: RefCell::new(Vec::new()),
        };

        bootstrap_plugin(&home, &plugin, &command(), &codex, &environment()).expect("bootstraps");

        let homes = codex.homes.borrow();
        assert!(!homes.is_empty());
        assert!(
            homes.iter().all(|value| value == &home.to_string_lossy()),
            "every invocation runs against the isolated home: {homes:?}"
        );
    }

    // Codex claiming success is not enough; the configuration must show it.
    #[test]
    fn refuses_an_install_that_left_no_registration() {
        let (_temp, plugin, home) = setup();
        let mut codex = FakeCodex::new(&home);
        codex.write_config = false;

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("an unverified install is refused");

        assert_eq!(
            error.to_string(),
            "Codex plugin bootstrap produced an unreadable config.toml."
        );
    }

    #[test]
    fn refuses_a_disabled_plugin() {
        let (_temp, plugin, home) = setup();
        let mut codex = FakeCodex::new(&home);
        codex.enabled = false;

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("a disabled plugin is refused");

        assert_eq!(
            error.to_string(),
            "Codex Security plugin is not enabled after bootstrap."
        );
    }

    // A registration pointing somewhere else would run a different plugin.
    #[test]
    fn refuses_a_registration_pointing_elsewhere() {
        let (_temp, plugin, home) = setup();
        let elsewhere = home.parent().expect("parent").join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("create");
        let mut codex = FakeCodex::new(&home);
        codex.source_override = Some(elsewhere);

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("a foreign registration is refused");

        assert_eq!(
            error.to_string(),
            "Codex plugin marketplace registration has the wrong source."
        );
    }

    #[test]
    fn refuses_an_install_that_produced_no_plugin() {
        let (_temp, plugin, home) = setup();
        let mut codex = FakeCodex::new(&home);
        codex.installed_versions = Vec::new();

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("no installed plugin is refused");

        assert_eq!(
            error.to_string(),
            "Codex plugin install did not produce one installed Codex Security plugin."
        );
    }

    // Two installed versions leave it ambiguous which one a scan would run.
    #[test]
    fn refuses_an_ambiguous_install() {
        let (_temp, plugin, home) = setup();
        let mut codex = FakeCodex::new(&home);
        codex.installed_versions = vec!["0.1.14".to_owned(), "0.1.15".to_owned()];

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("an ambiguous install is refused");

        assert_eq!(
            error.to_string(),
            "Codex plugin install did not produce one installed Codex Security plugin."
        );
    }

    // The plugin that got installed must be the plugin that was selected.
    #[test]
    fn refuses_an_install_of_a_different_version() {
        let (_temp, plugin, home) = setup();
        let mut codex = FakeCodex::new(&home);
        codex.installed_manifest = r#"{"name":"codex-security","version":"9.9.9"}"#.to_owned();

        let error = bootstrap_plugin(&home, &plugin, &command(), &codex, &environment())
            .expect_err("a substituted plugin is refused");

        assert_eq!(
            error.to_string(),
            "Installed Codex Security plugin metadata does not match the selected plugin."
        );
    }

    #[test]
    fn reports_a_failing_codex_invocation() {
        let (_temp, plugin, home) = setup();
        struct FailingCodex;
        impl CodexRunner for FailingCodex {
            fn run(
                &self,
                _command: &CodexCommand,
                _args: &[&str],
                _environment: &ProcessEnvironment,
            ) -> Result<String> {
                Err(Error::plugin_bootstrap(
                    "Codex plugin bootstrap failed: boom",
                ))
            }
        }

        let error = bootstrap_plugin(&home, &plugin, &command(), &FailingCodex, &environment())
            .expect_err("a failing codex is reported");

        assert_eq!(error.to_string(), "Codex plugin bootstrap failed: boom");
    }
}
