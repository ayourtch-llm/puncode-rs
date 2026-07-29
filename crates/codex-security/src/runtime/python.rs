//! Finding a Python interpreter the plugin can actually run under.
//!
//! Ported from `resolvePluginPython` in `src/runtime.ts`.
//!
//! The plugin's scan scripts need Python 3.10 or later, and on 3.10 they also
//! need `tomli`. Rather than trust a version string, each candidate is probed
//! by running it: an interpreter that cannot import what the plugin needs is
//! not usable, whatever it claims. Candidates are resolved through the trusted
//! executable search, so a `python` sitting in the repository under scan is
//! never a candidate at all.

#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, expand_home};
use crate::trusted_executable::resolve_trusted_executable;

/// How long a candidate interpreter has to answer the probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Printed by the probe when the interpreter is usable.
const PROBE_MARKER: &str = "codex-security-python-ok";

/// Refuses anything below 3.10, and 3.10 without `tomli`.
const PROBE_SCRIPT: &str = "import importlib.util,sys\n\
if sys.version_info < (3, 10): raise SystemExit(1)\n\
if sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\n\
print('codex-security-python-ok')";

/// Where to look for an interpreter, and what the scan must not reach into.
#[derive(Debug, Clone)]
pub struct PluginPythonOptions {
    /// An interpreter named explicitly; if it is unusable, resolution fails
    /// rather than falling back.
    pub configured_path: Option<String>,
    pub environment: ProcessEnvironment,
    /// The repository under scan, which may not supply the interpreter.
    pub protected_root: PathBuf,
    pub home_directory: Option<PathBuf>,
    pub managed_runtime_roots: Option<Vec<PathBuf>>,
}

impl PluginPythonOptions {
    #[must_use]
    pub fn new(environment: ProcessEnvironment, protected_root: impl Into<PathBuf>) -> Self {
        Self {
            configured_path: None,
            environment,
            protected_root: protected_root.into(),
            home_directory: None,
            managed_runtime_roots: None,
        }
    }
}

/// Whether a candidate names a path rather than a command to find on `PATH`.
#[must_use]
pub fn is_python_path_candidate(candidate: &str) -> bool {
    candidate.contains('/') || candidate.contains('\\') || candidate.starts_with('.')
}

/// The environment the plugin's scripts run under.
#[must_use]
pub fn plugin_execution_environment(
    python: &Path,
    environment: &ProcessEnvironment,
) -> ProcessEnvironment {
    let mut environment = environment.clone();
    environment.insert("PYTHON".to_owned(), python.to_string_lossy().into_owned());
    environment
}

/// Finds a usable interpreter, in the order the caller's intent implies.
///
/// An explicitly configured interpreter, or one named by `PYTHON`, must work:
/// silently falling back to a different interpreter would run the scan under
/// something the caller did not choose.
pub fn resolve_plugin_python(options: &PluginPythonOptions) -> Result<PathBuf> {
    if let Some(configured) = &options.configured_path {
        return require_python(configured, "configured plugin Python", options);
    }
    if let Some(inherited) = options
        .environment
        .get("PYTHON")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return require_python(inherited, "PYTHON", options);
    }

    let managed_roots = options.managed_runtime_roots.clone().unwrap_or_else(|| {
        let home = options
            .home_directory
            .clone()
            .or_else(std::env::home_dir)
            .unwrap_or_default();
        vec![
            home.join(".cache")
                .join("codex-runtimes")
                .join("codex-primary-runtime"),
        ]
    });
    for root in &managed_roots {
        for relative in managed_relative_candidates() {
            let candidate = root.join(relative);
            if let Some(resolved) =
                usable_python(&candidate.to_string_lossy(), options, PROBE_TIMEOUT)
            {
                return Ok(resolved);
            }
        }
    }

    for candidate in path_candidates() {
        if let Some(resolved) = usable_python(candidate, options, PROBE_TIMEOUT) {
            return Ok(resolved);
        }
    }

    Err(Error::plugin_python_unavailable(
        "The bundled Codex Security plugin requires Python 3.10 or later (Python 3.10 also \
         requires tomli), but no usable interpreter was found. Set pythonPath, --python, or \
         PYTHON, install the Codex managed runtime, or add python3/python to PATH.",
    ))
}

#[cfg(windows)]
fn managed_relative_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("dependencies/python/python.exe"),
        PathBuf::from("dependencies/python/python/python.exe"),
        PathBuf::from("dependencies/python/bin/python.exe"),
    ]
}

#[cfg(not(windows))]
fn managed_relative_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("dependencies/python/bin/python3"),
        PathBuf::from("dependencies/python/bin/python"),
    ]
}

#[cfg(windows)]
fn path_candidates() -> [&'static str; 2] {
    ["python", "python3"]
}

#[cfg(not(windows))]
fn path_candidates() -> [&'static str; 2] {
    ["python3", "python"]
}

fn require_python(candidate: &str, source: &str, options: &PluginPythonOptions) -> Result<PathBuf> {
    usable_python(candidate, options, PROBE_TIMEOUT).ok_or_else(|| {
        Error::plugin_python_unavailable(format!(
            "The {source} interpreter is unavailable or unusable: {candidate}. The bundled \
             Codex Security plugin requires Python 3.10 or later for scan execution; Python \
             3.10 also requires tomli."
        ))
    })
}

/// Probes one candidate, returning the interpreter if it can run the plugin.
pub(crate) fn usable_python(
    candidate: &str,
    options: &PluginPythonOptions,
    timeout: Duration,
) -> Option<PathBuf> {
    let expanded;
    let candidate = if is_python_path_candidate(candidate) {
        expanded = expand_home(candidate, &options.environment);
        expanded.to_string_lossy().into_owned()
    } else {
        candidate.to_owned()
    };

    let command =
        resolve_trusted_executable(&candidate, &options.environment, &options.protected_root)?;

    let mut probe = Command::new(&command.executable);
    probe
        .arg("-I")
        .arg("-c")
        .arg(PROBE_SCRIPT)
        .env_clear()
        .envs(&command.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let output = run_with_timeout(probe, timeout)?;
    (output.trim() == PROBE_MARKER).then_some(command.executable)
}

/// Runs `command`, returning its stdout, or `None` if it fails or outstays
/// `timeout`.
fn run_with_timeout(mut command: Command, timeout: Duration) -> Option<String> {
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let child = Arc::new(Mutex::new(child));

    // Killing the child closes the pipe, which releases the read below. An
    // interpreter that hangs therefore costs the timeout, not the scan.
    let watchdog = Arc::clone(&child);
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        if let Ok(mut child) = watchdog.lock()
            && let Ok(None) = child.try_wait()
        {
            let _ = child.kill();
        }
    });

    let mut text = String::new();
    let read = stdout.read_to_string(&mut text);
    let status = child.lock().ok()?.wait().ok()?;
    if read.is_err() || !status.success() {
        return None;
    }
    Some(text)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Writes an executable shell script standing in for an interpreter.
    fn interpreter(dir: &Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("create directory");
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    /// A stand-in that answers the probe correctly.
    fn usable_body() -> String {
        format!("printf '{PROBE_MARKER}\\n'")
    }

    fn options(path_entries: &[&Path], protected_root: &Path) -> PluginPythonOptions {
        let joined = path_entries
            .iter()
            .map(|entry| entry.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":");
        let environment = ProcessEnvironment::from([("PATH".to_owned(), joined)]);
        PluginPythonOptions::new(environment, protected_root)
    }

    /// Resolves, retrying while a freshly written stub is still busy.
    ///
    /// See the note in `runtime::workbench`: an executable written and exec'd
    /// from the same process can transiently fail with `ETXTBSY`. Used only
    /// where resolution is expected to succeed.
    fn resolve_stub(options: &PluginPythonOptions) -> Result<PathBuf> {
        for _ in 0..100 {
            match resolve_plugin_python(options) {
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                outcome => return outcome,
            }
        }
        resolve_plugin_python(options)
    }

    #[test]
    fn recognizes_path_shaped_candidates() {
        assert!(is_python_path_candidate("/usr/bin/python3"));
        assert!(is_python_path_candidate("./python"));
        assert!(is_python_path_candidate("../python"));
        assert!(is_python_path_candidate(r"C:\python\python.exe"));
        assert!(!is_python_path_candidate("python3"));
        assert!(!is_python_path_candidate("python"));
    }

    #[test]
    fn resolves_an_interpreter_from_path() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        let python = interpreter(&bin, "python3", &usable_body());
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let resolved = resolve_stub(&options(&[&bin], &repository)).expect("resolves");

        assert_eq!(resolved, std::fs::canonicalize(&python).expect("canonical"));
    }

    // The probe is what decides usability, and the fallback is by interpreter
    // name: a failing `python3` leads to trying `python`, not to a different
    // `python3` further along PATH.
    #[test]
    fn falls_back_by_interpreter_name_when_the_probe_fails() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", "exit 1");
        let usable = interpreter(&bin, "python", &usable_body());
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let resolved = resolve_stub(&options(&[&bin], &repository)).expect("resolves");

        assert_eq!(resolved, std::fs::canonicalize(&usable).expect("canonical"));
    }

    // Only the first match for a given name is ever probed, so a working
    // interpreter further along PATH does not rescue a broken earlier one.
    #[test]
    fn does_not_search_past_the_first_match_for_a_name() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let first = base.join("first");
        interpreter(&first, "python3", "exit 1");
        let second = base.join("second");
        interpreter(&second, "python3", &usable_body());
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let error = resolve_plugin_python(&options(&[&first, &second], &repository))
            .expect_err("a later entry with the same name is not consulted");

        assert!(
            error
                .to_string()
                .contains("no usable interpreter was found"),
            "{error}"
        );
    }

    #[test]
    fn skips_an_interpreter_that_answers_with_something_else() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", "printf 'some other output\\n'");
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let error = resolve_plugin_python(&options(&[&bin], &repository))
            .expect_err("an unrecognized answer is not usable");

        assert!(
            error.to_string().contains("requires Python 3.10 or later"),
            "{error}"
        );
        assert!(
            error.is_plugin_bootstrap(),
            "python errors are bootstrap errors"
        );
    }

    #[test]
    fn prefers_python3_over_python() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        let three = interpreter(&bin, "python3", &usable_body());
        interpreter(&bin, "python", &usable_body());
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let resolved = resolve_stub(&options(&[&bin], &repository)).expect("resolves");

        assert_eq!(resolved, std::fs::canonicalize(&three).expect("canonical"));
    }

    // An explicitly chosen interpreter must not silently fall back to another:
    // the scan would run under something the caller did not pick.
    #[test]
    fn does_not_fall_back_from_a_configured_interpreter() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", &usable_body());
        let broken = interpreter(&base.join("custom"), "python3", "exit 1");
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let mut options = options(&[&bin], &repository);
        options.configured_path = Some(broken.to_string_lossy().into_owned());

        let error = resolve_plugin_python(&options).expect_err("no fallback is allowed");

        assert!(
            error
                .to_string()
                .starts_with("The configured plugin Python interpreter is unavailable"),
            "{error}"
        );
    }

    #[test]
    fn does_not_fall_back_from_the_python_environment_variable() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", &usable_body());
        let broken = interpreter(&base.join("custom"), "python3", "exit 1");
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let mut options = options(&[&bin], &repository);
        options
            .environment
            .insert("PYTHON".to_owned(), broken.to_string_lossy().into_owned());

        let error = resolve_plugin_python(&options).expect_err("no fallback is allowed");

        assert!(
            error
                .to_string()
                .starts_with("The PYTHON interpreter is unavailable"),
            "{error}"
        );
    }

    #[test]
    fn ignores_a_blank_python_environment_variable() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        let python = interpreter(&bin, "python3", &usable_body());
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let mut options = options(&[&bin], &repository);
        options
            .environment
            .insert("PYTHON".to_owned(), "   ".to_owned());

        let resolved = resolve_stub(&options).expect("falls through to PATH");

        assert_eq!(resolved, std::fs::canonicalize(&python).expect("canonical"));
    }

    #[test]
    fn prefers_a_managed_runtime_over_path() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", &usable_body());
        let managed = base.join("managed");
        let managed_python = interpreter(
            &managed.join("dependencies").join("python").join("bin"),
            "python3",
            &usable_body(),
        );
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let mut options = options(&[&bin], &repository);
        options.managed_runtime_roots = Some(vec![managed]);

        let resolved = resolve_stub(&options).expect("resolves");

        assert_eq!(
            resolved,
            std::fs::canonicalize(&managed_python).expect("canonical")
        );
    }

    // The repository under scan must never supply the interpreter.
    #[test]
    fn refuses_an_interpreter_inside_the_protected_root() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let repository = base.join("repository");
        let hostile = repository.join("bin");
        interpreter(&hostile, "python3", &usable_body());

        let error = resolve_plugin_python(&options(&[&hostile], &repository))
            .expect_err("a repository interpreter is refused");

        assert!(
            error
                .to_string()
                .contains("no usable interpreter was found"),
            "{error}"
        );
    }

    // A hanging interpreter costs the timeout, not the scan.
    #[test]
    fn gives_up_on_an_interpreter_that_hangs() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        interpreter(&bin, "python3", "sleep 30");
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");

        let started = std::time::Instant::now();
        let resolved = usable_python(
            "python3",
            &options(&[&bin], &repository),
            Duration::from_millis(250),
        );

        assert_eq!(resolved, None);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the probe should not wait for the interpreter"
        );
    }

    #[test]
    fn sets_python_in_the_execution_environment() {
        let environment = ProcessEnvironment::from([("KEEP".to_owned(), "ok".to_owned())]);

        let prepared = plugin_execution_environment(Path::new("/usr/bin/python3"), &environment);

        assert_eq!(prepared["PYTHON"], "/usr/bin/python3");
        assert_eq!(prepared["KEEP"], "ok");
    }
}
