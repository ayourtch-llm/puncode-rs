//! Running the plugin's workbench scripts.
//!
//! Ported from `runWorkbench`, `codexSecurityStateDirectory` and
//! `preparePersistentScanRoot` in `src/runtime.ts`.
//!
//! The workbench is a Python program shipped with the plugin that owns the scan
//! database. It is invoked with `-I -B` so it cannot pick up site packages or
//! write bytecode next to the plugin, and its environment has the API keys
//! removed: the workbench manages local state and never needs to talk to the
//! API, so handing it credentials would widen their exposure for no reason.

#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, expand_home, lexical_absolute};

use super::output::safe_prefix;

/// How much output the workbench may produce.
const MAX_WORKBENCH_OUTPUT: usize = 4 * 1024 * 1024;

/// Environment variables the workbench is never given.
const WITHHELD_VARIABLES: [&str; 2] = ["OPENAI_API_KEY", "CODEX_API_KEY"];

/// What the workbench needs in order to run.
#[derive(Debug, Clone)]
pub struct WorkbenchCommandOptions<'a> {
    pub python: &'a Path,
    pub plugin_root: &'a Path,
    pub environment: &'a ProcessEnvironment,
    /// Prefixes the error when the workbench cannot be run.
    pub failure_message: Option<&'a str>,
}

/// Where Codex Security keeps state that outlives a single scan.
#[must_use]
pub fn puncode_security_state_directory(environment: &ProcessEnvironment) -> PathBuf {
    if let Some(configured) = environment_value(environment, "CODEX_SECURITY_STATE_DIR") {
        return lexical_absolute(&expand_home(&configured, environment));
    }
    let codex_home = environment_value(environment, "CODEX_HOME").unwrap_or_else(|| {
        std::env::home_dir()
            .unwrap_or_default()
            .join(".codex")
            .to_string_lossy()
            .into_owned()
    });
    lexical_absolute(&expand_home(&codex_home, environment))
        .join("state")
        .join("plugins")
        .join("codex-security")
}

/// Reads a variable, preferring an exact match but tolerating differing case.
fn environment_value(environment: &ProcessEnvironment, requested: &str) -> Option<String> {
    if let Some(exact) = environment
        .get(requested)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return Some(exact.to_owned());
    }
    environment
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case(requested) && !value.trim().is_empty())
        .map(|(_, value)| value.trim().to_owned())
}

/// Creates the directory a repository's scans accumulate in.
pub fn prepare_persistent_scan_root(
    state_directory: &Path,
    repository_name: &str,
) -> Result<PathBuf> {
    let root = state_directory
        .join("scans")
        .join(safe_prefix(repository_name));

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&root).map_err(|error| {
        Error::puncode_security(format!(
            "Could not prepare the scan history directory: {}",
            root.display()
        ))
        .with_source(error)
    })?;

    std::fs::canonicalize(&root).map_err(|error| {
        Error::puncode_security(format!(
            "Could not prepare the scan history directory: {}",
            root.display()
        ))
        .with_source(error)
    })
}

/// Runs the workbench and returns the JSON object it printed.
pub fn run_workbench(
    options: &WorkbenchCommandOptions<'_>,
    args: &[&str],
) -> Result<Map<String, Value>> {
    let failed = |detail: &str| {
        Error::puncode_security(format!(
            "{}: {detail}",
            options
                .failure_message
                .unwrap_or("Could not run the Codex Security workbench")
        ))
    };

    let script = options.plugin_root.join("scripts").join("workbench_db.py");
    let environment: ProcessEnvironment = options
        .environment
        .iter()
        .filter(|(name, _)| {
            !WITHHELD_VARIABLES
                .iter()
                .any(|withheld| name.eq_ignore_ascii_case(withheld))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    // `-I` isolates the interpreter from site packages and the environment;
    // `-B` stops it writing bytecode beside the plugin.
    let mut child = Command::new(options.python)
        .arg("-I")
        .arg("-B")
        .arg(&script)
        .args(args)
        .env_clear()
        .envs(&environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| failed(&error.to_string()))?;

    let mut stdout = child.stdout.take().ok_or_else(|| failed("no output"))?;
    let mut text = Vec::new();
    // One byte over the limit is enough to know it was exceeded.
    stdout
        .by_ref()
        .take(MAX_WORKBENCH_OUTPUT as u64 + 1)
        .read_to_end(&mut text)
        .map_err(|error| failed(&error.to_string()))?;
    let mut stderr_text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_text);
    }
    let status = child.wait().map_err(|error| failed(&error.to_string()))?;

    if text.len() > MAX_WORKBENCH_OUTPUT {
        return Err(failed("stdout maxBuffer length exceeded"));
    }
    if !status.success() {
        let detail = if stderr_text.trim().is_empty() {
            String::from_utf8_lossy(&text).trim().to_owned()
        } else {
            stderr_text.trim().to_owned()
        };
        return Err(failed(&detail));
    }

    let value: Value = serde_json::from_slice(&text).map_err(|error| {
        Error::puncode_security("The Codex Security workbench returned invalid JSON.")
            .with_source(error)
    })?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Error::puncode_security(
            "The Codex Security workbench returned an invalid response.",
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// A stand-in for Python that runs the "script" it is handed.
    fn fake_python(base: &Path, body: &str) -> PathBuf {
        let path = base.join("python3");
        // Ignores the -I/-B flags and the script path, then behaves as told.
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn plugin_root(base: &Path) -> PathBuf {
        let root = base.join("plugin");
        std::fs::create_dir_all(root.join("scripts")).expect("create");
        std::fs::write(
            root.join("scripts").join("workbench_db.py"),
            b"# workbench\n",
        )
        .expect("write");
        root
    }

    /// Runs the workbench, retrying only while the freshly written stub is
    /// still busy.
    ///
    /// Writing an executable and exec'ing it from the same process races on
    /// Linux: a concurrently forking thread inherits the still-open write
    /// descriptor, and the exec fails with `ETXTBSY` until that child reaches
    /// its own exec. Only stubs built in-process are affected.
    fn run_stub(
        options: &WorkbenchCommandOptions<'_>,
        args: &[&str],
    ) -> Result<Map<String, Value>> {
        for _ in 0..100 {
            match run_workbench(options, args) {
                Err(error) if error.to_string().contains("Text file busy") => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                outcome => return outcome,
            }
        }
        run_workbench(options, args)
    }

    fn options<'a>(
        python: &'a Path,
        plugin: &'a Path,
        environment: &'a ProcessEnvironment,
    ) -> WorkbenchCommandOptions<'a> {
        WorkbenchCommandOptions {
            python,
            plugin_root: plugin,
            environment,
            failure_message: None,
        }
    }

    #[test]
    fn returns_the_object_the_workbench_printed() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, r#"printf '{"scans":[],"ok":true}'"#);
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let result =
            run_stub(&options(&python, &plugin, &environment), &["list-scans"]).expect("runs");

        assert_eq!(result["ok"], Value::Bool(true));
        assert!(result["scans"].is_array());
    }

    #[test]
    fn passes_arguments_through() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        // Echo the arguments after the script path as a JSON array.
        let python = fake_python(&base, r#"shift 3; printf '{"args":["%s","%s"]}' "$1" "$2""#);
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let result = run_stub(
            &options(&python, &plugin, &environment),
            &["complete-scan", "--scan-id"],
        )
        .expect("runs");

        assert_eq!(result["args"][0], Value::from("complete-scan"));
        assert_eq!(result["args"][1], Value::from("--scan-id"));
    }

    // The workbench manages local state and never calls the API, so it is not
    // given credentials.
    #[test]
    fn withholds_api_credentials_from_the_workbench() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(
            &base,
            r#"printf '{"openai":"%s","codex":"%s","keep":"%s"}' "$OPENAI_API_KEY" "$CODEX_API_KEY" "$KEEP""#,
        );
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::from([
            ("OPENAI_API_KEY".to_owned(), "sk-secret".to_owned()),
            ("CODEX_API_KEY".to_owned(), "codex-secret".to_owned()),
            ("KEEP".to_owned(), "kept".to_owned()),
        ]);

        let result = run_stub(&options(&python, &plugin, &environment), &[]).expect("runs");

        assert_eq!(
            result["openai"],
            Value::from(""),
            "the API key must not be passed"
        );
        assert_eq!(
            result["codex"],
            Value::from(""),
            "the API key must not be passed"
        );
        assert_eq!(
            result["keep"],
            Value::from("kept"),
            "other variables pass through"
        );
    }

    #[test]
    fn withholds_credentials_regardless_of_case() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, r#"printf '{"lower":"%s"}' "$openai_api_key""#);
        let plugin = plugin_root(&base);
        let environment =
            ProcessEnvironment::from([("openai_api_key".to_owned(), "sk-secret".to_owned())]);

        let result = run_stub(&options(&python, &plugin, &environment), &[]).expect("runs");

        assert_eq!(result["lower"], Value::from(""));
    }

    #[test]
    fn reports_invalid_json() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, "printf 'not json'");
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let error = run_stub(&options(&python, &plugin, &environment), &[]).expect_err("invalid");

        assert_eq!(
            error.to_string(),
            "The Codex Security workbench returned invalid JSON."
        );
    }

    #[test]
    fn reports_a_response_that_is_not_an_object() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, "printf '[1,2,3]'");
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let error = run_stub(&options(&python, &plugin, &environment), &[]).expect_err("invalid");

        assert_eq!(
            error.to_string(),
            "The Codex Security workbench returned an invalid response."
        );
    }

    #[test]
    fn reports_a_failing_workbench_with_its_stderr() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, "printf 'database is locked' >&2\nexit 1");
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let error = run_stub(&options(&python, &plugin, &environment), &[]).expect_err("fails");

        assert_eq!(
            error.to_string(),
            "Could not run the Codex Security workbench: database is locked"
        );
    }

    #[test]
    fn uses_the_callers_failure_message() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(&base, "printf 'boom' >&2\nexit 2");
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();
        let mut options = options(&python, &plugin, &environment);
        options.failure_message = Some("Could not save the Puncode Security scan");

        let error = run_stub(&options, &[]).expect_err("fails");

        assert_eq!(
            error.to_string(),
            "Could not save the Puncode Security scan: boom"
        );
    }

    #[test]
    fn refuses_output_beyond_the_limit() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let python = fake_python(
            &base,
            &format!("yes x | head -c {} ", MAX_WORKBENCH_OUTPUT + 1_024),
        );
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let error = run_stub(&options(&python, &plugin, &environment), &[]).expect_err("too large");

        assert!(
            error.to_string().contains("maxBuffer length exceeded"),
            "{error}"
        );
    }

    #[test]
    fn reports_a_missing_interpreter() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        let plugin = plugin_root(&base);
        let environment = ProcessEnvironment::new();

        let error = run_stub(
            &options(&base.join("absent-python"), &plugin, &environment),
            &[],
        )
        .expect_err("missing interpreter");

        assert!(
            error
                .to_string()
                .starts_with("Could not run the Codex Security workbench:"),
            "{error}"
        );
    }

    // --- state directory ---

    #[test]
    fn prefers_an_explicitly_configured_state_directory() {
        let environment = ProcessEnvironment::from([
            (
                "CODEX_SECURITY_STATE_DIR".to_owned(),
                "/var/state".to_owned(),
            ),
            ("CODEX_HOME".to_owned(), "/home/user/.codex".to_owned()),
        ]);

        assert_eq!(
            puncode_security_state_directory(&environment),
            PathBuf::from("/var/state")
        );
    }

    #[test]
    fn derives_the_state_directory_from_the_codex_home() {
        let environment =
            ProcessEnvironment::from([("CODEX_HOME".to_owned(), "/home/user/.codex".to_owned())]);

        assert_eq!(
            puncode_security_state_directory(&environment),
            PathBuf::from("/home/user/.codex/state/plugins/codex-security")
        );
    }

    #[test]
    fn ignores_blank_state_variables() {
        let environment = ProcessEnvironment::from([
            ("CODEX_SECURITY_STATE_DIR".to_owned(), "   ".to_owned()),
            ("CODEX_HOME".to_owned(), "/home/user/.codex".to_owned()),
        ]);

        assert_eq!(
            puncode_security_state_directory(&environment),
            PathBuf::from("/home/user/.codex/state/plugins/codex-security")
        );
    }

    #[test]
    fn expands_a_home_relative_state_directory() {
        let environment = ProcessEnvironment::from([
            ("HOME".to_owned(), "/home/user".to_owned()),
            ("CODEX_SECURITY_STATE_DIR".to_owned(), "~/state".to_owned()),
        ]);

        assert_eq!(
            puncode_security_state_directory(&environment),
            PathBuf::from("/home/user/state")
        );
    }

    #[test]
    fn creates_a_private_persistent_scan_root() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");

        let root = prepare_persistent_scan_root(&base, "/src/example/repo").expect("prepared");

        assert_eq!(root, base.join("scans").join("repo"));
        let mode = std::fs::metadata(&root).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn reuses_an_existing_persistent_scan_root() {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");

        let first = prepare_persistent_scan_root(&base, "repo").expect("prepared");
        std::fs::write(first.join("scan.db"), b"state\n").expect("write");
        let second = prepare_persistent_scan_root(&base, "repo").expect("prepared again");

        assert_eq!(first, second);
        assert!(second.join("scan.db").is_file(), "existing state is kept");
    }
}
