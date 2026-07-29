//! Installing a Git hook that scans before a commit.
//!
//! Ported from the `install-hook` command in `src/cli.ts`.
//!
//! The hook is written only when there is nothing there, or when what is there
//! is a hook this command wrote. Overwriting someone's own pre-commit hook
//! would silently remove whatever checks it was doing.

use std::path::{Path, PathBuf};

use puncode_security::targets::ProcessEnvironment;
use serde_json::json;

use crate::cli::{Format, InstallHookArgs};

/// Writes the hook, or explains why it will not.
pub fn run(
    arguments: &InstallHookArgs,
    current_directory: &Path,
    environment: &ProcessEnvironment,
) -> Result<String, String> {
    let repository = arguments
        .repository
        .clone()
        .unwrap_or_else(|| current_directory.to_path_buf());
    let severity = format!("{:?}", arguments.fail_on_severity).to_lowercase();

    // Git is asked where the hook belongs, rather than assuming `.git/hooks`:
    // a worktree or a configured `core.hooksPath` puts it somewhere else.
    let hook = hook_path(&repository, environment)?;
    let contents = hook_contents(&severity)?;

    match std::fs::read_to_string(&hook) {
        Ok(existing) if existing == contents => {}
        Ok(_) => {
            return Err(format!(
                "A pre-commit hook already exists at {}.",
                hook.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = hook.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("Unable to create {}: {error}", parent.display()))?;
            }
            write_hook(&hook, &contents)?;
        }
        Err(error) => {
            return Err(format!("Unable to read {}: {error}", hook.display()));
        }
    }

    let report = json!({
        "hook": hook.to_string_lossy(),
        "failOnSeverity": severity,
    });
    Ok(match arguments.output.resolved() {
        Format::Text => format!(
            "Installed a pre-commit scan at {}\n  blocking findings at or above {severity}",
            hook.display()
        ),
        Format::Json => serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?,
        Format::Jsonl => serde_json::to_string(&report).map_err(|error| error.to_string())?,
    })
}

/// Where Git wants this repository's pre-commit hook.
fn hook_path(repository: &Path, environment: &ProcessEnvironment) -> Result<PathBuf, String> {
    let output = std::process::Command::new("git")
        .args([
            "-C",
            &repository.to_string_lossy(),
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "hooks/pre-commit",
        ])
        .env_clear()
        .envs(environment)
        .output()
        .map_err(|error| format!("Could not run git: {error}"))?;

    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!("Not a Git repository: {detail}"));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

/// The hook this command installs.
///
/// The absolute path of this executable is used, not a bare name: a hook runs
/// with whatever `PATH` Git gives it, and a hook that silently stops finding
/// the scanner is worse than one that was never installed.
fn hook_contents(severity: &str) -> Result<String, String> {
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("Unable to locate this executable: {error}"))?;
    Ok(format!(
        "#!/bin/sh\nset -eu\nexec {} scan . --working-tree --fail-on-severity {severity}\n",
        shell_quote(&executable.to_string_lossy())
    ))
}

/// Quotes a path for a POSIX shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

/// Writes the hook, executable and refusing to clobber.
fn write_hook(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Unable to write {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("Unable to write {}: {error}", path.display()))
}
