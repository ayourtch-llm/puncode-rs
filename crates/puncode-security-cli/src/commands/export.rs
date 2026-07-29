//! Exporting a finished scan in another format.
//!
//! Ported from `runExport` in `src/cli.ts`.
//!
//! The export is produced by the plugin, but where it may be written is decided
//! here. A scan directory is a sealed contract — its artifacts are hashed and
//! checked against each other — so an export that landed on top of one would
//! quietly invalidate the scan it came from. Only the one export location
//! inside a scan is permitted; anything else must be outside it.

use std::path::{Path, PathBuf};

use puncode_security::runtime::{PluginPythonOptions, bundled_plugin_root, resolve_plugin_python};
use puncode_security::targets::ProcessEnvironment;

use crate::cli::{ExportArgs, ExportFormat};

/// What an export writes when it is kept inside its scan.
fn default_output(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Csv => "findings.csv",
        ExportFormat::Json => "findings.json",
        ExportFormat::Sarif => "results.sarif",
    }
}

fn format_name(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Csv => "csv",
        ExportFormat::Json => "json",
        ExportFormat::Sarif => "sarif",
    }
}

/// What the export did.
pub struct ExportOutcome {
    /// The export itself, when it was asked for on standard output.
    pub contents: Option<String>,
    /// A line for the person, when it was written to a file.
    pub note: Option<String>,
}

/// Exports a finished scan.
pub fn run(
    arguments: &ExportArgs,
    current_directory: &Path,
    environment: &ProcessEnvironment,
) -> Result<ExportOutcome, String> {
    let scan_dir =
        std::fs::canonicalize(&arguments.scan_dir).unwrap_or_else(|_| arguments.scan_dir.clone());
    let to_stdout = arguments.output.as_deref() == Some("-");

    let output_path = if to_stdout {
        None
    } else {
        Some(resolve_output(arguments, &scan_dir, current_directory)?)
    };

    let plugin_root = bundled_plugin_root().map_err(|error| error.to_string())?;
    let python = resolve_plugin_python(&PluginPythonOptions {
        configured_path: arguments.python.clone(),
        environment: environment.clone(),
        protected_root: current_directory.to_path_buf(),
        home_directory: None,
        managed_runtime_roots: None,
    })
    .map_err(|error| error.to_string())?;

    let mut command = std::process::Command::new(&python);
    command
        .arg("-I")
        .arg(plugin_root.join("scripts/finalize_scan_contract.py"))
        .arg("--scan-dir")
        .arg(&scan_dir)
        .arg("--export-format")
        .arg(format_name(arguments.export_format));
    if let Some(path) = &output_path {
        command.arg("--export-output").arg(path);
    }
    if let Some(source_root) = &arguments.source_root {
        command.arg("--source-root").arg(source_root);
    }

    let produced = command
        .env_clear()
        .envs(environment)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("Could not run the Codex Security exporter: {error}"))?;

    if !produced.status.success() {
        let detail = String::from_utf8_lossy(&produced.stderr).trim().to_owned();
        return Err(format!(
            "Could not export Codex Security findings as {}: {detail}",
            format_name(arguments.export_format).to_uppercase()
        ));
    }

    Ok(match &output_path {
        None => ExportOutcome {
            contents: Some(String::from_utf8_lossy(&produced.stdout).into_owned()),
            note: None,
        },
        Some(path) => ExportOutcome {
            contents: None,
            note: Some(format!(
                "{}: {}",
                format_name(arguments.export_format).to_uppercase(),
                path.display()
            )),
        },
    })
}

/// Where the export may be written.
fn resolve_output(
    arguments: &ExportArgs,
    scan_dir: &Path,
    current_directory: &Path,
) -> Result<PathBuf, String> {
    let requested = arguments.output.as_deref().map_or_else(
        || {
            scan_dir
                .join("exports")
                .join(default_output(arguments.export_format))
        },
        |output| absolute(current_directory, Path::new(output)),
    );

    // Inside the scan, only the one export location is allowed: a scan
    // directory is a sealed contract, and writing over an artifact would
    // invalidate the scan the export came from.
    if let Ok(inside) = requested.strip_prefix(scan_dir) {
        let permitted = Path::new("exports").join(default_output(arguments.export_format));
        if inside != permitted {
            return Err("The export output path cannot overwrite a scan artifact.".to_owned());
        }
        return Ok(requested);
    }

    // Outside it, the directory has to exist: the exporter writes a file, not
    // a tree, and a missing directory is a typo worth reporting plainly.
    let parent = requested
        .parent()
        .ok_or_else(|| "The export output path has no directory.".to_owned())?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|_| {
        format!(
            "Export output directory does not exist: {}. Create the directory and retry.",
            parent.display()
        )
    })?;

    // A path that reaches its destination through a link is refused: the
    // export would land somewhere the caller did not name.
    let resolved = canonical_parent.join(
        requested
            .file_name()
            .ok_or_else(|| "The export output path has no file name.".to_owned())?,
    );
    if resolved != requested && requested.starts_with(current_directory) {
        return Err("The export output path cannot traverse a repository symlink.".to_owned());
    }
    Ok(resolved)
}

/// `path` against `base`, unless it is already absolute.
fn absolute(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
