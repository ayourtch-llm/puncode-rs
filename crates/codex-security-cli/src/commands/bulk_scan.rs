//! Scanning many repositories from one inventory.
//!
//! Ported from the `bulk-scan` command in `src/cli.ts`.
//!
//! The campaign itself lives in the library; this reads the inventory, wires a
//! scanner to it, and reports what happened. A campaign is resumable, so the
//! same command run twice picks up where the first left off rather than paying
//! to scan everything again.

use std::path::{Path, PathBuf};

use codex_security::api::{CodexSecurity, IgnoreScanEvents, ScanCancellation, ScanOptions};
use codex_security::config::CodexSecurityConfig;
use codex_security::models::Completeness;
use codex_security::multiscan::{
    Campaign, MultiscanObserver, MultiscanOptions, MultiscanProgress, MultiscanTask,
    ProcessGitRunner, ProgressStatus, ScanOutcome, ScanRunner, acquire_lock,
    ensure_output_directory, parse_inventory, run_campaign,
};
use codex_security::targets::{ProcessEnvironment, ScanMode};
use serde_json::json;

use crate::cli::{BulkScanArgs, Format, Mode};

/// Runs a campaign over the repositories an inventory names.
pub fn run(
    arguments: &BulkScanArgs,
    current_directory: &Path,
    environment: &ProcessEnvironment,
) -> Result<String, String> {
    // With no inventory, the wizard finds repositories and writes one.
    let discovered = match &arguments.input {
        Some(_) => None,
        None => match discover(arguments, current_directory, environment)? {
            Some(result) => Some(result),
            // Abandoned, or nothing matched: nothing was written, so there is
            // nothing to scan and nothing to clean up.
            None => return Ok("Nothing to scan.".to_owned()),
        },
    };

    let (input, output_dir) = match (&discovered, &arguments.input, &arguments.output_dir) {
        (Some(result), _, _) => (result.input_path.clone(), result.output_dir.clone()),
        (None, Some(input), Some(output_dir)) => (
            absolute(current_directory, input),
            absolute(current_directory, output_dir),
        ),
        (None, Some(_), None) => {
            return Err("--output-dir is required when scanning from a CSV.".to_owned());
        }
        (None, None, _) => unreachable!("the wizard supplies both paths"),
    };
    let source = std::fs::read_to_string(&input)
        .map_err(|error| format!("Could not read {}: {error}", input.display()))?;
    // Relative repositories are resolved against the inventory, not the
    // working directory: the file is what names them.
    let inventory_directory = input.parent().unwrap_or(current_directory);
    let tasks = parse_inventory(
        &source,
        inventory_directory,
        match arguments.mode {
            Mode::Standard => ScanMode::Standard,
            Mode::Deep => ScanMode::Deep,
        },
    )
    .map_err(|error| error.to_string())?;

    ensure_output_directory(&output_dir).map_err(|error| error.to_string())?;
    // Claimed for the whole campaign: two supervisors writing one ledger would
    // corrupt it.
    let _lock = acquire_lock(&output_dir).map_err(|error| error.to_string())?;

    let scanner = CampaignScanner {
        config: config(arguments)?,
    };
    let observer = ReportProgress {
        quiet: arguments.output.resolved() != Format::Text,
    };
    let result = run_campaign(
        &tasks,
        &output_dir,
        &Campaign {
            options: &MultiscanOptions {
                workers: arguments.workers,
                max_attempts: arguments.max_attempts,
                github_host: None,
            },
            environment,
            git: &ProcessGitRunner::new(current_directory),
            scanner: &scanner,
            observer: &observer,
        },
    )
    .map_err(|error| error.to_string())?;

    let report = json!({
        "total": result.total,
        "completed": result.completed,
        "failed": result.failed,
        "skipped": result.skipped,
        "resultsPath": result.results_path.to_string_lossy(),
    });
    Ok(match arguments.output.resolved() {
        Format::Text => format!(
            "Scanned {} of {} repositories ({} failed, {} already done)\n  results: {}",
            result.completed - result.skipped,
            result.total,
            result.failed,
            result.skipped,
            result.results_path.display()
        ),
        Format::Json => serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?,
        Format::Jsonl => serde_json::to_string(&report).map_err(|error| error.to_string())?,
    })
}

/// Finds repositories to scan and writes an inventory naming them.
fn discover(
    arguments: &BulkScanArgs,
    current_directory: &Path,
    environment: &ProcessEnvironment,
) -> Result<Option<crate::commands::wizard::WizardResult>, String> {
    // `GH_HOST` is how someone points the CLI at an enterprise instance, and
    // it is the same variable `gh` itself reads.
    let host = environment
        .get("GH_HOST")
        .map(|host| host.trim())
        .filter(|host| !host.is_empty())
        .unwrap_or("github.com")
        .to_owned();

    let transport = crate::commands::github::HttpTransport::new(&host, environment)?;
    let source = crate::commands::github::GitHubSource::new(transport);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });

    let _ = arguments;
    crate::commands::wizard::run(
        &source,
        &crate::commands::wizard::TerminalPrompt,
        &host,
        current_directory,
        now,
    )
}

/// The configuration every repository in the campaign is scanned under.
fn config(arguments: &BulkScanArgs) -> Result<CodexSecurityConfig, String> {
    let overrides =
        crate::overrides::parse_codex_overrides(&arguments.codex, arguments.model.as_deref())?;
    Ok(CodexSecurityConfig {
        plugin_path: arguments.plugin_path.clone(),
        python_path: arguments.python.as_ref().map(PathBuf::from),
        codex_overrides: (!overrides.is_empty()).then_some(overrides),
    })
}

/// Scans one checked-out repository.
struct CampaignScanner {
    config: CodexSecurityConfig,
}

impl ScanRunner for CampaignScanner {
    fn run(
        &self,
        checkout: &Path,
        task: &MultiscanTask,
        scan_dir: &Path,
    ) -> codex_security::Result<ScanOutcome> {
        // A client per repository: each gets its own isolated runtime, so one
        // repository's scan cannot disturb another's.
        let client = CodexSecurity::new(self.config.clone());
        let mut options = ScanOptions::new()
            .with_mode(task.mode)
            .with_output_dir(scan_dir.to_string_lossy().into_owned());
        if let Some(scope) = &task.scope {
            options = options.with_target(codex_security::targets::ScanTarget::Paths(vec![
                scope.clone(),
            ]));
        }

        let outcome = client.run(
            &checkout.to_string_lossy(),
            &options,
            &mut IgnoreScanEvents,
            &ScanCancellation::new(),
        );
        let closed = client.close();
        let result = outcome?;
        closed?;

        Ok(ScanOutcome {
            cost: result.cost.clone(),
            coverage_complete: result.coverage.completeness == Completeness::Complete,
        })
    }
}

/// Reports each repository as the campaign reaches it.
struct ReportProgress {
    /// A structured run has no room for commentary.
    quiet: bool,
}

impl MultiscanObserver for ReportProgress {
    fn on_progress(&self, progress: &MultiscanProgress) {
        if self.quiet {
            return;
        }
        let line = match progress.status {
            ProgressStatus::Started => {
                format!("{} (attempt {})", progress.repository, progress.attempt)
            }
            ProgressStatus::Completed => format!("{} completed", progress.repository),
            ProgressStatus::Failed => format!(
                "{} failed: {}",
                progress.repository,
                progress.error.as_deref().unwrap_or("unknown error")
            ),
        };
        eprintln!("codex-security: {line}");
    }
}

/// `path` against `base`, unless it is already absolute.
fn absolute(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
