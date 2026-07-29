//! Reading and showing saved scans.
//!
//! Ported from the `scans list` and `scans show` commands in `src/cli.ts`.
//!
//! These read the workbench's record of past scans. The record is JSON, and
//! that is what a caller asking for JSON gets, unmodified — the human-readable
//! report is a rendering of the same data, not a different answer. Rendering
//! only happens for a terminal, so a redirected or piped run stays machine
//! readable whether or not anyone remembered a flag.

use std::path::{Path, PathBuf};

use puncode_security::runtime::{
    PluginPythonOptions, WorkbenchCommandOptions, bundled_plugin_root,
    puncode_security_state_directory, resolve_plugin_python, run_workbench,
};
use puncode_security::scan_comparison::{
    ProcessComparisonAgent, ScanComparisonInput, ScanComparisonOptions, match_scan_findings,
};
use puncode_security::scan_history_renderer::{
    HistoryCommand, RendererOptions, render_scan_history,
};
use puncode_security::targets::ProcessEnvironment;
use serde_json::{Map, Value};

use crate::cli::{Format, ScansCompareArgs, ScansListArgs, ScansMatchArgs, ScansShowArgs};

/// Everything the history commands need from the outside world.
pub struct HistoryContext {
    pub environment: ProcessEnvironment,
    pub current_directory: PathBuf,
    /// Terminal width, when the output is a terminal.
    pub columns: Option<usize>,
    /// Milliseconds since the epoch, for judging what is stale.
    pub now: i64,
}

impl HistoryContext {
    /// Whether the report should be drawn for a person.
    fn renders_for_a_terminal(&self, format: Format) -> bool {
        format == Format::Text && self.columns.is_some()
    }

    /// Whether colour is welcome.
    ///
    /// A pipe, `NO_COLOR`, or a terminal that cannot render it all mean no.
    fn uses_color(&self) -> bool {
        !self.environment.contains_key("NO_COLOR")
            && self.environment.get("TERM").map(String::as_str) != Some("dumb")
    }
}

/// Lists the saved scans for a repository or scan root.
pub fn list(arguments: &ScansListArgs, context: &HistoryContext) -> Result<String, String> {
    // A scan root names where output lives rather than what was scanned, so
    // asking for one without a repository means "everything under here".
    let repository = match (&arguments.scan_root, &arguments.repository) {
        (Some(_), None) => None,
        (_, repository) => Some(resolve(
            &context.current_directory,
            repository.as_deref().unwrap_or(&context.current_directory),
        )),
    };
    let scan_root = arguments
        .scan_root
        .as_ref()
        .map(|root| resolve(&context.current_directory, root));

    let mut request = vec!["list-scans".to_owned()];
    if let Some(repository) = &repository {
        request.push("--repository".to_owned());
        request.push(repository.to_string_lossy().into_owned());
    }
    if let Some(scan_root) = &scan_root {
        request.push("--scan-root".to_owned());
        request.push(scan_root.to_string_lossy().into_owned());
    }

    let record = workbench(&request, context)?;
    present(
        &record,
        HistoryCommand::List,
        arguments.output.resolved(),
        context,
        &RendererSettings {
            repository,
            scan_root,
            show_linked_findings: false,
        },
    )
}

/// Shows one saved scan.
pub fn show(arguments: &ScansShowArgs, context: &HistoryContext) -> Result<String, String> {
    let record = workbench(
        &[
            "get-scan".to_owned(),
            "--scan-id".to_owned(),
            arguments.scan_id.clone(),
        ],
        context,
    )?;

    // The workbench answers with the scan wrapped alongside its recipe; the
    // report wants them as one object.
    let mut flattened = record
        .get("scan")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| record.clone());
    for name in ["recipe", "parentScanId"] {
        if let Some(value) = record.get(name) {
            flattened.insert(name.to_owned(), value.clone());
        }
    }

    present(
        &flattened,
        HistoryCommand::Show,
        arguments.output.resolved(),
        context,
        &RendererSettings {
            show_linked_findings: arguments.show_linked_findings,
            ..RendererSettings::default()
        },
    )
}

/// Compares two saved scans using the matches already recorded.
///
/// `--require-matches` is passed because a comparison without them would be a
/// guess: the workbench refuses rather than reporting findings as resolved
/// when nothing has actually matched them.
pub fn compare(arguments: &ScansCompareArgs, context: &HistoryContext) -> Result<String, String> {
    let record = workbench(
        &[
            "compare-scans".to_owned(),
            "--before-scan-id".to_owned(),
            arguments.before_id.clone(),
            "--after-scan-id".to_owned(),
            arguments.after_id.clone(),
            "--require-matches".to_owned(),
        ],
        context,
    )?;

    present(
        &record,
        HistoryCommand::Compare,
        arguments.output.resolved(),
        context,
        &RendererSettings::default(),
    )
}

/// Matches findings across two saved scans by root cause.
///
/// A match already computed is reused unless the caller asks for it again:
/// matching costs a model turn, and repeating it for an unchanged pair would
/// spend money to reach the same answer.
pub fn match_scans(arguments: &ScansMatchArgs, context: &HistoryContext) -> Result<String, String> {
    let (Some(before), Some(after)) = (&arguments.before_id, &arguments.after_id) else {
        // `--all` is checked before this runs; reaching here without two scans
        // would be a bug rather than a usage error.
        return Err("Name two scans to match.".to_owned());
    };

    let comparison = workbench(
        &[
            "compare-scans".to_owned(),
            "--before-scan-id".to_owned(),
            before.clone(),
            "--after-scan-id".to_owned(),
            after.clone(),
            "--include-matching-inputs".to_owned(),
        ],
        context,
    )?;

    // The inputs are working data, not part of the report.
    let cached = comparison
        .get("matchingCached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut visible = comparison.clone();
    visible.remove("matchingCached");
    let inputs = visible.remove("matchingInputs");

    if cached && !arguments.force {
        return present(
            &visible,
            HistoryCommand::Compare,
            arguments.output.resolved(),
            context,
            &RendererSettings::default(),
        );
    }

    let inputs: ScanComparisonInput = serde_json::from_value(inputs.unwrap_or(Value::Null))
        .map_err(|error| format!("The workbench did not supply findings to match: {error}"))?;
    let agent = ProcessComparisonAgent::new(
        puncode_security::runtime::resolve_codex_command(
            &context.environment,
            &context.current_directory,
        )
        .map_err(|error| error.to_string())?
        .command,
        &context.environment,
    );
    let matches = match_scan_findings(&inputs, &ScanComparisonOptions::default(), &agent)
        .map_err(|error| error.to_string())?;

    let saved = workbench(
        &[
            "save-scan-comparison".to_owned(),
            "--before-scan-id".to_owned(),
            before.clone(),
            "--after-scan-id".to_owned(),
            after.clone(),
            "--matches-json".to_owned(),
            serde_json::to_string(&matches).map_err(|error| error.to_string())?,
        ],
        context,
    )?;

    present(
        &saved,
        HistoryCommand::Compare,
        arguments.output.resolved(),
        context,
        &RendererSettings::default(),
    )
}

/// The arguments a saved scan ran with, ready to run again.
///
/// Failing here is a different thing from a scan failing: the recipe could not
/// be read, so nothing was attempted.
pub fn rerun_arguments(
    scan_id: &str,
    context: &HistoryContext,
) -> Result<crate::cli::ScanArgs, String> {
    let record = workbench(
        &[
            "get-scan-recipe".to_owned(),
            "--scan-id".to_owned(),
            scan_id.to_owned(),
        ],
        context,
    )?;
    crate::commands::recipe::scan_arguments(record.get("recipe"), scan_id)
}

/// Matches every unmatched pair in the current repository's history.
pub fn match_all(arguments: &ScansMatchArgs, context: &HistoryContext) -> Result<String, String> {
    let mut request = vec![
        "list-unmatched-scan-pairs".to_owned(),
        "--repository".to_owned(),
        context.current_directory.to_string_lossy().into_owned(),
    ];
    if arguments.force {
        request.push("--force".to_owned());
    }
    let plan = workbench(&request, context)?;

    let agent = ProcessComparisonAgent::new(
        puncode_security::runtime::resolve_codex_command(
            &context.environment,
            &context.current_directory,
        )
        .map_err(|error| error.to_string())?
        .command,
        &context.environment,
    );
    let store = WorkbenchStore { context };
    let outcome = crate::commands::match_all::match_all(&plan, &agent, &store)?;

    present(
        &outcome.report,
        HistoryCommand::MatchAll,
        arguments.output.resolved(),
        context,
        &RendererSettings::default(),
    )
}

/// Saves comparisons back to the workbench.
struct WorkbenchStore<'a> {
    context: &'a HistoryContext,
}

impl crate::commands::match_all::ComparisonStore for WorkbenchStore<'_> {
    fn save(
        &self,
        before_scan_id: &str,
        after_scan_id: &str,
        matches: &puncode_security::scan_comparison::ScanComparisonResult,
    ) -> Result<(), String> {
        workbench(
            &[
                "save-scan-comparison".to_owned(),
                "--before-scan-id".to_owned(),
                before_scan_id.to_owned(),
                "--after-scan-id".to_owned(),
                after_scan_id.to_owned(),
                "--matches-json".to_owned(),
                serde_json::to_string(matches).map_err(|error| error.to_string())?,
            ],
            self.context,
        )
        .map(|_| ())
    }
}

/// What the renderer needs beyond the record itself.
#[derive(Default)]
struct RendererSettings {
    repository: Option<PathBuf>,
    scan_root: Option<PathBuf>,
    show_linked_findings: bool,
}

/// Renders the record for a terminal, or hands it back as it arrived.
fn present(
    record: &Map<String, Value>,
    command: HistoryCommand,
    format: Format,
    context: &HistoryContext,
    settings: &RendererSettings,
) -> Result<String, String> {
    if context.renders_for_a_terminal(format) {
        return Ok(render_scan_history(
            record,
            command,
            &RendererOptions {
                columns: context.columns,
                color: Some(context.uses_color()),
                now: Some(context.now),
                repository: settings
                    .repository
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                scan_root: settings
                    .scan_root
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                show_linked_findings: settings.show_linked_findings,
            },
        ));
    }

    // Anything not drawn for a person is the workbench's own JSON, unchanged.
    match format {
        Format::Json | Format::Text => serde_json::to_string_pretty(record),
        Format::Jsonl => serde_json::to_string(record),
    }
    .map_err(|error| error.to_string())
}

/// Asks the workbench a question about saved scans.
fn workbench(request: &[String], context: &HistoryContext) -> Result<Map<String, Value>, String> {
    let mut environment = context.environment.clone();
    environment.insert(
        "CODEX_SECURITY_STATE_DIR".to_owned(),
        puncode_security_state_directory(&context.environment)
            .to_string_lossy()
            .into_owned(),
    );

    let plugin_root = bundled_plugin_root().map_err(|error| error.to_string())?;
    let python = resolve_plugin_python(&PluginPythonOptions {
        configured_path: None,
        environment: environment.clone(),
        protected_root: context.current_directory.clone(),
        home_directory: None,
        managed_runtime_roots: None,
    })
    .map_err(|error| error.to_string())?;

    let arguments: Vec<&str> = request.iter().map(String::as_str).collect();
    run_workbench(
        &WorkbenchCommandOptions {
            python: &python,
            plugin_root: &plugin_root,
            environment: &environment,
            failure_message: Some("Could not read Puncode Security scan history"),
        },
        &arguments,
    )
    .map_err(|error| error.to_string())
}

/// `path` against `base`, unless it is already absolute.
fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    base.join(path)
}
