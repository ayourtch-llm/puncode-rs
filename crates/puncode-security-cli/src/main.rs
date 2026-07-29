//! Thin command line front end over the `puncode-security` library.
//!
//! This binary is intentionally minimal: argument parsing and process I/O only.
//! Behavior, rendering, and formatting all live in the library crate.

mod cli;
mod commands;
mod overrides;
mod validate;

use clap::Parser;

use cli::{Cli, Command, ScansCommand};

/// What the process exits with.
///
/// Ported from the exit codes in `src/cli.ts`: a scan that found something at
/// or above the failure severity is not the same as a scan that could not run,
/// and a CI job needs to tell them apart.
pub mod exit {
    /// Nothing to report.
    pub const SUCCESS: u8 = 0;
    /// The scan ran and found something worth failing on.
    pub const FINDINGS: u8 = 1;
    /// The command could not run, or its arguments were unusable.
    pub const ERROR: u8 = 2;
}

/// Repeats a saved scan with the configuration it originally ran under.
///
/// The recipe is rebuilt and then run through exactly the same path an
/// ordinary scan takes, so a rerun cannot drift from what a scan does.
fn rerun(options: &cli::ScansRerunArgs) -> std::process::ExitCode {
    let context = history_context();
    let mut arguments = match commands::history::rerun_arguments(&options.scan_id, &context) {
        Ok(arguments) => arguments,
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            return std::process::ExitCode::from(exit::ERROR);
        }
    };
    // How the rerun reports is the caller's choice now, not the original run's.
    arguments.output = options.output.clone();
    scan(&arguments)
}

/// Runs a plugin skill over findings or issues.
///
/// The exit code is Codex's own, so a script can act on the outcome the same
/// way it would if it had run Codex directly.
fn skill(
    which: commands::skill::Skill,
    inputs: &[String],
    codex_overrides: &[String],
) -> std::process::ExitCode {
    let current_directory = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let name = match which {
        commands::skill::Skill::Validation => "validate",
        commands::skill::Skill::FixFinding => "patch",
    };
    let outcome = commands::skill::build(which, inputs, codex_overrides, &current_directory)
        .and_then(|invocation| {
            commands::skill::run(
                &invocation,
                name,
                &std::env::vars().collect(),
                &current_directory,
            )
        });

    match outcome {
        Ok(outcome) => {
            // The answer goes to standard output; anything about the run does
            // not, so a redirected answer stays only the answer.
            if let Some(message) = &outcome.message {
                println!("{message}");
            }
            if let Some(problem) = &outcome.problem {
                eprintln!("puncode-security: {problem}");
            }
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}

/// Exports a finished scan.
///
/// The export goes to standard output when that is what was asked for, and the
/// note about where it was written goes to standard error, so redirecting the
/// export never captures the note alongside it.
fn export(options: &cli::ExportArgs) -> std::process::ExitCode {
    let outcome = commands::export::run(
        options,
        &std::env::current_dir().unwrap_or_else(|_| ".".into()),
        &std::env::vars().collect(),
    );
    match outcome {
        Ok(outcome) => {
            if let Some(contents) = &outcome.contents {
                print!("{contents}");
            }
            if let Some(note) = &outcome.note {
                eprintln!("{note}");
            }
            std::process::ExitCode::from(exit::SUCCESS)
        }
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}

/// Signs in, handing the terminal to Codex.
///
/// The exit code is Codex's own, so a script can act on a failed sign-in the
/// same way it would if it had run Codex directly.
fn login(options: &cli::LoginArgs) -> std::process::ExitCode {
    match commands::login::run(options, &std::env::vars().collect()) {
        Ok(outcome) => {
            for note in &outcome.notes {
                eprintln!("{note}");
            }
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}

/// Runs a scan, reporting progress as it goes.
///
/// The report goes to standard output and everything else to standard error,
/// so a redirected report stays parseable. The exit code is what a CI job acts
/// on, so it is returned rather than folded into the usual success path.
/// Runs a scan, or several, reporting how much repeated runs agreed.
///
/// Repeats are sequential. Several scans at once against one endpoint contend
/// with each other, and the point of repeating is to see the model's own
/// variation rather than the effects of load.
fn scan(options: &cli::ScanArgs) -> std::process::ExitCode {
    if options.repeat <= 1 {
        return scan_once(options);
    }

    let Some(base) = &options.output_dir else {
        eprintln!("puncode-security: --repeat needs --output-dir.");
        return std::process::ExitCode::from(exit::ERROR);
    };

    // Said before anything is spent, not discovered afterwards.
    eprintln!(
        "puncode-security: running {} scans, one after another. This costs {} times a single \
         scan.",
        options.repeat, options.repeat
    );

    let mut directories = Vec::new();
    let mut worst = exit::SUCCESS;
    let mut failed = Vec::new();

    for run in 1..=options.repeat {
        // One scan per output directory is a workbench rule, so each run needs
        // its own.
        let directory = std::path::Path::new(base).join(format!("run-{run}"));
        eprintln!("puncode-security: run {run} of {}", options.repeat);

        let mut once = options.clone();
        once.output_dir = Some(directory.to_string_lossy().into_owned());
        once.repeat = 1;
        // One capture file per run. Sharing one truncates it on every run
        // after the first, and the reason to capture while repeating is to see
        // why the runs differed — which needs all of them.
        once.capture_traffic = options
            .capture_traffic
            .as_deref()
            .map(|path| capture_for_run(path, run));

        let code = scan_once(&once);
        // A run that failed is named rather than swallowed; the rest are still
        // worth comparing, and a partial answer beats none.
        if code != std::process::ExitCode::from(exit::SUCCESS) {
            failed.push(run);
        }
        if directory.join("findings.json").is_file() {
            directories.push(directory);
        }
        worst = worst.max(run_severity(&code));
    }

    if !failed.is_empty() {
        eprintln!(
            "puncode-security: {} of {} runs did not finish cleanly: {}",
            failed.len(),
            options.repeat,
            failed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if directories.len() < 2 {
        eprintln!("puncode-security: too few runs produced findings to compare.");
        return std::process::ExitCode::from(worst);
    }

    match commands::consensus::run(&directories, None, false) {
        Ok(report) => println!("{report}"),
        Err(problem) => eprintln!("puncode-security: {problem}"),
    }
    std::process::ExitCode::from(worst)
}

/// The exit code as a number, for comparing runs.
///
/// `ExitCode` cannot be inspected, so severity is tracked alongside it.
fn run_severity(code: &std::process::ExitCode) -> u8 {
    if *code == std::process::ExitCode::from(exit::SUCCESS) {
        exit::SUCCESS
    } else if *code == std::process::ExitCode::from(exit::FINDINGS) {
        exit::FINDINGS
    } else {
        exit::ERROR
    }
}

fn scan_once(options: &cli::ScanArgs) -> std::process::ExitCode {
    use std::io::IsTerminal;

    if options.dangerously_disable_sandbox {
        eprintln!(
            "puncode-security: WARNING: the sandbox is off. The agent's shell commands run with \
             your access to this machine, over a repository being scanned because it is not \
             trusted. Prefer a host where the Codex sandbox works, or a container dedicated to \
             this scan."
        );
    }

    let started = puncode_security::contract::utc_rfc3339_now();
    let cancellation = std::sync::Arc::new(puncode_security::api::ScanCancellation::new());
    let interrupted = commands::progress::install_interrupt_handler(&cancellation);
    // Progress is for a person; a structured report has no room for it.
    let mut progress = commands::progress::ScanProgress::new(
        options.output.resolved() != cli::Format::Text || !std::io::stderr().is_terminal(),
        options.max_cost_usd_for_progress(),
    );

    let outcome = commands::scan::run(
        options,
        &std::env::current_dir().unwrap_or_else(|_| ".".into()),
        &mut progress,
        &cancellation,
    );

    // An interrupt decides the outcome whatever the scan itself reported: the
    // person asked it to stop, so "stopped" is the honest answer even if the
    // work happened to reach an end on the way down.
    if let Some(signal) = interrupted.requested() {
        eprintln!("puncode-security: Scan {}.", signal.description());
        report_partial_output(progress.scan_dir.as_deref());
        return std::process::ExitCode::from(signal.exit_code());
    }

    // Written whatever the outcome: a scan that failed still produced
    // artifacts someone may read, and how they were produced still matters.
    record_provenance(options, progress.scan_dir.as_deref(), &started);

    match outcome {
        Ok(outcome) => {
            println!("{}", outcome.report);
            for line in &outcome.summary {
                eprintln!("puncode-security: {line}");
            }
            if let Some(warning) = &outcome.coverage_warning {
                eprintln!("puncode-security: {warning}");
            }
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            // The failure can be accurate and still point the wrong way.
            for explanation in progress.explanations(&problem) {
                eprintln!("puncode-security: {explanation}");
            }
            // Evidence rather than only a diagnosis. The workbench can say the
            // scanned tree changed and cannot say what changed; usually it is
            // one build artefact sitting next to the source, and naming it
            // turns a baffling failure into an obvious one.
            // The same idea for the manifest: the workbench can say it does not
            // match and cannot say how, while the answer is on disk in the
            // partial output it just kept.
            if puncode_security::diagnosis::recognise(&problem)
                == Some(puncode_security::diagnosis::Cause::ManifestNotAsSerialised)
                && let Some(scan_dir) = progress.scan_dir.as_deref()
            {
                for line in commands::scan::manifest_evidence(scan_dir) {
                    eprintln!("puncode-security: {line}");
                }
            }
            // The same evidence answers both: something wrote into the target,
            // and git can name it when the workbench cannot.
            if matches!(
                puncode_security::diagnosis::recognise(&problem),
                Some(
                    puncode_security::diagnosis::Cause::WorkingTreeChanged
                        | puncode_security::diagnosis::Cause::TargetMovedSinceRegistration
                )
            ) {
                let repository = options
                    .repository
                    .clone()
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
                let changed = puncode_security::diagnosis::changed_paths(&repository);
                if !changed.is_empty() {
                    eprintln!("puncode-security: what differs from the last commit:");
                    for path in changed {
                        eprintln!("puncode-security:   {path}");
                    }
                }
            }
            report_partial_output(progress.scan_dir.as_deref());
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}

/// Checks a scan's results against themselves.
///
/// Exits 1 when they do not hold together. That is a result, not an error, in
/// the same way a scan finding something is.
fn verify(options: &cli::VerifyArgs) -> std::process::ExitCode {
    let verification = match commands::verify::run(&options.scan_dir) {
        Ok(verification) => verification,
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            return std::process::ExitCode::from(exit::ERROR);
        }
    };

    if options.output.resolved().is_structured() {
        println!("{}", commands::verify::render_json(&verification));
    } else {
        println!(
            "{}",
            commands::verify::render(&verification, &options.scan_dir)
        );
    }

    if verification.holds() {
        std::process::ExitCode::from(exit::SUCCESS)
    } else {
        std::process::ExitCode::from(exit::FINDINGS)
    }
}

/// Reports what would stop a scan.
///
/// Exits 1 when something is broken, so a job can refuse to go on. A check that
/// could not run is not a failure — it is reported as skipped and does not
/// change the exit code, because treating "unknown" as "broken" would train
/// people to ignore this.
fn doctor(options: &cli::DoctorArgs) -> std::process::ExitCode {
    let checks = commands::doctor::examine(&commands::doctor::Examination {
        environment: std::env::vars().collect(),
        working_directory: std::env::current_dir().unwrap_or_else(|_| ".".into()),
        base_url: options.base_url.clone(),
        model: options.model.clone(),
    });

    if options.output.resolved().is_structured() {
        println!("{}", commands::doctor::render_json(&checks));
    } else {
        println!("{}", commands::doctor::render(&checks));
    }

    if checks.iter().any(|check| check.health.blocks_a_scan()) {
        return std::process::ExitCode::from(exit::FINDINGS);
    }
    std::process::ExitCode::from(exit::SUCCESS)
}

/// Scores scans against the corpus, failing when a threshold is not met.
///
/// Exits 1 for a shortfall rather than 2, matching `scan`: a measurement that
/// came out badly is a result, not an error.
fn bench(options: &cli::BenchArgs) -> std::process::ExitCode {
    let outcome = match commands::bench::run(
        &options.ground_truth,
        &options.results,
        &options.corpus_root,
    ) {
        Ok(outcome) => outcome,
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            return std::process::ExitCode::from(exit::ERROR);
        }
    };

    let shortfalls =
        commands::bench::shortfalls(&outcome, options.min_detection, options.max_false_positives);

    let comparison = match &options.baseline {
        Some(baseline) => match commands::bench::against_baseline(
            &options.ground_truth,
            baseline,
            &outcome,
            &options.corpus_root,
        ) {
            Ok(pair) => Some(pair),
            Err(problem) => {
                eprintln!("puncode-security: could not read the baseline: {problem}");
                return std::process::ExitCode::from(exit::ERROR);
            }
        },
        None => None,
    };

    if options.output.resolved().is_structured() {
        println!("{}", commands::bench::render_json(&outcome, &shortfalls));
    } else {
        println!("{}", commands::bench::render(&outcome));
        if let Some((comparison, produced_differently)) = &comparison {
            println!(
                "{}",
                commands::bench::render_comparison(comparison, produced_differently)
            );
        }
    }

    if let Some((comparison, produced_differently)) = &comparison
        && comparison.regressed()
    {
        // Still a failure — a job watching for this should stop either way —
        // but the reason it may not mean what it looks like goes on the same
        // line as the alarm, not somewhere above it.
        if produced_differently.is_empty() {
            eprintln!("puncode-security: something that used to be found is no longer found.");
        } else {
            eprintln!(
                "puncode-security: something that used to be found is no longer found, but the \
                 two runs were not produced the same way, so this may be that difference."
            );
        }
        return std::process::ExitCode::from(exit::FINDINGS);
    }

    if shortfalls.is_empty() {
        return std::process::ExitCode::from(exit::SUCCESS);
    }
    for shortfall in &shortfalls {
        eprintln!("puncode-security: {}", shortfall.describe());
    }
    std::process::ExitCode::from(exit::FINDINGS)
}

/// The capture destination for one run of a repeated scan.
///
/// The run number goes before the extension, so the files sort together and
/// keep whatever suffix the caller chose.
fn capture_for_run(path: &std::path::Path, run: usize) -> std::path::PathBuf {
    let stem = path.file_stem().map_or_else(
        || "traffic".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let name = match path.extension() {
        Some(extension) => format!("{stem}-run-{run}.{}", extension.to_string_lossy()),
        None => format!("{stem}-run-{run}"),
    };
    path.with_file_name(name)
}

/// Writes down how this scan was produced, beside what it produced.
///
/// Best effort: a scan that ran is not undone by failing to describe itself, so
/// a problem here is reported and nothing more.
fn record_provenance(options: &cli::ScanArgs, scan_dir: Option<&std::path::Path>, started: &str) {
    let Some(scan_dir) = scan_dir else { return };

    let record = puncode_security::provenance::Provenance {
        tool: "puncode-security".to_owned(),
        tool_version: puncode_security::version::VERSION.to_owned(),
        plugin_version: puncode_security::version::BUNDLED_PLUGIN_VERSION.to_owned(),
        plugin_digest: puncode_security::runtime::bundled_plugin_root()
            .ok()
            .and_then(|root| std::fs::read_to_string(root.join(".unpacked")).ok())
            .map(|digest| digest.trim().to_owned()),
        model: options.model.clone(),
        // Display is redacted, so the record cannot carry a credential.
        endpoint: options.base_url.as_ref().map(ToString::to_string),
        wire_api: options.base_url.as_ref().map(|_| {
            puncode_security::model_endpoint::WireApi::from(options.wire_api)
                .as_str()
                .to_owned()
        }),
        endpoint_adaptations: options
            .endpoint_compat
            .iter()
            .map(|compat| match compat {
                cli::EndpointCompat::MergeSystem => "merge-system".to_owned(),
            })
            .collect(),
        sandbox_disabled: options.dangerously_disable_sandbox,
        mode: format!("{:?}", options.mode).to_lowercase(),
        started_at: started.to_owned(),
        completed_at: puncode_security::contract::utc_rfc3339_now(),
    };

    if let Err(error) = record.write(scan_dir) {
        eprintln!("puncode-security: could not record how this scan was produced: {error}");
    }
}

/// Says where a stopped scan left what it had produced.
///
/// Naming the directory matters more here than anywhere else: the person is
/// being told the run did not finish, and this is what says the work was not
/// thrown away.
fn report_partial_output(scan_dir: Option<&std::path::Path>) {
    match scan_dir {
        Some(scan_dir) => eprintln!(
            "puncode-security: Partial output was kept at {}.",
            scan_dir.display()
        ),
        None => eprintln!("puncode-security: No partial output was kept."),
    }
}

/// What the history commands need from the process.
///
/// The width is only reported when standard output is a terminal, because that
/// is what decides whether the report is drawn for a person or handed over as
/// JSON: a redirected or piped run stays machine readable whether or not
/// anyone remembered a flag.
fn history_context() -> commands::history::HistoryContext {
    use std::io::IsTerminal;

    let environment: puncode_security::targets::ProcessEnvironment = std::env::vars().collect();
    let columns = std::io::stdout().is_terminal().then(|| {
        environment
            .get("COLUMNS")
            .and_then(|value| value.parse().ok())
            .unwrap_or(96)
    });
    commands::history::HistoryContext {
        current_directory: std::env::current_dir().unwrap_or_else(|_| ".".into()),
        columns,
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
            }),
        environment,
    }
}

fn main() -> std::process::ExitCode {
    let arguments = Cli::parse();

    // `--mcp` is a mode rather than a command: it hands the whole process over
    // to the protocol on standard input and output.
    if arguments.mcp {
        if arguments.command.is_some() {
            eprintln!("error: --mcp serves the protocol and cannot be combined with a command.");
            return std::process::ExitCode::from(exit::ERROR);
        }
        return match commands::mcp::serve(std::io::stdin().lock(), std::io::stdout().lock()) {
            Ok(()) => std::process::ExitCode::from(exit::SUCCESS),
            Err(problem) => {
                eprintln!("error: {problem}");
                std::process::ExitCode::from(exit::ERROR)
            }
        };
    }

    let Some(command) = &arguments.command else {
        // Nothing asked for: show what can be asked for.
        let _ = <Cli as clap::CommandFactory>::command().print_help();
        return std::process::ExitCode::from(exit::ERROR);
    };

    if let Some(problem) = validate::validate(command) {
        eprintln!("error: {problem}");
        return std::process::ExitCode::from(exit::ERROR);
    }

    let outcome = match command {
        Command::Info(options) => commands::info::run(options),
        Command::Logout => commands::logout::run(&std::env::vars().collect()),
        Command::Consensus(options) => commands::consensus::run(
            &options.directories,
            options.min_agreement,
            options.output.resolved().is_structured(),
        ),
        // Returns early: a run that fell short of its thresholds must exit
        // non-zero, which the shared success path cannot express.
        Command::Bench(options) => return bench(options),
        // Returns early: a broken environment must exit non-zero so this can
        // gate a job.
        Command::Doctor(options) => return doctor(options),
        // Returns early: results that do not hold together must exit non-zero.
        Command::Verify(options) => return verify(options),
        Command::Export(options) => return export(options),
        Command::BulkScan(options) => commands::bulk_scan::run(
            options,
            &std::env::current_dir().unwrap_or_else(|_| ".".into()),
            &std::env::vars().collect(),
        ),
        Command::Validate(options) => {
            return skill(
                commands::skill::Skill::Validation,
                &options.findings,
                &options.codex,
            );
        }
        Command::Patch(options) => {
            return skill(
                commands::skill::Skill::FixFinding,
                &options.issues,
                &options.codex,
            );
        }
        Command::InstallHook(options) => commands::install_hook::run(
            options,
            &std::env::current_dir().unwrap_or_else(|_| ".".into()),
            &std::env::vars().collect(),
        ),
        Command::Login(options) => return login(options),
        Command::Scan(options) if options.dry_run => commands::scan::dry_run(
            options,
            &std::env::current_dir().unwrap_or_else(|_| ".".into()),
        ),
        Command::Scan(options) => return scan(options),
        Command::Scans(ScansCommand::List(options)) => {
            commands::history::list(options, &history_context())
        }
        Command::Scans(ScansCommand::Show(options)) => {
            commands::history::show(options, &history_context())
        }
        Command::Scans(ScansCommand::Compare(options)) => {
            commands::history::compare(options, &history_context())
        }
        Command::Scans(ScansCommand::Rerun(options)) => return rerun(options),
        Command::Scans(ScansCommand::Match(options)) if options.all => {
            commands::history::match_all(options, &history_context())
        }
        Command::Scans(ScansCommand::Match(options)) => {
            commands::history::match_scans(options, &history_context())
        }
    };

    match outcome {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::from(exit::SUCCESS)
        }
        Err(problem) => {
            eprintln!("puncode-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}
