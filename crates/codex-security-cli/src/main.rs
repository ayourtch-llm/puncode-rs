//! Thin command line front end over the `codex-security` library.
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
            eprintln!("codex-security: {problem}");
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
                eprintln!("codex-security: {problem}");
            }
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(problem) => {
            eprintln!("codex-security: {problem}");
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
            eprintln!("codex-security: {problem}");
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
            eprintln!("codex-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}

/// Runs a scan, reporting progress as it goes.
///
/// The report goes to standard output and everything else to standard error,
/// so a redirected report stays parseable. The exit code is what a CI job acts
/// on, so it is returned rather than folded into the usual success path.
fn scan(options: &cli::ScanArgs) -> std::process::ExitCode {
    use std::io::IsTerminal;

    let cancellation = std::sync::Arc::new(codex_security::api::ScanCancellation::new());
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
        eprintln!("codex-security: Scan {}.", signal.description());
        report_partial_output(progress.scan_dir.as_deref());
        return std::process::ExitCode::from(signal.exit_code());
    }

    match outcome {
        Ok(outcome) => {
            println!("{}", outcome.report);
            for line in &outcome.summary {
                eprintln!("codex-security: {line}");
            }
            if let Some(warning) = &outcome.coverage_warning {
                eprintln!("codex-security: {warning}");
            }
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(problem) => {
            eprintln!("codex-security: {problem}");
            // The failure can be accurate and still point the wrong way.
            for explanation in progress.explanations(&problem) {
                eprintln!("codex-security: {explanation}");
            }
            report_partial_output(progress.scan_dir.as_deref());
            std::process::ExitCode::from(exit::ERROR)
        }
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
            "codex-security: Partial output was kept at {}.",
            scan_dir.display()
        ),
        None => eprintln!("codex-security: No partial output was kept."),
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

    let environment: codex_security::targets::ProcessEnvironment = std::env::vars().collect();
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
            eprintln!("codex-security: {problem}");
            std::process::ExitCode::from(exit::ERROR)
        }
    }
}
