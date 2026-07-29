//! Rules that span several arguments.
//!
//! Ported from `validateCliArguments` in `src/cli.ts`.
//!
//! Clap checks each flag on its own; these are the combinations that are
//! individually fine and together are not. They are reported as argument
//! errors, before any work starts, because the alternative is a scan that runs
//! for minutes and then cannot write what it was asked to write.

use crate::cli::{Command, ExportFormat, ScanArgs, ScansMatchArgs};

/// Reports why a command's arguments cannot be used together, if they cannot.
#[must_use]
pub fn validate(command: &Command) -> Option<String> {
    match command {
        // These commands report to a person; there is no machine-readable form
        // of "here is the sign-in URL, open it".
        Command::Validate(arguments) if arguments.output.resolved().is_structured() => {
            Some(unsupported_structured_output("validate"))
        }
        Command::Patch(arguments) if arguments.output.resolved().is_structured() => {
            Some(unsupported_structured_output("patch"))
        }
        Command::Login(arguments) if arguments.output.resolved().is_structured() => {
            Some(unsupported_structured_output("login"))
        }
        Command::Logout => None,
        Command::Export(arguments) => {
            // Both would be written to the same stream, interleaved.
            let to_stdout = arguments.output.as_deref() == Some("-");
            if arguments.output_options.resolved().is_structured()
                && to_stdout
                && arguments.export_format == ExportFormat::Csv
            {
                return Some(
                    "CSV stdout cannot be combined with JSON output; write CSV to a file or omit \
                     --json."
                        .to_owned(),
                );
            }
            // The fingerprints it feeds are a SARIF concept; nothing else
            // would do anything with the checkout.
            if arguments.source_root.is_some() && arguments.export_format != ExportFormat::Sarif {
                return Some(
                    "--source-root is only supported with --export-format sarif".to_owned(),
                );
            }
            None
        }
        Command::Scan(arguments) => validate_scan(arguments),
        Command::Scans(crate::cli::ScansCommand::Match(arguments)) => validate_match(arguments),
        _ => None,
    }
}

fn unsupported_structured_output(command: &str) -> String {
    format!(
        "{command} does not support noninteractive JSON output; run it without --json or --format \
         json."
    )
}

/// Checks the ways a scan target can be over-specified.
fn validate_scan(arguments: &ScanArgs) -> Option<String> {
    let targets = usize::from(!arguments.paths.is_empty())
        + usize::from(arguments.diff.is_some())
        + usize::from(arguments.working_tree);
    if targets > 1 {
        return Some("Choose one scan target: --path, --diff, or --working-tree.".to_owned());
    }
    // A ref only means something alongside the target it belongs to.
    if arguments.head.is_some() && arguments.diff.is_none() {
        return Some("--head requires --diff.".to_owned());
    }
    if arguments.base.is_some() && !arguments.working_tree {
        return Some("--base requires --working-tree.".to_owned());
    }
    // Deep mode reads the whole tree, which a diff cannot describe.
    if arguments.mode == crate::cli::Mode::Deep
        && (arguments.diff.is_some() || arguments.working_tree)
    {
        return Some("Deep mode supports repository and path targets only.".to_owned());
    }
    if arguments
        .max_cost
        .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
    {
        return Some("The scan cost limit must be a positive USD amount.".to_owned());
    }
    None
}

/// Checks that a match names what it should compare.
fn validate_match(arguments: &ScansMatchArgs) -> Option<String> {
    if arguments.all {
        if arguments.before_id.is_some() || arguments.after_id.is_some() {
            return Some("--all matches every scan; do not also name two scans.".to_owned());
        }
        return None;
    }
    if arguments.before_id.is_none() || arguments.after_id.is_none() {
        return Some("Name two scans to match, or pass --all.".to_owned());
    }
    None
}
