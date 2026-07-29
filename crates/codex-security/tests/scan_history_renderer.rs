//! Differential tests for the scan-history renderer.
//!
//! The renderer's output is exact — colours, padding, wrapping and ordering are
//! all part of it — so hand-written expectations would be guesses. Every case
//! here was rendered by the TypeScript implementation and captured verbatim in
//! `fixtures/scan-history.json`; this asserts the port produces the same bytes.

use std::collections::BTreeMap;

use codex_security::scan_history_renderer::{HistoryCommand, RendererOptions, render_scan_history};
use serde::Deserialize;
use serde_json::{Map, Value};

/// One captured case: the arguments given, and what came back.
#[derive(Debug, Deserialize)]
struct Case {
    args: (Map<String, Value>, String, RendererArgs),
    text: String,
}

/// The renderer options as the probe passed them.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RendererArgs {
    columns: Option<usize>,
    color: Option<bool>,
    now: Option<i64>,
    repository: Option<String>,
    scan_root: Option<String>,
    show_linked_findings: Option<bool>,
}

impl From<&RendererArgs> for RendererOptions {
    fn from(args: &RendererArgs) -> Self {
        Self {
            columns: args.columns,
            color: args.color,
            now: args.now,
            repository: args.repository.clone(),
            scan_root: args.scan_root.clone(),
            show_linked_findings: args.show_linked_findings.unwrap_or(false),
        }
    }
}

fn command_of(name: &str) -> HistoryCommand {
    match name {
        "list" => HistoryCommand::List,
        "show" => HistoryCommand::Show,
        "compare" => HistoryCommand::Compare,
        "match-all" => HistoryCommand::MatchAll,
        other => panic!("unknown command {other}"),
    }
}

fn cases() -> BTreeMap<String, Case> {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scan-history.json"),
    )
    .expect("read the captured renderings");
    serde_json::from_str(&text).expect("parse the captured renderings")
}

/// Renders one captured case with the port.
fn render(case: &Case) -> String {
    let (result, command, options) = &case.args;
    render_scan_history(result, command_of(command), &RendererOptions::from(options))
}

/// Reports the first line that differs, which is far easier to read than a
/// diff of two screens of escape codes.
fn assert_same(name: &str, case: &Case) {
    let actual = render(case);
    if actual == case.text {
        return;
    }
    let expected_lines: Vec<&str> = case.text.split('\n').collect();
    let actual_lines: Vec<&str> = actual.split('\n').collect();
    for (index, (expected, got)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
        assert_eq!(
            got,
            expected,
            "{name}: line {} differs\n  expected {expected:?}\n  actual   {got:?}",
            index + 1
        );
    }
    assert_eq!(
        actual_lines.len(),
        expected_lines.len(),
        "{name}: line count differs"
    );
}

#[test]
fn renders_every_captured_case_exactly() {
    let cases = cases();
    assert_eq!(cases.len(), 20, "the fixture should cover every case");
    for (name, case) in &cases {
        assert_same(name, case);
    }
}

/// Runs one named case, so a failure names the report that broke.
macro_rules! case {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            let cases = cases();
            let case = cases.get($name).expect(concat!("case ", $name));
            assert_same($name, case);
        }
    };
}

case!(renders_a_wide_list, "list-wide");
case!(renders_a_narrow_list, "list-narrow");
case!(renders_a_list_spanning_repositories, "list-multi-repo");
case!(hides_a_stale_running_scan, "list-stale-running");
case!(renders_a_list_without_color, "list-no-color");
case!(renders_a_list_for_one_repository, "list-single-scan");
case!(clamps_a_very_wide_terminal, "list-clamps-width");
case!(clamps_a_very_narrow_terminal, "list-clamps-narrow");
case!(renders_a_full_scan_detail, "show-full");
case!(renders_a_failed_scan, "show-failure");
case!(renders_linked_findings_when_asked, "show-linked");
case!(hides_linked_findings_by_default, "show-linked-hidden");
case!(reports_truncated_findings, "show-truncated");
case!(renders_a_full_comparison, "compare-full");
case!(
    warns_about_incomplete_coverage,
    "compare-incomplete-coverage"
);
case!(wraps_a_long_summary_line, "compare-summary-wrap");
case!(wraps_a_long_finding_title, "compare-long-title-wrap");
case!(renders_match_all_results, "match-all");
case!(renders_match_all_with_nothing_to_report, "match-all-clean");

// Scan records carry text from the repository under review; an escape sequence
// in a title would otherwise repaint the report around it.
#[test]
fn neutralises_control_characters_in_scan_data() {
    let cases = cases();
    let case = cases.get("control-chars").expect("case control-chars");

    assert_same("control-chars", case);

    // The rendered output holds no escape sequence that did not come from the
    // renderer's own colouring.
    assert!(
        !render(case).contains("[31mred"),
        "an escape sequence from scan data survived"
    );
}
