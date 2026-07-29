//! Rendering scan history for a terminal.
//!
//! Ported from `src/scan-history-renderer.ts`.
//!
//! The output is exact: colours, padding, wrapping and ordering are all part of
//! the contract, so this is checked against output captured from the TypeScript
//! implementation rather than against hand-written expectations.
//!
//! Everything printed passes through [`clean`] first. The values come from scan
//! records, which carry text taken from the repository under review; a finding
//! title containing escape sequences would otherwise repaint or overwrite the
//! surrounding report.

#![allow(dead_code)]

use std::path::Path;

use serde_json::{Map, Value};

use crate::contract::datetime::civil_from_days;

/// Which report is being rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryCommand {
    List,
    Show,
    Compare,
    MatchAll,
}

impl HistoryCommand {
    fn label(self) -> &'static str {
        match self {
            Self::List => "SCAN HISTORY",
            Self::Show => "SCAN DETAILS",
            Self::Compare => "SCAN COMPARISON",
            Self::MatchAll => "MATCH RESULTS",
        }
    }
}

/// How the report should be laid out.
#[derive(Debug, Clone, Default)]
pub struct RendererOptions {
    pub columns: Option<usize>,
    /// Colour is on unless a caller turns it off.
    pub color: Option<bool>,
    /// Milliseconds since the epoch, for deciding what counts as stale.
    pub now: Option<i64>,
    pub repository: Option<String>,
    pub scan_root: Option<String>,
    pub show_linked_findings: bool,
}

/// A running scan older than this is assumed to have died.
const STALE_SCAN_MILLISECONDS: i64 = 24 * 60 * 60 * 1_000;

/// The colour and icon each comparison outcome is drawn with.
///
/// The order is the order outcomes are reported in, so it is fixed here rather
/// than derived: resolved work first, then anything that needs attention.
const STATUS_STYLES: [(&str, u8, &str); 6] = [
    ("resolved", 32, "✓"),
    ("reopened", 31, "↻"),
    ("new", 31, "+"),
    ("persisting", 33, "●"),
    ("not_rescanned", 36, "○"),
    ("unknown", 35, "?"),
];

/// Severity colours, most severe first; the order also ranks findings.
const SEVERITY_COLORS: [(&str, u8); 5] = [
    ("CRITICAL", 31),
    ("HIGH", 31),
    ("MEDIUM", 33),
    ("LOW", 36),
    ("INFORMATIONAL", 37),
];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The reason a finding was not looked at again.
const OUTSIDE_SCOPE: &str = "The affected path was excluded or outside the later scope.";

/// Renders one history report.
#[must_use]
pub fn render_scan_history(
    result: &Map<String, Value>,
    command: HistoryCommand,
    options: &RendererOptions,
) -> String {
    Renderer::new(command, options).render(result)
}

/// Builds one report, accumulating lines as it goes.
struct Renderer<'a> {
    command: HistoryCommand,
    options: &'a RendererOptions,
    color: bool,
    width: usize,
    lines: Vec<String>,
}

impl<'a> Renderer<'a> {
    fn new(command: HistoryCommand, options: &'a RendererOptions) -> Self {
        Self {
            command,
            options,
            color: options.color.unwrap_or(true),
            // Narrow enough to read, wide enough to be useful.
            width: options.columns.unwrap_or(96).clamp(48, 120),
            lines: Vec::new(),
        }
    }

    fn paint(&self, value: &str, code: u8) -> String {
        if self.color {
            format!("\u{1b}[{code}m{value}\u{1b}[0m")
        } else {
            value.to_owned()
        }
    }

    fn dim(&self, value: &str) -> String {
        self.paint(value, 90)
    }

    fn strong(&self, value: &str) -> String {
        self.paint(value, 1)
    }

    fn accent(&self, value: &str) -> String {
        self.paint(value, 36)
    }

    fn push(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    fn render(mut self, result: &Map<String, Value>) -> String {
        self.push("");
        self.push(format!(
            "  {} {}  {}  {}",
            self.accent("◆"),
            self.strong("CODEX SECURITY"),
            self.accent("/"),
            self.strong(self.command.label())
        ));
        self.push(format!(
            "  {}",
            self.accent(&"━".repeat(self.width.saturating_sub(4)))
        ));

        match self.command {
            HistoryCommand::List => self.render_list(result),
            HistoryCommand::Show => self.render_show(result),
            HistoryCommand::Compare => self.render_compare(result),
            HistoryCommand::MatchAll => self.render_match_all(result),
        }

        format!("{}\n\n", self.lines.join("\n"))
    }

    /// Wraps `value` to the report width, indenting continuations.
    fn wrap(&mut self, value: &str, indent: usize, prefix: Option<&str>) {
        let available = self.width.saturating_sub(indent).saturating_sub(2);
        let mut line = String::new();
        let mut first = true;
        for word in split_whitespace_js(&clean_str(value)) {
            if !line.is_empty() && line.chars().count() + word.chars().count() + 1 > available {
                let lead = match (first, prefix) {
                    (true, Some(prefix)) => prefix.to_owned(),
                    _ => " ".repeat(indent),
                };
                self.push(format!("{lead}{line}"));
                first = false;
                line = word.to_owned();
            } else if line.is_empty() {
                line = word.to_owned();
            } else {
                line = format!("{line} {word}");
            }
        }
        if !line.is_empty() {
            let lead = match (first, prefix) {
                (true, Some(prefix)) => prefix.to_owned(),
                _ => " ".repeat(indent),
            };
            self.push(format!("{lead}{line}"));
        }
    }

    /// Renders one finding, with its location and any linked findings.
    fn finding(&mut self, entry: &Map<String, Value>, include_reason: bool) {
        let severity = finding_severity(entry);
        let title = clean(entry.get("title"));
        let badge = self.paint(&pad_end(&severity, 8), severity_color(&severity));
        self.wrap(&title, 14, Some(&format!("    {badge}  ")));

        let before = string_list(entry.get("beforeOccurrenceIds"));
        let after = string_list(entry.get("afterOccurrenceIds"));
        let grouped = if before.is_some() || after.is_some() {
            format!(
                "  {}  {} → {}",
                self.accent("·"),
                before.as_ref().map_or(1, Vec::len),
                after.as_ref().map_or(1, Vec::len)
            )
        } else {
            String::new()
        };

        let matches = object_list(entry.get("matches"));
        let known_scan_ids = string_list(entry.get("knownScanIds"));
        let known_scans = match &known_scan_ids {
            Some(ids) if !ids.is_empty() => {
                let first = truncate(&clean_str(&ids[0]), 8);
                let last = if ids.len() > 1 {
                    format!(" … {}", truncate(&clean_str(&ids[ids.len() - 1]), 8))
                } else {
                    String::new()
                };
                format!(" in {first}{last}")
            }
            _ => String::new(),
        };
        let known_since = match (
            self.command == HistoryCommand::Show,
            matches.as_ref().is_some_and(|found| !found.is_empty()),
            entry.get("knownSince").filter(|value| truthy(value)),
        ) {
            (true, true, Some(known_since)) => format!(
                "  {}  {}{known_scans}",
                self.accent("·"),
                self.strong(&format!(
                    "Known since {}",
                    format_known_since(&clean(Some(known_since)))
                ))
            ),
            _ => String::new(),
        };

        // A finding names either a path directly or its first location.
        let path = match entry.get("path").filter(|value| !value.is_null()) {
            Some(path) => clean(Some(path)),
            None => {
                let location = object_list(entry.get("locations"))
                    .and_then(|locations| locations.first().cloned());
                let line = location
                    .as_ref()
                    .and_then(|location| location.get("startLine").cloned())
                    .filter(truthy);
                format!(
                    "{}{}",
                    js_string(location.as_ref().and_then(|location| location.get("path"))),
                    line.map_or_else(String::new, |line| format!(":{}", js_string(Some(&line))))
                )
            }
        };
        self.push(format!(
            "              {}{grouped}{known_since}",
            self.dim(&clean_str(&path))
        ));

        let show_linked = self.command != HistoryCommand::Show || self.options.show_linked_findings;
        let has_matches = matches.as_ref().is_some_and(|found| !found.is_empty());
        if has_matches && show_linked {
            self.push(format!(
                "              {} {}",
                self.accent("↔"),
                self.strong("LINKED FINDINGS")
            ));
            for found in matches.iter().flatten() {
                self.push(format!(
                    "                {} {}",
                    self.strong("MATCHED SCAN"),
                    self.accent(&truncate(&clean(found.get("scanId")), 8))
                ));
                let title = clean(found.get("title"));
                self.wrap(&format!("↳ {title}"), 18, None);
            }
        }

        let reason = entry
            .get("matchReason")
            .filter(|value| truthy(value))
            .map(|value| clean(Some(value)))
            .or_else(|| {
                entry
                    .get("reason")
                    .filter(|value| truthy(value))
                    .map(|value| clean(Some(value)))
            })
            .or_else(|| {
                has_matches.then(|| {
                    let mut seen = Vec::new();
                    for found in matches.iter().flatten() {
                        let reason = clean(found.get("reason"));
                        if !seen.contains(&reason) {
                            seen.push(reason);
                        }
                    }
                    seen.join("; ")
                })
            })
            .filter(|reason| !reason.is_empty());

        if let Some(reason) = reason
            && include_reason
            && (!has_matches || show_linked)
        {
            if has_matches {
                self.push(format!(
                    "                {}",
                    self.strong("SAME ROOT CAUSE")
                ));
                self.wrap(&reason, 18, None);
            } else {
                self.wrap(&format!("↳ {reason}"), 14, None);
            }
        }
    }
}

impl Renderer<'_> {
    /// The list of scans for a repository.
    fn render_list(&mut self, result: &Map<String, Value>) {
        // A running scan nobody has updated for a day is assumed dead, and is
        // hidden rather than reported as still in progress.
        let now = self.options.now.unwrap_or(0);
        let scans: Vec<Map<String, Value>> = object_list(result.get("scans"))
            .unwrap_or_default()
            .into_iter()
            .filter(|scan| {
                let status = scan
                    .get("progress")
                    .and_then(Value::as_object)
                    .and_then(|progress| progress.get("status"));
                if status.and_then(Value::as_str) != Some("running") {
                    return true;
                }
                match scan.get("updatedAt").and_then(Value::as_str) {
                    None => true,
                    Some(updated) => parse_iso_millis(updated)
                        .is_none_or(|updated| now - updated < STALE_SCAN_MILLISECONDS),
                }
            })
            .collect();

        let repository = basename(&clean_str(
            &self
                .options
                .scan_root
                .clone()
                .or_else(|| self.options.repository.clone())
                .unwrap_or_else(|| {
                    scans
                        .first()
                        .map_or_else(String::new, |scan| js_string(scan.get("targetPath")))
                }),
        ));
        let latest = scans
            .iter()
            .find(|scan| {
                scan.get("progress")
                    .and_then(Value::as_object)
                    .and_then(|progress| progress.get("status"))
                    .and_then(Value::as_str)
                    == Some("complete")
            })
            .and_then(|scan| scan.get("findingCount"));

        // Several repositories only need naming when the caller did not pick
        // one, and only then is the extra column worth its width.
        let mut targets: Vec<String> = Vec::new();
        for scan in &scans {
            let target = js_string(scan.get("targetPath"));
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        let multiple = self.options.repository.is_none() && targets.len() > 1;
        let wide = self.width >= if multiple { 96 } else { 80 };

        let count = scans.len();
        let latest_note = latest.map_or_else(String::new, |latest| {
            format!(
                "  {}  latest: {} findings",
                self.accent("·"),
                clean(Some(latest))
            )
        });
        self.push(format!(
            "  {}  {}  {count} {}{latest_note}",
            self.strong(&repository),
            self.accent("·"),
            if count == 1 { "scan" } else { "scans" }
        ));
        self.push("");

        if wide {
            let repository_column = if multiple {
                format!(" {}", self.strong(&pad_end("REPOSITORY", 18)))
            } else {
                String::new()
            };
            self.push(format!(
                "  {} {} {}{repository_column} {} {}",
                self.strong(&pad_end("SCAN", 36)),
                self.strong(&pad_end("DATE", 10)),
                self.strong(&pad_end("MODE", 8)),
                self.strong("FINDINGS"),
                self.strong("STATUS")
            ));
        }

        for scan in &scans {
            let status = clean(
                scan.get("progress")
                    .and_then(Value::as_object)
                    .and_then(|progress| progress.get("status")),
            );
            let complete = status == "complete";
            let status_color = if complete {
                32
            } else if status == "running" {
                36
            } else {
                31
            };
            let status_label = self.paint(
                &format!(
                    "{} {}",
                    if complete { "✓" } else { "●" },
                    status.to_uppercase()
                ),
                status_color,
            );
            let started = truncate(&clean(scan.get("startedAt")), 10);
            let findings = clean(scan.get("findingCount"));
            let scan_repository = basename(&clean(scan.get("targetPath")));

            if wide {
                let repository_column = if multiple {
                    format!(" {}", pad_end(&truncate(&scan_repository, 18), 18))
                } else {
                    String::new()
                };
                self.push(format!(
                    "  {} {} {}{repository_column} {} {status_label}",
                    pad_end(&clean(scan.get("scanId")), 36),
                    pad_end(&started, 10),
                    pad_end(&clean(scan.get("mode")), 8),
                    pad_end(&findings, 8)
                ));
            } else {
                let repository_note = if multiple {
                    format!("  {}  {scan_repository}", self.accent("·"))
                } else {
                    String::new()
                };
                self.push(format!("  {}", clean(scan.get("scanId"))));
                self.push(format!(
                    "    {started}{repository_note}  {}  {findings} findings  {}  {status_label}",
                    self.accent("·"),
                    self.accent("·")
                ));
            }
        }
    }

    /// One scan in detail.
    fn render_show(&mut self, result: &Map<String, Value>) {
        let status = clean(
            result
                .get("progress")
                .and_then(Value::as_object)
                .and_then(|progress| progress.get("status")),
        );
        let status_color = if status == "complete" {
            32
        } else if status == "running" {
            36
        } else {
            31
        };
        self.push(format!(
            "  {}  {}  {}",
            self.strong(&basename(&js_string(result.get("targetPath")))),
            self.accent("·"),
            clean(result.get("scanId"))
        ));
        self.push(format!(
            "  {}  {}  {}",
            self.paint(
                &format!(
                    "{} {}",
                    if status == "complete" { "✓" } else { "●" },
                    status.to_uppercase()
                ),
                status_color
            ),
            self.accent("·"),
            clean(result.get("mode"))
        ));

        if let Some(failure) = result.get("failureMessage").filter(|value| truthy(value)) {
            let prefix = format!("  {}  ", self.paint("ERROR", 31));
            self.wrap(&js_string(Some(failure)), 11, Some(&prefix));
        }
        if let Some(parent) = result.get("parentScanId").filter(|value| truthy(value)) {
            self.push(format!(
                "  {}  {}",
                self.strong("PARENT SCAN"),
                truncate(&clean(Some(parent)), 8)
            ));
        }

        if let Some(summary) = result.get("severityCounts").and_then(Value::as_object) {
            // Zero counts say nothing, so they are left out entirely.
            let parts: Vec<String> = summary
                .iter()
                .filter(|(_, count)| truthy(count))
                .map(|(severity, count)| {
                    let label = severity.to_uppercase();
                    self.paint(
                        &format!("{} {label}", clean(Some(count))),
                        severity_color(&label),
                    )
                })
                .collect();
            self.push(format!(
                "  {}",
                parts.join(&format!("  {}  ", self.accent("·")))
            ));
        }

        let recipe = result.get("recipe").and_then(Value::as_object);
        if let Some(config) = recipe
            .and_then(|recipe| recipe.get("config"))
            .and_then(Value::as_object)
            .filter(|config| !config.is_empty())
        {
            let parts: Vec<String> = config
                .iter()
                .map(|(key, value)| format!("{}={}", clean_str(key), clean(Some(value))))
                .collect();
            self.push(format!(
                "  {}  {}",
                self.strong("CONFIGURATION"),
                parts.join(&format!("  {}  ", self.accent("·")))
            ));
        }

        if let Some(coverage) = result
            .get("progress")
            .and_then(Value::as_object)
            .and_then(|progress| progress.get("coverage"))
            .and_then(Value::as_object)
        {
            let mut parts = Vec::new();
            if let Some(worklist) = coverage
                .get("worklistRows")
                .filter(|value| !value.is_null())
            {
                parts.push(format!(
                    "{} of {} reviewed",
                    clean(coverage.get("closedRows")),
                    clean(Some(worklist))
                ));
            }
            if let Some(files) = coverage.get("filesTotal").filter(|value| !value.is_null()) {
                parts.push(format!("{} files", clean(Some(files))));
            }
            if !parts.is_empty() {
                self.push(format!(
                    "  {}  {}",
                    self.strong("COVERAGE"),
                    parts.join(&format!("  {}  ", self.accent("·")))
                ));
            }
        }

        if let Some(paths) = recipe
            .and_then(|recipe| recipe.get("knowledgeBasePaths"))
            .and_then(|value| string_list(Some(value)))
            .filter(|paths| !paths.is_empty())
        {
            let rendered: Vec<String> = paths
                .iter()
                .map(|path| self.dim(&clean_str(path)))
                .collect();
            self.push(format!(
                "  {}  {}",
                self.strong("KNOWLEDGE BASE"),
                rendered.join(", ")
            ));
        }

        if let Some(artifacts) = result
            .get("artifacts")
            .and_then(Value::as_object)
            .filter(|artifacts| !artifacts.is_empty())
        {
            self.push(format!("  {}", self.strong("ARTIFACTS")));
            let scan_directory = result
                .get("scanDir")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(directory) = &scan_directory {
                self.push(format!("    {}", self.dim(&clean_str(directory))));
            }
            for (kind, path) in artifacts {
                let label = split_camel_case(kind).to_uppercase();
                let artifact_path = match &scan_directory {
                    Some(directory) => relative_path(directory, &js_string(Some(path))),
                    None => js_string(Some(path)),
                };
                self.push(format!(
                    "    {}  {}",
                    self.strong(&pad_end(&clean_str(&label), 15)),
                    self.dim(&clean_str(&artifact_path))
                ));
            }
        }

        let findings = object_list(result.get("findings")).unwrap_or_default();
        if !findings.is_empty() {
            let count = result
                .get("findingCount")
                .and_then(Value::as_u64)
                .map_or(findings.len(), |count| {
                    usize::try_from(count).unwrap_or(findings.len())
                });
            // Saying "3 of 40" is the difference between a clean scan and a
            // truncated one.
            let truncated =
                result.get("findingsTruncated").is_some_and(truthy) || count > findings.len();
            let label = if truncated {
                format!("{} of {count}", findings.len())
            } else {
                count.to_string()
            };
            self.push("");
            self.push(format!(
                "  {}  {}",
                self.strong("FINDINGS"),
                self.strong(&label)
            ));
            for entry in &findings {
                self.push("");
                self.finding(entry, true);
            }
        }
    }

    /// One scan against another.
    fn render_compare(&mut self, result: &Map<String, Value>) {
        if let Some(repository) = result.get("repository").filter(|value| truthy(value)) {
            self.push(format!(
                "  {}",
                self.strong(&basename(&js_string(Some(repository))))
            ));
        }
        self.push(format!(
            "  {} → {}",
            truncate(&clean(result.get("beforeScanId")), 8),
            truncate(&clean(result.get("afterScanId")), 8)
        ));

        let completeness = result
            .get("coverage")
            .and_then(Value::as_object)
            .and_then(|coverage| coverage.get("afterCompleteness"));
        if completeness.and_then(Value::as_str) != Some("complete") {
            // Without full coverage, "resolved" only means "not seen again".
            self.push(format!(
                "  {}",
                self.paint(
                    &format!(
                        "⚠ Follow-up coverage is {}; resolved findings cannot be confirmed.",
                        clean(completeness)
                    ),
                    33
                )
            ));
        }

        // A finding outside the later scope was not re-examined, which is not
        // the same as its outcome being unknown.
        let findings: Vec<Map<String, Value>> = object_list(result.get("findings"))
            .unwrap_or_default()
            .into_iter()
            .map(|mut entry| {
                let unknown = entry.get("status").and_then(Value::as_str) == Some("unknown");
                let outside = entry.get("reason").and_then(Value::as_str) == Some(OUTSIDE_SCOPE);
                if unknown && outside {
                    entry.insert(
                        "status".to_owned(),
                        Value::String("not_rescanned".to_owned()),
                    );
                }
                entry
            })
            .collect();
        let not_rescanned = findings
            .iter()
            .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("not_rescanned"))
            .count();

        let mut summary = result
            .get("summary")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if not_rescanned > 0 {
            let unknown = summary
                .get("unknown")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let moved = i64::try_from(not_rescanned).unwrap_or_default();
            summary.insert("unknown".to_owned(), Value::from(unknown - moved));
            summary.insert("not_rescanned".to_owned(), Value::from(moved));
        }

        self.push("");
        let mut summary_line = String::from("  ");
        let mut summary_length = 2;
        for (status, color, icon) in STATUS_STYLES {
            let Some(value) = summary.get(status).filter(|value| truthy(value)) else {
                continue;
            };
            let label = format!("{icon} {} {}", clean(Some(value)), status.replace('_', " "));
            let length = label.chars().count();
            if summary_length > 2 && summary_length + length + 4 > self.width - 2 {
                self.push(summary_line);
                summary_line = String::from("  ");
                summary_length = 2;
            }
            let separator = if summary_length > 2 { "    " } else { "" };
            summary_line.push_str(&format!("{separator}{}", self.paint(&label, color)));
            summary_length += length + if summary_length > 2 { 4 } else { 0 };
        }
        if summary_length > 2 {
            self.push(summary_line);
        }

        for (status, color, icon) in STATUS_STYLES {
            let mut group: Vec<Map<String, Value>> = findings
                .iter()
                .filter(|entry| clean(entry.get("status")).to_lowercase() == status)
                .cloned()
                .collect();
            if group.is_empty() {
                continue;
            }
            // Most severe first, so the worst outcome leads each group.
            group.sort_by_key(|entry| severity_rank(&finding_severity(entry)));

            let title = format!(
                "{icon} {}{}",
                status[..1].to_uppercase(),
                status[1..].replace('_', " ")
            );
            let heading = format!(
                "{title} ({} finding{})",
                group.len(),
                if group.len() == 1 { "" } else { "s" }
            );
            let rule = "━".repeat(std::cmp::max(
                2,
                self.width
                    .saturating_sub(heading.chars().count())
                    .saturating_sub(8),
            ));
            self.push("");
            self.push(format!(
                "  {}",
                self.paint(&format!("━━ {heading} {rule}"), color)
            ));
            if status == "not_rescanned" {
                self.push(format!(
                    "    {}",
                    self.accent("Outside follow-up scan coverage")
                ));
            }
            for entry in &group {
                self.push("");
                self.finding(entry, status != "not_rescanned");
            }
        }
    }

    /// A summary of matching a whole history.
    fn render_match_all(&mut self, result: &Map<String, Value>) {
        self.push(format!(
            "  {}",
            self.strong(&basename(&js_string(result.get("repository"))))
        ));
        self.push("");
        self.push(format!(
            "  {} {} scans    {} {} comparisons    {} {} root-cause matches",
            self.paint("●", 36),
            clean(result.get("scanCount")),
            self.paint("↔", 36),
            clean(result.get("matchedPairs")),
            self.paint("◆", 32),
            clean(result.get("findingMatches"))
        ));
        if let Some(unavailable) = result.get("unavailableScans").filter(|value| truthy(value)) {
            self.push(format!(
                "  {}",
                self.paint(
                    &format!("{} scans unavailable", clean(Some(unavailable))),
                    33
                )
            ));
        }
    }
}

/// Splits `camelCase` into words, as the artifact labels are drawn.
fn split_camel_case(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 4);
    let mut previous_lower = false;
    for character in value.chars() {
        if previous_lower && character.is_ascii_uppercase() {
            result.push(' ');
        }
        previous_lower = character.is_ascii_lowercase();
        result.push(character);
    }
    result
}

/// Whether a JSON value is truthy the way JavaScript judges it.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(value)`, as JavaScript would produce it.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                // Array joining renders null and undefined as nothing.
                Value::Null => String::new(),
                item => js_string(Some(item)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
    }
}

/// Strips escape sequences and neutralises control characters.
fn clean(value: Option<&Value>) -> String {
    clean_str(&js_string(value))
}

/// Strips CSI escape sequences, then replaces any remaining control character
/// with a space.
fn clean_str(value: &str) -> String {
    let mut without_escapes = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.peek() == Some(&'[') {
            characters.next();
            // Parameter bytes, then intermediate bytes, then one final byte.
            while characters
                .peek()
                .is_some_and(|next| ('\u{30}'..='\u{3f}').contains(next))
            {
                characters.next();
            }
            while characters
                .peek()
                .is_some_and(|next| ('\u{20}'..='\u{2f}').contains(next))
            {
                characters.next();
            }
            if characters
                .peek()
                .is_some_and(|next| ('\u{40}'..='\u{7e}').contains(next))
            {
                characters.next();
            }
            continue;
        }
        without_escapes.push(character);
    }

    without_escapes
        .chars()
        .map(|character| {
            if character <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Splits on runs of whitespace, the way JavaScript's `split(/\s+/)` does.
///
/// A leading run produces an empty first element, which the wrapper then
/// ignores; reproducing that keeps wrapping identical for padded input.
fn split_whitespace_js(value: &str) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_whitespace = false;
    for (index, character) in value.chars().enumerate() {
        if character.is_whitespace() {
            if !in_whitespace {
                words.push(std::mem::take(&mut current));
                in_whitespace = true;
            }
        } else {
            if in_whitespace || index == 0 {
                in_whitespace = false;
            }
            current.push(character);
        }
    }
    if !current.is_empty() || in_whitespace {
        words.push(current);
    }
    words
}

fn pad_end(value: &str, width: usize) -> String {
    let length = value.chars().count();
    if length >= width {
        return value.to_owned();
    }
    format!("{value}{}", " ".repeat(width - length))
}

fn truncate(value: &str, length: usize) -> String {
    value.chars().take(length).collect()
}

/// The severity of a finding, uppercased.
///
/// A severity is either a bare level or an object carrying one.
fn finding_severity(entry: &Map<String, Value>) -> String {
    let severity = entry.get("severity");
    let value = match severity {
        Some(Value::String(_)) => severity,
        Some(Value::Object(object)) => object.get("level"),
        other => other,
    };
    clean(value).to_uppercase()
}

fn severity_color(severity: &str) -> u8 {
    SEVERITY_COLORS
        .iter()
        .find(|(name, _)| *name == severity)
        .map_or(37, |(_, color)| *color)
}

/// Where a severity ranks, for ordering findings.
fn severity_rank(severity: &str) -> i32 {
    SEVERITY_COLORS
        .iter()
        .position(|(name, _)| *name == severity)
        .map_or(-1, |index| i32::try_from(index).unwrap_or(-1))
}

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    Some(
        value?
            .as_array()?
            .iter()
            .map(|item| js_string(Some(item)))
            .collect(),
    )
}

fn object_list(value: Option<&Value>) -> Option<Vec<Map<String, Value>>> {
    Some(
        value?
            .as_array()?
            .iter()
            .filter_map(|item| item.as_object().cloned())
            .collect(),
    )
}

/// The last component of a path, as `basename` reports it.
fn basename(value: &str) -> String {
    Path::new(value).file_name().map_or_else(
        || {
            // A path that is only separators has no name.
            if value.is_empty() {
                String::new()
            } else {
                value.to_owned()
            }
        },
        |name| name.to_string_lossy().into_owned(),
    )
}

/// `to` expressed relative to `from`, as `relative` reports it.
fn relative_path(from: &str, to: &str) -> String {
    Path::new(to).strip_prefix(from).map_or_else(
        |_| to.to_owned(),
        |path| path.to_string_lossy().into_owned(),
    )
}

/// An ISO timestamp as `Mon D, YYYY` in UTC.
fn format_known_since(value: &str) -> String {
    let Some(milliseconds) = parse_iso_millis(value) else {
        return "Invalid Date".to_owned();
    };
    let days = milliseconds.div_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let name = MONTHS
        .get(usize::try_from(month).unwrap_or(1).saturating_sub(1))
        .copied()
        .unwrap_or("Jan");
    format!("{name} {day}, {year}")
}

/// Milliseconds since the epoch for an ISO 8601 timestamp.
pub fn parse_iso_millis(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let number = |start: usize, length: usize| -> Option<i64> {
        std::str::from_utf8(bytes.get(start..start + length)?)
            .ok()?
            .parse()
            .ok()
    };
    let (year, month, day) = (number(0, 4)?, number(5, 2)?, number(8, 2)?);
    let (hour, minute, second) = if bytes.len() > 18 {
        (
            number(11, 2).unwrap_or(0),
            number(14, 2).unwrap_or(0),
            number(17, 2).unwrap_or(0),
        )
    } else {
        (0, 0, 0)
    };
    let days = days_from_civil(year, month, day);
    Some(((days * 86_400) + hour * 3_600 + minute * 60 + second) * 1_000)
}

/// Days since the Unix epoch for a civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
