//! Scoring scans against a corpus of known flaws.
//!
//! Reads scan output that already exists rather than running scans itself.
//! Scoring and scanning are separate jobs: a corpus can be re-scored after the
//! rules change without spending another run, and a scan made by any means —
//! any model, any endpoint — can be scored the same way.

use std::path::Path;

use puncode_security::benchmark::{
    BenchmarkReport, Comparison, GroundTruth, ReportedFinding, ReportedLocation, Shortfall,
    Thresholds, compare, score_fixture,
};
use serde_json::Value;

/// Scores every fixture that has a scan directory under `results`.
///
/// A fixture with no scan directory is reported as unscanned rather than as
/// zero found — those are different facts, and conflating them would make a
/// missing run look like a total failure to detect.
pub fn run(ground_truth: &Path, results: &Path, corpus_root: &Path) -> Result<Report, String> {
    let text = std::fs::read_to_string(ground_truth)
        .map_err(|error| format!("Could not read {}: {error}", ground_truth.display()))?;
    let corpus = GroundTruth::parse(&text)?;

    let mut scores = Vec::new();
    let mut unscanned = Vec::new();

    for fixture in &corpus.fixtures {
        let findings_path = results.join(&fixture.name).join("findings.json");
        let Ok(body) = std::fs::read_to_string(&findings_path) else {
            unscanned.push(fixture.name.clone());
            continue;
        };
        let findings = parse_findings(&body, corpus_root, &fixture.path)?;
        scores.push(score_fixture(fixture, &findings));
    }

    Ok(Report {
        report: BenchmarkReport { scores },
        unscanned,
    })
}

/// A scored corpus, plus what could not be scored.
pub struct Report {
    pub report: BenchmarkReport,
    pub unscanned: Vec<String>,
}

/// Pulls the locations out of a findings document.
///
/// Only the title and where it points are needed; everything else a scan says
/// about a finding is prose, and scoring on prose would measure wording.
fn parse_findings(
    body: &str,
    corpus_root: &Path,
    fixture_path: &str,
) -> Result<Vec<ReportedFinding>, String> {
    let document: Value =
        serde_json::from_str(body).map_err(|error| format!("findings are not JSON: {error}"))?;
    let items = document
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Findings cite paths relative to the repository that was scanned; the
    // corpus records them relative to its own root.
    let prefix = corpus_root.join(fixture_path);

    Ok(items
        .iter()
        .map(|item| ReportedFinding {
            title: item
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("(untitled)")
                .to_owned(),
            severity: item
                .get("severity")
                .and_then(|severity| severity.get("level"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            locations: locations(item, &prefix),
        })
        .collect())
}

/// Every place a finding points at.
fn locations(item: &Value, prefix: &Path) -> Vec<ReportedLocation> {
    item.get("locations")
        .and_then(Value::as_array)
        .map(|found| {
            found
                .iter()
                .filter_map(|location| {
                    let file = location.get("path").and_then(Value::as_str)?;
                    let line = location
                        .get("startLine")
                        .or_else(|| location.get("line"))
                        .and_then(Value::as_u64)
                        .unwrap_or(1);
                    Some(ReportedLocation {
                        file: prefix.join(file).to_string_lossy().into_owned(),
                        line: u32::try_from(line).unwrap_or(u32::MAX),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The same numbers, for another program.
///
/// Includes what was missed and what matched nothing, because a machine reading
/// this is usually deciding whether something regressed, and a bare rate cannot
/// say which flaw stopped being found.
#[must_use]
pub fn render_json(outcome: &Report, shortfalls: &[Shortfall]) -> String {
    let report = &outcome.report;
    let fixtures: Vec<Value> = report
        .scores
        .iter()
        .map(|score| {
            serde_json::json!({
                "fixture": score.fixture,
                "control": score.control,
                "planted": score.planted(),
                "found": score.found(),
                "missed": score.missed(),
                "unmatched": score.unmatched,
                "decoysTripped": score.decoys_tripped,
            })
        })
        .collect();
    let by_class: serde_json::Map<String, Value> = report
        .by_cwe()
        .into_iter()
        .map(|(class, (found, planted))| {
            (
                class,
                serde_json::json!({ "found": found, "planted": planted }),
            )
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        // Absent rather than zero when nothing was planted: an undefined rate
        // and a rate of zero are different facts.
        "detectionRate": report.detection_rate(),
        "planted": report.planted(),
        "found": report.found(),
        "falsePositives": report.false_positives(),
        "controlFalsePositives": report.control_false_positives(),
        "fixtures": fixtures,
        "byClass": by_class,
        "severityAgreement": report.severity_agreement().map(|(agreed, comparable)| {
            serde_json::json!({ "agreed": agreed, "comparable": comparable })
        }),
        "severityDisagreements": report
            .severity_disagreements()
            .into_iter()
            .map(|(id, expected, reported)| {
                serde_json::json!({ "flaw": id, "corpus": expected, "scan": reported })
            })
            .collect::<Vec<_>>(),
        "unscanned": outcome.unscanned,
        "shortfalls": shortfalls.iter().map(Shortfall::describe).collect::<Vec<_>>(),
    }))
    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
}

/// Every way the run fell short of what was asked of it.
#[must_use]
pub fn shortfalls(
    outcome: &Report,
    min_detection: Option<f64>,
    max_false_positives: Option<usize>,
) -> Vec<Shortfall> {
    outcome.report.shortfalls(&Thresholds {
        min_detection,
        max_false_positives,
    })
}

/// What changed between an earlier run and this one.
pub fn against_baseline(
    ground_truth: &Path,
    baseline: &Path,
    current: &Report,
    corpus_root: &Path,
) -> Result<Comparison, String> {
    let earlier = run(ground_truth, baseline, corpus_root)?;
    Ok(compare(&earlier.report, &current.report))
}

/// The comparison, for a person.
#[must_use]
pub fn render_comparison(comparison: &Comparison) -> String {
    let mut lines = vec![
        String::new(),
        "Against the baseline".to_owned(),
        String::new(),
    ];

    if comparison.newly_missed.is_empty()
        && comparison.newly_found.is_empty()
        && comparison.severity_moved.is_empty()
    {
        lines.push("  nothing changed".to_owned());
    }
    for id in &comparison.newly_missed {
        lines.push(format!(
            "  LOST     {id} was found before and is not found now"
        ));
    }
    for id in &comparison.newly_found {
        lines.push(format!("  gained   {id} is found now and was not before"));
    }
    for (id, before, after) in &comparison.severity_moved {
        lines.push(format!("  moved    {id}: {before} then, {after} now"));
    }
    if !comparison.not_comparable.is_empty() {
        // Said rather than silently skipped: a corpus that changed shape is not
        // a regression, but pretending those flaws were compared would be a lie.
        lines.push(format!(
            "  {} flaw(s) only one run could find, so not compared: {}",
            comparison.not_comparable.len(),
            comparison.not_comparable.join(", ")
        ));
    }

    if comparison.regressed() {
        lines.push(String::new());
        // A red result must not imply more certainty than one run supports.
        lines.push(
            "One run is weak evidence: this model's output varies between runs over unchanged"
                .to_owned(),
        );
        lines.push("code. Repeat before concluding something broke.".to_owned());
    }

    lines.join("\n")
}

/// The report, for a person.
#[must_use]
pub fn render(outcome: &Report) -> String {
    let report = &outcome.report;
    let mut lines = vec!["Detection".to_owned(), String::new()];

    for score in &report.scores {
        if score.control {
            let fooled = if score.decoys_tripped.is_empty() {
                String::new()
            } else {
                // Named, because being fooled by code written to look dangerous
                // is a different failure from inventing something from nothing.
                format!("   fooled by: {}", score.decoys_tripped.join(", "))
            };
            lines.push(format!(
                "  {:<20} control — {} false positive(s){fooled}",
                score.fixture,
                score.unmatched.len()
            ));
            continue;
        }
        let missed = score.missed();
        lines.push(format!(
            "  {:<20} {} of {} found{}",
            score.fixture,
            score.found(),
            score.planted(),
            if missed.is_empty() {
                String::new()
            } else {
                format!("   missed: {}", missed.join(", "))
            }
        ));
    }

    lines.push(String::new());
    match report.detection_rate() {
        Some(rate) => lines.push(format!(
            "  detection      {:.0}%  ({} of {})",
            rate * 100.0,
            report.found(),
            report.planted()
        )),
        // Not zero: a rate over no opportunities is undefined.
        None => lines.push("  detection      not measured — nothing was planted".to_owned()),
    }
    lines.push(format!(
        "  unmatched      {}  ({} on fixtures with nothing planted)",
        report.false_positives(),
        report.control_false_positives()
    ));

    // Reported as agreement, never as accuracy. Severity is a judgement, and
    // the corpus is one opinion about it.
    if let Some((agreed, comparable)) = report.severity_agreement() {
        lines.push(format!(
            "  severity       {agreed} of {comparable} rated as the corpus does"
        ));
        for (id, expected, reported) in report.severity_disagreements() {
            lines.push(format!(
                "                 {id}: corpus {expected}, scan {reported}"
            ));
        }
    }

    let by_class = report.by_cwe();
    if !by_class.is_empty() {
        lines.push(String::new());
        lines.push("By class".to_owned());
        lines.push(String::new());
        for (class, (found, planted)) in by_class {
            lines.push(format!("  {class:<16} {found} of {planted}"));
        }
    }

    if !outcome.unscanned.is_empty() {
        lines.push(String::new());
        // Said plainly: an absent scan is not a failure to detect, and the
        // totals above do not account for it either way.
        lines.push(format!(
            "Not scanned, and not counted above: {}",
            outcome.unscanned.join(", ")
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn corpus_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn reads_a_findings_document() {
        let body = json!({
            "findings": [{
                "title": "SQL injection",
                "severity": { "level": "high" },
                "locations": [{ "path": "src/app.py", "startLine": 10 }],
            }]
        })
        .to_string();

        let findings = parse_findings(&body, Path::new("/corpus"), "fixtures/flask-injection")
            .expect("parses");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL injection");
        assert_eq!(findings[0].locations[0].line, 10);
        assert!(
            findings[0].locations[0]
                .file
                .ends_with("fixtures/flask-injection/src/app.py"),
            "{:?}",
            findings[0].locations[0].file
        );
    }

    /// A finding with nowhere to point cannot match anything, and must not
    /// crash the scoring.
    #[test]
    fn tolerates_a_finding_without_locations() {
        let body = json!({ "findings": [{ "title": "vague" }] }).to_string();

        let findings = parse_findings(&body, Path::new("/corpus"), "f").expect("parses");

        assert_eq!(findings.len(), 1);
        assert!(findings[0].locations.is_empty());
    }

    #[test]
    fn tolerates_a_document_with_no_findings() {
        for body in ["{}", r#"{"findings":[]}"#] {
            let findings = parse_findings(body, Path::new("/corpus"), "f").expect("parses");
            assert!(findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn refuses_something_that_is_not_json() {
        assert!(parse_findings("not json", Path::new("/corpus"), "f").is_err());
    }

    /// An unscanned fixture is not a fixture that found nothing.
    #[test]
    fn reports_an_unscanned_fixture_separately() {
        let empty = tempfile::tempdir().expect("a directory");

        let outcome = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            empty.path(),
            &corpus_dir(),
        )
        .expect("runs");

        assert!(outcome.report.scores.is_empty());
        assert!(!outcome.unscanned.is_empty());
        let rendered = render(&outcome);
        assert!(rendered.contains("Not scanned"), "{rendered}");
        assert!(rendered.contains("not counted above"), "{rendered}");
    }

    #[test]
    fn scores_a_scan_against_the_shipped_corpus() {
        let results = tempfile::tempdir().expect("a directory");
        let fixture = results.path().join("flask-injection");
        std::fs::create_dir_all(&fixture).expect("creates");
        std::fs::write(
            fixture.join("findings.json"),
            json!({
                "findings": [
                    { "title": "SQL injection",
                      "locations": [{ "path": "src/app.py", "startLine": 10 }] },
                    { "title": "Command injection",
                      "locations": [{ "path": "src/app.py", "startLine": 15 }] },
                ]
            })
            .to_string(),
        )
        .expect("writes");

        let outcome = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            results.path(),
            &corpus_dir(),
        )
        .expect("runs");

        assert_eq!(outcome.report.found(), 2);
        assert_eq!(outcome.report.false_positives(), 0);
    }

    /// The rendering must not report an undefined rate as zero.
    #[test]
    fn does_not_render_an_unmeasured_rate_as_zero() {
        let outcome = Report {
            report: BenchmarkReport { scores: Vec::new() },
            unscanned: Vec::new(),
        };

        let rendered = render(&outcome);

        assert!(rendered.contains("not measured"), "{rendered}");
        assert!(!rendered.contains("0%"), "{rendered}");
    }
}
