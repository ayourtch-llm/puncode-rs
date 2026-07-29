//! Scoring scans against a corpus of known flaws.
//!
//! Reads scan output that already exists rather than running scans itself.
//! Scoring and scanning are separate jobs: a corpus can be re-scored after the
//! rules change without spending another run, and a scan made by any means —
//! any model, any endpoint — can be scored the same way.

use std::path::Path;

use puncode_security::benchmark::{
    BenchmarkReport, Comparison, GroundTruth, ReportedFinding, ReportedLocation, Shortfall,
    Thresholds, compare, deferrals_from_coverage, score_fixture_with_deferrals,
};
use puncode_security::corpus_audit::{Leak, audit_fixture, describe as describe_leak};
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
    let mut leaks = Vec::new();

    for fixture in &corpus.fixtures {
        // Audited whether or not it was scanned. A corpus that gives its
        // answers away is worth saying even when there is no number to qualify.
        leaks.extend(audit_fixture(
            &fixture.name,
            &corpus_root.join(&fixture.path),
        ));
        let findings_path = results.join(&fixture.name).join("findings.json");
        let Ok(body) = std::fs::read_to_string(&findings_path) else {
            unscanned.push(fixture.name.clone());
            continue;
        };
        let findings = parse_findings(&body, corpus_root, &fixture.path)?;
        // Absent is ordinary: a scan made by another tool has no coverage
        // document, and one that is unreadable is not a reason to refuse to
        // score the findings. Either way the result is fewer deferrals known,
        // which shows up as "never noticed" rather than as a silent pass.
        let deferrals = std::fs::read_to_string(results.join(&fixture.name).join("coverage.json"))
            .ok()
            .and_then(|body| deferrals_from_coverage(&body).ok())
            .unwrap_or_default();
        scores.push(score_fixture_with_deferrals(fixture, &findings, &deferrals));
    }

    Ok(Report {
        report: BenchmarkReport { scores },
        unscanned,
        leaks,
    })
}

/// A scored corpus, plus what could not be scored.
pub struct Report {
    pub report: BenchmarkReport,
    pub unscanned: Vec<String>,
    /// Text in a fixture that names what is planted in it.
    ///
    /// Carried beside the score rather than checked separately, because the
    /// two must be read together: a detection rate measured over a corpus that
    /// gives its answers away is not a detection rate, and it looks exactly
    /// like one.
    pub leaks: Vec<Leak>,
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
                "neverNoticed": score.never_noticed(),
                "deferred": score.deferred().into_iter().map(|(id, deferral)| {
                    serde_json::json!({ "flaw": id, "reason": deferral.reason })
                }).collect::<Vec<_>>(),
                "unmatched": score.unmatched,
                "decoysTripped": score.decoys_tripped,
                "decoysDeferred": score.decoys_deferred,
                "unattributedDeferrals": score.unattributed_deferrals,
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
        // Kept apart from the rate on purpose: a deferral is not a detection,
        // and a scanner that explained every flaw away would still score zero.
        "neverNoticed": report.never_noticed(),
        "deferred": report.deferred(),
        "unattributedDeferrals": report.unattributed_deferrals(),
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
        // Named "corpusLeaks" rather than folded into shortfalls: a threshold
        // says the run fell short, this says the measurement is not one.
        "corpusLeaks": outcome.leaks.iter().map(|leak| serde_json::json!({
            "fixture": leak.fixture,
            "file": leak.file,
            "line": leak.line,
            "phrase": leak.phrase,
            "text": leak.text,
        })).collect::<Vec<_>>(),
        "shortfalls": shortfalls.iter().map(Shortfall::describe).collect::<Vec<_>>(),
    }))
    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
}

/// A deferral's reasoning, short enough to read in a table.
///
/// Truncation announces itself, because a reason cut off mid-sentence can read
/// as the opposite of what it said.
fn trim_reason(reason: &str) -> String {
    const LIMIT: usize = 96;
    let flat = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= LIMIT {
        return flat;
    }
    let kept: String = flat.chars().take(LIMIT).collect();
    format!("{kept}… (cut; full text in coverage.json)")
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
    let mut lines = Vec::new();

    // Before the numbers, never after. Somebody reading a score stops at the
    // score, and this is the fact that decides whether the score means
    // anything at all.
    if !outcome.leaks.is_empty() {
        lines.push("THE CORPUS GIVES ITS ANSWERS AWAY".to_owned());
        lines.push(String::new());
        for leak in &outcome.leaks {
            lines.push(format!("  {}", describe_leak(leak)));
        }
        lines.push(String::new());
        lines.push(
            "A scan reads its whole target, so these numbers measure reading and not".to_owned(),
        );
        lines.push("detection. Take the text out and run it again.".to_owned());
        lines.push(String::new());
    }

    lines.push("Detection".to_owned());
    lines.push(String::new());

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
            if !score.decoys_deferred.is_empty() {
                // The good outcome, and invisible without saying it: the scan
                // looked at code written to fool it and stopped short.
                lines.push(format!(
                    "  {:<20} nearly fooled, then stopped short: {}",
                    "",
                    score.decoys_deferred.join(", ")
                ));
            }
            continue;
        }
        let never = score.never_noticed();
        lines.push(format!(
            "  {:<20} {} of {} found{}",
            score.fixture,
            score.found(),
            score.planted(),
            if never.is_empty() {
                String::new()
            } else {
                format!("   never noticed: {}", never.join(", "))
            }
        ));
        for (id, deferral) in score.deferred() {
            // Deliberately not folded in with the misses. The scan reported
            // neither, but one of them it had never seen and the other it
            // looked at and argued about, and those call for different repairs.
            lines.push(format!("  {:<20} set aside, not reported: {id}", ""));
            if let Some(reason) = &deferral.reason {
                lines.push(format!("  {:<20}   \"{}\"", "", trim_reason(reason)));
            }
        }
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
    if report.deferred() > 0 || report.never_noticed() > 0 {
        // The split that the detection rate cannot express. A blind spot needs
        // a better scanner; a deferral needs someone to read the reasoning and
        // agree or not.
        lines.push(format!(
            "  not reported   {} never noticed, {} seen and set aside",
            report.never_noticed(),
            report.deferred()
        ));
    }
    if report.unattributed_deferrals() > 0 {
        // Said rather than dropped: scoring that quietly discards what it
        // cannot place looks more complete than it is.
        lines.push(format!(
            "  unaccounted    {} deferral(s) the corpus could not place",
            report.unattributed_deferrals()
        ));
    }

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

    pub(super) fn corpus_dir() -> std::path::PathBuf {
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

        let findings =
            parse_findings(&body, Path::new("/corpus"), "fixtures/orders-api").expect("parses");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL injection");
        assert_eq!(findings[0].locations[0].line, 10);
        assert!(
            findings[0].locations[0]
                .file
                .ends_with("fixtures/orders-api/src/app.py"),
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
        let fixture = results.path().join("orders-api");
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
            leaks: Vec::new(),
        };

        let rendered = render(&outcome);

        assert!(rendered.contains("not measured"), "{rendered}");
        assert!(!rendered.contains("0%"), "{rendered}");
    }

    /// The two runs that both scored 88% were not the same result, and the
    /// report has to say so.
    #[test]
    fn distinguishes_a_blind_spot_from_a_judgement() {
        let results = tempfile::tempdir().expect("a directory");
        let fixture = results.path().join("link-service");
        std::fs::create_dir_all(&fixture).expect("creates");
        std::fs::write(
            fixture.join("findings.json"),
            json!({ "findings": [
                { "title": "Traversal", "locations": [{ "path": "src/server.js", "startLine": 12 }] },
                { "title": "SSRF", "locations": [{ "path": "src/server.js", "startLine": 22 }] },
            ]})
            .to_string(),
        )
        .expect("writes");

        // First without a coverage document: nothing says the third was seen.
        let blind = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            results.path(),
            &corpus_dir(),
        )
        .expect("runs");
        let rendered = render(&blind);
        assert!(
            rendered.contains("never noticed: timing-unsafe-compare"),
            "{rendered}"
        );

        // Then with the coverage document that run actually wrote.
        std::fs::copy(
            corpus_dir().join("crates/puncode-security/tests/data/coverage-node-traversal.json"),
            fixture.join("coverage.json"),
        )
        .expect("copies");
        let judged = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            results.path(),
            &corpus_dir(),
        )
        .expect("runs");
        let rendered = render(&judged);

        assert!(
            rendered.contains("set aside, not reported: timing-unsafe-compare"),
            "{rendered}"
        );
        assert!(rendered.contains("environment variable"), "{rendered}");
        assert!(
            rendered.contains("0 never noticed, 1 seen and set aside"),
            "{rendered}"
        );
        // And the rate is unchanged: a deferral is not a detection.
        assert_eq!(
            blind.report.detection_rate(),
            judged.report.detection_rate()
        );
        assert_eq!(judged.report.found(), 2);
    }

    /// An unreadable coverage document must not stop the findings being scored.
    #[test]
    fn scores_findings_even_when_the_coverage_document_is_broken() {
        let results = tempfile::tempdir().expect("a directory");
        let fixture = results.path().join("orders-api");
        std::fs::create_dir_all(&fixture).expect("creates");
        std::fs::write(
            fixture.join("findings.json"),
            json!({ "findings": [
                { "title": "SQLi", "locations": [{ "path": "src/app.py", "startLine": 10 }] },
            ]})
            .to_string(),
        )
        .expect("writes");
        std::fs::write(fixture.join("coverage.json"), "{ not json").expect("writes");

        let outcome = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            results.path(),
            &corpus_dir(),
        )
        .expect("runs");

        assert_eq!(outcome.report.found(), 1);
        // With nothing readable to say otherwise, the other flaw is a blind
        // spot rather than a judgement. Erring that way is the honest default.
        assert_eq!(outcome.report.never_noticed(), 1);
        assert_eq!(outcome.report.deferred(), 0);
    }

    /// Truncation has to announce itself: a reason cut mid-sentence can read as
    /// the opposite of what it said.
    #[test]
    fn a_cut_reason_says_it_was_cut() {
        let long = "safe because ".repeat(40);

        let trimmed = trim_reason(&long);

        assert!(trimmed.contains("cut"), "{trimmed}");
        assert!(trimmed.contains("coverage.json"), "{trimmed}");
        assert!(trimmed.len() < long.len());
    }

    #[test]
    fn a_short_reason_is_left_alone() {
        assert_eq!(
            trim_reason("token comes from the environment"),
            "token comes from the environment"
        );
    }
}

#[cfg(test)]
mod corpus_audit_tests {
    use super::tests::corpus_dir;
    use super::*;

    /// A compromised corpus must be said before the number it invalidates, not
    /// after. Whoever is reading a score stops at the score.
    #[test]
    fn a_leaking_corpus_is_announced_above_the_numbers() {
        let outcome = Report {
            report: BenchmarkReport { scores: Vec::new() },
            unscanned: Vec::new(),
            leaks: vec![Leak {
                fixture: "kv-store".to_owned(),
                file: "src/store.c".to_owned(),
                line: 19,
                phrase: "use after free".to_owned(),
                text: "/* Use after free: the record is released ... */".to_owned(),
            }],
        };

        let rendered = render(&outcome);

        let warning = rendered
            .find("GIVES ITS ANSWERS AWAY")
            .expect("the warning");
        let numbers = rendered.find("Detection").expect("the numbers");
        assert!(warning < numbers, "{rendered}");
        assert!(rendered.contains("src/store.c:19"), "{rendered}");
        assert!(rendered.contains("measure reading and not"), "{rendered}");
    }

    /// And a clean corpus must not be nagged about.
    #[test]
    fn a_clean_corpus_says_nothing() {
        let outcome = Report {
            report: BenchmarkReport { scores: Vec::new() },
            unscanned: Vec::new(),
            leaks: Vec::new(),
        };

        assert!(!render(&outcome).contains("ANSWERS AWAY"));
    }

    /// The shipped corpus, through the command a person actually runs.
    #[test]
    fn the_shipped_corpus_is_audited_by_bench_itself() {
        let empty = tempfile::tempdir().expect("a directory");

        let outcome = run(
            &corpus_dir().join("benchmark/ground-truth.json"),
            empty.path(),
            &corpus_dir(),
        )
        .expect("runs");

        assert!(
            outcome.leaks.is_empty(),
            "{}",
            outcome
                .leaks
                .iter()
                .map(describe_leak)
                .collect::<Vec<_>>()
                .join("\n")
        );
        // Proof the audit ran at all rather than finding nothing because it
        // looked nowhere: the fixtures must be where the corpus says they are.
        for fixture in [
            "orders-api",
            "kv-store",
            "link-service",
            "inventory-service",
        ] {
            assert!(
                corpus_dir().join("fixtures").join(fixture).is_dir(),
                "{fixture}"
            );
        }
    }

    /// A machine reading the score needs the same warning.
    #[test]
    fn the_structured_form_carries_the_leaks() {
        let outcome = Report {
            report: BenchmarkReport { scores: Vec::new() },
            unscanned: Vec::new(),
            leaks: vec![Leak {
                fixture: "f".to_owned(),
                file: "a.py".to_owned(),
                line: 3,
                phrase: "sql injection".to_owned(),
                text: "# sql injection below".to_owned(),
            }],
        };

        let structured = render_json(&outcome, &[]);

        assert!(structured.contains("corpusLeaks"), "{structured}");
        assert!(structured.contains("sql injection"), "{structured}");
    }
}
