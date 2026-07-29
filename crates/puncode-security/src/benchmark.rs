//! Measuring whether a scan actually finds what is there.
//!
//! Not a port: upstream has no notion of a corpus with known answers.
//!
//! A scan produces findings; nobody can say whether they are the right ones
//! without something to check them against. This scores a scan against a corpus
//! of deliberately planted flaws, so "is this model any good at this?" has a
//! number rather than an impression.
//!
//! Two properties matter and only one of them is obvious. Detection says how
//! much was found. **False positives say whether anyone will keep using the
//! tool** — a scanner that cries wolf is switched off, and then it finds
//! nothing at all. The corpus therefore carries a fixture with nothing planted
//! in it, and anything reported there counts against the score.
//!
//! Matching is by location, never by wording. A model that calls something
//! "OS command injection" and one that calls it "unsafe subprocess invocation"
//! have found the same flaw, and scoring them differently would measure
//! vocabulary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How far from a planted line a finding may sit and still be that flaw.
///
/// A model may point at the vulnerable call, the assignment feeding it, or the
/// enclosing handler. All three are the same flaw found; insisting on the exact
/// line would measure precision of citation rather than detection.
pub const LINE_TOLERANCE: u32 = 12;

/// A flaw deliberately placed in a fixture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlantedFlaw {
    pub id: String,
    pub file: String,
    /// Inclusive first and last line where the flaw is expressed.
    pub lines: (u32, u32),
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// One fixture and everything planted in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub flaws: Vec<PlantedFlaw>,
    /// A fixture with nothing planted, kept to measure false positives.
    #[serde(default)]
    pub control: bool,
}

/// The corpus as a whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub fixtures: Vec<Fixture>,
}

impl GroundTruth {
    /// Reads a corpus description.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|error| format!("ground truth is not usable: {error}"))
    }

    /// The fixture of that name, if the corpus has one.
    #[must_use]
    pub fn fixture(&self, name: &str) -> Option<&Fixture> {
        self.fixtures.iter().find(|fixture| fixture.name == name)
    }
}

/// Where a scan says a finding is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedLocation {
    pub file: String,
    pub line: u32,
}

/// What a scan reported, reduced to what scoring needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedFinding {
    pub title: String,
    pub severity: Option<String>,
    /// Every location the finding cites. A finding matches if any of them do.
    pub locations: Vec<ReportedLocation>,
}

/// What became of one planted flaw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlawOutcome {
    pub flaw_id: String,
    pub cwe: Option<String>,
    /// The title of the finding that matched, if one did.
    pub found_as: Option<String>,
}

impl FlawOutcome {
    #[must_use]
    pub fn found(&self) -> bool {
        self.found_as.is_some()
    }
}

/// How a scan did against one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureScore {
    pub fixture: String,
    pub control: bool,
    pub outcomes: Vec<FlawOutcome>,
    /// Findings that matched nothing planted.
    ///
    /// On a control fixture every finding lands here, which is the point of
    /// having one.
    pub unmatched: Vec<String>,
}

impl FixtureScore {
    #[must_use]
    pub fn found(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.found())
            .count()
    }

    #[must_use]
    pub fn planted(&self) -> usize {
        self.outcomes.len()
    }

    #[must_use]
    pub fn missed(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|outcome| !outcome.found())
            .map(|outcome| outcome.flaw_id.as_str())
            .collect()
    }
}

/// Scores one fixture's findings against what was planted in it.
///
/// A planted flaw is matched by at most one finding and a finding matches at
/// most one flaw, so neither one finding covering everything nor ten findings
/// on one line can inflate the result.
#[must_use]
pub fn score_fixture(fixture: &Fixture, findings: &[ReportedFinding]) -> FixtureScore {
    let mut claimed: Vec<bool> = vec![false; findings.len()];
    let mut outcomes = Vec::with_capacity(fixture.flaws.len());

    for flaw in &fixture.flaws {
        let matched = findings
            .iter()
            .enumerate()
            .find(|(index, finding)| !claimed[*index] && cites(finding, flaw));
        let found_as = matched.map(|(index, finding)| {
            claimed[index] = true;
            finding.title.clone()
        });
        outcomes.push(FlawOutcome {
            flaw_id: flaw.id.clone(),
            cwe: flaw.cwe.clone(),
            found_as,
        });
    }

    let unmatched = findings
        .iter()
        .enumerate()
        .filter(|(index, _)| !claimed[*index])
        .map(|(_, finding)| finding.title.clone())
        .collect();

    FixtureScore {
        fixture: fixture.name.clone(),
        control: fixture.control,
        outcomes,
        unmatched,
    }
}

/// Whether a finding points at where a flaw was planted.
fn cites(finding: &ReportedFinding, flaw: &PlantedFlaw) -> bool {
    finding.locations.iter().any(|location| {
        same_file(&location.file, &flaw.file) && within_tolerance(location.line, flaw.lines)
    })
}

/// Whether two paths name the same file.
///
/// A scan may report a path relative to the repository, relative to a
/// subdirectory, or absolute. Comparing from the right-hand end matches all
/// three without accepting a file that merely ends similarly, because the
/// comparison is per path segment.
fn same_file(reported: &str, planted: &str) -> bool {
    let reported: Vec<&str> = reported
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let planted: Vec<&str> = planted.split('/').filter(|part| !part.is_empty()).collect();
    if reported.is_empty() || planted.is_empty() {
        return false;
    }
    let shared = reported.len().min(planted.len());
    reported[reported.len() - shared..] == planted[planted.len() - shared..]
}

fn within_tolerance(line: u32, planted: (u32, u32)) -> bool {
    let (first, last) = planted;
    line + LINE_TOLERANCE >= first && line <= last.saturating_add(LINE_TOLERANCE)
}

/// The whole corpus scored together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkReport {
    pub scores: Vec<FixtureScore>,
}

impl BenchmarkReport {
    #[must_use]
    pub fn planted(&self) -> usize {
        self.scores.iter().map(FixtureScore::planted).sum()
    }

    #[must_use]
    pub fn found(&self) -> usize {
        self.scores.iter().map(FixtureScore::found).sum()
    }

    /// Findings that matched nothing planted, anywhere in the corpus.
    #[must_use]
    pub fn false_positives(&self) -> usize {
        self.scores.iter().map(|score| score.unmatched.len()).sum()
    }

    /// False positives from fixtures with nothing planted at all.
    ///
    /// Reported separately because it admits no argument: there was nothing
    /// there to find.
    #[must_use]
    pub fn control_false_positives(&self) -> usize {
        self.scores
            .iter()
            .filter(|score| score.control)
            .map(|score| score.unmatched.len())
            .sum()
    }

    /// The share of planted flaws that were found, in `0.0..=1.0`.
    ///
    /// `None` when the corpus plants nothing, because a rate over no
    /// opportunities is not zero — it is undefined, and reporting it as zero
    /// would look like total failure.
    #[must_use]
    pub fn detection_rate(&self) -> Option<f64> {
        let planted = self.planted();
        if planted == 0 {
            return None;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "corpus sizes are far below the precision limit"
        )]
        Some(self.found() as f64 / planted as f64)
    }

    /// Detection broken down by CWE, as (found, planted).
    ///
    /// This is where a corpus earns its keep: an aggregate rate hides that a
    /// model finds every injection and no memory-safety flaw.
    #[must_use]
    pub fn by_cwe(&self) -> BTreeMap<String, (usize, usize)> {
        let mut totals: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for outcome in self.scores.iter().flat_map(|score| &score.outcomes) {
            let key = outcome
                .cwe
                .clone()
                .unwrap_or_else(|| "unclassified".to_owned());
            let entry = totals.entry(key).or_insert((0, 0));
            entry.1 += 1;
            if outcome.found() {
                entry.0 += 1;
            }
        }
        totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flaw(id: &str, file: &str, first: u32, last: u32, cwe: &str) -> PlantedFlaw {
        PlantedFlaw {
            id: id.to_owned(),
            file: file.to_owned(),
            lines: (first, last),
            cwe: Some(cwe.to_owned()),
            severity: None,
            summary: None,
        }
    }

    fn finding(title: &str, file: &str, line: u32) -> ReportedFinding {
        ReportedFinding {
            title: title.to_owned(),
            severity: None,
            locations: vec![ReportedLocation {
                file: file.to_owned(),
                line,
            }],
        }
    }

    fn fixture(flaws: Vec<PlantedFlaw>) -> Fixture {
        Fixture {
            name: "f".to_owned(),
            path: "fixtures/f".to_owned(),
            language: None,
            flaws,
            control: false,
        }
    }

    #[test]
    fn counts_a_flaw_found_at_its_line() {
        let subject = fixture(vec![flaw("a", "src/app.py", 10, 10, "CWE-89")]);

        let score = score_fixture(&subject, &[finding("SQL injection", "src/app.py", 10)]);

        assert_eq!(score.found(), 1);
        assert!(score.unmatched.is_empty());
    }

    /// Two models describing one flaw differently have both found it. Scoring
    /// on wording would measure vocabulary, not detection.
    #[test]
    fn matches_on_location_not_on_wording() {
        let subject = fixture(vec![flaw("a", "src/app.py", 15, 15, "CWE-78")]);

        for title in [
            "OS command injection",
            "Unsafe subprocess invocation",
            "Shell metacharacter injection in /ping",
        ] {
            let score = score_fixture(&subject, &[finding(title, "src/app.py", 15)]);
            assert_eq!(score.found(), 1, "{title}");
        }
    }

    /// A model may cite the vulnerable call, the assignment feeding it, or the
    /// enclosing handler.
    #[test]
    fn accepts_a_nearby_line() {
        let subject = fixture(vec![flaw("a", "src/app.py", 20, 20, "CWE-89")]);

        for line in [20 - LINE_TOLERANCE, 20, 20 + LINE_TOLERANCE] {
            let score = score_fixture(&subject, &[finding("found", "src/app.py", line)]);
            assert_eq!(score.found(), 1, "line {line}");
        }
    }

    #[test]
    fn rejects_a_line_well_away_from_the_flaw() {
        let subject = fixture(vec![flaw("a", "src/app.py", 20, 20, "CWE-89")]);

        let score = score_fixture(&subject, &[finding("elsewhere", "src/app.py", 200)]);

        assert_eq!(score.found(), 0);
        assert_eq!(score.unmatched, ["elsewhere"]);
    }

    #[test]
    fn rejects_the_right_line_in_the_wrong_file() {
        let subject = fixture(vec![flaw("a", "src/app.py", 10, 10, "CWE-89")]);

        let score = score_fixture(&subject, &[finding("wrong file", "src/other.py", 10)]);

        assert_eq!(score.found(), 0);
    }

    /// Paths arrive relative, absolute, or relative to somewhere else.
    #[test]
    fn matches_the_same_file_however_its_path_is_written() {
        let subject = fixture(vec![flaw("a", "src/app.py", 10, 10, "CWE-89")]);

        for reported in [
            "src/app.py",
            "/home/someone/repo/src/app.py",
            "./src/app.py",
        ] {
            let score = score_fixture(&subject, &[finding("found", reported, 10)]);
            assert_eq!(score.found(), 1, "{reported}");
        }
    }

    /// Segment-wise comparison, so a file that merely ends similarly is not
    /// mistaken for the planted one.
    #[test]
    fn does_not_match_a_file_that_only_ends_alike() {
        let subject = fixture(vec![flaw("a", "src/app.py", 10, 10, "CWE-89")]);

        let score = score_fixture(&subject, &[finding("no", "src/notapp.py", 10)]);

        assert_eq!(score.found(), 0);
    }

    /// One finding cannot cover two flaws, or a single vague report would score
    /// as though it had found everything.
    #[test]
    fn one_finding_claims_only_one_flaw() {
        let subject = fixture(vec![
            flaw("a", "src/app.py", 10, 10, "CWE-89"),
            flaw("b", "src/app.py", 12, 12, "CWE-78"),
        ]);

        let score = score_fixture(
            &subject,
            &[finding("something is wrong here", "src/app.py", 11)],
        );

        assert_eq!(score.found(), 1);
        assert_eq!(score.missed().len(), 1);
    }

    /// Nor can repeating the same finding inflate the count.
    #[test]
    fn repeated_findings_do_not_inflate_the_score() {
        let subject = fixture(vec![flaw("a", "src/app.py", 10, 10, "CWE-89")]);

        let score = score_fixture(
            &subject,
            &[
                finding("SQL injection", "src/app.py", 10),
                finding("SQL injection again", "src/app.py", 10),
                finding("and again", "src/app.py", 10),
            ],
        );

        assert_eq!(score.found(), 1);
        assert_eq!(score.unmatched.len(), 2, "the surplus is not free");
    }

    /// The number that decides whether anyone keeps the tool switched on.
    #[test]
    fn every_finding_on_a_control_fixture_is_a_false_positive() {
        let mut subject = fixture(Vec::new());
        subject.control = true;

        let score = score_fixture(&subject, &[finding("imagined", "src/inventory.py", 30)]);
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.control_false_positives(), 1);
        assert_eq!(report.found(), 0);
    }

    #[test]
    fn a_quiet_control_fixture_costs_nothing() {
        let mut subject = fixture(Vec::new());
        subject.control = true;

        let report = BenchmarkReport {
            scores: vec![score_fixture(&subject, &[])],
        };

        assert_eq!(report.control_false_positives(), 0);
        assert_eq!(report.detection_rate(), None, "nothing was planted");
    }

    /// A rate over no opportunities is undefined, not zero — reporting zero
    /// would read as total failure.
    #[test]
    fn reports_no_rate_when_nothing_was_planted() {
        let report = BenchmarkReport {
            scores: vec![score_fixture(&fixture(Vec::new()), &[])],
        };

        assert_eq!(report.detection_rate(), None);
    }

    #[test]
    fn reports_the_share_that_was_found() {
        let subject = fixture(vec![
            flaw("a", "src/app.py", 10, 10, "CWE-89"),
            flaw("b", "src/app.py", 40, 40, "CWE-78"),
            flaw("c", "src/app.py", 80, 80, "CWE-22"),
        ]);

        let report = BenchmarkReport {
            scores: vec![score_fixture(
                &subject,
                &[
                    finding("one", "src/app.py", 10),
                    finding("two", "src/app.py", 40),
                ],
            )],
        };

        assert!(
            (report.detection_rate().expect("a rate") - 2.0 / 3.0).abs() < 1e-9,
            "{:?}",
            report.detection_rate()
        );
    }

    /// An aggregate rate hides that a model finds every injection and no
    /// memory-safety flaw, which is the thing worth knowing.
    #[test]
    fn breaks_detection_down_by_class() {
        let subject = fixture(vec![
            flaw("a", "src/app.py", 10, 10, "CWE-89"),
            flaw("b", "src/app.py", 40, 40, "CWE-89"),
            flaw("c", "src/store.c", 20, 20, "CWE-416"),
        ]);

        let report = BenchmarkReport {
            scores: vec![score_fixture(
                &subject,
                &[
                    finding("one", "src/app.py", 10),
                    finding("two", "src/app.py", 40),
                ],
            )],
        };

        let by_class = report.by_cwe();
        assert_eq!(by_class["CWE-89"], (2, 2));
        assert_eq!(by_class["CWE-416"], (0, 1), "memory safety was missed");
    }

    #[test]
    fn a_flaw_spanning_lines_is_matched_anywhere_within_it() {
        let subject = fixture(vec![flaw("a", "src/store.c", 33, 36, "CWE-416")]);

        for line in [33, 34, 35, 36] {
            let score = score_fixture(&subject, &[finding("uaf", "src/store.c", line)]);
            assert_eq!(score.found(), 1, "line {line}");
        }
    }

    #[test]
    fn reads_the_shipped_corpus() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../benchmark/ground-truth.json"),
        )
        .expect("the corpus is shipped");

        let corpus = GroundTruth::parse(&text).expect("the corpus parses");

        assert!(corpus.fixture("flask-injection").is_some());
        let control = corpus.fixture("clean-python").expect("a control fixture");
        assert!(control.control, "the control fixture must be marked as one");
        assert!(control.flaws.is_empty(), "nothing may be planted in it");
    }

    /// Every path and line in the corpus must point at a file that exists,
    /// otherwise the benchmark silently scores against fiction.
    #[test]
    fn every_planted_flaw_points_at_a_real_line() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("benchmark/ground-truth.json"))
            .expect("the corpus is shipped");
        let corpus = GroundTruth::parse(&text).expect("the corpus parses");

        for fixture in &corpus.fixtures {
            for flaw in &fixture.flaws {
                let path = root.join(&fixture.path).join(&flaw.file);
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|_| panic!("{} names {}", flaw.id, path.display()));
                let lines = u32::try_from(body.lines().count()).unwrap_or(u32::MAX);
                assert!(
                    flaw.lines.0 >= 1 && flaw.lines.1 <= lines,
                    "{} points at lines {:?} of a {}-line file",
                    flaw.id,
                    flaw.lines,
                    lines
                );
            }
        }
    }
}
