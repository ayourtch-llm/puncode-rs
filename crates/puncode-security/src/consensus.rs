//! Telling stable findings apart from noise.
//!
//! Not a port: upstream reports one scan at a time.
//!
//! Scan the same code twice and you do not get the same answer. Across the runs
//! this was built against, findings appeared and vanished, severities moved
//! between high and critical, and the same flaw arrived under three different
//! titles. A reviewer reading one report cannot tell which findings would
//! survive a second look.
//!
//! This takes several runs over the same target and reports how many of them
//! saw each finding. A flaw reported by three runs of three is a different
//! proposition from one reported once, and that difference is what a reviewer
//! needs in order to spend attention well.
//!
//! **Agreement is not truth.** Runs sharing a blind spot agree exactly as
//! readily as runs being right, and three runs of one model agree more easily
//! than three different models would. What this measures is stability. Nothing
//! here should be read as a second opinion in the sense of an independent one,
//! unless the runs really were independent.

use std::collections::BTreeMap;

use crate::benchmark::{ReportedFinding, ReportedLocation};

/// How far apart two locations may be and still be the same flaw.
///
/// Deliberately tighter than the benchmark's tolerance. There the question is
/// "did the model find the thing we planted", where pointing at the enclosing
/// handler counts. Here it is "are these two reports the same thing", and
/// merging two genuinely distinct flaws that happen to sit close together would
/// hide one of them.
pub const MERGE_TOLERANCE: u32 = 4;

/// One finding, and how many runs reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreedFinding {
    /// The titles each run gave it, in run order, deduplicated.
    ///
    /// Kept in full rather than reduced to one: when runs disagree about what
    /// something is, that disagreement is worth seeing.
    pub titles: Vec<String>,
    /// Where the finding sits, from the first run that reported it.
    pub locations: Vec<ReportedLocation>,
    /// Which runs saw it, by index.
    pub runs: Vec<usize>,
    /// How many runs there were in total.
    pub total_runs: usize,
    /// The weakness class every run in this group named, when they named one.
    ///
    /// Runs that named different classes are not in the same group at all —
    /// see [`merge`] — so this holds at most one value, and holding none means
    /// no run said.
    pub cwe: Option<String>,
    /// Severities reported, deduplicated and sorted.
    ///
    /// More than one entry means the runs disagreed about how bad it is.
    pub severities: Vec<String>,
}

impl AgreedFinding {
    /// How many runs reported it.
    #[must_use]
    pub fn agreement(&self) -> usize {
        self.runs.len()
    }

    /// Whether every run saw it.
    #[must_use]
    pub fn unanimous(&self) -> bool {
        self.agreement() == self.total_runs
    }

    /// Whether exactly one run saw it.
    ///
    /// Not a synonym for wrong. A single run may be the only one that looked
    /// carefully enough, which is why these are reported rather than dropped.
    #[must_use]
    pub fn solitary(&self) -> bool {
        self.agreement() == 1
    }

    /// The shortest title, as the one to lead with.
    ///
    /// Shortest rather than first: a run's ordering is arbitrary, and the
    /// briefest phrasing is usually the one naming the flaw rather than
    /// describing the circumstances.
    #[must_use]
    pub fn headline(&self) -> &str {
        self.titles
            .iter()
            .min_by_key(|title| title.len())
            .map_or("(untitled)", String::as_str)
    }

    /// Whether the runs disagreed about severity.
    #[must_use]
    pub fn severity_disputed(&self) -> bool {
        self.severities.len() > 1
    }
}

/// Findings from several runs, merged by where they point.
///
/// Within one run, two findings never merge: a run reporting the same flaw
/// twice is a fact about that run, and collapsing them would hide it.
#[must_use]
pub fn merge(runs: &[Vec<ReportedFinding>]) -> Vec<AgreedFinding> {
    let total_runs = runs.len();
    let mut merged: Vec<AgreedFinding> = Vec::new();

    for (index, findings) in runs.iter().enumerate() {
        for finding in findings {
            // Only groups this run has not already contributed to, so one run
            // cannot count twice towards its own agreement.
            // Same place is not enough. Two runs naming different weaknesses
            // at one line have not agreed about anything, and merging them
            // reports agreement where there is none — which is the whole
            // output of this command. Seen for real: a timing-unsafe
            // comparison called CWE-208 by one run and CWE-306, weak
            // authentication, by another, merged into "2 of 7".
            let existing = merged.iter_mut().find(|group| {
                !group.runs.contains(&index)
                    && overlaps(&group.locations, finding)
                    && compatible_class(group.cwe.as_deref(), finding.cwe.as_deref())
            });

            match existing {
                Some(group) => {
                    if !group.titles.contains(&finding.title) {
                        group.titles.push(finding.title.clone());
                    }
                    // A run that names a class fills one in for a group that
                    // had none; a group that already has one keeps it, since
                    // the two were only merged because they agree.
                    if group.cwe.is_none() {
                        group.cwe.clone_from(&finding.cwe);
                    }
                    group.runs.push(index);
                    if let Some(severity) = &finding.severity
                        && !group.severities.contains(severity)
                    {
                        group.severities.push(severity.clone());
                        group.severities.sort();
                    }
                }
                None => merged.push(AgreedFinding {
                    titles: vec![finding.title.clone()],
                    cwe: finding.cwe.clone(),
                    locations: finding.locations.clone(),
                    runs: vec![index],
                    total_runs,
                    severities: finding.severity.clone().into_iter().collect(),
                }),
            }
        }
    }

    // Most agreed first: a reviewer's attention is the scarce resource.
    merged.sort_by(|left, right| {
        right
            .agreement()
            .cmp(&left.agreement())
            .then_with(|| left.headline().cmp(right.headline()))
    });
    merged
}

/// Whether two stated classes can belong to the same finding.
///
/// A run that names no class has not disagreed with anything, so it merges
/// freely: penalising a scan for leaving a taxonomy field empty would measure
/// form-filling. Only two runs that both name a class, and name different ones,
/// are kept apart.
fn compatible_class(group: Option<&str>, finding: Option<&str>) -> bool {
    match (group, finding) {
        (Some(group), Some(finding)) => group.eq_ignore_ascii_case(finding),
        _ => true,
    }
}

/// Whether a finding points anywhere the group already covers.
fn overlaps(locations: &[ReportedLocation], finding: &ReportedFinding) -> bool {
    finding.locations.iter().any(|candidate| {
        locations.iter().any(|known| {
            known.file == candidate.file && known.line.abs_diff(candidate.line) <= MERGE_TOLERANCE
        })
    })
}

/// A summary of how much the runs agreed with each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementSummary {
    pub total_runs: usize,
    pub distinct: usize,
    pub unanimous: usize,
    pub solitary: usize,
    pub severity_disputes: usize,
}

/// Summarises a merged set.
#[must_use]
pub fn summarise(findings: &[AgreedFinding], total_runs: usize) -> AgreementSummary {
    AgreementSummary {
        total_runs,
        distinct: findings.len(),
        unanimous: findings.iter().filter(|f| f.unanimous()).count(),
        solitary: findings.iter().filter(|f| f.solitary()).count(),
        severity_disputes: findings.iter().filter(|f| f.severity_disputed()).count(),
    }
}

/// Findings grouped by how many runs saw them, most agreed first.
#[must_use]
pub fn by_agreement(findings: &[AgreedFinding]) -> BTreeMap<usize, Vec<&AgreedFinding>> {
    let mut grouped: BTreeMap<usize, Vec<&AgreedFinding>> = BTreeMap::new();
    for finding in findings {
        grouped
            .entry(finding.agreement())
            .or_default()
            .push(finding);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(title: &str, file: &str, line: u32) -> ReportedFinding {
        ReportedFinding {
            title: title.to_owned(),
            cwe: None,
            severity: None,
            locations: vec![ReportedLocation {
                file: file.to_owned(),
                line,
            }],
        }
    }

    fn graded(title: &str, file: &str, line: u32, severity: &str) -> ReportedFinding {
        ReportedFinding {
            severity: Some(severity.to_owned()),
            ..at(title, file, line)
        }
    }

    #[test]
    fn a_finding_every_run_saw_is_unanimous() {
        let merged = merge(&[
            vec![at("SQL injection", "app.py", 10)],
            vec![at("SQL injection", "app.py", 10)],
            vec![at("SQL injection", "app.py", 10)],
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agreement(), 3);
        assert!(merged[0].unanimous());
    }

    /// The whole point: two runs describing one flaw differently have found the
    /// same flaw, and grouping on titles would report it as two.
    #[test]
    fn groups_the_same_flaw_described_differently() {
        let merged = merge(&[
            vec![at("OS command injection", "app.py", 15)],
            vec![at(
                "Unsafe subprocess invocation with shell=True",
                "app.py",
                15,
            )],
        ]);

        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(merged[0].agreement(), 2);
        assert_eq!(merged[0].titles.len(), 2, "both phrasings are kept");
    }

    #[test]
    fn keeps_distinct_flaws_apart() {
        let merged = merge(&[
            vec![
                at("SQL injection", "app.py", 10),
                at("Command injection", "app.py", 40),
            ],
            vec![
                at("SQL injection", "app.py", 10),
                at("Command injection", "app.py", 40),
            ],
        ]);

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(AgreedFinding::unanimous));
    }

    /// Tighter than the benchmark's tolerance on purpose: merging two genuinely
    /// distinct flaws that sit close together would hide one of them.
    #[test]
    fn does_not_merge_flaws_that_are_merely_nearby() {
        let merged = merge(&[
            vec![at("one", "app.py", 10)],
            vec![at("two", "app.py", 10 + MERGE_TOLERANCE + 1)],
        ]);

        assert_eq!(merged.len(), 2, "{merged:?}");
        assert!(merged.iter().all(AgreedFinding::solitary));
    }

    #[test]
    fn merges_a_report_a_line_or_two_away() {
        let merged = merge(&[
            vec![at("one", "app.py", 10)],
            vec![at("two", "app.py", 10 + MERGE_TOLERANCE)],
        ]);

        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn does_not_merge_across_files() {
        let merged = merge(&[
            vec![at("one", "app.py", 10)],
            vec![at("two", "other.py", 10)],
        ]);

        assert_eq!(merged.len(), 2);
    }

    /// A run reporting the same flaw twice is a fact about that run. Letting it
    /// count twice would manufacture agreement out of one run's repetition.
    #[test]
    fn one_run_cannot_agree_with_itself() {
        let merged = merge(&[
            vec![
                at("SQL injection", "app.py", 10),
                at("SQL injection again", "app.py", 10),
            ],
            vec![at("SQL injection", "app.py", 10)],
        ]);

        let best = merged
            .iter()
            .map(AgreedFinding::agreement)
            .max()
            .expect("a group");
        assert_eq!(
            best, 2,
            "no group may claim more runs than exist: {merged:?}"
        );
        assert!(merged.iter().all(|group| {
            let mut seen = group.runs.clone();
            seen.sort_unstable();
            seen.dedup();
            seen.len() == group.runs.len()
        }));
    }

    /// Reported, not discarded. One run may be the only one that looked
    /// carefully enough, and dropping it would lose a real finding silently.
    #[test]
    fn keeps_a_finding_only_one_run_saw() {
        let merged = merge(&[vec![at("seen once", "app.py", 10)], vec![], vec![]]);

        assert_eq!(merged.len(), 1);
        assert!(merged[0].solitary());
        assert_eq!(
            merged[0].total_runs, 3,
            "the denominator is what makes it readable"
        );
    }

    #[test]
    fn orders_the_most_agreed_first() {
        let merged = merge(&[
            vec![at("once", "app.py", 10), at("thrice", "app.py", 50)],
            vec![at("thrice", "app.py", 50)],
            vec![at("thrice", "app.py", 50)],
        ]);

        assert_eq!(merged[0].headline(), "thrice");
        assert_eq!(merged[0].agreement(), 3);
        assert_eq!(merged[1].agreement(), 1);
    }

    /// Runs disagreeing about how bad something is, is worth surfacing rather
    /// than silently picking one.
    #[test]
    fn records_a_severity_the_runs_disagreed_on() {
        let merged = merge(&[
            vec![graded("SQLi", "app.py", 10, "high")],
            vec![graded("SQLi", "app.py", 10, "critical")],
        ]);

        assert!(merged[0].severity_disputed());
        assert_eq!(merged[0].severities, ["critical", "high"]);
    }

    #[test]
    fn does_not_invent_a_dispute_when_the_runs_agree() {
        let merged = merge(&[
            vec![graded("SQLi", "app.py", 10, "high")],
            vec![graded("SQLi", "app.py", 10, "high")],
        ]);

        assert!(!merged[0].severity_disputed());
    }

    #[test]
    fn summarises_a_set() {
        let merged = merge(&[
            vec![at("both", "app.py", 10), at("only here", "app.py", 60)],
            vec![at("both", "app.py", 10)],
        ]);

        let summary = summarise(&merged, 2);

        assert_eq!(summary.distinct, 2);
        assert_eq!(summary.unanimous, 1);
        assert_eq!(summary.solitary, 1);
    }

    #[test]
    fn a_single_run_is_all_solitary_and_all_unanimous() {
        let merged = merge(&[vec![at("alone", "app.py", 10)]]);

        // Both, and neither is misleading: one of one is every run there was.
        assert!(merged[0].unanimous());
        assert!(merged[0].solitary());
    }

    #[test]
    fn no_runs_yields_nothing() {
        assert!(merge(&[]).is_empty());
        assert_eq!(summarise(&[], 0).distinct, 0);
    }

    #[test]
    fn runs_that_found_nothing_still_count_in_the_denominator() {
        let merged = merge(&[vec![at("found", "app.py", 10)], vec![], vec![]]);

        assert_eq!(merged[0].total_runs, 3);
        assert_eq!(merged[0].agreement(), 1);
    }

    #[test]
    fn groups_by_how_many_runs_agreed() {
        let merged = merge(&[
            vec![at("both", "app.py", 10), at("one", "app.py", 60)],
            vec![at("both", "app.py", 10)],
        ]);

        let grouped = by_agreement(&merged);

        assert_eq!(grouped[&2].len(), 1);
        assert_eq!(grouped[&1].len(), 1);
    }

    /// A finding with nowhere to point cannot be matched to anything, and must
    /// not merge with everything by default.
    #[test]
    fn a_finding_without_a_location_does_not_swallow_others() {
        let vague = ReportedFinding {
            title: "something somewhere".to_owned(),
            cwe: None,
            severity: None,
            locations: Vec::new(),
        };

        let merged = merge(&[vec![vague], vec![at("specific", "app.py", 10)]]);

        assert_eq!(merged.len(), 2, "{merged:?}");
    }
}

#[cfg(test)]
mod class_tests {
    use super::*;

    fn finding(title: &str, line: u32, cwe: Option<&str>, severity: &str) -> ReportedFinding {
        ReportedFinding {
            title: title.to_owned(),
            severity: Some(severity.to_owned()),
            cwe: cwe.map(str::to_owned),
            locations: vec![ReportedLocation {
                file: "src/server.js".to_owned(),
                line,
            }],
        }
    }

    /// The real case, from seven runs of the same fixture. One run found the
    /// timing-unsafe comparison; another found a different weakness at the same
    /// endpoint — the token travelling in a query string. Merging them reported
    /// "2 of 7" and a severity dispute, and neither had happened.
    #[test]
    fn two_weaknesses_at_one_place_are_not_agreement() {
        let runs = vec![
            vec![finding(
                "Timing side-channel in admin token comparison",
                35,
                Some("CWE-208"),
                "low",
            )],
            vec![finding(
                "Weak authentication in /admin endpoint exposes token via GET",
                33,
                Some("CWE-306"),
                "medium",
            )],
        ];

        let merged = merge(&runs);

        assert_eq!(merged.len(), 2, "{merged:?}");
        for group in &merged {
            assert_eq!(group.agreement(), 1);
            // And neither is reported as disputed, because nothing disputed it.
            assert_eq!(group.severities.len(), 1, "{group:?}");
        }
    }

    /// Runs that name the same class still merge however differently they word
    /// it — scoring on wording would measure vocabulary.
    #[test]
    fn the_same_class_merges_across_different_wording() {
        let runs = vec![
            vec![finding(
                "Path traversal in /file",
                12,
                Some("CWE-22"),
                "high",
            )],
            vec![finding(
                "Path Traversal via /file?name= allows arbitrary read",
                13,
                Some("CWE-22"),
                "high",
            )],
        ];

        let merged = merge(&runs);

        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(merged[0].agreement(), 2);
        assert_eq!(merged[0].titles.len(), 2);
        assert_eq!(merged[0].cwe.as_deref(), Some("CWE-22"));
    }

    /// A run that names no class has not disagreed with anything. Penalising a
    /// scan for leaving the field empty would measure form-filling.
    #[test]
    fn a_run_that_names_no_class_still_merges() {
        let runs = vec![
            vec![finding("Path traversal", 12, Some("CWE-22"), "high")],
            vec![finding("Path traversal", 12, None, "high")],
        ];

        let merged = merge(&runs);

        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(merged[0].agreement(), 2);
        // The class survives from the run that named one.
        assert_eq!(merged[0].cwe.as_deref(), Some("CWE-22"));
    }

    /// And the class is filled in whichever order the runs arrive.
    #[test]
    fn the_class_is_taken_from_whichever_run_named_it() {
        let runs = vec![
            vec![finding("Path traversal", 12, None, "high")],
            vec![finding("Path traversal", 12, Some("CWE-22"), "high")],
        ];

        assert_eq!(merge(&runs)[0].cwe.as_deref(), Some("CWE-22"));
    }

    /// Case is not a disagreement.
    #[test]
    fn class_comparison_ignores_case() {
        let runs = vec![
            vec![finding("Traversal", 12, Some("CWE-22"), "high")],
            vec![finding("Traversal", 12, Some("cwe-22"), "high")],
        ];

        assert_eq!(merge(&runs).len(), 1);
    }
}
