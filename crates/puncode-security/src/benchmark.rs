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

/// How far a same-class finding in the same file may sit and still be that flaw.
///
/// Wider than [`LINE_TOLERANCE`] because it rests on two agreeing signals
/// rather than one. A real run cited an off-by-one fifteen lines from where it
/// is, which proximity alone could not have credited to the right flaw — and
/// did not: it credited the flaw to a different finding entirely.
pub const CLASS_TOLERANCE: u32 = 60;

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

/// Code written to resemble something unsafe while being safe.
///
/// A finding against one of these is a false positive of the kind that costs
/// most: the reviewer has to read it to discover it is wrong. An empty control
/// only asks whether a scanner invents findings from nothing, which is the easy
/// case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decoy {
    pub id: String,
    pub file: String,
    pub lines: (u32, u32),
    /// The class it is written to look like.
    #[serde(default)]
    pub resembles: Option<String>,
    /// Why it is genuinely safe.
    #[serde(default)]
    pub safe_because: Option<String>,
}

/// Where a deferral points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeferredSpan {
    pub file: String,
    /// Inclusive first and last line.
    pub lines: (u32, u32),
}

/// Something a scan looked at, judged, and consciously set aside.
///
/// This is neither a finding nor a miss, and collapsing it into either loses
/// the fact that matters most. A scanner that never noticed a flaw has a blind
/// spot; one that noticed it and wrote down why it was not reporting it has
/// made a judgement you can read and disagree with. The first needs a better
/// scanner and the second needs a conversation, so a score that shows only
/// "not found" points at the wrong repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deferral {
    pub id: String,
    /// Why the scan set it aside, in its own words.
    #[serde(default)]
    pub reason: Option<String>,
    /// Files the deferral names, without lines.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Where it points, when the scan said precisely enough.
    #[serde(default)]
    pub spans: Vec<DeferredSpan>,
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
    /// Safe code written to look unsafe.
    #[serde(default)]
    pub decoys: Vec<Decoy>,
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
    /// The weakness class the scan assigned, when it assigned one.
    pub cwe: Option<String>,
    /// Every location the finding cites. A finding matches if any of them do.
    pub locations: Vec<ReportedLocation>,
}

/// How a finding came to be credited to a planted flaw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    /// The finding names the same weakness class, in the same file.
    ///
    /// Two independent signals agreeing. Line numbers from a model are
    /// unreliable enough that proximity alone has assigned flaws to the wrong
    /// findings here, so class agreement is tried first and is allowed a wider
    /// line tolerance.
    Class,
    /// Only the location lined up.
    ///
    /// Still a match — a model that calls something "OS command injection" and
    /// one that calls it "unsafe subprocess invocation" have found the same
    /// flaw, and scoring on wording would measure vocabulary. But when both
    /// sides state a class and the classes differ, that is worth seeing next to
    /// the number it produced.
    Location,
}

/// What became of one planted flaw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlawOutcome {
    pub flaw_id: String,
    pub cwe: Option<String>,
    /// The title of the finding that matched, if one did.
    pub found_as: Option<String>,
    /// What the corpus says this deserves.
    pub expected_severity: Option<String>,
    /// What the scan called it.
    pub reported_severity: Option<String>,
    /// The class the scan gave the finding that matched.
    pub reported_cwe: Option<String>,
    /// Which signal credited the finding to this flaw.
    pub matched_by: Option<MatchedBy>,
    /// The deferral covering this flaw, when the scan set it aside instead of
    /// reporting it.
    ///
    /// Only ever set on a flaw that was not found: a reported flaw needs no
    /// excuse. Detection deliberately does not count these — the scan did not
    /// report it, and a rate that credited deferrals would let a scanner reach
    /// a hundred percent by explaining every flaw away.
    pub deferred_as: Option<Deferral>,
}

impl FlawOutcome {
    /// Whether the scan rated this as the corpus does.
    ///
    /// `None` when either side did not say. Severity is a judgement, so this is
    /// reported as agreement rather than correctness: a corpus author and a
    /// model can reasonably differ, and the useful signal is how far apart they
    /// are rather than who is right.
    #[must_use]
    pub fn severity_agrees(&self) -> Option<bool> {
        let expected = self.expected_severity.as_deref()?;
        let reported = self.reported_severity.as_deref()?;
        Some(expected.eq_ignore_ascii_case(reported))
    }
}

impl FlawOutcome {
    #[must_use]
    pub fn found(&self) -> bool {
        self.found_as.is_some()
    }

    /// Whether the scan saw this and set it aside rather than reporting it.
    #[must_use]
    pub fn deferred(&self) -> bool {
        self.deferred_as.is_some()
    }

    /// Whether the scan gave no sign of having seen this at all.
    ///
    /// The number worth watching. Everything else is a judgement that can be
    /// argued with; this is a blind spot.
    #[must_use]
    pub fn never_noticed(&self) -> bool {
        !self.found() && !self.deferred()
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
    /// Decoys a finding was reported against, by decoy id.
    ///
    /// Reported apart from other noise: being fooled by code written to look
    /// dangerous is a different failure from inventing something out of thin
    /// air, and says more about how a scanner will behave on real code.
    pub decoys_tripped: Vec<String>,
    /// Deferrals that could not be tied to anything planted, by deferral id.
    ///
    /// Said rather than dropped. A deferral the corpus cannot place is not
    /// evidence of anything, and silently discarding it would let the scoring
    /// look more complete than it is.
    pub unattributed_deferrals: Vec<String>,
    /// Decoys the scan set aside rather than reporting, by decoy id.
    ///
    /// A near miss, and the most encouraging thing in a report: the scan looked
    /// at code written to fool it, suspected something, and stopped short of
    /// claiming it. Worth seeing, because the same code under a different model
    /// is where a false positive comes from.
    pub decoys_deferred: Vec<String>,
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

    /// Flaws the scan saw and set aside, with why.
    #[must_use]
    pub fn deferred(&self) -> Vec<(&str, &Deferral)> {
        self.outcomes
            .iter()
            .filter_map(|outcome| Some((outcome.flaw_id.as_str(), outcome.deferred_as.as_ref()?)))
            .collect()
    }

    /// Flaws the scan gave no sign of having seen.
    #[must_use]
    pub fn never_noticed(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.never_noticed())
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
    score_fixture_with_deferrals(fixture, findings, &[])
}

/// The same, also accounting for what the scan set aside.
///
/// A deferral is attributed to at most one flaw and a flaw takes at most one
/// deferral, on the same reasoning as findings: neither should be able to cover
/// the corpus by being vague.
#[must_use]
pub fn score_fixture_with_deferrals(
    fixture: &Fixture,
    findings: &[ReportedFinding],
    deferrals: &[Deferral],
) -> FixtureScore {
    let mut claimed: Vec<bool> = vec![false; findings.len()];
    let mut taken: Vec<bool> = vec![false; deferrals.len()];
    let mut outcomes = Vec::with_capacity(fixture.flaws.len());

    // Class agreement first, across every flaw, before anything is matched on
    // proximity alone. Done as two passes rather than one because a
    // flaw-by-flaw scan takes whatever is nearest and available: in a real run
    // that assigned the use-after-free to the off-by-one's finding and the
    // off-by-one to the use-after-free's, and still scored three of three.
    let mut assigned: Vec<Option<(usize, MatchedBy)>> = vec![None; fixture.flaws.len()];
    for (position, flaw) in fixture.flaws.iter().enumerate() {
        if let Some(index) = nearest_same_class(findings, &claimed, flaw) {
            claimed[index] = true;
            assigned[position] = Some((index, MatchedBy::Class));
        }
    }
    for (position, flaw) in fixture.flaws.iter().enumerate() {
        if assigned[position].is_some() {
            continue;
        }
        if let Some((index, _)) = findings
            .iter()
            .enumerate()
            .find(|(index, finding)| !claimed[*index] && cites(finding, flaw))
        {
            claimed[index] = true;
            assigned[position] = Some((index, MatchedBy::Location));
        }
    }

    for (position, flaw) in fixture.flaws.iter().enumerate() {
        let matched = assigned[position].map(|(index, how)| (&findings[index], how));
        let (found_as, reported_severity, reported_cwe, matched_by) = match matched {
            Some((finding, how)) => (
                Some(finding.title.clone()),
                finding.severity.clone(),
                finding.cwe.clone(),
                Some(how),
            ),
            None => (None, None, None, None),
        };
        // Only looked for when the flaw was not reported. A found flaw needs no
        // excuse, and letting a deferral attach to one would double-count it.
        let deferred_as = if found_as.is_some() {
            None
        } else {
            deferrals
                .iter()
                .enumerate()
                .find(|(index, deferral)| !taken[*index] && covers(deferral, flaw, fixture))
                .map(|(index, deferral)| {
                    taken[index] = true;
                    deferral.clone()
                })
        };

        outcomes.push(FlawOutcome {
            flaw_id: flaw.id.clone(),
            cwe: flaw.cwe.clone(),
            found_as,
            expected_severity: flaw.severity.clone(),
            reported_severity,
            reported_cwe,
            matched_by,
            deferred_as,
        });
    }

    let unmatched: Vec<String> = findings
        .iter()
        .enumerate()
        .filter(|(index, _)| !claimed[*index])
        .map(|(_, finding)| finding.title.clone())
        .collect();

    // Which of the unmatched findings landed on something written to look
    // dangerous. A finding may trip a decoy and still be counted once as noise;
    // this names what it was fooled by.
    let decoys_tripped = fixture
        .decoys
        .iter()
        .filter(|decoy| {
            findings
                .iter()
                .enumerate()
                .any(|(index, finding)| !claimed[index] && cites_decoy(finding, decoy))
        })
        .map(|decoy| decoy.id.clone())
        .collect();

    // A deferral landing on safe code written to look dangerous. The scan
    // suspected it and stopped short, which is the outcome to want there.
    let decoys_deferred = fixture
        .decoys
        .iter()
        .filter(|decoy| {
            deferrals
                .iter()
                .enumerate()
                .any(|(index, deferral)| !taken[index] && touches_decoy(deferral, decoy))
        })
        .map(|decoy| decoy.id.clone())
        .collect();

    let unattributed_deferrals = deferrals
        .iter()
        .enumerate()
        .filter(|(index, _)| !taken[*index])
        .map(|(_, deferral)| deferral.id.clone())
        .collect();

    FixtureScore {
        fixture: fixture.name.clone(),
        control: fixture.control,
        outcomes,
        unmatched,
        decoys_tripped,
        unattributed_deferrals,
        decoys_deferred,
    }
}

/// Whether a deferral points at where a flaw was planted.
///
/// Precise spans decide it when the scan gave them. When it named only a file,
/// the deferral is attributed **only if that file holds exactly one planted
/// flaw** — otherwise one vague deferral over a file with three flaws in it
/// would be credited against whichever came first, which is not evidence that
/// the scan saw that one.
fn covers(deferral: &Deferral, flaw: &PlantedFlaw, fixture: &Fixture) -> bool {
    if !deferral.spans.is_empty() {
        return deferral
            .spans
            .iter()
            .any(|span| same_file(&span.file, &flaw.file) && overlaps(span.lines, flaw.lines));
    }
    let alone = fixture
        .flaws
        .iter()
        .filter(|other| same_file(&other.file, &flaw.file))
        .count()
        == 1;
    alone
        && deferral
            .paths
            .iter()
            .any(|path| same_file(path, &flaw.file))
}

/// Whether a deferral points at a decoy. Spans only: a file-wide deferral says
/// nothing about one routine in it.
fn touches_decoy(deferral: &Deferral, decoy: &Decoy) -> bool {
    deferral
        .spans
        .iter()
        .any(|span| same_file(&span.file, &decoy.file) && overlaps(span.lines, decoy.lines))
}

/// Whether two line ranges are close enough to be the same code.
fn overlaps(span: (u32, u32), planted: (u32, u32)) -> bool {
    within_tolerance(span.0, planted)
        || within_tolerance(span.1, planted)
        || (span.0 <= planted.0 && span.1 >= planted.1)
}

/// Whether a finding points at a decoy.
fn cites_decoy(finding: &ReportedFinding, decoy: &Decoy) -> bool {
    finding.locations.iter().any(|location| {
        same_file(&location.file, &decoy.file) && within_tolerance(location.line, decoy.lines)
    })
}

/// The nearest unclaimed finding of the same class in the same file.
///
/// Nearest rather than first, so two flaws of one class in one file go to the
/// findings actually about them.
fn nearest_same_class(
    findings: &[ReportedFinding],
    claimed: &[bool],
    flaw: &PlantedFlaw,
) -> Option<usize> {
    let planted = flaw.cwe.as_deref()?;
    findings
        .iter()
        .enumerate()
        .filter(|(index, _)| !claimed[*index])
        .filter(|(_, finding)| {
            finding
                .cwe
                .as_deref()
                .is_some_and(|reported| reported.eq_ignore_ascii_case(planted))
        })
        .filter_map(|(index, finding)| {
            finding
                .locations
                .iter()
                .filter(|location| same_file(&location.file, &flaw.file))
                .map(|location| distance(location.line, flaw.lines))
                .min()
                .filter(|distance| *distance <= CLASS_TOLERANCE)
                .map(|distance| (distance, index))
        })
        .min()
        .map(|(_, index)| index)
}

/// How far a line sits from a planted range, zero when inside it.
fn distance(line: u32, planted: (u32, u32)) -> u32 {
    let (first, last) = planted;
    first.saturating_sub(line).max(line.saturating_sub(last))
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

/// Reads what a scan set aside, from its coverage document.
///
/// Two places record it and this reads both. `deferred[]` is the explicit list;
/// `surfaces[]` carries a disposition, and a scan may mark a surface for follow
/// up without writing a matching deferral. Trusting one of them would make the
/// result depend on which convention a given run happened to use, so both are
/// read and the surface ids deduplicate them.
///
/// Line numbers come from surface labels, which the plugin writes as
/// `path:first-last (what it is)`. When a label does not carry a range the
/// deferral keeps only its paths, and scoring is correspondingly cautious.
pub fn deferrals_from_coverage(text: &str) -> Result<Vec<Deferral>, String> {
    let document: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| format!("coverage document is not usable: {error}"))?;

    let surfaces = document
        .get("surfaces")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let span_of = |id: &str| -> Option<DeferredSpan> {
        surfaces
            .iter()
            .find(|surface| surface.get("id").and_then(serde_json::Value::as_str) == Some(id))
            .and_then(|surface| surface.get("label"))
            .and_then(serde_json::Value::as_str)
            .and_then(span_from_label)
    };

    let mut deferrals = Vec::new();
    let mut seen_surfaces: Vec<String> = Vec::new();

    for item in document
        .get("deferred")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let ids: Vec<String> = item
            .get("surfaceIds")
            .and_then(serde_json::Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .filter_map(|id| id.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let spans: Vec<DeferredSpan> = ids.iter().filter_map(|id| span_of(id)).collect();
        seen_surfaces.extend(ids);
        deferrals.push(Deferral {
            id: item
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("(unnamed)")
                .to_owned(),
            reason: item
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            paths: item
                .get("paths")
                .and_then(serde_json::Value::as_array)
                .map(|found| {
                    found
                        .iter()
                        .filter_map(|path| path.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            spans,
        });
    }

    for surface in &surfaces {
        let Some(id) = surface.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if seen_surfaces.iter().any(|seen| seen == id) {
            continue;
        }
        let disposition = surface
            .get("disposition")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !matches!(disposition, "needs_follow_up" | "deferred") {
            continue;
        }
        let label = surface
            .get("label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let span = span_from_label(label);
        deferrals.push(Deferral {
            id: id.to_owned(),
            reason: surface
                .get("notes")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            paths: span.iter().map(|span| span.file.clone()).collect(),
            spans: span.into_iter().collect(),
        });
    }

    Ok(deferrals)
}

/// Pulls `path:first-last` out of a surface label.
///
/// Returns nothing rather than guessing when the label is prose. A wrong span
/// would attribute a deferral to a flaw the scan never looked at, which is the
/// one error this whole distinction exists to avoid.
fn span_from_label(label: &str) -> Option<DeferredSpan> {
    let head = label.split_whitespace().next()?;
    let (file, range) = head.rsplit_once(':')?;
    if file.is_empty() {
        return None;
    }
    let (first, last) = match range.split_once('-') {
        Some((first, last)) => (first.parse().ok()?, last.parse().ok()?),
        None => {
            let only: u32 = range.parse().ok()?;
            (only, only)
        }
    };
    if first > last {
        return None;
    }
    Some(DeferredSpan {
        file: file.to_owned(),
        lines: (first, last),
    })
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

    /// Flaws where the scan rated the severity as the corpus does, over those
    /// where both said something.
    ///
    /// `None` when nothing could be compared. Reported as agreement, never as
    /// accuracy: severity is a judgement and the corpus is one opinion.
    #[must_use]
    pub fn severity_agreement(&self) -> Option<(usize, usize)> {
        let comparable: Vec<bool> = self
            .scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .filter_map(FlawOutcome::severity_agrees)
            .collect();
        if comparable.is_empty() {
            return None;
        }
        Some((
            comparable.iter().filter(|agreed| **agreed).count(),
            comparable.len(),
        ))
    }

    /// Flaws the scan rated differently, as (id, expected, reported).
    #[must_use]
    pub fn severity_disagreements(&self) -> Vec<(&str, &str, &str)> {
        self.scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .filter(|outcome| outcome.severity_agrees() == Some(false))
            .filter_map(|outcome| {
                Some((
                    outcome.flaw_id.as_str(),
                    outcome.expected_severity.as_deref()?,
                    outcome.reported_severity.as_deref()?,
                ))
            })
            .collect()
    }

    /// Flaws the scan saw and set aside, anywhere in the corpus.
    ///
    /// Not counted as found. Reported because the aggregate rate cannot tell a
    /// blind spot from a judgement, and only one of those is fixed by a better
    /// scanner.
    #[must_use]
    pub fn deferred(&self) -> usize {
        self.scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .filter(|outcome| outcome.deferred())
            .count()
    }

    /// Flaws the scan gave no sign of having seen.
    #[must_use]
    pub fn never_noticed(&self) -> usize {
        self.scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .filter(|outcome| outcome.never_noticed())
            .count()
    }

    /// Decoys the scan set aside rather than reporting, anywhere in the corpus.
    #[must_use]
    pub fn decoys_deferred(&self) -> Vec<&str> {
        self.scores
            .iter()
            .flat_map(|score| score.decoys_deferred.iter().map(String::as_str))
            .collect()
    }

    /// Deferrals nothing in the corpus could account for.
    #[must_use]
    pub fn unattributed_deferrals(&self) -> usize {
        self.scores
            .iter()
            .map(|score| score.unattributed_deferrals.len())
            .sum()
    }

    /// Flaws credited to a finding of a different class, as (id, corpus, scan).
    ///
    /// Reported, not rejected. Matching is by location and never by wording,
    /// deliberately — but a flaw credited to a finding the scan itself
    /// classified differently is a match resting on one signal, and the reader
    /// deciding what the number means should see which ones those are.
    #[must_use]
    pub fn class_disagreements(&self) -> Vec<(&str, &str, &str)> {
        self.scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .filter(|outcome| outcome.matched_by == Some(MatchedBy::Location))
            .filter_map(|outcome| {
                let expected = outcome.cwe.as_deref()?;
                let reported = outcome.reported_cwe.as_deref()?;
                (!expected.eq_ignore_ascii_case(reported)).then_some((
                    outcome.flaw_id.as_str(),
                    expected,
                    reported,
                ))
            })
            .collect()
    }

    /// Decoys tripped anywhere in the corpus.
    #[must_use]
    pub fn decoys_tripped(&self) -> Vec<&str> {
        self.scores
            .iter()
            .flat_map(|score| score.decoys_tripped.iter().map(String::as_str))
            .collect()
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

/// What a run must reach to be considered acceptable.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Thresholds {
    /// Least acceptable share of planted flaws found, in `0.0..=1.0`.
    pub min_detection: Option<f64>,
    /// Most acceptable findings that matched nothing planted.
    pub max_false_positives: Option<usize>,
}

/// Why a run was judged unacceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shortfall {
    /// Detection was below the floor.
    Detection { required: String, actual: String },
    /// Too many findings matched nothing planted.
    FalsePositives { allowed: usize, actual: usize },
    /// A detection floor was set, but nothing was planted to detect.
    ///
    /// Not a pass. A threshold checked against an undefined rate that quietly
    /// succeeds is worse than no threshold, because it reports as a guard while
    /// guarding nothing.
    NothingToDetect { required: String },
}

impl Shortfall {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Detection { required, actual } => {
                format!("detection {actual} is below the required {required}")
            }
            Self::FalsePositives { allowed, actual } => {
                format!(
                    "{actual} findings matched nothing planted, more than the {allowed} allowed"
                )
            }
            Self::NothingToDetect { required } => format!(
                "a detection floor of {required} was set, but the corpus plants nothing to detect"
            ),
        }
    }
}

impl BenchmarkReport {
    /// Every way the run fell short of what was asked of it.
    #[must_use]
    pub fn shortfalls(&self, thresholds: &Thresholds) -> Vec<Shortfall> {
        let mut found = Vec::new();

        if let Some(required) = thresholds.min_detection {
            match self.detection_rate() {
                Some(rate) if rate + f64::EPSILON < required => {
                    found.push(Shortfall::Detection {
                        required: format!("{:.0}%", required * 100.0),
                        actual: format!("{:.0}%", rate * 100.0),
                    });
                }
                Some(_) => {}
                // Refused rather than passed: see Shortfall::NothingToDetect.
                None => found.push(Shortfall::NothingToDetect {
                    required: format!("{:.0}%", required * 100.0),
                }),
            }
        }

        if let Some(allowed) = thresholds.max_false_positives {
            let actual = self.false_positives();
            if actual > allowed {
                found.push(Shortfall::FalsePositives { allowed, actual });
            }
        }

        found
    }
}

/// What changed between two runs over the same corpus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Comparison {
    /// Found before, missed now. The case a job should stop for.
    pub newly_missed: Vec<String>,
    /// Missed before, found now.
    pub newly_found: Vec<String>,
    /// Severities that moved, as (id, before, after).
    pub severity_moved: Vec<(String, String, String)>,
    /// Flaws only one of the runs had a chance to find.
    ///
    /// A corpus that grew is not a regression, and neither is one that shrank.
    pub not_comparable: Vec<String>,
}

impl Comparison {
    /// Whether something that used to be found is no longer found.
    #[must_use]
    pub fn regressed(&self) -> bool {
        !self.newly_missed.is_empty()
    }
}

/// Compares a run against an earlier one.
///
/// Only flaws both runs could have found are judged. Model output varies
/// between runs, so a single difference is weak evidence either way — this
/// reports what moved, not what it means.
#[must_use]
pub fn compare(before: &BenchmarkReport, after: &BenchmarkReport) -> Comparison {
    use std::collections::BTreeMap;

    let index = |report: &BenchmarkReport| -> BTreeMap<String, (bool, Option<String>)> {
        report
            .scores
            .iter()
            .flat_map(|score| &score.outcomes)
            .map(|outcome| {
                (
                    outcome.flaw_id.clone(),
                    (outcome.found(), outcome.reported_severity.clone()),
                )
            })
            .collect()
    };
    let (before, after) = (index(before), index(after));

    let mut comparison = Comparison::default();
    for (id, (found_after, severity_after)) in &after {
        let Some((found_before, severity_before)) = before.get(id) else {
            comparison.not_comparable.push(id.clone());
            continue;
        };
        match (found_before, found_after) {
            (true, false) => comparison.newly_missed.push(id.clone()),
            (false, true) => comparison.newly_found.push(id.clone()),
            _ => {}
        }
        if let (Some(before), Some(after)) = (severity_before, severity_after)
            && !before.eq_ignore_ascii_case(after)
        {
            comparison
                .severity_moved
                .push((id.clone(), before.clone(), after.clone()));
        }
    }
    // A flaw the earlier run had and this one does not is equally uncomparable.
    for id in before.keys() {
        if !after.contains_key(id) {
            comparison.not_comparable.push(id.clone());
        }
    }
    comparison.not_comparable.sort();
    comparison.not_comparable.dedup();
    comparison
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
            cwe: None,
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
            decoys: Vec::new(),
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

        assert!(corpus.fixture("orders-api").is_some());
        let control = corpus
            .fixture("inventory-service")
            .expect("a control fixture");
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

#[cfg(test)]
mod threshold_tests {
    use super::*;

    fn report(found: usize, planted: usize, unmatched: usize) -> BenchmarkReport {
        let outcomes = (0..planted)
            .map(|index| FlawOutcome {
                flaw_id: format!("f{index}"),
                cwe: None,
                found_as: (index < found).then(|| "found".to_owned()),
                expected_severity: None,
                reported_severity: None,
                reported_cwe: None,
                matched_by: None,
                deferred_as: None,
            })
            .collect();
        BenchmarkReport {
            scores: vec![FixtureScore {
                fixture: "f".to_owned(),
                control: false,
                outcomes,
                unmatched: (0..unmatched).map(|i| format!("noise {i}")).collect(),
                decoys_tripped: Vec::new(),
                unattributed_deferrals: Vec::new(),
                decoys_deferred: Vec::new(),
            }],
        }
    }

    #[test]
    fn a_run_that_meets_its_floor_has_nothing_to_report() {
        let thresholds = Thresholds {
            min_detection: Some(0.8),
            max_false_positives: Some(1),
        };

        assert!(report(4, 5, 1).shortfalls(&thresholds).is_empty());
    }

    #[test]
    fn detection_below_the_floor_is_a_shortfall() {
        let thresholds = Thresholds {
            min_detection: Some(0.8),
            ..Thresholds::default()
        };

        let shortfalls = report(2, 5, 0).shortfalls(&thresholds);

        assert_eq!(shortfalls.len(), 1);
        assert!(shortfalls[0].describe().contains("40%"), "{shortfalls:?}");
    }

    /// A floor met exactly is met. Floating point must not turn 80% into a
    /// failure against a floor of 80%.
    #[test]
    fn a_floor_met_exactly_passes() {
        let thresholds = Thresholds {
            min_detection: Some(0.8),
            ..Thresholds::default()
        };

        assert!(report(4, 5, 0).shortfalls(&thresholds).is_empty());
    }

    /// The bug this guards against: a threshold that passes because there was
    /// nothing to measure reports as a guard while guarding nothing.
    #[test]
    fn a_floor_against_an_empty_corpus_is_refused_not_passed() {
        let thresholds = Thresholds {
            min_detection: Some(0.8),
            ..Thresholds::default()
        };
        let empty = BenchmarkReport { scores: Vec::new() };

        let shortfalls = empty.shortfalls(&thresholds);

        assert_eq!(shortfalls.len(), 1, "an unmeasurable floor must not pass");
        assert!(
            matches!(shortfalls[0], Shortfall::NothingToDetect { .. }),
            "{shortfalls:?}"
        );
    }

    #[test]
    fn too_much_noise_is_a_shortfall() {
        let thresholds = Thresholds {
            max_false_positives: Some(1),
            ..Thresholds::default()
        };

        let shortfalls = report(5, 5, 3).shortfalls(&thresholds);

        assert_eq!(shortfalls.len(), 1);
        assert!(shortfalls[0].describe().contains('3'), "{shortfalls:?}");
    }

    /// Zero tolerated means zero, not "a few".
    #[test]
    fn a_zero_allowance_admits_no_noise() {
        let thresholds = Thresholds {
            max_false_positives: Some(0),
            ..Thresholds::default()
        };

        assert!(report(5, 5, 0).shortfalls(&thresholds).is_empty());
        assert_eq!(report(5, 5, 1).shortfalls(&thresholds).len(), 1);
    }

    /// Both can fail at once, and a caller fixing one should see the other.
    #[test]
    fn reports_every_way_a_run_fell_short() {
        let thresholds = Thresholds {
            min_detection: Some(0.9),
            max_false_positives: Some(0),
        };

        assert_eq!(report(1, 5, 2).shortfalls(&thresholds).len(), 2);
    }

    #[test]
    fn asking_for_nothing_judges_nothing() {
        assert!(
            report(0, 5, 9)
                .shortfalls(&Thresholds::default())
                .is_empty()
        );
    }
}

#[cfg(test)]
mod decoy_tests {
    use super::*;

    fn control_with_decoy() -> Fixture {
        Fixture {
            name: "clean".to_owned(),
            path: "fixtures/clean".to_owned(),
            language: None,
            flaws: Vec::new(),
            control: true,
            decoys: vec![Decoy {
                id: "sql-placeholders-from-count".to_owned(),
                file: "src/inventory.py".to_owned(),
                lines: (55, 57),
                resembles: Some("CWE-89".to_owned()),
                safe_because: Some("placeholders come from the count".to_owned()),
            }],
        }
    }

    fn finding(title: &str, line: u32) -> ReportedFinding {
        ReportedFinding {
            title: title.to_owned(),
            cwe: None,
            severity: None,
            locations: vec![ReportedLocation {
                file: "src/inventory.py".to_owned(),
                line,
            }],
        }
    }

    /// Being fooled by code written to look dangerous is a different failure
    /// from inventing something from nothing, and says more about how a scanner
    /// behaves on real code.
    #[test]
    fn names_the_decoy_a_finding_was_fooled_by() {
        let score = score_fixture(&control_with_decoy(), &[finding("SQL injection", 56)]);

        assert_eq!(score.decoys_tripped, ["sql-placeholders-from-count"]);
        // Still counted as noise; the decoy names what it was fooled by.
        assert_eq!(score.unmatched.len(), 1);
    }

    #[test]
    fn a_finding_elsewhere_is_noise_but_not_a_decoy_trip() {
        let score = score_fixture(&control_with_decoy(), &[finding("something", 500)]);

        assert!(
            score.decoys_tripped.is_empty(),
            "{:?}",
            score.decoys_tripped
        );
        assert_eq!(score.unmatched.len(), 1);
    }

    #[test]
    fn a_quiet_control_trips_nothing() {
        let score = score_fixture(&control_with_decoy(), &[]);

        assert!(score.decoys_tripped.is_empty());
        assert!(score.unmatched.is_empty());
    }

    /// The shipped corpus must carry decoys, or the control only measures the
    /// easy case.
    #[test]
    fn the_shipped_control_carries_decoys() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../benchmark/ground-truth.json"),
        )
        .expect("the corpus is shipped");
        let corpus = GroundTruth::parse(&text).expect("parses");

        let control = corpus.fixture("inventory-service").expect("a control");
        assert!(!control.decoys.is_empty(), "the control has no decoys");
        for decoy in &control.decoys {
            assert!(
                decoy.safe_because.is_some(),
                "{} does not say why it is safe",
                decoy.id
            );
        }
    }

    /// Every decoy must point at a line that exists, or the corpus is scoring
    /// against fiction.
    #[test]
    fn every_decoy_points_at_a_real_line() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("benchmark/ground-truth.json"))
            .expect("the corpus is shipped");
        let corpus = GroundTruth::parse(&text).expect("parses");

        for fixture in &corpus.fixtures {
            for decoy in &fixture.decoys {
                let path = root.join(&fixture.path).join(&decoy.file);
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|_| panic!("{} names {}", decoy.id, path.display()));
                let lines = u32::try_from(body.lines().count()).unwrap_or(u32::MAX);
                assert!(
                    decoy.lines.0 >= 1 && decoy.lines.1 <= lines,
                    "{} points at {:?} of a {}-line file",
                    decoy.id,
                    decoy.lines,
                    lines
                );
            }
        }
    }
}

#[cfg(test)]
mod severity_tests {
    use super::*;

    fn flaw_with(severity: &str) -> PlantedFlaw {
        PlantedFlaw {
            id: "a".to_owned(),
            file: "src/app.py".to_owned(),
            lines: (10, 10),
            cwe: Some("CWE-89".to_owned()),
            severity: Some(severity.to_owned()),
            summary: None,
        }
    }

    fn fixture_with(severity: &str) -> Fixture {
        Fixture {
            name: "f".to_owned(),
            path: "fixtures/f".to_owned(),
            language: None,
            flaws: vec![flaw_with(severity)],
            control: false,
            decoys: Vec::new(),
        }
    }

    fn rated(severity: Option<&str>) -> ReportedFinding {
        ReportedFinding {
            title: "found".to_owned(),
            cwe: None,
            severity: severity.map(str::to_owned),
            locations: vec![ReportedLocation {
                file: "src/app.py".to_owned(),
                line: 10,
            }],
        }
    }

    #[test]
    fn notices_when_the_scan_rates_a_flaw_as_the_corpus_does() {
        let score = score_fixture(&fixture_with("high"), &[rated(Some("high"))]);
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.severity_agreement(), Some((1, 1)));
        assert!(report.severity_disagreements().is_empty());
    }

    /// A critical rated low is nearly as bad as one missed, so a difference is
    /// surfaced with both opinions rather than hidden.
    #[test]
    fn names_both_opinions_when_they_differ() {
        let score = score_fixture(&fixture_with("critical"), &[rated(Some("low"))]);
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.severity_agreement(), Some((0, 1)));
        assert_eq!(report.severity_disagreements(), [("a", "critical", "low")]);
    }

    /// Wording, not judgement.
    #[test]
    fn ignores_the_case_a_severity_was_written_in() {
        let score = score_fixture(&fixture_with("high"), &[rated(Some("HIGH"))]);
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.severity_agreement(), Some((1, 1)));
    }

    /// Nothing is claimed when one side did not say.
    #[test]
    fn compares_nothing_when_a_severity_is_missing() {
        for reported in [None, Some("high")] {
            let mut fixture = fixture_with("high");
            if reported.is_none() {
                // Scan said nothing.
            } else {
                // Corpus says nothing.
                fixture.flaws[0].severity = None;
            }
            let score = score_fixture(&fixture, &[rated(reported)]);
            let report = BenchmarkReport {
                scores: vec![score],
            };
            assert_eq!(report.severity_agreement(), None);
        }
    }

    /// A flaw that was never found has no reported severity to compare.
    #[test]
    fn a_missed_flaw_is_not_a_severity_disagreement() {
        let score = score_fixture(&fixture_with("critical"), &[]);
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.severity_agreement(), None);
        assert!(report.severity_disagreements().is_empty());
    }
}

#[cfg(test)]
mod comparison_tests {
    use super::*;

    fn report(entries: &[(&str, bool, Option<&str>)]) -> BenchmarkReport {
        BenchmarkReport {
            scores: vec![FixtureScore {
                fixture: "f".to_owned(),
                control: false,
                outcomes: entries
                    .iter()
                    .map(|(id, found, severity)| FlawOutcome {
                        flaw_id: (*id).to_owned(),
                        cwe: None,
                        found_as: found.then(|| "found".to_owned()),
                        expected_severity: None,
                        reported_severity: severity.map(str::to_owned),
                        reported_cwe: None,
                        matched_by: None,
                        deferred_as: None,
                    })
                    .collect(),
                unmatched: Vec::new(),
                decoys_tripped: Vec::new(),
                unattributed_deferrals: Vec::new(),
                decoys_deferred: Vec::new(),
            }],
        }
    }

    /// The case a job should stop for.
    #[test]
    fn names_what_stopped_being_found() {
        let comparison = compare(
            &report(&[("a", true, None), ("b", true, None)]),
            &report(&[("a", true, None), ("b", false, None)]),
        );

        assert_eq!(comparison.newly_missed, ["b"]);
        assert!(comparison.regressed());
    }

    /// Only reporting the bad direction makes a tool feel like a nag.
    #[test]
    fn names_what_started_being_found() {
        let comparison = compare(
            &report(&[("a", false, None)]),
            &report(&[("a", true, None)]),
        );

        assert_eq!(comparison.newly_found, ["a"]);
        assert!(!comparison.regressed());
    }

    /// A corpus that grew is not a regression.
    #[test]
    fn a_flaw_the_earlier_run_never_had_is_not_a_regression() {
        let comparison = compare(
            &report(&[("a", true, None)]),
            &report(&[("a", true, None), ("new", false, None)]),
        );

        assert!(!comparison.regressed(), "{comparison:?}");
        assert_eq!(comparison.not_comparable, ["new"]);
    }

    /// Nor is one that shrank.
    #[test]
    fn a_flaw_dropped_from_the_corpus_is_not_a_regression() {
        let comparison = compare(
            &report(&[("a", true, None), ("gone", true, None)]),
            &report(&[("a", true, None)]),
        );

        assert!(!comparison.regressed());
        assert_eq!(comparison.not_comparable, ["gone"]);
    }

    /// A flaw still found but rated lower is worth seeing: a reviewer working
    /// down a list by severity reaches it later, or not at all.
    #[test]
    fn notices_a_severity_that_moved() {
        let comparison = compare(
            &report(&[("a", true, Some("critical"))]),
            &report(&[("a", true, Some("medium"))]),
        );

        assert_eq!(
            comparison.severity_moved,
            [("a".to_owned(), "critical".to_owned(), "medium".to_owned())]
        );
        // Not a regression on its own; the flaw is still found.
        assert!(!comparison.regressed());
    }

    #[test]
    fn two_identical_runs_differ_in_nothing() {
        let run = report(&[("a", true, Some("high")), ("b", false, None)]);

        let comparison = compare(&run, &run);

        assert_eq!(comparison, Comparison::default());
    }
}

#[cfg(test)]
mod deferral_tests {
    use super::*;

    fn flaw(id: &str, file: &str, first: u32, last: u32) -> PlantedFlaw {
        PlantedFlaw {
            id: id.to_owned(),
            file: file.to_owned(),
            lines: (first, last),
            cwe: None,
            severity: None,
            summary: None,
        }
    }

    fn fixture(flaws: Vec<PlantedFlaw>) -> Fixture {
        Fixture {
            name: "f".to_owned(),
            path: "fixtures/f".to_owned(),
            language: None,
            flaws,
            control: false,
            decoys: Vec::new(),
        }
    }

    fn deferral(id: &str, file: &str, first: u32, last: u32) -> Deferral {
        Deferral {
            id: id.to_owned(),
            reason: Some("wanted deployment context".to_owned()),
            paths: vec![file.to_owned()],
            spans: vec![DeferredSpan {
                file: file.to_owned(),
                lines: (first, last),
            }],
        }
    }

    /// The distinction the whole feature exists for.
    #[test]
    fn a_flaw_the_scan_set_aside_is_not_a_flaw_it_never_saw() {
        let corpus = fixture(vec![flaw("timing", "src/server.js", 35, 35)]);

        let score = score_fixture_with_deferrals(
            &corpus,
            &[],
            &[deferral("candidate-1", "src/server.js", 28, 33)],
        );

        assert!(!score.outcomes[0].found(), "a deferral is not a finding");
        assert!(score.outcomes[0].deferred());
        assert!(!score.outcomes[0].never_noticed());
        assert_eq!(score.never_noticed(), Vec::<&str>::new());
    }

    /// Detection must stay the share that was *reported*. Crediting deferrals
    /// would let a scan reach a hundred percent by explaining every flaw away.
    #[test]
    fn deferring_everything_does_not_raise_detection() {
        let corpus = fixture(vec![flaw("timing", "src/server.js", 35, 35)]);

        let score = score_fixture_with_deferrals(
            &corpus,
            &[],
            &[deferral("candidate-1", "src/server.js", 28, 33)],
        );
        let report = BenchmarkReport {
            scores: vec![score],
        };

        assert_eq!(report.found(), 0);
        assert_eq!(report.detection_rate(), Some(0.0));
        assert_eq!(report.deferred(), 1);
    }

    /// A flaw that was reported takes no excuse, even if a deferral sits on it.
    #[test]
    fn a_reported_flaw_is_not_also_recorded_as_deferred() {
        let corpus = fixture(vec![flaw("timing", "src/server.js", 35, 35)]);
        let finding = ReportedFinding {
            title: "Timing attack".to_owned(),
            cwe: None,
            severity: None,
            locations: vec![ReportedLocation {
                file: "src/server.js".to_owned(),
                line: 35,
            }],
        };

        let score = score_fixture_with_deferrals(
            &corpus,
            &[finding],
            &[deferral("candidate-1", "src/server.js", 35, 35)],
        );

        assert!(score.outcomes[0].found());
        assert!(!score.outcomes[0].deferred());
        // And the deferral is said to be unaccounted for rather than dropped.
        assert_eq!(score.unattributed_deferrals, vec!["candidate-1"]);
    }

    /// One vague deferral must not cover a file full of flaws.
    #[test]
    fn a_file_wide_deferral_is_not_credited_when_the_file_holds_several_flaws() {
        let corpus = fixture(vec![
            flaw("overflow", "src/store.c", 23, 23),
            flaw("use-after-free", "src/store.c", 33, 36),
            flaw("off-by-one", "src/store.c", 54, 54),
        ]);
        let vague = Deferral {
            id: "candidate-1".to_owned(),
            reason: None,
            paths: vec!["src/store.c".to_owned()],
            spans: Vec::new(),
        };

        let score = score_fixture_with_deferrals(&corpus, &[], &[vague]);

        assert_eq!(score.never_noticed().len(), 3);
        assert_eq!(score.unattributed_deferrals, vec!["candidate-1"]);
    }

    /// When there is only one flaw in the file there is no ambiguity to guard
    /// against, so a file-wide deferral does count.
    #[test]
    fn a_file_wide_deferral_counts_when_the_file_holds_one_flaw() {
        let corpus = fixture(vec![flaw("timing", "src/server.js", 35, 35)]);
        let vague = Deferral {
            id: "candidate-1".to_owned(),
            reason: None,
            paths: vec!["src/server.js".to_owned()],
            spans: Vec::new(),
        };

        let score = score_fixture_with_deferrals(&corpus, &[], &[vague]);

        assert!(score.outcomes[0].deferred());
    }

    /// Two flaws must not share one deferral.
    #[test]
    fn one_deferral_covers_at_most_one_flaw() {
        let corpus = fixture(vec![
            flaw("first", "src/server.js", 30, 30),
            flaw("second", "src/server.js", 34, 34),
        ]);

        let score = score_fixture_with_deferrals(
            &corpus,
            &[],
            &[deferral("candidate-1", "src/server.js", 30, 34)],
        );

        assert_eq!(score.deferred().len(), 1);
        assert_eq!(score.never_noticed().len(), 1);
    }

    /// A deferral on a decoy is the outcome to want: it looked, suspected, and
    /// stopped short of claiming it.
    #[test]
    fn a_deferral_on_a_decoy_is_reported_as_a_near_miss() {
        let mut corpus = fixture(Vec::new());
        corpus.control = true;
        corpus.decoys = vec![Decoy {
            id: "path-join-validated".to_owned(),
            file: "src/inventory.py".to_owned(),
            lines: (85, 88),
            resembles: Some("CWE-22".to_owned()),
            safe_because: None,
        }];

        let score = score_fixture_with_deferrals(
            &corpus,
            &[],
            &[deferral("candidate-1", "src/inventory.py", 85, 88)],
        );

        assert_eq!(score.decoys_deferred, vec!["path-join-validated"]);
        // Still a near miss, never a false positive: nothing was reported.
        assert!(score.unmatched.is_empty());
        assert!(score.decoys_tripped.is_empty());
    }

    /// A deferral pointing somewhere else must not be credited to a flaw.
    #[test]
    fn a_deferral_elsewhere_leaves_a_flaw_unnoticed() {
        let corpus = fixture(vec![flaw("timing", "src/server.js", 35, 35)]);

        let score = score_fixture_with_deferrals(
            &corpus,
            &[],
            &[deferral("candidate-1", "src/other.js", 35, 35)],
        );

        assert!(score.outcomes[0].never_noticed());
        assert_eq!(score.unattributed_deferrals, vec!["candidate-1"]);
    }
}

#[cfg(test)]
mod coverage_parsing_tests {
    use super::*;

    /// The real document from a real run, kept because every shape here was
    /// first written from a guess about the schema and the guess was wrong.
    fn real_coverage() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/coverage-node-traversal.json"),
        )
        .expect("the captured coverage document")
    }

    #[test]
    fn reads_a_deferral_out_of_a_real_coverage_document() {
        let deferrals = deferrals_from_coverage(&real_coverage()).expect("parses");

        assert_eq!(deferrals.len(), 1, "{deferrals:?}");
        let deferral = &deferrals[0];
        assert_eq!(deferral.id, "candidate-4b1d1f1e08b4b1f2");
        assert!(
            deferral
                .reason
                .as_deref()
                .expect("a reason")
                .contains("environment variable"),
            "{deferral:?}"
        );
        // The line range comes from the surface label, not from the deferral.
        assert_eq!(
            deferral.spans,
            vec![DeferredSpan {
                file: "src/server.js".to_owned(),
                lines: (28, 33),
            }]
        );
    }

    /// The end-to-end claim: the run that scored 2 of 3 did not overlook the
    /// third flaw, it set it aside. This is the case that made the whole
    /// distinction worth building, so it is checked against the real document
    /// and the shipped corpus rather than against invented inputs.
    #[test]
    fn the_run_that_scored_two_of_three_had_seen_the_third() {
        let corpus = GroundTruth::parse(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../benchmark/ground-truth.json"),
            )
            .expect("the shipped corpus"),
        )
        .expect("parses");
        let fixture = corpus.fixture("link-service").expect("the fixture");
        let deferrals = deferrals_from_coverage(&real_coverage()).expect("parses");
        // What that run actually reported: the traversal and the SSRF.
        let findings = vec![
            ReportedFinding {
                title: "Path traversal".to_owned(),
                cwe: None,
                severity: Some("high".to_owned()),
                locations: vec![ReportedLocation {
                    file: "src/server.js".to_owned(),
                    line: 12,
                }],
            },
            ReportedFinding {
                title: "SSRF".to_owned(),
                cwe: None,
                severity: Some("high".to_owned()),
                locations: vec![ReportedLocation {
                    file: "src/server.js".to_owned(),
                    line: 22,
                }],
            },
        ];

        let score = score_fixture_with_deferrals(fixture, &findings, &deferrals);

        assert_eq!(score.found(), 2);
        assert_eq!(score.missed(), vec!["timing-unsafe-compare"]);
        assert_eq!(
            score.never_noticed(),
            Vec::<&str>::new(),
            "the scan saw it and said why it was not reporting it"
        );
        let (id, deferral) = score.deferred()[0];
        assert_eq!(id, "timing-unsafe-compare");
        assert!(deferral.reason.is_some());
    }

    /// A surface marked for follow up without a matching deferral entry is
    /// still something the scan set aside.
    #[test]
    fn reads_a_surface_marked_for_follow_up_with_no_deferral_entry() {
        let document = serde_json::json!({
            "surfaces": [{
                "id": "src-a-py-login",
                "disposition": "needs_follow_up",
                "label": "src/a.py:10-20 (login)",
                "notes": "not sure this is reachable",
            }],
            "deferred": [],
        })
        .to_string();

        let deferrals = deferrals_from_coverage(&document).expect("parses");

        assert_eq!(deferrals.len(), 1);
        assert_eq!(deferrals[0].id, "src-a-py-login");
        assert_eq!(
            deferrals[0].reason.as_deref(),
            Some("not sure this is reachable")
        );
        assert_eq!(deferrals[0].spans[0].lines, (10, 20));
    }

    /// The same surface named both ways is one deferral, not two.
    #[test]
    fn does_not_count_a_surface_twice_when_a_deferral_already_names_it() {
        let document = serde_json::json!({
            "surfaces": [{
                "id": "s1",
                "disposition": "needs_follow_up",
                "label": "src/a.py:10-20 (login)",
            }],
            "deferred": [{ "id": "candidate-1", "surfaceIds": ["s1"], "paths": ["src/a.py"] }],
        })
        .to_string();

        let deferrals = deferrals_from_coverage(&document).expect("parses");

        assert_eq!(deferrals.len(), 1, "{deferrals:?}");
        assert_eq!(deferrals[0].id, "candidate-1");
    }

    /// A reported surface is not a deferral.
    #[test]
    fn a_reported_surface_is_not_treated_as_set_aside() {
        let document = serde_json::json!({
            "surfaces": [{ "id": "s1", "disposition": "reported", "label": "src/a.py:1-2 (x)" }],
        })
        .to_string();

        assert!(
            deferrals_from_coverage(&document)
                .expect("parses")
                .is_empty()
        );
    }

    /// A label that is prose yields no span rather than a wrong one.
    #[test]
    fn refuses_to_guess_a_span_from_a_label_without_one() {
        for label in [
            "the login handler",
            "src/a.py",
            "src/a.py:notaline",
            "src/a.py:20-10",
            ":10-20",
        ] {
            assert_eq!(span_from_label(label), None, "{label}");
        }
    }

    #[test]
    fn reads_a_single_line_label() {
        assert_eq!(
            span_from_label("src/a.py:42 (thing)"),
            Some(DeferredSpan {
                file: "src/a.py".to_owned(),
                lines: (42, 42),
            })
        );
    }

    #[test]
    fn a_coverage_document_with_nothing_set_aside_yields_nothing() {
        for body in ["{}", r#"{"deferred":[],"surfaces":[]}"#] {
            assert!(
                deferrals_from_coverage(body).expect("parses").is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn refuses_something_that_is_not_json() {
        assert!(deferrals_from_coverage("not json").is_err());
    }
}

#[cfg(test)]
mod real_matching_tests {
    use super::*;

    /// The findings from a real run of `kv-store`, kept because the defect they
    /// exposed was invisible in every invented case: the model cited lines far
    /// enough from the truth that proximity alone assigned two flaws to each
    /// other's findings, and the score came out three of three.
    fn real_findings() -> Vec<ReportedFinding> {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/findings-kv-store-swapped.json"),
        )
        .expect("the captured findings");
        let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        document["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|finding| ReportedFinding {
                title: finding["title"].as_str().unwrap_or_default().to_owned(),
                severity: finding["severity"]["level"].as_str().map(str::to_owned),
                cwe: finding["taxonomy"]["cwe"][0].as_str().map(str::to_owned),
                locations: finding["locations"]
                    .as_array()
                    .expect("locations")
                    .iter()
                    .flat_map(|location| {
                        let file = location["path"].as_str().unwrap_or_default().to_owned();
                        [location.get("startLine"), location.get("endLine")]
                            .into_iter()
                            .flatten()
                            .filter_map(serde_json::Value::as_u64)
                            .map(move |line| ReportedLocation {
                                file: file.clone(),
                                line: u32::try_from(line).unwrap_or(u32::MAX),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect(),
            })
            .collect()
    }

    fn kv_store() -> Fixture {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../benchmark/ground-truth.json"),
        )
        .expect("the shipped corpus");
        GroundTruth::parse(&text)
            .expect("parses")
            .fixture("kv-store")
            .expect("the fixture")
            .clone()
    }

    /// Every flaw goes to the finding that is actually about it.
    #[test]
    fn each_flaw_is_credited_to_the_finding_about_it() {
        let score = score_fixture(&kv_store(), &real_findings());

        for (id, expected) in [
            ("stack-overflow", "Buffer overflow"),
            ("use-after-free", "Use-after-free"),
            ("off-by-one", "Off-by-one"),
        ] {
            let outcome = score
                .outcomes
                .iter()
                .find(|outcome| outcome.flaw_id == id)
                .expect(id);
            let title = outcome.found_as.as_deref().unwrap_or("(not found)");
            assert!(
                title.starts_with(expected),
                "{id} was credited to \"{title}\""
            );
        }
    }

    /// And the assignment rests on class agreement, not on proximity — which
    /// for two of these is the only thing that could have got it right.
    #[test]
    fn the_swapped_pair_is_matched_by_class_and_not_by_line() {
        let score = score_fixture(&kv_store(), &real_findings());

        for id in ["use-after-free", "off-by-one"] {
            let outcome = score
                .outcomes
                .iter()
                .find(|outcome| outcome.flaw_id == id)
                .expect(id);
            assert_eq!(outcome.matched_by, Some(MatchedBy::Class), "{id}");
        }
    }

    /// The finding nothing planted accounts for stays unmatched, rather than
    /// being absorbed by a flaw it says nothing about.
    #[test]
    fn the_unplanted_finding_is_still_unmatched() {
        let score = score_fixture(&kv_store(), &real_findings());

        assert_eq!(score.unmatched.len(), 1, "{:?}", score.unmatched);
        assert!(
            score.unmatched[0].contains("strdup"),
            "{:?}",
            score.unmatched
        );
    }

    /// Location-only matching still works when the classes are simply absent,
    /// because a scan that names no class is not a scan that got it wrong.
    #[test]
    fn a_finding_without_a_class_still_matches_by_location() {
        let mut findings = real_findings();
        for finding in &mut findings {
            finding.cwe = None;
        }

        let score = score_fixture(&kv_store(), &findings);

        assert_eq!(score.found(), 3);
        assert!(
            score
                .outcomes
                .iter()
                .all(|outcome| outcome.matched_by == Some(MatchedBy::Location))
        );
    }

    /// A match resting on location alone, where both sides named a class and
    /// the classes differ, is reported rather than hidden.
    #[test]
    fn a_class_disagreement_is_reported() {
        let fixture = Fixture {
            name: "f".to_owned(),
            path: "fixtures/f".to_owned(),
            language: None,
            flaws: vec![PlantedFlaw {
                id: "planted".to_owned(),
                file: "a.c".to_owned(),
                lines: (10, 10),
                cwe: Some("CWE-193".to_owned()),
                severity: None,
                summary: None,
            }],
            control: false,
            decoys: Vec::new(),
        };
        let findings = vec![ReportedFinding {
            title: "Something else".to_owned(),
            severity: None,
            cwe: Some("CWE-476".to_owned()),
            locations: vec![ReportedLocation {
                file: "a.c".to_owned(),
                line: 12,
            }],
        }];

        let report = BenchmarkReport {
            scores: vec![score_fixture(&fixture, &findings)],
        };

        assert_eq!(report.found(), 1);
        assert_eq!(
            report.class_disagreements(),
            vec![("planted", "CWE-193", "CWE-476")]
        );
    }
}
