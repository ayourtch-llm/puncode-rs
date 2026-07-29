//! Matching findings across a whole repository history.
//!
//! Ported from `matchAllScans` in `src/cli.ts`.
//!
//! Matching is one model turn, so a batch matches every earlier scan's findings
//! against the later scan at once rather than a turn per pair. The single
//! answer is then split back per earlier scan, keeping only the occurrences
//! that scan actually reported — a match naming an occurrence from a different
//! scan would attribute a finding to a scan that never saw it.

use codex_security::scan_comparison::{
    ComparisonAgent, ComparisonFinding, ScanComparisonInput, ScanComparisonOptions,
    ScanComparisonResult, match_scan_findings,
};
use serde_json::{Map, Value, json};

/// One later scan and the earlier ones it should be matched against.
struct Batch {
    after_scan_id: String,
    after_findings: Vec<ComparisonFinding>,
    before_scans: Vec<BeforeScan>,
}

/// One earlier scan in a batch.
struct BeforeScan {
    scan_id: String,
    findings: Vec<ComparisonFinding>,
}

/// What matching a whole history did.
#[derive(Debug)]
pub struct MatchAllOutcome {
    pub report: Map<String, Value>,
}

/// Saves one comparison for a pair of scans.
pub trait ComparisonStore {
    fn save(
        &self,
        before_scan_id: &str,
        after_scan_id: &str,
        matches: &ScanComparisonResult,
    ) -> Result<(), String>;
}

/// Matches every unmatched pair the plan names.
pub fn match_all(
    plan: &Map<String, Value>,
    agent: &dyn ComparisonAgent,
    store: &dyn ComparisonStore,
) -> Result<MatchAllOutcome, String> {
    let batches = read_batches(plan)?;
    let mut matched_pairs = 0_u64;
    let mut finding_matches = 0_u64;

    for batch in &batches {
        // Every earlier scan's findings at once: one turn for the batch.
        let before: Vec<ComparisonFinding> = batch
            .before_scans
            .iter()
            .flat_map(|scan| scan.findings.iter().cloned())
            .collect();

        let matching = if before.is_empty() || batch.after_findings.is_empty() {
            // Nothing to compare, and a turn that would say so costs the same
            // as one that would not.
            ScanComparisonResult::default()
        } else {
            match_scan_findings(
                &ScanComparisonInput {
                    before,
                    after: batch.after_findings.clone(),
                },
                &ScanComparisonOptions {
                    // One earlier scan can be sure while another is not, which
                    // is only a contradiction within a single pair.
                    allow_historical_uncertainty: true,
                    ..ScanComparisonOptions::default()
                },
                agent,
            )
            .map_err(|error| error.to_string())?
        };

        for scan in &batch.before_scans {
            let comparison = split_for(&matching, scan)?;
            finding_matches += comparison
                .matches
                .iter()
                .map(|group| {
                    group.before_occurrence_ids.len() as u64
                        * group.after_occurrence_ids.len() as u64
                })
                .sum::<u64>();
            store.save(&scan.scan_id, &batch.after_scan_id, &comparison)?;
            matched_pairs += 1;
        }
    }

    Ok(MatchAllOutcome {
        report: json!({
            "repository": plan.get("repository").cloned().unwrap_or(Value::Null),
            "scanCount": plan.get("scanCount").cloned().unwrap_or(Value::Null),
            "unavailableScans": plan.get("unavailableScans").cloned().unwrap_or(Value::Null),
            "matchedPairs": matched_pairs,
            "skippedPairs": plan.get("skippedPairs").cloned().unwrap_or(Value::Null),
            "findingMatches": finding_matches,
        })
        .as_object()
        .cloned()
        .unwrap_or_default(),
    })
}

/// The part of a history-wide match that belongs to one earlier scan.
///
/// Occurrences from other scans are dropped: a match naming one would
/// attribute a finding to a scan that never reported it.
fn split_for(
    matching: &ScanComparisonResult,
    scan: &BeforeScan,
) -> Result<ScanComparisonResult, String> {
    let known: std::collections::BTreeSet<&str> = scan
        .findings
        .iter()
        .map(|finding| finding.occurrence_id.as_str())
        .collect();

    let matches: Vec<_> = matching
        .matches
        .iter()
        .filter_map(|group| {
            let before: Vec<String> = group
                .before_occurrence_ids
                .iter()
                .filter(|id| known.contains(id.as_str()))
                .cloned()
                .collect();
            (!before.is_empty()).then(|| codex_security::scan_comparison::ComparisonMatch {
                before_occurrence_ids: before,
                ..group.clone()
            })
        })
        .collect();

    let uncertain: Vec<_> = matching
        .uncertain
        .iter()
        .filter(|pair| known.contains(pair.before_occurrence_id.as_str()))
        .cloned()
        .collect();

    // Within one pair, being unsure about something already matched
    // confidently is a contradiction — the relaxation only spans scans.
    let matched_after: std::collections::BTreeSet<&str> = matches
        .iter()
        .flat_map(|group| group.after_occurrence_ids.iter().map(String::as_str))
        .collect();
    if uncertain
        .iter()
        .any(|pair| matched_after.contains(pair.after_occurrence_id.as_str()))
    {
        return Err(
            "Scan matching returned conflicting confirmed and uncertain findings.".to_owned(),
        );
    }

    Ok(ScanComparisonResult { matches, uncertain })
}

/// Reads the batches the workbench planned.
fn read_batches(plan: &Map<String, Value>) -> Result<Vec<Batch>, String> {
    let batches = plan
        .get("batches")
        .and_then(Value::as_array)
        .ok_or_else(|| "The workbench did not supply a matching plan.".to_owned())?;

    batches
        .iter()
        .map(|batch| {
            let batch = batch
                .as_object()
                .ok_or_else(|| "The matching plan is malformed.".to_owned())?;
            Ok(Batch {
                after_scan_id: batch
                    .get("afterScanId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "The matching plan names no later scan.".to_owned())?
                    .to_owned(),
                after_findings: findings(batch.get("afterFindings"))?,
                before_scans: batch
                    .get("beforeScans")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "The matching plan names no earlier scans.".to_owned())?
                    .iter()
                    .map(|scan| {
                        let scan = scan
                            .as_object()
                            .ok_or_else(|| "The matching plan is malformed.".to_owned())?;
                        Ok(BeforeScan {
                            scan_id: scan
                                .get("scanId")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    "The matching plan names an earlier scan without an \
                                     identifier."
                                        .to_owned()
                                })?
                                .to_owned(),
                            findings: findings(scan.get("findings"))?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            })
        })
        .collect()
}

/// The findings a plan entry carries.
fn findings(value: Option<&Value>) -> Result<Vec<ComparisonFinding>, String> {
    serde_json::from_value(value.cloned().unwrap_or_else(|| json!([])))
        .map_err(|error| format!("The matching plan carries unreadable findings: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An agent that replies with a prepared result.
    struct FakeAgent {
        reply: String,
        turns: RefCell<usize>,
    }

    impl FakeAgent {
        fn new(reply: &Value) -> Self {
            Self {
                reply: reply.to_string(),
                turns: RefCell::new(0),
            }
        }
    }

    impl ComparisonAgent for FakeAgent {
        fn compare(
            &self,
            _prompt: &str,
            _options: &ScanComparisonOptions,
        ) -> codex_security::Result<String> {
            *self.turns.borrow_mut() += 1;
            Ok(self.reply.clone())
        }
    }

    /// A store that records what it was asked to save.
    #[derive(Default)]
    struct Recorder {
        saved: RefCell<Vec<(String, String, ScanComparisonResult)>>,
    }

    impl ComparisonStore for Recorder {
        fn save(
            &self,
            before: &str,
            after: &str,
            matches: &ScanComparisonResult,
        ) -> Result<(), String> {
            self.saved
                .borrow_mut()
                .push((before.to_owned(), after.to_owned(), matches.clone()));
            Ok(())
        }
    }

    fn finding(id: &str) -> Value {
        json!({ "occurrenceId": id })
    }

    /// A plan with one later scan and two earlier ones.
    fn plan() -> Map<String, Value> {
        json!({
            "repository": "/repos/payments",
            "scanCount": 3,
            "unavailableScans": 0,
            "skippedPairs": 1,
            "batches": [{
                "afterScanId": "after",
                "afterFindings": [finding("after-1"), finding("after-2")],
                "beforeScans": [
                    { "scanId": "older", "findings": [finding("older-1")] },
                    { "scanId": "newer", "findings": [finding("newer-1")] },
                ],
            }],
        })
        .as_object()
        .cloned()
        .expect("a plan")
    }

    fn a_match(before: &[&str], after: &[&str]) -> Value {
        json!({
            "beforeOccurrenceIds": before,
            "afterOccurrenceIds": after,
            "confidence": "high",
            "reason": "Same root cause.",
        })
    }

    // Matching is one model turn, so a batch is matched once rather than once
    // per earlier scan.
    #[test]
    fn matches_a_batch_in_one_turn() {
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1"], &["after-1"])],
            "uncertain": [],
        }));
        let store = Recorder::default();

        match_all(&plan(), &agent, &store).expect("matches");

        assert_eq!(*agent.turns.borrow(), 1);
        assert_eq!(store.saved.borrow().len(), 2, "one comparison per pair");
    }

    // A match naming an occurrence from a different scan would attribute a
    // finding to a scan that never reported it.
    #[test]
    fn keeps_only_the_occurrences_each_scan_reported() {
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1", "newer-1"], &["after-1"])],
            "uncertain": [],
        }));
        let store = Recorder::default();

        match_all(&plan(), &agent, &store).expect("matches");

        let saved = store.saved.borrow();
        let older = saved
            .iter()
            .find(|entry| entry.0 == "older")
            .expect("older");
        let newer = saved
            .iter()
            .find(|entry| entry.0 == "newer")
            .expect("newer");
        assert_eq!(older.2.matches[0].before_occurrence_ids, ["older-1"]);
        assert_eq!(newer.2.matches[0].before_occurrence_ids, ["newer-1"]);
    }

    // A group naming no occurrence from a scan is not that scan's match.
    #[test]
    fn drops_a_group_that_belongs_to_another_scan() {
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1"], &["after-1"])],
            "uncertain": [],
        }));
        let store = Recorder::default();

        match_all(&plan(), &agent, &store).expect("matches");

        let saved = store.saved.borrow();
        let newer = saved
            .iter()
            .find(|entry| entry.0 == "newer")
            .expect("newer");
        assert!(newer.2.matches.is_empty(), "{:?}", newer.2);
    }

    // One earlier scan being sure while another is not is ordinary across a
    // history, and each scan keeps only its own uncertainty.
    #[test]
    fn splits_uncertainty_by_the_scan_that_reported_it() {
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1"], &["after-1"])],
            "uncertain": [{
                "beforeOccurrenceId": "newer-1",
                "afterOccurrenceId": "after-1",
                "reason": "Uncertain in the later scan.",
            }],
        }));
        let store = Recorder::default();

        match_all(&plan(), &agent, &store).expect("matches");

        let saved = store.saved.borrow();
        let older = saved
            .iter()
            .find(|entry| entry.0 == "older")
            .expect("older");
        let newer = saved
            .iter()
            .find(|entry| entry.0 == "newer")
            .expect("newer");
        assert!(older.2.uncertain.is_empty(), "{:?}", older.2);
        assert_eq!(newer.2.uncertain.len(), 1);
    }

    // The relaxation is only across scans. Within one scan, saying a later
    // finding both is and might be a match is a contradiction — and it is one
    // the comparison validator cannot see, because there it looks like two
    // different earlier findings.
    #[test]
    fn refuses_a_scan_that_is_both_sure_and_unsure() {
        let mut plan = plan();
        plan["batches"][0]["beforeScans"][0]["findings"] =
            json!([finding("older-1"), finding("older-2")]);
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1"], &["after-1"])],
            "uncertain": [{
                "beforeOccurrenceId": "older-2",
                "afterOccurrenceId": "after-1",
                "reason": "Also uncertain, from the same scan.",
            }],
        }));
        let store = Recorder::default();

        let error = match_all(&plan, &agent, &store).expect_err("refused");

        assert!(
            error.contains("conflicting confirmed and uncertain findings"),
            "{error}"
        );
    }

    // A turn that would say "nothing to compare" costs the same as one that
    // would not, so it is not taken.
    #[test]
    fn takes_no_turn_when_there_is_nothing_to_compare() {
        let mut plan = plan();
        plan["batches"][0]["afterFindings"] = json!([]);
        let agent = FakeAgent::new(&json!({ "matches": [], "uncertain": [] }));
        let store = Recorder::default();

        match_all(&plan, &agent, &store).expect("matches");

        assert_eq!(*agent.turns.borrow(), 0);
        // The pairs are still recorded as compared, with nothing matched.
        assert_eq!(store.saved.borrow().len(), 2);
    }

    #[test]
    fn counts_what_it_matched() {
        let agent = FakeAgent::new(&json!({
            "matches": [a_match(&["older-1", "newer-1"], &["after-1", "after-2"])],
            "uncertain": [],
        }));
        let store = Recorder::default();

        let outcome = match_all(&plan(), &agent, &store).expect("matches");

        assert_eq!(outcome.report["matchedPairs"], json!(2));
        // One before occurrence times two after occurrences, for each scan.
        assert_eq!(outcome.report["findingMatches"], json!(4));
        assert_eq!(outcome.report["repository"], json!("/repos/payments"));
        assert_eq!(outcome.report["skippedPairs"], json!(1));
    }

    #[test]
    fn refuses_a_plan_it_cannot_read() {
        let agent = FakeAgent::new(&json!({ "matches": [], "uncertain": [] }));
        let store = Recorder::default();

        let error = match_all(&Map::new(), &agent, &store).expect_err("refused");

        assert!(error.contains("did not supply a matching plan"), "{error}");
    }

    #[test]
    fn reports_nothing_matched_for_an_empty_plan() {
        let plan = json!({ "repository": "/repos/payments", "batches": [] })
            .as_object()
            .cloned()
            .expect("a plan");
        let agent = FakeAgent::new(&json!({ "matches": [], "uncertain": [] }));
        let store = Recorder::default();

        let outcome = match_all(&plan, &agent, &store).expect("matches");

        assert_eq!(outcome.report["matchedPairs"], json!(0));
        assert!(store.saved.borrow().is_empty());
    }
}
