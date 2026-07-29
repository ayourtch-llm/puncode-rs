//! Behavior tests for scan cost estimation and tracking.
//!
//! Ported from the upstream `tests-ts/cost.test.ts`. Cases marked "oracle"
//! were derived by probing the TypeScript implementation directly.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use codex_security::cost::{ScanCost, ScanCostTracker, estimate_scan_cost, format_usd};
use serde_json::{Value, json};
use tempfile::TempDir;

fn write_session(
    home: &Path,
    thread_id: &str,
    usage: Value,
    parent_thread_id: Option<&str>,
) -> PathBuf {
    let directory = home.join("sessions").join("2026").join("07").join("26");
    fs::create_dir_all(&directory).expect("create session directory");
    let path = directory.join(format!("rollout-{thread_id}.jsonl"));

    let mut meta = json!({ "id": thread_id });
    if let Some(parent) = parent_thread_id {
        meta["source"] = json!({ "subagent": { "thread_spawn": { "parent_thread_id": parent } } });
    }
    let lines = [
        json!({ "type": "session_meta", "payload": meta }).to_string(),
        json!({
            "type": "event_msg",
            "payload": { "type": "token_count", "info": { "total_token_usage": usage } }
        })
        .to_string(),
        String::new(),
    ];
    fs::write(&path, lines.join("\n")).expect("write session file");
    path
}

// ---------------------------------------------------------------------------
// estimate_scan_cost
// ---------------------------------------------------------------------------

#[test]
fn uses_published_gpt_5_6_model_rates() {
    let usage = json!({ "input_tokens": 1_000_000, "output_tokens": 1_000_000 });

    assert_eq!(
        estimate_scan_cost(Some("gpt-5.6"), &usage)
            .unwrap()
            .estimated_usd,
        35.0
    );
    assert_eq!(
        estimate_scan_cost(Some("gpt-5.6-sol"), &usage)
            .unwrap()
            .estimated_usd,
        35.0
    );
    assert_eq!(
        estimate_scan_cost(Some("gpt-5.6-terra"), &usage)
            .unwrap()
            .estimated_usd,
        17.5
    );
    assert_eq!(
        estimate_scan_cost(Some("gpt-5.6-luna"), &usage)
            .unwrap()
            .estimated_usd,
        7.0
    );
}

#[test]
fn charges_cached_input_at_its_discounted_rate() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({ "input_tokens": 1_250, "cached_input_tokens": 200, "output_tokens": 30 }),
    );

    assert_eq!(
        cost,
        Some(ScanCost {
            model: "gpt-5.6-sol".to_owned(),
            input_tokens: 1_250,
            cached_input_tokens: 200,
            cache_write_input_tokens: 0,
            output_tokens: 30,
            estimated_usd: 0.00625,
        })
    );
}

#[test]
fn charges_cache_writes_at_their_published_rate() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({
            "input_tokens": 1_000,
            "cached_input_tokens": 100,
            "cache_write_input_tokens": 200,
            "output_tokens": 10
        }),
    );

    assert_eq!(cost.unwrap().estimated_usd, 0.0051);
}

#[test]
fn does_not_double_charge_reasoning_tokens_included_in_output() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({ "input_tokens": 1_000, "output_tokens": 10, "reasoning_output_tokens": 9 }),
    );

    assert_eq!(cost.unwrap().estimated_usd, 0.0053);
}

#[test]
fn does_not_invent_prices_for_unknown_models_or_incomplete_usage() {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    let cases: Vec<(Option<&str>, Value)> = vec![
        (
            Some("unknown-model"),
            json!({ "input_tokens": 1, "output_tokens": 1 }),
        ),
        (Some("gpt-5.6-sol"), Value::Null),
        (Some("gpt-5.6-sol"), json!({})),
        (
            Some("gpt-5.6-sol"),
            json!({ "input_tokens": -1, "output_tokens": 1 }),
        ),
        (
            Some("gpt-5.6-sol"),
            json!({ "input_tokens": 1.5, "output_tokens": 1 }),
        ),
        (
            Some("gpt-5.6-sol"),
            json!({ "input_tokens": 1, "cached_input_tokens": 2, "output_tokens": 1 }),
        ),
        (
            Some("gpt-5.6-sol"),
            json!({ "input_tokens": MAX_SAFE_INTEGER, "output_tokens": MAX_SAFE_INTEGER }),
        ),
    ];

    for (model, usage) in cases {
        assert_eq!(
            estimate_scan_cost(model, &usage),
            None,
            "model={model:?} usage={usage}"
        );
    }
}

#[test]
fn rejects_a_missing_model() {
    let usage = json!({ "input_tokens": 1_000, "output_tokens": 10 });

    assert_eq!(estimate_scan_cost(None, &usage), None);
}

// Adversarial: upstream accepts `cache_write_tokens` as an alias for
// `cache_write_input_tokens`, and treats an explicit JSON null as absent.
#[test]
fn accepts_the_legacy_cache_write_tokens_alias() {
    let aliased = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({
            "input_tokens": 1_000,
            "cached_input_tokens": 100,
            "cache_write_tokens": 200,
            "output_tokens": 10
        }),
    );

    assert_eq!(aliased.unwrap().cache_write_input_tokens, 200);
}

#[test]
fn treats_explicit_nulls_as_absent_optional_counts() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({
            "input_tokens": 1_000,
            "cached_input_tokens": Value::Null,
            "cache_write_input_tokens": Value::Null,
            "output_tokens": 10,
            "reasoning_output_tokens": Value::Null
        }),
    );

    assert_eq!(cost.unwrap().estimated_usd, 0.0053);
}

#[test]
fn rejects_usage_whose_reasoning_exceeds_its_output() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({ "input_tokens": 1_000, "output_tokens": 10, "reasoning_output_tokens": 11 }),
    );

    assert_eq!(cost, None);
}

#[test]
fn rejects_non_numeric_token_counts() {
    let cost = estimate_scan_cost(
        Some("gpt-5.6-sol"),
        &json!({ "input_tokens": "1000", "output_tokens": 10 }),
    );

    assert_eq!(cost, None);
}

// ---------------------------------------------------------------------------
// format_usd (oracle-derived; upstream has no direct tests for this)
// ---------------------------------------------------------------------------

#[test]
fn formats_usd_like_intl_number_format() {
    assert_eq!(format_usd(0.0), "$0.00");
    assert_eq!(format_usd(35.0), "$35.00");
    assert_eq!(format_usd(0.00625), "$0.00625");
    assert_eq!(format_usd(0.0051), "$0.0051");
    assert_eq!(format_usd(1234.5), "$1,234.50");
    assert_eq!(format_usd(1_234_567.891), "$1,234,567.891");
    assert_eq!(format_usd(-1.5), "-$1.50");
    assert_eq!(format_usd(1e-9), "$0.000000001");
    assert_eq!(format_usd(1e21), "$1,000,000,000,000,000,000,000.00");
}

#[test]
fn formats_usd_rounding_half_away_from_zero() {
    // Rust's `{:.9}` rounds half-to-even and would render these one ulp low;
    // Intl rounds half-expand.
    assert_eq!(format_usd(0.000_976_562_5), "$0.000976563");
    assert_eq!(format_usd(1.000_976_562_5), "$1.000976563");
    assert_eq!(format_usd(0.002_929_687_5), "$0.002929688");
    assert_eq!(format_usd(5e-10), "$0.000000001");
    assert_eq!(format_usd(1.49e-9), "$0.000000001");
    assert_eq!(format_usd(0.000_488_281_25), "$0.000488281");
}

// Differential: every case was produced by running the TypeScript `formatUsd`
// over the same bit pattern. Regenerate with `probe-fixture.ts`.
#[test]
fn formats_usd_identically_to_the_typescript_implementation() {
    #[derive(serde::Deserialize)]
    struct Case {
        bits: String,
        expected: String,
    }

    let fixture = include_str!("fixtures/format-usd.json");
    let cases: Vec<Case> = serde_json::from_str(fixture).expect("parse fixture");
    assert!(
        cases.len() > 1_000,
        "fixture should be broad, got {}",
        cases.len()
    );

    let mut mismatches = Vec::new();
    for case in &cases {
        let value = f64::from_bits(case.bits.parse().expect("parse bits"));
        let actual = format_usd(value);
        if actual != case.expected {
            mismatches.push(format!(
                "{value:e}: expected {}, got {actual}",
                case.expected
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn formats_usd_below_the_smallest_representable_cent() {
    assert_eq!(format_usd(4e-10), "$0.00");
    assert_eq!(format_usd(-4e-10), "-$0.00");
}

// Deviation: upstream looks the model up as a plain object property, so any
// name inherited from `Object.prototype` ("toString", "constructor",
// "__proto__", ...) resolves to a function and throws `TypeError: {} is not
// iterable`. There is no such hazard in Rust; these resolve to no pricing.
#[test]
fn treats_object_prototype_names_as_unknown_models() {
    let usage = json!({ "input_tokens": 1, "output_tokens": 1 });

    for model in [
        "toString",
        "constructor",
        "valueOf",
        "hasOwnProperty",
        "__proto__",
    ] {
        assert_eq!(
            estimate_scan_cost(Some(model), &usage),
            None,
            "model={model}"
        );
    }
}

#[test]
fn formats_usd_non_finite_and_signed_zero() {
    assert_eq!(format_usd(f64::NAN), "$NaN");
    assert_eq!(format_usd(f64::INFINITY), "$∞");
    assert_eq!(format_usd(f64::NEG_INFINITY), "-$∞");
    assert_eq!(format_usd(-0.0), "-$0.00");
}

// ---------------------------------------------------------------------------
// ScanCostTracker
// ---------------------------------------------------------------------------

#[test]
fn counts_the_scan_and_delegated_workers_without_including_other_scans() {
    let home = TempDir::new().expect("temp dir");
    write_session(
        home.path(),
        "scan-thread",
        json!({
            "input_tokens": 1_000,
            "cached_input_tokens": 100,
            "cache_write_input_tokens": 200,
            "output_tokens": 10,
            "reasoning_output_tokens": 2
        }),
        None,
    );
    write_session(
        home.path(),
        "worker-thread",
        json!({
            "input_tokens": 250,
            "cached_input_tokens": 50,
            "output_tokens": 5,
            "reasoning_output_tokens": 1
        }),
        Some("scan-thread"),
    );
    write_session(
        home.path(),
        "unrelated-thread",
        json!({ "input_tokens": 1_000_000, "output_tokens": 1_000_000 }),
        None,
    );

    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-sol");
    tracker.start("scan-thread");
    let snapshot = tracker.stop(None).expect("stop tracker");

    assert_eq!(
        snapshot.usage,
        Some(json!({
            "input_tokens": 1_250,
            "cached_input_tokens": 150,
            "cache_write_input_tokens": 200,
            "output_tokens": 15,
            "reasoning_output_tokens": 3,
            "total_tokens": 1_265
        }))
    );
    assert_eq!(
        snapshot.cost,
        Some(ScanCost {
            model: "gpt-5.6-sol".to_owned(),
            input_tokens: 1_250,
            cached_input_tokens: 150,
            cache_write_input_tokens: 200,
            output_tokens: 15,
            estimated_usd: 0.006275,
        })
    );
}

#[test]
fn uses_each_sessions_final_cumulative_usage_without_double_counting() {
    let home = TempDir::new().expect("temp dir");
    let path = write_session(
        home.path(),
        "scan-thread",
        json!({ "input_tokens": 100, "output_tokens": 10 }),
        None,
    );

    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-terra");
    tracker.start("scan-thread");
    let first = tracker.refresh().expect("refresh tracker");
    assert_eq!(first.cost.unwrap().estimated_usd, 0.0004);

    let latest = json!({
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": { "total_token_usage": { "input_tokens": 250, "output_tokens": 20 } }
        }
    })
    .to_string();
    let mut contents = fs::read_to_string(&path).expect("read session file");
    contents.push_str(&format!("{latest}\n{latest}\n"));
    fs::write(&path, contents).expect("append session events");

    let snapshot = tracker.stop(None).expect("stop tracker");

    assert_eq!(
        snapshot.cost,
        Some(ScanCost {
            model: "gpt-5.6-terra".to_owned(),
            input_tokens: 250,
            cached_input_tokens: 0,
            cache_write_input_tokens: 0,
            output_tokens: 20,
            estimated_usd: 0.000925,
        })
    );
}

#[test]
fn reports_a_changed_running_cost_only_once() {
    let home = TempDir::new().expect("temp dir");
    write_session(
        home.path(),
        "scan-thread",
        json!({ "input_tokens": 1_250, "cached_input_tokens": 200, "output_tokens": 30 }),
        None,
    );

    let updates = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&updates);
    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-sol")
        .with_max_cost_usd(0.005)
        .with_cost_observer(move |cost| recorded.lock().expect("lock").push(cost.estimated_usd));

    tracker.start("scan-thread");
    tracker.refresh().expect("refresh tracker");
    tracker.stop(None).expect("stop tracker");

    assert_eq!(*updates.lock().expect("lock"), vec![0.00625]);
}

#[test]
fn falls_back_to_the_completed_turn_when_session_logs_are_unavailable() {
    let home = TempDir::new().expect("temp dir");
    let usage = json!({ "input_tokens": 1_000, "output_tokens": 20 });

    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-luna");
    tracker.start("scan-thread");
    let snapshot = tracker.stop(Some(usage.clone())).expect("stop tracker");

    assert_eq!(snapshot.usage, Some(usage));
    assert_eq!(
        snapshot.cost,
        Some(ScanCost {
            model: "gpt-5.6-luna".to_owned(),
            input_tokens: 1_000,
            cached_input_tokens: 0,
            cache_write_input_tokens: 0,
            output_tokens: 20,
            estimated_usd: 0.00112,
        })
    );
}

// Adversarial: a session log that is missing, truncated mid-line, or contains
// unparsable lines must not poison tracking.
#[test]
fn ignores_unparsable_session_lines() {
    let home = TempDir::new().expect("temp dir");
    let path = write_session(
        home.path(),
        "scan-thread",
        json!({ "input_tokens": 100, "output_tokens": 10 }),
        None,
    );
    let mut contents = fs::read_to_string(&path).expect("read session file");
    contents.push_str("not json\n{\"type\":\"event_msg\"}\n");
    fs::write(&path, contents).expect("append junk");

    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-terra");
    tracker.start("scan-thread");

    assert_eq!(
        tracker
            .stop(None)
            .expect("stop tracker")
            .cost
            .unwrap()
            .estimated_usd,
        0.0004
    );
}

#[test]
fn tolerates_a_missing_sessions_directory() {
    let home = TempDir::new().expect("temp dir");
    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-terra");
    tracker.start("scan-thread");

    assert_eq!(
        tracker.refresh().expect("refresh tracker"),
        Default::default()
    );
}

#[test]
fn does_not_read_sessions_before_a_thread_is_started() {
    let home = TempDir::new().expect("temp dir");
    write_session(
        home.path(),
        "scan-thread",
        json!({ "input_tokens": 100, "output_tokens": 10 }),
        None,
    );

    let mut tracker = ScanCostTracker::new(home.path(), "gpt-5.6-terra");

    assert_eq!(
        tracker.refresh().expect("refresh tracker"),
        Default::default()
    );
}
