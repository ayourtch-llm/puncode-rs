//! Behavior tests for worker progress parsing.
//!
//! Ported from `tests-ts/worker-progress.test.ts`.

use puncode_security::codex::ThreadEvent;
use puncode_security::worker_progress::{
    ScanWorkerPhase, ScanWorkerStatus, WorkerDelegation, worker_status_from_event,
};
use serde_json::json;

fn command_event(command: &str, output: &str) -> ThreadEvent {
    serde_json::from_value(json!({
        "type": "item.completed",
        "item": {
            "id": "command-1",
            "type": "command_execution",
            "command": command,
            "aggregated_output": output,
            "exit_code": 0,
            "status": "completed"
        }
    }))
    .expect("event parses")
}

fn message_event(text: &str) -> ThreadEvent {
    serde_json::from_value(json!({
        "type": "item.completed",
        "item": { "id": "message-1", "type": "agent_message", "text": text }
    }))
    .expect("event parses")
}

#[test]
fn reads_configured_worker_capacity_from_a_completed_preflight() {
    let output = json!({
        "profile": "security_scan",
        "status": "ready",
        "results": [
            { "capability": "delegated_workers", "status": "pass", "actual": true },
            { "capability": "usable_worker_slots_6", "status": "pass", "actual": 8 }
        ]
    })
    .to_string();
    let event = command_event(
        r#""/managed/python" "$CODEX_SECURITY_PLUGIN_ROOT/scripts/config_preflight.py" --profile security_scan"#,
        &output,
    );

    assert_eq!(
        worker_status_from_event(&event),
        Some(ScanWorkerStatus::Preflight {
            delegation: WorkerDelegation::Available,
            configured_slots: Some(8),
        })
    );
}

#[test]
fn keeps_unavailable_and_unknown_delegation_distinct_from_capacity() {
    for (status, delegation) in [
        ("fail", WorkerDelegation::Unavailable),
        ("unknown", WorkerDelegation::Unknown),
    ] {
        let output = json!({
            "profile": "security_scan",
            "status": if status == "unknown" { "incomplete" } else { "ready" },
            "results": [
                { "capability": "delegated_workers", "status": status },
                { "capability": "usable_worker_slots_6", "status": "pass", "actual": 8 }
            ]
        })
        .to_string();
        let event = command_event(
            "python3 /plugin/scripts/config_preflight.py --profile security_scan",
            &output,
        );

        assert_eq!(
            worker_status_from_event(&event),
            Some(ScanWorkerStatus::Preflight {
                delegation,
                configured_slots: Some(8),
            })
        );
    }
}

#[test]
fn accepts_a_diff_preflight_without_a_worker_slot_requirement() {
    let output = json!({
        "profile": "security_diff_scan",
        "status": "ready",
        "results": [{ "capability": "delegated_workers", "status": "pass" }]
    })
    .to_string();
    let event = command_event(
        r"python3 C:\plugin\scripts\config_preflight.py --profile security_diff_scan",
        &output,
    );

    assert_eq!(
        worker_status_from_event(&event),
        Some(ScanWorkerStatus::Preflight {
            delegation: WorkerDelegation::Available,
            configured_slots: None,
        })
    );
}

#[test]
fn reads_a_bounded_dispatch_marker_from_the_agent_message() {
    let event = message_event(
        "Reviewing the ranked worklist.\n\
         CODEX_SECURITY_WORKER_STATUS {\"phase\":\"file_review\",\"planned\":6,\"started\":3}",
    );

    assert_eq!(
        worker_status_from_event(&event),
        Some(ScanWorkerStatus::Dispatch {
            phase: ScanWorkerPhase::FileReview,
            planned: 6,
            started: 3,
        })
    );

    let event = message_event(
        r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":0}"#,
    );
    assert_eq!(
        worker_status_from_event(&event),
        Some(ScanWorkerStatus::Dispatch {
            phase: ScanWorkerPhase::Ranking,
            planned: 6,
            started: 0,
        })
    );
}

#[test]
fn ignores_unrelated_malformed_conflicting_or_oversized_events() {
    let preflight = json!({
        "profile": "security_scan",
        "results": [{ "capability": "delegated_workers", "status": "pass" }]
    })
    .to_string();
    let oversized = format!("{preflight}{}", " ".repeat(65 * 1024));
    let conflicting_delegation = json!({
        "profile": "security_scan",
        "results": [
            { "capability": "delegated_workers", "status": "pass" },
            { "capability": "delegated_workers", "status": "fail" }
        ]
    })
    .to_string();
    let unknown_profile = json!({
        "profile": "deep_security_scan",
        "results": [{ "capability": "delegated_workers", "status": "pass" }]
    })
    .to_string();
    let non_string_profile = json!({
        "profile": ["security_scan"],
        "results": [{ "capability": "delegated_workers", "status": "pass" }]
    })
    .to_string();

    let events = [
        // Merely naming the script is not running it.
        command_event("rg config_preflight.py /repository", &preflight),
        command_event("python3 /plugin/scripts/config_preflight.py", "not json"),
        command_event(
            "python3 /plugin/scripts/config_preflight.py",
            &unknown_profile,
        ),
        command_event(
            "python3 /plugin/scripts/config_preflight.py",
            &non_string_profile,
        ),
        command_event(
            "python3 /plugin/scripts/config_preflight.py",
            &conflicting_delegation,
        ),
        command_event("python3 /plugin/scripts/config_preflight.py", &oversized),
        message_event(
            r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":3}"#,
        ),
        message_event(
            r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":-1,"started":0}"#,
        ),
        message_event(
            r#"CODEX_SECURITY_WORKER_STATUS {"phase":"discovery","planned":2,"started":1}"#,
        ),
        message_event(
            r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":1,"path":"/repository"}"#,
        ),
        message_event(
            "CODEX_SECURITY_WORKER_STATUS {\"phase\":\"ranking\",\"planned\":2,\"started\":1}\n\
             CODEX_SECURITY_WORKER_STATUS {\"phase\":\"ranking\",\"planned\":2,\"started\":0}",
        ),
    ];

    for (index, event) in events.iter().enumerate() {
        assert_eq!(
            worker_status_from_event(event),
            None,
            "event {index} should be ignored"
        );
    }
}

// Adversarial: only completed items of the two known kinds carry status.
#[test]
fn ignores_events_that_are_not_completed_items() {
    let started: ThreadEvent = serde_json::from_value(json!({
        "type": "item.started",
        "item": { "id": "message-1", "type": "agent_message",
                  "text": "CODEX_SECURITY_WORKER_STATUS {\"phase\":\"ranking\",\"planned\":2,\"started\":1}" }
    }))
    .expect("event parses");
    let other_item: ThreadEvent = serde_json::from_value(json!({
        "type": "item.completed",
        "item": { "id": "r1", "type": "reasoning", "text": "thinking" }
    }))
    .expect("event parses");
    let turn: ThreadEvent =
        serde_json::from_value(json!({ "type": "turn.started" })).expect("event parses");

    assert_eq!(worker_status_from_event(&started), None);
    assert_eq!(worker_status_from_event(&other_item), None);
    assert_eq!(worker_status_from_event(&turn), None);
}

// The path separator before the script name is what distinguishes running it
// from mentioning it, on both platforms.
#[test]
fn recognizes_the_preflight_script_only_when_invoked() {
    let output = json!({
        "profile": "security_scan",
        "results": [{ "capability": "delegated_workers", "status": "pass" }]
    })
    .to_string();

    let invoked = [
        "config_preflight.py",
        "/a/config_preflight.py",
        r"C:\a\config_preflight.py --flag",
        r#""/a/config_preflight.py""#,
        "'/a/config_preflight.py'",
        // Trailing whitespace satisfies the lookahead.
        "x/config_preflight.py\n",
    ];
    for command in invoked {
        assert!(
            worker_status_from_event(&command_event(command, &output)).is_some(),
            "{command} should count as an invocation"
        );
    }

    let mentioned = [
        "rg config_preflight.py /repository",
        "cat my_config_preflight.py",
        "python3 /a/config_preflight.pyc",
        "echo config_preflight.python",
        // Only a path separator counts before the name, not any whitespace.
        "python3\tconfig_preflight.py",
    ];
    for command in mentioned {
        assert_eq!(
            worker_status_from_event(&command_event(command, &output)),
            None,
            "{command} should not count as an invocation"
        );
    }
}

#[test]
fn rejects_worker_counts_beyond_the_supported_maximum() {
    let over = message_event(
        r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":1025,"started":0}"#,
    );
    let at_limit = message_event(
        r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":1024,"started":1024}"#,
    );

    assert_eq!(worker_status_from_event(&over), None);
    assert_eq!(
        worker_status_from_event(&at_limit),
        Some(ScanWorkerStatus::Dispatch {
            phase: ScanWorkerPhase::Ranking,
            planned: 1024,
            started: 1024,
        })
    );
}

#[test]
fn ignores_a_fractional_worker_count() {
    let event = message_event(
        r#"CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2.5,"started":1}"#,
    );

    assert_eq!(worker_status_from_event(&event), None);
}

#[test]
fn renders_phase_and_delegation_wire_values() {
    assert_eq!(ScanWorkerPhase::AttackPath.as_str(), "attack_path");
    assert_eq!(ScanWorkerPhase::FileReview.as_str(), "file_review");
    assert_eq!(WorkerDelegation::Unavailable.as_str(), "unavailable");
}
