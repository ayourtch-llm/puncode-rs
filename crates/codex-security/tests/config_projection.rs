//! Differential tests for the scan configuration projections.
//!
//! Expectations were produced by running the TypeScript implementation over the
//! same configurations. Regenerate with `probe-cfg.ts`.

use std::collections::BTreeMap;

use codex_security::api::{scan_preflight_codex_config, scan_runtime_codex_config};
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
struct Fixture {
    preflight: BTreeMap<String, PreflightCase>,
    runtime: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct PreflightCase {
    ok: Option<Value>,
    error: Option<String>,
}

/// The inputs the fixture was generated from, mirrored here so the comparison
/// is against the same configurations.
fn inputs() -> BTreeMap<String, Value> {
    let mut inputs = BTreeMap::new();
    inputs.insert("empty".to_owned(), json!({}));
    inputs.insert(
        "typical".to_owned(),
        json!({
            "model": "gpt-5.6-sol", "model_reasoning_effort": "xhigh",
            "model_provider": "openai", "service_tier": "default",
            "features": { "goals": true, "multi_agent": false, "enable_fanout": true,
                          "multi_agent_v2": { "enabled": true, "max_concurrent_threads_per_session": 9 } },
            "agents": { "max_threads": 4, "max_depth": 2 },
            "multiagent_config": { "max_concurrency": 3 },
            "profile": "deep-scan"
        }),
    );
    inputs.insert(
        "secret_shaped_values".to_owned(),
        json!({ "model": "sk-my-secret-token", "model_provider": "vendor-api-key-1",
                "model_reasoning_effort": "high", "service_tier": "bearer" }),
    );
    inputs.insert(
        "secretish_words".to_owned(),
        json!({ "model": "has key inside", "model_provider": "MCP", "service_tier": "env" }),
    );
    inputs.insert(
        "lookalikes".to_owned(),
        json!({ "model": "monkey", "model_provider": "keystone", "service_tier": "tokenizer" }),
    );
    inputs.insert(
        "control_characters".to_owned(),
        json!({ "model": format!("gpt{}bad", '\u{1}'), "model_provider": "ok-provider" }),
    );
    inputs.insert(
        "oversized_values".to_owned(),
        json!({ "model": "x".repeat(513), "model_provider": "y".repeat(512) }),
    );
    inputs.insert(
        "unknown_settings".to_owned(),
        json!({ "totally_unknown": "kept?", "api_key": "sk-secret", "model": "gpt-5.6" }),
    );
    inputs.insert(
        "bad_features".to_owned(),
        json!({ "features": { "goals": "yes",
                "multi_agent_v2": { "enabled": "no", "max_concurrent_threads_per_session": -1 } } }),
    );
    inputs.insert(
        "v2_boolean".to_owned(),
        json!({ "features": { "multi_agent_v2": true } }),
    );
    inputs.insert(
        "v2_empty_object".to_owned(),
        json!({ "features": { "multi_agent_v2": {} } }),
    );
    inputs.insert(
        "bad_agents".to_owned(),
        json!({ "agents": { "max_threads": 1.5, "max_depth": 1_000_001 } }),
    );
    inputs.insert(
        "agents_at_limit".to_owned(),
        json!({ "agents": { "max_threads": 1_000_000, "max_depth": 0 } }),
    );
    inputs.insert(
        "profiles".to_owned(),
        json!({ "profiles": { "good-1": { "model": "gpt-5.6" }, "bad name!": { "model": "gpt-5.6" },
                              "empty": {}, "with_secret": { "model": "sk-token" } } }),
    );
    inputs.insert(
        "root_markers".to_owned(),
        json!({ "project_root_markers": [".git", "", "x".repeat(257), "api_key", "Cargo.toml", 7] }),
    );
    inputs.insert(
        "projects".to_owned(),
        json!({ "projects": {
            "/abs/trusted": { "trust_level": "trusted" },
            "/abs/untrusted": { "trust_level": "untrusted" },
            "/abs/bogus": { "trust_level": "maybe" },
            "relative/path": { "trust_level": "trusted" }
        } }),
    );
    inputs.insert(
        "bad_profile_name".to_owned(),
        json!({ "profile": "not a profile!" }),
    );
    inputs
}

fn runtime_inputs() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("empty".to_owned(), json!({})),
        (
            "with_sandbox".to_owned(),
            json!({ "sandbox_mode": "danger-full-access", "model": "gpt-5.6" }),
        ),
        (
            "with_permissions".to_owned(),
            json!({ "permissions": { "existing": { "filesystem": {} } } }),
        ),
    ])
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/config-projection.json")).expect("fixture parses")
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().expect("object").clone()
}

#[test]
fn projects_preflight_config_identically_to_the_typescript_implementation() {
    let fixture = fixture();
    let inputs = inputs();
    assert_eq!(
        inputs.len(),
        fixture.preflight.len(),
        "every case is compared"
    );

    let mut mismatches = Vec::new();
    for (name, input) in &inputs {
        let expected = fixture.preflight.get(name).expect("fixture case");
        let actual = scan_preflight_codex_config(&object(input));
        match (&expected.ok, &expected.error, actual) {
            (Some(expected), _, Ok(actual)) => {
                if &Value::Object(actual.clone()) != expected {
                    mismatches.push(format!(
                        "{name}: expected {expected}, got {}",
                        Value::Object(actual)
                    ));
                }
            }
            (_, Some(expected), Err(actual)) => {
                if actual.to_string() != *expected {
                    mismatches.push(format!("{name}: expected error {expected}, got {actual}"));
                }
            }
            (_, _, result) => mismatches.push(format!("{name}: outcome differs: {result:?}")),
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
fn hardens_runtime_config_identically_to_the_typescript_implementation() {
    let fixture = fixture();

    for (name, input) in runtime_inputs() {
        let expected = fixture.runtime.get(&name).expect("fixture case");
        let actual = Value::Object(scan_runtime_codex_config(&object(&input)));

        assert_eq!(&actual, expected, "{name}");
    }
}

// The sandbox is not negotiable: a configured mode is removed rather than
// merged, so it cannot survive into the scan.
#[test]
fn removes_a_configured_sandbox_mode() {
    let hardened = scan_runtime_codex_config(&object(&json!({
        "sandbox_mode": "danger-full-access",
        "model": "gpt-5.6"
    })));

    assert!(!hardened.contains_key("sandbox_mode"));
    assert_eq!(hardened["allow_login_shell"], json!(false));
    assert_eq!(
        hardened["default_permissions"],
        json!("codex_security_scan")
    );
    assert_eq!(
        hardened["permissions"]["codex_security_scan"]["filesystem"],
        json!({ ":root": "read", ":workspace_roots": "write" })
    );
    assert_eq!(
        hardened["model"],
        json!("gpt-5.6"),
        "unrelated settings survive"
    );
}

#[test]
fn keeps_configured_permissions_alongside_the_scan_profile() {
    let hardened = scan_runtime_codex_config(&object(&json!({
        "permissions": { "existing": { "filesystem": {} } }
    })));

    assert!(
        hardened["permissions"]["existing"].is_object(),
        "caller permissions survive"
    );
    assert!(hardened["permissions"]["codex_security_scan"].is_object());
}

// The preflight projection is an allowlist: a setting nobody thought about is
// dropped rather than disclosed to the model.
#[test]
fn drops_settings_outside_the_allowlist() {
    let projected = scan_preflight_codex_config(&object(&json!({
        "totally_unknown": "kept?",
        "api_key": "sk-secret",
        "model": "gpt-5.6"
    })))
    .expect("projects");

    assert_eq!(projected.len(), 1);
    assert_eq!(projected["model"], json!("gpt-5.6"));
}

// Values are judged by their content, not their key: an allowlisted setting
// holding something credential-shaped is still dropped.
#[test]
fn drops_credential_shaped_values_from_allowlisted_settings() {
    let projected = scan_preflight_codex_config(&object(&json!({
        "model": "sk-my-secret-token",
        "model_provider": "vendor-api-key-1",
        "model_reasoning_effort": "high"
    })))
    .expect("projects");

    assert_eq!(
        projected.len(),
        1,
        "only the innocuous value survives: {projected:?}"
    );
    assert_eq!(projected["model_reasoning_effort"], json!("high"));
}

#[test]
fn keeps_values_that_merely_contain_the_letters() {
    let projected = scan_preflight_codex_config(&object(&json!({
        "model": "monkey",
        "model_provider": "keystone",
        "service_tier": "tokenizer"
    })))
    .expect("projects");

    assert_eq!(
        projected.len(),
        3,
        "substrings are not matches: {projected:?}"
    );
}

#[test]
fn refuses_a_projection_that_is_too_large() {
    // The maximum number of profiles, each holding maximum-length values.
    let mut profiles = Map::new();
    for index in 0..256 {
        profiles.insert(
            format!("profile{index}"),
            json!({ "model": "m".repeat(512), "model_provider": "p".repeat(512) }),
        );
    }
    let mut config = Map::new();
    config.insert("profiles".to_owned(), Value::Object(profiles));

    let error =
        scan_preflight_codex_config(&config).expect_err("a projection this large is refused");

    assert_eq!(
        error.to_string(),
        "The sanitized Codex Security preflight config exceeds the size limit."
    );
}
