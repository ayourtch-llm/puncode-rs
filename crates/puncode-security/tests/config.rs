//! Behavior tests for Codex configuration merging and writing.
//!
//! Ported from `tests-ts/config.test.ts`.

use puncode_security::config::{
    PuncodeSecurityConfig, default_codex_config, merged_codex_config, scan_model_configuration,
    write_codex_config,
};
use serde_json::{Map, Value, json};
use tempfile::TempDir;

fn overrides(value: Value) -> PuncodeSecurityConfig {
    PuncodeSecurityConfig {
        codex_overrides: Some(value.as_object().expect("overrides are an object").clone()),
        ..PuncodeSecurityConfig::default()
    }
}

fn merge_error(value: Value) -> String {
    merged_codex_config(&overrides(value))
        .expect_err("expected a configuration error")
        .to_string()
}

fn parse_toml(text: &str) -> Value {
    // `from_str` parses a document; `str::parse` would read a single value.
    let table: toml::Value = toml::from_str(text).expect("written config is valid TOML");
    serde_json::to_value(table).expect("TOML converts to JSON")
}

#[test]
fn deep_merges_native_multi_agent_v2_defaults() {
    let merged = merged_codex_config(&overrides(json!({
        "features": { "multi_agent_v2": { "max_concurrent_threads_per_session": 4 } },
        "model_reasoning_effort": "high"
    })))
    .expect("merge succeeds");

    assert_eq!(
        merged["features"],
        json!({
            "plugins": true,
            "goals": true,
            "multi_agent_v2": { "enabled": true, "max_concurrent_threads_per_session": 4 }
        })
    );
    assert!(merged.get("agents").is_none());
    assert_eq!(merged["model"], json!("gpt-5.6-sol"));
    assert_eq!(merged["model_reasoning_effort"], json!("high"));
}

#[test]
fn applies_defaults_when_there_are_no_overrides() {
    let merged = merged_codex_config(&PuncodeSecurityConfig::default()).expect("merge succeeds");

    assert_eq!(merged["model"], json!("gpt-5.6-sol"));
    assert_eq!(merged["model_reasoning_effort"], json!("xhigh"));
    assert_eq!(merged["cli_auth_credentials_store"], json!("file"));
    assert_eq!(
        merged["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"],
        json!(9)
    );
}

#[test]
fn rejects_prototype_bearing_override_keys() {
    for key in ["__proto__", "constructor", "prototype"] {
        let value = json!({ "features": { "custom": [{ key: { "polluted": true } }] } });

        assert_eq!(
            merge_error(value),
            format!("Invalid Codex override key: {key}.")
        );
    }
}

// Adversarial: the merge must not mutate the shared defaults, or a second
// merge would inherit the first one's overrides.
#[test]
fn does_not_leak_overrides_between_merges() {
    let first = merged_codex_config(&overrides(json!({
        "model": "custom-model",
        "features": { "multi_agent_v2": { "max_concurrent_threads_per_session": 1 } }
    })))
    .expect("first merge");
    assert_eq!(first["model"], json!("custom-model"));

    let second = merged_codex_config(&PuncodeSecurityConfig::default()).expect("second merge");

    assert_eq!(
        second["model"],
        json!("gpt-5.6-sol"),
        "defaults were mutated"
    );
    assert_eq!(
        second["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"],
        json!(9),
        "defaults were mutated"
    );
    assert_eq!(
        default_codex_config()["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"],
        json!(9)
    );
}

#[test]
fn rejects_owned_plugin_configuration() {
    assert!(merge_error(json!({ "features": false })).contains("features must be a TOML table"));
    assert!(
        merge_error(json!({ "features": { "plugins": false } }))
            .contains("owns plugin loading configuration")
    );
    assert!(merge_error(json!({ "plugins": {} })).contains("owns plugin loading configuration"));
    assert!(
        merge_error(json!({ "marketplaces": {} })).contains("owns plugin loading configuration")
    );
}

#[test]
fn rejects_legacy_multi_agent_settings() {
    assert!(merge_error(json!({ "agents": { "max_threads": 2 } })).contains("legacy v1"));
    assert!(
        merge_error(json!({ "features": { "multi_agent_v2": { "enabled": false } } }))
            .contains("cannot be disabled")
    );
    assert!(
        merge_error(json!({ "profiles": { "legacy": { "agents": { "max_threads": 2 } } } }))
            .contains("legacy v1")
    );
}

#[test]
fn rejects_profiles_that_disable_owned_configuration() {
    assert!(
        merge_error(json!({
            "profile": "disabled",
            "profiles": { "disabled": { "features": { "plugins": false } } }
        }))
        .contains("owns plugin loading configuration")
    );
    assert!(
        merge_error(json!({
            "profile": "disabled",
            "profiles": { "disabled": { "features": { "multi_agent_v2": { "enabled": false } } } }
        }))
        .contains("cannot be disabled")
    );
    assert!(
        merge_error(json!({ "profiles": "not-a-table" })).contains("profiles must be TOML tables")
    );
    assert!(
        merge_error(json!({ "profiles": { "bad": "not-a-table" } }))
            .contains("profile bad must be a TOML table")
    );
    assert!(
        merge_error(json!({ "profiles": { "bad": { "features": false } } }))
            .contains("profile bad features must be a TOML table")
    );
}

#[test]
fn accepts_profiles_that_only_tune_multi_agent_limits() {
    let merged = merged_codex_config(&overrides(json!({
        "profiles": {
            "deep": {
                "features": { "multi_agent_v2": { "max_concurrent_threads_per_session": 5 } }
            }
        }
    })))
    .expect("tuning a profile limit is allowed");

    assert_eq!(
        merged["profiles"]["deep"]["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"],
        json!(5)
    );
}

#[test]
fn writes_toml_atomically_with_restrictive_permissions() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("home").join("config.toml");
    let config = json!({
        "features": { "plugins": true, "goals": true },
        "agents": { "max_threads": 12 },
        "model_reasoning_effort": "high"
    });

    write_codex_config(&path, config.as_object().expect("object")).expect("write config");

    let text = std::fs::read_to_string(&path).expect("read config");
    assert_eq!(parse_toml(&text), config);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "config must not be group or world readable"
        );
    }
}

#[test]
fn serializes_numeric_overrides() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("config.toml");
    let config = json!({
        "max_safe": 9_007_199_254_740_991_i64,
        "fractional": 1.5,
        "exponent": 1e-7
    });

    write_codex_config(&path, config.as_object().expect("object")).expect("write config");

    let text = std::fs::read_to_string(&path).expect("read config");
    assert_eq!(parse_toml(&text), config);
}

#[test]
fn serializes_nested_inline_tables_in_arrays() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("config.toml");
    let config = json!({
        "hooks": {
            "SessionStart": [{
                "matcher": "*",
                "hooks": [{ "type": "command", "command": "echo hi" }]
            }]
        }
    });

    write_codex_config(&path, config.as_object().expect("object")).expect("write config");

    let text = std::fs::read_to_string(&path).expect("read config");
    assert_eq!(parse_toml(&text), config);
}

// TOML has no null, so a config carrying one cannot be written.
#[test]
fn rejects_a_configuration_that_cannot_be_serialized() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("config.toml");
    let config = json!({ "model": Value::Null });

    let error = write_codex_config(&path, config.as_object().expect("object"))
        .expect_err("null cannot be represented in TOML");

    assert_eq!(error.to_string(), "Invalid Codex configuration.");
    assert!(!path.exists(), "a failed write must not create the target");
}

// Adversarial: a failed write must not leave its temporary file behind.
#[test]
fn leaves_no_temporary_file_behind_after_a_failed_write() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("config.toml");

    let _ = write_codex_config(
        &path,
        json!({ "bad": Value::Null }).as_object().expect("object"),
    );

    let leftovers: Vec<_> = std::fs::read_dir(root.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files remained: {leftovers:?}"
    );
}

#[test]
fn replaces_an_existing_configuration() {
    let root = TempDir::new().expect("temp dir");
    let path = root.path().join("config.toml");
    write_codex_config(
        &path,
        json!({ "model": "first" }).as_object().expect("object"),
    )
    .expect("first write");

    write_codex_config(
        &path,
        json!({ "model": "second" }).as_object().expect("object"),
    )
    .expect("second write");

    let text = std::fs::read_to_string(&path).expect("read config");
    assert_eq!(parse_toml(&text), json!({ "model": "second" }));
    assert_eq!(
        std::fs::read_dir(root.path()).expect("read dir").count(),
        1,
        "only the config should remain"
    );
}

#[test]
fn reads_the_scan_model_configuration() {
    let config = merged_codex_config(&PuncodeSecurityConfig::default()).expect("merge");

    let model = scan_model_configuration(&config).expect("valid configuration");

    assert_eq!(model.model, "gpt-5.6-sol");
    assert_eq!(model.reasoning_effort, "xhigh");
}

#[test]
fn rejects_a_blank_or_missing_scan_model() {
    let cases = [
        json!({}),
        json!({ "model": "" }),
        json!({ "model": "   " }),
        json!({ "model": 7 }),
    ];

    for case in cases {
        let config: Map<String, Value> = case.as_object().expect("object").clone();
        let error = scan_model_configuration(&config).expect_err("model must be present");
        assert_eq!(
            error.to_string(),
            "The configured Codex model must be a nonempty string."
        );
    }
}

#[test]
fn rejects_a_blank_or_missing_reasoning_effort() {
    let cases = [
        json!({ "model": "m" }),
        json!({ "model": "m", "model_reasoning_effort": "" }),
        json!({ "model": "m", "model_reasoning_effort": "  " }),
    ];

    for case in cases {
        let config: Map<String, Value> = case.as_object().expect("object").clone();
        let error = scan_model_configuration(&config).expect_err("effort must be present");
        assert_eq!(
            error.to_string(),
            "The configured Codex reasoning effort must be a nonempty string."
        );
    }
}

// Upstream returns the model verbatim even when it has surrounding whitespace;
// only the emptiness check trims.
#[test]
fn returns_the_model_without_trimming_it() {
    let config: Map<String, Value> =
        json!({ "model": " padded ", "model_reasoning_effort": " high " })
            .as_object()
            .expect("object")
            .clone();

    let model = scan_model_configuration(&config).expect("valid configuration");

    assert_eq!(model.model, " padded ");
    assert_eq!(model.reasoning_effort, " high ");
}
