//! Pointing the scan at an OpenAI-compatible endpoint.

use codex_security::config::{CodexSecurityConfig, merged_codex_config};
use codex_security::model_endpoint::{
    ENDPOINT_PROVIDER, ModelEndpoint, WireApi, model_endpoint_overrides,
    validate_cost_limit_for_endpoint,
};
use serde_json::Value;

fn endpoint(base_url: &str) -> ModelEndpoint {
    ModelEndpoint {
        base_url: base_url.to_owned(),
        ..ModelEndpoint::default()
    }
}

/// The endpoint has to reach Codex as a provider it will actually select, not
/// merely as one it knows about.
#[test]
fn names_the_provider_it_defines() {
    let overrides = model_endpoint_overrides(&endpoint("http://localhost:8080/v1")).expect("valid");

    assert_eq!(
        overrides.get("model_provider").and_then(Value::as_str),
        Some(ENDPOINT_PROVIDER)
    );
    let defined = overrides
        .get("model_providers")
        .and_then(Value::as_object)
        .expect("a provider table");
    assert!(defined.contains_key(ENDPOINT_PROVIDER), "{defined:?}");
}

#[test]
fn carries_the_address_it_was_given() {
    let overrides =
        model_endpoint_overrides(&endpoint("http://198.51.100.10:8080/v1")).expect("valid");

    assert_eq!(
        overrides["model_providers"][ENDPOINT_PROVIDER]["base_url"],
        "http://198.51.100.10:8080/v1"
    );
}

/// Codex 0.146 refuses a provider configured for chat completions, so the
/// default has to be the shape it will actually accept. Defaulting to one it
/// rejects would make every unqualified endpoint fail at startup.
#[test]
fn speaks_the_shape_codex_still_accepts_unless_told_otherwise() {
    let default = model_endpoint_overrides(&endpoint("http://localhost:8080/v1")).expect("valid");
    assert_eq!(
        default["model_providers"][ENDPOINT_PROVIDER]["wire_api"],
        "responses"
    );

    let chat = model_endpoint_overrides(&ModelEndpoint {
        base_url: "http://localhost:8080/v1".to_owned(),
        wire_api: WireApi::Chat,
        ..ModelEndpoint::default()
    })
    .expect("valid");
    assert_eq!(
        chat["model_providers"][ENDPOINT_PROVIDER]["wire_api"],
        "chat"
    );
}

/// Codex reads the key from an environment variable rather than the config, so
/// the config names the variable and never holds the secret itself.
#[test]
fn names_the_variable_holding_the_key_rather_than_the_key() {
    let overrides = model_endpoint_overrides(&ModelEndpoint {
        base_url: "http://localhost:8080/v1".to_owned(),
        api_key_env: "MY_LOCAL_KEY".to_owned(),
        ..ModelEndpoint::default()
    })
    .expect("valid");

    let provider = &overrides["model_providers"][ENDPOINT_PROVIDER];
    assert_eq!(provider["env_key"], "MY_LOCAL_KEY");
    let rendered = serde_json::to_string(&overrides).expect("json");
    assert!(!rendered.contains("Bearer"), "{rendered}");
}

/// A bad address should fail here, where it can be explained, rather than as a
/// connection error minutes into a scan.
#[test]
fn refuses_an_address_that_is_not_a_usable_endpoint() {
    for bad in [
        "",
        "   ",
        "localhost:8080",
        "ftp://localhost:8080/v1",
        "file:///etc/passwd",
        "not a url",
    ] {
        assert!(
            model_endpoint_overrides(&endpoint(bad)).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn accepts_a_secured_address() {
    assert!(model_endpoint_overrides(&endpoint("https://models.example.com/v1")).is_ok());
}

/// The name of the variable ends up in a config file and on a command line, so
/// it has to be a plausible variable name rather than arbitrary text.
#[test]
fn refuses_a_key_variable_that_is_not_a_variable_name() {
    for bad in [
        "",
        "has space",
        "has=equals",
        "lower-case-dashes",
        "1LEADING",
    ] {
        let result = model_endpoint_overrides(&ModelEndpoint {
            base_url: "http://localhost:8080/v1".to_owned(),
            api_key_env: bad.to_owned(),
            ..ModelEndpoint::default()
        });
        assert!(result.is_err(), "accepted {bad:?}");
    }
}

/// What it produces has to survive the merge that actually configures Codex.
#[test]
fn survives_the_merge_into_the_real_configuration() {
    let overrides =
        model_endpoint_overrides(&endpoint("http://198.51.100.10:8080/v1")).expect("ok");
    let merged = merged_codex_config(&CodexSecurityConfig {
        codex_overrides: Some(overrides),
        ..CodexSecurityConfig::default()
    })
    .expect("merges");

    assert_eq!(
        merged.get("model_provider").and_then(Value::as_str),
        Some(ENDPOINT_PROVIDER)
    );
    let rendered = toml::to_string(&merged).expect("toml");
    assert!(
        rendered.contains("http://198.51.100.10:8080/v1"),
        "{rendered}"
    );
}

/// A cost ceiling means nothing against an endpoint whose prices are unknown.
///
/// The model-name check already catches an unpriced model. This catches the
/// case it cannot see: a name that *is* priced, served from somewhere that
/// price does not describe.
#[test]
fn refuses_a_cost_limit_against_a_custom_endpoint() {
    let refused = validate_cost_limit_for_endpoint(Some(5.0), Some("http://localhost:8080/v1"));

    let complaint = refused.expect_err("a refusal").to_string();
    assert!(complaint.contains("cannot be enforced"), "{complaint}");
}

/// Without an endpoint, hosted pricing is exactly what applies.
#[test]
fn allows_a_cost_limit_without_an_endpoint() {
    assert!(validate_cost_limit_for_endpoint(Some(5.0), None).is_ok());
}

/// An endpoint on its own is fine; only the pairing is a problem.
#[test]
fn allows_an_endpoint_without_a_cost_limit() {
    assert!(validate_cost_limit_for_endpoint(None, Some("http://localhost:8080/v1")).is_ok());
}
