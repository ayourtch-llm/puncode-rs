//! Deciding what configuration a scan is allowed to see.
//!
//! Ported from `scanRuntimeCodexConfig` and `scanPreflightCodexConfig` in
//! `src/api.ts`.
//!
//! Two different problems. The runtime projection *hardens* the configuration a
//! scan runs under: the sandbox is not negotiable and the filesystem is
//! read-only outside the workspace. The preflight projection instead *narrows*
//! the configuration reported back out — it is an allowlist, not a filter, so a
//! setting nobody thought about is dropped rather than disclosed, and any value
//! that reads like a credential is dropped even if its key looked harmless.

#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// The permission profile a scan runs under.
const SCAN_PERMISSION_PROFILE: &str = "codex_security_scan";

/// How large the sanitized preflight configuration may be.
const MAX_PREFLIGHT_BYTES: usize = 256 * 1024;

/// Entries kept from a collection before truncation.
const MAX_COLLECTION_ENTRIES: usize = 256;
/// Root markers kept.
const MAX_ROOT_MARKERS: usize = 64;

/// The largest integer a projected setting may carry.
const MAX_SAFE_SETTING: i64 = 1_000_000;

/// Words that make a value look like a credential wherever it appears.
///
/// Matched against the *value*, not the key: a harmless-looking setting can
/// still hold a token, and preflight output is shown to the model.
static SECRET_SHAPED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[^a-z0-9])(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|key|secret|token|env|mcp|set|password|passwd|credential|authorization|bearer)(?:[^a-z0-9]|$)",
    )
    .expect("valid pattern")
});

static PROFILE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid pattern"));

/// Hardens the configuration a scan runs under.
///
/// `sandbox_mode` is removed rather than overridden so a configured value
/// cannot survive, and the scan profile is installed alongside any permissions
/// the caller configured.
#[must_use]
pub fn scan_runtime_codex_config(config: &Map<String, Value>) -> Map<String, Value> {
    let mut hardened = config.clone();
    hardened.remove("sandbox_mode");

    let mut permissions = hardened
        .get("permissions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    permissions.insert(
        SCAN_PERMISSION_PROFILE.to_owned(),
        serde_json::json!({
            "filesystem": {
                ":root": "read",
                ":workspace_roots": "write",
            }
        }),
    );

    hardened.insert("allow_login_shell".to_owned(), Value::Bool(false));
    hardened.insert(
        "default_permissions".to_owned(),
        Value::String(SCAN_PERMISSION_PROFILE.to_owned()),
    );
    hardened.insert("permissions".to_owned(), Value::Object(permissions));
    hardened
}

/// Narrows configuration down to what preflight may report.
///
/// Only known-safe settings survive, and the result is size-bounded because it
/// is handed to the model.
///
/// One difference from upstream worth knowing: where more than
/// `MAX_COLLECTION_ENTRIES` profiles or projects are configured, upstream keeps
/// the first in JavaScript insertion order while this keeps the first in sorted
/// key order. Both keep a bounded, sanitized subset; which subset differs only
/// past the limit.
pub fn scan_preflight_codex_config(config: &Map<String, Value>) -> Result<Map<String, Value>> {
    let mut result = execution_config(config);

    if let Some(profile) = config.get("profile").and_then(safe_profile_name) {
        result.insert("profile".to_owned(), Value::String(profile.to_owned()));
    }

    if let Some(profiles) = config.get("profiles").and_then(Value::as_object) {
        let mut sanitized = Map::new();
        for (name, profile) in profiles.iter().take(MAX_COLLECTION_ENTRIES) {
            let (Some(name), Some(profile)) = (
                safe_profile_name(&Value::String(name.clone())).map(str::to_owned),
                profile.as_object(),
            ) else {
                continue;
            };
            let projected = execution_config(profile);
            if !projected.is_empty() {
                sanitized.insert(name, Value::Object(projected));
            }
        }
        if !sanitized.is_empty() {
            result.insert("profiles".to_owned(), Value::Object(sanitized));
        }
    }

    if let Some(markers) = config.get("project_root_markers").and_then(Value::as_array) {
        let kept: Vec<Value> = markers
            .iter()
            .filter(|marker| safe_string(marker, 256).is_some())
            .take(MAX_ROOT_MARKERS)
            .cloned()
            .collect();
        result.insert("project_root_markers".to_owned(), Value::Array(kept));
    }

    if let Some(projects) = config.get("projects").and_then(Value::as_object) {
        let mut sanitized = Map::new();
        for (path, project) in projects.iter().take(MAX_COLLECTION_ENTRIES) {
            let path_value = Value::String(path.clone());
            if safe_string(&path_value, 4096).is_none() || !std::path::Path::new(path).is_absolute()
            {
                continue;
            }
            let Some(project) = project.as_object() else {
                continue;
            };
            // Only the two known trust levels; anything else is not a value
            // this projection understands.
            let trust = project.get("trust_level").and_then(Value::as_str);
            if trust != Some("trusted") && trust != Some("untrusted") {
                continue;
            }
            sanitized.insert(
                path.clone(),
                serde_json::json!({ "trust_level": trust.unwrap_or_default() }),
            );
        }
        if !sanitized.is_empty() {
            result.insert("projects".to_owned(), Value::Object(sanitized));
        }
    }

    let encoded = serde_json::to_string(&Value::Object(result.clone())).map_err(|error| {
        Error::puncode_security(
            "The sanitized Codex Security preflight config exceeds the size limit.",
        )
        .with_source(error)
    })?;
    if encoded.len() > MAX_PREFLIGHT_BYTES {
        return Err(Error::puncode_security(
            "The sanitized Codex Security preflight config exceeds the size limit.",
        ));
    }
    Ok(result)
}

/// The execution settings that may be reported, from a config or one profile.
fn execution_config(source: &Map<String, Value>) -> Map<String, Value> {
    let mut result = Map::new();

    for key in [
        "model",
        "model_reasoning_effort",
        "model_provider",
        "service_tier",
    ] {
        if let Some(value) = source.get(key).and_then(|value| safe_string(value, 512)) {
            result.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }

    let features = capability_features(source.get("features"));
    if !features.is_empty() {
        result.insert("features".to_owned(), Value::Object(features));
    }

    if let Some(agents) = source.get("agents").and_then(Value::as_object) {
        let mut sanitized = Map::new();
        for key in ["max_threads", "max_depth"] {
            if let Some(value) = agents.get(key).and_then(safe_integer) {
                sanitized.insert(key.to_owned(), Value::from(value));
            }
        }
        if !sanitized.is_empty() {
            result.insert("agents".to_owned(), Value::Object(sanitized));
        }
    }

    if let Some(concurrency) = source
        .get("multiagent_config")
        .and_then(Value::as_object)
        .and_then(|config| config.get("max_concurrency"))
        .and_then(safe_integer)
    {
        result.insert(
            "multiagent_config".to_owned(),
            serde_json::json!({ "max_concurrency": concurrency }),
        );
    }

    result
}

/// The capability flags that may be reported.
fn capability_features(value: Option<&Value>) -> Map<String, Value> {
    let mut result = Map::new();
    let Some(features) = value.and_then(Value::as_object) else {
        return result;
    };

    for key in ["goals", "multi_agent", "enable_fanout"] {
        if let Some(flag) = features.get(key).and_then(Value::as_bool) {
            result.insert(key.to_owned(), Value::Bool(flag));
        }
    }

    match features.get("multi_agent_v2") {
        Some(Value::Bool(flag)) => {
            result.insert("multi_agent_v2".to_owned(), Value::Bool(*flag));
        }
        Some(Value::Object(multi_agent)) => {
            let mut sanitized = Map::new();
            if let Some(enabled) = multi_agent.get("enabled").and_then(Value::as_bool) {
                sanitized.insert("enabled".to_owned(), Value::Bool(enabled));
            }
            if let Some(capacity) = multi_agent
                .get("max_concurrent_threads_per_session")
                .and_then(safe_integer)
            {
                sanitized.insert(
                    "max_concurrent_threads_per_session".to_owned(),
                    Value::from(capacity),
                );
            }
            if !sanitized.is_empty() {
                result.insert("multi_agent_v2".to_owned(), Value::Object(sanitized));
            }
        }
        _ => {}
    }
    result
}

/// A string short enough, free of control characters, and not credential-shaped.
fn safe_string(value: &Value, max_length: usize) -> Option<&str> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > max_length {
        return None;
    }
    if text
        .chars()
        .any(|character| matches!(character, '\u{0}'..='\u{1f}' | '\u{7f}'))
    {
        return None;
    }
    (!SECRET_SHAPED.is_match(text)).then_some(text)
}

fn safe_profile_name(value: &Value) -> Option<&str> {
    let text = safe_string(value, 128)?;
    PROFILE_NAME.is_match(text).then_some(text)
}

/// A non-negative integer small enough to be a plausible setting.
fn safe_integer(value: &Value) -> Option<i64> {
    let number = value.as_i64()?;
    (0..=MAX_SAFE_SETTING).contains(&number).then_some(number)
}
