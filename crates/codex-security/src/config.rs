//! Codex configuration: defaults, override merging, and atomic writes.
//!
//! Ported from `src/config.ts`.
//!
//! One check does not survive the port. Upstream rejects a non-object
//! `codexOverrides` at runtime ("codexOverrides must be an object"), because
//! JavaScript callers can pass anything. Here the field is a JSON object, so
//! that state is unrepresentable; callers deserializing untrusted input get a
//! parse error from serde instead.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::error::{Error, Result};

/// A JSON object, the shape Codex configuration takes before serialization.
pub type JsonObject = Map<String, Value>;

/// Keys that JavaScript treats specially on objects. Upstream refuses them at
/// any depth; the port keeps the check so both implementations accept exactly
/// the same configurations.
const RESERVED_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

const REQUIRES_V2: &str = "The selected Codex Security plugin requires native multi-agent v2; ";

/// Configuration for a Codex Security client.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CodexSecurityConfig {
    pub plugin_path: Option<PathBuf>,
    pub codex_overrides: Option<JsonObject>,
    pub python_path: Option<PathBuf>,
}

/// The model settings a scan will run under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanModelConfiguration {
    pub model: String,
    pub reasoning_effort: String,
}

static DEFAULT_CODEX_CONFIG: LazyLock<JsonObject> = LazyLock::new(|| {
    json!({
        "cli_auth_credentials_store": "file",
        "model": "gpt-5.6-sol",
        "model_reasoning_effort": "xhigh",
        "features": {
            "plugins": true,
            "goals": true,
            "multi_agent_v2": {
                "enabled": true,
                "max_concurrent_threads_per_session": 9,
            },
        },
    })
    .as_object()
    .expect("default configuration is an object")
    .clone()
});

/// The configuration a scan starts from before overrides are applied.
///
/// Upstream deep-freezes this object; here it is shared immutably and every
/// merge works on a clone.
#[must_use]
pub fn default_codex_config() -> &'static JsonObject {
    &DEFAULT_CODEX_CONFIG
}

/// Reads the model settings out of a merged configuration.
pub fn scan_model_configuration(config: &JsonObject) -> Result<ScanModelConfiguration> {
    let model = nonempty_string(config.get("model")).ok_or_else(|| {
        Error::configuration("The configured Codex model must be a nonempty string.")
    })?;
    let reasoning_effort =
        nonempty_string(config.get("model_reasoning_effort")).ok_or_else(|| {
            Error::configuration("The configured Codex reasoning effort must be a nonempty string.")
        })?;

    Ok(ScanModelConfiguration {
        // Returned verbatim: only the emptiness check trims.
        model: model.to_owned(),
        reasoning_effort: reasoning_effort.to_owned(),
    })
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// Applies `config`'s overrides on top of the defaults.
pub fn merged_codex_config(config: &CodexSecurityConfig) -> Result<JsonObject> {
    let empty = JsonObject::new();
    let overrides = config.codex_overrides.as_ref().unwrap_or(&empty);

    validate_override_keys_object(overrides)?;
    validate_overrides(overrides)?;
    validate_native_multi_agent_v2_overrides(overrides)?;

    let mut merged = DEFAULT_CODEX_CONFIG.clone();
    deep_merge(&mut merged, overrides);
    Ok(merged)
}

/// Writes `config` as TOML, atomically and readable only by its owner.
pub fn write_codex_config(path: &Path, config: &JsonObject) -> Result<()> {
    let parent = config_parent(path);
    create_private_dir(parent)?;

    let contents = toml::to_string(config)
        .map_err(|error| Error::configuration("Invalid Codex configuration.").with_source(error))?;

    let temporary = parent.join(temporary_name());
    let write = write_private_file(&temporary, &contents).and_then(|()| {
        fs::rename(&temporary, path).map_err(|error| {
            Error::configuration(format!(
                "Could not write the Codex configuration to {}: {error}",
                path.display()
            ))
            .with_source(error)
        })
    });

    if write.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write
}

/// The directory the configuration and its temporary file live in.
///
/// `Path::parent` yields an empty path for a bare filename such as
/// `config.toml`, which is not a usable directory. Upstream's `dirname` yields
/// `"."` for the same input.
fn config_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// A name unlikely to collide with a concurrent writer's temporary file.
fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{}-{nanos}-{sequence}.config.toml.tmp", std::process::id())
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::configuration(format!(
            "Could not create the Codex configuration directory {}: {error}",
            path.display()
        ))
        .with_source(error)
    })
}

/// Creates `path` exclusively, forces owner-only permissions, and flushes it to
/// disk.
///
/// The permissions are set after creation as well as requested at creation:
/// the mode passed to `open` is masked by the process umask, so a restrictive
/// umask would otherwise leave the file more permissive than intended.
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let configuration_error = |error: std::io::Error| {
        Error::configuration(format!(
            "Could not write the Codex configuration to {}: {error}",
            path.display()
        ))
        .with_source(error)
    };

    let mut file = options.open(path).map_err(configuration_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(configuration_error)?;
    }
    file.write_all(contents.as_bytes())
        .map_err(configuration_error)?;
    file.sync_all().map_err(configuration_error)?;
    Ok(())
}

/// Rejects JavaScript-reserved keys anywhere in the overrides, including inside
/// arrays.
fn validate_override_keys(value: &Value) -> Result<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                validate_override_keys(item)?;
            }
            Ok(())
        }
        Value::Object(object) => validate_override_keys_object(object),
        _ => Ok(()),
    }
}

fn validate_override_keys_object(object: &JsonObject) -> Result<()> {
    for (key, item) in object {
        if RESERVED_KEYS.contains(&key.as_str()) {
            return Err(Error::configuration(format!(
                "Invalid Codex override key: {key}."
            )));
        }
        validate_override_keys(item)?;
    }
    Ok(())
}

fn validate_overrides(overrides: &JsonObject) -> Result<()> {
    let owns_plugins = || Error::configuration("Codex Security owns plugin loading configuration.");

    if overrides.contains_key("plugins") || overrides.contains_key("marketplaces") {
        return Err(owns_plugins());
    }
    if overrides.contains_key("features") {
        let features = overrides["features"]
            .as_object()
            .ok_or_else(|| Error::configuration("Codex override features must be a TOML table."))?;
        if features.contains_key("plugins") {
            return Err(owns_plugins());
        }
    }

    let Some(profiles) = overrides.get("profiles") else {
        return Ok(());
    };
    let profiles = profiles
        .as_object()
        .ok_or_else(|| Error::configuration("Codex override profiles must be TOML tables."))?;

    for (name, profile) in profiles {
        let profile = profile.as_object().ok_or_else(|| {
            Error::configuration(format!(
                "Codex override profile {name} must be a TOML table."
            ))
        })?;
        let Some(features) = profile.get("features") else {
            continue;
        };
        let features = features.as_object().ok_or_else(|| {
            Error::configuration(format!(
                "Codex override profile {name} features must be a TOML table."
            ))
        })?;
        if features.contains_key("plugins") {
            return Err(Error::configuration(format!(
                "Codex Security owns plugin loading configuration in profile {name}."
            )));
        }
    }
    Ok(())
}

/// The bundled plugin needs native multi-agent v2, so overrides may not disable
/// it or fall back to the v1 thread limit.
fn validate_native_multi_agent_v2_overrides(overrides: &JsonObject) -> Result<()> {
    if let Some(agents) = overrides.get("agents").and_then(Value::as_object)
        && agents.contains_key("max_threads")
    {
        return Err(Error::configuration(format!(
            "{REQUIRES_V2}agents.max_threads is a legacy v1 setting. Use \
             features.multi_agent_v2.max_concurrent_threads_per_session instead."
        )));
    }

    if let Some(features) = overrides.get("features") {
        let features = features.as_object().ok_or_else(|| {
            Error::configuration(format!(
                "{REQUIRES_V2}features must remain a table containing features.multi_agent_v2."
            ))
        })?;
        if let Some(multi_agent_v2) = features.get("multi_agent_v2") {
            let multi_agent_v2 = multi_agent_v2.as_object().ok_or_else(|| {
                Error::configuration(format!(
                    "{REQUIRES_V2}features.multi_agent_v2 must remain a table with enabled = true."
                ))
            })?;
            if multi_agent_v2
                .get("enabled")
                .is_some_and(|enabled| enabled != &Value::Bool(true))
            {
                return Err(Error::configuration(format!(
                    "{REQUIRES_V2}features.multi_agent_v2.enabled cannot be disabled."
                )));
            }
        }
    }

    let Some(profiles) = overrides.get("profiles").and_then(Value::as_object) else {
        return Ok(());
    };
    for (name, profile) in profiles {
        let Some(profile) = profile.as_object() else {
            continue;
        };
        if let Some(agents) = profile.get("agents").and_then(Value::as_object)
            && agents.contains_key("max_threads")
        {
            return Err(Error::configuration(format!(
                "{REQUIRES_V2}profile {name} agents.max_threads is a legacy v1 setting."
            )));
        }
        let Some(features) = profile.get("features").and_then(Value::as_object) else {
            continue;
        };
        let Some(multi_agent_v2) = features.get("multi_agent_v2") else {
            continue;
        };
        let disabled = multi_agent_v2.as_object().is_none_or(|table| {
            table
                .get("enabled")
                .is_some_and(|enabled| enabled != &Value::Bool(true))
        });
        if disabled {
            return Err(Error::configuration(format!(
                "{REQUIRES_V2}profile {name} features.multi_agent_v2 cannot be disabled."
            )));
        }
    }
    Ok(())
}

/// Merges `overrides` into `base`, recursing only where both sides are tables.
fn deep_merge(base: &mut JsonObject, overrides: &JsonObject) {
    for (key, value) in overrides {
        let merged = match (base.get(key), value) {
            (Some(Value::Object(existing)), Value::Object(override_table)) => {
                let mut existing = existing.clone();
                deep_merge(&mut existing, override_table);
                Value::Object(existing)
            }
            _ => value.clone(),
        };
        base.insert(key.clone(), merged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare filename must resolve to the current directory, not an empty
    /// path: `create_dir_all("")` fails, so writing to `config.toml` would
    /// error where upstream succeeds.
    #[test]
    fn resolves_the_parent_of_a_bare_filename() {
        assert_eq!(config_parent(Path::new("config.toml")), Path::new("."));
        assert_eq!(
            config_parent(Path::new("home/config.toml")),
            Path::new("home")
        );
        assert_eq!(config_parent(Path::new("/config.toml")), Path::new("/"));
        assert_eq!(config_parent(Path::new("/")), Path::new("."));
    }

    #[test]
    fn temporary_names_do_not_repeat() {
        let first = temporary_name();
        let second = temporary_name();

        assert_ne!(first, second);
        assert!(first.starts_with('.') && first.ends_with(".config.toml.tmp"));
    }
}
