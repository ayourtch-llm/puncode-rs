//! Pointing the scan at an OpenAI-compatible endpoint.
//!
//! Not a port: upstream always talks to hosted Codex. This exists so the same
//! scan can run against a self-hosted or otherwise OpenAI-compatible server.
//!
//! Codex already supports this through its own `model_providers` table, so this
//! does not invent a transport — it builds the configuration Codex expects from
//! a small set of parameters, and refuses inputs that would only fail later.
//! Nothing here is defaulted to a particular host: the address is always
//! supplied by the caller.

use serde_json::{Map, Value, json};

use crate::config::JsonObject;
use crate::error::{Error, Result};

/// The provider name the endpoint is registered under.
///
/// Named for this tool rather than something like `local`, so it cannot
/// silently replace a provider the person configured themselves.
pub const ENDPOINT_PROVIDER: &str = "codex-security-endpoint";

/// The request shape an endpoint speaks.
///
/// Codex 0.146 removed support for `chat` and refuses a provider configured
/// with it, so `responses` is the default. `chat` remains selectable for older
/// Codex builds that still accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireApi {
    /// The responses API.
    #[default]
    Responses,
    /// OpenAI chat completions. Refused by Codex 0.146 and later.
    Chat,
}

impl WireApi {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
        }
    }
}

/// Where to run the model, and how to talk to it.
#[derive(Debug, Clone)]
pub struct ModelEndpoint {
    /// The API root, such as `http://localhost:8080/v1`.
    pub base_url: String,
    /// Which request shape the endpoint speaks.
    pub wire_api: WireApi,
    /// The environment variable holding the API key.
    ///
    /// Codex reads the key from the environment, so the configuration names
    /// the variable and never contains the secret.
    pub api_key_env: String,
}

impl Default for ModelEndpoint {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            wire_api: WireApi::default(),
            // The same variable the hosted path already uses, so pointing at a
            // different server does not also mean moving the key.
            api_key_env: "OPENAI_API_KEY".to_owned(),
        }
    }
}

/// Refuses a cost ceiling that could not be enforced against this endpoint.
///
/// Pricing is looked up by model name, which stops meaning anything once the
/// model is served from somewhere else: the same name on another endpoint may
/// cost nothing, or may cost something quite different. Enforcing a hosted
/// price against it would be enforcing a ceiling on a number that does not
/// describe the spending, and a ceiling believed to be protecting someone when
/// it is not is worse than no ceiling at all.
///
/// This sits alongside the model-name check rather than replacing it: that one
/// catches an unpriced model, this catches a priced name being served from
/// somewhere its price does not apply.
pub fn validate_cost_limit_for_endpoint(
    max_cost_usd: Option<f64>,
    base_url: Option<&str>,
) -> Result<()> {
    if max_cost_usd.is_none() || base_url.is_none() {
        return Ok(());
    }
    Err(Error::configuration(
        "A scan cost limit cannot be enforced against a custom model endpoint, \
         because model pricing describes the hosted service rather than this one. \
         Remove the cost limit, or scan without an endpoint.",
    ))
}

/// The Codex configuration that puts the model on this endpoint.
///
/// Fails on an address or variable name that could not work, so the problem is
/// reported here rather than as a connection error minutes into a scan.
pub fn model_endpoint_overrides(endpoint: &ModelEndpoint) -> Result<JsonObject> {
    let base_url = endpoint.base_url.trim();
    require_usable_address(base_url)?;
    require_variable_name(&endpoint.api_key_env)?;

    let mut providers = Map::new();
    providers.insert(
        ENDPOINT_PROVIDER.to_owned(),
        json!({
            "name": "Puncode Security endpoint",
            "base_url": base_url,
            "wire_api": endpoint.wire_api.as_str(),
            "env_key": endpoint.api_key_env,
        }),
    );

    let mut overrides = Map::new();
    overrides.insert(
        "model_provider".to_owned(),
        Value::String(ENDPOINT_PROVIDER.to_owned()),
    );
    overrides.insert("model_providers".to_owned(), Value::Object(providers));
    Ok(overrides)
}

/// Refuses an address the model could not be reached at.
fn require_usable_address(base_url: &str) -> Result<()> {
    if base_url.is_empty() {
        return Err(Error::configuration(
            "A model endpoint address is required, such as http://localhost:8080/v1.",
        ));
    }

    let parsed = url::Url::parse(base_url).map_err(|error| {
        Error::configuration(format!(
            "Model endpoint address is not a URL: {base_url} ({error})"
        ))
    })?;

    // Only the schemes an HTTP API can be served over. A `file:` address in
    // particular would be a request to read the filesystem, not to call a model.
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(Error::configuration(format!(
            "Model endpoint address must be http or https: {base_url}"
        )));
    }
    if !parsed.has_host() {
        return Err(Error::configuration(format!(
            "Model endpoint address has no host: {base_url}"
        )));
    }
    Ok(())
}

/// Refuses something that could not name an environment variable.
fn require_variable_name(name: &str) -> Result<()> {
    let usable = !name.is_empty()
        && !name.starts_with(|character: char| character.is_ascii_digit())
        && name.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        });
    if usable {
        return Ok(());
    }
    Err(Error::configuration(format!(
        "Model endpoint API key variable is not an environment variable name: {name}"
    )))
}
