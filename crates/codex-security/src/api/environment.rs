//! Reading credentials and settings out of the environment.
//!
//! Ported from `environmentValue`, `environmentApiKey`, `scanAuthentication`,
//! `withoutCodexHome`, `definedEnvironment` and `initialCredentialsAvailable`
//! in `src/api.ts`.
//!
//! Variable names are matched case-insensitively, because a scan may inherit an
//! environment assembled by a shell, a CI system, or Windows, and a credential
//! that is present but spelled differently should not silently look absent.
//!
//! Upstream's `definedEnvironment` drops variables whose value is `undefined`;
//! that state does not exist here, so no equivalent is needed.

#![allow(dead_code)]

use std::path::Path;

use crate::error::Result;
use crate::targets::ProcessEnvironment;

/// Which variable supplied an API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeySource {
    OpenAiApiKey,
    CodexApiKey,
}

impl ApiKeySource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiApiKey => "OPENAI_API_KEY",
            Self::CodexApiKey => "CODEX_API_KEY",
        }
    }
}

/// How a scan will authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAuthentication {
    /// Credentials stored in the Codex home.
    StoredCredentials { verified: bool },
    /// A key supplied through the environment.
    ApiKey {
        source: ApiKeySource,
        verified: bool,
    },
}

/// The variables an API key may arrive in, most preferred first.
const API_KEY_VARIABLES: [ApiKeySource; 2] =
    [ApiKeySource::OpenAiApiKey, ApiKeySource::CodexApiKey];

/// Reads a variable, preferring an exact name but accepting any casing.
///
/// The value is returned as written; only the blank check trims.
#[must_use]
pub fn environment_value<'a>(
    environment: &'a ProcessEnvironment,
    requested: &str,
) -> Option<&'a str> {
    if let Some(exact) = environment
        .get(requested)
        .filter(|value| !value.trim().is_empty())
    {
        return Some(exact);
    }
    environment
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case(requested) && !value.trim().is_empty())
        .map(|(_, value)| value.as_str())
}

/// The API key in the environment, and where it came from.
///
/// Each variable is checked completely — exact spelling then any casing —
/// before the next is considered, so a differently-cased `OPENAI_API_KEY` still
/// takes precedence over an exact `CODEX_API_KEY`.
#[must_use]
pub fn environment_api_key_entry(
    environment: &ProcessEnvironment,
) -> Option<(ApiKeySource, String)> {
    for source in API_KEY_VARIABLES {
        if let Some(value) = environment_value(environment, source.as_str()) {
            return Some((source, value.trim().to_owned()));
        }
    }
    None
}

/// The API key in the environment, if there is one.
#[must_use]
pub fn environment_api_key(environment: &ProcessEnvironment) -> Option<String> {
    environment_api_key_entry(environment).map(|(_, value)| value)
}

/// How a scan will authenticate, before anything has been checked.
#[must_use]
pub fn scan_authentication(environment: &ProcessEnvironment) -> ScanAuthentication {
    match environment_api_key_entry(environment) {
        Some((source, _)) => ScanAuthentication::ApiKey {
            source,
            verified: false,
        },
        None => ScanAuthentication::StoredCredentials { verified: false },
    }
}

/// The environment with any `CODEX_HOME` removed.
///
/// The isolated home is set deliberately where it is needed; an inherited one
/// would send a subprocess to the user's real Codex home instead.
#[must_use]
pub fn without_codex_home(environment: &ProcessEnvironment) -> ProcessEnvironment {
    environment
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("CODEX_HOME"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Whether the scan starts with usable stored credentials.
///
/// An API key in the environment takes precedence, so there is nothing to
/// import; otherwise the user's ambient credentials are copied into the
/// isolated home and the answer is whether any were found.
pub fn initial_credentials_available(
    environment: &ProcessEnvironment,
    ambient_home: &str,
    isolated_home: &Path,
    importer: &dyn Fn(&str, &Path, &ProcessEnvironment) -> Result<bool>,
) -> Result<bool> {
    if environment_api_key(environment).is_some() {
        return Ok(false);
    }
    importer(ambient_home, isolated_home, environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(pairs: &[(&str, &str)]) -> ProcessEnvironment {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn reads_a_variable_by_exact_name() {
        let environment = environment(&[("CODEX_HOME", "/home/user/.codex")]);

        assert_eq!(
            environment_value(&environment, "CODEX_HOME"),
            Some("/home/user/.codex")
        );
    }

    #[test]
    fn reads_a_variable_whatever_its_casing() {
        let environment = environment(&[("codex_home", "/home/user/.codex")]);

        assert_eq!(
            environment_value(&environment, "CODEX_HOME"),
            Some("/home/user/.codex")
        );
    }

    #[test]
    fn treats_a_blank_variable_as_absent() {
        let environment = environment(&[("CODEX_HOME", "   ")]);

        assert_eq!(environment_value(&environment, "CODEX_HOME"), None);
    }

    // Only the blank check trims; the value itself is returned as written.
    #[test]
    fn returns_the_value_without_trimming_it() {
        let environment = environment(&[("CODEX_HOME", " /padded ")]);

        assert_eq!(
            environment_value(&environment, "CODEX_HOME"),
            Some(" /padded ")
        );
    }

    #[test]
    fn falls_back_to_a_differently_cased_variable_when_the_exact_one_is_blank() {
        let environment = environment(&[("CODEX_HOME", ""), ("Codex_Home", "/from/other")]);

        assert_eq!(
            environment_value(&environment, "CODEX_HOME"),
            Some("/from/other")
        );
    }

    #[test]
    fn finds_an_api_key_and_names_its_source() {
        let environment = environment(&[("OPENAI_API_KEY", "sk-one")]);

        assert_eq!(
            environment_api_key_entry(&environment),
            Some((ApiKeySource::OpenAiApiKey, "sk-one".to_owned()))
        );
        assert_eq!(environment_api_key(&environment), Some("sk-one".to_owned()));
    }

    #[test]
    fn trims_the_api_key_value() {
        let environment = environment(&[("CODEX_API_KEY", "  sk-padded  ")]);

        assert_eq!(
            environment_api_key(&environment),
            Some("sk-padded".to_owned())
        );
    }

    // Each variable is resolved completely before the next is considered.
    #[test]
    fn prefers_openai_even_when_only_its_casing_differs() {
        let environment = environment(&[
            ("openai_api_key", "sk-openai"),
            ("CODEX_API_KEY", "sk-codex"),
        ]);

        assert_eq!(
            environment_api_key_entry(&environment),
            Some((ApiKeySource::OpenAiApiKey, "sk-openai".to_owned())),
            "a differently-cased OPENAI_API_KEY still outranks an exact CODEX_API_KEY"
        );
    }

    #[test]
    fn falls_back_to_the_codex_key() {
        let environment = environment(&[("OPENAI_API_KEY", "  "), ("CODEX_API_KEY", "sk-codex")]);

        assert_eq!(
            environment_api_key_entry(&environment),
            Some((ApiKeySource::CodexApiKey, "sk-codex".to_owned()))
        );
    }

    #[test]
    fn reports_no_key_when_there_is_none() {
        assert_eq!(
            environment_api_key(&environment(&[("PATH", "/usr/bin")])),
            None
        );
    }

    #[test]
    fn describes_how_a_scan_will_authenticate() {
        assert_eq!(
            scan_authentication(&environment(&[("OPENAI_API_KEY", "sk-one")])),
            ScanAuthentication::ApiKey {
                source: ApiKeySource::OpenAiApiKey,
                verified: false
            }
        );
        assert_eq!(
            scan_authentication(&environment(&[])),
            ScanAuthentication::StoredCredentials { verified: false }
        );
    }

    // An inherited CODEX_HOME would send a subprocess to the user's real home.
    #[test]
    fn removes_the_codex_home_whatever_its_casing() {
        let environment = environment(&[
            ("CODEX_HOME", "/real"),
            ("codex_home", "/also-real"),
            ("KEEP", "ok"),
        ]);

        let stripped = without_codex_home(&environment);

        assert!(
            !stripped
                .keys()
                .any(|name| name.eq_ignore_ascii_case("CODEX_HOME"))
        );
        assert_eq!(stripped["KEEP"], "ok");
    }

    // An environment key means there is nothing to import.
    #[test]
    fn reports_no_stored_credentials_when_a_key_is_in_the_environment() {
        let environment = environment(&[("OPENAI_API_KEY", "sk-one")]);
        let importer = |_: &str, _: &Path, _: &ProcessEnvironment| -> Result<bool> {
            panic!("the importer must not run when a key is present")
        };

        let available =
            initial_credentials_available(&environment, "~/.codex", Path::new("/iso"), &importer)
                .expect("resolves");

        assert!(!available);
    }

    #[test]
    fn reports_whether_ambient_credentials_were_imported() {
        let environment = environment(&[]);
        let found = |_: &str, _: &Path, _: &ProcessEnvironment| -> Result<bool> { Ok(true) };
        let absent = |_: &str, _: &Path, _: &ProcessEnvironment| -> Result<bool> { Ok(false) };

        assert!(
            initial_credentials_available(&environment, "~/.codex", Path::new("/iso"), &found)
                .expect("resolves")
        );
        assert!(
            !initial_credentials_available(&environment, "~/.codex", Path::new("/iso"), &absent)
                .expect("resolves")
        );
    }
}
