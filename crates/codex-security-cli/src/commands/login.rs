//! Signing in to Codex.
//!
//! Ported from the `login` command in `src/cli.ts`.
//!
//! Signing in is a conversation: Codex prints a URL or a code and waits for the
//! person to finish in a browser, and `--with-api-key` reads a secret from
//! standard input. So this hands the terminal straight to Codex rather than
//! capturing it — a captured prompt is one nobody can answer, and a captured
//! secret is one that ends up in a buffer.

use codex_security::api::{ApiKeySource, ScanAuthentication, scan_authentication};
use codex_security::runtime::resolve_codex_command;
use codex_security::targets::ProcessEnvironment;

use crate::cli::{LoginAction, LoginArgs};

/// What signing in did.
pub struct LoginOutcome {
    /// Lines for the person, on standard error.
    pub notes: Vec<String>,
    pub exit_code: u8,
}

/// Signs in, or reports who is signed in.
pub fn run(
    arguments: &LoginArgs,
    environment: &ProcessEnvironment,
) -> Result<LoginOutcome, String> {
    let protected_root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let command =
        resolve_codex_command(environment, &protected_root).map_err(|error| error.to_string())?;

    let mut codex_arguments: Vec<String> = vec!["login".to_owned()];
    if arguments.action == Some(LoginAction::Status) {
        codex_arguments.push("status".to_owned());
    }
    for (asked, flag) in [
        (arguments.device_auth, "--device-auth"),
        (arguments.with_api_key, "--with-api-key"),
        (arguments.with_access_token, "--with-access-token"),
    ] {
        if asked {
            codex_arguments.push(flag.to_owned());
        }
    }
    // Named explicitly so the sign-in stored is the one a scan will look for.
    codex_arguments.push("-c".to_owned());
    codex_arguments.push("cli_auth_credentials_store=\"file\"".to_owned());

    // Inherited rather than captured: the person has to be able to answer.
    let status = std::process::Command::new(&command.command)
        .args(&command.prefix_args)
        .args(&codex_arguments)
        .env_clear()
        .envs(environment)
        .status()
        .map_err(|error| format!("Could not run Codex login: {error}"))?;
    let exit_code = u8::try_from(status.code().unwrap_or(1)).unwrap_or(1);

    if arguments.action != Some(LoginAction::Status) {
        return Ok(LoginOutcome {
            notes: Vec::new(),
            exit_code,
        });
    }

    // A key in the environment is what a scan would actually use, whatever
    // Codex has stored, so saying only "signed in as ..." would be misleading.
    match scan_authentication(environment) {
        ScanAuthentication::ApiKey { source, .. } if matches!(exit_code, 0 | 1) => {
            Ok(LoginOutcome {
                notes: vec![
                    format!(
                        "Effective scan authentication: API key from {}.",
                        match source {
                            ApiKeySource::OpenAiApiKey => "OPENAI_API_KEY",
                            ApiKeySource::CodexApiKey => "CODEX_API_KEY",
                        }
                    ),
                    "To use a ChatGPT sign-in, unset OPENAI_API_KEY and CODEX_API_KEY.".to_owned(),
                ],
                exit_code: 0,
            })
        }
        _ => Ok(LoginOutcome {
            notes: Vec::new(),
            exit_code,
        }),
    }
}
