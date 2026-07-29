//! Removing the stored sign-in.
//!
//! Ported from the `logout` command in `src/cli.ts`.
//!
//! This deliberately runs against the user's own Codex home rather than an
//! isolated one: the point is to remove the credentials a scan would otherwise
//! pick up, and credentials in a temporary home would already be gone.

use codex_security::auth::run_codex;
use codex_security::runtime::resolve_codex_command;
use codex_security::targets::ProcessEnvironment;

/// Signs out, reporting what Codex said if it refused.
pub fn run(environment: &ProcessEnvironment) -> Result<String, String> {
    // The current directory stands in for a protected root: there is no
    // repository here, but a `codex` sitting in the working directory is still
    // not something to run.
    let protected_root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let command =
        resolve_codex_command(environment, &protected_root).map_err(|error| error.to_string())?;

    // The credential store is named explicitly so the sign-in removed is the
    // one a scan would have used.
    let result = run_codex(
        &command,
        &["logout", "-c", "cli_auth_credentials_store=\"file\""],
        environment,
        None,
    )
    .map_err(|error| error.to_string())?;

    if !result.success {
        let detail = [result.stderr.trim(), result.stdout.trim()]
            .into_iter()
            .find(|candidate| !candidate.is_empty())
            .unwrap_or("unknown error");
        return Err(format!("Could not sign out: {detail}"));
    }
    Ok("Signed out.".to_owned())
}
