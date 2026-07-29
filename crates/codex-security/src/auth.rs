//! Signing Codex in and out.
//!
//! Ported from `src/auth.ts`.
//!
//! Codex owns the credentials; this module only drives its login commands and
//! reads back what they printed. The one piece of real logic is finding the URL
//! a user should open: `codex login` prints a local callback URL alongside the
//! real one, and showing the local one would send the user nowhere useful.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, LazyLock, Mutex};

use regex::Regex;
use url::Url;

use crate::error::{Error, Result};
use crate::runtime::CodexCommand;
use crate::targets::ProcessEnvironment;

/// What a Codex command reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    pub success: bool,
    /// `None` when the command was killed by a signal.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Whether Codex currently has usable credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatus {
    pub authenticated: bool,
    /// What Codex said, for showing to the user.
    pub details: String,
}

/// Terminal escape sequences that would otherwise break URL detection.
static OSC_SEQUENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\u{1b}\\][^\u{7}]*(?:\u{7}|\u{1b}\\\\)").expect("valid pattern"));
static CSI_SEQUENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\u{1b}\\[[0-?]*[ -/]*[@-~]").expect("valid pattern"));
static URL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://[^\s<>]+").expect("valid pattern"));

/// Punctuation that commonly follows a URL in prose rather than belonging to it.
const TRAILING_PUNCTUATION: [char; 8] = ['.', ',', ';', ':', '!', '?', ')', ']'];

/// Runs a Codex command, optionally writing `input` to its standard input.
pub fn run_codex(
    command: &CodexCommand,
    args: &[&str],
    environment: &ProcessEnvironment,
    input: Option<&str>,
) -> Result<LoginResult> {
    let failed = |detail: String| Error::plugin_bootstrap(format!("Could not run codex: {detail}"));

    let mut child = Command::new(&command.command)
        .args(&command.prefix_args)
        .args(args)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| failed(error.to_string()))?;

    if let Some(mut stdin) = child.stdin.take() {
        // A short-lived command can close stdin before the write lands. Its
        // exit status is what matters, so a broken pipe is not an error here.
        let _ = stdin.write_all(input.unwrap_or_default().as_bytes());
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut handle) = child.stdout.take() {
        let _ = handle.read_to_string(&mut stdout);
    }
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    let status = child.wait().map_err(|error| failed(error.to_string()))?;

    Ok(LoginResult {
        success: status.success(),
        exit_code: status.code(),
        stdout,
        stderr,
    })
}

/// Stores an API key as Codex's credentials.
pub fn login_api_key(
    command: &CodexCommand,
    environment: &ProcessEnvironment,
    api_key: &str,
) -> Result<LoginResult> {
    if api_key.trim().is_empty() {
        return Err(Error::plugin_bootstrap("The API key must be non-empty."));
    }
    // Passed on standard input rather than as an argument, where it would be
    // visible in the process list.
    run_codex(
        command,
        &["login", "--with-api-key"],
        environment,
        Some(&format!("{api_key}\n")),
    )
}

/// Asks Codex whether it is signed in.
pub fn account_status(
    command: &CodexCommand,
    environment: &ProcessEnvironment,
) -> Result<AccountStatus> {
    let result = run_codex(command, &["login", "status"], environment, None)?;
    let details = [result.stdout.trim(), result.stderr.trim()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    // A zero exit is not enough on its own: Codex reports "not logged in"
    // successfully.
    let denied = details.to_lowercase();
    let authenticated = result.exit_code == Some(0)
        && !denied.contains("not logged in")
        && !denied.contains("unauthenticated");

    Ok(AccountStatus {
        authenticated,
        details,
    })
}

/// Signs Codex out.
pub fn logout(command: &CodexCommand, environment: &ProcessEnvironment) -> Result<()> {
    let result = run_codex(command, &["logout"], environment, None)?;
    if !result.success {
        let detail = [result.stderr.trim(), result.stdout.trim()]
            .into_iter()
            .find(|part| !part.is_empty())
            .unwrap_or("unknown error");
        return Err(Error::plugin_bootstrap(format!(
            "Codex logout failed: {detail}"
        )));
    }
    Ok(())
}

/// The URL a user should open, from whatever Codex printed.
///
/// Login output contains a local callback URL as well as the real one. Sending
/// a user to the callback would do nothing, so loopback addresses in every
/// spelling are skipped.
#[must_use]
pub fn preferred_auth_url(value: &str) -> Option<String> {
    let text = plain_terminal_text(value);
    URL_PATTERN
        .find_iter(&text)
        .map(|found| {
            found
                .as_str()
                .trim_end_matches(|character| {
                    TRAILING_PUNCTUATION.contains(&character) || character == '}'
                })
                .to_owned()
        })
        .find(|candidate| is_reachable_host(candidate))
}

/// Whether a URL points somewhere a user could actually open.
fn is_reachable_host(candidate: &str) -> bool {
    let Ok(parsed) = Url::parse(candidate) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // A trailing dot is the DNS root and does not change the host.
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');

    if host == "localhost" || host.ends_with(".localhost") || host == "0.0.0.0" {
        return false;
    }
    // IPv4 loopback is the whole 127.0.0.0/8 block.
    if host.starts_with("127.") && host.split('.').count() == 4 {
        let numeric = host
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
        if numeric {
            return false;
        }
    }
    // IPv6 loopback, in the spellings Codex might print.
    if matches!(host, "[::1]" | "[::]" | "[::ffff:0:0]")
        || host.starts_with("[::ffff:7f")
        || host.starts_with("[::7f")
    {
        return false;
    }
    true
}

/// Terminal output with escape sequences and carriage returns removed.
#[must_use]
pub fn plain_terminal_text(value: &str) -> String {
    let without_osc = OSC_SEQUENCE.replace_all(value, "");
    let without_csi = CSI_SEQUENCE.replace_all(&without_osc, "");
    without_csi.replace('\r', "")
}

/// The device code in `output`, if it names one.
///
/// Two shapes are recognised, in the order upstream tries them: a labelled code
/// first, then a bare grouped one, so a label wins over anything else on screen
/// that happens to look like a code.
#[must_use]
fn user_code_in(output: &str) -> Option<String> {
    static LABELLED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:code|user code)\s*[:=]\s*([A-Z0-9-]{4,})").expect("a valid pattern")
    });
    static GROUPED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b").expect("a valid pattern")
    });

    if let Some(captured) = LABELLED
        .captures(output)
        .and_then(|captures| captures.get(1))
    {
        return Some(captured.as_str().to_owned());
    }
    GROUPED
        .find(output)
        .map(|matched| matched.as_str().to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// A stand-in for the codex executable.
    fn fake_codex(base: &Path, body: &str) -> CodexCommand {
        let path = base.join("codex");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        CodexCommand {
            command: path,
            prefix_args: Vec::new(),
        }
    }

    fn environment() -> ProcessEnvironment {
        ProcessEnvironment::new()
    }

    /// Retries only while a freshly written stub is still busy.
    ///
    /// Writing an executable and exec'ing it from the same process races on
    /// Linux: a concurrently forking thread inherits the still-open write
    /// descriptor. Wraps any call that spawns, so the higher-level helpers are
    /// covered too.
    fn retry_busy<T>(mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
        for _ in 0..100 {
            match attempt() {
                Err(error) if error.to_string().contains("Text file busy") => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                outcome => return outcome,
            }
        }
        attempt()
    }

    fn base() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical");
        (temp, base)
    }

    #[test]
    fn reports_what_a_command_printed() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'out'\nprintf 'err' >&2\nexit 0");

        let result = retry_busy(|| run_codex(&command, &["login", "status"], &environment(), None))
            .expect("runs");

        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, "out");
        assert_eq!(result.stderr, "err");
    }

    // The key goes on standard input, never in the argument list where it would
    // show up in the process table.
    #[test]
    fn passes_the_api_key_on_standard_input() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "cat\nprintf '%s' \"$*\" >&2");

        let result =
            retry_busy(|| login_api_key(&command, &environment(), "sk-secret")).expect("runs");

        assert_eq!(result.stdout, "sk-secret\n");
        assert_eq!(
            result.stderr, "login --with-api-key",
            "the key is not an argument"
        );
    }

    #[test]
    fn refuses_a_blank_api_key() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "exit 0");

        for key in ["", "   ", "\n"] {
            let error = login_api_key(&command, &environment(), key).expect_err("blank is refused");
            assert_eq!(error.to_string(), "The API key must be non-empty.");
        }
    }

    // A zero exit is not enough: Codex reports "not logged in" successfully.
    #[test]
    fn reads_an_unauthenticated_status_despite_a_zero_exit() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'Not logged in'\nexit 0");

        let status = retry_busy(|| account_status(&command, &environment())).expect("runs");

        assert!(!status.authenticated);
        assert_eq!(status.details, "Not logged in");
    }

    #[test]
    fn reads_an_authenticated_status() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'Logged in as user@example.com'\nexit 0");

        let status = retry_busy(|| account_status(&command, &environment())).expect("runs");

        assert!(status.authenticated);
        assert_eq!(status.details, "Logged in as user@example.com");
    }

    #[test]
    fn treats_a_failing_status_command_as_unauthenticated() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'boom' >&2\nexit 1");

        let status = retry_busy(|| account_status(&command, &environment())).expect("runs");

        assert!(!status.authenticated);
        assert_eq!(status.details, "boom");
    }

    #[test]
    fn joins_both_streams_into_the_status_details() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'first'\nprintf 'second' >&2\nexit 0");

        let status = retry_busy(|| account_status(&command, &environment())).expect("runs");

        assert_eq!(status.details, "first\nsecond");
    }

    #[test]
    fn signs_out() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "exit 0");

        retry_busy(|| logout(&command, &environment())).expect("signs out");
    }

    #[test]
    fn reports_a_failing_logout_with_its_detail() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'no session' >&2\nexit 1");

        let error = retry_busy(|| logout(&command, &environment())).expect_err("logout fails");

        assert_eq!(error.to_string(), "Codex logout failed: no session");
    }

    #[test]
    fn reports_a_silent_logout_failure() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "exit 3");

        let error = retry_busy(|| logout(&command, &environment())).expect_err("logout fails");

        assert_eq!(error.to_string(), "Codex logout failed: unknown error");
    }

    // --- login URL extraction ---

    #[test]
    fn finds_the_url_a_user_should_open() {
        let output = "Open this URL to sign in:\n  https://auth.openai.com/activate?code=ABCD\n";

        assert_eq!(
            preferred_auth_url(output).as_deref(),
            Some("https://auth.openai.com/activate?code=ABCD")
        );
    }

    // Login output contains a local callback URL; sending a user there would do
    // nothing.
    #[test]
    fn skips_the_local_callback_url() {
        let output = concat!(
            "Listening on http://localhost:1455/auth/callback\n",
            "Open https://auth.openai.com/activate to continue\n"
        );

        assert_eq!(
            preferred_auth_url(output).as_deref(),
            Some("https://auth.openai.com/activate")
        );
    }

    #[test]
    fn skips_every_spelling_of_loopback() {
        for local in [
            "http://localhost:1455/cb",
            "http://app.localhost/cb",
            "http://127.0.0.1:1455/cb",
            "http://127.9.9.9/cb",
            "http://0.0.0.0:1455/cb",
            "http://[::1]:1455/cb",
            "http://[::]:1455/cb",
        ] {
            let output = format!("{local}\nhttps://auth.openai.com/activate\n");
            assert_eq!(
                preferred_auth_url(&output).as_deref(),
                Some("https://auth.openai.com/activate"),
                "{local} should be skipped"
            );
        }
    }

    // A host that merely starts with "127" is not loopback.
    #[test]
    fn does_not_mistake_a_similar_host_for_loopback() {
        let output = "https://127.example.com/activate\n";

        assert_eq!(
            preferred_auth_url(output).as_deref(),
            Some("https://127.example.com/activate")
        );
    }

    #[test]
    fn trims_punctuation_that_followed_the_url() {
        let output = "Visit https://auth.openai.com/activate.\n";

        assert_eq!(
            preferred_auth_url(output).as_deref(),
            Some("https://auth.openai.com/activate")
        );
    }

    // Codex colorizes its output; the escapes must not break detection.
    #[test]
    fn sees_through_terminal_colouring() {
        let output = "\u{1b}[1mOpen \u{1b}[4mhttps://auth.openai.com/activate\u{1b}[0m\r\n";

        assert_eq!(
            preferred_auth_url(output).as_deref(),
            Some("https://auth.openai.com/activate")
        );
    }

    #[test]
    fn strips_escape_sequences_and_carriage_returns() {
        let text = "\u{1b}]0;title\u{7}plain\u{1b}[31mred\u{1b}[0m\r\n";

        assert_eq!(plain_terminal_text(text), "plainred\n");
    }

    #[test]
    fn reports_no_url_when_there_is_none() {
        assert_eq!(preferred_auth_url("nothing to open here"), None);
        assert_eq!(preferred_auth_url(""), None);
        assert_eq!(preferred_auth_url("http://localhost:1455/cb"), None);
    }

    // ------------------------------------------------------------------
    // CodexLoginHandle
    // ------------------------------------------------------------------

    /// Starts a login, retrying only while the freshly written stub is busy.
    fn start_login(command: &CodexCommand, args: &[&str]) -> CodexLoginHandle {
        retry_busy(|| CodexLoginHandle::start(command, args, &environment()))
            .expect("the login starts")
    }

    // A caller must be able to show the URL long before the login finishes.
    #[test]
    fn waits_for_the_sign_in_url_before_the_login_completes() {
        let (_temp, base) = base();
        let command = fake_codex(
            &base,
            "printf 'Open https://auth.openai.com/activate to continue\n'\nsleep 0.2",
        );

        let handle = start_login(&command, &["login"]);
        handle
            .wait_for_instructions(false)
            .expect("the instructions arrive");

        assert_eq!(
            handle.auth_url().as_deref(),
            Some("https://auth.openai.com/activate")
        );
        handle.wait().expect("the login finishes");
    }

    // Device-code sign-in needs both the URL and the code before it is usable.
    #[test]
    fn waits_for_both_the_url_and_the_code() {
        let (_temp, base) = base();
        let command = fake_codex(
            &base,
            "printf 'Visit https://auth.openai.com/activate\n'\n\
             printf 'Your code is: ABCD-1234\n'",
        );

        let handle = start_login(&command, &["login", "--device-auth"]);
        handle
            .wait_for_instructions(true)
            .expect("the instructions arrive");

        assert_eq!(
            handle.verification_url().as_deref(),
            Some("https://auth.openai.com/activate")
        );
        assert_eq!(handle.user_code().as_deref(), Some("ABCD-1234"));
        handle.wait().expect("the login finishes");
    }

    // Instructions printed at once, by a login that then keeps running.
    //
    // This is the case that matters: the wait must return while the process is
    // still alive, not once it eventually exits. Bounded in time so a
    // regression fails here rather than hanging. It cannot reliably reproduce a
    // lost wakeup on its own — that depends on exactly when output lands — so
    // the invariant is enforced by construction in `wait_for_instructions`,
    // which checks readiness under the same lock the wait releases.
    #[test]
    fn wakes_when_the_url_arrives_after_the_wait_begins() {
        let (_temp, base) = base();
        // `/bin/echo` rather than the shell builtin: a builtin writing down a
        // pipe is block-buffered, so its output would not appear until exit.
        let command = fake_codex(
            &base,
            "/bin/echo 'Open https://auth.openai.com/activate'\nexec sleep 30",
        );

        let handle = start_login(&command, &["login"]);
        let started = std::time::Instant::now();
        handle
            .wait_for_instructions(false)
            .expect("the instructions arrive");
        let waited = started.elapsed();
        handle.cancel();

        assert_eq!(
            handle.auth_url().as_deref(),
            Some("https://auth.openai.com/activate")
        );
        assert!(
            waited < std::time::Duration::from_secs(10),
            "the wait slept through the instructions: {waited:?}"
        );
    }

    #[test]
    fn reports_a_successful_login() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'https://auth.openai.com/activate\n'");

        let handle = start_login(&command, &["login"]);
        let result = handle.wait().expect("the login finishes");

        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
    }

    // A login that fails before printing anything must say so rather than
    // leaving the caller waiting forever.
    #[test]
    fn reports_a_login_that_ended_before_showing_instructions() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'no browser available\n' >&2\nexit 3");

        let handle = start_login(&command, &["login"]);
        let error = handle
            .wait_for_instructions(false)
            .expect_err("the login ended early");

        assert!(
            error.to_string().contains("no browser available"),
            "unexpected: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("exited before authentication instructions"),
            "unexpected: {error}"
        );
    }

    // Already authenticated: nothing to show, and nothing wrong.
    #[test]
    fn accepts_a_login_that_succeeded_without_instructions() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "printf 'Already logged in\n'");

        let handle = start_login(&command, &["login"]);

        handle
            .wait_for_instructions(false)
            .expect("a successful login needs no instructions");
    }

    // A login must not outlive the client that started it.
    #[test]
    fn cancelling_stops_the_login() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "exec sleep 30");

        let handle = start_login(&command, &["login"]);
        handle.cancel();
        let result = handle.wait().expect("the login finishes");

        assert!(!result.success, "a cancelled login is not a success");
    }

    #[test]
    fn reports_a_cancelled_login_to_whoever_is_waiting() {
        let (_temp, base) = base();
        let command = fake_codex(&base, "exec sleep 30");
        let handle = start_login(&command, &["login"]);

        let canceller = std::thread::spawn({
            // Cancelled from another thread, as closing the client does.
            let pid = handle.pid;
            move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                pid
            }
        });
        let pid = canceller.join().expect("the canceller ran");
        assert_eq!(pid, handle.pid);
        handle.cancel();

        let error = handle
            .wait_for_instructions(false)
            .expect_err("the login was cancelled");

        assert_eq!(error.to_string(), "Codex login was canceled.");
    }

    #[test]
    fn reports_a_login_that_could_not_start() {
        let (_temp, base) = base();
        let command = CodexCommand {
            command: base.join("missing-codex"),
            prefix_args: Vec::new(),
        };

        let error = CodexLoginHandle::start(&command, &["login"], &environment())
            .expect_err("there is no executable");

        assert!(
            error.to_string().contains("Could not start Codex login"),
            "unexpected: {error}"
        );
    }

    // The label must be `code` or `user code` followed directly by `:` or `=`;
    // an ungrouped code is only ever found this way.
    #[test]
    fn finds_a_labelled_device_code() {
        for (output, expected) in [
            ("code: ABCD-1234", "ABCD-1234"),
            ("user code = WXYZ7890", "WXYZ7890"),
            ("CODE: abcd-1234", "abcd-1234"),
        ] {
            assert_eq!(user_code_in(output).as_deref(), Some(expected), "{output}");
        }
    }

    // A label wins over anything else on screen that looks like a code.
    #[test]
    fn prefers_a_labelled_code_over_a_bare_one() {
        let output = "ZZZZ-9999 appears first\ncode: ABCD-1234";

        assert_eq!(user_code_in(output).as_deref(), Some("ABCD-1234"));
    }

    // "Your code is: X" does not match the label, so the grouped fallback is
    // what finds it. Pinned because it reads like a labelled match and is not.
    #[test]
    fn finds_a_conversationally_labelled_code_by_its_shape() {
        assert_eq!(
            user_code_in("Your code is: ABCD-1234").as_deref(),
            Some("ABCD-1234")
        );
    }

    #[test]
    fn falls_back_to_a_bare_grouped_code() {
        assert_eq!(
            user_code_in("Enter ABCD-1234 to continue").as_deref(),
            Some("ABCD-1234")
        );
        // A bare code must be grouped and uppercase to be recognised.
        assert_eq!(user_code_in("Enter abcd-1234 to continue"), None);
        assert_eq!(user_code_in("Enter ABCD1234 to continue"), None);
    }

    #[test]
    fn reports_no_code_when_there_is_none() {
        assert_eq!(user_code_in("Open the link to continue"), None);
    }
}

/// An interactive Codex login in progress.
///
/// Ported from `CodexLoginHandle` in `src/auth.ts`.
///
/// Signing in interactively means waiting for Codex to print a URL — and, for
/// device-code sign-in, a code — then waiting again for the person to finish in
/// their browser. Both waits must be observable separately: a caller needs to
/// show the instructions long before the login completes.
///
/// Upstream models this with promises; here reader threads accumulate the
/// child's output and a condition variable wakes whoever is waiting. Upstream
/// also takes an `onSuccess` callback to record that credentials became
/// available; here [`CodexLoginHandle::wait`] simply reports the result and the
/// caller records it, which keeps the handle free of client state.
#[derive(Debug)]
pub struct CodexLoginHandle {
    shared: Arc<LoginState>,
    /// The child's process id, for cancelling it.
    pid: u32,
    readers: Vec<std::thread::JoinHandle<()>>,
}

/// What the reader and reaper threads share with whoever is waiting.
#[derive(Debug, Default)]
struct LoginProgress {
    stdout: String,
    stderr: String,
    /// Set once the child has been reaped.
    exited: bool,
    exit_code: Option<i32>,
    /// Counts the output streams that have reached end of file.
    readers_done: usize,
    /// Set by [`CodexLoginHandle::cancel`], so the result is not a success.
    cancelled: bool,
    /// A spawn or wait failure, which no exit code describes.
    failure: Option<String>,
}

#[derive(Debug, Default)]
struct LoginState {
    progress: Mutex<LoginProgress>,
    changed: Condvar,
}

impl LoginState {
    fn lock(&self) -> std::sync::MutexGuard<'_, LoginProgress> {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The child's combined output, as the URL and code matchers expect it.
    fn combined(&self) -> String {
        let progress = self.lock();
        format!("{}\n{}", progress.stdout, progress.stderr)
    }
}

impl CodexLoginHandle {
    /// Starts `codex` with `args` and begins collecting what it prints.
    pub fn start(
        command: &CodexCommand,
        args: &[&str],
        environment: &ProcessEnvironment,
    ) -> Result<Self> {
        let mut child = Command::new(&command.command)
            .args(&command.prefix_args)
            .args(args)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                Error::plugin_bootstrap(format!("Could not start Codex login: {error}"))
                    .with_source(error)
            })?;

        let pid = child.id();
        let shared = Arc::new(LoginState::default());
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(spawn_reader(Arc::clone(&shared), stdout, Stream::Stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(spawn_reader(Arc::clone(&shared), stderr, Stream::Stderr));
        }

        // Reaped on its own thread so waiting for instructions and waiting for
        // the login to finish are independent.
        let reaper = Arc::clone(&shared);
        readers.push(std::thread::spawn(move || {
            let outcome = child.wait();
            let mut progress = reaper.lock();
            match outcome {
                Ok(status) => progress.exit_code = status.code(),
                Err(error) => progress.failure = Some(error.to_string()),
            }
            progress.exited = true;
            drop(progress);
            reaper.changed.notify_all();
        }));

        Ok(Self {
            shared,
            pid,
            readers,
        })
    }

    /// The sign-in URL Codex printed, once it has printed one.
    #[must_use]
    pub fn auth_url(&self) -> Option<String> {
        preferred_auth_url(&self.shared.combined())
    }

    /// The URL a device-code sign-in directs the person to.
    #[must_use]
    pub fn verification_url(&self) -> Option<String> {
        self.auth_url()
    }

    /// The code a device-code sign-in asks the person to enter.
    #[must_use]
    pub fn user_code(&self) -> Option<String> {
        user_code_in(&plain_terminal_text(&self.shared.combined()))
    }

    /// Blocks until the instructions a caller must show are available.
    ///
    /// A login that finishes before printing anything is not a failure — it was
    /// already authenticated — so a successful exit ends the wait too.
    ///
    /// The readiness check happens under the same lock the wait releases. Doing
    /// it outside would let output arrive in the gap between checking and
    /// waiting: the notification would already have fired, and the wait would
    /// sleep through instructions that had in fact arrived.
    pub fn wait_for_instructions(&self, device_code: bool) -> Result<()> {
        let streams = self.output_streams();
        let mut progress = self.shared.lock();
        loop {
            if instructions_ready(&progress, device_code) {
                return Ok(());
            }
            if progress.exited && progress.readers_done == streams {
                if progress.exit_code == Some(0) && !progress.cancelled {
                    return Ok(());
                }
                return Err(login_failed(
                    progress.cancelled,
                    progress.exit_code,
                    &progress.stdout,
                    &progress.stderr,
                    progress.failure.as_deref(),
                ));
            }
            progress = self
                .shared
                .changed
                .wait(progress)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Blocks until the login finishes, and reports how it went.
    pub fn wait(mut self) -> Result<LoginResult> {
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let progress = self.shared.lock();
        if let Some(failure) = &progress.failure {
            return Err(Error::plugin_bootstrap(format!(
                "Could not run Codex login: {failure}"
            )));
        }
        Ok(LoginResult {
            success: progress.exit_code == Some(0) && !progress.cancelled,
            exit_code: progress.exit_code,
            stdout: progress.stdout.clone(),
            stderr: progress.stderr.clone(),
        })
    }

    /// Stops the login, so it does not outlive the client that started it.
    ///
    /// Only the process Codex was started as is signalled, matching upstream.
    /// Anything it spawned in turn — a browser, say — is left alone, and while
    /// such a child holds the output pipes open, [`CodexLoginHandle::wait`]
    /// keeps waiting for them to close.
    pub fn cancel(&self) {
        self.canceller().cancel();
    }

    /// A cancel switch for this login, for whoever needs to stop it elsewhere.
    ///
    /// A client hands out the handle but must still be able to cancel it when
    /// it closes, which this makes possible without sharing the handle itself.
    #[must_use]
    pub fn canceller(&self) -> LoginCanceller {
        LoginCanceller {
            shared: Arc::clone(&self.shared),
            pid: self.pid,
        }
    }

    /// How many output streams the child was given.
    fn output_streams(&self) -> usize {
        // Every reader but the reaper reads a stream.
        self.readers.len().saturating_sub(1)
    }
}

/// A cancelled login is stopped, not left running in the background.
impl Drop for CodexLoginHandle {
    fn drop(&mut self) {
        self.cancel();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

/// Stops a login that someone else is holding.
#[derive(Debug, Clone)]
pub struct LoginCanceller {
    shared: Arc<LoginState>,
    pid: u32,
}

impl LoginCanceller {
    /// Stops the login, if it is still running.
    pub fn cancel(&self) {
        {
            let mut progress = self.shared.lock();
            if progress.exited {
                return;
            }
            progress.cancelled = true;
        }
        terminate(self.pid);
        self.shared.changed.notify_all();
    }

    /// Whether the login has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.shared.lock().exited
    }
}

/// Whether the instructions a caller must show have arrived.
///
/// Takes the already-locked progress so the check and the decision to wait are
/// made together.
fn instructions_ready(progress: &LoginProgress, device_code: bool) -> bool {
    let combined = format!("{}\n{}", progress.stdout, progress.stderr);
    let Some(_url) = preferred_auth_url(&combined) else {
        return false;
    };
    // A device-code sign-in is unusable without both halves.
    !device_code || user_code_in(&plain_terminal_text(&combined)).is_some()
}

/// Which stream a reader is draining.
#[derive(Debug, Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// Accumulates one stream, waking anyone waiting after every chunk.
fn spawn_reader(
    shared: Arc<LoginState>,
    mut source: impl std::io::Read + Send + 'static,
    stream: Stream,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match source.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let chunk = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let mut progress = shared.lock();
                    match stream {
                        Stream::Stdout => progress.stdout.push_str(&chunk),
                        Stream::Stderr => progress.stderr.push_str(&chunk),
                    }
                    drop(progress);
                    shared.changed.notify_all();
                }
            }
        }
        let mut progress = shared.lock();
        progress.readers_done += 1;
        drop(progress);
        shared.changed.notify_all();
    })
}

/// Why a login ended before it could show any instructions.
fn login_failed(
    cancelled: bool,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    failure: Option<&str>,
) -> Error {
    if cancelled {
        return Error::plugin_bootstrap("Codex login was canceled.");
    }
    let detail = [stderr.trim(), stdout.trim(), failure.unwrap_or_default()]
        .into_iter()
        .find(|candidate| !candidate.is_empty())
        .map_or_else(
            || exit_code.map_or_else(|| "unknown error".to_owned(), |code| code.to_string()),
            str::to_owned,
        );
    Error::plugin_bootstrap(format!(
        "Codex login exited before authentication instructions were available: {detail}"
    ))
}

/// Asks a process to stop.
fn terminate(pid: u32) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(pid)
        && let Some(pid) = rustix::process::Pid::from_raw(pid)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
    #[cfg(not(unix))]
    let _ = pid;
}
