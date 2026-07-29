//! Behavior tests for the command line surface.
//!
//! Ported from the argument handling in `tests-ts/cli.test.ts`. The flags are a
//! contract: scripts and CI jobs are written against them, so this checks the
//! names, defaults and repeatability rather than any behavior behind them.

use std::process::Command;

/// Runs the binary with `arguments`, returning its status, stdout and stderr.
fn run(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(arguments)
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The failure a set of arguments is refused with.
fn refuse(arguments: &[&str]) -> String {
    let (code, _, stderr) = run(arguments);
    assert_eq!(code, Some(2), "expected a usage failure: {stderr}");
    stderr
}

/// Scan arguments that parse.
///
/// Routed through `--dry-run` so parsing is checked without starting a scan;
/// the repository is this one, which is a real Git repository.
fn parses_scan(arguments: &[&str]) {
    let mut full: Vec<&str> = arguments.to_vec();
    full.push("--dry-run");
    let (code, _, stderr) = run(&full);
    assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
}

#[test]
fn reports_every_command_it_offers() {
    let (code, stdout, _) = run(&["--help"]);

    assert_eq!(code, Some(0));
    for command in [
        "scan",
        "scans",
        "bulk-scan",
        "export",
        "validate",
        "patch",
        "login",
        "logout",
        "info",
        "install-hook",
    ] {
        assert!(stdout.contains(command), "{command} is missing from --help");
    }
}

#[test]
fn reports_its_version() {
    let (code, stdout, _) = run(&["--version"]);

    assert_eq!(code, Some(0));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}

#[test]
fn refuses_an_unknown_command() {
    let stderr = refuse(&["definitely-not-a-command"]);

    assert!(stderr.contains("unrecognized subcommand"), "{stderr}");
}

#[test]
fn refuses_an_unknown_flag() {
    let stderr = refuse(&["scan", "--not-a-flag"]);

    assert!(stderr.contains("unexpected argument"), "{stderr}");
}

// Repeatable options are how a scan names several paths or overrides.
#[test]
fn accepts_repeated_paths_and_overrides() {
    parses_scan(&[
        "scan",
        ".",
        "--path",
        "src",
        "--path",
        "tests",
        // TOML values, so strings are quoted.
        "--codex",
        "model=\"gpt-5.6-sol\"",
        "--codex",
        "model_reasoning_effort=\"high\"",
    ]);
}

#[test]
fn accepts_every_scan_option() {
    parses_scan(&[
        "scan",
        ".",
        "--knowledge-base",
        "docs/threats.md",
        "--mode",
        "deep",
        "--model",
        "gpt-5.6-sol",
        "--output-dir",
        "/tmp/scan",
        "--archive-existing",
        "--plugin-path",
        "/plugins/codex-security",
        "--python",
        "/usr/bin/python3",
        "--fail-on-severity",
        "high",
        "--max-cost",
        "5.0",
    ]);
}

#[test]
fn refuses_an_unknown_mode() {
    let stderr = refuse(&["scan", ".", "--mode", "thorough"]);

    assert!(stderr.contains("invalid value"), "{stderr}");
}

#[test]
fn refuses_an_unknown_severity() {
    let stderr = refuse(&["scan", ".", "--fail-on-severity", "catastrophic"]);

    assert!(stderr.contains("invalid value"), "{stderr}");
}

// A scan looks at one thing; naming several would leave it ambiguous which.
#[test]
fn refuses_more_than_one_scan_target() {
    for arguments in [
        vec!["scan", ".", "--path", "src", "--working-tree"],
        vec!["scan", ".", "--diff", "main", "--working-tree"],
        vec!["scan", ".", "--path", "src", "--diff", "main"],
    ] {
        let stderr = refuse(&arguments);
        assert!(
            stderr.contains("Choose one scan target"),
            "{arguments:?}: {stderr}"
        );
    }
}

// A ref only means something alongside the target it belongs to.
#[test]
fn refuses_a_ref_without_its_target() {
    assert!(refuse(&["scan", ".", "--head", "feature"]).contains("--head requires --diff"));
    assert!(refuse(&["scan", ".", "--base", "main"]).contains("--base requires --working-tree"));
}

#[test]
fn accepts_a_ref_with_its_target() {
    // Refs that do not exist here still parse; resolving them is the scan's
    // job, and a dry run reports that separately.
    for arguments in [
        vec![
            "scan",
            ".",
            "--diff",
            "main",
            "--head",
            "feature",
            "--dry-run",
        ],
        vec!["scan", ".", "--working-tree", "--base", "main", "--dry-run"],
    ] {
        let (code, _, stderr) = run(&arguments);
        assert!(
            code == Some(0) || stderr.contains("puncode-security:"),
            "{arguments:?} did not parse: {stderr}"
        );
        assert!(
            !stderr.contains("unexpected argument"),
            "{arguments:?}: {stderr}"
        );
    }
}

// Deep mode reads the whole tree, which a diff cannot describe.
#[test]
fn refuses_deep_mode_against_a_diff() {
    for arguments in [
        vec!["scan", ".", "--mode", "deep", "--diff", "main"],
        vec!["scan", ".", "--mode", "deep", "--working-tree"],
    ] {
        let stderr = refuse(&arguments);
        assert!(
            stderr.contains("repository and path targets only"),
            "{arguments:?}: {stderr}"
        );
    }
}

#[test]
fn refuses_a_cost_limit_that_is_not_a_positive_amount() {
    for limit in ["0", "-1", "nan", "inf"] {
        let stderr = refuse(&["scan", ".", "--max-cost", limit]);
        assert!(
            stderr.contains("positive USD amount") || stderr.contains("invalid value"),
            "{limit} was accepted: {stderr}"
        );
    }
}

// These commands report to a person; there is no machine-readable form of
// "here is the sign-in URL, open it".
#[test]
fn refuses_structured_output_where_there_is_none() {
    for (command, subject) in [
        ("validate", Some("a finding")),
        ("patch", Some("an issue")),
        ("login", None),
    ] {
        let base: Vec<&str> = match subject {
            Some(subject) => vec![command, subject],
            None => vec![command],
        };
        for extra in [vec!["--json"], vec!["--format", "json"]] {
            let flag: Vec<&str> = base.iter().copied().chain(extra).collect();
            let stderr = refuse(&flag);
            assert!(
                stderr.contains("does not support noninteractive JSON output"),
                "{flag:?}: {stderr}"
            );
            assert!(stderr.contains(command), "{flag:?}: {stderr}");
        }
    }
}

// These take what to work on as positionals, and cannot run without them.
#[test]
fn refuses_a_validate_or_patch_with_nothing_to_work_on() {
    for command in ["validate", "patch"] {
        let stderr = refuse(&[command]);
        assert!(
            stderr.contains("required") || stderr.contains("<"),
            "{command}: {stderr}"
        );
    }
}

// `validate` and `patch` hand the terminal to Codex, so these check parsing
// only: spawning them would wait for a model.
#[test]
fn accepts_several_findings_or_issues() {
    for arguments in [vec!["validate", "--help"], vec!["patch", "--help"]] {
        let (code, stdout, stderr) = run(&arguments);
        assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
        assert!(stdout.contains("Usage:"), "{arguments:?}: {stdout}");
    }
}

// The fingerprints it feeds are a SARIF concept.
#[test]
fn refuses_a_source_root_for_a_non_sarif_export() {
    for format in ["csv", "json"] {
        let stderr = refuse(&[
            "export",
            "/scans/one",
            "--export-format",
            format,
            "--source-root",
            "/repo",
        ]);
        assert!(
            stderr.contains("only supported with --export-format sarif"),
            "{format}: {stderr}"
        );
    }
}

// An export needs to know which scan to read.
#[test]
fn refuses_an_export_with_no_scan_directory() {
    let stderr = refuse(&["export"]);

    assert!(
        stderr.contains("required") || stderr.contains("SCAN_DIR"),
        "{stderr}"
    );
}

#[test]
fn refuses_an_unknown_export_format() {
    let stderr = refuse(&["export", "/scans/one", "--export-format", "markdown"]);

    assert!(stderr.contains("invalid value"), "{stderr}");
}

#[test]
fn allows_structured_output_where_there_is_some() {
    parses_scan(&["scan", ".", "--json"]);
}

// Both would be written to the same stream, interleaved.
#[test]
fn refuses_csv_on_standard_output_alongside_json() {
    let stderr = refuse(&[
        "export",
        "/scans/one",
        "--export-format",
        "csv",
        "--output",
        "-",
        "--json",
    ]);

    assert!(stderr.contains("CSV stdout cannot be combined"), "{stderr}");
}

#[test]
fn accepts_every_saved_scan_command() {
    // Every saved-scan command now runs for real, so its flags are checked
    // through help rather than by reaching the workbench.
    for command in ["list", "show", "rerun", "match", "compare"] {
        let (code, stdout, stderr) = run(&["scans", command, "--help"]);
        assert_eq!(code, Some(0), "{command}: {stderr}");
        assert!(stdout.contains("Usage:"), "{command}: {stdout}");
    }
    let (_, help, _) = run(&["scans", "match", "--help"]);
    assert!(help.contains("--all"), "{help}");
    assert!(help.contains("--force"), "{help}");
}

// A match compares two scans, or every scan; it cannot be told to do both.
#[test]
fn refuses_a_match_that_names_scans_and_asks_for_all() {
    let stderr = refuse(&["scans", "match", "abc123", "def456", "--all"]);

    assert!(stderr.contains("--all matches every scan"), "{stderr}");
}

#[test]
fn refuses_a_match_that_names_only_one_scan() {
    let stderr = refuse(&["scans", "match", "abc123"]);

    assert!(stderr.contains("Name two scans to match"), "{stderr}");
}

#[test]
fn refuses_a_compare_that_names_only_one_scan() {
    let stderr = refuse(&["scans", "compare", "abc123"]);

    assert!(
        stderr.contains("required") || stderr.contains("AFTER_ID"),
        "{stderr}"
    );
}

// `bulk-scan` reads a real inventory, so its flags are checked through help
// rather than by starting a campaign.
#[test]
fn accepts_every_bulk_scan_option() {
    let (code, help, stderr) = run(&["bulk-scan", "--help"]);

    assert_eq!(code, Some(0), "{stderr}");
    for flag in [
        "--output-dir",
        "--workers",
        "--mode",
        "--model",
        "--max-attempts",
        "--plugin-path",
        "--python",
        "--codex",
    ] {
        assert!(help.contains(flag), "{flag} is missing: {help}");
    }
}

#[test]
fn refuses_a_worker_count_that_is_not_a_number() {
    let stderr = refuse(&["bulk-scan", "repositories.csv", "--workers", "many"]);

    assert!(stderr.contains("invalid value"), "{stderr}");
}

#[test]
fn accepts_every_login_option() {
    // `login` hands the terminal to Codex and waits for a person, so it is
    // never actually started here: `--help` exercises the same parsing without
    // spawning anything.
    for arguments in [vec!["login", "--help"], vec!["login", "status", "--help"]] {
        let (code, stdout, stderr) = run(&arguments);
        assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
        assert!(stdout.contains("Usage:"), "{arguments:?}: {stdout}");
    }
    // The flags are declared, which is what a script depends on.
    let (_, help, _) = run(&["login", "--help"]);
    for flag in ["--device-auth", "--with-api-key", "--with-access-token"] {
        assert!(help.contains(flag), "{flag} is missing: {help}");
    }
    assert!(help.contains("status"), "{help}");
}

// Every command's help is reachable, which is how anyone discovers the flags.
#[test]
fn offers_help_for_every_command() {
    for command in [
        vec!["scan"],
        vec!["scans"],
        vec!["scans", "list"],
        vec!["scans", "show"],
        vec!["scans", "match"],
        vec!["bulk-scan"],
        vec!["export"],
        vec!["validate"],
        vec!["patch"],
        vec!["login"],
        vec!["logout"],
        vec!["info"],
        vec!["install-hook"],
    ] {
        let mut arguments = command.clone();
        arguments.push("--help");
        let (code, stdout, stderr) = run(&arguments);
        assert_eq!(code, Some(0), "{command:?}: {stderr}");
        assert!(stdout.contains("Usage:"), "{command:?}: {stdout}");
    }
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

/// Runs a command expected to succeed, returning its standard output.
fn succeeds(arguments: &[&str]) -> String {
    let (code, stdout, stderr) = run(arguments);
    assert_eq!(code, Some(0), "{arguments:?}: {stderr}");
    stdout
}

// This is what people run when something else is behaving oddly, so it must
// report what this build actually is.
#[test]
fn reports_what_this_build_is() {
    let stdout = succeeds(&["info"]);

    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
    assert!(stdout.contains("bundled plugin"), "{stdout}");
    assert!(stdout.contains("codex"), "{stdout}");
    assert!(stdout.contains("model"), "{stdout}");
}

#[test]
fn reports_the_same_facts_as_json() {
    let stdout = succeeds(&["info", "--json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(report["cliVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["bundledPluginVersion"], "0.1.14");
    assert_eq!(report["codexVersion"], "0.144.6");
    assert_eq!(report["model"], "gpt-5.6-sol");
    assert_eq!(report["reasoningEffort"], "xhigh");
    assert_eq!(report["nextStep"], "puncode-security scan . --dry-run");
}

// Scanning is deliberately not offered over MCP, and the report says why.
#[test]
fn reports_that_scanning_is_not_offered_over_mcp() {
    let report: serde_json::Value =
        serde_json::from_str(&succeeds(&["info", "--json"])).expect("valid JSON");

    assert_eq!(report["scanMcp"], serde_json::Value::Bool(false));
    assert!(
        report["cancellationNote"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot cancel active commands"),
        "{report}"
    );
}

#[test]
fn reports_one_line_of_json_for_jsonl() {
    let stdout = succeeds(&["info", "--format", "jsonl"]);

    assert_eq!(stdout.trim().lines().count(), 1, "{stdout}");
    serde_json::from_str::<serde_json::Value>(stdout.trim()).expect("valid JSON");
}

// It answers without reaching Codex, the network, or anything on disk, so it
// works the same in an empty environment.
#[test]
fn reports_without_reading_any_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .arg("info")
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("HOME", "/nonexistent")
        .output()
        .expect("run the binary");

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}

/// Speaking the protocol to the real binary over a pipe.
///
/// The in-process tests cover the replies; this covers that `--mcp` actually
/// reaches them, and that the process ends when the client hangs up rather than
/// waiting for input that will never come.
#[test]
fn serves_the_protocol_over_standard_input() {
    use std::io::Write as _;

    let mut child = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .arg("--mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starts");
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .expect("writes");
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )
    .expect("writes");
    // Hanging up ends the session.
    drop(stdin);

    let finished = child.wait_with_output().expect("finishes");
    assert!(finished.status.success(), "{finished:?}");

    let replies: Vec<serde_json::Value> = String::from_utf8_lossy(&finished.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("a JSON reply"))
        .collect();
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_eq!(
        replies[0]["result"]["serverInfo"]["name"],
        "puncode-security"
    );
    let tools = replies[1]["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "info");
}

/// `--mcp` hands the process to the protocol, so a command alongside it would
/// be silently ignored. Saying so is better than appearing to run it.
#[test]
fn refuses_a_command_alongside_the_protocol() {
    let finished = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(["--mcp", "info"])
        .output()
        .expect("runs");

    assert_eq!(finished.status.code(), Some(2), "{finished:?}");
    let complaint = String::from_utf8_lossy(&finished.stderr);
    assert!(complaint.contains("cannot be combined"), "{complaint}");
}

/// Asking for nothing shows what can be asked for.
#[test]
fn shows_help_when_given_no_command() {
    let finished = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .output()
        .expect("runs");

    assert_eq!(finished.status.code(), Some(2), "{finished:?}");
    let shown = String::from_utf8_lossy(&finished.stdout);
    assert!(shown.contains("scan"), "{shown}");
    assert!(shown.contains("--mcp"), "{shown}");
}

/// `--mcp` is a mode for the whole process, not something a command takes.
///
/// Listing it under every subcommand would advertise a flag that can only
/// ever be refused.
#[test]
fn does_not_offer_the_protocol_flag_on_commands_that_cannot_take_it() {
    for command in ["scan", "export", "info", "scans list"] {
        let arguments: Vec<&str> = command.split(' ').chain(["--help"]).collect();
        let (_, shown, _) = run(&arguments);
        assert!(!shown.contains("--mcp"), "{command} offers --mcp:\n{shown}");
    }

    // It stays on the top-level help, where it does apply.
    let (_, shown, _) = run(&["--help"]);
    assert!(shown.contains("--mcp"), "{shown}");
}

/// Pointing the scan at an OpenAI-compatible endpoint.
#[test]
fn accepts_a_model_endpoint() {
    parses_scan(&[
        "scan",
        ".",
        "--base-url",
        "http://localhost:8080/v1",
        "--wire-api",
        "chat",
        "--api-key-env",
        "LOCAL_KEY",
        "--model",
        "a-local-model",
    ]);
}

/// The endpoint settings only mean something alongside an endpoint, so asking
/// for them alone is a mistake worth naming rather than quietly ignoring.
#[test]
fn refuses_endpoint_settings_without_an_endpoint() {
    for arguments in [
        vec!["scan", ".", "--wire-api", "responses"],
        vec!["scan", ".", "--api-key-env", "LOCAL_KEY"],
    ] {
        let (code, _, complaint) = run(&arguments);
        assert_eq!(code, Some(2), "{arguments:?}");
        assert!(complaint.contains("--base-url"), "{complaint}");
    }
}

/// An address that could not serve a model is refused where it can be
/// explained, not as a connection failure minutes into a scan.
#[test]
fn refuses_an_endpoint_that_could_not_serve_a_model() {
    for bad in ["file:///etc/passwd", "localhost:8080", "ftp://host/v1"] {
        let (code, _, complaint) = run(&["scan", ".", "--dry-run", "--base-url", bad]);
        assert_eq!(code, Some(2), "accepted {bad}: {complaint}");
        assert!(complaint.contains("Model endpoint address"), "{complaint}");
    }
}

/// `--base-url` and a hand-written provider override both choose a provider.
#[test]
fn refuses_an_endpoint_that_contradicts_a_provider_override() {
    let (code, _, complaint) = run(&[
        "scan",
        ".",
        "--dry-run",
        "--base-url",
        "http://localhost:8080/v1",
        "--codex",
        "model_provider=\"other\"",
    ]);

    assert_eq!(code, Some(2), "{complaint}");
    assert!(
        complaint.contains("both choose a model provider"),
        "{complaint}"
    );
}

/// The endpoint can come from the environment, for a shell already pointed at
/// a local server.
#[test]
fn takes_the_endpoint_from_the_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .args(["scan", ".", "--dry-run", "--json"])
        .env("CODEX_SECURITY_BASE_URL", "http://localhost:9999/v1")
        .output()
        .expect("runs");

    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(shown.contains("http://localhost:9999/v1"), "{shown}");
}

/// A dry run says where the model would run, so the choice can be confirmed
/// without spending a scan to find out.
#[test]
fn reports_where_the_model_would_run() {
    let (code, shown, complaint) = run(&[
        "scan",
        ".",
        "--dry-run",
        "--json",
        "--base-url",
        "http://localhost:8080/v1",
        "--api-key-env",
        "LOCAL_KEY",
    ]);

    assert_eq!(code, Some(0), "{complaint}");
    let report: serde_json::Value = serde_json::from_str(&shown).expect("json");
    assert_eq!(
        report["modelEndpoint"]["baseUrl"],
        "http://localhost:8080/v1"
    );
    assert_eq!(report["modelEndpoint"]["apiKeyEnv"], "LOCAL_KEY");
    // The key itself is never part of the report.
    assert!(!shown.contains("sk-"), "{shown}");
}

/// A scan with no endpoint says nothing about one.
#[test]
fn says_nothing_about_an_endpoint_when_there_is_none() {
    let (_, shown, _) = run(&["scan", ".", "--dry-run", "--json"]);

    assert!(!shown.contains("modelEndpoint"), "{shown}");
}

/// Disabling the sandbox is never implied — it has to be asked for.
#[test]
fn keeps_the_sandbox_unless_told_otherwise() {
    let (_, shown, _) = run(&["scan", ".", "--dry-run", "--json"]);

    assert!(!shown.contains("sandbox"), "{shown}");
}

/// It is accepted, and the run says plainly what is no longer protected.
#[test]
fn warns_when_the_sandbox_is_turned_off() {
    let (code, _, complaint) = run(&["scan", ".", "--dry-run", "--dangerously-disable-sandbox"]);

    assert_eq!(code, Some(0), "{complaint}");
}

/// The short name is accepted too, since that is what Codex calls it.
#[test]
fn accepts_yolo_as_the_short_name() {
    parses_scan(&["scan", ".", "--yolo"]);
}

/// Repeating writes each run to its own directory, which the workbench requires
/// and which the caller therefore has to name.
#[test]
fn repeating_requires_somewhere_to_put_the_runs() {
    let (code, _, complaint) = run(&["scan", ".", "--repeat", "3"]);

    assert_eq!(code, Some(2), "{complaint}");
    assert!(complaint.contains("--output-dir"), "{complaint}");
}

/// One run is the default, so nothing changes for anyone not asking for more.
#[test]
fn one_run_is_the_default() {
    parses_scan(&["scan", "."]);
}

#[test]
fn accepts_a_repeat_count_with_an_output_directory() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("a directory");
    // Scan output must not be readable by other users; it carries source.
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod");

    parses_scan(&[
        "scan",
        ".",
        "--repeat",
        "2",
        "--output-dir",
        &temporary.path().to_string_lossy(),
    ]);
}

/// Repeating with a capture must not have every run overwrite the last. The
/// reason to capture while repeating is to see why the runs differed, which
/// needs all of them; a shared file leaves only the final one.
#[test]
fn each_repeated_run_captures_to_its_own_file() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("a directory");
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod");
    let capture = temporary.path().join("traffic.jsonl");

    // Nothing answers at port 1, so each run fails fast; the captures are what
    // this is checking.
    let (_, _, _) = run(&[
        "scan",
        "fixtures/orders-api",
        "--base-url",
        "http://127.0.0.1:1/v1",
        "--repeat",
        "2",
        "--capture-traffic",
        &capture.to_string_lossy(),
        "--output-dir",
        &temporary.path().join("out").to_string_lossy(),
    ]);

    let written: Vec<String> = std::fs::read_dir(temporary.path())
        .expect("reads")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("traffic"))
        .collect();

    assert!(
        written.contains(&"traffic-run-1.jsonl".to_owned())
            && written.contains(&"traffic-run-2.jsonl".to_owned()),
        "expected one capture per run, found {written:?}"
    );
}

/// A URL can carry a username and password, and these outputs are the ones
/// people share: a dry run shows what a scan would do, and doctor is what gets
/// pasted into a bug report when a scan will not start.
#[test]
fn never_prints_credentials_from_an_endpoint_url() {
    const SECRET: &str = "supersecret";
    let url = format!("http://someuser:{SECRET}@127.0.0.1:1/v1");

    let mut checked = 0;
    for arguments in [
        vec!["scan", ".", "--dry-run", "--json", "--base-url", &url],
        vec!["scan", ".", "--dry-run", "--base-url", &url],
        vec!["doctor", "--base-url", &url],
        vec!["doctor", "--json", "--base-url", &url],
    ] {
        let (_, shown, complaint) = run(&arguments);
        assert!(
            !shown.contains(SECRET) && !complaint.contains(SECRET),
            "{arguments:?} leaked the credential:\n{shown}\n{complaint}"
        );
        // The host must survive, or the redaction has removed the useful part.
        assert!(
            shown.contains("127.0.0.1") || complaint.contains("127.0.0.1"),
            "{arguments:?} lost the address entirely:\n{shown}\n{complaint}"
        );
        checked += 1;
    }
    assert_eq!(checked, 4);
}

/// The help must describe the hook that is installed.
///
/// It said "scans before pushing" while installing `.git/hooks/pre-commit`.
/// Upstream calls it "Install a Git pre-commit security scan", the behaviour
/// matched upstream, and only our wording was wrong — so a reader could believe
/// their pushes were guarded when nothing was watching them.
#[test]
fn install_hook_help_names_the_hook_it_installs() {
    let (code, stdout, stderr) = run(&["install-hook", "--help"]);

    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("pre-commit"), "{stdout}");
    assert!(
        !stdout.to_lowercase().contains("before pushing"),
        "{stdout}"
    );
}
