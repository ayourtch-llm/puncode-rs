//! Behavior tests for the native codex client.
//!
//! The client replaces `@openai/codex-sdk`, whose behavior these tests pin:
//! spawn `codex exec --json`, write the prompt to stdin, read JSONL events from
//! stdout, and fail on a malformed line or a non-zero exit.
//!
//! Tests drive a stub `codex` executable so they never touch the network, a
//! model, or the user's real Codex home.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use codex_security::codex::{
    CodexClient, CodexThread, EventStream, ProcessCodexClient, ThreadEvent, ThreadOptions,
};
use tempfile::TempDir;

struct StubCodex {
    _dir: TempDir,
    executable: PathBuf,
    argv_log: PathBuf,
    stdin_log: PathBuf,
}

impl StubCodex {
    fn new(events: &str, exit_code: i32, stderr: &str) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let executable = dir.path().join("codex");
        let argv_log = dir.path().join("argv.txt");
        let stdin_log = dir.path().join("stdin.txt");

        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{argv}'\n\
             cat > '{stdin}'\n\
             cat <<'CODEX_STUB_EOF'\n{events}\nCODEX_STUB_EOF\n\
             printf '%s' '{stderr}' >&2\n\
             exit {exit_code}\n",
            argv = argv_log.display(),
            stdin = stdin_log.display(),
        );
        fs::write(&executable, script).expect("write stub");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod stub");

        Self {
            _dir: dir,
            executable,
            argv_log,
            stdin_log,
        }
    }

    fn client(&self) -> ProcessCodexClient {
        ProcessCodexClient::new(&self.executable)
    }

    fn argv(&self) -> Vec<String> {
        fs::read_to_string(&self.argv_log)
            .expect("stub recorded argv")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn stdin(&self) -> String {
        fs::read_to_string(&self.stdin_log).expect("stub recorded stdin")
    }
}

/// Starts a stream, retrying while the freshly written stub is still busy.
///
/// Writing an executable and exec'ing it from the same process races on Linux:
/// a concurrently forking thread inherits the still-open write descriptor, and
/// the exec fails with `ETXTBSY` until that child reaches its own exec. This
/// only affects stubs built in-process, never a real codex install.
fn start_stream(thread: &mut dyn CodexThread, prompt: &str) -> EventStream {
    for _ in 0..100 {
        match thread.run_streamed(prompt) {
            Ok(stream) => return stream,
            Err(error) if error.to_string().contains("Text file busy") => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("start stream: {error}"),
        }
    }
    panic!("stub executable stayed busy")
}

/// Drains a stream, failing the test on the first error.
fn collect(stub: &StubCodex, options: ThreadOptions, prompt: &str) -> Vec<ThreadEvent> {
    let client = stub.client();
    let mut thread = client.start_thread(options);
    start_stream(&mut *thread, prompt)
        .map(|event| event.expect("event"))
        .collect()
}

const SCAN_STREAM: &str = concat!(
    r#"{"type":"thread.started","thread_id":"019faaae-03d8-7940-b941-779a05f67245"}"#,
    "\n",
    r#"{"type":"turn.started"}"#,
    "\n",
    r#"{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"done"}}"#,
    "\n",
    r#"{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":5}}"#,
);

#[test]
fn spawns_codex_exec_with_the_json_protocol() {
    let stub = StubCodex::new(SCAN_STREAM, 0, "");
    let options = ThreadOptions::new()
        .working_directory("/tmp/scan-target")
        .skip_git_repo_check(true)
        .approval_policy("never");

    collect(&stub, options, "scan this");

    let argv = stub.argv();
    assert_eq!(argv[0], "exec", "codex exec is the entry subcommand");
    assert!(argv.contains(&"--json".to_owned()), "argv={argv:?}");
    assert!(
        argv.contains(&"--skip-git-repo-check".to_owned()),
        "argv={argv:?}"
    );
    assert!(argv.contains(&"--cd".to_owned()), "argv={argv:?}");
    assert!(
        argv.contains(&"/tmp/scan-target".to_owned()),
        "argv={argv:?}"
    );
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["--config", r#"approval_policy="never""#]),
        "approval policy is passed as a config override, argv={argv:?}"
    );
}

#[test]
fn sends_the_prompt_on_stdin() {
    let stub = StubCodex::new(SCAN_STREAM, 0, "");

    collect(&stub, ThreadOptions::new(), "audit the repository");

    assert_eq!(stub.stdin(), "audit the repository");
}

#[test]
fn parses_the_documented_event_stream() {
    let stub = StubCodex::new(SCAN_STREAM, 0, "");

    let events = collect(&stub, ThreadOptions::new(), "scan");

    assert_eq!(events.len(), 4);
    assert!(matches!(
        &events[0],
        ThreadEvent::ThreadStarted { thread_id } if thread_id.as_deref() == Some("019faaae-03d8-7940-b941-779a05f67245")
    ));
    assert!(matches!(events[1], ThreadEvent::TurnStarted));
    let ThreadEvent::ItemCompleted { item } = &events[2] else {
        panic!("expected item.completed, got {:?}", events[2]);
    };
    let item = item.as_ref().expect("item payload");
    assert_eq!(item.item_type, "agent_message");
    assert_eq!(item.text(), Some("done"));
    let ThreadEvent::TurnCompleted { usage } = &events[3] else {
        panic!("expected turn.completed");
    };
    assert_eq!(usage["output_tokens"], 20);
}

#[test]
fn exposes_the_thread_id_reported_by_the_stream() {
    let stub = StubCodex::new(SCAN_STREAM, 0, "");
    let client = stub.client();
    let mut thread = client.start_thread(ThreadOptions::new());
    assert_eq!(thread.id(), None, "no id before the stream starts");

    let events: Vec<_> = start_stream(&mut *thread, "scan").collect();
    drop(events);

    assert_eq!(
        thread.id().as_deref(),
        Some("019faaae-03d8-7940-b941-779a05f67245")
    );
}

// Item payloads carry fields outside the SDK's typed union (worker progress
// reads `command` and `aggregated_output`), so unknown keys must survive.
#[test]
fn preserves_item_fields_outside_the_typed_union() {
    let stream = concat!(
        r#"{"type":"item.completed","item":{"id":"i1","type":"command_execution","#,
        r#""command":"python config_preflight.py","aggregated_output":"{\"profile\":\"security_scan\"}"}}"#,
    );
    let stub = StubCodex::new(stream, 0, "");

    let events = collect(&stub, ThreadOptions::new(), "scan");

    let ThreadEvent::ItemCompleted { item } = &events[0] else {
        panic!("expected item.completed");
    };
    let item = item.as_ref().expect("item payload");
    assert_eq!(
        item.field("command").and_then(|v| v.as_str()),
        Some("python config_preflight.py")
    );
    assert!(item.field("aggregated_output").is_some());
}

#[test]
fn surfaces_stream_and_turn_failures_as_events() {
    let stream = concat!(
        r#"{"type":"error","message":"stream disconnected"}"#,
        "\n",
        r#"{"type":"turn.failed","error":{"message":"model refused"}}"#,
    );
    let stub = StubCodex::new(stream, 0, "");

    let events = collect(&stub, ThreadOptions::new(), "scan");

    assert!(matches!(
        &events[0],
        ThreadEvent::Error { message } if message.as_deref() == Some("stream disconnected")
    ));
    let ThreadEvent::TurnFailed { error } = &events[1] else {
        panic!("expected turn.failed");
    };
    assert_eq!(
        error.as_ref().and_then(|e| e.message.as_deref()),
        Some("model refused")
    );
}

// Forward compatibility: a newer codex may emit event and item types this
// build has never heard of, and upstream simply ignores them.
#[test]
fn tolerates_unknown_event_types() {
    let stream = concat!(
        r#"{"type":"turn.interrupted","reason":"whatever"}"#,
        "\n",
        r#"{"type":"turn.started"}"#,
    );
    let stub = StubCodex::new(stream, 0, "");

    let events = collect(&stub, ThreadOptions::new(), "scan");

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], ThreadEvent::Unknown));
    assert!(matches!(events[1], ThreadEvent::TurnStarted));
}

// Adversarial: upstream guards payload fields with runtime type checks and
// ignores what does not match. A malformed payload must not abort the stream,
// which a strict deserializer would do.
#[test]
fn ignores_malformed_payloads_without_ending_the_stream() {
    let stream = concat!(
        r#"{"type":"item.completed","item":{"id":"i1"}}"#,
        "\n",
        r#"{"type":"item.completed","item":"not-an-object"}"#,
        "\n",
        r#"{"type":"thread.started","thread_id":12345}"#,
        "\n",
        r#"{"type":"turn.failed","error":"not-an-object"}"#,
        "\n",
        r#"{"type":"error","message":{"nested":true}}"#,
        "\n",
        r#"{"type":"turn.started"}"#,
    );
    let stub = StubCodex::new(stream, 0, "");

    let events = collect(&stub, ThreadOptions::new(), "scan");

    assert_eq!(events.len(), 6, "every line survives: {events:?}");
    // An item with no `type` is kept but matches no known item type.
    let ThreadEvent::ItemCompleted { item } = &events[0] else {
        panic!("expected item.completed");
    };
    assert_eq!(item.as_ref().expect("item").item_type, "");
    // A non-object payload degrades to absent rather than failing.
    assert!(matches!(&events[1], ThreadEvent::ItemCompleted { item } if item.is_none()));
    assert!(matches!(&events[2], ThreadEvent::ThreadStarted { thread_id } if thread_id.is_none()));
    assert!(matches!(&events[3], ThreadEvent::TurnFailed { error } if error.is_none()));
    assert!(matches!(&events[4], ThreadEvent::Error { message } if message.is_none()));
    assert!(matches!(events[5], ThreadEvent::TurnStarted));
}

// `crlfDelay: Infinity` upstream folds CRLF into one line break.
#[test]
fn parses_crlf_terminated_lines() {
    let stub = StubCodex::new(
        "{\"type\":\"turn.started\"}\r\n{\"type\":\"turn.completed\",\"usage\":{}}",
        0,
        "",
    );

    let events = collect(&stub, ThreadOptions::new(), "scan");

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], ThreadEvent::TurnStarted));
}

// Invalid UTF-8 must degrade to a parse error, not silently end the stream.
#[test]
fn reports_invalid_utf8_as_a_parse_failure() {
    let dir = TempDir::new().expect("temp dir");
    let executable = dir.path().join("codex");
    fs::write(
        &executable,
        "#!/bin/sh\ncat > /dev/null\nprintf '\\xff\\xfe not json\\n'\n",
    )
    .expect("write stub");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod");

    let client = ProcessCodexClient::new(&executable);
    let mut thread = client.start_thread(ThreadOptions::new());
    let error = start_stream(&mut *thread, "scan")
        .find_map(Result::err)
        .expect("invalid utf-8 fails the stream");

    assert!(
        error.to_string().starts_with("Failed to parse item:"),
        "{error}"
    );
}

// An abandoned stream must not leave codex running.
#[test]
fn dropping_an_undrained_stream_terminates_codex() {
    let dir = TempDir::new().expect("temp dir");
    let executable = dir.path().join("codex");
    let marker = dir.path().join("still-running");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\ncat > /dev/null\n\
             printf '{{\"type\":\"turn.started\"}}\\n'\n\
             sleep 30\ntouch '{}'\n",
            marker.display()
        ),
    )
    .expect("write stub");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod");

    let client = ProcessCodexClient::new(&executable);
    let mut thread = client.start_thread(ThreadOptions::new());
    let mut stream = start_stream(&mut *thread, "scan");
    let first = stream.next().expect("first event").expect("event");
    assert!(matches!(first, ThreadEvent::TurnStarted));

    let started = std::time::Instant::now();
    drop(stream);

    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "drop must not block on the child"
    );
    assert!(
        !marker.exists(),
        "codex should have been killed before finishing"
    );
}

// Upstream is strict here: a line that is not JSON aborts the stream.
#[test]
fn fails_on_a_malformed_line() {
    let stub = StubCodex::new("not json at all", 0, "");
    let client = stub.client();
    let mut thread = client.start_thread(ThreadOptions::new());

    let error = start_stream(&mut *thread, "scan")
        .find_map(Result::err)
        .expect("malformed line fails the stream");

    assert_eq!(error.to_string(), "Failed to parse item: not json at all");
}

#[test]
fn fails_when_codex_exits_non_zero() {
    let stub = StubCodex::new(SCAN_STREAM, 3, "boom");
    let client = stub.client();
    let mut thread = client.start_thread(ThreadOptions::new());

    let error = start_stream(&mut *thread, "scan")
        .find_map(Result::err)
        .expect("non-zero exit fails the stream");

    assert_eq!(error.to_string(), "Codex Exec exited with code 3: boom");
}

#[test]
fn reports_a_missing_executable_when_the_stream_starts() {
    let client = ProcessCodexClient::new("/nonexistent/codex");
    let mut thread = client.start_thread(ThreadOptions::new());

    assert!(thread.run_streamed("scan").is_err());
}

#[test]
fn cancelling_ends_the_stream() {
    let stub = StubCodex::new(SCAN_STREAM, 0, "");
    let client = stub.client();
    let mut thread = client.start_thread(ThreadOptions::new());
    let mut stream = start_stream(&mut *thread, "scan");
    let cancel = stream.cancel_handle();

    cancel.cancel();
    let remaining: Vec<_> = stream.by_ref().filter_map(Result::ok).collect();

    assert!(
        remaining.len() < 4,
        "cancelled stream stops early, got {remaining:?}"
    );
}

/// A stub that records the environment it was given.
fn environment_stub() -> (TempDir, PathBuf, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let executable = dir.path().join("codex");
    let env_log = dir.path().join("env.txt");
    let script = format!(
        "#!/bin/sh\n\
         env > '{env}'\n\
         cat > /dev/null\n\
         printf '%s\\n' '{{\"type\":\"turn.completed\",\"usage\":null}}'\n",
        env = env_log.display(),
    );
    fs::write(&executable, script).expect("write stub");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    (dir, executable, env_log)
}

fn recorded_environment(env_log: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    fs::read_to_string(env_log)
        .expect("stub recorded env")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

// A scan must run against its isolated Codex home, never the user's real one,
// so the supplied environment replaces the ambient one rather than adding to it.
#[test]
fn runs_codex_in_exactly_the_supplied_environment() {
    let (_dir, executable, env_log) = environment_stub();
    let environment = [
        ("CODEX_HOME".to_owned(), "/isolated/home".to_owned()),
        ("PATH".to_owned(), "/usr/bin".to_owned()),
    ]
    .into_iter()
    .collect();
    let client = ProcessCodexClient::new(&executable).with_environment(environment);
    let mut thread = client.start_thread(ThreadOptions::new());

    start_stream(&mut *thread, "scan").for_each(|event| {
        event.expect("event");
    });

    let recorded = recorded_environment(&env_log);
    assert_eq!(
        recorded.get("CODEX_HOME").map(String::as_str),
        Some("/isolated/home")
    );
    assert!(
        !recorded.contains_key("HOME"),
        "an ambient variable leaked into the scan: {recorded:?}"
    );
}

// Without an explicit environment the client behaves as before, inheriting the
// caller's, so existing callers are unaffected.
#[test]
fn inherits_the_ambient_environment_by_default() {
    let (_dir, executable, env_log) = environment_stub();
    let client = ProcessCodexClient::new(&executable);
    let mut thread = client.start_thread(ThreadOptions::new());

    start_stream(&mut *thread, "scan").for_each(|event| {
        event.expect("event");
    });

    assert!(
        recorded_environment(&env_log).contains_key("PATH"),
        "the ambient environment should still be inherited"
    );
}

// The originator identifies this client to codex; a supplied environment that
// already names one is respected, exactly as an ambient one is.
#[test]
fn does_not_override_an_originator_the_environment_already_sets() {
    let (_dir, executable, env_log) = environment_stub();
    let environment = [
        ("PATH".to_owned(), "/usr/bin".to_owned()),
        (
            "CODEX_INTERNAL_ORIGINATOR_OVERRIDE".to_owned(),
            "caller_chosen".to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let client = ProcessCodexClient::new(&executable).with_environment(environment);
    let mut thread = client.start_thread(ThreadOptions::new());

    start_stream(&mut *thread, "scan").for_each(|event| {
        event.expect("event");
    });

    assert_eq!(
        recorded_environment(&env_log)
            .get("CODEX_INTERNAL_ORIGINATOR_OVERRIDE")
            .map(String::as_str),
        Some("caller_chosen")
    );
}

// An isolated environment that says nothing about the originator still gets
// this client's identity.
#[test]
fn names_itself_as_the_originator_in_a_supplied_environment() {
    let (_dir, executable, env_log) = environment_stub();
    let environment = [("PATH".to_owned(), "/usr/bin".to_owned())]
        .into_iter()
        .collect();
    let client = ProcessCodexClient::new(&executable).with_environment(environment);
    let mut thread = client.start_thread(ThreadOptions::new());

    start_stream(&mut *thread, "scan").for_each(|event| {
        event.expect("event");
    });

    assert!(
        recorded_environment(&env_log).contains_key("CODEX_INTERNAL_ORIGINATOR_OVERRIDE"),
        "the client should identify itself when the environment does not"
    );
}
