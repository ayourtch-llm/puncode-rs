//! Forwarding through the endpoint adapter.
//!
//! These run a real server behind the real adapter, because the whole point of
//! the adapter is what arrives at the other end.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use puncode_security::endpoint_shim::{Adaptations, CaptureLimit, EndpointShim, ShimOptions};
use serde_json::Value;

/// A server that records what it was sent and answers with what it was told to.
struct Recorder {
    base_url: String,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl Recorder {
    fn start(answer: &'static str, content_type: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binds");
        let base_url = format!("http://{}", listener.local_addr().expect("address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);

        std::thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(mut connection) = connection else {
                    continue;
                };
                let mut reader = BufReader::new(connection.try_clone().expect("clone"));
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 {
                        break;
                    }
                    let header = header.trim_end_matches(['\r', '\n']);
                    if header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.trim().eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                if let Ok(parsed) = serde_json::from_slice::<Value>(&body) {
                    recorded.lock().expect("the record").push(parsed);
                }
                let _ = connection.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    )
                    .as_bytes(),
                );
                let _ = connection.flush();
            }
        });

        Self { base_url, seen }
    }

    fn received(&self) -> Vec<Value> {
        self.seen.lock().expect("the record").clone()
    }
}

/// Options that merge system content and record nothing.
fn merging() -> ShimOptions {
    ShimOptions {
        adaptations: Adaptations { merge_system: true },
        capture: None,
        capture_limit: CaptureLimit::Default,
    }
}

/// Sends one request through the adapter and returns the raw answer.
fn through(shim: &EndpointShim, body: &str) -> String {
    through_path(shim, "/v1/responses", body)
}

/// As above, to a specific path.
///
/// Codex is pointed at the forwarder's root and posts `/responses`; the path is
/// appended to a base URL that already carries `/v1`. A live endpoint cares
/// about the difference even though the recorder in these tests does not.
fn through_path(shim: &EndpointShim, path: &str, body: &str) -> String {
    let address = shim.base_url().replace("http://", "");
    let mut stream = TcpStream::connect(address).expect("connects");
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("writes");
    stream.flush().expect("flushes");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("reads");
    answer
}

const REQUEST: &str = r#"{"model":"m","instructions":"sys","input":[
    {"role":"developer","content":[{"type":"input_text","text":"first"}]},
    {"role":"developer","content":[{"type":"input_text","text":"second"}]},
    {"role":"user","content":[{"type":"input_text","text":"question"}]}]}"#;

/// What the endpoint receives is the adapted request, not the original.
#[test]
fn the_endpoint_receives_one_system_message() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let shim = EndpointShim::start(&recorder.base_url, &merging()).expect("starts");

    through(&shim, REQUEST);

    let received = recorder.received();
    assert_eq!(received.len(), 1, "{received:?}");
    let roles: Vec<&str> = received[0]["input"]
        .as_array()
        .expect("input")
        .iter()
        .filter_map(|item| item["role"].as_str())
        .collect();
    assert_eq!(roles, ["user"]);
    assert_eq!(received[0]["instructions"], "sys\n\nfirst\n\nsecond");
}

/// Without the adaptation the request must arrive exactly as it was sent.
#[test]
fn passes_a_request_through_unchanged_when_not_adapting() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let shim = EndpointShim::start(&recorder.base_url, &ShimOptions::default()).expect("starts");

    through(&shim, REQUEST);

    let received = recorder.received();
    let roles: Vec<&str> = received[0]["input"]
        .as_array()
        .expect("input")
        .iter()
        .filter_map(|item| item["role"].as_str())
        .collect();
    assert_eq!(roles, ["developer", "developer", "user"]);
    assert_eq!(received[0]["instructions"], "sys");
}

/// The answer has to come back, or the adapter is a wall rather than a bridge.
#[test]
fn returns_the_endpoints_answer() {
    let recorder = Recorder::start(r#"{"answer":42}"#, "application/json");
    let shim = EndpointShim::start(&recorder.base_url, &merging()).expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("200"), "{answer}");
    assert!(answer.contains(r#"{"answer":42}"#), "{answer}");
}

/// An endpoint that cannot be reached has to be reported as such, rather than
/// leaving the caller waiting on a connection that will never answer.
#[test]
fn reports_an_endpoint_it_cannot_reach() {
    // Port 1 on loopback: nothing serves it.
    let shim = EndpointShim::start("http://127.0.0.1:1", &ShimOptions::default()).expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("502"), "{answer}");
    assert!(answer.contains("unreachable"), "{answer}");
}

/// A scan runs several agents at once, so the adapter must serve more than one
/// conversation at a time rather than making them queue.
#[test]
fn serves_several_requests_at_once() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let shim = Arc::new(EndpointShim::start(&recorder.base_url, &merging()).expect("starts"));

    let workers: Vec<_> = (0..8)
        .map(|_| {
            let shim = Arc::clone(&shim);
            std::thread::spawn(move || through(&shim, REQUEST))
        })
        .collect();
    for worker in workers {
        let answer = worker.join().expect("the worker finishes");
        assert!(answer.contains("200"), "{answer}");
    }

    assert_eq!(recorder.received().len(), 8);
}

/// It listens only where the Codex process on this machine can reach it.
#[test]
fn listens_only_on_the_loopback_interface() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let shim = EndpointShim::start(&recorder.base_url, &ShimOptions::default()).expect("starts");

    assert!(
        shim.base_url().starts_with("http://127.0.0.1:"),
        "{}",
        shim.base_url()
    );
}

/// Event streams are what a scan actually receives, and they must arrive as a
/// stream rather than being held until the model has finished talking.
#[test]
fn passes_an_event_stream_back() {
    let stream = "data: {\"type\":\"one\"}\n\ndata: {\"type\":\"two\"}\n\ndata: [DONE]\n\n";
    let recorder = Recorder::start(stream, "text/event-stream");
    let shim = EndpointShim::start(&recorder.base_url, &merging()).expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("text/event-stream"), "{answer}");
    assert!(answer.contains(r#"data: {"type":"one"}"#), "{answer}");
    assert!(answer.contains("[DONE]"), "{answer}");
}

/// Nothing is written unless a capture was asked for.
///
/// This is the property that matters most: the traffic carries the source under
/// review, so the default must leave no trace of it anywhere.
#[test]
fn records_nothing_when_no_capture_was_asked_for() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let shim = EndpointShim::start(&recorder.base_url, &merging()).expect("starts");

    through(&shim, REQUEST);

    let written: Vec<_> = std::fs::read_dir(directory.path())
        .expect("reads")
        .filter_map(std::result::Result::ok)
        .collect();
    assert!(written.is_empty(), "{written:?}");
}

/// A capture holds both sides, so a failure can be read as an exchange.
#[test]
fn records_both_what_was_sent_and_what_came_back() {
    let recorder = Recorder::start(r#"{"answer":42}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let destination = directory.path().join("traffic.jsonl");
    let shim = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations { merge_system: true },
            capture: Some(destination.clone()),
            capture_limit: CaptureLimit::Default,
        },
    )
    .expect("starts");

    through(&shim, REQUEST);
    // The response is recorded once the stream ends.
    std::thread::sleep(std::time::Duration::from_millis(300));

    let written = std::fs::read_to_string(&destination).expect("reads the capture");
    let entries: Vec<Value> = written
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("a JSON entry"))
        .collect();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["direction"], "request");
    assert_eq!(entries[1]["direction"], "response");
    assert_eq!(entries[1]["status"], 200);
    assert!(
        entries[1]["body"]
            .as_str()
            .unwrap_or_default()
            .contains("42"),
        "{entries:?}"
    );
}

/// What is recorded is what the endpoint was actually sent, not what Codex
/// composed — otherwise the capture would not show the request that failed.
#[test]
fn records_the_request_as_the_endpoint_received_it() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let destination = directory.path().join("traffic.jsonl");
    let shim = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations { merge_system: true },
            capture: Some(destination.clone()),
            capture_limit: CaptureLimit::Default,
        },
    )
    .expect("starts");

    through(&shim, REQUEST);

    let written = std::fs::read_to_string(&destination).expect("reads the capture");
    let first: Value =
        serde_json::from_str(written.lines().next().expect("an entry")).expect("JSON");
    let body: Value =
        serde_json::from_str(first["body"].as_str().expect("a body")).expect("the sent body");
    assert_eq!(body["instructions"], "sys\n\nfirst\n\nsecond");
}

/// The file holds source under review, so it is readable only by its owner.
#[test]
fn writes_the_capture_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let destination = directory.path().join("traffic.jsonl");
    let _shim = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations::default(),
            capture: Some(destination.clone()),
            capture_limit: CaptureLimit::Default,
        },
    )
    .expect("starts");

    let mode = std::fs::metadata(&destination)
        .expect("the capture exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
}

/// A destination that cannot be written is reported when the scan starts, not
/// discovered after it has been running for minutes.
#[test]
fn refuses_a_destination_it_cannot_write() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");

    let refused = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations::default(),
            capture: Some("/does/not/exist/traffic.jsonl".into()),
            capture_limit: CaptureLimit::Default,
        },
    );

    let complaint = refused.err().expect("a refusal").to_string();
    assert!(complaint.contains("traffic capture"), "{complaint}");
}

/// Talks to a real endpoint, when one is offered.
///
/// Ignored by default: the rest of this suite must pass with no network and no
/// server, so a test that needs both cannot be part of the ordinary run. Give
/// it an endpoint to exercise the path that only a real server can:
///
/// ```text
/// CODEX_SECURITY_TEST_BASE_URL=http://host:8080/v1 \
/// CODEX_SECURITY_TEST_MODEL=the-model \
///   cargo test -p puncode-security --test endpoint_shim -- --ignored
/// ```
#[test]
#[ignore = "needs a live OpenAI-compatible endpoint; see the doc comment"]
fn reaches_a_live_endpoint() {
    let Ok(base_url) = std::env::var("CODEX_SECURITY_TEST_BASE_URL") else {
        panic!("set CODEX_SECURITY_TEST_BASE_URL to the endpoint to test against");
    };
    let model = std::env::var("CODEX_SECURITY_TEST_MODEL")
        .expect("set CODEX_SECURITY_TEST_MODEL to a model the endpoint serves");

    let shim = EndpointShim::start(&base_url, &merging()).expect("starts");

    // Shaped like what Codex sends: instructions plus developer items, which is
    // the combination a single-system-message template refuses.
    let request = serde_json::json!({
        "model": model,
        "instructions": "You are terse.",
        "input": [
            { "role": "developer", "content": [{ "type": "input_text", "text": "Answer briefly." }] },
            { "role": "developer", "content": [{ "type": "input_text", "text": "Do not explain." }] },
            { "role": "user", "content": [{ "type": "input_text", "text": "Say OK." }] },
        ],
        "max_output_tokens": 16,
    })
    .to_string();

    let answer = through_path(&shim, "/responses", &request);

    assert!(
        answer.contains(" 200"),
        "the endpoint refused the adapted request:\n{answer}"
    );
    // The failure this adaptation exists for, so that it is named if it returns.
    assert!(
        !answer.contains("System message must be at the beginning"),
        "merging did not satisfy the template:\n{answer}"
    );
}

/// A body cut short must say so, and must report its real length.
///
/// This is the whole point of the limit being safe to lower: a short record
/// that claims to be whole is worse than no record.
#[test]
fn says_when_a_body_was_cut_short() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let destination = directory.path().join("traffic.jsonl");
    let shim = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations::default(),
            capture: Some(destination.clone()),
            capture_limit: CaptureLimit::Bytes(32),
        },
    )
    .expect("starts");

    through(&shim, REQUEST);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let written = std::fs::read_to_string(&destination).expect("reads the capture");
    let request: Value =
        serde_json::from_str(written.lines().next().expect("an entry")).expect("JSON");
    assert_eq!(request["truncated"], true);
    assert_eq!(request["body"].as_str().expect("a body").len(), 32);
    // The real length, not the kept length.
    assert!(
        request["bytes"].as_u64().expect("a length") > 32,
        "{request:?}"
    );
}

/// A whole body is not marked as cut short.
#[test]
fn does_not_claim_a_whole_body_was_cut() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let directory = tempfile::tempdir().expect("a directory");
    let destination = directory.path().join("traffic.jsonl");
    let shim = EndpointShim::start(
        &recorder.base_url,
        &ShimOptions {
            adaptations: Adaptations::default(),
            capture: Some(destination.clone()),
            capture_limit: CaptureLimit::Unlimited,
        },
    )
    .expect("starts");

    through(&shim, REQUEST);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let written = std::fs::read_to_string(&destination).expect("reads the capture");
    for line in written.lines().filter(|line| !line.trim().is_empty()) {
        let entry: Value = serde_json::from_str(line).expect("JSON");
        assert_eq!(entry["truncated"], false, "{entry:?}");
    }
}

#[test]
fn reports_the_limit_it_will_apply() {
    use puncode_security::endpoint_shim::DEFAULT_CAPTURE_LIMIT;

    assert_eq!(CaptureLimit::Default.bytes(), Some(DEFAULT_CAPTURE_LIMIT));
    assert_eq!(CaptureLimit::Bytes(64).bytes(), Some(64));
    assert_eq!(CaptureLimit::Unlimited.bytes(), None);
}
