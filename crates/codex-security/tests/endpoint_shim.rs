//! Forwarding through the endpoint adapter.
//!
//! These run a real server behind the real adapter, because the whole point of
//! the adapter is what arrives at the other end.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use codex_security::endpoint_shim::{Adaptations, EndpointShim};
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

/// Sends one request through the adapter and returns the raw answer.
fn through(shim: &EndpointShim, body: &str) -> String {
    let address = shim.base_url().replace("http://", "");
    let mut stream = TcpStream::connect(address).expect("connects");
    stream
        .write_all(
            format!(
                "POST /v1/responses HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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
    let shim = EndpointShim::start(&recorder.base_url, Adaptations { merge_system: true })
        .expect("starts");

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
    let shim = EndpointShim::start(&recorder.base_url, Adaptations::default()).expect("starts");

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
    let shim = EndpointShim::start(&recorder.base_url, Adaptations { merge_system: true })
        .expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("200"), "{answer}");
    assert!(answer.contains(r#"{"answer":42}"#), "{answer}");
}

/// An endpoint that cannot be reached has to be reported as such, rather than
/// leaving the caller waiting on a connection that will never answer.
#[test]
fn reports_an_endpoint_it_cannot_reach() {
    // Port 1 on loopback: nothing serves it.
    let shim = EndpointShim::start("http://127.0.0.1:1", Adaptations::default()).expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("502"), "{answer}");
    assert!(answer.contains("unreachable"), "{answer}");
}

/// A scan runs several agents at once, so the adapter must serve more than one
/// conversation at a time rather than making them queue.
#[test]
fn serves_several_requests_at_once() {
    let recorder = Recorder::start(r#"{"ok":true}"#, "application/json");
    let shim = Arc::new(
        EndpointShim::start(&recorder.base_url, Adaptations { merge_system: true })
            .expect("starts"),
    );

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
    let shim = EndpointShim::start(&recorder.base_url, Adaptations::default()).expect("starts");

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
    let shim = EndpointShim::start(&recorder.base_url, Adaptations { merge_system: true })
        .expect("starts");

    let answer = through(&shim, REQUEST);

    assert!(answer.contains("text/event-stream"), "{answer}");
    assert!(answer.contains(r#"data: {"type":"one"}"#), "{answer}");
    assert!(answer.contains("[DONE]"), "{answer}");
}
