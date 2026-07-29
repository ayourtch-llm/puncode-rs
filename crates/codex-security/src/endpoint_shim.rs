//! Adapting requests for endpoints that cannot accept them as Codex sends them.
//!
//! Not a port: upstream only ever talks to hosted Codex, which needs no such
//! adaptation.
//!
//! Codex's request shape is not negotiable and neither, in general, is the
//! server's — a self-hosted model is often behind someone else's deployment.
//! When the two disagree the scan simply fails, so this reshapes the request in
//! between.
//!
//! Every adaptation here is opt-in and named for the incompatibility it works
//! around, because silently rewriting what the model is asked is not something
//! that should happen by default. Nothing in this module inspects, stores or
//! logs the content it passes through: it moves text between fields and hands
//! it on.

use serde_json::Value;

/// What to change about each request on its way to the endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Adaptations {
    /// Collapse every piece of system-level content into one field.
    ///
    /// Some chat templates permit exactly one system message and refuse a
    /// request carrying more. Codex sends `instructions` alongside any number
    /// of `developer` items, which such a server turns into several.
    pub merge_system: bool,
}

impl Adaptations {
    /// Whether any adaptation is asked for.
    #[must_use]
    pub fn any(self) -> bool {
        self.merge_system
    }
}

/// Applies the adaptations to one request body.
pub fn adapt_request(body: &mut Value, adaptations: Adaptations) {
    if adaptations.merge_system {
        merge_system_content(body);
    }
}

/// Folds system-level input items into the `instructions` field.
///
/// The order is preserved and nothing is dropped: `instructions` keeps its
/// place at the front and the folded items follow in the order they were sent,
/// so the model is asked the same thing in the same sequence. Only the number
/// of system messages the server will construct changes.
fn merge_system_content(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let Some(Value::Array(input)) = object.get("input") else {
        return;
    };

    let mut folded: Vec<String> = Vec::new();
    let mut kept: Vec<Value> = Vec::new();
    for item in input {
        if item.get("role").and_then(Value::as_str) == Some("developer") {
            folded.extend(item_text(item));
        } else {
            kept.push(item.clone());
        }
    }

    if folded.is_empty() {
        return;
    }

    let mut instructions: Vec<String> = Vec::new();
    if let Some(existing) = object.get("instructions").and_then(Value::as_str)
        && !existing.is_empty()
    {
        instructions.push(existing.to_owned());
    }
    instructions.extend(folded);

    object.insert(
        "instructions".to_owned(),
        Value::String(instructions.join("\n\n")),
    );
    object.insert("input".to_owned(), Value::Array(kept));
}

/// The text an input item carries.
///
/// Content may be a plain string or a list of parts; anything without text,
/// such as an image, has nothing to fold and is left out rather than guessed at.
fn item_text(item: &Value) -> Vec<String> {
    match item.get("content") {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The forwarder
// ---------------------------------------------------------------------------

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

/// The largest request body that will be adapted.
///
/// A body beyond this is passed through untouched rather than held in memory.
const MAX_ADAPTED_BODY: usize = 32 * 1_024 * 1_024;

/// A local forwarder that adapts requests on their way to an endpoint.
///
/// Listens on the loopback interface only, so nothing outside this machine can
/// reach it, and on a port the operating system chooses, so it cannot collide
/// with anything the person is already running.
pub struct EndpointShim {
    address: SocketAddr,
    running: Arc<AtomicBool>,
}

impl EndpointShim {
    /// Starts forwarding to `upstream`.
    ///
    /// `upstream` is the endpoint's base URL; the path of each request is
    /// appended to its origin.
    pub fn start(upstream: &str, adaptations: Adaptations) -> Result<Self> {
        let upstream = upstream.trim_end_matches('/').to_owned();

        // Loopback only: this exists for the Codex process on this machine.
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
            Error::configuration(format!("Could not start the endpoint adapter: {error}"))
        })?;
        let address = listener.local_addr().map_err(|error| {
            Error::configuration(format!("Could not start the endpoint adapter: {error}"))
        })?;

        let running = Arc::new(AtomicBool::new(true));
        let alive = Arc::clone(&running);
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                if !alive.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(connection) = connection else { continue };
                let upstream = upstream.clone();
                // A scan runs several agents at once, so connections are served
                // concurrently rather than one after another.
                std::thread::spawn(move || {
                    let _ = serve_connection(connection, &upstream, adaptations);
                });
            }
        });

        Ok(Self { address, running })
    }

    /// The address Codex should be pointed at.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for EndpointShim {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Unblock the accept loop so the thread can notice and finish.
        let _ = TcpStream::connect(self.address);
    }
}

/// Forwards one request and streams the answer back.
fn serve_connection(
    mut connection: TcpStream,
    upstream: &str,
    adaptations: Adaptations,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(connection.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or("/").to_owned();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_owned(), value.trim().to_owned());
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    // Only a body small enough to hold is reshaped; anything larger goes on as
    // it arrived rather than being buffered without bound.
    if adaptations.any()
        && body.len() <= MAX_ADAPTED_BODY
        && let Ok(mut parsed) = serde_json::from_slice::<Value>(&body)
    {
        adapt_request(&mut parsed, adaptations);
        if let Ok(rewritten) = serde_json::to_vec(&parsed) {
            body = rewritten;
        }
    }

    let target = format!("{upstream}{path}");
    let mut outbound = ureq::http::Request::builder()
        .method(method.as_str())
        .uri(&target);
    for (name, value) in &headers {
        // Hop-by-hop and length headers describe this connection, not the next.
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "connection" | "transfer-encoding" | "accept-encoding"
        ) {
            continue;
        }
        outbound = outbound.header(name, value);
    }
    let Ok(outbound) = outbound.body(body.as_slice()) else {
        return Ok(());
    };

    // A status the endpoint reports is an answer to pass on, not an error to
    // swallow: the message in its body is what explains the refusal.
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .new_agent();

    let answer = agent.run(outbound);
    let (status, response) = match answer {
        Ok(response) => (response.status().as_u16(), Some(response)),
        Err(error) => {
            let message = format!("endpoint unreachable: {error}");
            let payload = serde_json::json!({ "error": { "message": message } }).to_string();
            connection.write_all(
                format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                )
                .as_bytes(),
            )?;
            let _ = connection.shutdown(Shutdown::Both);
            return Ok(());
        }
    };

    let Some(response) = response else {
        return Ok(());
    };

    // The answer is streamed rather than collected: these responses are event
    // streams, and holding one until it ends would turn progressive output into
    // a long silence.
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    connection.write_all(
        format!("HTTP/1.1 {status} \r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    connection.flush()?;

    let mut source = response.into_body().into_reader();
    let mut buffer = [0u8; 8 * 1_024];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        if connection.write_all(&buffer[..read]).is_err() {
            break;
        }
        // Flushed per chunk so each event reaches Codex as it arrives.
        let _ = connection.flush();
    }
    let _ = connection.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Value {
        json!({
            "model": "a-model",
            "instructions": "the system prompt",
            "input": [
                { "role": "developer", "content": [{ "type": "input_text", "text": "first" }] },
                { "role": "developer", "content": [{ "type": "input_text", "text": "second" }] },
                { "role": "user", "content": [{ "type": "input_text", "text": "the question" }] },
            ],
        })
    }

    /// A server that permits one system message must receive one.
    #[test]
    fn leaves_no_system_items_behind_in_the_input() {
        let mut body = request();

        adapt_request(&mut body, Adaptations { merge_system: true });

        let roles: Vec<&str> = body["input"]
            .as_array()
            .expect("input")
            .iter()
            .filter_map(|item| item["role"].as_str())
            .collect();
        assert_eq!(roles, ["user"]);
    }

    /// Folding must not lose what the model was told, or reorder it.
    #[test]
    fn keeps_every_instruction_in_the_order_it_was_sent() {
        let mut body = request();

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body["instructions"], "the system prompt\n\nfirst\n\nsecond");
    }

    #[test]
    fn keeps_the_question_untouched() {
        let mut body = request();

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body["input"][0]["content"][0]["text"], "the question");
        assert_eq!(body["model"], "a-model");
    }

    /// Rewriting what the model is asked is not something to do by default.
    #[test]
    fn changes_nothing_when_not_asked_to() {
        let mut body = request();
        let before = body.clone();

        adapt_request(&mut body, Adaptations::default());

        assert_eq!(body, before);
    }

    /// A request with nothing to fold must come out byte for byte the same,
    /// so turning the adaptation on is safe for endpoints that never needed it.
    #[test]
    fn leaves_a_request_with_no_system_items_alone() {
        let mut body = json!({
            "model": "a-model",
            "instructions": "the system prompt",
            "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "hi" }] }],
        });
        let before = body.clone();

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body, before);
    }

    /// There may be no `instructions` field to fold into.
    #[test]
    fn folds_into_a_request_that_had_no_instructions() {
        let mut body = json!({
            "input": [
                { "role": "developer", "content": [{ "type": "input_text", "text": "only this" }] },
                { "role": "user", "content": [{ "type": "input_text", "text": "hi" }] },
            ],
        });

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body["instructions"], "only this");
    }

    /// An empty `instructions` must not contribute a leading blank line.
    #[test]
    fn does_not_fold_an_empty_instructions_field() {
        let mut body = json!({
            "instructions": "",
            "input": [
                { "role": "developer", "content": [{ "type": "input_text", "text": "only this" }] },
            ],
        });

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body["instructions"], "only this");
    }

    /// Content is sometimes a bare string rather than a list of parts.
    #[test]
    fn folds_content_given_as_a_plain_string() {
        let mut body = json!({
            "input": [{ "role": "developer", "content": "plain" }],
        });

        adapt_request(&mut body, Adaptations { merge_system: true });

        assert_eq!(body["instructions"], "plain");
    }

    /// An item with nothing to fold, such as an image, is not guessed at — but
    /// it must still be taken out of the input, or the server still sees a
    /// system message and the whole exercise fails.
    #[test]
    fn removes_a_system_item_it_cannot_read_text_from() {
        let mut body = json!({
            "instructions": "the system prompt",
            "input": [
                { "role": "developer", "content": [{ "type": "input_image", "url": "x" }] },
                { "role": "developer", "content": [{ "type": "input_text", "text": "readable" }] },
                { "role": "user", "content": "hi" },
            ],
        });

        adapt_request(&mut body, Adaptations { merge_system: true });

        let roles: Vec<&str> = body["input"]
            .as_array()
            .expect("input")
            .iter()
            .filter_map(|item| item["role"].as_str())
            .collect();
        assert_eq!(roles, ["user"]);
        assert_eq!(body["instructions"], "the system prompt\n\nreadable");
    }

    /// Bodies that are not shaped like a request must not panic or be mangled.
    #[test]
    fn leaves_something_that_is_not_a_request_alone() {
        for mut body in [json!(null), json!([1, 2]), json!("text"), json!({})] {
            let before = body.clone();
            adapt_request(&mut body, Adaptations { merge_system: true });
            assert_eq!(body, before);
        }
    }

    #[test]
    fn reports_whether_anything_is_asked_for() {
        assert!(!Adaptations::default().any());
        assert!(Adaptations { merge_system: true }.any());
    }
}
