//! Serving the read-only surface over the Model Context Protocol.
//!
//! Ported from the `mcp` declarations in `src/cli.ts`.
//!
//! Only `info` is exposed. Every other command declines MCP upstream, and the
//! reason is stated in the server's own instructions: the transport cannot
//! cancel a running command, so a scan started through it could not be stopped.
//! Offering one would be offering something that cannot be taken back.
//!
//! The transport is JSON-RPC over standard input and output, one message per
//! line.

use std::io::{BufRead, Write};

use codex_security::version::VERSION;
use serde_json::{Value, json};

use crate::cli::{InfoArgs, OutputOptions};

/// The protocol revision this server speaks.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Why scanning is not offered here.
const INSTRUCTIONS: &str = "Use info for read-only SDK metadata. Scans and other state-changing \
                            commands are CLI-only because the MCP transport cannot cancel active \
                            commands.";

/// Serves until the client closes the connection.
pub fn serve(input: impl BufRead, mut output: impl Write) -> Result<(), String> {
    for line in input.lines() {
        let line = line.map_err(|error| format!("Could not read a request: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let Some(response) = respond(&line) else {
            // A notification expects no reply.
            continue;
        };
        writeln!(output, "{response}")
            .and_then(|()| output.flush())
            .map_err(|error| format!("Could not write a response: {error}"))?;
    }
    Ok(())
}

/// The reply to one request, or `None` for a notification.
fn respond(line: &str) -> Option<Value> {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        // No id to reply against, so there is nobody to tell.
        return Some(error_response(&Value::Null, -32_700, "Parse error"));
    };
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    // A request without an id is a notification; only requests get replies.
    let id = id?;

    Some(match method {
        "initialize" => result(&id, initialize()),
        "tools/list" => result(&id, json!({ "tools": [info_tool()] })),
        "tools/call" => call(&id, request.get("params")),
        "ping" => result(&id, json!({})),
        _ => error_response(&id, -32_601, &format!("Unknown method: {method}")),
    })
}

/// What this server is and what it offers.
fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "codex-security",
            "version": VERSION,
        },
        "instructions": INSTRUCTIONS,
    })
}

/// The one tool on offer.
///
/// The hints say what it will and will not do, so a caller can decide whether
/// to ask without having to try it.
fn info_tool() -> Value {
    json!({
        "name": "info",
        "description": "Show read-only SDK and bundled-plugin metadata.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        "annotations": {
            "readOnlyHint": true,
            "idempotentHint": true,
            "destructiveHint": false,
            "openWorldHint": false,
        },
    })
}

/// Runs a tool the client asked for.
fn call(id: &Value, params: Option<&Value>) -> Value {
    let name = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != "info" {
        // Named rather than merely refused, so a caller reaching for a scan
        // learns why it is not here.
        return result(
            id,
            json!({
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Unknown tool: {name}. Only info is available over MCP; \
                         state-changing commands are CLI-only.",
                    ),
                }],
            }),
        );
    }

    let arguments = InfoArgs {
        // The report is structured, whatever the terminal would have shown.
        output: OutputOptions {
            json: true,
            format: None,
        },
    };
    match crate::commands::info::run(&arguments) {
        Ok(report) => {
            let structured: Value = serde_json::from_str(&report).unwrap_or_else(|_| Value::Null);
            result(
                id,
                json!({
                    "content": [{ "type": "text", "text": report }],
                    "structuredContent": structured,
                }),
            )
        }
        Err(problem) => result(
            id,
            json!({
                "isError": true,
                "content": [{ "type": "text", "text": problem }],
            }),
        ),
    }
}

fn result(id: &Value, value: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": value })
}

fn error_response(id: &Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The replies to a sequence of requests.
    fn exchange(requests: &[Value]) -> Vec<Value> {
        let input: String = requests
            .iter()
            .map(|request| format!("{request}\n"))
            .collect();
        let mut output = Vec::new();
        serve(std::io::BufReader::new(input.as_bytes()), &mut output).expect("serves");
        String::from_utf8_lossy(&output)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("a JSON reply"))
            .collect()
    }

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    #[test]
    fn reports_what_it_is() {
        let replies = exchange(&[request(1, "initialize", json!({}))]);

        assert_eq!(replies[0]["id"], 1);
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], "codex-security");
        assert_eq!(replies[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    // The reason scanning is absent is part of what the server says about
    // itself, so a caller is not left guessing.
    #[test]
    fn explains_why_scanning_is_not_offered() {
        let replies = exchange(&[request(1, "initialize", json!({}))]);

        let instructions = replies[0]["result"]["instructions"]
            .as_str()
            .unwrap_or_default();
        assert!(
            instructions.contains("cannot cancel active commands"),
            "{instructions}"
        );
        assert!(instructions.contains("CLI-only"), "{instructions}");
    }

    // Every other command declines MCP upstream; offering one here would be
    // offering something that cannot be stopped.
    #[test]
    fn offers_only_the_read_only_report() {
        let replies = exchange(&[request(1, "tools/list", json!({}))]);

        let tools = replies[0]["result"]["tools"].as_array().expect("tools");
        assert_eq!(tools.len(), 1, "{tools:?}");
        assert_eq!(tools[0]["name"], "info");
        assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
        assert_eq!(tools[0]["annotations"]["destructiveHint"], false);
        assert_eq!(tools[0]["annotations"]["openWorldHint"], false);
    }

    #[test]
    fn answers_the_report_it_offers() {
        let replies = exchange(&[request(
            1,
            "tools/call",
            json!({ "name": "info", "arguments": {} }),
        )]);

        let structured = &replies[0]["result"]["structuredContent"];
        assert_eq!(structured["cliVersion"], VERSION);
        assert_eq!(structured["scanMcp"], false);
        // Also as text, for clients that do not read structured content.
        let text = replies[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("bundledPluginVersion"), "{text}");
    }

    // A caller reaching for a scan learns why it is not here.
    #[test]
    fn explains_an_unknown_tool_rather_than_only_refusing() {
        let replies = exchange(&[request(
            1,
            "tools/call",
            json!({ "name": "scan", "arguments": {} }),
        )]);

        assert_eq!(replies[0]["result"]["isError"], true);
        let text = replies[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("Only info is available"), "{text}");
        assert!(text.contains("CLI-only"), "{text}");
    }

    #[test]
    fn refuses_a_method_it_does_not_have() {
        let replies = exchange(&[request(1, "resources/list", json!({}))]);

        assert_eq!(replies[0]["error"]["code"], -32_601);
    }

    // A notification expects no reply, and answering one would confuse a
    // client that is not waiting.
    #[test]
    fn says_nothing_to_a_notification() {
        let replies = exchange(&[
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            request(1, "ping", json!({})),
        ]);

        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(replies[0]["id"], 1);
    }

    #[test]
    fn answers_several_requests_in_order() {
        let replies = exchange(&[
            request(1, "initialize", json!({})),
            request(2, "tools/list", json!({})),
            request(3, "ping", json!({})),
        ]);

        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["id"], 1);
        assert_eq!(replies[1]["id"], 2);
        assert_eq!(replies[2]["id"], 3);
    }

    #[test]
    fn reports_a_request_it_cannot_parse() {
        let mut output = Vec::new();
        serve(
            std::io::BufReader::new("not json\n".as_bytes()),
            &mut output,
        )
        .expect("serves");

        let reply: Value =
            serde_json::from_str(String::from_utf8_lossy(&output).trim()).expect("a reply");
        assert_eq!(reply["error"]["code"], -32_700);
    }

    #[test]
    fn ignores_blank_lines() {
        let replies = exchange(&[json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })]);

        assert_eq!(replies.len(), 1);
    }
}
