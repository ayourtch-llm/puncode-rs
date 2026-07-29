//! Reporting versions and configuration.
//!
//! Ported from the `info` command in `src/cli.ts`.
//!
//! This is the command people run when something else is behaving oddly, so it
//! reports what this build actually is rather than what it was meant to be, and
//! answers without touching Codex, the network, or any configuration on disk.

use codex_security::config::{default_codex_config, scan_model_configuration};
use codex_security::version::{BUNDLED_PLUGIN_VERSION, CODEX_EXECUTABLE_VERSION, VERSION};
use serde_json::{Value, json};

use crate::cli::{Format, InfoArgs};

/// Why scanning is not offered over the MCP transport.
const CANCELLATION_NOTE: &str =
    "Scans are CLI-only because the MCP transport cannot cancel active commands.";

/// What to try next, for someone who just installed this.
const NEXT_STEP: &str = "codex-security scan . --dry-run";

/// Reports what this build is.
pub fn run(arguments: &InfoArgs) -> Result<String, String> {
    let model =
        scan_model_configuration(default_codex_config()).map_err(|error| error.to_string())?;

    // Upstream also reports the TypeScript SDK's version; this port drives the
    // codex executable directly and has no such SDK, so it is left out rather
    // than reported as something meaningless.
    let report = json!({
        "sdkVersion": VERSION,
        "bundledPluginVersion": BUNDLED_PLUGIN_VERSION,
        "scanMcp": false,
        "cancellationNote": CANCELLATION_NOTE,
        "cliVersion": VERSION,
        "codexVersion": CODEX_EXECUTABLE_VERSION,
        "model": model.model,
        "reasoningEffort": model.reasoning_effort,
        "nextStep": NEXT_STEP,
    });

    Ok(match arguments.output.resolved() {
        Format::Text => render_text(&report),
        Format::Json => serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?,
        // One object is one line, so the two structured forms agree here.
        Format::Jsonl => serde_json::to_string(&report).map_err(|error| error.to_string())?,
    })
}

/// The same report, for a person.
fn render_text(report: &Value) -> String {
    let field = |name: &str| -> String {
        report
            .get(name)
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };

    [
        format!("codex-security {}", field("cliVersion")),
        String::new(),
        format!("  bundled plugin   {}", field("bundledPluginVersion")),
        format!("  codex            {}", field("codexVersion")),
        format!("  model            {}", field("model")),
        format!("  reasoning effort {}", field("reasoningEffort")),
        format!("  scan over MCP    {}", field("scanMcp")),
        String::new(),
        field("cancellationNote").to_string(),
        String::new(),
        format!("Next: {}", field("nextStep")),
    ]
    .join("\n")
}
