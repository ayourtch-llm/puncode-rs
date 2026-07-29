//! Reading worker progress out of the scan event stream.
//!
//! Ported from `src/worker-progress.ts`.
//!
//! The plugin reports delegation capacity and dispatch counts through ordinary
//! thread items rather than a dedicated channel, so these are parsed
//! defensively: anything that does not match exactly is ignored rather than
//! guessed at.

use serde_json::Value;

use crate::codex::{ThreadEvent, ThreadItem};

/// Parsed payloads above this size are ignored, so a large agent message
/// cannot be turned into unbounded work.
const MAX_WORKER_STATUS_BYTES: usize = 64 * 1_024;

/// The largest plausible worker count; anything beyond it is treated as junk.
const MAX_WORKER_COUNT: u64 = 1_024;

const WORKER_STATUS_PREFIX: &str = "CODEX_SECURITY_WORKER_STATUS ";

const PREFLIGHT_SCRIPT: &str = "config_preflight.py";

/// The phase of a scan that is dispatching workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanWorkerPhase {
    Ranking,
    FileReview,
    Validation,
    AttackPath,
}

impl ScanWorkerPhase {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ranking" => Some(Self::Ranking),
            "file_review" => Some(Self::FileReview),
            "validation" => Some(Self::Validation),
            "attack_path" => Some(Self::AttackPath),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ranking => "ranking",
            Self::FileReview => "file_review",
            Self::Validation => "validation",
            Self::AttackPath => "attack_path",
        }
    }
}

/// Whether the scan can delegate work to parallel workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerDelegation {
    Available,
    Unavailable,
    Unknown,
}

impl WorkerDelegation {
    fn parse(status: &str) -> Option<Self> {
        match status {
            "pass" => Some(Self::Available),
            "fail" => Some(Self::Unavailable),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// A progress report derived from a scan event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanWorkerStatus {
    /// The preflight check reported whether delegation is usable.
    Preflight {
        delegation: WorkerDelegation,
        /// Worker slots the configuration allows, when the preflight reported
        /// a capacity requirement.
        configured_slots: Option<u64>,
    },
    /// Workers were dispatched for a phase.
    Dispatch {
        phase: ScanWorkerPhase,
        planned: u64,
        started: u64,
    },
}

/// Extracts a worker status from `event`, or `None` if it carries none.
#[must_use]
pub fn worker_status_from_event(event: &ThreadEvent) -> Option<ScanWorkerStatus> {
    let ThreadEvent::ItemCompleted { item: Some(item) } = event else {
        return None;
    };
    match item.item_type.as_str() {
        "command_execution" => preflight_status(item),
        "agent_message" => dispatch_status(item),
        _ => None,
    }
}

fn preflight_status(item: &ThreadItem) -> Option<ScanWorkerStatus> {
    let command = item.field("command").and_then(Value::as_str)?;
    if !runs_preflight_script(command) {
        return None;
    }
    let output = item.field("aggregated_output").and_then(Value::as_str)?;
    if output.len() > MAX_WORKER_STATUS_BYTES {
        return None;
    }

    let payload: Value = serde_json::from_str(output).ok()?;
    let payload = payload.as_object()?;
    let profile = payload.get("profile").and_then(Value::as_str)?;
    if profile != "security_scan" && profile != "security_diff_scan" {
        return None;
    }
    let results = payload.get("results")?.as_array()?;

    // Exactly one delegation verdict, or the report is ambiguous.
    let mut delegated = results.iter().filter(|result| {
        result
            .as_object()
            .and_then(|result| result.get("capability"))
            .and_then(Value::as_str)
            == Some("delegated_workers")
    });
    let delegation = delegated.next()?;
    if delegated.next().is_some() {
        return None;
    }
    let delegation = WorkerDelegation::parse(
        delegation
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )?;

    // At most one capacity verdict; its absence just means no requirement.
    let capacity: Vec<&Value> = results
        .iter()
        .filter(|result| {
            result
                .as_object()
                .and_then(|result| result.get("capability"))
                .and_then(Value::as_str)
                .is_some_and(|capability| capability.starts_with("usable_worker_slots_"))
        })
        .collect();
    if capacity.len() > 1 {
        return None;
    }
    let configured_slots = capacity
        .first()
        .and_then(|result| result.get("actual"))
        .and_then(worker_count);

    Some(ScanWorkerStatus::Preflight {
        delegation,
        configured_slots,
    })
}

fn dispatch_status(item: &ThreadItem) -> Option<ScanWorkerStatus> {
    let text = item.field("text").and_then(Value::as_str)?;
    if text.len() > MAX_WORKER_STATUS_BYTES {
        return None;
    }

    // Exactly one marker, or the message is reporting conflicting states.
    let mut markers = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter_map(|line| line.strip_prefix(WORKER_STATUS_PREFIX));
    let marker = markers.next()?;
    if markers.next().is_some() {
        return None;
    }

    let payload: Value = serde_json::from_str(marker).ok()?;
    let payload = payload.as_object()?;
    // The marker is a closed shape: an unexpected key means a different
    // protocol than this build understands.
    if payload.len() != 3 {
        return None;
    }
    let phase = ScanWorkerPhase::parse(payload.get("phase").and_then(Value::as_str)?)?;
    let planned = worker_count(payload.get("planned")?)?;
    let started = worker_count(payload.get("started")?)?;
    if started > planned {
        return None;
    }

    Some(ScanWorkerStatus::Dispatch {
        phase,
        planned,
        started,
    })
}

/// Whether `command` invokes the preflight script, rather than merely
/// mentioning its name.
///
/// Upstream uses `/(?:^|[\\/])config_preflight\.py(?=$|["'\s])/u`: the name must
/// start the command or follow a path separator, and must end the command or be
/// followed by a quote or whitespace. `rg config_preflight.py /repository`
/// therefore does not count.
fn runs_preflight_script(command: &str) -> bool {
    command.match_indices(PREFLIGHT_SCRIPT).any(|(start, _)| {
        let preceded =
            start == 0 || matches!(command[..start].chars().next_back(), Some('/') | Some('\\'));
        let end = start + PREFLIGHT_SCRIPT.len();
        let followed = match command[end..].chars().next() {
            None => true,
            Some(character) => character == '"' || character == '\'' || character.is_whitespace(),
        };
        preceded && followed
    })
}

/// A JSON number that is a plausible worker count.
fn worker_count(value: &Value) -> Option<u64> {
    let count = value.as_u64()?;
    (count <= MAX_WORKER_COUNT).then_some(count)
}
