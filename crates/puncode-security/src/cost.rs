//! Scan cost estimation and live cost tracking.
//!
//! Ported from `src/cost.ts`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The largest integer JavaScript represents exactly. Upstream validates token
/// counts and computed costs with `Number.isSafeInteger`, so the same bound
/// applies here.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const SESSION_READ_SIZE: usize = 64 * 1_024;

/// Per-token rates in nanodollars: input, cached input, cache-write input, output.
const MODEL_PRICING_NANODOLLARS: &[(&str, [u64; 4])] = &[
    ("gpt-5.6", [5_000, 500, 6_250, 30_000]),
    ("gpt-5.6-sol", [5_000, 500, 6_250, 30_000]),
    ("gpt-5.6-terra", [2_500, 250, 3_125, 15_000]),
    ("gpt-5.6-luna", [1_000, 100, 1_250, 6_000]),
];

/// An estimated cost for a scan, in US dollars.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCost {
    pub model: String,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_write_input_tokens: u64,
    pub output_tokens: u64,
    pub estimated_usd: f64,
}

/// Normalized token usage for a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanTokenUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_write_input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub total_tokens: u64,
}

/// A point-in-time view of a tracked scan's usage and cost.
///
/// `usage` is deliberately untyped: on the session-log path it holds normalized
/// [`ScanTokenUsage`], but on the fallback path it holds the caller-supplied
/// value verbatim. Upstream surfaces this value opaquely in turn metadata, so
/// the asymmetry is observable and is preserved here.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanCostSnapshot {
    pub usage: Option<Value>,
    pub cost: Option<ScanCost>,
}

/// Observer invoked when a tracked scan's running cost changes.
type CostObserver = Box<dyn FnMut(&ScanCost) + Send>;

#[derive(Debug, Default)]
struct SessionUsage {
    offset: u64,
    remainder: Vec<u8>,
    thread_id: Option<String>,
    parent_thread_id: Option<String>,
    usage: Option<ScanTokenUsage>,
}

/// Tracks the cost of a running scan by tailing Codex session logs.
///
/// Unlike the TypeScript original, this tracker does not poll on its own timer:
/// [`refresh`](Self::refresh) is driven by the caller. That keeps the library
/// runtime-agnostic; observable results are unchanged.
pub struct ScanCostTracker {
    codex_home: PathBuf,
    model: String,
    max_cost_usd: Option<f64>,
    on_cost: Option<CostObserver>,
    sessions: BTreeMap<PathBuf, SessionUsage>,
    thread_id: Option<String>,
    snapshot: ScanCostSnapshot,
    last_cost: Option<f64>,
}

impl ScanCostTracker {
    pub fn new(codex_home: impl Into<PathBuf>, model: impl Into<String>) -> Self {
        Self {
            codex_home: codex_home.into(),
            model: model.into(),
            max_cost_usd: None,
            on_cost: None,
            sessions: BTreeMap::new(),
            thread_id: None,
            snapshot: ScanCostSnapshot::default(),
            last_cost: None,
        }
    }

    /// Sets the cost ceiling this scan is allowed to reach.
    #[must_use]
    pub fn with_max_cost_usd(mut self, max_cost_usd: f64) -> Self {
        self.max_cost_usd = Some(max_cost_usd);
        self
    }

    /// Registers an observer invoked whenever the running cost changes.
    #[must_use]
    pub fn with_cost_observer(mut self, observer: impl FnMut(&ScanCost) + Send + 'static) -> Self {
        self.on_cost = Some(Box::new(observer));
        self
    }

    /// The configured cost ceiling, if any.
    #[must_use]
    pub fn max_cost_usd(&self) -> Option<f64> {
        self.max_cost_usd
    }

    /// Binds the tracker to a scan thread. Later calls are ignored, matching
    /// upstream.
    pub fn start(&mut self, thread_id: impl Into<String>) {
        if self.thread_id.is_none() {
            self.thread_id = Some(thread_id.into());
        }
    }

    /// Re-reads session logs and returns the latest snapshot.
    pub fn refresh(&mut self) -> io::Result<ScanCostSnapshot> {
        self.read_sessions()?;
        Ok(self.snapshot.clone())
    }

    /// Finishes tracking, falling back to `fallback_usage` when the session logs
    /// never yielded usage.
    pub fn stop(&mut self, fallback_usage: Option<Value>) -> io::Result<ScanCostSnapshot> {
        self.refresh()?;
        if self.snapshot.usage.is_some() {
            return Ok(self.snapshot.clone());
        }

        let fallback = fallback_usage.unwrap_or(Value::Null);
        let cost = estimate_scan_cost(Some(&self.model), &fallback);
        self.snapshot = ScanCostSnapshot {
            usage: (!fallback.is_null()).then_some(fallback),
            cost: cost.clone(),
        };
        self.report_cost(cost.as_ref());
        Ok(self.snapshot.clone())
    }

    fn read_sessions(&mut self) -> io::Result<()> {
        let Some(thread_id) = self.thread_id.clone() else {
            return Ok(());
        };

        let mut paths = Vec::new();
        collect_session_files(&self.codex_home.join("sessions"), &mut paths)?;
        for path in paths {
            let session = self.sessions.entry(path.clone()).or_default();
            read_session_usage(&path, session)?;
        }

        // A scan's cost includes the threads it delegates to, transitively.
        let mut included = BTreeSet::from([thread_id]);
        let mut changed = true;
        while changed {
            changed = false;
            for session in self.sessions.values() {
                let (Some(thread), Some(parent)) = (&session.thread_id, &session.parent_thread_id)
                else {
                    continue;
                };
                if included.contains(parent) && !included.contains(thread) {
                    included.insert(thread.clone());
                    changed = true;
                }
            }
        }

        let mut total: Option<ScanTokenUsage> = None;
        for session in self.sessions.values() {
            let (Some(thread), Some(usage)) = (&session.thread_id, &session.usage) else {
                continue;
            };
            if included.contains(thread) {
                total = Some(add_token_usage(total.as_ref(), usage));
            }
        }
        let Some(total) = total else {
            return Ok(());
        };

        let usage = serde_json::to_value(&total).expect("token usage serializes");
        let cost = estimate_scan_cost(Some(&self.model), &usage);
        self.snapshot = ScanCostSnapshot {
            usage: Some(usage),
            cost: cost.clone(),
        };
        self.report_cost(cost.as_ref());
        Ok(())
    }

    fn report_cost(&mut self, cost: Option<&ScanCost>) {
        let Some(cost) = cost else { return };
        if self.last_cost == Some(cost.estimated_usd) {
            return;
        }
        self.last_cost = Some(cost.estimated_usd);
        if let Some(observer) = self.on_cost.as_mut() {
            observer(cost);
        }
    }
}

/// Collects `*.jsonl` session logs, ignoring a missing directory.
fn collect_session_files(directory: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_session_files(&path, out)?;
        } else if file_type.is_file() && entry.file_name().to_string_lossy().ends_with(".jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

/// Reads any bytes appended since the last pass, parsing whole lines only.
fn read_session_usage(path: &Path, session: &mut SessionUsage) -> io::Result<()> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    let mut buffer = vec![0_u8; SESSION_READ_SIZE];
    loop {
        file.seek(SeekFrom::Start(session.offset))?;
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }
        session.offset += bytes_read as u64;

        let mut contents = std::mem::take(&mut session.remainder);
        contents.extend_from_slice(&buffer[..bytes_read]);

        let mut line_start = 0;
        while let Some(offset) = contents[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let line_end = line_start + offset;
            read_session_event(&contents[line_start..line_end], session);
            line_start = line_end + 1;
        }
        session.remainder = contents[line_start..].to_vec();
    }
}

fn read_session_event(line: &[u8], session: &mut SessionUsage) {
    if line.is_empty() {
        return;
    }
    let Ok(event) = serde_json::from_str::<Value>(&String::from_utf8_lossy(line)) else {
        return;
    };
    let (Some(event), Some(payload)) = (
        event.as_object(),
        event.get("payload").and_then(Value::as_object),
    ) else {
        return;
    };

    match event.get("type").and_then(Value::as_str) {
        Some("session_meta") => {
            if let Some(id) = payload.get("id").and_then(Value::as_str) {
                session.thread_id = Some(id.to_owned());
            }
            let spawned = payload
                .get("source")
                .and_then(Value::as_object)
                .and_then(|source| source.get("subagent"))
                .and_then(Value::as_object)
                .and_then(|subagent| subagent.get("thread_spawn"))
                .and_then(Value::as_object)
                .and_then(|spawn| spawn.get("parent_thread_id"));
            let parent = match payload.get("parent_thread_id") {
                Some(value) if !value.is_null() => Some(value),
                _ => spawned,
            };
            if let Some(parent) = parent.and_then(Value::as_str) {
                session.parent_thread_id = Some(parent.to_owned());
            }
        }
        Some("event_msg") => {
            if payload.get("type").and_then(Value::as_str) != Some("token_count") {
                return;
            }
            let Some(info) = payload.get("info").and_then(Value::as_object) else {
                return;
            };
            let total = info.get("total_token_usage").unwrap_or(&Value::Null);
            if let Some(usage) = token_usage(total) {
                session.usage = Some(usage);
            }
        }
        _ => {}
    }
}

fn add_token_usage(previous: Option<&ScanTokenUsage>, next: &ScanTokenUsage) -> ScanTokenUsage {
    let Some(previous) = previous else {
        return next.clone();
    };
    ScanTokenUsage {
        input_tokens: previous.input_tokens + next.input_tokens,
        cached_input_tokens: previous.cached_input_tokens + next.cached_input_tokens,
        cache_write_input_tokens: previous.cache_write_input_tokens + next.cache_write_input_tokens,
        output_tokens: previous.output_tokens + next.output_tokens,
        reasoning_output_tokens: previous.reasoning_output_tokens + next.reasoning_output_tokens,
        total_tokens: previous.total_tokens + next.total_tokens,
    }
}

/// A JSON number that is a non-negative safe integer, mirroring the upstream
/// `isTokenCount` guard.
fn token_count(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    if let Some(count) = number.as_u64() {
        return (count <= MAX_SAFE_INTEGER).then_some(count);
    }
    // JSON integers written with a fraction (`100.0`) are still safe integers
    // in JavaScript, so accept integral floats within range.
    let count = number.as_f64()?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (count.fract() == 0.0 && count >= 0.0 && count <= MAX_SAFE_INTEGER as f64)
        .then_some(count as u64)
}

fn token_usage(value: &Value) -> Option<ScanTokenUsage> {
    let usage = value.as_object()?;
    // `??` treats an explicit null the same as an absent key.
    let present = |key: &str| usage.get(key).filter(|value| !value.is_null());
    let optional = |key: &str| match present(key) {
        Some(value) => token_count(value),
        None => Some(0),
    };

    let input_tokens = token_count(present("input_tokens")?)?;
    let output_tokens = token_count(present("output_tokens")?)?;
    let cached_input_tokens = optional("cached_input_tokens")?;
    let cache_write_input_tokens =
        match present("cache_write_input_tokens").or_else(|| present("cache_write_tokens")) {
            Some(value) => token_count(value)?,
            None => 0,
        };
    let reasoning_output_tokens = optional("reasoning_output_tokens")?;

    if cached_input_tokens + cache_write_input_tokens > input_tokens
        || reasoning_output_tokens > output_tokens
    {
        return None;
    }

    Some(ScanTokenUsage {
        input_tokens,
        cached_input_tokens,
        cache_write_input_tokens,
        output_tokens,
        reasoning_output_tokens,
        total_tokens: input_tokens + output_tokens,
    })
}

/// Estimates the cost of `usage` under `model`'s published rates.
///
/// Returns `None` when the model is unknown, the usage is unusable, or the
/// computed cost exceeds exact-integer precision.
#[must_use]
pub fn estimate_scan_cost(model: Option<&str>, usage: &Value) -> Option<ScanCost> {
    let model = model?;
    let pricing = MODEL_PRICING_NANODOLLARS
        .iter()
        .find_map(|(name, pricing)| (*name == model).then_some(pricing))?;
    let usage = token_usage(usage)?;

    let [
        input_rate,
        cached_input_rate,
        cache_write_input_rate,
        output_rate,
    ] = *pricing;
    // Uncached input is billed at the full rate; the rest is billed at its own.
    let uncached = usage.input_tokens - usage.cached_input_tokens - usage.cache_write_input_tokens;
    let nanodollars = i128::from(uncached) * i128::from(input_rate)
        + i128::from(usage.cached_input_tokens) * i128::from(cached_input_rate)
        + i128::from(usage.cache_write_input_tokens) * i128::from(cache_write_input_rate)
        + i128::from(usage.output_tokens) * i128::from(output_rate);
    if nanodollars > i128::from(MAX_SAFE_INTEGER) {
        return None;
    }

    #[allow(clippy::cast_precision_loss)]
    Some(ScanCost {
        model: model.to_owned(),
        input_tokens: usage.input_tokens,
        cached_input_tokens: usage.cached_input_tokens,
        cache_write_input_tokens: usage.cache_write_input_tokens,
        output_tokens: usage.output_tokens,
        estimated_usd: nanodollars as f64 / 1_000_000_000.0,
    })
}

/// The number of fraction digits `Intl` is asked to render, at most.
const MAX_FRACTION_DIGITS: usize = 9;
const MIN_FRACTION_DIGITS: usize = 2;

/// Formats a US dollar amount the way `Intl.NumberFormat("en-US")` does with
/// 2 minimum and 9 maximum fraction digits.
///
/// Two subtleties drive this implementation:
///
/// * `Intl` rounds half away from zero, whereas Rust's `{:.9}` rounds half to
///   even. `0.0009765625` is an exact tie at the ninth fraction digit and must
///   render as `$0.000976563`, not `$0.000976562`.
/// * `Intl` rounds the *shortest round-tripping* decimal representation of the
///   double, not its exact value — unlike `Number.prototype.toFixed`, which
///   uses the exact value. `83643225353.8` is exactly `83643225353.800003052…`,
///   yet renders as `$83,643,225,353.80`. Rust's `{}` produces the same
///   shortest representation, so it is the right starting point.
#[must_use]
pub fn format_usd(value: f64) -> String {
    if value.is_nan() {
        return "$NaN".to_owned();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value.is_infinite() {
        return format!("{sign}$\u{221e}");
    }

    let shortest = format!("{}", value.abs());
    let (whole, fraction) = shortest.split_once('.').unwrap_or((shortest.as_str(), ""));
    let mut integer_digits: Vec<u8> = whole.bytes().map(|digit| digit - b'0').collect();
    let mut fraction_digits: Vec<u8> = fraction
        .bytes()
        .take(MAX_FRACTION_DIGITS)
        .map(|digit| digit - b'0')
        .collect();

    // Half-expand: anything at or above half rounds away from zero, and the
    // first dropped digit alone decides that.
    let rounds_up = fraction
        .as_bytes()
        .get(MAX_FRACTION_DIGITS)
        .is_some_and(|digit| *digit >= b'5');
    if rounds_up {
        carry_one(&mut fraction_digits, &mut integer_digits);
    }

    while fraction_digits.len() < MIN_FRACTION_DIGITS {
        fraction_digits.push(0);
    }
    while fraction_digits.len() > MIN_FRACTION_DIGITS && fraction_digits.last() == Some(&0) {
        fraction_digits.pop();
    }

    let mut out = format!("{sign}$");
    for (index, digit) in integer_digits.iter().enumerate() {
        if index > 0 && (integer_digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(char::from(b'0' + digit));
    }
    out.push('.');
    out.extend(fraction_digits.iter().map(|digit| char::from(b'0' + digit)));
    out
}

/// Adds one to the least significant fraction digit, carrying into the integer
/// digits and growing them if the carry runs off the end.
fn carry_one(fraction_digits: &mut [u8], integer_digits: &mut Vec<u8>) {
    for digit in fraction_digits.iter_mut().rev() {
        if *digit < 9 {
            *digit += 1;
            return;
        }
        *digit = 0;
    }
    for digit in integer_digits.iter_mut().rev() {
        if *digit < 9 {
            *digit += 1;
            return;
        }
        *digit = 0;
    }
    integer_digits.insert(0, 1);
}
