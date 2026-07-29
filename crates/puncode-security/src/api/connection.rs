//! Making sense of the messages a failing connection produces.
//!
//! Ported from `classifyConnectionFailure`, `reconnectAttempt` and
//! `reconnectDetails` in `src/api.ts`.
//!
//! Codex reports transport trouble as free text on the event stream. There is
//! no structured code to branch on, so the text is classified by pattern — well
//! enough to tell a caller whether a scan is waiting on a rate limit, on
//! credentials, or on the network, and how many reconnection attempts remain.
//! Anything unrecognized stays unclassified rather than being guessed at.

#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

/// What a connection failure appears to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
    RateLimited,
    Unauthorized,
    Forbidden,
    NetworkError,
    Timeout,
    Unknown,
}

impl ConnectionFailure {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }
}

/// Why a scan is reconnecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectReason {
    Network,
    Authentication,
    Authorization,
    RateLimit,
}

impl ReconnectReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::RateLimit => "rate_limit",
        }
    }
}

/// What a caller can be told about a reconnection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScanReconnectDetails {
    pub reason: ReconnectReason,
    /// Only present when the message named a plausible delay.
    pub retry_after_seconds: Option<f64>,
}

static RATE_LIMITED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\brate[_ -]?limit(?:ed|[_ -]exceeded)?\b|\b429\b|\btoo many requests\b")
        .expect("valid pattern")
});

static UNAUTHORIZED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b401\b|\bunauthori[sz]ed\b|\binvalid[_ -](?:api[_ -]?key|authentication|token|credentials?)\b|\b(?:expired|revoked)[_ -](?:api[_ -]?key|token|credentials?)\b|\b(?:api[_ -]?key|token|credentials?)(?: has)? (?:expired|been revoked)\b",
    )
    .expect("valid pattern")
});

static FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b403\b|\bforbidden\b|\bpermission denied\b|\b(?:model|organization|project) access\b|\b(?:access denied|do not have access|not authorized|insufficient permissions)\b|\bmodel[_ -]?not[_ -]?found\b",
    )
    .expect("valid pattern")
});

static NETWORK_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:ENOTFOUND|ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT)\b|\b(?:network|connection|TLS|DNS)\b|\berror sending request\b",
    )
    .expect("valid pattern")
});

static TIMEOUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:timed? out|timeout)\b").expect("valid pattern"));

/// `Reconnecting... 2/5`, with the trailing boundary checked separately
/// because the original pattern uses a lookahead.
static RECONNECTING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Reconnecting(?:\.\.\.|\x{2026})[ \t]+([1-9]\d{0,2})/([1-9]\d{0,2})")
        .expect("valid pattern")
});

static RETRY_DELAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:try again|retry)\s+in\s+(\d{1,6}(?:\.\d{1,3})?)\s*(?:s\b|seconds?\b)")
        .expect("valid pattern")
});

/// The longest retry delay worth reporting; anything beyond it is treated as
/// noise rather than a real hint.
const MAX_RETRY_AFTER_SECONDS: f64 = 3_600.0;

/// Classifies a failure message.
///
/// The order matters: a rate-limit message often also mentions the connection,
/// so the most specific classification is checked first.
#[must_use]
pub fn classify_connection_failure(message: &str) -> ConnectionFailure {
    if RATE_LIMITED.is_match(message) {
        return ConnectionFailure::RateLimited;
    }
    if UNAUTHORIZED.is_match(message) {
        return ConnectionFailure::Unauthorized;
    }
    if FORBIDDEN.is_match(message) {
        return ConnectionFailure::Forbidden;
    }
    if NETWORK_ERROR.is_match(message) {
        return ConnectionFailure::NetworkError;
    }
    if TIMEOUT.is_match(message) {
        return ConnectionFailure::Timeout;
    }
    ConnectionFailure::Unknown
}

/// Reads `Reconnecting... 2/5` as an attempt out of a maximum.
///
/// Returns nothing unless the counts are coherent: an attempt beyond the
/// maximum is not a progress report worth passing on.
#[must_use]
pub fn reconnect_attempt(message: &str) -> Option<(u32, u32)> {
    let captures = RECONNECTING.captures(message)?;
    // The original pattern requires the counts to be followed by a space, a
    // tab, an opening parenthesis, or the end of the message.
    let end = captures.get(0)?.end();
    let boundary = message[end..].chars().next();
    if !matches!(boundary, None | Some(' ' | '\t' | '(')) {
        return None;
    }

    let attempt: u32 = captures.get(1)?.as_str().parse().ok()?;
    let max_attempts: u32 = captures.get(2)?.as_str().parse().ok()?;
    (attempt <= max_attempts).then_some((attempt, max_attempts))
}

/// Describes why a reconnection is happening, when the message says enough.
#[must_use]
pub fn reconnect_details(message: &str) -> Option<ScanReconnectDetails> {
    let reason = match classify_connection_failure(message) {
        ConnectionFailure::RateLimited => ReconnectReason::RateLimit,
        ConnectionFailure::NetworkError => ReconnectReason::Network,
        ConnectionFailure::Unauthorized => ReconnectReason::Authentication,
        ConnectionFailure::Forbidden => ReconnectReason::Authorization,
        // A timeout or an unrecognized message says nothing useful.
        ConnectionFailure::Timeout | ConnectionFailure::Unknown => return None,
    };

    if reason != ReconnectReason::RateLimit {
        return Some(ScanReconnectDetails {
            reason,
            retry_after_seconds: None,
        });
    }

    let retry_after_seconds = RETRY_DELAY
        .captures(message)
        .and_then(|captures| captures.get(1))
        .and_then(|delay| delay.as_str().parse::<f64>().ok())
        .filter(|seconds| {
            seconds.is_finite() && *seconds > 0.0 && *seconds <= MAX_RETRY_AFTER_SECONDS
        });
    Some(ScanReconnectDetails {
        reason,
        retry_after_seconds,
    })
}
