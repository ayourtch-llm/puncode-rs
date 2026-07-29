//! The Codex Security client.
//!
//! Ported from `src/api.ts`. Being brought over in pieces: the connection
//! classification first, then the prompt and configuration projections, then
//! the scan orchestration itself.

mod client;
mod collect;
mod config_projection;
mod connection;
mod environment;
mod events;
mod prompt;
mod runtime_prep;
mod scan;

pub use client::{
    ClientDependencies, CreateCodexClient, PrepareRuntimeFn, PuncodeSecurity,
    PuncodeSecurityMetadata, ResolveCodexCommand, ScanOptions, ScanPreflight,
};

pub use collect::collect_result;

pub use runtime_prep::{PreparedRuntime, RuntimePreparation, prepare_runtime};

pub use config_projection::{scan_preflight_codex_config, scan_runtime_codex_config};

pub use prompt::{
    ScanRecipeOptions, require_output_outside_repository, scan_prompt, scan_recipe, skill_name_for,
    target_instruction, validate_scan_cost_limit,
};

pub use events::{
    IgnoreScanEvents, ScanCancellation, ScanEventOptions, ScanObserver, run_scan_events,
};

pub use environment::{
    ApiKeySource, ScanAuthentication, environment_api_key, environment_api_key_entry,
    environment_value, initial_credentials_available, scan_authentication, without_codex_home,
};

pub use connection::{
    ConnectionFailure, ReconnectReason, ScanReconnectDetails, classify_connection_failure,
    reconnect_attempt, reconnect_details,
};
