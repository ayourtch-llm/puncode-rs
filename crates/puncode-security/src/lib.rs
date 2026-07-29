//! Rust SDK for running Codex Security scans.
//!
//! This crate is a port of the `@openai/codex-security` TypeScript SDK. All
//! behavior lives here; the `puncode-security-cli` binary is a thin presentation
//! layer over this library.

pub mod api;
pub mod auth;
pub mod benchmark;
pub mod bulk_scan_discovery;
pub mod codex;
pub mod config;
pub mod consensus;
pub mod contract;
pub mod corpus_audit;
pub mod cost;
pub mod diagnosis;
pub mod endpoint_shim;
pub mod error;
pub mod knowledge_base;
pub mod manifest_form;
pub mod model_endpoint;
pub mod models;
pub mod multiscan;
pub mod provenance;
pub mod result;
pub mod runtime;
pub mod scan_comparison;
pub mod scan_history_renderer;
pub mod targets;
pub mod trusted_executable;
pub mod version;
pub mod worker_progress;

pub use contract::{
    LoadContractOptions, LoadedContract, ScanExpectation, load_contract, require_scan_file,
};
pub use cost::{ScanCost, ScanCostSnapshot, ScanCostTracker, ScanTokenUsage, estimate_scan_cost};
pub use error::{Error, ErrorKind, ProtectedScanPathKind, Result};
pub use models::{CoverageDocument, Finding, FindingsDocument, ScanManifest, SeverityLevel};
pub use result::{ScanResult, ScanResultOptions, TurnResultMetadata};
pub use version::{BUNDLED_PLUGIN_VERSION, CODEX_EXECUTABLE_VERSION, VERSION};
