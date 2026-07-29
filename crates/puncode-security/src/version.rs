//! Version constants.
//!
//! Ported from `src/version.ts`. Upstream reads `package.json` at runtime and
//! throws if it is missing or malformed; these are compile-time constants, so
//! that failure mode does not exist here.
//!
//! Upstream also exports `CODEX_SDK_VERSION`, the pinned `@openai/codex-sdk`
//! npm version. This port drives the codex executable directly (see
//! [`crate::codex`]) and has no such dependency, so that constant is
//! deliberately absent; [`VERSION`] identifies the SDK.

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the Codex Security plugin this build ships.
///
/// Must match `version` in the bundled plugin's `.codex-plugin/plugin.json`.
pub const BUNDLED_PLUGIN_VERSION: &str = "0.1.14";

/// The `codex` executable version this port targets.
///
/// Upstream vendors a matching binary through the `@openai/codex` npm package.
/// This port resolves `codex` from `PATH` instead, so the constant records the
/// version the protocol was verified against rather than one that is enforced.
pub const CODEX_EXECUTABLE_VERSION: &str = "0.144.6";
