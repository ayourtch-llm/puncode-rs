//! Preparing the environment a scan runs in.
//!
//! Ported from `src/runtime.ts`, which is being brought over in pieces:
//! output-directory safety first, then plugin bootstrap, then the codex and
//! Python resolution helpers.

mod archive;
mod bootstrap;
mod isolated;
mod marketplace;
mod output;
mod plugin;
mod python;
mod workbench;

pub use output::LocationCheck;

pub use output::{PrepareOutputOptions, prepare_output_dir, validate_output_dir};

pub(crate) use output::{plan_output_archive, require_model_safe_output_dir};

pub use bootstrap::{CodexRunner, PluginInstall, ProcessCodexRunner, bootstrap_plugin};

pub use isolated::{
    CodexCommand, cleanup_sdk_directory, create_isolated_home, import_ambient_auth,
    resolve_codex_command,
};

pub use workbench::{
    WorkbenchCommandOptions, codex_security_state_directory, prepare_persistent_scan_root,
    run_workbench,
};

pub use python::{
    PluginPythonOptions, is_python_path_candidate, plugin_execution_environment,
    resolve_plugin_python,
};

pub use marketplace::create_marketplace;

pub use plugin::{
    MARKETPLACE_NAME, PLUGIN_NAME, PluginMetadata, bundled_plugin_root, extract_plugin_zip,
    plugin_metadata, resolve_plugin_path, validate_plugin_root,
};
