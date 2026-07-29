//! The command line surface.
//!
//! Ported from the command definitions in `src/cli.ts`.
//!
//! The shape is the contract: scripts and CI jobs are written against these
//! flags, so names, defaults and repeatability all match upstream. What clap
//! cannot express — rules that span several flags — is checked separately in
//! [`validate`], so those failures read as argument errors rather than
//! surfacing much later as something confusing.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Scan repositories for security findings with Codex.
#[derive(Debug, Parser)]
#[command(name = "puncode-security", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Serve the read-only surface over the Model Context Protocol.
    ///
    /// Only `info` is offered. Scanning stays on the command line because the
    /// transport cannot cancel a running command, so a scan started through it
    /// could not be stopped.
    #[arg(long)]
    pub mcp: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a Codex Security scan.
    ///
    /// Boxed because `scan` carries far more options than any other command,
    /// and every parsed command would otherwise be as large as this one.
    Scan(Box<ScanArgs>),
    /// Work with saved scans.
    #[command(subcommand)]
    Scans(ScansCommand),
    /// Scan many repositories from a CSV inventory.
    BulkScan(BulkScanArgs),
    /// Export a finished scan in another format.
    Export(ExportArgs),
    /// Validate one or more candidate security findings.
    Validate(ValidateArgs),
    /// Patch one or more security issues.
    Patch(PatchArgs),
    /// Sign in to Codex.
    Login(LoginArgs),
    /// Sign out of Codex.
    Logout,
    /// Report versions and configuration.
    Info(InfoArgs),
    /// Install a Git hook that scans before pushing.
    InstallHook(InstallHookArgs),
    /// Score scans against a corpus of known flaws.
    Bench(BenchArgs),
    /// Compare several scans of the same target.
    Consensus(ConsensusArgs),
}

/// A known incompatibility to work around when talking to an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum EndpointCompat {
    /// Send system-level content as a single field.
    ///
    /// For servers whose chat template permits exactly one system message and
    /// refuse a request carrying more.
    MergeSystem,
}

/// Scoring scans against a corpus of known flaws.
#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Directory holding one scan output directory per fixture.
    #[arg(value_name = "RESULTS")]
    pub results: PathBuf,
    /// The corpus description.
    #[arg(
        long,
        value_name = "FILE",
        default_value = "benchmark/ground-truth.json"
    )]
    pub ground_truth: PathBuf,
    /// Root the corpus paths are relative to.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub corpus_root: PathBuf,
    /// Fail unless at least this share of planted flaws was found (0.0-1.0).
    ///
    /// A corpus that plants nothing cannot satisfy this, and is refused rather
    /// than passed: a floor that succeeds without measuring anything reports as
    /// a guard while guarding nothing.
    #[arg(long, value_name = "RATE")]
    pub min_detection: Option<f64>,
    /// Fail if more than this many findings matched nothing planted.
    #[arg(long, value_name = "N")]
    pub max_false_positives: Option<usize>,
    #[command(flatten)]
    pub output: OutputOptions,
}

/// Comparing several scans of one target.
#[derive(Debug, Args)]
pub struct ConsensusArgs {
    /// Scan directories to compare; at least two.
    #[arg(value_name = "SCAN_DIR", num_args = 2..)]
    pub directories: Vec<PathBuf>,
    /// Show only findings at least this many runs reported.
    ///
    /// Off by default. A finding seen once may be the one that was looked at
    /// most carefully, so hiding it is a choice to make deliberately.
    #[arg(long, value_name = "N")]
    pub min_agreement: Option<usize>,
    #[command(flatten)]
    pub output: OutputOptions,
}

/// Request shape an OpenAI-compatible endpoint speaks.
///
/// Codex 0.146 removed `chat` and refuses a provider configured with it, so
/// `responses` is the default; `chat` stays available for older Codex builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
#[value(rename_all = "lowercase")]
pub enum WireApi {
    /// The responses API.
    #[default]
    Responses,
    /// Chat completions. Refused by Codex 0.146 and later.
    Chat,
}

impl From<WireApi> for puncode_security::model_endpoint::WireApi {
    fn from(value: WireApi) -> Self {
        match value {
            WireApi::Chat => Self::Chat,
            WireApi::Responses => Self::Responses,
        }
    }
}

/// How thoroughly to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Mode {
    Standard,
    Deep,
}

/// Severities a scan can be told to fail on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// How results are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Format {
    Text,
    Json,
    Jsonl,
}

impl Format {
    /// Whether this format is meant for another program to read.
    #[must_use]
    pub fn is_structured(self) -> bool {
        matches!(self, Self::Json | Self::Jsonl)
    }
}

/// What an export is written as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Sarif,
}

/// Options shared by every command that can report machine-readable output.
#[derive(Debug, Args, Clone, Default)]
pub struct OutputOptions {
    /// Write results as JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// How results are written.
    #[arg(long, global = true, value_enum)]
    pub format: Option<Format>,
}

impl OutputOptions {
    /// The format that was asked for, however it was asked for.
    #[must_use]
    pub fn resolved(&self) -> Format {
        match (self.json, self.format) {
            (_, Some(format)) => format,
            (true, None) => Format::Json,
            (false, None) => Format::Text,
        }
    }
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Repository root to scan (default: current directory).
    pub repository: Option<PathBuf>,
    /// Scan only PATH; repeat for multiple paths.
    #[arg(long = "path", value_name = "PATH")]
    pub paths: Vec<String>,
    /// Read security docs; repeat for multiple paths.
    #[arg(long = "knowledge-base", value_name = "PATH")]
    pub knowledge_base: Vec<String>,
    /// Scan Git changes from BASE to --head.
    #[arg(long, value_name = "BASE")]
    pub diff: Option<String>,
    /// Scan staged and unstaged changes.
    #[arg(long)]
    pub working_tree: bool,
    /// Git head ref for --diff.
    #[arg(long, value_name = "REF")]
    pub head: Option<String>,
    /// Git base ref for --working-tree.
    #[arg(long, value_name = "REF")]
    pub base: Option<String>,
    /// Scan mode.
    #[arg(long, value_enum, default_value = "standard")]
    pub mode: Mode,
    /// Model to use for the scan.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,
    /// Write scan artifacts to DIR.
    #[arg(long, value_name = "DIR")]
    pub output_dir: Option<String>,
    /// Archive existing results before scanning.
    #[arg(long)]
    pub archive_existing: bool,
    /// Use a Codex Security plugin directory or ZIP.
    #[arg(long, value_name = "PATH")]
    pub plugin_path: Option<PathBuf>,
    /// Python interpreter for the bundled plugin runtime.
    #[arg(long, value_name = "PATH")]
    pub python: Option<String>,
    /// Override isolated Codex config with KEY=VALUE; repeat as needed.
    #[arg(long = "codex", value_name = "KEY=VALUE")]
    pub codex: Vec<String>,
    /// Run the model against an OpenAI-compatible endpoint at URL.
    ///
    /// For a self-hosted or local model server. Pair with `--model` to name the
    /// model the endpoint serves.
    #[arg(long, value_name = "URL", env = "CODEX_SECURITY_BASE_URL")]
    pub base_url: Option<String>,
    /// Request shape the endpoint speaks.
    #[arg(long, value_enum, default_value = "responses", requires = "base_url")]
    pub wire_api: WireApi,
    /// Work around a known endpoint incompatibility; repeat as needed.
    ///
    /// Requests are adapted on their way to the endpoint by a forwarder that
    /// runs on this machine and listens only on the loopback interface.
    #[arg(
        long = "endpoint-compat",
        value_enum,
        value_name = "ADAPTATION",
        requires = "base_url"
    )]
    pub endpoint_compat: Vec<EndpointCompat>,
    /// Record endpoint traffic to FILE for diagnosis.
    ///
    /// Writes the prompts, the model's answers, and the source excerpts they
    /// carry. The file is created readable only by you, and may not be placed
    /// inside the repository being scanned.
    #[arg(long, value_name = "FILE", requires = "base_url")]
    pub capture_traffic: Option<PathBuf>,
    /// Keep at most BYTES of each captured body (0 for no limit).
    ///
    /// Defaults to 1 MiB. A larger project may need considerably more; a body
    /// that is cut short is always recorded as such.
    #[arg(long, value_name = "BYTES", requires = "capture_traffic")]
    pub capture_max_bytes: Option<usize>,
    /// Environment variable holding the endpoint's API key.
    #[arg(
        long,
        value_name = "NAME",
        default_value = "OPENAI_API_KEY",
        requires = "base_url"
    )]
    pub api_key_env: String,
    /// Run the agent's commands with no sandbox. DANGEROUS.
    ///
    /// A scan runs shell commands chosen by the model over a repository you do
    /// not necessarily trust, and the sandbox is what keeps that to the
    /// workspace. Without it, those commands have your access to this machine.
    ///
    /// Only for a host already confined by something else — a container or a
    /// throwaway VM. Prefer running where the Codex sandbox works: a container
    /// configured to permit bubblewrap, or a dedicated one per scan.
    #[arg(long, visible_alias = "yolo")]
    pub dangerously_disable_sandbox: bool,
    /// Exit 1 for findings at or above LEVEL.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub fail_on_severity: Option<Severity>,
    /// Stop the scan once the estimated spend passes USD.
    ///
    /// Negative values are accepted here so the refusal explains what is wrong
    /// with them, rather than clap reporting an unknown flag.
    #[arg(long, value_name = "USD", allow_negative_numbers = true)]
    pub max_cost: Option<f64>,
    /// Report what would run without scanning.
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub output: OutputOptions,
    /// The scan this one repeats, when it was rebuilt from a saved recipe.
    ///
    /// Not a flag: it is set by `scans rerun`, never typed.
    #[arg(skip)]
    pub parent_scan_id: Option<String>,
    /// The plugin version the original scan used, when repeating one.
    ///
    /// Not a flag: a rerun against a different plugin would not reproduce the
    /// scan it claims to repeat.
    #[arg(skip)]
    pub expected_plugin_version: Option<String>,
    /// The configuration a saved recipe recorded.
    ///
    /// Not a flag: a rerun uses the model and settings the original scan ran
    /// under, or it is not repeating that scan.
    #[arg(skip)]
    pub saved_overrides: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ScanArgs {
    /// The cost ceiling progress should mention, if one was set.
    #[must_use]
    pub fn max_cost_usd_for_progress(&self) -> Option<f64> {
        self.max_cost
    }
}

#[derive(Debug, Subcommand)]
pub enum ScansCommand {
    /// List saved scans.
    List(ScansListArgs),
    /// Show one saved scan.
    Show(ScansShowArgs),
    /// Run a saved scan's recipe again.
    Rerun(ScansRerunArgs),
    /// Match findings across two saved scans.
    Match(ScansMatchArgs),
    /// Compare two saved scans.
    Compare(ScansCompareArgs),
}

#[derive(Debug, Args)]
pub struct ScansListArgs {
    /// Repository to inspect (default: current directory).
    pub repository: Option<PathBuf>,
    /// Include scans whose output is under ROOT.
    #[arg(long, value_name = "ROOT")]
    pub scan_root: Option<PathBuf>,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ScansShowArgs {
    /// Saved scan identifier or unique prefix.
    pub scan_id: String,
    /// Show findings linked across previous scans.
    #[arg(long)]
    pub show_linked_findings: bool,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ScansRerunArgs {
    /// Saved scan identifier.
    pub scan_id: String,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ScansMatchArgs {
    /// Earlier saved scan identifier.
    pub before_id: Option<String>,
    /// Later saved scan identifier.
    pub after_id: Option<String>,
    /// Match all completed scans of the current repository.
    #[arg(long)]
    pub all: bool,
    /// Recompute an existing semantic finding comparison.
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ScansCompareArgs {
    /// Earlier saved scan identifier.
    pub before_id: String,
    /// Later saved scan identifier.
    pub after_id: String,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct BulkScanArgs {
    /// CSV inventory of repositories to scan.
    pub input: Option<PathBuf>,
    /// Write scan results to DIR.
    #[arg(long, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,
    /// How many repositories to scan at once.
    #[arg(long, default_value_t = 4, value_name = "N")]
    pub workers: usize,
    /// Scan mode.
    #[arg(long, value_enum, default_value = "standard")]
    pub mode: Mode,
    /// Model to use for the scans.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,
    /// How many times to try a repository before giving up.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub max_attempts: u32,
    /// Use a Codex Security plugin directory or ZIP.
    #[arg(long, value_name = "PATH")]
    pub plugin_path: Option<PathBuf>,
    /// Python interpreter for the bundled plugin runtime.
    #[arg(long, value_name = "PATH")]
    pub python: Option<String>,
    /// Override isolated Codex config with KEY=VALUE; repeat as needed.
    #[arg(long = "codex", value_name = "KEY=VALUE")]
    pub codex: Vec<String>,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Completed Codex Security scan directory.
    pub scan_dir: PathBuf,
    /// Export format (default: sarif).
    #[arg(long, value_enum, default_value = "sarif")]
    pub export_format: ExportFormat,
    /// Write the selected format to FILE or stdout with `-`.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
    /// Repository checkout used for SARIF source-line fingerprints.
    #[arg(long, value_name = "ROOT")]
    pub source_root: Option<PathBuf>,
    /// Python interpreter for the bundled plugin runtime.
    #[arg(long, value_name = "PATH")]
    pub python: Option<String>,
    #[command(flatten)]
    pub output_options: OutputOptions,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Finding text, or a file containing findings.
    #[arg(required = true, value_name = "FINDING")]
    pub findings: Vec<String>,
    /// Override model or model_reasoning_effort with KEY=VALUE.
    #[arg(long = "codex", value_name = "KEY=VALUE")]
    pub codex: Vec<String>,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct PatchArgs {
    /// Issue text, or a file containing issues.
    #[arg(required = true, value_name = "ISSUE")]
    pub issues: Vec<String>,
    /// Override model or model_reasoning_effort with KEY=VALUE.
    #[arg(long = "codex", value_name = "KEY=VALUE")]
    pub codex: Vec<String>,
    #[command(flatten)]
    pub output: OutputOptions,
}

/// What `login` should do beyond signing in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LoginAction {
    /// Report who is signed in.
    Status,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Show login status.
    #[arg(value_enum)]
    pub action: Option<LoginAction>,
    /// Sign in with a device code, for a machine with no browser.
    #[arg(long)]
    pub device_auth: bool,
    /// Sign in with an API key read from standard input.
    #[arg(long)]
    pub with_api_key: bool,
    /// Sign in with an access token read from standard input.
    #[arg(long)]
    pub with_access_token: bool,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct InfoArgs {
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Debug, Args)]
pub struct InstallHookArgs {
    /// Repository to install the hook into (default: current directory).
    pub repository: Option<PathBuf>,
    /// Run the agent's commands with no sandbox. DANGEROUS.
    ///
    /// A scan runs shell commands chosen by the model over a repository you do
    /// not necessarily trust, and the sandbox is what keeps that to the
    /// workspace. Without it, those commands have your access to this machine.
    ///
    /// Only for a host already confined by something else — a container or a
    /// throwaway VM. Prefer running where the Codex sandbox works: a container
    /// configured to permit bubblewrap, or a dedicated one per scan.
    #[arg(long, visible_alias = "yolo")]
    pub dangerously_disable_sandbox: bool,
    /// Exit 1 for findings at or above LEVEL.
    #[arg(long, value_enum, default_value = "high", value_name = "LEVEL")]
    pub fail_on_severity: Severity,
    #[command(flatten)]
    pub output: OutputOptions,
}
