//! End-to-end behavior tests for `PuncodeSecurity::run`.
//!
//! Ported from the scan-pipeline cases in `tests-ts/api.test.ts`.
//!
//! The whole pipeline runs: a stub `codex` writes the scan artifacts and emits
//! the event stream, a stub workbench records the scan, and the real contract
//! validation checks what came back. Nothing here reaches the network, a model,
//! or the user's Codex home.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use puncode_security::api::{
    ClientDependencies, PreparedRuntime, PuncodeSecurity, ScanCancellation, ScanObserver,
    ScanOptions,
};
use puncode_security::codex::ProcessCodexClient;
use puncode_security::config::PuncodeSecurityConfig;
use puncode_security::cost::ScanCost;
use puncode_security::runtime::{CodexCommand, PluginInstall};
use puncode_security::targets::ProcessEnvironment;
use serde_json::json;
use tempfile::TempDir;

/// The plugin version the fake plugin tree reports.
const PLUGIN_VERSION: &str = "0.1.14";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod script");
}

/// A plugin tree with the skill a repository scan names and a workbench script.
fn plugin_tree(base: &Path) -> PathBuf {
    let root = base.join("plugin");
    fs::create_dir_all(root.join(".codex-plugin")).expect("create plugin");
    fs::write(
        root.join(".codex-plugin/plugin.json"),
        json!({ "name": "puncode-security", "version": PLUGIN_VERSION }).to_string(),
    )
    .expect("write plugin manifest");
    for skill in ["security-scan", "deep-security-scan", "security-diff-scan"] {
        let directory = root.join("skills").join(skill);
        fs::create_dir_all(&directory).expect("create skill");
        fs::write(directory.join("SKILL.md"), "# Skill\n").expect("write skill");
    }
    fs::create_dir_all(root.join("scripts")).expect("create scripts");
    fs::write(root.join("scripts/workbench_db.py"), "# stub\n").expect("write workbench");

    // The real schemas, so the contract is validated for real.
    let schemas = root.join("schemas");
    fs::create_dir_all(&schemas).expect("create schemas");
    for name in [
        "scan-manifest.schema.json",
        "findings.schema.json",
        "coverage.schema.json",
    ] {
        fs::copy(fixtures().join("schemas").join(name), schemas.join(name)).expect("copy schema");
    }
    root
}

/// A stub interpreter that is both the plugin Python and the workbench.
///
/// It must answer the interpreter probe before it is trusted to run anything,
/// then stand in for `python -I -B .../workbench_db.py`, so it handles the
/// interpreter flags, the probe script, and the workbench subcommands.
fn stub_workbench(base: &Path) -> (PathBuf, PathBuf) {
    let python = base.join("python");
    let log = base.join("workbench.log");
    write_executable(
        &python,
        &format!(
            r#"#!/bin/sh
# The probe runs `-I -c <script>` and expects the marker on stdout.
if [ "$1" = "-I" ] && [ "$2" = "-c" ]; then
  printf 'puncode-security-python-ok
'
  exit 0
fi
# Otherwise skip the interpreter flags and the script path.
while [ $# -gt 0 ]; do
  case "$1" in
    -I|-B) shift ;;
    *.py) shift; break ;;
    *) break ;;
  esac
done
command="$1"
printf '%s
' "$*" >> '{log}'
scan_dir=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--scan-dir" ]; then scan_dir="$2"; fi
  shift
done
case "$command" in
  register-cli-scan)
    printf '{{"scanId":"scan_1","targetId":"target_1","scanDir":"%s"}}
' "$scan_dir" ;;
  *)
    printf '{{}}
' ;;
esac
"#,
            log = log.display()
        ),
    );
    (python, log)
}

/// The event stream a completed scan produces.
const SCAN_EVENTS: &str = concat!(
    r#"{"type":"thread.started","thread_id":"019faaae-03d8-7940-b941-779a05f67245"}"#,
    "\n",
    r#"{"type":"turn.started"}"#,
    "\n",
    r#"{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"scan complete"}}"#,
    "\n",
    r#"{"type":"turn.completed","usage":{"input_tokens":1250,"cached_input_tokens":200,"output_tokens":30,"reasoning_output_tokens":5}}"#,
);

/// A stub `codex` that writes the scan artifacts and emits `events`.
///
/// Writing the artifacts is what the real agent does, so the contract
/// validation downstream is exercised for real.
fn stub_codex(base: &Path, events: &str, artifacts: Option<&Path>) -> PathBuf {
    let executable = base.join("codex");
    let copy = match artifacts {
        Some(source) => format!(
            "cp '{source}'/* \"$CODEX_SECURITY_SCAN_DIR\"/\n\
             printf '# Scan report\\n' > \"$CODEX_SECURITY_SCAN_DIR/report.md\"\n",
            source = source.display()
        ),
        None => String::new(),
    };
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\ncat > /dev/null\n{copy}cat <<'CODEX_STUB_EOF'\n{events}\nCODEX_STUB_EOF\n"
        ),
    );
    executable
}

/// The scan artifacts a completed repository scan would leave behind.
///
/// The bundled example describes a Git-backed scan of a different plugin
/// version; the fields the contract binds to the request are rewritten so the
/// example matches this test's unversioned repository.
fn scan_artifacts(base: &Path) -> PathBuf {
    let directory = base.join("artifacts");
    fs::create_dir_all(&directory).expect("create artifacts");
    let source = fixtures().join("completed-scan");
    for name in ["findings.json", "coverage.json"] {
        fs::copy(source.join(name), directory.join(name)).expect("copy artifact");
    }

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(source.join("scan-manifest.json")).expect("read"))
            .expect("parse manifest");
    let scan = manifest
        .get_mut("scan")
        .and_then(serde_json::Value::as_object_mut)
        .expect("a scan object");
    scan["producer"]["version"] = json!(PLUGIN_VERSION);
    // The test repository is not version controlled, so the scan describes a
    // directory snapshot rather than a Git revision.
    scan["target"]["kind"] = json!("directory_snapshot");
    scan["target"]
        .as_object_mut()
        .expect("target")
        .remove("revision");
    fs::write(
        directory.join("scan-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    directory
}

/// A runtime pointing at the fake plugin, with credentials already available.
fn prepared_runtime(
    base: &Path,
    plugin_root: &Path,
    environment: &ProcessEnvironment,
) -> PreparedRuntime {
    let codex_home = base.join("runtime/codex-home");
    fs::create_dir_all(&codex_home).expect("create codex home");
    let mut runtime_environment = environment.clone();
    runtime_environment.insert("CODEX_HOME".to_owned(), codex_home.display().to_string());
    PreparedRuntime {
        codex_home,
        bootstrap_workspace: None,
        config_path: None,
        plugin: PluginInstall {
            plugin_root: plugin_root.to_path_buf(),
            marketplace_root: base.join("runtime/marketplace"),
            installed_root: plugin_root.to_path_buf(),
            marketplace_name: "codex-security-sdk".to_owned(),
            name: "puncode-security".to_owned(),
            version: PLUGIN_VERSION.to_owned(),
        },
        environment: runtime_environment,
        credentials_available: true,
        effective_config: None,
    }
}

/// Everything one scan needs, wired to stubs.
struct Harness {
    _root: TempDir,
    repository: PathBuf,
    output: PathBuf,
    workbench_log: PathBuf,
    codex: PathBuf,
    plugin_root: PathBuf,
    environment: ProcessEnvironment,
    base: PathBuf,
    client: PuncodeSecurity,
}

impl Harness {
    fn new(events: &str) -> Self {
        Self::with_artifacts(events, true)
    }

    fn with_artifacts(events: &str, write_artifacts: bool) -> Self {
        let root = TempDir::new().expect("root");
        let base = fs::canonicalize(root.path()).expect("canonicalize");

        // Not a git repository: the scan then describes a directory snapshot.
        let repository = base.join("repository");
        fs::create_dir_all(repository.join("src")).expect("create repository");
        fs::write(repository.join("src/main.rs"), "fn main() {}").expect("write source");

        let plugin_root = plugin_tree(&base);
        let artifacts = write_artifacts.then(|| scan_artifacts(&base));
        let codex = stub_codex(&base, events, artifacts.as_deref());
        let (python, workbench_log) = stub_workbench(&base);

        let environment: ProcessEnvironment = [
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("PYTHON".to_owned(), python.display().to_string()),
            (
                "CODEX_SECURITY_STATE_DIR".to_owned(),
                base.join("state").display().to_string(),
            ),
        ]
        .into_iter()
        .collect();

        let mut harness = Self {
            output: base.join("scan"),
            _root: root,
            repository,
            workbench_log,
            codex,
            plugin_root,
            environment,
            base,
            client: PuncodeSecurity::new(PuncodeSecurityConfig::default()),
        };
        harness.rewire();
        harness
    }

    /// Rebuilds the client against the harness's current stubs.
    fn rewire(&mut self) {
        let runtime = prepared_runtime(&self.base, &self.plugin_root, &self.environment);
        let codex_for_client = self.codex.clone();
        let codex_for_command = self.codex.clone();
        let dependencies = ClientDependencies::default()
            .with_environment(self.environment.clone())
            .with_temporary_root(&self.base)
            .with_prepare_runtime(Box::new(move |_, _| Ok(runtime.clone())))
            .with_create_codex(Box::new(move |environment, _| {
                Box::new(
                    ProcessCodexClient::new(&codex_for_client)
                        .with_environment(environment.clone()),
                )
            }))
            .with_resolve_command(Box::new(move |_, _| {
                Ok(CodexCommand {
                    command: codex_for_command.clone(),
                    prefix_args: Vec::new(),
                })
            }));
        self.client =
            PuncodeSecurity::with_dependencies(PuncodeSecurityConfig::default(), dependencies);
    }

    fn options(&self) -> ScanOptions {
        ScanOptions::new().with_output_dir(self.output.display().to_string())
    }

    /// Every workbench command the scan issued.
    fn workbench_commands(&self) -> Vec<String> {
        fs::read_to_string(&self.workbench_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Records everything a scan reported.
#[derive(Default)]
struct Recorder {
    scan_started: bool,
    thread_ids: Vec<String>,
    output_dirs: Vec<PathBuf>,
    costs: Vec<ScanCost>,
    authentications: usize,
}

impl ScanObserver for Recorder {
    fn on_scan_started(&mut self) {
        self.scan_started = true;
    }

    fn on_thread_started(&mut self, thread_id: &str) {
        self.thread_ids.push(thread_id.to_owned());
    }

    fn on_output_dir_ready(&mut self, scan_dir: &Path) {
        self.output_dirs.push(scan_dir.to_path_buf());
    }

    fn on_cost(&mut self, cost: &ScanCost) {
        self.costs.push(cost.clone());
    }

    fn on_authentication(&mut self, _: puncode_security::api::ScanAuthentication) {
        self.authentications += 1;
    }
}

#[test]
fn runs_a_scan_and_returns_its_validated_results() {
    let harness = Harness::new(SCAN_EVENTS);
    let mut observer = Recorder::default();

    let result = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut observer,
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    assert_eq!(result.thread_id, "019faaae-03d8-7940-b941-779a05f67245");
    assert_eq!(result.scan_dir, harness.output);
    // The contract was loaded and checked, not merely read.
    assert_eq!(result.manifest.scan.producer.version, PLUGIN_VERSION);
    assert!(observer.scan_started);
    assert_eq!(observer.output_dirs, vec![harness.output.clone()]);
    assert_eq!(observer.authentications, 1);
}

// Registered before the agent starts and completed after, so a scan is always
// accounted for.
#[test]
fn records_the_scan_with_the_workbench() {
    let harness = Harness::new(SCAN_EVENTS);

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    let commands = harness.workbench_commands();
    assert!(
        commands
            .first()
            .is_some_and(|line| line.starts_with("register-cli-scan")),
        "the scan was not registered first: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|line| line.starts_with("complete-scan")),
        "the scan was not completed: {commands:?}"
    );
    assert!(
        !commands.iter().any(|line| line.starts_with("fail-scan")),
        "a successful scan must not be recorded as failed: {commands:?}"
    );
}

// The agent is told where to write and what it is scanning.
#[test]
fn tells_the_agent_where_the_scan_lives() {
    let harness = Harness::new(SCAN_EVENTS);

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    // The stub wrote its artifacts into the directory it was given, which only
    // works if CODEX_SECURITY_SCAN_DIR reached it.
    assert!(harness.output.join("scan-manifest.json").is_file());
    assert!(harness.output.join("report.md").is_file());
}

// A scan whose artifacts never appeared is incomplete, not successful.
#[test]
fn refuses_a_scan_that_produced_no_artifacts() {
    let harness = Harness::with_artifacts(SCAN_EVENTS, false);

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the scan is incomplete");

    assert_eq!(error.class_name(), "IncompleteScanError");
    assert!(
        error.to_string().contains("scan-manifest.json"),
        "the missing artifacts should be named: {error}"
    );
}

// The workbench is told how a scan ended even when the failure is what stopped
// it, so a dead scan does not linger as running.
#[test]
fn records_a_failed_scan_with_the_workbench() {
    let harness = Harness::with_artifacts(SCAN_EVENTS, false);

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the scan fails");

    let commands = harness.workbench_commands();
    assert!(
        commands.iter().any(|line| line.starts_with("fail-scan")),
        "the failure was not recorded: {commands:?}"
    );
}

// A turn that never completed did not produce results, whatever is on disk.
#[test]
fn refuses_a_stream_that_ends_before_the_turn_completes() {
    let events = concat!(
        r#"{"type":"thread.started","thread_id":"thread_1"}"#,
        "\n",
        r#"{"type":"turn.started"}"#,
    );
    let harness = Harness::new(events);

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the turn never completed");

    assert_eq!(error.class_name(), "IncompleteScanError");
}

// An error the agent is not retrying ends the scan.
#[test]
fn stops_on_an_error_the_agent_is_not_retrying() {
    let events = concat!(
        r#"{"type":"thread.started","thread_id":"thread_1"}"#,
        "\n",
        r#"{"type":"error","message":"the model refused the request"}"#,
    );
    let harness = Harness::new(events);

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the stream failed");

    assert!(
        error.to_string().contains("the model refused the request"),
        "unexpected: {error}"
    );
}

// A re-run must reproduce the original scan, which a different plugin cannot.
#[test]
fn refuses_a_rerun_against_a_different_plugin_version() {
    let harness = Harness::new(SCAN_EVENTS);

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options().with_expected_plugin_version("0.1.0"),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the plugin version differs");

    assert!(
        error.to_string().contains("plugin version 0.1.0"),
        "unexpected: {error}"
    );
}

// Knowledge-base documents exist only for the scan that asked for them.
#[test]
fn removes_the_knowledge_base_once_the_scan_ends() {
    let harness = Harness::new(SCAN_EVENTS);
    let documents = harness._root.path().join("documents");
    fs::create_dir_all(&documents).expect("create documents");
    fs::write(documents.join("scope.md"), "Ignore debug endpoints.").expect("write");

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness
                .options()
                .with_knowledge_base_paths([documents.display().to_string()]),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    // Nothing named like a knowledge base survives under the scan's root.
    let leftovers: Vec<_> = fs::read_dir(harness._root.path())
        .expect("read root")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("puncode-security-knowledge-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "the knowledge base was left behind: {leftovers:?}"
    );
}

/// The thread the stub codex reports.
const THREAD_ID: &str = "019faaae-03d8-7940-b941-779a05f67245";

/// Makes the stub codex write a session log the cost tracker will read.
///
/// The real agent writes these as it works, which is how a running scan's
/// spend becomes visible before the turn ends.
fn stub_codex_with_session(base: &Path, artifacts: &Path, usage: serde_json::Value) -> PathBuf {
    let executable = base.join("codex");
    let session = json!({ "type": "session_meta", "payload": { "id": THREAD_ID } }).to_string();
    let tokens = json!({
        "type": "event_msg",
        "payload": { "type": "token_count", "info": { "total_token_usage": usage } }
    })
    .to_string();

    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\ncat > /dev/null\n\
             sessions=\"$CODEX_HOME/sessions/2026/07/29\"\n\
             mkdir -p \"$sessions\"\n\
             printf '%s\\n%s\\n' '{session}' '{tokens}' > \"$sessions/rollout-{THREAD_ID}.jsonl\"\n\
             cp '{artifacts}'/* \"$CODEX_SECURITY_SCAN_DIR\"/\n\
             printf '# Scan report\\n' > \"$CODEX_SECURITY_SCAN_DIR/report.md\"\n\
             cat <<'CODEX_STUB_EOF'\n{SCAN_EVENTS}\nCODEX_STUB_EOF\n",
            artifacts = artifacts.display()
        ),
    );
    executable
}

impl Harness {
    /// A harness whose agent also records what the scan spent.
    fn with_session_usage(usage: serde_json::Value) -> Self {
        let mut harness = Self::with_artifacts(SCAN_EVENTS, true);
        let artifacts = harness.base.join("artifacts");
        harness.codex = stub_codex_with_session(&harness.base, &artifacts, usage);
        harness.rewire();
        harness
    }
}

// The spend is reported as the scan runs, not only once it ends.
#[test]
fn reports_what_the_scan_is_spending() {
    let harness = Harness::with_session_usage(json!({
        "input_tokens": 1_000_000,
        "cached_input_tokens": 0,
        "output_tokens": 100_000,
    }));
    let mut observer = Recorder::default();

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut observer,
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    assert!(
        !observer.costs.is_empty(),
        "the scan reported no cost at all"
    );
    assert!(
        observer.costs.iter().all(|cost| cost.estimated_usd > 0.0),
        "a reported cost was zero: {:?}",
        observer.costs
    );
}

// A budget stops the scan and says so, rather than reporting a generic
// interruption the caller cannot act on.
#[test]
fn stops_a_scan_that_passes_its_cost_limit() {
    let harness = Harness::with_session_usage(json!({
        "input_tokens": 1_000_000,
        "cached_input_tokens": 0,
        "output_tokens": 1_000_000,
    }));

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options().with_max_cost_usd(0.01),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the budget stops the scan");

    assert_eq!(error.class_name(), "ScanCostLimitExceededError");
    assert_eq!(error.max_cost_usd(), Some(0.01));
    assert!(
        error.cost().is_some_and(|cost| cost.estimated_usd > 0.01),
        "the cost that broke the budget should be reported: {error}"
    );
    // A cost limit is a kind of interruption, so partial output is named.
    assert!(error.is_scan_interrupted());
}

// A generous budget does not interfere.
#[test]
fn completes_a_scan_that_stays_within_its_cost_limit() {
    let harness = Harness::with_session_usage(json!({
        "input_tokens": 1_000,
        "cached_input_tokens": 0,
        "output_tokens": 100,
    }));

    harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options().with_max_cost_usd(1_000.0),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect("the scan completes");
}

// A budget that cannot be evaluated is not a budget; reporting success would
// be a guess about money. This needs a turn that reports no usage at all and
// leaves no session log behind, so nothing can price it.
#[test]
fn refuses_a_budgeted_scan_whose_spend_is_unknown() {
    let events = concat!(
        r#"{"type":"thread.started","thread_id":"019faaae-03d8-7940-b941-779a05f67245"}"#,
        "\n",
        r#"{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"done"}}"#,
        "\n",
        r#"{"type":"turn.completed","usage":null}"#,
    );
    let harness = Harness::new(events);

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options().with_max_cost_usd(10.0),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect_err("the spend is unknown");

    assert!(
        error.to_string().contains("Cannot evaluate the cost limit"),
        "unexpected: {error}"
    );
}

// A turn that did report usage can be priced, so the budget applies normally.
#[test]
fn evaluates_a_budget_from_the_turns_reported_usage() {
    let harness = Harness::new(SCAN_EVENTS);

    let result = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options().with_max_cost_usd(1_000.0),
            &mut Recorder::default(),
            &ScanCancellation::new(),
        )
        .expect("the scan completes");

    assert!(
        result.cost.is_some_and(|cost| cost.estimated_usd > 0.0),
        "the scan should have been priced from the turn usage"
    );
}

// A scan cancelled while it runs reports the interruption and names where the
// partial output was left.
#[test]
fn stops_a_scan_cancelled_while_it_runs() {
    let harness = Harness::new(SCAN_EVENTS);
    let cancellation = ScanCancellation::new();

    // Cancelled from the observer, which runs inside the event loop.
    struct CancelOnFirstEvent<'a>(&'a ScanCancellation);
    impl ScanObserver for CancelOnFirstEvent<'_> {
        fn on_thread_started(&mut self, _: &str) {
            self.0.cancel();
        }
    }

    let error = harness
        .client
        .run(
            &harness.repository.display().to_string(),
            &harness.options(),
            &mut CancelOnFirstEvent(&cancellation),
            &cancellation,
        )
        .expect_err("the scan was cancelled");

    assert!(error.is_scan_interrupted(), "unexpected: {error}");
    assert_eq!(error.scan_dir(), Some(harness.output.as_path()));
}
