//! Behavior tests for a real `scan` run.
//!
//! The scan is driven end to end through the binary, with a stub `codex` on
//! `PATH` standing in for the agent: it performs the plugin bootstrap, writes
//! the artifacts a finished scan leaves behind, and emits the event stream.
//! Everything else — the isolated runtime, the vendored plugin, the contract
//! validation, the exit-code policy — is the real thing.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;
use tempfile::TempDir;

/// The plugin version the vendored tree reports.
const PLUGIN_VERSION: &str = "0.1.14";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../puncode-security/tests/fixtures")
}

fn write_executable(path: &Path, script: &str) {
    std::fs::write(path, script).expect("write script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// The scan artifacts a completed repository scan produces.
///
/// The bundled example describes a Git-backed scan by a different plugin
/// version, so the fields the contract binds to the request are rewritten to
/// match this test's unversioned repository.
fn scan_artifacts(base: &Path) -> PathBuf {
    let directory = base.join("artifacts");
    std::fs::create_dir_all(&directory).expect("create artifacts");
    let source = fixtures().join("completed-scan");
    for name in ["findings.json", "coverage.json"] {
        std::fs::copy(source.join(name), directory.join(name)).expect("copy artifact");
    }

    let mut manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(source.join("scan-manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    let scan = manifest
        .get_mut("scan")
        .and_then(serde_json::Value::as_object_mut)
        .expect("a scan object");
    scan["producer"]["version"] = json!(PLUGIN_VERSION);
    scan["target"]["kind"] = json!("directory_snapshot");
    scan["target"]
        .as_object_mut()
        .expect("target")
        .remove("revision");
    std::fs::write(
        directory.join("scan-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize"),
    )
    .expect("write manifest");
    directory
}

/// A stub `codex` that bootstraps the plugin and then runs a scan.
///
/// The same executable answers both: the bootstrap installs the plugin into the
/// isolated home and writes the registration, and `exec` writes the artifacts
/// and prints the event stream.
fn stub_codex(base: &Path, artifacts: &Path, events: &str) -> PathBuf {
    let directory = base.join("bin");
    std::fs::create_dir_all(&directory).expect("create bin");
    let executable = directory.join("codex");
    let stream = base.join("events.jsonl");
    std::fs::write(&stream, events).expect("write events");

    write_executable(
        &executable,
        &format!(
            r#"#!/bin/sh
case "$1 $2" in
  "plugin marketplace")
    exit 0 ;;
  "plugin add")
    # Installed from the marketplace the bootstrap published, so the installed
    # tree is the real plugin: the contract is validated against its schemas.
    installed="$CODEX_HOME/plugins/cache/codex-security-sdk/codex-security/{PLUGIN_VERSION}"
    mkdir -p "$installed"
    cp -R "$CODEX_HOME/sdk-marketplace/plugins/codex-security/." "$installed"/
    printf '[marketplaces."codex-security-sdk"]\nsource = "%s"\n\n[plugins."codex-security@codex-security-sdk"]\nenabled = true\n' \
      "$CODEX_HOME/sdk-marketplace" > "$CODEX_HOME/config.toml"
    exit 0 ;;
  "login "*)
    exit 0 ;;
esac
if [ "$1" = "exec" ]; then
  # Any failure below must abort the stub: its standard error is only surfaced
  # when it exits non-zero, so a silent failure would look like a scan that
  # simply produced nothing.
  set -e
  cat > /dev/null
  cp '{artifacts}'/* "$CODEX_SECURITY_SCAN_DIR"/
  printf '# Scan report\n' > "$CODEX_SECURITY_SCAN_DIR/report.md"
  # The workbench checks the manifest names the scan it registered, and the
  # contract checks the manifest's digests match the documents beside it, so
  # the identifier is rewritten and the digests recomputed together.
  # `$PYTHON` rather than a bare name: the scan sanitizes PATH, and this is
  # the interpreter it resolved for the plugin.
  "$PYTHON" - "$CODEX_SECURITY_SCAN_DIR" "$CODEX_SECURITY_SCAN_ID" "$CODEX_SECURITY_TARGET_ID" \
    "$CODEX_SECURITY_TARGET_DISPLAY_NAME" "$CODEX_SECURITY_REPOSITORY" <<'REWRITE'
import hashlib, json, os, subprocess, sys
scan_dir, scan_id, target_id, display_name, repository = sys.argv[1:6]
for name in ("findings.json", "coverage.json"):
    path = f"{{scan_dir}}/{{name}}"
    document = json.load(open(path))
    document["scanId"] = scan_id
    open(path, "w").write(json.dumps(document, indent=2) + "\n")

manifest = json.load(open(f"{{scan_dir}}/scan-manifest.json"))
manifest["scan"]["id"] = scan_id
# The workbench recorded what it thinks the target is, including a snapshot
# digest it computed from the repository; the manifest has to agree with it,
# so it is read back rather than guessed at.
query = subprocess.run(
    [os.environ["PYTHON"], "-I", "-B",
     os.environ["CODEX_SECURITY_PLUGIN_ROOT"] + "/scripts/workbench_db.py",
     "get-scan", "--scan-id", scan_id],
    capture_output=True, text=True,
)
if query.returncode != 0:
    sys.stderr.write("STUB workbench query failed: " + query.stderr + "\n")
    sys.exit(1)
registered = json.loads(query.stdout)["scan"]
# The workbench publishes the target it will insist on, including a snapshot
# digest it computed from the repository, so the manifest is built from that
# rather than from the example's own values.
contract_target = registered["contract"]["target"]
target = {{
    "kind": contract_target["allowedKinds"][0],
    "targetId": contract_target["targetId"],
    "displayName": contract_target["displayName"],
}}
if "requiredSnapshotDigest" in contract_target:
    target["snapshotDigest"] = contract_target["requiredSnapshotDigest"]
if registered.get("targetRevision") not in (None, "unversioned"):
    target["revision"] = registered["targetRevision"]
manifest["scan"]["target"] = target
# The workbench reuses the manifest's own timing when it is already sealed,
# and the contract requires the seal to match the completion.
stamp = registered.get("updatedAt") or manifest["scan"]["completedAt"]
manifest["scan"]["startedAt"] = stamp
manifest["scan"]["completedAt"] = stamp
manifest["scan"]["sealedAt"] = stamp
manifest["scan"]["scope"]["includePaths"] = \
    registered["contract"]["scope"]["requiredIncludePaths"]
manifest["scan"]["scope"]["excludePaths"] = \
    registered["contract"]["scope"]["requiredExcludePaths"]
target_id = target["targetId"]
# Coverage has to describe the same scope the manifest claims; the contract
# compares the two documents against each other.
coverage_path = f"{{scan_dir}}/coverage.json"
coverage = json.load(open(coverage_path))
coverage["includePaths"] = manifest["scan"]["scope"]["includePaths"]
coverage["excludePaths"] = manifest["scan"]["scope"]["excludePaths"]
open(coverage_path, "w").write(json.dumps(coverage, indent=2) + "\n")
# Finding identities are derived from the scan and target, so changing the
# scan identifier means rederiving them exactly as the contract does.
findings_path = f"{{scan_dir}}/findings.json"
findings = json.load(open(findings_path))
for finding in findings["findings"]:
    parts = "\0".join([
        "codex-security/v1",
        target_id,
        finding["ruleId"],
        finding["identity"]["anchor"],
        finding["identity"].get("instance") or "",
    ])
    fingerprint = "codex-security/v1:sha256:" + hashlib.sha256(parts.encode()).hexdigest()
    finding["fingerprints"]["primary"] = fingerprint
    finding["findingId"] = "csf_" + hashlib.sha256(fingerprint.encode()).hexdigest()[:24]
    finding["occurrenceId"] = "occ_" + hashlib.sha256(
        "\0".join([scan_id, fingerprint]).encode()
    ).hexdigest()[:24]
open(findings_path, "w").write(json.dumps(findings, indent=2) + "\n")
for artifact in manifest["scan"]["artifacts"]:
    body = open(f"{{scan_dir}}/{{artifact['path']}}", "rb").read()
    artifact["sha256"] = hashlib.sha256(body).hexdigest()
open(f"{{scan_dir}}/scan-manifest.json", "w").write(json.dumps(manifest, indent=2) + "\n")
REWRITE
  cat '{stream}'
  exit 0
fi
exit 0
"#,
            artifacts = artifacts.display(),
            stream = stream.display(),
        ),
    );
    executable
}

/// The event stream a completed scan produces.
const SCAN_EVENTS: &str = concat!(
    r#"{"type":"thread.started","thread_id":"019faaae-03d8-7940-b941-779a05f67245"}"#,
    "\n",
    r#"{"type":"turn.started"}"#,
    "\n",
    r#"{"type":"item.completed","item":{"id":"i0","type":"agent_message","text":"done"}}"#,
    "\n",
    r#"{"type":"turn.completed","usage":{"input_tokens":1250,"cached_input_tokens":200,"output_tokens":30}}"#,
    "\n",
);

/// A directory that satisfies the scan's constraints on where things may live.
fn test_root() -> PathBuf {
    let root = std::env::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".cache/puncode-security-tests");
    std::fs::create_dir_all(&root).expect("create the test root");
    root
}

/// Everything one scan needs.
struct Harness {
    _root: TempDir,
    repository: PathBuf,
    bin: PathBuf,
    state: PathBuf,
    home: PathBuf,
}

impl Harness {
    fn new(events: &str) -> Self {
        // The scan's own safety rules constrain where this can live: not
        // under the system temporary directory, because a `codex` found there
        // is not trusted; and not inside a Git worktree, because the scan
        // refuses to write its state anywhere inside the tree under review.
        let root = TempDir::new_in(test_root()).expect("root");
        let base = std::fs::canonicalize(root.path()).expect("canonicalize");

        // Not a Git repository, so the scan describes a directory snapshot.
        let repository = base.join("repository");
        std::fs::create_dir_all(repository.join("src")).expect("create repository");
        std::fs::write(repository.join("src/main.rs"), "fn main() {}").expect("write");

        let artifacts = scan_artifacts(&base);
        let codex = stub_codex(&base, &artifacts, events);
        let state = base.join("state");
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("create home");

        Self {
            repository,
            bin: codex.parent().expect("bin").to_path_buf(),
            state,
            home,
            _root: root,
        }
    }

    /// Runs the binary with the stub codex on `PATH`.
    fn run(&self, arguments: &[&str]) -> (Option<i32>, String, String) {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
            .args(arguments)
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("CODEX_SECURITY_STATE_DIR", &self.state)
            .env("OPENAI_API_KEY", "sk-test")
            .output()
            .expect("run the binary");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn scan(&self, extra: &[&str]) -> (Option<i32>, String, String) {
        let repository = self.repository.display().to_string();
        let mut arguments = vec!["scan", repository.as_str()];
        arguments.extend_from_slice(extra);
        self.run(&arguments)
    }
}

// The tests below are the ones a stub agent can establish on its own.
//
// A *successful* scan cannot yet be driven from here: the workbench and the
// contract both bind the manifest to what the workbench registered — the scan
// and target identifiers, the display name, and a snapshot digest the plugin
// computes from the repository — and a stub would have to reimplement that
// bookkeeping to produce a manifest they accept. The library's `tests/scan.rs`
// covers the successful path against the same contract validation, with the
// workbench stubbed; what is missing here is only the CLI's own success path
// (exit codes for findings-at-threshold, and the summary lines).

// A turn that never completed produced no results, whatever is on disk, and
// that has to fail rather than report an empty scan.
#[test]
fn fails_when_the_agent_stops_early() {
    let events = concat!(
        r#"{"type":"thread.started","thread_id":"thread_1"}"#,
        "\n",
        r#"{"type":"turn.started"}"#,
        "\n",
    );
    let harness = Harness::new(events);

    let (code, _, stderr) = harness.scan(&["--json"]);

    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("puncode-security:"), "{stderr}");
}

// Results quote source and reproduction steps, so writing them into the tree
// under review would contaminate the very thing being reviewed.
#[test]
fn refuses_output_inside_the_repository() {
    let harness = Harness::new(SCAN_EVENTS);

    let (code, _, stderr) = harness.scan(&[
        "--output-dir",
        &harness.repository.join("results").display().to_string(),
    ]);

    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("protected scan root") || stderr.contains("outside"),
        "{stderr}"
    );
}

// Progress belongs to a person, so a structured run stays quiet apart from the
// summary a caller may still want.
#[test]
fn reports_no_progress_chatter_for_a_structured_run() {
    let harness = Harness::new(SCAN_EVENTS);

    let (_, _, stderr) = harness.scan(&["--json"]);

    assert!(!stderr.contains("Scanning."), "{stderr}");
    assert!(!stderr.contains("Authentication:"), "{stderr}");
}

// A failing scan names where it left partial output, which is the difference
// between a wasted run and one someone can inspect.
#[test]
fn names_where_partial_output_was_kept() {
    let events = concat!(
        r#"{"type":"thread.started","thread_id":"thread_1"}"#,
        "\n",
        r#"{"type":"turn.started"}"#,
        "\n",
    );
    let harness = Harness::new(events);

    let (_, _, stderr) = harness.scan(&["--json"]);

    assert!(stderr.contains("Partial output was kept at"), "{stderr}");
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------

/// A stub `codex` that records how it was invoked.
fn stub_logout(base: &Path, exit_code: i32, stderr: &str) -> (PathBuf, PathBuf) {
    let directory = base.join("logout-bin");
    std::fs::create_dir_all(&directory).expect("create bin");
    let executable = directory.join("codex");
    let argv = base.join("logout-argv.txt");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{argv}'\nprintf '%s' '{stderr}' >&2\nexit {exit_code}\n",
            argv = argv.display(),
        ),
    );
    (directory, argv)
}

/// Runs the binary with a stub codex for signing out.
fn run_logout(base: &Path, exit_code: i32, stderr: &str) -> (Option<i32>, String, String, PathBuf) {
    let (bin, argv) = stub_logout(base, exit_code, stderr);
    let output = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
        .arg("logout")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("run the binary");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        argv,
    )
}

#[test]
fn signs_out_of_the_stored_credentials() {
    let root = TempDir::new_in(test_root()).expect("root");
    let base = std::fs::canonicalize(root.path()).expect("canonicalize");

    let (code, stdout, stderr, argv) = run_logout(&base, 0, "");

    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("Signed out"), "{stdout}");
    // The credential store is named explicitly, so the sign-in removed is the
    // one a scan would have used.
    let arguments = std::fs::read_to_string(&argv).expect("the stub recorded argv");
    assert!(arguments.contains("logout"), "{arguments}");
    assert!(
        arguments.contains("cli_auth_credentials_store=\"file\""),
        "{arguments}"
    );
}

// A sign-out that did not happen must not look like one that did.
#[test]
fn reports_a_refused_sign_out() {
    let root = TempDir::new_in(test_root()).expect("root");
    let base = std::fs::canonicalize(root.path()).expect("canonicalize");

    let (code, _, stderr, _) = run_logout(&base, 1, "not signed in");

    assert_eq!(code, Some(2));
    assert!(stderr.contains("Could not sign out"), "{stderr}");
    assert!(stderr.contains("not signed in"), "{stderr}");
}

/// A scan stopped by a signal reports the conventional code, not a failure.
///
/// A CI job acts on the difference between "someone stopped this" and "this
/// broke", so the two must not look alike.
#[test]
fn an_interrupted_scan_reports_the_conventional_exit_code() {
    for (signal, expected, described) in [
        (rustix::process::Signal::INT, 130, "canceled by Ctrl-C"),
        (rustix::process::Signal::TERM, 143, "terminated by SIGTERM"),
    ] {
        // The harness satisfies the scan's rules about where it may live; the
        // codex it installs is then replaced with one that never finishes, so
        // the signal is what decides the outcome.
        let harness = Harness::new(SCAN_EVENTS);
        // Its own descriptors go nowhere: an orphaned child holding this
        // test's stderr would keep the pipe open long after the process it
        // belonged to had gone, and reading to end-of-file would wait for it.
        write_executable(
            &harness.bin.join("codex"),
            "#!/bin/sh\nexec sleep 5 </dev/null 2>/dev/null\n",
        );

        let path = format!(
            "{}:{}",
            harness.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_puncode-security"))
            .args(["scan", &harness.repository.to_string_lossy(), "--json"])
            .env("PATH", path)
            .env("HOME", &harness.home)
            .env("CODEX_SECURITY_STATE_DIR", &harness.state)
            .env("OPENAI_API_KEY", "sk-test")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("starts");

        // Long enough for the handler to be installed before signalling.
        std::thread::sleep(std::time::Duration::from_millis(2_000));
        let process = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("a pid"))
            .expect("a live pid");
        rustix::process::kill_process(process, signal).expect("signals");

        // Read as lines arrive rather than to end-of-file. The stub leaves an
        // orphan holding this pipe, so end-of-file may be a long way off, and
        // waiting for it would make a fast test slow for no added confidence.
        let collected = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let sink = std::sync::Arc::clone(&collected);
        let stderr = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                sink.lock().expect("the collected output").push_str(&line);
                sink.lock().expect("the collected output").push('\n');
            }
        });

        let status = child.wait().expect("finishes");
        // The messages are written before the exit, so they have arrived.
        let complaint = collected.lock().expect("the collected output").clone();
        assert_eq!(
            status.code(),
            Some(expected),
            "signal {signal:?}:\n{complaint}"
        );
        assert!(complaint.contains(described), "{complaint}");
        // Whether or not output survived, the person is told which it was.
        assert!(
            complaint.contains("Partial output was kept at")
                || complaint.contains("No partial output was kept"),
            "{complaint}"
        );
    }
}
