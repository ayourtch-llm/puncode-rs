//! Behavior tests for the multiscan inventory.
//!
//! Ported from `tests-ts/multiscan.test.ts`. The CSV cases are checked against
//! output captured from the upstream parser in `fixtures/csv-parse.json`, since
//! quoting, line endings and blank-line handling are exactly where a
//! hand-written parser drifts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use codex_security::multiscan::{
    MultiscanTask, build_github_credential_args, normalize_repository, parse_csv_rows,
    parse_inventory, redact_error,
};
use codex_security::targets::ScanMode;
use serde::Deserialize;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn directory() -> PathBuf {
    PathBuf::from("/campaign")
}

/// Reads an inventory that is expected to be valid.
fn inventory(source: &str) -> Vec<MultiscanTask> {
    parse_inventory(source, &directory(), ScanMode::Standard).expect("a valid inventory")
}

/// The failure an invalid inventory reports.
fn refuse(source: &str) -> String {
    parse_inventory(source, &directory(), ScanMode::Standard)
        .expect_err("the inventory is refused")
        .to_string()
}

#[test]
fn reads_a_minimal_inventory() {
    let tasks = inventory(&format!(
        "id,repository,revision\npayments,/repos/pay,{SHA}\n"
    ));

    assert_eq!(
        tasks,
        vec![MultiscanTask {
            id: "payments".to_owned(),
            repository: "/repos/pay".to_owned(),
            revision: SHA.to_owned(),
            mode: ScanMode::Standard,
            scope: None,
        }]
    );
}

// Quoting, embedded delimiters, Windows line endings and a byte-order mark all
// appear in inventories people actually write.
#[test]
fn reads_quoted_fields_and_windows_line_endings() {
    let source = format!(
        "\u{feff}\"id\",\"repository\",\"revision\",\"scope\",\"mode\",\"notes\"\r\n\
         \"payments\",\"/repos/comma, quoted\",\"{SHA}\",\"src\",\"deep\",\"contains \"\"quotes\"\"\"\r\n\r\n"
    );

    let tasks = inventory(&source);

    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].repository, "/repos/comma, quoted");
    assert_eq!(tasks[0].mode, ScanMode::Deep);
    assert_eq!(tasks[0].scope.as_deref(), Some("src"));
}

// A row that does not match its header means the file does not say what it
// appears to, so nothing runs.
#[test]
fn refuses_a_row_that_does_not_match_its_header() {
    let short = refuse("id,repository,revision\npayments,/repos/pay\n");
    let long = refuse(&format!(
        "id,repository,revision\npayments,/repos/pay,{SHA},extra\n"
    ));

    assert!(short.contains("must match their header columns"), "{short}");
    assert!(long.contains("must match their header columns"), "{long}");
}

// The rest of the file is being read as one field, so nothing can be trusted.
#[test]
fn refuses_an_unterminated_quote() {
    let error = refuse(&format!(
        "id,repository,revision\npayments,\"/repos/pay,{SHA}\n"
    ));

    assert!(error.contains("could not be parsed"), "{error}");
}

#[test]
fn refuses_duplicate_headers() {
    let error = refuse(&format!(
        "id,repository,revision,id\npayments,/repos/pay,{SHA},again\n"
    ));

    assert!(
        error.contains("requires id, repository, and revision columns"),
        "{error}"
    );
}

#[test]
fn refuses_a_missing_column() {
    let error = refuse("id,repository\npayments,/repos/pay\n");

    assert!(
        error.contains("requires id, repository, and revision columns"),
        "{error}"
    );
}

#[test]
fn refuses_an_inventory_with_no_rows() {
    let error = refuse("id,repository,revision\n");

    assert!(error.contains("at least one repository"), "{error}");
}

// The identifier becomes a directory name under the output root.
#[test]
fn refuses_an_unsafe_task_id() {
    for id in [
        "../escape",
        "with/slash",
        "with\\backslash",
        ".leading-dot",
        "-leading-dash",
        "",
        "with space",
    ] {
        let error = refuse(&format!("id,repository,revision\n{id},/repos/pay,{SHA}\n"));
        assert!(
            error.contains("safe, unique path names")
                || error.contains("must match their header columns"),
            "{id} was accepted: {error}"
        );
    }
}

#[test]
fn refuses_a_duplicate_task_id() {
    let error = refuse(&format!(
        "id,repository,revision\npay,/repos/a,{SHA}\nPAY,/repos/b,{SHA}\n"
    ));

    assert!(error.contains("must be unique"), "{error}");
}

// A branch or tag could move between reading the inventory and cloning, so
// only a full commit identifies what was actually scanned.
#[test]
fn refuses_a_revision_that_is_not_a_full_sha() {
    for revision in [
        "main",
        "0123456",
        "HEAD",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        let error = refuse(&format!(
            "id,repository,revision\npay,/repos/a,{revision}\n"
        ));
        assert!(
            error.contains("full immutable Git SHAs"),
            "{revision} was accepted: {error}"
        );
    }
}

#[test]
fn accepts_both_sha1_and_sha256_revisions() {
    let sha256 = "a".repeat(64);
    let tasks = inventory(&format!(
        "id,repository,revision\npay,/repos/a,{SHA}\nledger,/repos/b,{sha256}\n"
    ));

    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[1].revision, sha256);
}

// The revision is compared and stored in one casing.
#[test]
fn lowercases_the_revision() {
    let tasks = inventory(&format!(
        "id,repository,revision\npay,/repos/a,{}\n",
        SHA.to_uppercase()
    ));

    assert_eq!(tasks[0].revision, SHA);
}

#[test]
fn refuses_an_unknown_mode() {
    let error = refuse(&format!(
        "id,repository,revision,mode\npay,/repos/a,{SHA},thorough\n"
    ));

    assert!(error.contains("standard or deep"), "{error}");
}

#[test]
fn falls_back_to_the_default_mode() {
    let tasks = parse_inventory(
        &format!("id,repository,revision\npay,/repos/a,{SHA}\n"),
        &directory(),
        ScanMode::Deep,
    )
    .expect("a valid inventory");

    assert_eq!(tasks[0].mode, ScanMode::Deep);
}

// A scope that escapes its repository would scan something never named.
#[test]
fn refuses_a_scope_that_leaves_the_repository() {
    for scope in ["/etc", "../outside", "a/../../b", "back\\slash"] {
        let error = refuse(&format!(
            "id,repository,revision,scope\npay,/repos/a,{SHA},{scope}\n"
        ));
        assert!(
            error.contains("stay inside its repository"),
            "{scope} was accepted: {error}"
        );
    }
}

#[test]
fn resolves_a_relative_repository_against_the_inventory_directory() {
    let tasks = inventory(&format!(
        "id,repository,revision\npay,./checkouts/a,{SHA}\n"
    ));

    assert_eq!(tasks[0].repository, "/campaign/checkouts/a");
}

// ---------------------------------------------------------------------------
// normalize_repository
// ---------------------------------------------------------------------------

fn normalized(repository: &str) -> String {
    normalize_repository(repository, &directory()).expect("a valid repository")
}

fn rejected(repository: &str) -> String {
    normalize_repository(repository, &directory())
        .expect_err("the repository is refused")
        .to_string()
}

#[test]
fn keeps_an_ssh_style_reference_as_written() {
    assert_eq!(
        normalized("git@github.com:owner/repo.git"),
        "git@github.com:owner/repo.git"
    );
}

#[test]
fn keeps_a_supported_url() {
    assert_eq!(
        normalized("https://github.com/owner/repo.git"),
        "https://github.com/owner/repo.git"
    );
    assert_eq!(
        normalized("ssh://git@github.com/owner/repo.git"),
        "ssh://git@github.com/owner/repo.git"
    );
}

// A URL carrying a credential would be written into the campaign's records and
// into any error the clone produced.
#[test]
fn refuses_a_url_carrying_credentials() {
    for repository in [
        "https://token@github.com/owner/repo.git",
        "https://user:pass@github.com/owner/repo.git",
        "ssh://git:secret@github.com/owner/repo.git",
    ] {
        let error = rejected(repository);
        assert!(
            error.contains("must not contain embedded credentials"),
            "{repository} was accepted: {error}"
        );
    }
}

#[test]
fn refuses_a_url_with_a_query_or_fragment() {
    for repository in [
        "https://github.com/owner/repo.git?token=abc",
        "https://github.com/owner/repo.git#fragment",
    ] {
        let error = rejected(repository);
        assert!(
            error.contains("must not contain embedded credentials"),
            "{repository} was accepted: {error}"
        );
    }
}

#[test]
fn refuses_an_unsupported_protocol() {
    for repository in [
        "http://github.com/owner/repo.git",
        "file:///etc/passwd",
        "git://github.com/owner/repo.git",
    ] {
        let error = rejected(repository);
        assert!(
            error.contains("protocol is unsupported"),
            "{repository} was accepted: {error}"
        );
    }
}

// A reference with no `://` is a path, not a transport. Git's `ext::` and
// `file::` helpers only take effect when git is handed them as a URL; resolved
// against the inventory directory they become an ordinary absolute path, which
// is what git then treats them as.
#[test]
fn treats_a_transport_helper_without_a_scheme_as_a_path() {
    assert_eq!(
        normalized("ext::sh -c whoami"),
        "/campaign/ext::sh -c whoami"
    );
}

#[test]
fn refuses_an_empty_or_oversized_repository() {
    assert!(rejected("").contains("safe local paths"));
    assert!(rejected(&"a".repeat(4097)).contains("safe local paths"));
    assert!(rejected("with\0null").contains("safe local paths"));
}

// ---------------------------------------------------------------------------
// build_github_credential_args
// ---------------------------------------------------------------------------

// The helper is bound to one origin, and the empty assignment first clears any
// helper the user's configuration already set for it.
#[test]
fn scopes_github_credentials_to_one_origin() {
    let args = build_github_credential_args(Some("github.com")).expect("valid host");

    assert_eq!(
        args,
        vec![
            "-c".to_owned(),
            "credential.https://github.com.helper=".to_owned(),
            "-c".to_owned(),
            "credential.https://github.com.helper=!gh auth git-credential".to_owned(),
        ]
    );
}

#[test]
fn supplies_no_credentials_without_a_host() {
    assert!(
        build_github_credential_args(None)
            .expect("no host")
            .is_empty()
    );
}

// Anything beyond a bare host would widen where the credential is offered.
#[test]
fn refuses_a_host_that_is_more_than_a_host() {
    for host in [
        "github.com/path",
        "user@github.com",
        "github.com?query",
        "github.com#fragment",
        "GitHub.com/",
        "",
    ] {
        assert!(
            build_github_credential_args(Some(host)).is_err(),
            "{host} was accepted"
        );
    }
}

#[test]
fn accepts_an_enterprise_host_with_a_port() {
    let args = build_github_credential_args(Some("github.example.com:8443")).expect("valid host");

    assert_eq!(
        args[1],
        "credential.https://github.example.com:8443.helper="
    );
}

// ---------------------------------------------------------------------------
// redact_error
// ---------------------------------------------------------------------------

// The campaign's records outlive the run, so a failure quoting a token must not
// be written down as it arrived.
#[test]
fn redacts_secrets_from_failures() {
    for (message, expected) in [
        ("api_key: sk-abcdefghijkl", "api_key: [redacted]"),
        ("token=ghp_abcdefghijkl", "token=[redacted]"),
        ("PASSWORD = hunter2", "PASSWORD = [redacted]"),
        (
            "Authorization: Bearer abc.def",
            "Authorization: Bearer [redacted]",
        ),
        ("basic dXNlcjpwYXNz", "basic [redacted]"),
    ] {
        assert_eq!(redact_error(message), expected, "for {message}");
    }
}

#[test]
fn redacts_known_token_shapes_anywhere() {
    for message in [
        "clone failed for https://ghp_abcdefghijklmnop@github.com/o/r",
        "failed with sk-proj-abcdefghijkl",
        "npm_abcdefghijklmnop rejected",
        "github_pat_abcdefghijkl expired",
    ] {
        let redacted = redact_error(message);
        assert!(
            redacted.contains("[redacted]"),
            "nothing was redacted in {message}: {redacted}"
        );
        for secret in [
            "ghp_abcdefghijklmnop",
            "sk-proj-abcdefghijkl",
            "npm_abcdefghijklmnop",
        ] {
            assert!(!redacted.contains(secret), "{secret} survived: {redacted}");
        }
    }
}

#[test]
fn leaves_ordinary_failures_readable() {
    let message = "fatal: repository '/repos/missing' does not exist";

    assert_eq!(redact_error(message), message);
}

// ---------------------------------------------------------------------------
// CSV parsing, against the upstream parser
// ---------------------------------------------------------------------------

/// One captured parse: the source, the rows, and any errors reported.
#[derive(Debug, Deserialize)]
struct CsvCase {
    source: String,
    data: Vec<Vec<String>>,
    errors: Vec<serde_json::Value>,
}

fn csv_cases() -> BTreeMap<String, CsvCase> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csv-parse.json"),
    )
    .expect("read the captured parses");
    serde_json::from_str(&text).expect("parse the captured parses")
}

// Quoting, line endings and blank-line handling are exactly where a
// hand-written parser drifts, so the parser is compared directly against the
// upstream one rather than only through the inventory it feeds.
#[test]
fn splits_rows_the_way_the_upstream_parser_does() {
    let cases = csv_cases();
    assert!(cases.len() >= 15, "the fixture should cover every case");

    for (name, case) in &cases {
        match parse_csv_rows(&case.source) {
            Ok(rows) => {
                assert!(
                    case.errors.is_empty(),
                    "{name}: the upstream parser reported {:?}",
                    case.errors
                );
                assert_eq!(rows, case.data, "{name} parsed differently");
            }
            Err(error) => assert!(
                !case.errors.is_empty(),
                "{name} was refused but the upstream parser accepted it: {error}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Durable campaign state
// ---------------------------------------------------------------------------

use codex_security::multiscan::{
    MultiscanReceipt, ReceiptStatus, acquire_lock, acquire_lock_with, append_receipt,
    ensure_manifest, ensure_output_directory, has_artifacts, read_receipts,
};
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn task(id: &str) -> MultiscanTask {
    MultiscanTask {
        id: id.to_owned(),
        repository: format!("/repos/{id}"),
        revision: SHA.to_owned(),
        mode: ScanMode::Standard,
        scope: None,
    }
}

fn receipt(id: &str, status: ReceiptStatus) -> MultiscanReceipt {
    MultiscanReceipt {
        id: id.to_owned(),
        repository: format!("/repos/{id}"),
        revision: SHA.to_owned(),
        mode: ScanMode::Standard,
        scope: None,
        status,
        attempt: 1,
        output_dir: PathBuf::from(format!("/out/{id}")),
        cost: None,
        error: None,
    }
}

#[test]
fn creates_a_private_output_directory() {
    let root = TempDir::new().expect("root");
    let output = root.path().join("campaign/nested");

    ensure_output_directory(&output).expect("creates the directory");

    let mode = std::fs::metadata(&output)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "the output directory must be private");
}

#[test]
fn accepts_an_output_directory_that_already_exists() {
    let root = TempDir::new().expect("root");

    ensure_output_directory(root.path()).expect("first");
    ensure_output_directory(root.path()).expect("second");
}

// The campaign removes checkouts beneath this directory; a link would point
// that removal somewhere else entirely.
#[test]
fn refuses_an_output_directory_that_is_a_symbolic_link() {
    let root = TempDir::new().expect("root");
    let target = root.path().join("elsewhere");
    std::fs::create_dir(&target).expect("create target");
    let link = root.path().join("output");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let error = ensure_output_directory(&link).expect_err("refused");

    assert!(
        error.to_string().contains("must not be symbolic links"),
        "{error}"
    );
}

// Two supervisors writing one ledger would corrupt it.
#[test]
fn refuses_a_second_supervisor() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let _first = acquire_lock(root.path()).expect("the first claim succeeds");

    let error = acquire_lock(root.path()).expect_err("the second is refused");

    assert!(error.to_string().contains("already running"), "{error}");
}

#[test]
fn releases_its_claim() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");

    let lock = acquire_lock(root.path()).expect("claimed");
    lock.release().expect("released");

    acquire_lock(root.path()).expect("the directory can be claimed again");
}

// A campaign that panicked still gives up its claim.
#[test]
fn releases_its_claim_when_dropped() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");

    drop(acquire_lock(root.path()).expect("claimed"));

    acquire_lock(root.path()).expect("the directory can be claimed again");
}

// A claim left by a process that has since died must not lock the directory
// forever.
#[test]
fn takes_over_a_claim_left_by_a_dead_supervisor() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    // Claimed by process 4242, which is not running.
    std::mem::forget(acquire_lock_with(root.path(), 4242, &|_| false).expect("first claim"));

    let lock =
        acquire_lock_with(root.path(), 99, &|_| false).expect("the stale claim is taken over");

    lock.release().expect("released");
}

#[test]
fn honours_a_claim_whose_owner_is_still_running() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    std::mem::forget(acquire_lock_with(root.path(), 4242, &|_| true).expect("first claim"));

    let error = acquire_lock_with(root.path(), 99, &|pid| pid == 4242)
        .expect_err("the live claim is honoured");

    assert!(error.to_string().contains("already running"), "{error}");
}

// Resuming into a directory built from a different inventory would mix two
// campaigns' results together.
#[test]
fn refuses_a_manifest_that_does_not_match() {
    let root = TempDir::new().expect("root");
    let manifest = root.path().join("manifest.json");
    ensure_manifest(&manifest, &[task("payments")]).expect("first");

    ensure_manifest(&manifest, &[task("payments")]).expect("an identical inventory resumes");
    let error = ensure_manifest(&manifest, &[task("ledger")]).expect_err("refused");

    assert!(
        error.to_string().contains("does not match existing output"),
        "{error}"
    );
}

#[test]
fn keeps_the_manifest_private() {
    let root = TempDir::new().expect("root");
    let manifest = root.path().join("manifest.json");

    ensure_manifest(&manifest, &[task("payments")]).expect("written");

    let mode = std::fs::metadata(&manifest)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn reads_back_the_receipts_it_recorded() {
    let root = TempDir::new().expect("root");
    let ledger = root.path().join("results.jsonl");

    append_receipt(&ledger, &receipt("payments", ReceiptStatus::Completed)).expect("first");
    append_receipt(&ledger, &receipt("ledger", ReceiptStatus::Failed)).expect("second");

    let receipts = read_receipts(&ledger).expect("read");
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts["payments"].status, ReceiptStatus::Completed);
    assert_eq!(receipts["ledger"].status, ReceiptStatus::Failed);
}

#[test]
fn reports_no_receipts_before_a_campaign_has_run() {
    let root = TempDir::new().expect("root");

    let receipts = read_receipts(&root.path().join("missing.jsonl")).expect("read");

    assert!(receipts.is_empty());
}

// A campaign killed mid-write leaves a partial line; a receipt that was never
// finished describes nothing, so it is truncated away.
#[test]
fn repairs_a_ledger_torn_by_a_crash() {
    let root = TempDir::new().expect("root");
    let ledger = root.path().join("results.jsonl");
    append_receipt(&ledger, &receipt("payments", ReceiptStatus::Completed)).expect("first");
    // A half-written receipt, as an interrupted campaign would leave it.
    std::fs::write(
        &ledger,
        format!(
            "{}{{\"id\":\"ledger\",\"repos",
            std::fs::read_to_string(&ledger).expect("read")
        ),
    )
    .expect("tear the ledger");

    let receipts = read_receipts(&ledger).expect("read");

    assert_eq!(receipts.len(), 1, "the torn receipt is discarded");
    assert!(
        std::fs::read_to_string(&ledger)
            .expect("read")
            .ends_with('\n'),
        "the ledger is repaired on disk"
    );
    // The repaired ledger accepts further receipts.
    append_receipt(&ledger, &receipt("ledger", ReceiptStatus::Completed)).expect("append");
    assert_eq!(read_receipts(&ledger).expect("read").len(), 2);
}

// Task identifiers are compared without regard to case, as the inventory does.
#[test]
fn keys_receipts_without_regard_to_case() {
    let root = TempDir::new().expect("root");
    let ledger = root.path().join("results.jsonl");
    append_receipt(&ledger, &receipt("Payments", ReceiptStatus::Completed)).expect("append");

    let receipts = read_receipts(&ledger).expect("read");

    assert!(receipts.contains_key("payments"));
}

#[test]
fn keeps_the_ledger_private() {
    let root = TempDir::new().expect("root");
    let ledger = root.path().join("results.jsonl");

    append_receipt(&ledger, &receipt("payments", ReceiptStatus::Completed)).expect("append");

    let mode = std::fs::metadata(&ledger)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

// Resuming trusts a scan directory only when everything a scan produces is
// there; a partial directory means the work was not finished.
#[test]
fn recognises_a_complete_scan_directory() {
    let root = TempDir::new().expect("root");
    let scan = root.path().join("scan");
    std::fs::create_dir(&scan).expect("create");

    assert!(!has_artifacts(&scan), "an empty directory is not complete");
    for artifact in ["scan-manifest.json", "findings.json", "coverage.json"] {
        std::fs::write(scan.join(artifact), "{}").expect("write");
    }
    assert!(!has_artifacts(&scan), "the report is still missing");

    std::fs::write(scan.join("report.md"), "# Report\n").expect("write");
    assert!(has_artifacts(&scan));
}

#[test]
fn reports_no_artifacts_for_a_missing_directory() {
    let root = TempDir::new().expect("root");

    assert!(!has_artifacts(&root.path().join("missing")));
}

// ---------------------------------------------------------------------------
// Checking out a pinned revision
// ---------------------------------------------------------------------------

use codex_security::multiscan::{GitRunner, checkout_environment, checkout_revision};
use codex_security::targets::ProcessEnvironment;
use std::cell::RefCell;

/// A git that records what it was asked to do and answers `head` for HEAD.
struct FakeGit {
    calls: RefCell<Vec<Vec<String>>>,
    environments: RefCell<Vec<ProcessEnvironment>>,
    head: String,
    fail_on: Option<String>,
}

impl FakeGit {
    fn new(head: &str) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            environments: RefCell::new(Vec::new()),
            head: head.to_owned(),
            fail_on: None,
        }
    }

    /// The subcommand of each invocation, in order.
    fn subcommands(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter_map(|call| {
                let index = call.iter().position(|value| value == "-C")?;
                call.get(index + 2).cloned()
            })
            .collect()
    }

    fn call_containing(&self, needle: &str) -> Option<Vec<String>> {
        self.calls
            .borrow()
            .iter()
            .find(|call| call.iter().any(|value| value == needle))
            .cloned()
    }
}

impl GitRunner for FakeGit {
    fn run(
        &self,
        arguments: &[String],
        environment: &ProcessEnvironment,
    ) -> codex_security::Result<String> {
        self.calls.borrow_mut().push(arguments.to_vec());
        self.environments.borrow_mut().push(environment.clone());
        if let Some(fail_on) = &self.fail_on
            && arguments.iter().any(|value| value == fail_on)
        {
            return Err(codex_security::Error::codex_security("git failed"));
        }
        if arguments.iter().any(|value| value == "rev-parse") {
            return Ok(self.head.clone());
        }
        Ok(String::new())
    }
}

fn checkout(git: &FakeGit, host: Option<&str>) -> codex_security::Result<()> {
    let environment: ProcessEnvironment = [("PATH".to_owned(), "/usr/bin".to_owned())]
        .into_iter()
        .collect();
    checkout_revision(
        &task("payments"),
        Path::new("/checkout"),
        host,
        &environment,
        git,
    )
}

#[test]
fn materialises_only_the_pinned_commit() {
    let git = FakeGit::new(SHA);

    checkout(&git, None).expect("the checkout succeeds");

    assert_eq!(
        git.subcommands(),
        ["init", "fetch", "checkout", "rev-parse"]
    );
    let fetch = git.call_containing("fetch").expect("a fetch ran");
    assert!(fetch.contains(&"--depth=1".to_owned()), "{fetch:?}");
    assert!(fetch.contains(&"--no-tags".to_owned()), "{fetch:?}");
    // `--` keeps a repository named like an option from being read as one.
    let separator = fetch.iter().position(|value| value == "--").expect("--");
    assert_eq!(fetch[separator + 1], "/repos/payments");
    assert_eq!(fetch[separator + 2], SHA);
}

// A repository can ship hooks, and git would otherwise run them during the
// checkout — code from the very repository under review, before anyone has
// looked at it.
#[test]
fn disables_repository_hooks_before_fetching() {
    let git = FakeGit::new(SHA);

    checkout(&git, None).expect("the checkout succeeds");

    for call in git.calls.borrow().iter() {
        let hooks = call
            .windows(2)
            .find(|pair| pair[0] == "-c" && pair[1].starts_with("core.hooksPath"));
        assert_eq!(
            hooks.map(|pair| pair[1].clone()),
            Some("core.hooksPath=/dev/null".to_owned()),
            "hooks were not disabled for {call:?}"
        );
    }
}

// A server that answered with a different commit would otherwise be scanned as
// though it were the pinned revision.
#[test]
fn refuses_a_checkout_that_is_not_the_pinned_revision() {
    let git = FakeGit::new("f".repeat(40).as_str());

    let error = checkout(&git, None).expect_err("the revision differs");

    assert!(
        error.to_string().contains("did not match the pinned SHA"),
        "{error}"
    );
}

#[test]
fn accepts_a_head_reported_in_upper_case() {
    let git = FakeGit::new(&SHA.to_uppercase());

    checkout(&git, None).expect("the checkout succeeds");
}

#[test]
fn scopes_credentials_to_the_requested_host() {
    let git = FakeGit::new(SHA);

    checkout(&git, Some("github.com")).expect("the checkout succeeds");

    let init = git.call_containing("init").expect("an init ran");
    assert!(
        init.iter()
            .any(|value| value == "credential.https://github.com.helper=!gh auth git-credential"),
        "{init:?}"
    );
}

#[test]
fn passes_no_credential_arguments_without_a_host() {
    let git = FakeGit::new(SHA);

    checkout(&git, None).expect("the checkout succeeds");

    for call in git.calls.borrow().iter() {
        assert!(
            !call.iter().any(|value| value.contains("credential.")),
            "credentials leaked into {call:?}"
        );
    }
}

#[test]
fn stops_at_the_first_failing_step() {
    let mut git = FakeGit::new(SHA);
    git.fail_on = Some("fetch".to_owned());

    checkout(&git, None).expect_err("the fetch fails");

    assert_eq!(
        git.subcommands(),
        ["init", "fetch"],
        "nothing should run after a failed fetch"
    );
}

// Inherited git variables would point the checkout somewhere other than its
// own directory.
#[test]
fn removes_git_variables_that_redirect_the_checkout() {
    let source: ProcessEnvironment = [
        ("GIT_DIR", "/elsewhere/.git"),
        ("git_work_tree", "/elsewhere"),
        ("GIT_INDEX_FILE", "/tmp/index"),
        ("GIT_OBJECT_DIRECTORY", "/tmp/objects"),
        ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/tmp/alt"),
        ("PATH", "/usr/bin"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect();

    let environment = checkout_environment(&source);

    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        assert!(
            !environment.keys().any(|key| key.eq_ignore_ascii_case(name)),
            "{name} survived"
        );
    }
    assert_eq!(environment["PATH"], "/usr/bin");
}

// A private repository should fail rather than hang waiting for a password,
// and LFS smudge filters are code the repository chose to run.
#[test]
fn disables_prompting_and_lfs_smudging() {
    let environment = checkout_environment(&ProcessEnvironment::new());

    assert_eq!(environment["GIT_TERMINAL_PROMPT"], "0");
    assert_eq!(environment["GIT_LFS_SKIP_SMUDGE"], "1");
}

#[test]
fn runs_every_step_in_the_checkout_directory() {
    let git = FakeGit::new(SHA);

    checkout(&git, None).expect("the checkout succeeds");

    for call in git.calls.borrow().iter() {
        let index = call.iter().position(|value| value == "-C").expect("-C");
        assert_eq!(call[index + 1], "/checkout", "{call:?}");
    }
}

// The fake git proves the sequence is what was intended; this proves the
// sequence actually works, against a real git and a real repository.
#[test]
fn checks_out_a_pinned_commit_from_a_real_repository() {
    use codex_security::multiscan::ProcessGitRunner;

    let root = TempDir::new().expect("root");
    let source = root.path().join("source");
    std::fs::create_dir_all(source.join("src")).expect("create source");
    std::fs::write(source.join("src/app.rs"), "fn main() {}").expect("write");
    let revision = commit_all(&source);

    let checkout = root.path().join("checkout");
    std::fs::create_dir(&checkout).expect("create checkout");
    let pinned = MultiscanTask {
        id: "payments".to_owned(),
        repository: source.display().to_string(),
        revision: revision.clone(),
        mode: ScanMode::Standard,
        scope: None,
    };
    let environment: ProcessEnvironment = std::env::vars().collect();

    checkout_revision(
        &pinned,
        &checkout,
        None,
        &environment,
        &ProcessGitRunner::new(root.path()),
    )
    .expect("the checkout succeeds");

    assert_eq!(
        std::fs::read_to_string(checkout.join("src/app.rs")).expect("the tree was materialised"),
        "fn main() {}"
    );
}

// The verification is what makes the pin meaningful, so it is checked against
// real git rather than only against the fake.
#[test]
fn refuses_a_real_checkout_that_is_not_the_pinned_revision() {
    use codex_security::multiscan::ProcessGitRunner;

    let root = TempDir::new().expect("root");
    let source = root.path().join("source");
    std::fs::create_dir_all(&source).expect("create source");
    std::fs::write(source.join("a.txt"), "one").expect("write");
    commit_all(&source);

    let checkout = root.path().join("checkout");
    std::fs::create_dir(&checkout).expect("create checkout");
    let pinned = MultiscanTask {
        id: "payments".to_owned(),
        repository: source.display().to_string(),
        // A well-formed SHA that this repository does not contain.
        revision: "b".repeat(40),
        mode: ScanMode::Standard,
        scope: None,
    };
    let environment: ProcessEnvironment = std::env::vars().collect();

    let error = checkout_revision(
        &pinned,
        &checkout,
        None,
        &environment,
        &ProcessGitRunner::new(root.path()),
    )
    .expect_err("the revision is not there");

    // The fetch fails outright, which is the same refusal by a shorter route.
    assert!(
        error.to_string().contains("git failed")
            || error.to_string().contains("did not match the pinned SHA"),
        "{error}"
    );
}

/// Commits everything in `repository`, returning the commit SHA.
fn commit_all(repository: &Path) -> String {
    let git = |arguments: &[&str]| -> std::process::Output {
        std::process::Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Scan")
            .env("GIT_AUTHOR_EMAIL", "scan@example.com")
            .env("GIT_COMMITTER_NAME", "Scan")
            .env("GIT_COMMITTER_EMAIL", "scan@example.com")
            .output()
            .expect("run git")
    };
    for arguments in [
        vec!["init", "--quiet"],
        vec!["add", "."],
        vec!["commit", "--quiet", "-m", "initial"],
    ] {
        let output = git(&arguments);
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&git(&["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_owned()
}

// The `-c core.hooksPath=/dev/null` override is only worth anything if it
// really beats the configuration git would otherwise obey. A hook configured
// globally must not run during a checkout of an unreviewed repository.
#[test]
fn a_globally_configured_hook_does_not_run_during_a_checkout() {
    use codex_security::multiscan::ProcessGitRunner;

    let root = TempDir::new().expect("root");
    let source = root.path().join("source");
    std::fs::create_dir_all(&source).expect("create source");
    std::fs::write(source.join("a.txt"), "one").expect("write");
    let revision = commit_all(&source);

    // A hook that leaves a marker behind if git ever runs it.
    let hooks = root.path().join("hooks");
    std::fs::create_dir(&hooks).expect("create hooks");
    let marker = root.path().join("hook-ran");
    for hook in [
        "post-checkout",
        "post-index-change",
        "reference-transaction",
    ] {
        let path = hooks.join(hook);
        std::fs::write(
            &path,
            format!("#!/bin/sh\n/bin/echo ran > '{}'\n", marker.display()),
        )
        .expect("write hook");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let global = root.path().join("gitconfig");
    std::fs::write(
        &global,
        format!("[core]\n\thooksPath = {}\n", hooks.display()),
    )
    .expect("write global config");

    let checkout = root.path().join("checkout");
    std::fs::create_dir(&checkout).expect("create checkout");
    let mut environment: ProcessEnvironment = std::env::vars().collect();
    environment.insert("GIT_CONFIG_GLOBAL".to_owned(), global.display().to_string());
    let pinned = MultiscanTask {
        id: "payments".to_owned(),
        repository: source.display().to_string(),
        revision,
        mode: ScanMode::Standard,
        scope: None,
    };

    checkout_revision(
        &pinned,
        &checkout,
        None,
        &environment,
        &ProcessGitRunner::new(root.path()),
    )
    .expect("the checkout succeeds");

    assert!(
        !marker.exists(),
        "a configured git hook ran during the checkout"
    );
}

// The same configuration, without the override, does run the hook — which is
// what makes the test above meaningful rather than vacuous.
#[test]
fn the_hook_configuration_used_above_really_would_run() {
    let root = TempDir::new().expect("root");
    let source = root.path().join("source");
    std::fs::create_dir_all(&source).expect("create source");
    std::fs::write(source.join("a.txt"), "one").expect("write");
    commit_all(&source);

    let hooks = root.path().join("hooks");
    std::fs::create_dir(&hooks).expect("create hooks");
    let marker = root.path().join("hook-ran");
    let path = hooks.join("post-checkout");
    std::fs::write(
        &path,
        format!("#!/bin/sh\n/bin/echo ran > '{}'\n", marker.display()),
    )
    .expect("write hook");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let global = root.path().join("gitconfig");
    std::fs::write(
        &global,
        format!("[core]\n\thooksPath = {}\n", hooks.display()),
    )
    .expect("write global config");

    // A checkout with no override, exactly as git would otherwise run it.
    let status = std::process::Command::new("git")
        .args(["checkout", "--quiet", "--detach", "HEAD"])
        .current_dir(&source)
        .env("GIT_CONFIG_GLOBAL", &global)
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .expect("run git");

    assert!(status.success());
    assert!(
        marker.exists(),
        "the hook never ran, so the protection test proves nothing"
    );
}

// ---------------------------------------------------------------------------
// The campaign loop
// ---------------------------------------------------------------------------

use codex_security::multiscan::{
    Campaign, MultiscanObserver, MultiscanOptions, MultiscanProgress, ProgressStatus, ScanOutcome,
    ScanRunner, run_campaign,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A git that materialises a checkout without touching the network.
struct LocalGit;

impl GitRunner for LocalGit {
    fn run(
        &self,
        arguments: &[String],
        _environment: &ProcessEnvironment,
    ) -> codex_security::Result<String> {
        let index = arguments
            .iter()
            .position(|value| value == "-C")
            .expect("-C");
        let path = PathBuf::from(&arguments[index + 1]);
        match arguments.get(index + 2).map(String::as_str) {
            Some("rev-parse") => Ok(SHA.to_owned()),
            Some("checkout") => {
                std::fs::create_dir_all(path.join("src")).expect("create tree");
                std::fs::write(path.join("src/app.rs"), "fn main() {}").expect("write");
                Ok(String::new())
            }
            _ => Ok(String::new()),
        }
    }
}

/// A scanner that writes the artifacts a completed scan leaves behind.
struct FakeScanner {
    runs: AtomicUsize,
    /// Task ids that should fail, and how many times each still will.
    failures: Mutex<BTreeMap<String, usize>>,
    coverage_complete: bool,
    scanned: Mutex<Vec<(String, PathBuf)>>,
}

impl FakeScanner {
    fn new() -> Self {
        Self {
            runs: AtomicUsize::new(0),
            failures: Mutex::new(BTreeMap::new()),
            coverage_complete: true,
            scanned: Mutex::new(Vec::new()),
        }
    }

    fn failing(id: &str, times: usize) -> Self {
        let scanner = Self::new();
        scanner
            .failures
            .lock()
            .expect("failures")
            .insert(id.to_owned(), times);
        scanner
    }
}

impl ScanRunner for FakeScanner {
    fn run(
        &self,
        checkout: &Path,
        task: &MultiscanTask,
        scan_dir: &Path,
    ) -> codex_security::Result<ScanOutcome> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        self.scanned
            .lock()
            .expect("scanned")
            .push((task.id.clone(), checkout.to_path_buf()));

        {
            let mut failures = self.failures.lock().expect("failures");
            if let Some(remaining) = failures.get_mut(&task.id)
                && *remaining > 0
            {
                *remaining -= 1;
                return Err(codex_security::Error::codex_security(
                    "the scan failed with token=ghp_abcdefghijklmnop",
                ));
            }
        }

        std::fs::create_dir_all(scan_dir).expect("create scan dir");
        for artifact in ["scan-manifest.json", "findings.json", "coverage.json"] {
            std::fs::write(scan_dir.join(artifact), "{}").expect("write artifact");
        }
        std::fs::write(scan_dir.join("report.md"), "# Report\n").expect("write report");
        Ok(ScanOutcome {
            cost: None,
            coverage_complete: self.coverage_complete,
        })
    }
}

/// Records every progress event a campaign reported.
#[derive(Default)]
struct Progress(Mutex<Vec<MultiscanProgress>>);

impl MultiscanObserver for Progress {
    fn on_progress(&self, progress: &MultiscanProgress) {
        self.0.lock().expect("progress").push(progress.clone());
    }
}

/// Runs a campaign over `tasks` with the given scanner.
fn campaign(
    output: &Path,
    tasks: &[MultiscanTask],
    scanner: &FakeScanner,
    options: MultiscanOptions,
    observer: &Progress,
) -> codex_security::Result<codex_security::multiscan::MultiscanResult> {
    let environment: ProcessEnvironment = ProcessEnvironment::new();
    run_campaign(
        tasks,
        output,
        &Campaign {
            options: &options,
            environment: &environment,
            git: &LocalGit,
            scanner,
            observer,
        },
    )
}

#[test]
fn runs_every_task_and_records_each_one() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks = [task("payments"), task("ledger")];
    let scanner = FakeScanner::new();
    let observer = Progress::default();

    let result = campaign(
        root.path(),
        &tasks,
        &scanner,
        MultiscanOptions::default(),
        &observer,
    )
    .expect("the campaign runs");

    assert_eq!(result.total, 2);
    assert_eq!(result.completed, 2);
    assert_eq!(result.failed, 0);
    assert_eq!(result.skipped, 0);
    let receipts = read_receipts(&result.results_path).expect("receipts");
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts["payments"].status, ReceiptStatus::Completed);
}

// A campaign that already finished a repository must not pay to scan it again.
#[test]
fn resumes_without_repeating_finished_work() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks = [task("payments"), task("ledger")];
    let first = FakeScanner::new();
    campaign(
        root.path(),
        &tasks,
        &first,
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the first campaign runs");
    assert_eq!(first.runs.load(Ordering::SeqCst), 2);

    let second = FakeScanner::new();
    let result = campaign(
        root.path(),
        &tasks,
        &second,
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the second campaign runs");

    assert_eq!(
        second.runs.load(Ordering::SeqCst),
        0,
        "nothing was rescanned"
    );
    assert_eq!(result.skipped, 2);
    assert_eq!(result.completed, 2);
}

// A receipt alone could outlive its output, so the artifacts are checked too.
#[test]
fn rescans_a_repository_whose_output_has_gone_missing() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks = [task("payments")];
    campaign(
        root.path(),
        &tasks,
        &FakeScanner::new(),
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the first campaign runs");
    std::fs::remove_dir_all(root.path().join("artifacts/payments")).expect("remove output");

    let scanner = FakeScanner::new();
    let result = campaign(
        root.path(),
        &tasks,
        &scanner,
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the second campaign runs");

    assert_eq!(scanner.runs.load(Ordering::SeqCst), 1, "it was rescanned");
    assert_eq!(result.skipped, 0);
}

#[test]
fn retries_a_failing_repository_and_records_every_attempt() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks = [task("payments")];
    let scanner = FakeScanner::failing("payments", 1);
    let observer = Progress::default();

    let result = campaign(
        root.path(),
        &tasks,
        &scanner,
        MultiscanOptions {
            max_attempts: 2,
            ..MultiscanOptions::default()
        },
        &observer,
    )
    .expect("the campaign runs");

    assert_eq!(result.completed, 1);
    assert_eq!(result.failed, 0);
    assert_eq!(scanner.runs.load(Ordering::SeqCst), 2);
    // Both attempts are on record, not only the one that worked.
    let ledger = std::fs::read_to_string(&result.results_path).expect("ledger");
    assert_eq!(ledger.lines().count(), 2);
    let statuses: Vec<ProgressStatus> = observer
        .0
        .lock()
        .expect("progress")
        .iter()
        .map(|event| event.status)
        .collect();
    assert_eq!(
        statuses,
        [
            ProgressStatus::Started,
            ProgressStatus::Failed,
            ProgressStatus::Started,
            ProgressStatus::Completed
        ]
    );
}

#[test]
fn gives_up_after_the_last_attempt() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks = [task("payments"), task("ledger")];
    let scanner = FakeScanner::failing("payments", 99);

    let result = campaign(
        root.path(),
        &tasks,
        &scanner,
        MultiscanOptions {
            max_attempts: 2,
            ..MultiscanOptions::default()
        },
        &Progress::default(),
    )
    .expect("the campaign runs");

    assert_eq!(result.failed, 1);
    // One repository failing does not stop the others.
    assert_eq!(result.completed, 1);
}

// The campaign's records outlive the run, so a failure quoting a token must not
// be written into them as it arrived.
#[test]
fn redacts_secrets_from_recorded_failures() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let observer = Progress::default();

    let result = campaign(
        root.path(),
        &[task("payments")],
        &FakeScanner::failing("payments", 99),
        MultiscanOptions::default(),
        &observer,
    )
    .expect("the campaign runs");

    let ledger = std::fs::read_to_string(&result.results_path).expect("ledger");
    assert!(!ledger.contains("ghp_abcdefghijklmnop"), "{ledger}");
    assert!(ledger.contains("[redacted]"), "{ledger}");
    let reported = observer.0.lock().expect("progress");
    let failure = reported
        .iter()
        .find(|event| event.status == ProgressStatus::Failed)
        .expect("a failure was reported");
    assert!(
        !failure
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("ghp_"),
        "{:?}",
        failure.error
    );
}

// A partial scan says nothing about what it did not look at, so calling it
// complete would be a false clean bill.
#[test]
fn treats_incomplete_coverage_as_a_failure() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let mut scanner = FakeScanner::new();
    scanner.coverage_complete = false;

    let result = campaign(
        root.path(),
        &[task("payments")],
        &scanner,
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the campaign runs");

    assert_eq!(result.failed, 1);
    assert_eq!(result.completed, 0);
    let receipts = read_receipts(&result.results_path).expect("receipts");
    assert!(
        receipts["payments"]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("coverage is incomplete"),
        "{:?}",
        receipts["payments"].error
    );
}

// The checkout is a copy of an unreviewed repository and has no reason to
// outlive the scan.
#[test]
fn removes_each_checkout_when_its_attempt_ends() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");

    campaign(
        root.path(),
        &[task("payments")],
        &FakeScanner::failing("payments", 99),
        MultiscanOptions::default(),
        &Progress::default(),
    )
    .expect("the campaign runs");

    assert!(
        !root.path().join("checkouts/payments").exists(),
        "a checkout survived a failed attempt"
    );
}

#[test]
fn works_on_several_repositories_at_once() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let tasks: Vec<MultiscanTask> = (0..6).map(|index| task(&format!("repo{index}"))).collect();
    let scanner = FakeScanner::new();

    let result = campaign(
        root.path(),
        &tasks,
        &scanner,
        MultiscanOptions {
            workers: 4,
            ..MultiscanOptions::default()
        },
        &Progress::default(),
    )
    .expect("the campaign runs");

    assert_eq!(result.completed, 6);
    assert_eq!(scanner.runs.load(Ordering::SeqCst), 6, "each task ran once");
    // Every receipt survived, so concurrent appends did not interleave.
    assert_eq!(
        read_receipts(&result.results_path).expect("receipts").len(),
        6
    );
}

#[test]
fn refuses_a_campaign_with_no_workers() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");

    let error = campaign(
        root.path(),
        &[task("payments")],
        &FakeScanner::new(),
        MultiscanOptions {
            workers: 0,
            ..MultiscanOptions::default()
        },
        &Progress::default(),
    )
    .expect_err("refused");

    assert!(error.to_string().contains("positive integer"), "{error}");
}

#[test]
fn refuses_a_campaign_with_no_attempts() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");

    let error = campaign(
        root.path(),
        &[task("payments")],
        &FakeScanner::new(),
        MultiscanOptions {
            max_attempts: 0,
            ..MultiscanOptions::default()
        },
        &Progress::default(),
    )
    .expect_err("refused");

    assert!(error.to_string().contains("positive integer"), "{error}");
}

// The scope is resolved through whatever the repository actually contains,
// including a link it ships that points outside itself.
#[test]
fn refuses_a_scope_that_escapes_through_a_symbolic_link() {
    let root = TempDir::new().expect("root");
    ensure_output_directory(root.path()).expect("output");
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).expect("create outside");

    /// A git that ships a link pointing out of the repository.
    struct EscapingGit(PathBuf);
    impl GitRunner for EscapingGit {
        fn run(
            &self,
            arguments: &[String],
            _: &ProcessEnvironment,
        ) -> codex_security::Result<String> {
            let index = arguments
                .iter()
                .position(|value| value == "-C")
                .expect("-C");
            let path = PathBuf::from(&arguments[index + 1]);
            match arguments.get(index + 2).map(String::as_str) {
                Some("rev-parse") => Ok(SHA.to_owned()),
                Some("checkout") => {
                    std::os::unix::fs::symlink(&self.0, path.join("src")).expect("symlink");
                    Ok(String::new())
                }
                _ => Ok(String::new()),
            }
        }
    }

    let scoped = MultiscanTask {
        scope: Some("src".to_owned()),
        ..task("payments")
    };
    let scanner = FakeScanner::new();
    let environment = ProcessEnvironment::new();
    let options = MultiscanOptions::default();

    let result = run_campaign(
        &[scoped],
        root.path(),
        &Campaign {
            options: &options,
            environment: &environment,
            git: &EscapingGit(outside),
            scanner: &scanner,
            observer: &Progress::default(),
        },
    )
    .expect("the campaign runs");

    assert_eq!(result.failed, 1);
    assert_eq!(
        scanner.runs.load(Ordering::SeqCst),
        0,
        "nothing was scanned"
    );
    let receipts = read_receipts(&result.results_path).expect("receipts");
    assert!(
        receipts["payments"]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("escapes its repository"),
        "{:?}",
        receipts["payments"].error
    );
}
