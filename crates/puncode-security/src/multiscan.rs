//! Scanning many repositories from one inventory.
//!
//! Ported from `src/multiscan.ts`.
//!
//! The inventory is a CSV a person wrote, naming repositories to clone and
//! commits to check out, so every field is treated as hostile until proven
//! otherwise. Task identifiers become directory names, revisions become
//! arguments to `git checkout`, and repositories become clone targets: each is
//! validated before anything runs, and the whole inventory is rejected rather
//! than partially started, so a mistake on the last row does not leave half a
//! campaign behind.
//!
//! Failures are redacted before they are recorded. A clone that fails often
//! quotes the URL it tried, and that URL may carry a token.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::cost::ScanCost;
use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, ScanMode};

/// The longest repository reference the inventory may name.
const MAX_REPOSITORY_LENGTH: usize = 4096;

/// One repository to scan, as the inventory describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiscanTask {
    pub id: String,
    /// A local path, an SSH-style reference, or an `https`/`ssh` URL.
    pub repository: String,
    /// A full commit SHA; a branch could move between reading and cloning.
    pub revision: String,
    pub mode: ScanMode,
    /// A repository-relative subdirectory to scan, when the row names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Reads the inventory, rejecting the whole file if any row is unusable.
pub fn parse_inventory(
    source: &str,
    directory: &Path,
    default_mode: ScanMode,
) -> Result<Vec<MultiscanTask>> {
    let (mut rows, errors) = parse_csv(source);
    if let Some(first) = errors.first() {
        return Err(Error::puncode_security(format!(
            "Multiscan CSV could not be parsed: {first}"
        )));
    }

    let headers = if rows.is_empty() {
        Vec::new()
    } else {
        rows.remove(0)
    };
    let required = ["id", "repository", "revision"];
    let unique: std::collections::BTreeSet<&String> = headers.iter().collect();
    if headers.is_empty()
        || !required
            .iter()
            .all(|name| headers.iter().any(|header| header == name))
        || unique.len() != headers.len()
    {
        return Err(Error::puncode_security(
            "Multiscan CSV requires id, repository, and revision columns.",
        ));
    }
    if rows.is_empty() {
        return Err(Error::puncode_security(
            "Multiscan CSV must contain at least one repository.",
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut tasks = Vec::with_capacity(rows.len());
    for fields in rows {
        // A short or long row means the file does not say what it appears to.
        if fields.len() != headers.len() {
            return Err(Error::puncode_security(
                "Multiscan CSV rows must match their header columns.",
            ));
        }
        let get = |name: &str| -> String {
            headers
                .iter()
                .position(|header| header == name)
                .and_then(|index| fields.get(index))
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };

        // The identifier becomes a directory name under the output root.
        let id = get("id");
        if !safe_task_id(&id) {
            return Err(Error::puncode_security(
                "Multiscan task IDs must be safe, unique path names.",
            ));
        }
        if !seen.insert(id.to_lowercase()) {
            return Err(Error::puncode_security(
                "Multiscan task IDs must be unique.",
            ));
        }

        // A branch or tag could move between reading the inventory and
        // cloning, so only a full commit identifies what was scanned.
        let revision = get("revision").to_lowercase();
        if !full_commit_sha(&revision) {
            return Err(Error::puncode_security(
                "Multiscan revisions must be full immutable Git SHAs.",
            ));
        }

        let mode = match get("mode").as_str() {
            "" => default_mode,
            "standard" => ScanMode::Standard,
            "deep" => ScanMode::Deep,
            _ => {
                return Err(Error::puncode_security(
                    "Multiscan mode must be standard or deep.",
                ));
            }
        };

        let scope = get("scope");
        if !scope.is_empty() && !safe_scope(&scope) {
            return Err(Error::puncode_security(
                "Multiscan scope must stay inside its repository.",
            ));
        }

        tasks.push(MultiscanTask {
            id,
            repository: normalize_repository(&get("repository"), directory)?,
            revision,
            mode,
            scope: (!scope.is_empty()).then_some(scope),
        });
    }
    Ok(tasks)
}

/// Whether an identifier is safe to use as a directory name.
fn safe_task_id(id: &str) -> bool {
    let mut characters = id.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() || id.chars().count() > 128 {
        return false;
    }
    characters.all(|character| {
        character.is_ascii_alphanumeric()
            || character == '.'
            || character == '_'
            || character == '-'
    })
}

/// Whether a revision is a full SHA-1 or SHA-256 commit identifier.
fn full_commit_sha(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64)
        && revision
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

/// Whether a scope stays inside the repository it belongs to.
fn safe_scope(scope: &str) -> bool {
    !Path::new(scope).is_absolute()
        && !scope.contains('\\')
        && !scope.split('/').any(|segment| segment == "..")
        && !scope.contains('\0')
}

/// Resolves a repository reference, refusing anything unsafe.
///
/// A URL carrying credentials is refused rather than used: it would be written
/// into the campaign's records and into any error the clone produced.
pub fn normalize_repository(repository: &str, directory: &Path) -> Result<String> {
    static SSH_STYLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[^@\s/:]+@[^:\s/]+:.+$").expect("a valid pattern"));

    if repository.is_empty()
        || repository.len() > MAX_REPOSITORY_LENGTH
        || repository.contains('\0')
    {
        return Err(Error::puncode_security(
            "Multiscan repositories must be safe local paths or Git URLs.",
        ));
    }
    // `git@github.com:owner/repo.git` is not a URL but is a valid reference.
    if SSH_STYLE.is_match(repository) {
        return Ok(repository.to_owned());
    }
    if !repository.contains("://") {
        return Ok(resolve(directory, repository)
            .to_string_lossy()
            .into_owned());
    }

    let url = Url::parse(repository)
        .map_err(|_| Error::puncode_security("Multiscan repository URL is invalid."))?;
    if url.scheme() != "https" && url.scheme() != "ssh" {
        return Err(Error::puncode_security(
            "Multiscan repository URL protocol is unsupported.",
        ));
    }
    // An `ssh://` username names an account, but an `https://` one is a token.
    if url.password().is_some()
        || (url.scheme() == "https" && !url.username().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::puncode_security(
            "Repository URLs must not contain embedded credentials, query strings, or fragments.",
        ));
    }
    Ok(repository.to_owned())
}

/// Joins `path` onto `directory` unless it is already absolute.
fn resolve(directory: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return crate::targets::lexical_absolute(path);
    }
    crate::targets::lexical_absolute(&directory.join(path))
}

/// The `git` arguments that let a checkout use the GitHub CLI's credentials.
///
/// The helper is bound to one origin, and the empty assignment first clears any
/// helper the user's configuration already set for it: without that, an
/// inherited helper would also run.
pub fn build_github_credential_args(host: Option<&str>) -> Result<Vec<String>> {
    let Some(host) = host else {
        return Ok(Vec::new());
    };
    let invalid = || Error::puncode_security("GitHub credential host is invalid.");
    let url = Url::parse(&format!("https://{host}")).map_err(|_| invalid())?;

    // Anything beyond a bare host would widen where the credential is offered.
    let authority = url.host_str().map_or_else(String::new, |name| {
        url.port()
            .map_or_else(|| name.to_owned(), |port| format!("{name}:{port}"))
    });
    if authority != host.to_lowercase()
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }

    let key = format!("credential.{}.helper", url.origin().ascii_serialization());
    Ok(vec![
        "-c".to_owned(),
        format!("{key}="),
        "-c".to_owned(),
        format!("{key}=!gh auth git-credential"),
    ])
}

/// Removes anything secret-looking from a failure before it is recorded.
///
/// A clone that fails often quotes the URL it tried, and that URL may carry a
/// token; the campaign's records outlive the run.
#[must_use]
pub fn redact_error(message: &str) -> String {
    static LABELLED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)((?:api[_-]?key|token|secret|credential|password)[A-Za-z0-9_-]*\s*[:=]\s*)[^\s,;]+",
        )
        .expect("a valid pattern")
    });
    static KNOWN_PREFIXES: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|npm_)[A-Za-z0-9_*=-]{8,}")
            .expect("a valid pattern")
    });
    static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(Bearer|Basic|Token)\s+[^\s,;]+").expect("a valid pattern")
    });

    let labelled = LABELLED.replace_all(message, "${1}[redacted]");
    let known = KNOWN_PREFIXES.replace_all(&labelled, "[redacted]");
    AUTHORIZATION
        .replace_all(&known, "${1} [redacted]")
        .into_owned()
}

/// Reads CSV the way the upstream parser does, returning its rows.
///
/// Exposed so the parsing itself can be checked against the upstream parser
/// rather than only through the inventory it feeds.
pub fn parse_csv_rows(source: &str) -> Result<Vec<Vec<String>>> {
    let (rows, errors) = parse_csv(source);
    match errors.first() {
        Some(first) => Err(Error::puncode_security(format!(
            "Multiscan CSV could not be parsed: {first}"
        ))),
        None => Ok(rows),
    }
}

/// A CSV row, and the reasons it could not be read.
type CsvRows = (Vec<Vec<String>>, Vec<String>);

/// Reads CSV the way the upstream parser does.
///
/// Quoted fields may hold delimiters, newlines, and doubled quotes; rows may
/// end with `\r\n`, `\n` or `\r`; a leading byte-order mark is dropped; and
/// blank or whitespace-only lines are skipped entirely. An unterminated quote
/// is reported rather than guessed at, because the rest of the file is then
/// being read as one field.
fn parse_csv(source: &str) -> CsvRows {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut errors = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = source.chars().peekable();

    while let Some(character) = characters.next() {
        if quoted {
            if character == '"' {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(character);
            }
            continue;
        }
        match character {
            '"' if field.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' | '\n' => {
                if character == '\r' && characters.peek() == Some(&'\n') {
                    characters.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            character => field.push(character),
        }
    }
    if quoted {
        errors.push("Quoted field unterminated".to_owned());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    // Greedy skipping drops any line that carries nothing but whitespace.
    rows.retain(|row| row.iter().any(|field| !field.trim().is_empty()));
    (rows, errors)
}

/// The artifacts a completed scan must have left behind.
const REQUIRED_ARTIFACTS: [&str; 4] = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
];

/// What a campaign recorded about one task, once it finished.
///
/// Receipts are the campaign's memory: a run that is interrupted resumes from
/// them rather than repeating work that already cost money.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiscanReceipt {
    pub id: String,
    pub repository: String,
    pub revision: String,
    pub mode: ScanMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub status: ReceiptStatus,
    pub attempt: u32,
    pub output_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<ScanCost>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// How a task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    Completed,
    Failed,
}

/// Creates the campaign's output directory, private to its owner.
///
/// A symbolic link is refused rather than followed: the campaign later removes
/// checkouts beneath this directory, and a link would point that removal
/// somewhere else entirely.
pub fn ensure_output_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_symlink() => {
            return Err(Error::puncode_security(
                "Multiscan output directories must not be symbolic links.",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::puncode_security(format!(
                "Unable to inspect the multiscan output directory: {}",
                path.display()
            ))
            .with_source(error));
        }
    }

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::puncode_security(format!(
            "Unable to create the multiscan output directory: {}",
            path.display()
        ))
        .with_source(error)
    })
}

/// Holds a campaign's exclusive claim on an output directory.
#[derive(Debug)]
pub struct MultiscanLock {
    path: PathBuf,
}

impl MultiscanLock {
    /// Releases the claim.
    pub fn release(self) -> Result<()> {
        self.remove()
    }

    fn remove(&self) -> Result<()> {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::puncode_security(format!(
                "Unable to release the multiscan lock at {}",
                self.path.display()
            ))
            .with_source(error)),
        }
    }
}

/// A campaign that panicked still gives up its claim.
impl Drop for MultiscanLock {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Claims an output directory for one campaign.
///
/// The claim is a directory, because creating one is atomic. A claim left by a
/// process that has since died is taken over rather than honoured forever, but
/// only after checking the recorded process is really gone: two supervisors
/// writing the same ledger would corrupt it.
pub fn acquire_lock(output: &Path) -> Result<MultiscanLock> {
    acquire_lock_with(output, std::process::id(), &process_is_running)
}

/// Claims an output directory, with the liveness check and owner injectable.
pub fn acquire_lock_with(
    output: &Path,
    pid: u32,
    is_running: &dyn Fn(u32) -> bool,
) -> Result<MultiscanLock> {
    let path = output.join(".lock");
    let owner_path = path.join("owner.json");

    // Bounded so a pathological contender cannot spin here forever.
    for _ in 0..16 {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => {
                write_new_private(&owner_path, &format!("{{\"pid\":{pid}}}\n"))?;
                return Ok(MultiscanLock { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Error::puncode_security(format!(
                    "Unable to claim the multiscan output directory: {}",
                    output.display()
                ))
                .with_source(error));
            }
        }

        let owner: Option<u32> = std::fs::read_to_string(&owner_path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.get("pid").and_then(serde_json::Value::as_u64))
            .and_then(|pid| u32::try_from(pid).ok());
        if owner.is_some_and(is_running) {
            return Err(Error::puncode_security(
                "A multiscan supervisor is already running.",
            ));
        }

        // Moved aside before being removed, so a supervisor that wakes up mid
        // removal cannot see a half-deleted claim as a live one.
        let stale = output.join(format!(".lock.stale-{}", unique_suffix()));
        if std::fs::rename(&path, &stale).is_ok() {
            let _ = std::fs::remove_dir_all(&stale);
        }
    }
    Err(Error::puncode_security(
        "Unable to claim the multiscan output directory.",
    ))
}

/// Whether a process is still there to be signalled.
fn process_is_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        let Some(pid) = rustix::process::Pid::from_raw(pid) else {
            return false;
        };
        // Signal zero checks for the process without disturbing it.
        rustix::process::test_kill_process(pid).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Records the inventory a campaign is running, refusing a changed one.
///
/// Resuming into an output directory built from a different inventory would
/// mix two campaigns' results together, so the manifest must match exactly.
pub fn ensure_manifest(path: &Path, tasks: &[MultiscanTask]) -> Result<()> {
    let expected = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "tasks": tasks,
        }))
        .map_err(|error| {
            Error::puncode_security("Unable to record the multiscan manifest").with_source(error)
        })?
    );

    match write_new_private(path, &expected) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("already exists") => {
            let existing = std::fs::read_to_string(path).map_err(|error| {
                Error::puncode_security("Unable to read the multiscan manifest").with_source(error)
            })?;
            if existing == expected {
                return Ok(());
            }
            Err(Error::puncode_security(
                "Multiscan manifest does not match existing output directory.",
            ))
        }
        Err(error) => Err(error),
    }
}

/// Reads the receipts a previous run left, repairing a torn final line.
///
/// A campaign killed mid-write leaves a partial line; it is truncated away,
/// because a receipt that was never finished describes nothing.
pub fn read_receipts(path: &Path) -> Result<BTreeMap<String, MultiscanReceipt>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(error) => {
            return Err(Error::puncode_security(format!(
                "Unable to read the multiscan ledger at {}",
                path.display()
            ))
            .with_source(error));
        }
    };

    let mut lines: Vec<&str> = contents.split('\n').collect();
    if !contents.ends_with('\n') {
        let partial = lines.pop().unwrap_or_default();
        let keep = contents.len() - partial.len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.set_len(keep as u64))
            .map_err(|error| {
                Error::puncode_security("Unable to repair the multiscan ledger").with_source(error)
            })?;
    }

    let mut receipts = BTreeMap::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        let receipt: MultiscanReceipt = serde_json::from_str(line).map_err(|error| {
            Error::puncode_security("Multiscan ledger holds an unreadable receipt")
                .with_source(error)
        })?;
        receipts.insert(receipt.id.to_lowercase(), receipt);
    }
    Ok(receipts)
}

/// Appends one receipt, flushed to disk before returning.
///
/// The flush is what makes the ledger resumable: a receipt still in a buffer
/// when the machine dies would have the campaign repeat work already paid for.
pub fn append_receipt(path: &Path, receipt: &MultiscanReceipt) -> Result<()> {
    use std::io::Write;
    let line = format!(
        "{}\n",
        serde_json::to_string(receipt).map_err(|error| {
            Error::puncode_security("Unable to record a multiscan receipt").with_source(error)
        })?
    );

    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::puncode_security(format!(
            "Unable to open the multiscan ledger at {}",
            path.display()
        ))
        .with_source(error)
    })?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            Error::puncode_security("Unable to record a multiscan receipt").with_source(error)
        })
}

/// Whether a scan directory holds everything a completed scan produces.
#[must_use]
pub fn has_artifacts(path: &Path) -> bool {
    if !std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    REQUIRED_ARTIFACTS.iter().all(|artifact| {
        std::fs::symlink_metadata(path.join(artifact)).is_ok_and(|metadata| metadata.is_file())
    })
}

/// Writes a file that must not already exist, readable only by its owner.
fn write_new_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        let detail = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "already exists"
        } else {
            "could not be created"
        };
        Error::puncode_security(format!("{} {detail}", path.display())).with_source(error)
    })?;
    file.write_all(contents.as_bytes()).map_err(|error| {
        Error::puncode_security(format!("Unable to write {}", path.display())).with_source(error)
    })
}

/// A short suffix distinguishing stale claims moved aside in the same moment.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::from(elapsed.subsec_nanos()));
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:08x}{counter:04x}")
}

/// Git variables that would point a checkout somewhere other than its own
/// directory, and are removed before running anything.
const UNSAFE_GIT_VARIABLES: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
];

/// Runs one `git` invocation and returns its trimmed output.
pub trait GitRunner {
    fn run(&self, arguments: &[String], environment: &ProcessEnvironment) -> Result<String>;
}

/// The environment a checkout runs `git` in.
///
/// The inherited variables that redirect git are removed, the terminal prompt
/// is disabled so a private repository fails instead of hanging waiting for a
/// password, and LFS content is left unfetched: the scan reads source, and a
/// smudge filter is code the repository chose to run.
#[must_use]
pub fn checkout_environment(environment: &ProcessEnvironment) -> ProcessEnvironment {
    let mut environment: ProcessEnvironment = environment
        .iter()
        .filter(|(name, _)| {
            !UNSAFE_GIT_VARIABLES
                .iter()
                .any(|unsafe_name| name.eq_ignore_ascii_case(unsafe_name))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    environment.insert("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned());
    environment.insert("GIT_LFS_SKIP_SMUDGE".to_owned(), "1".to_owned());
    environment
}

/// The arguments every checkout command begins with.
///
/// `core.hooksPath` is pointed at nothing before anything is fetched. A
/// repository can ship hooks, and git would otherwise run them during the
/// checkout — arbitrary code from the very repository under review, before it
/// has been looked at.
fn git_prefix(path: &Path, github_host: Option<&str>) -> Result<Vec<String>> {
    let mut arguments = vec!["-c".to_owned(), "core.hooksPath=/dev/null".to_owned()];
    arguments.extend(build_github_credential_args(github_host)?);
    arguments.push("-C".to_owned());
    arguments.push(path.to_string_lossy().into_owned());
    Ok(arguments)
}

/// Materialises a task's pinned commit in `path`.
///
/// Only the one commit is fetched, and what arrives is checked against the SHA
/// that was asked for: a server that answered with something else would
/// otherwise be scanned as though it were the pinned revision.
pub fn checkout_revision(
    task: &MultiscanTask,
    path: &Path,
    github_host: Option<&str>,
    environment: &ProcessEnvironment,
    runner: &dyn GitRunner,
) -> Result<()> {
    let environment = checkout_environment(environment);
    let prefix = git_prefix(path, github_host)?;
    let git = |arguments: &[&str]| -> Result<String> {
        let mut full = prefix.clone();
        full.extend(arguments.iter().map(|value| (*value).to_owned()));
        runner.run(&full, &environment)
    };

    git(&["init", "--quiet"])?;
    // `--` keeps a repository named like an option from being read as one.
    git(&[
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        "--",
        &task.repository,
        &task.revision,
    ])?;
    git(&["checkout", "--quiet", "--detach", "FETCH_HEAD"])?;

    let head = git(&["rev-parse", "HEAD"])?.trim().to_lowercase();
    if head != task.revision {
        return Err(Error::puncode_security(
            "Git checkout revision did not match the pinned SHA.",
        ));
    }
    Ok(())
}

/// Runs `git` from a trusted `PATH`.
#[derive(Debug, Clone)]
pub struct ProcessGitRunner {
    protected_root: PathBuf,
}

impl ProcessGitRunner {
    #[must_use]
    pub fn new(protected_root: impl Into<PathBuf>) -> Self {
        Self {
            protected_root: protected_root.into(),
        }
    }
}

impl GitRunner for ProcessGitRunner {
    fn run(&self, arguments: &[String], environment: &ProcessEnvironment) -> Result<String> {
        // Resolved through the trusted search, so a `git` committed to the
        // repository being scanned is never the one that runs.
        let command = crate::trusted_executable::resolve_trusted_executable(
            "git",
            environment,
            &self.protected_root,
        )
        .ok_or_else(|| Error::puncode_security("Git is not available on a trusted PATH."))?;

        let output = std::process::Command::new(&command.executable)
            .args(arguments)
            .env_clear()
            .envs(&command.environment)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| {
                Error::puncode_security(format!("Could not run git: {error}")).with_source(error)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            // Redacted: a failing fetch quotes the URL it tried.
            return Err(Error::puncode_security(format!(
                "git failed: {}",
                redact_error(&detail)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

/// What one scan produced, as the campaign needs to judge it.
#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub cost: Option<ScanCost>,
    /// A partial scan is treated as a failure: it says nothing about what it
    /// did not look at, so calling it complete would be a false clean bill.
    pub coverage_complete: bool,
}

/// Scans one checked-out repository.
pub trait ScanRunner {
    fn run(&self, checkout: &Path, task: &MultiscanTask, scan_dir: &Path) -> Result<ScanOutcome>;
}

/// How one task is progressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStatus {
    Started,
    Completed,
    Failed,
}

/// One step in a campaign, as it happens.
#[derive(Debug, Clone)]
pub struct MultiscanProgress {
    pub repository: String,
    pub status: ProgressStatus,
    pub attempt: u32,
    /// Present, and already redacted, when the attempt failed.
    pub error: Option<String>,
}

/// Watches a campaign run.
pub trait MultiscanObserver: Sync {
    fn on_progress(&self, progress: &MultiscanProgress) {
        let _ = progress;
    }
}

/// An observer that does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct IgnoreMultiscanProgress;

impl MultiscanObserver for IgnoreMultiscanProgress {}

/// How a campaign should be run.
#[derive(Debug, Clone)]
pub struct MultiscanOptions {
    /// How many repositories to work on at once.
    pub workers: usize,
    /// How many times to try a repository before giving up on it.
    pub max_attempts: u32,
    pub github_host: Option<String>,
}

impl Default for MultiscanOptions {
    fn default() -> Self {
        Self {
            workers: 1,
            max_attempts: 1,
            github_host: None,
        }
    }
}

/// What a campaign did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiscanResult {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    /// Repositories a previous run had already finished.
    pub skipped: usize,
    pub results_path: PathBuf,
}

/// What a campaign needs in order to run.
pub struct Campaign<'a> {
    pub options: &'a MultiscanOptions,
    pub environment: &'a ProcessEnvironment,
    pub git: &'a (dyn GitRunner + Sync),
    pub scanner: &'a (dyn ScanRunner + Sync),
    pub observer: &'a (dyn MultiscanObserver + Sync),
}

/// Runs every task, resuming whatever a previous run already finished.
pub fn run_campaign(
    tasks: &[MultiscanTask],
    output: &Path,
    campaign: &Campaign<'_>,
) -> Result<MultiscanResult> {
    if campaign.options.workers < 1 {
        return Err(Error::puncode_security(
            "Multiscan workers must be a positive integer.",
        ));
    }
    if campaign.options.max_attempts < 1 {
        return Err(Error::puncode_security(
            "Multiscan max attempts must be a positive integer.",
        ));
    }

    let ledger = output.join("results.jsonl");
    ensure_output_directory(&output.join("checkouts"))?;
    ensure_output_directory(&output.join("artifacts"))?;
    ensure_manifest(&output.join("manifest.json"), tasks)?;
    let receipts = read_receipts(&ledger)?;

    // A task counts as done only if its receipt says so *and* the artifacts it
    // names are still there; a receipt alone could outlive its output.
    let mut pending = Vec::new();
    let mut skipped = 0;
    for task in tasks {
        let receipt = receipts.get(&task.id.to_lowercase());
        let finished = receipt.is_some_and(|receipt| {
            receipt.status == ReceiptStatus::Completed
                && receipt.output_dir == attempt_dir(output, &task.id, receipt.attempt)
                && has_artifacts(&receipt.output_dir)
        });
        if finished {
            skipped += 1;
        } else {
            pending.push(task.clone());
        }
    }

    if pending.is_empty() {
        return Ok(MultiscanResult {
            total: tasks.len(),
            completed: skipped,
            failed: 0,
            skipped,
            results_path: ledger,
        });
    }

    let state = CampaignState {
        next: std::sync::atomic::AtomicUsize::new(0),
        completed: std::sync::atomic::AtomicUsize::new(skipped),
        failed: std::sync::atomic::AtomicUsize::new(0),
        ledger: std::sync::Mutex::new(()),
    };
    let workers = campaign.options.workers.min(pending.len());
    let mut failure: Option<Error> = None;

    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| scope.spawn(|| work(&pending, output, &ledger, &receipts, campaign, &state)))
            .collect();
        for handle in handles {
            let outcome = match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => Err(Error::puncode_security(
                    "A multiscan worker stopped unexpectedly.",
                )),
            };
            if let Err(error) = outcome {
                failure.get_or_insert(error);
            }
        }
    });

    if let Some(failure) = failure {
        return Err(failure);
    }
    Ok(MultiscanResult {
        total: tasks.len(),
        completed: state.completed.load(std::sync::atomic::Ordering::SeqCst),
        failed: state.failed.load(std::sync::atomic::Ordering::SeqCst),
        skipped,
        results_path: ledger,
    })
}

/// What the workers share.
struct CampaignState {
    next: std::sync::atomic::AtomicUsize,
    completed: std::sync::atomic::AtomicUsize,
    failed: std::sync::atomic::AtomicUsize,
    /// Serialises appends, so two workers cannot interleave a receipt.
    ledger: std::sync::Mutex<()>,
}

/// Where one attempt's artifacts live.
fn attempt_dir(output: &Path, id: &str, attempt: u32) -> PathBuf {
    output
        .join("artifacts")
        .join(id)
        .join(format!("attempt-{attempt}"))
}

/// Takes tasks until there are none left.
fn work(
    pending: &[MultiscanTask],
    output: &Path,
    ledger: &Path,
    receipts: &BTreeMap<String, MultiscanReceipt>,
    campaign: &Campaign<'_>,
    state: &CampaignState,
) -> Result<()> {
    use std::sync::atomic::Ordering;

    loop {
        let index = state.next.fetch_add(1, Ordering::SeqCst);
        let Some(task) = pending.get(index) else {
            return Ok(());
        };

        // Attempts continue where a previous run left off, so a resumed
        // campaign does not overwrite the output it already produced.
        let mut attempt = receipts
            .get(&task.id.to_lowercase())
            .map_or(0, |receipt| receipt.attempt);
        for retry in 0..campaign.options.max_attempts {
            attempt += 1;
            let scan_dir = attempt_dir(output, &task.id, attempt);
            let checkout = output.join("checkouts").join(&task.id);
            campaign.observer.on_progress(&MultiscanProgress {
                repository: task.id.clone(),
                status: ProgressStatus::Started,
                attempt,
                error: None,
            });

            let outcome = attempt_task(task, &checkout, &scan_dir, campaign);
            // The checkout is removed however the attempt ended: it is a copy
            // of an unreviewed repository and has no reason to outlive the scan.
            let _ = std::fs::remove_dir_all(&checkout);

            let (status, cost, error) = match outcome {
                Ok(outcome) => (ReceiptStatus::Completed, outcome.cost, None),
                Err(error) => (
                    ReceiptStatus::Failed,
                    None,
                    Some(redact_error(&error.to_string())),
                ),
            };

            {
                let _guard = state
                    .ledger
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                append_receipt(
                    ledger,
                    &MultiscanReceipt {
                        id: task.id.clone(),
                        repository: task.repository.clone(),
                        revision: task.revision.clone(),
                        mode: task.mode,
                        scope: task.scope.clone(),
                        status,
                        attempt,
                        output_dir: scan_dir,
                        cost,
                        error: error.clone(),
                    },
                )?;
            }
            campaign.observer.on_progress(&MultiscanProgress {
                repository: task.id.clone(),
                status: if status == ReceiptStatus::Completed {
                    ProgressStatus::Completed
                } else {
                    ProgressStatus::Failed
                },
                attempt,
                error: error.clone(),
            });

            if error.is_none() {
                state.completed.fetch_add(1, Ordering::SeqCst);
                break;
            }
            // Counted once the last attempt has also failed.
            if retry == campaign.options.max_attempts - 1 {
                state.failed.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Checks out one repository and scans it.
fn attempt_task(
    task: &MultiscanTask,
    checkout: &Path,
    scan_dir: &Path,
    campaign: &Campaign<'_>,
) -> Result<ScanOutcome> {
    if let Some(parent) = scan_dir.parent() {
        ensure_output_directory(parent)?;
    }
    // Removed first, so a checkout left by an interrupted attempt cannot be
    // mistaken for this one's.
    let _ = std::fs::remove_dir_all(checkout);
    ensure_output_directory(checkout)?;

    checkout_revision(
        task,
        checkout,
        campaign.options.github_host.as_deref(),
        campaign.environment,
        campaign.git,
    )?;

    // Checked after the checkout, not before: the scope is resolved through
    // whatever the repository actually contains, including any symbolic link
    // it ships that points outside itself.
    if let Some(scope) = &task.scope {
        require_scope_inside(checkout, scope)?;
    }

    let outcome = campaign.scanner.run(checkout, task, scan_dir)?;
    if !outcome.coverage_complete {
        return Err(Error::puncode_security(
            "Multiscan repository coverage is incomplete.",
        ));
    }
    Ok(outcome)
}

/// Refuses a scope that resolves outside the repository it belongs to.
fn require_scope_inside(checkout: &Path, scope: &str) -> Result<()> {
    let escaped = || Error::puncode_security("Multiscan scope escapes its repository.");
    let root = std::fs::canonicalize(checkout).map_err(|_| escaped())?;
    let scoped = std::fs::canonicalize(checkout.join(scope)).map_err(|_| escaped())?;
    if !scoped.starts_with(&root) {
        return Err(escaped());
    }
    Ok(())
}
