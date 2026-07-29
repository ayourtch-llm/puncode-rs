//! Resolving and validating what a scan will look at.
//!
//! Ported from `src/targets.ts`.
//!
//! Two deliberate differences from upstream:
//!
//! * The process environment is passed in rather than read from a global. It is
//!   needed for `PATH` resolution and `HOME` expansion, and threading it makes
//!   the trust boundary explicit — and testable without mutating process state.
//! * `AbortSignal` is not threaded through. These operations are short git
//!   invocations and filesystem lookups; cancellation lives at the scan level.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::trusted_executable::resolve_trusted_executable;

/// Environment variables, as seen by the scan.
pub type ProcessEnvironment = BTreeMap<String, String>;

/// Git variables that would redirect git away from the repository being
/// scanned, making the target ambiguous.
const UNSUPPORTED_GIT_ENVIRONMENT: [&str; 7] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_REPLACE_REF_BASE",
];

/// How thoroughly to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    #[default]
    Standard,
    Deep,
}

impl ScanMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }
}

/// Whether a diff compares two refs or a ref against the working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTargetKind {
    Refs,
    WorkingTree,
}

/// A diff to scan.
///
/// Constructed only through [`DiffTarget::refs`] and
/// [`DiffTarget::working_tree`], which validate their inputs. Upstream freezes
/// the object and re-validates it during normalization because JavaScript
/// callers can forge one; private fields make that unnecessary here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffTarget {
    kind: DiffTargetKind,
    base: String,
    head: Option<String>,
}

impl DiffTarget {
    /// A diff between two refs. `head` defaults to `HEAD`.
    pub fn refs(base: impl Into<String>, head: Option<String>) -> Result<Self> {
        let base = base.into();
        let head = head.unwrap_or_else(|| "HEAD".to_owned());
        if base.is_empty() {
            return Err(Error::invalid_target(
                "The diff base ref must be non-empty.",
            ));
        }
        if head.is_empty() {
            return Err(Error::invalid_target(
                "Git diff refs must include a non-empty head ref.",
            ));
        }
        Ok(Self {
            kind: DiffTargetKind::Refs,
            base,
            head: Some(head),
        })
    }

    /// A diff between a ref and the working tree. `base` defaults to `HEAD`.
    pub fn working_tree(base: Option<String>) -> Result<Self> {
        let base = base.unwrap_or_else(|| "HEAD".to_owned());
        if base.is_empty() {
            return Err(Error::invalid_target(
                "The diff base ref must be non-empty.",
            ));
        }
        Ok(Self {
            kind: DiffTargetKind::WorkingTree,
            base,
            head: None,
        })
    }

    #[must_use]
    pub fn kind(&self) -> DiffTargetKind {
        self.kind
    }

    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    #[must_use]
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }
}

/// What a scan was asked to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    /// The whole repository.
    Repository,
    /// A diff.
    Diff(DiffTarget),
    /// Specific paths within the repository.
    Paths(Vec<String>),
}

/// The kind of target after normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizedTargetKind {
    Repository,
    Paths,
    Refs,
    WorkingTree,
}

impl NormalizedTargetKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Paths => "paths",
            Self::Refs => "refs",
            Self::WorkingTree => "working_tree",
        }
    }
}

/// A target resolved against a repository, with refs bound to commit IDs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizedTarget {
    pub kind: Option<NormalizedTargetKind>,
    /// Repository-relative paths, using `/` separators.
    pub paths: Vec<String>,
    pub base: Option<String>,
    pub head: Option<String>,
    /// The ref as the caller wrote it, before resolution.
    pub base_ref: Option<String>,
    pub head_ref: Option<String>,
}

impl NormalizedTarget {
    fn of_kind(kind: NormalizedTargetKind) -> Self {
        Self {
            kind: Some(kind),
            ..Self::default()
        }
    }
}

/// Reads the current process environment.
#[must_use]
pub fn process_environment() -> ProcessEnvironment {
    std::env::vars().collect()
}

/// Expands a leading `~`, then makes the path absolute.
#[must_use]
pub fn resolve_repository_path(repository: &str, environment: &ProcessEnvironment) -> PathBuf {
    lexical_absolute(&expand_home(repository, environment))
}

/// Resolves a repository path to a canonical directory.
pub fn normalize_repository(repository: &str, environment: &ProcessEnvironment) -> Result<PathBuf> {
    let candidate = resolve_repository_path(repository, environment);
    let canonical = std::fs::canonicalize(&candidate)
        .ok()
        .filter(|path| path.is_dir())
        .ok_or_else(|| {
            Error::invalid_target(format!(
                "Repository is not a directory: {}",
                candidate.display()
            ))
        })?;
    Ok(canonical)
}

/// The root of the git worktree containing `repository`, if there is one.
#[must_use]
pub fn enclosing_git_worktree_root(
    repository: &Path,
    environment: &ProcessEnvironment,
) -> Option<PathBuf> {
    let root = git_output(repository, &["rev-parse", "--show-toplevel"], environment).ok()?;
    std::fs::canonicalize(root).ok()
}

/// Rejects git environment variables that would point git somewhere other than
/// the repository under scan.
pub fn validated_git_environment(environment: &ProcessEnvironment) -> Result<()> {
    for (name, value) in environment {
        let unsupported = UNSUPPORTED_GIT_ENVIRONMENT
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate));
        if unsupported && !value.trim().is_empty() {
            return Err(Error::invalid_target(format!(
                "{name} is not supported for Codex Security scans."
            )));
        }
    }
    Ok(())
}

/// The commit `HEAD` points at, or `None` outside a repository.
#[must_use]
pub fn repository_revision(repository: &Path, environment: &ProcessEnvironment) -> Option<String> {
    git_output(
        repository,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        environment,
    )
    .ok()
}

/// Rejects a mode the target cannot support.
pub fn validate_mode(target: &NormalizedTarget, mode: ScanMode) -> Result<()> {
    let diff = matches!(
        target.kind,
        Some(NormalizedTargetKind::Refs | NormalizedTargetKind::WorkingTree)
    );
    if mode == ScanMode::Deep && diff {
        return Err(Error::invalid_target(
            "Deep mode supports repository and path targets only.",
        ));
    }
    Ok(())
}

/// Resolves `target` against `repository`, binding refs to commit IDs and paths
/// to repository-relative paths.
pub fn normalize_target(
    repository: &str,
    target: &ScanTarget,
    environment: &ProcessEnvironment,
) -> Result<NormalizedTarget> {
    let root = normalize_repository(repository, environment)?;

    match target {
        ScanTarget::Repository => Ok(NormalizedTarget::of_kind(NormalizedTargetKind::Repository)),
        ScanTarget::Diff(diff) => normalize_diff(&root, diff, environment),
        ScanTarget::Paths(paths) => normalize_paths(&root, paths, environment),
    }
}

fn normalize_diff(
    root: &Path,
    diff: &DiffTarget,
    environment: &ProcessEnvironment,
) -> Result<NormalizedTarget> {
    require_git_repository(root, environment)?;
    let base = resolve_git_ref(root, &diff.base, environment)?;

    match diff.kind {
        DiffTargetKind::Refs => {
            let head_ref = diff.head.as_deref().unwrap_or("HEAD");
            Ok(NormalizedTarget {
                kind: Some(NormalizedTargetKind::Refs),
                paths: Vec::new(),
                base: Some(base),
                head: Some(resolve_git_ref(root, head_ref, environment)?),
                base_ref: Some(diff.base.clone()),
                head_ref: Some(head_ref.to_owned()),
            })
        }
        DiffTargetKind::WorkingTree => Ok(NormalizedTarget {
            kind: Some(NormalizedTargetKind::WorkingTree),
            paths: Vec::new(),
            base: Some(base),
            head: Some(resolve_git_ref(root, "HEAD", environment)?),
            base_ref: Some(diff.base.clone()),
            head_ref: Some("HEAD".to_owned()),
        }),
    }
}

fn normalize_paths(
    root: &Path,
    targets: &[String],
    environment: &ProcessEnvironment,
) -> Result<NormalizedTarget> {
    if targets.is_empty() {
        return Err(Error::invalid_target(
            "A path scan target must contain at least one path.",
        ));
    }

    let mut paths: Vec<String> = Vec::new();
    for value in targets {
        if value.is_empty() {
            return Err(Error::invalid_target(
                "Path scan targets must not contain an empty path.",
            ));
        }
        let expanded = expand_home(value, environment);
        let candidate = if expanded.is_absolute() {
            lexical_absolute(&expanded)
        } else {
            lexical_absolute(&root.join(&expanded))
        };

        let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
            Error::invalid_target(format!("Path target does not exist: {value}")).with_source(error)
        })?;
        let relative = canonical.strip_prefix(root).map_err(|_| {
            Error::invalid_target(format!("Path target is outside the repository: {value}"))
        })?;

        let normalized = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let normalized = if normalized.is_empty() {
            ".".to_owned()
        } else {
            normalized
        };
        if !paths.contains(&normalized) {
            paths.push(normalized);
        }
    }

    Ok(NormalizedTarget {
        kind: Some(NormalizedTargetKind::Paths),
        paths,
        ..NormalizedTarget::default()
    })
}

/// Diff targets are resolved against the worktree root, not a subdirectory:
/// git would silently widen the diff to the whole worktree otherwise.
fn require_git_repository(repository: &Path, environment: &ProcessEnvironment) -> Result<()> {
    let root = git_output(repository, &["rev-parse", "--show-toplevel"], environment).map_err(
        |error| {
            Error::invalid_target(format!(
                "Diff targets require a Git repository: {}",
                repository.display()
            ))
            .with_source(error)
        },
    )?;
    let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| PathBuf::from(&root));
    if canonical_root != repository {
        return Err(Error::invalid_target(format!(
            "Diff target repository must be the Git worktree root: {}",
            canonical_root.display()
        )));
    }
    Ok(())
}

fn resolve_git_ref(
    repository: &Path,
    reference: &str,
    environment: &ProcessEnvironment,
) -> Result<String> {
    git_output(
        repository,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{reference}^{{commit}}"),
        ],
        environment,
    )
    .map_err(|error| {
        Error::invalid_target(format!("unknown Git ref: {reference}")).with_source(error)
    })
}

/// Runs git in `repository` and returns its trimmed stdout.
///
/// The executable is resolved with the repository treated as untrusted, so a
/// `git` shim committed to the repository is never run.
fn git_output(
    repository: &Path,
    args: &[&str],
    environment: &ProcessEnvironment,
) -> Result<String> {
    let protected_root = outermost_git_marker_root(repository);
    let command = resolve_trusted_executable(
        "git",
        &isolated_git_environment(environment),
        &protected_root,
    )
    .ok_or_else(|| Error::invalid_target("Git is not available on a trusted PATH."))?;

    let output = Command::new(&command.executable)
        .arg("-C")
        .arg(repository)
        .args(args)
        .env_clear()
        .envs(&command.environment)
        .output()
        .map_err(|error| {
            Error::invalid_target(format!("Could not run git: {error}")).with_source(error)
        })?;

    if !output.status.success() {
        return Err(Error::invalid_target(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The outermost ancestor of `repository` that carries a `.git` marker.
///
/// Everything at or below that directory is repository-controlled, so it is the
/// root that must be excluded when resolving `git` itself.
fn outermost_git_marker_root(repository: &Path) -> PathBuf {
    let mut current = repository.to_path_buf();
    let mut root = repository.to_path_buf();
    loop {
        if std::fs::symlink_metadata(current.join(".git")).is_ok() {
            root.clone_from(&current);
        }
        let Some(parent) = current.parent() else {
            return root;
        };
        if parent == current {
            return root;
        }
        current = parent.to_path_buf();
    }
}

/// The environment with every `GIT_*` variable removed.
fn isolated_git_environment(environment: &ProcessEnvironment) -> ProcessEnvironment {
    environment
        .iter()
        .filter(|(name, _)| !name.to_ascii_uppercase().starts_with("GIT_"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Expands a leading `~`, collapsing any run of separators after it.
pub(crate) fn expand_home(value: &str, environment: &ProcessEnvironment) -> PathBuf {
    let Some(home) = home_directory(environment) else {
        return PathBuf::from(value);
    };
    if value == "~" {
        return home;
    }
    if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        let rest = rest.trim_start_matches(['/', '\\']);
        return home.join(rest);
    }
    PathBuf::from(value)
}

fn home_directory(environment: &ProcessEnvironment) -> Option<PathBuf> {
    environment
        .get("HOME")
        .or_else(|| environment.get("USERPROFILE"))
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(std::env::home_dir)
}

/// An absolute path with `.` and `..` collapsed lexically, matching Node's
/// `path.resolve`.
pub(crate) fn lexical_absolute(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component);
                }
            }
            other => normalized.push(other),
        }
    }
    normalized
}
