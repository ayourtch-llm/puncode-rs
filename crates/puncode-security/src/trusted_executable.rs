//! Resolving an executable that the scanned repository cannot influence.
//!
//! Ported from `src/trusted-executable.ts`.
//!
//! A scan runs tools such as `git` against a repository it does not trust. If
//! that repository can place a binary on `PATH` — directly, or through a
//! symlink from a directory that is on `PATH` — it could take over the scan.
//! This resolver therefore ignores every `PATH` entry and every candidate
//! binary that resolves inside the protected root, and hands back a sanitized
//! environment whose `PATH` has those entries removed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// An executable outside the protected root, with an environment safe to run
/// it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedExecutable {
    pub executable: PathBuf,
    pub environment: BTreeMap<String, String>,
}

/// The separator between `PATH` entries.
#[cfg(windows)]
const PATH_DELIMITER: char = ';';
#[cfg(not(windows))]
const PATH_DELIMITER: char = ':';

/// A suffix to try when looking for `candidate`, and whether a file found that
/// way can actually be executed directly.
struct Extension {
    suffix: &'static str,
    runnable: bool,
}

/// Windows resolves bare names through a list of extensions. Batch files are
/// listed because, while they cannot be launched directly, a batch file that
/// links into the repository still makes its `PATH` entry untrustworthy.
#[cfg(windows)]
fn extensions(candidate: &str) -> Vec<Extension> {
    let suffixed = candidate.to_ascii_lowercase();
    if suffixed.ends_with(".exe") || suffixed.ends_with(".com") {
        return vec![Extension {
            suffix: "",
            runnable: true,
        }];
    }
    vec![
        Extension {
            suffix: ".exe",
            runnable: true,
        },
        Extension {
            suffix: ".com",
            runnable: true,
        },
        Extension {
            suffix: ".bat",
            runnable: false,
        },
        Extension {
            suffix: ".cmd",
            runnable: false,
        },
        Extension {
            suffix: "",
            runnable: false,
        },
    ]
}

#[cfg(not(windows))]
fn extensions(_candidate: &str) -> Vec<Extension> {
    vec![Extension {
        suffix: "",
        runnable: true,
    }]
}

/// Finds `candidate` on the environment's `PATH`, refusing anything that
/// resolves inside `protected_root`.
///
/// Returns `None` when no trustworthy executable is found.
#[must_use]
pub fn resolve_trusted_executable(
    candidate: &str,
    environment: &BTreeMap<String, String>,
    protected_root: &Path,
) -> Option<TrustedExecutable> {
    let root = canonicalize(protected_root).unwrap_or_else(|| lexical_absolute(protected_root));

    let path_value = environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();

    // Trustworthy search directories, canonicalized and in order.
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in path_value.split(PATH_DELIMITER) {
        if entry.is_empty() || !Path::new(entry).is_absolute() {
            continue;
        }
        let Some(canonical) = canonicalize(Path::new(entry)) else {
            continue;
        };
        if is_within(&root, &canonical) || entries.contains(&canonical) {
            continue;
        }
        entries.push(canonical);
    }

    let path_like = candidate.contains('/') || candidate.contains('\\');
    let candidates: Vec<(Option<&PathBuf>, PathBuf, bool)> = if path_like {
        let resolved = absolute(Path::new(candidate)).unwrap_or_else(|| PathBuf::from(candidate));
        vec![(None, resolved, true)]
    } else {
        entries
            .iter()
            .flat_map(|entry| {
                extensions(candidate).into_iter().map(move |extension| {
                    (
                        Some(entry),
                        entry.join(format!("{candidate}{}", extension.suffix)),
                        extension.runnable,
                    )
                })
            })
            .collect()
    };

    // Scanning continues past the first match: a later candidate may reveal
    // that one of the search directories links into the repository, and that
    // directory must still be stripped from the sanitized PATH.
    let mut unsafe_entries: Vec<&PathBuf> = Vec::new();
    let mut executable: Option<PathBuf> = None;
    for (entry, path, runnable) in &candidates {
        let Some(canonical) = canonicalize(path) else {
            continue;
        };
        if is_within(&root, &canonical) {
            if let Some(entry) = entry
                && !unsafe_entries.contains(entry)
            {
                unsafe_entries.push(entry);
            }
            continue;
        }
        if !runnable || !is_executable(&canonical) {
            continue;
        }
        if !canonical.is_file() {
            continue;
        }
        if executable.is_none() {
            executable = Some(canonical);
        }
    }

    let executable = executable?;

    let mut sanitized: BTreeMap<String, String> = environment
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("PATH"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let trusted_path = entries
        .iter()
        .filter(|entry| !unsafe_entries.contains(entry))
        .map(|entry| entry.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(&PATH_DELIMITER.to_string());
    sanitized.insert("PATH".to_owned(), trusted_path);

    Some(TrustedExecutable {
        executable,
        environment: sanitized,
    })
}

fn canonicalize(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

fn absolute(path: &Path) -> Option<PathBuf> {
    std::path::absolute(path).ok()
}

/// An absolute path with `.` and `..` collapsed lexically.
///
/// Used only when the protected root cannot be canonicalized, where upstream
/// falls back to `resolve()`. `std::path::absolute` deliberately preserves
/// `..`, so a root such as `/a/b/../c` would not prefix-match canonical paths
/// under `/a/c` and everything there would look trustworthy.
fn lexical_absolute(path: &Path) -> PathBuf {
    use std::path::Component;

    let absolute = absolute(path).unwrap_or_else(|| path.to_path_buf());
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

/// Whether `candidate` is `root` or sits underneath it. Both are expected to be
/// canonical.
fn is_within(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

/// Whether the current process may execute `path`.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// Windows has no execute bit; upstream checks only for existence.
#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.exists()
}
