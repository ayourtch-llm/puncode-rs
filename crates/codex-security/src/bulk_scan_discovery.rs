//! Building a multiscan inventory from an owner's repositories.
//!
//! Ported from `src/bulk-scan-discovery.ts`.
//!
//! Listing repositories is the easy part; the value here is in what is left
//! out. Archived, forked and empty repositories are skipped, and anything not
//! pushed to recently is treated as out of scope — scanning a thousand dormant
//! repositories costs real money and tells nobody anything.
//!
//! Where the repositories come from is a [`RepositorySource`], so the GitHub
//! transport is not baked in. This port drives Codex through processes rather
//! than an async runtime, and pulling one in for a single listing call would be
//! a poor trade; a caller supplies whatever client it already has.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// How far back a repository must have been pushed to be worth scanning.
pub const ACTIVITY_WINDOW_DAYS: i64 = 90;

/// The longest identifier the multiscan inventory accepts.
const MAX_TASK_ID_LENGTH: usize = 128;

/// One repository as the source reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryNode {
    /// `owner/name`, as GitHub spells it.
    pub name_with_owner: String,
    /// When it was last pushed to, as an ISO timestamp.
    pub pushed_at: String,
    /// The commit its default branch points at, or `None` if it has no
    /// branches at all.
    pub default_branch_oid: Option<String>,
}

/// One page of repositories.
#[derive(Debug, Clone, Default)]
pub struct RepositoryPage {
    pub nodes: Vec<RepositoryNode>,
    /// The cursor for the next page, if there is one.
    pub end_cursor: Option<String>,
}

/// A repository worth scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRepository {
    pub full_name: String,
    pub url: String,
    pub revision: String,
}

/// Lists an owner's repositories, newest activity first.
///
/// The source is expected to exclude archived and forked repositories, as the
/// upstream query does, and to order results by descending push date — that
/// ordering is what lets discovery stop early rather than page through years
/// of dormant repositories.
pub trait RepositorySource {
    /// The organizations the signed-in account can list.
    fn organizations(&self) -> Result<Vec<String>>;

    /// The account itself, for when it belongs to no organization.
    ///
    /// A personal account is still something to scan, so an empty list of
    /// organizations is not the end of the search.
    fn signed_in_account(&self) -> Result<String> {
        Err(Error::codex_security(
            "This repository source cannot report a signed-in account.",
        ))
    }

    /// One page of `owner`'s repositories.
    fn repositories(&self, owner: &str, cursor: Option<&str>) -> Result<RepositoryPage>;
}

/// Collects the repositories worth scanning for `owner`.
///
/// Paging stops at the first repository older than `cutoff`, because the source
/// returns them newest first: everything after it is older still.
pub fn discover_repositories(
    source: &dyn RepositorySource,
    host: &str,
    owner: &str,
    cutoff: i64,
) -> Result<Vec<DiscoveredRepository>> {
    let mut repositories = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let page = source.repositories(owner, cursor.as_deref())?;
        for node in page.nodes {
            if parse_pushed_at(&node.pushed_at).is_none_or(|pushed| pushed < cutoff) {
                return Ok(repositories);
            }
            // No default branch means nothing has ever been committed.
            let Some(oid) = node.default_branch_oid else {
                continue;
            };
            repositories.push(DiscoveredRepository {
                url: format!("https://{host}/{}.git", node.name_with_owner),
                full_name: node.name_with_owner,
                revision: oid.to_lowercase(),
            });
        }
        match page.end_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(repositories),
        }
    }
}

/// The inventory identifier for a repository.
///
/// `owner/name` becomes `owner--name`, which is safe as a directory name. A
/// name too long for the inventory is truncated and given a digest of the full
/// name, so two long names under one owner cannot collide.
#[must_use]
pub fn repository_id(full_name: &str) -> String {
    // Only the first separator is replaced, matching upstream: the rest of a
    // name is not a path.
    let id = match full_name.split_once('/') {
        Some((owner, name)) => format!("{owner}--{name}"),
        None => full_name.to_owned(),
    };
    if id.chars().count() <= MAX_TASK_ID_LENGTH {
        return id;
    }
    let digest = format!("{:x}", Sha256::digest(full_name.as_bytes()));
    let head: String = id.chars().take(111).collect();
    format!("{head}-{}", &digest[..16])
}

/// Refuses an output directory that already holds a scan.
///
/// Writing an inventory over an existing one would orphan the results beside
/// it: the ledger would describe repositories the inventory no longer names.
pub fn validate_wizard_output(output_dir: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(output_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::codex_security(format!(
                "Unable to inspect {}",
                output_dir.display()
            ))
            .with_source(error));
        }
    };
    if !metadata.is_dir() {
        return Err(Error::codex_security(
            "The scan output must be a real directory.",
        ));
    }

    for name in ["repositories.csv", "manifest.json"] {
        if std::fs::symlink_metadata(output_dir.join(name)).is_ok() {
            return Err(Error::codex_security(
                "The selected output directory already contains a repository list or scan. \
                 Choose a new directory or resume the existing scan.",
            ));
        }
    }
    Ok(())
}

/// The inventory CSV for a set of repositories.
#[must_use]
pub fn inventory_csv(repositories: &[DiscoveredRepository]) -> String {
    let mut csv = String::from("id,repository,revision");
    for repository in repositories {
        csv.push('\n');
        csv.push_str(&csv_field(&repository_id(&repository.full_name)));
        csv.push(',');
        csv.push_str(&csv_field(&repository.url));
        csv.push(',');
        csv.push_str(&csv_field(&repository.revision));
    }
    csv.push('\n');
    csv
}

/// Writes the inventory, refusing to overwrite one that is already there.
pub fn write_inventory(path: &Path, repositories: &[DiscoveredRepository]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::codex_security(format!(
            "Unable to write the repository list to {}",
            path.display()
        ))
        .with_source(error)
    })?;
    file.write_all(inventory_csv(repositories).as_bytes())
        .map_err(|error| {
            Error::codex_security("Unable to write the repository list").with_source(error)
        })
}

/// Creates the directory the wizard will write into, private to its owner.
pub fn create_wizard_output(output_dir: &Path) -> Result<PathBuf> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output_dir).map_err(|error| {
        Error::codex_security(format!("Unable to create {}", output_dir.display()))
            .with_source(error)
    })?;
    Ok(output_dir.join("repositories.csv"))
}

/// Quotes a CSV field only when it needs quoting, as the upstream writer does.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        return format!("\"{}\"", value.replace('"', "\"\""));
    }
    value.to_owned()
}

/// Milliseconds since the epoch for an ISO timestamp.
fn parse_pushed_at(value: &str) -> Option<i64> {
    crate::scan_history_renderer::parse_iso_millis(value)
}
