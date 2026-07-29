//! Loading and validating the canonical scan contract.
//!
//! Ported from `src/contract.ts`.
//!
//! A scan directory is evidence produced by a plugin working on an untrusted
//! repository, and it is read back later, possibly on another machine. Loading
//! it is therefore a sequence of independent checks rather than a parse:
//!
//! 1. the scan directory is pinned by identity ([`files`]),
//! 2. each document is read within strict bounds ([`document`]),
//! 3. the plugin's schemas are bounded before use and then applied ([`schema`]),
//! 4. the documents are checked against each other ([`canonical`]),
//! 5. the manifest seal is verified against what is on disk ([`seal`]), and
//! 6. the result is checked against the request that produced it
//!    ([`expectation`]).
//!
//! Any one of these failing rejects the contract.

mod canonical;
pub(crate) mod datetime;
mod document;
mod expectation;
pub(crate) mod files;
mod schema;
mod seal;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{Error, Result};
use crate::models::{CoverageDocument, FindingsDocument, ScanManifest};

pub use expectation::ScanExpectation;

use canonical::validate_canonical_contract;
use document::{parse_json, read_bounded_document};
use expectation::validate_expectation;
use files::{
    ScanRoot, open_checked_scan_file, open_no_follow, require_checked_scan_file, require_scan_root,
    sha256_bytes, verify_scan_root,
};
use schema::{compile_validator, require_schema_complexity, validate_document};
use seal::validate_seal;

/// The contract documents, their schemas, and how large each may be.
///
/// The limits differ by an order of magnitude because a findings document
/// grows with the number of issues found, while a manifest does not.
const DOCUMENTS: [(&str, &str, u64); 3] = [
    (
        "scan-manifest.json",
        "scan-manifest.schema.json",
        16 * 1024 * 1024,
    ),
    ("findings.json", "findings.schema.json", 128 * 1024 * 1024),
    ("coverage.json", "coverage.schema.json", 32 * 1024 * 1024),
];

/// Schemas are configuration, not data, and are bounded far more tightly.
const MAX_SCHEMA_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

/// The three documents that make up a validated scan contract.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedContract {
    pub manifest: ScanManifest,
    pub findings: FindingsDocument,
    pub coverage: CoverageDocument,
}

/// Where to find the schemas, and optionally what the scan was asked to do.
#[derive(Debug, Clone)]
pub struct LoadContractOptions<'a> {
    /// The installed plugin directory holding `schemas/`.
    pub plugin_root: &'a Path,
    /// When given, the contract is also checked against this request.
    pub expectation: Option<&'a ScanExpectation>,
}

impl<'a> LoadContractOptions<'a> {
    #[must_use]
    pub fn new(plugin_root: &'a Path) -> Self {
        Self {
            plugin_root,
            expectation: None,
        }
    }

    #[must_use]
    pub fn with_expectation(mut self, expectation: &'a ScanExpectation) -> Self {
        self.expectation = Some(expectation);
        self
    }
}

/// Loads and fully validates the scan contract in `scan_directory`.
pub fn load_contract(
    scan_directory: &Path,
    options: &LoadContractOptions<'_>,
) -> Result<LoadedContract> {
    let scan_root = require_scan_root(scan_directory)?;
    let scan_dir = scan_root.path.clone();

    // Digests are taken from the bytes that are actually parsed, so a document
    // sealed as its own artifact cannot be verified against a different read.
    let mut document_digests: BTreeMap<String, String> = BTreeMap::new();
    let mut payloads: BTreeMap<&str, Value> = BTreeMap::new();
    for (filename, _, maximum) in DOCUMENTS {
        let payload = read_scan_json(
            &scan_dir,
            filename,
            maximum,
            &mut document_digests,
            Some(&scan_root),
        )?;
        payloads.insert(filename, payload);
    }

    for (filename, schema_name, _) in DOCUMENTS {
        let schema = read_schema_json(&options.plugin_root.join("schemas").join(schema_name))?;
        require_schema_complexity(&schema, schema_name)?;
        let validator = compile_validator(&schema, schema_name)?;
        validate_document(&validator, filename, &payloads[filename])?;
    }

    let manifest: ScanManifest = typed(&payloads["scan-manifest.json"], "scan-manifest.json")?;
    let findings: FindingsDocument = typed(&payloads["findings.json"], "findings.json")?;
    let coverage: CoverageDocument = typed(&payloads["coverage.json"], "coverage.json")?;

    if findings.scan_id != manifest.scan.id || coverage.scan_id != manifest.scan.id {
        return Err(Error::contract_validation(
            "Canonical contract scan IDs do not match.",
        ));
    }
    if coverage.include_paths != manifest.scan.scope.include_paths {
        return Err(Error::contract_validation(
            "Coverage include paths do not match the manifest scope.",
        ));
    }
    if coverage.exclude_paths != manifest.scan.scope.exclude_paths {
        return Err(Error::contract_validation(
            "Coverage exclude paths do not match the manifest scope.",
        ));
    }

    validate_canonical_contract(&manifest, &findings)?;
    validate_seal(
        &scan_dir,
        &manifest,
        &findings,
        &coverage,
        &document_digests,
        Some(&scan_root),
    )?;
    if let Some(expectation) = options.expectation {
        validate_expectation(&manifest, &coverage, expectation)?;
    }
    // Everything above described the directory as it was pinned; confirm it
    // still is, so a swap during the read invalidates the load.
    verify_scan_root(&scan_root)?;

    Ok(LoadedContract {
        manifest,
        findings,
        coverage,
    })
}

/// Resolves a scan-relative path to a checked regular file inside the scan
/// directory.
pub fn require_scan_file(
    scan_directory: &Path,
    relative_path: &str,
    context: &str,
) -> Result<PathBuf> {
    Ok(require_checked_scan_file(scan_directory, relative_path, context, None)?.path)
}

fn typed<T: serde::de::DeserializeOwned>(payload: &Value, filename: &str) -> Result<T> {
    serde_json::from_value(payload.clone()).map_err(|error| {
        Error::contract_validation(format!("{filename}: unexpected contract document shape."))
            .with_source(error)
    })
}

/// Reads one contract document, recording the digest of the bytes parsed.
fn read_scan_json(
    scan_dir: &Path,
    filename: &str,
    maximum: u64,
    document_digests: &mut BTreeMap<String, String>,
    expected_root: Option<&ScanRoot>,
) -> Result<Value> {
    let mut file = open_checked_scan_file(scan_dir, filename, filename, expected_root)?;
    let path = scan_dir.join(filename);
    let bytes = read_bounded_document(&mut file, &path, maximum)?;
    document_digests.insert(filename.to_owned(), sha256_bytes(&bytes));
    Ok(Value::Object(parse_json(&path, &bytes)?))
}

/// Reads a plugin schema, refusing symlinks and anything that changes while it
/// is being opened.
///
/// The schemas live outside the scan directory, so the scan-relative checks do
/// not apply; the identity checks still do.
fn read_schema_json(path: &Path) -> Result<Value> {
    let unreadable =
        || Error::contract_validation(format!("{}: unreadable JSON document.", path.display()));
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| unreadable())?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Error::contract_validation(format!(
                "Missing required contract document: {}",
                path.display()
            ));
        }
        unreadable()
    })?;
    if !parent_metadata.is_dir()
        || parent_metadata.is_symlink()
        || !metadata.is_file()
        || metadata.is_symlink()
    {
        return Err(unreadable());
    }

    let mut file = open_no_follow(path).map_err(|_| unreadable())?;
    let opened = file.metadata().map_err(|_| unreadable())?;
    let current_parent = std::fs::symlink_metadata(parent).map_err(|_| unreadable())?;
    let current = std::fs::symlink_metadata(path).map_err(|_| unreadable())?;
    if !opened.is_file()
        || !files::same_object(&opened, &metadata)
        || !current_parent.is_dir()
        || current_parent.is_symlink()
        || !files::same_object(&current_parent, &parent_metadata)
        || !current.is_file()
        || current.is_symlink()
        || !files::same_object(&current, &metadata)
    {
        return Err(unreadable());
    }

    let bytes = read_bounded_document(&mut file, path, MAX_SCHEMA_DOCUMENT_BYTES)?;
    Ok(Value::Object(parse_json(path, &bytes)?))
}
