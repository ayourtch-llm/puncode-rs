//! End-to-end tests for loading a scan contract.
//!
//! Ported from `tests-ts/contract.test.ts`. These run over a real copy of the
//! bundled example scan, against the real plugin schemas.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use puncode_security::contract::{LoadContractOptions, load_contract, require_scan_file};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The fixtures directory doubles as a plugin root: it contains `schemas/`.
fn plugin_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A writable copy of the bundled example scan.
fn example_scan() -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("temp dir");
    let scan = fs::canonicalize(root.path())
        .expect("canonical")
        .join("scan");
    fs::create_dir(&scan).expect("create scan directory");
    let source = plugin_root().join("completed-scan");
    for name in ["scan-manifest.json", "findings.json", "coverage.json"] {
        fs::copy(source.join(name), scan.join(name)).expect("copy document");
    }
    (root, scan)
}

fn options() -> LoadContractOptions<'static> {
    // Leaked so the borrow can outlive the helper; tests are short-lived.
    LoadContractOptions::new(Box::leak(plugin_root().into_boxed_path()))
}

fn load(scan: &Path) -> puncode_security::Result<puncode_security::LoadedContract> {
    load_contract(scan, &options())
}

fn rewrite(scan: &Path, name: &str, edit: impl FnOnce(&mut Value)) {
    let path = scan.join(name);
    let mut document: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    edit(&mut document);
    fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("serialize")
        ),
    )
    .expect("write");
}

/// Reseals the manifest so a document edit is not rejected by the seal before
/// the check under test runs.
fn reseal(scan: &Path) {
    let digests: Vec<(String, String)> = ["findings.json", "coverage.json"]
        .iter()
        .map(|name| {
            let bytes = fs::read(scan.join(name)).expect("read artifact");
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            ((*name).to_owned(), format!("{:x}", hasher.finalize()))
        })
        .collect();
    rewrite(scan, "scan-manifest.json", |manifest| {
        for artifact in manifest["scan"]["artifacts"]
            .as_array_mut()
            .expect("artifacts")
        {
            let path = artifact["path"].as_str().expect("path").to_owned();
            if let Some((_, digest)) = digests.iter().find(|(name, _)| *name == path) {
                artifact["sha256"] = json!(digest);
            }
        }
    });
}

#[test]
fn loads_the_unchanged_plugin_example() {
    let (_root, scan) = example_scan();

    let contract = load(&scan).expect("the example loads");

    assert_eq!(
        contract.manifest.document_type,
        "codex-security.scan-manifest"
    );
    assert_eq!(
        contract.manifest.scan.target.target_id,
        "target_sha256_example"
    );
    assert_eq!(
        contract.findings.findings[0].severity.level,
        puncode_security::SeverityLevel::High
    );
    assert_eq!(contract.coverage.mode.as_str(), "repository");
    assert_eq!(contract.findings.scan_id, contract.manifest.scan.id);
}

#[test]
fn accepts_a_scan_directory_beneath_a_symlinked_parent() {
    let root = TempDir::new().expect("temp dir");
    let base = fs::canonicalize(root.path()).expect("canonical");
    let parent = base.join("actual-parent");
    fs::create_dir(&parent).expect("create parent");
    let source = plugin_root().join("completed-scan");
    fs::create_dir(parent.join("scan")).expect("create scan");
    for name in ["scan-manifest.json", "findings.json", "coverage.json"] {
        fs::copy(source.join(name), parent.join("scan").join(name)).expect("copy");
    }
    std::os::unix::fs::symlink(&parent, base.join("linked-parent")).expect("symlink");

    assert!(load(&base.join("linked-parent").join("scan")).is_ok());
}

#[test]
fn rejects_a_symlinked_scan_directory() {
    let (_root, scan) = example_scan();
    let linked = scan.parent().expect("parent").join("linked-scan");
    std::os::unix::fs::symlink(&scan, &linked).expect("symlink");

    let error = load(&linked).expect_err("a symlinked scan directory is refused");

    assert_eq!(
        error.to_string(),
        "Scan directory must be an existing non-symlink directory."
    );
}

#[test]
fn rejects_a_missing_document() {
    let (_root, scan) = example_scan();
    fs::remove_file(scan.join("coverage.json")).expect("remove");

    let error = load(&scan).expect_err("a missing document is refused");

    assert!(error.to_string().contains("coverage.json"), "{error}");
}

#[test]
fn rejects_an_oversized_document() {
    for (name, maximum) in [
        ("scan-manifest.json", 16 * 1024 * 1024_u64),
        ("findings.json", 128 * 1024 * 1024),
        ("coverage.json", 32 * 1024 * 1024),
    ] {
        let (_root, scan) = example_scan();
        // Sparse, so the bound is exercised without writing the bytes.
        let file = fs::OpenOptions::new()
            .write(true)
            .open(scan.join(name))
            .expect("open");
        file.set_len(maximum + 1).expect("grow");

        let error = load(&scan).expect_err("an oversized document is refused");

        assert!(
            error
                .to_string()
                .contains(&format!("JSON document exceeds the {maximum}-byte limit")),
            "{name}: {error}"
        );
    }
}

#[test]
fn rejects_deeply_nested_json() {
    let (_root, scan) = example_scan();
    let depth = 258;
    fs::write(
        scan.join("findings.json"),
        format!(
            "{{\"overflow\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        ),
    )
    .expect("write");

    let error = load(&scan).expect_err("deep nesting is refused");

    assert!(
        error
            .to_string()
            .contains("JSON document exceeds the 256-level nesting limit"),
        "{error}"
    );
}

// The seal is what makes an edited artifact detectable.
#[test]
fn rejects_a_document_edited_after_sealing() {
    let (_root, scan) = example_scan();
    rewrite(&scan, "coverage.json", |coverage| {
        coverage["completeness"] = json!("partial");
    });

    let error = load(&scan).expect_err("an edited artifact is refused");

    assert!(
        error
            .to_string()
            .ends_with(": sealed artifact changed or is missing."),
        "{error}"
    );
}

#[test]
fn rejects_mismatched_scan_ids() {
    let (_root, scan) = example_scan();
    rewrite(&scan, "coverage.json", |coverage| {
        coverage["scanId"] = json!("scan_example_002");
    });
    reseal(&scan);

    let error = load(&scan).expect_err("mismatched scan ids are refused");

    assert_eq!(
        error.to_string(),
        "Canonical contract scan IDs do not match."
    );
}

#[test]
fn rejects_coverage_scope_that_disagrees_with_the_manifest() {
    let (_root, scan) = example_scan();
    rewrite(&scan, "coverage.json", |coverage| {
        coverage["includePaths"] = json!(["docs/"]);
    });
    reseal(&scan);

    let error = load(&scan).expect_err("a scope mismatch is refused");

    assert_eq!(
        error.to_string(),
        "Coverage include paths do not match the manifest scope."
    );
}

#[test]
fn rejects_a_forged_finding_identity() {
    let (_root, scan) = example_scan();
    rewrite(&scan, "findings.json", |findings| {
        findings["findings"][0]["findingId"] = json!("csf_000000000000000000000000");
    });
    reseal(&scan);

    let error = load(&scan).expect_err("a forged finding is refused");

    assert_eq!(
        error.to_string(),
        "findings.findings[0].findingId: does not match derived fingerprint identity."
    );
}

#[test]
fn rejects_a_document_that_violates_its_schema() {
    let (_root, scan) = example_scan();
    rewrite(&scan, "findings.json", |findings| {
        findings["findings"][0]["severity"]["level"] = json!("catastrophic");
    });
    reseal(&scan);

    let error = load(&scan).expect_err("a schema violation is refused");

    assert!(error.to_string().starts_with("findings.json:"), "{error}");
    assert!(
        error.to_string().contains("schema validation failed"),
        "{error}"
    );
}

#[test]
fn rejects_a_missing_schema() {
    let (_root, scan) = example_scan();
    let empty = TempDir::new().expect("temp dir");
    fs::create_dir(empty.path().join("schemas")).expect("create schemas");
    let options = LoadContractOptions::new(empty.path());

    let error = load_contract(&scan, &options).expect_err("a missing schema is refused");

    assert!(
        error
            .to_string()
            .starts_with("Missing required contract document:"),
        "{error}"
    );
}

#[test]
fn resolves_a_scan_relative_file() {
    let (_root, scan) = example_scan();

    let path = require_scan_file(&scan, "findings.json", "findings").expect("resolves");

    assert_eq!(path, scan.join("findings.json"));
}

#[test]
fn refuses_a_scan_relative_file_that_escapes() {
    let (_root, scan) = example_scan();

    for relative in ["../outside.json", "/etc/passwd"] {
        assert!(
            require_scan_file(&scan, relative, "artifact").is_err(),
            "{relative} should be refused"
        );
    }
}
