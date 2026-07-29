//! Behavior tests for building a multiscan inventory from GitHub.
//!
//! Ported from `tests-ts/bulk-scan-discovery.test.ts`. The GitHub transport is
//! a [`RepositorySource`], so every case here drives a fake one: what is being
//! tested is which repositories are selected and what is written down, not how
//! they were fetched.

#![cfg(unix)]

use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use puncode_security::bulk_scan_discovery::{
    DiscoveredRepository, RepositoryNode, RepositoryPage, RepositorySource, create_wizard_output,
    discover_repositories, inventory_csv, repository_id, validate_wizard_output, write_inventory,
};
use puncode_security::multiscan::parse_inventory;
use puncode_security::targets::ScanMode;
use tempfile::TempDir;

/// Milliseconds for an ISO date, so cutoffs read as dates in the tests.
fn at(timestamp: &str) -> i64 {
    let (date, time) = timestamp.split_once('T').unwrap_or((timestamp, "00:00:00"));
    let parts: Vec<i64> = date
        .split('-')
        .map(|value| value.parse().expect("a date part"))
        .collect();
    let clock: Vec<i64> = time
        .trim_end_matches('Z')
        .split(':')
        .map(|value| value.parse().expect("a time part"))
        .collect();
    let (year, month, day) = (parts[0], parts[1], parts[2]);
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    ((days * 86_400) + clock[0] * 3_600 + clock[1] * 60 + clock[2]) * 1_000
}

/// A source that hands out prepared pages and records what it was asked for.
struct FakeSource {
    pages: RefCell<Vec<RepositoryPage>>,
    requests: RefCell<Vec<Option<String>>>,
    organizations: Vec<String>,
}

impl FakeSource {
    fn new(pages: Vec<RepositoryPage>) -> Self {
        Self {
            pages: RefCell::new(pages),
            requests: RefCell::new(Vec::new()),
            organizations: Vec::new(),
        }
    }
}

impl RepositorySource for FakeSource {
    fn organizations(&self) -> puncode_security::Result<Vec<String>> {
        Ok(self.organizations.clone())
    }

    fn repositories(
        &self,
        _owner: &str,
        cursor: Option<&str>,
    ) -> puncode_security::Result<RepositoryPage> {
        self.requests.borrow_mut().push(cursor.map(str::to_owned));
        let mut pages = self.pages.borrow_mut();
        if pages.is_empty() {
            return Ok(RepositoryPage::default());
        }
        Ok(pages.remove(0))
    }
}

fn node(name: &str, pushed_at: &str, oid: Option<&str>) -> RepositoryNode {
    RepositoryNode {
        name_with_owner: name.to_owned(),
        pushed_at: pushed_at.to_owned(),
        default_branch_oid: oid.map(str::to_owned),
    }
}

const OID: &str = "0123456789ABCDEF0123456789abcdef01234567";

#[test]
fn discovers_active_repositories() {
    let source = FakeSource::new(vec![RepositoryPage {
        nodes: vec![
            node("acme/payments", "2026-07-01T00:00:00Z", Some(OID)),
            node("acme/ledger", "2026-06-01T00:00:00Z", Some(OID)),
        ],
        end_cursor: None,
    }]);

    let found = discover_repositories(&source, "github.com", "acme", at("2026-01-01"))
        .expect("discovery succeeds");

    assert_eq!(
        found,
        vec![
            DiscoveredRepository {
                full_name: "acme/payments".to_owned(),
                url: "https://github.com/acme/payments.git".to_owned(),
                // Stored in one casing, as the inventory requires.
                revision: OID.to_lowercase(),
            },
            DiscoveredRepository {
                full_name: "acme/ledger".to_owned(),
                url: "https://github.com/acme/ledger.git".to_owned(),
                revision: OID.to_lowercase(),
            },
        ]
    );
}

#[test]
fn pages_until_there_is_nothing_left() {
    let source = FakeSource::new(vec![
        RepositoryPage {
            nodes: vec![node("acme/one", "2026-07-01T00:00:00Z", Some(OID))],
            end_cursor: Some("cursor-1".to_owned()),
        },
        RepositoryPage {
            nodes: vec![node("acme/two", "2026-06-01T00:00:00Z", Some(OID))],
            end_cursor: None,
        },
    ]);

    let found = discover_repositories(&source, "github.com", "acme", at("2026-01-01"))
        .expect("discovery succeeds");

    assert_eq!(found.len(), 2);
    assert_eq!(
        source.requests.borrow().as_slice(),
        [None, Some("cursor-1".to_owned())],
        "the second page follows the cursor"
    );
}

// Repositories arrive newest first, so the first one older than the cutoff
// means everything after it is older still: paging stops rather than walking
// years of dormant repositories.
#[test]
fn stops_at_the_first_repository_older_than_the_cutoff() {
    let source = FakeSource::new(vec![
        RepositoryPage {
            nodes: vec![
                node("acme/active", "2026-07-01T00:00:00Z", Some(OID)),
                node("acme/dormant", "2025-01-01T00:00:00Z", Some(OID)),
                node("acme/never-reached", "2026-07-01T00:00:00Z", Some(OID)),
            ],
            end_cursor: Some("cursor-1".to_owned()),
        },
        RepositoryPage {
            nodes: vec![node("acme/later-page", "2026-07-01T00:00:00Z", Some(OID))],
            end_cursor: None,
        },
    ]);

    let found = discover_repositories(&source, "github.com", "acme", at("2026-04-01"))
        .expect("discovery succeeds");

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].full_name, "acme/active");
    assert_eq!(
        source.requests.borrow().len(),
        1,
        "no further page should be fetched"
    );
}

// Nothing has ever been committed, so there is nothing to scan.
#[test]
fn skips_a_repository_with_no_default_branch() {
    let source = FakeSource::new(vec![RepositoryPage {
        nodes: vec![
            node("acme/empty", "2026-07-01T00:00:00Z", None),
            node("acme/payments", "2026-07-01T00:00:00Z", Some(OID)),
        ],
        end_cursor: None,
    }]);

    let found = discover_repositories(&source, "github.com", "acme", at("2026-01-01"))
        .expect("discovery succeeds");

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].full_name, "acme/payments");
}

#[test]
fn builds_urls_for_an_enterprise_host() {
    let source = FakeSource::new(vec![RepositoryPage {
        nodes: vec![node("acme/payments", "2026-07-01T00:00:00Z", Some(OID))],
        end_cursor: None,
    }]);

    let found = discover_repositories(&source, "github.example.com", "acme", at("2026-01-01"))
        .expect("discovery succeeds");

    assert_eq!(found[0].url, "https://github.example.com/acme/payments.git");
}

#[test]
fn reports_nothing_when_no_repository_is_active() {
    let source = FakeSource::new(vec![RepositoryPage {
        nodes: vec![node("acme/dormant", "2020-01-01T00:00:00Z", Some(OID))],
        end_cursor: None,
    }]);

    let found = discover_repositories(&source, "github.com", "acme", at("2026-01-01"))
        .expect("discovery succeeds");

    assert!(found.is_empty());
}

// ---------------------------------------------------------------------------
// repository_id
// ---------------------------------------------------------------------------

#[test]
fn derives_a_safe_identifier_from_a_repository_name() {
    assert_eq!(repository_id("acme/payments"), "acme--payments");
}

// Only the first separator is a path separator; the rest of a name is not.
#[test]
fn replaces_only_the_first_separator() {
    assert_eq!(repository_id("acme/group/nested"), "acme--group/nested");
}

// Two long names under one owner must not collide, so the truncated identifier
// carries a digest of the full name.
#[test]
fn distinguishes_two_names_too_long_for_the_inventory() {
    let owner = "a".repeat(60);
    let first = format!("{owner}/{}", "b".repeat(100));
    let second = format!("{owner}/{}", "c".repeat(100));

    let (first_id, second_id) = (repository_id(&first), repository_id(&second));

    assert_ne!(first_id, second_id);
    assert!(first_id.chars().count() <= 128, "{}", first_id.len());
    assert!(second_id.chars().count() <= 128);
}

#[test]
fn derives_a_stable_identifier() {
    let name = format!("{}/{}", "a".repeat(60), "b".repeat(100));

    assert_eq!(repository_id(&name), repository_id(&name));
}

// The identifier is what the inventory validates, so it must satisfy it.
#[test]
fn derives_identifiers_the_inventory_accepts() {
    let repositories = [
        DiscoveredRepository {
            full_name: "acme/payments".to_owned(),
            url: "https://github.com/acme/payments.git".to_owned(),
            revision: OID.to_lowercase(),
        },
        DiscoveredRepository {
            full_name: format!("{}/{}", "a".repeat(60), "b".repeat(100)),
            url: "https://github.com/long/name.git".to_owned(),
            revision: OID.to_lowercase(),
        },
    ];

    let tasks = parse_inventory(
        &inventory_csv(&repositories),
        Path::new("/campaign"),
        ScanMode::Standard,
    )
    .expect("the inventory it writes is one it can read back");

    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0].id, "acme--payments");
}

// ---------------------------------------------------------------------------
// Writing the inventory
// ---------------------------------------------------------------------------

#[test]
fn writes_a_header_and_one_row_per_repository() {
    let repositories = [DiscoveredRepository {
        full_name: "acme/payments".to_owned(),
        url: "https://github.com/acme/payments.git".to_owned(),
        revision: OID.to_lowercase(),
    }];

    let csv = inventory_csv(&repositories);

    assert_eq!(
        csv,
        format!(
            "id,repository,revision\nacme--payments,https://github.com/acme/payments.git,{}\n",
            OID.to_lowercase()
        )
    );
}

#[test]
fn writes_an_empty_inventory_as_a_bare_header() {
    assert_eq!(inventory_csv(&[]), "id,repository,revision\n");
}

#[test]
fn keeps_the_inventory_private() {
    let root = TempDir::new().expect("root");
    let path = root.path().join("repositories.csv");

    write_inventory(&path, &[]).expect("written");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn refuses_to_overwrite_an_existing_inventory() {
    let root = TempDir::new().expect("root");
    let path = root.path().join("repositories.csv");
    write_inventory(&path, &[]).expect("first");

    write_inventory(&path, &[]).expect_err("the second is refused");
}

#[test]
fn creates_a_private_output_directory() {
    let root = TempDir::new().expect("root");
    let output = root.path().join("security-scans");

    let inventory = create_wizard_output(&output).expect("created");

    assert_eq!(inventory, output.join("repositories.csv"));
    let mode = std::fs::metadata(&output)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

// ---------------------------------------------------------------------------
// validate_wizard_output
// ---------------------------------------------------------------------------

#[test]
fn accepts_an_output_directory_that_is_not_there_yet() {
    let root = TempDir::new().expect("root");

    validate_wizard_output(&root.path().join("new")).expect("nothing is in the way");
}

#[test]
fn accepts_an_empty_output_directory() {
    let root = TempDir::new().expect("root");

    validate_wizard_output(root.path()).expect("nothing is in the way");
}

// Writing an inventory over an existing one would orphan the results beside
// it: the ledger would describe repositories the inventory no longer names.
#[test]
fn refuses_an_output_directory_that_already_holds_a_scan() {
    for existing in ["repositories.csv", "manifest.json"] {
        let root = TempDir::new().expect("root");
        std::fs::write(root.path().join(existing), "").expect("write");

        let error = validate_wizard_output(root.path()).expect_err("refused");

        assert!(
            error
                .to_string()
                .contains("already contains a repository list"),
            "{existing}: {error}"
        );
    }
}

#[test]
fn refuses_an_output_path_that_is_not_a_directory() {
    let root = TempDir::new().expect("root");
    let path = root.path().join("a-file");
    std::fs::write(&path, "").expect("write");

    let error = validate_wizard_output(&path).expect_err("refused");

    assert!(
        error.to_string().contains("must be a real directory"),
        "{error}"
    );
}

// A link could point the scan's output somewhere else entirely.
#[test]
fn refuses_an_output_path_that_is_a_symbolic_link() {
    let root = TempDir::new().expect("root");
    let target = root.path().join("elsewhere");
    std::fs::create_dir(&target).expect("create");
    let link = root.path().join("output");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let error = validate_wizard_output(&link).expect_err("refused");

    assert!(
        error.to_string().contains("must be a real directory"),
        "{error}"
    );
}
