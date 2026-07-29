//! Differential tests for the scan prompt.
//!
//! Every expected prompt was produced by running the TypeScript implementation
//! with the same inputs. Regenerate with `probe-prompt.ts`.
//!
//! The prompt is compared verbatim: it pins the identifiers a scan must not
//! invent, so a dropped or reworded line is a behavior change, not a cosmetic
//! one.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use codex_security::api::{scan_prompt, skill_name_for, target_instruction};
use codex_security::error::ProtectedScanPathKind;
use codex_security::targets::{NormalizedTarget, NormalizedTargetKind, ScanMode};
use serde::Deserialize;
use tempfile::TempDir;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
    #[serde(rename = "missingSkillError")]
    missing_skill_error: String,
}

#[derive(Deserialize)]
struct Case {
    target: String,
    mode: String,
    #[serde(rename = "hasConfigPath")]
    has_config_path: bool,
    #[serde(rename = "hasKnowledgeBase")]
    has_knowledge_base: bool,
    skill: String,
    #[serde(rename = "targetInstruction")]
    target_instruction: String,
    prompt: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/scan-prompts.json")).expect("fixture parses")
}

/// A plugin directory with every scan skill installed.
/// Whether a line is the port's deliberate addition to upstream's prompt.
fn is_scope_extension(line: &str) -> bool {
    (line.starts_with("Use exactly [") && line.contains("scan.scope."))
        || line.starts_with("Before writing scan-manifest.json, read the workbench")
        || line.starts_with("From the same contract,")
}

fn plugin_root() -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("temp dir");
    let root = std::fs::canonicalize(temp.path()).expect("canonical");
    for skill in ["security-scan", "deep-security-scan", "security-diff-scan"] {
        let directory = root.join("skills").join(skill);
        std::fs::create_dir_all(&directory).expect("create skill directory");
        std::fs::write(directory.join("SKILL.md"), b"# skill\n").expect("write skill");
    }
    (temp, root)
}

fn target_named(name: &str) -> NormalizedTarget {
    match name {
        "repository" => NormalizedTarget {
            kind: Some(NormalizedTargetKind::Repository),
            ..NormalizedTarget::default()
        },
        "paths" => NormalizedTarget {
            kind: Some(NormalizedTargetKind::Paths),
            paths: vec!["src".to_owned(), "docs".to_owned()],
            ..NormalizedTarget::default()
        },
        "refs" => NormalizedTarget {
            kind: Some(NormalizedTargetKind::Refs),
            base: Some("aaa111".to_owned()),
            head: Some("bbb222".to_owned()),
            base_ref: Some("main".to_owned()),
            head_ref: Some("feature".to_owned()),
            ..NormalizedTarget::default()
        },
        _ => NormalizedTarget {
            kind: Some(NormalizedTargetKind::WorkingTree),
            base: Some("ccc333".to_owned()),
            head: Some("ddd444".to_owned()),
            base_ref: Some("HEAD".to_owned()),
            head_ref: Some("HEAD".to_owned()),
            ..NormalizedTarget::default()
        },
    }
}

fn mode_named(name: &str) -> ScanMode {
    if name == "deep" {
        ScanMode::Deep
    } else {
        ScanMode::Standard
    }
}

#[test]
fn builds_prompts_identically_to_the_typescript_implementation() {
    let (_temp, root) = plugin_root();
    let fixture = fixture();
    assert_eq!(fixture.cases.len(), 32, "every combination is compared");

    let mut mismatches = Vec::new();
    for case in &fixture.cases {
        let target = target_named(&case.target);
        let mode = mode_named(&case.mode);
        let actual = scan_prompt(
            &root,
            &target,
            mode,
            case.has_config_path,
            case.has_knowledge_base,
        )
        .expect("prompt builds");

        // The port adds scope instructions upstream does not, because the
        // workbench enforces a scope it never states and a weaker model guesses
        // differently every run. Removing exactly those lines leaves what
        // upstream produces, so every other divergence is still caught.
        let actual: String = actual
            .lines()
            .filter(|line| !is_scope_extension(line))
            .collect::<Vec<_>>()
            .join("\n");

        if actual != case.prompt {
            let label = format!(
                "{}/{}/config={}/kb={}",
                case.target, case.mode, case.has_config_path, case.has_knowledge_base
            );
            // Report the first differing line rather than two long prompts.
            let difference = actual
                .lines()
                .zip(case.prompt.lines())
                .find(|(actual, expected)| actual != expected)
                .map_or_else(
                    || {
                        format!(
                            "line count differs: {} vs {}",
                            actual.lines().count(),
                            case.prompt.lines().count()
                        )
                    },
                    |(actual, expected)| format!("got:\n  {actual}\nexpected:\n  {expected}"),
                );
            mismatches.push(format!("{label}: {difference}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n\n")
    );
}

#[test]
fn selects_skills_identically() {
    for case in &fixture().cases {
        let target = target_named(&case.target);
        assert_eq!(
            skill_name_for(&target, mode_named(&case.mode)),
            case.skill,
            "{}/{}",
            case.target,
            case.mode
        );
    }
}

#[test]
fn describes_targets_identically() {
    for case in &fixture().cases {
        let target = target_named(&case.target);
        assert_eq!(
            target_instruction(&target),
            case.target_instruction,
            "{}",
            case.target
        );
    }
}

// A prompt naming a skill that is not installed would fail deep inside the
// agent instead of here.
#[test]
fn refuses_a_plugin_missing_the_scan_skill() {
    let temp = TempDir::new().expect("temp dir");
    let bare = std::fs::canonicalize(temp.path()).expect("canonical");

    let error = scan_prompt(
        &bare,
        &target_named("repository"),
        ScanMode::Standard,
        false,
        false,
    )
    .expect_err("a missing skill is refused");

    assert_eq!(error.to_string(), fixture().missing_skill_error);
}

#[test]
fn refuses_a_symlinked_skill_file() {
    let (_temp, root) = plugin_root();
    let real = root.join("elsewhere.md");
    std::fs::write(&real, b"# skill\n").expect("write");
    let skill = root.join("skills").join("security-scan").join("SKILL.md");
    std::fs::remove_file(&skill).expect("remove");
    std::os::unix::fs::symlink(&real, &skill).expect("symlink");

    let error = scan_prompt(
        &root,
        &target_named("repository"),
        ScanMode::Standard,
        false,
        false,
    )
    .expect_err("a symlinked skill is refused");

    assert!(error.to_string().contains("missing scan skill"), "{error}");
}

// Scan results carry source excerpts; writing them into the repository would
// mix them into the tree under review.
#[test]
fn refuses_output_inside_the_repository() {
    let repository = Path::new("/src/project");

    for output in ["/src/project", "/src/project/results", "/src/project/a/b"] {
        let error = require_output_outside(repository, Path::new(output));
        assert!(error.is_output_inside_protected_root(), "{output}: {error}");
    }
}

#[test]
fn accepts_output_beside_or_above_the_repository() {
    let repository = Path::new("/src/project");

    for output in [
        "/src/results",
        "/src",
        "/tmp/results",
        "/src/project-results",
    ] {
        assert!(
            codex_security::api::require_output_outside_repository(
                repository,
                Path::new(output),
                ProtectedScanPathKind::Output,
            )
            .is_ok(),
            "{output} should be accepted"
        );
    }
}

#[test]
fn names_the_kind_of_path_it_refused() {
    let error = require_output_outside(Path::new("/repo"), Path::new("/repo/tmp"));

    assert_eq!(error.path_kind(), Some(ProtectedScanPathKind::Output));
    assert_eq!(error.protected_root(), Some(Path::new("/repo")));
}

fn require_output_outside(repository: &Path, output: &Path) -> codex_security::Error {
    codex_security::api::require_output_outside_repository(
        repository,
        output,
        ProtectedScanPathKind::Output,
    )
    .expect_err("output inside the repository is refused")
}

/// The workbench refuses a save whose scope differs from what it registered,
/// and nothing else tells the agent what that was. Observed across repeated
/// runs of one unchanged scan: `["."]`, `["src"]`, `[]`, and `[".git/**"]` for
/// a field that must be empty.
#[test]
fn states_the_scope_the_workbench_will_require() {
    let target = NormalizedTarget {
        kind: Some(NormalizedTargetKind::Repository),
        ..NormalizedTarget::default()
    };

    let (_temp, root) = plugin_root();
    let prompt = scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

    assert!(
        prompt.contains(r#"Use exactly ["."] as scan.scope.includePaths"#),
        "{prompt}"
    );
    assert!(
        prompt.contains("Use exactly [] as scan.scope.excludePaths"),
        "{prompt}"
    );
}

/// A paths scan is scoped to what was asked for, not to the whole repository.
#[test]
fn states_the_requested_paths_as_the_scope() {
    let target = NormalizedTarget {
        kind: Some(NormalizedTargetKind::Paths),
        paths: vec!["src".to_owned(), "lib".to_owned()],
        ..NormalizedTarget::default()
    };

    let (_temp, root) = plugin_root();
    let prompt = scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

    assert!(
        prompt.contains(r#"Use exactly ["src","lib"] as scan.scope.includePaths"#),
        "{prompt}"
    );
}

/// A diff-shaped scan has its scope checked differently, so stating one would
/// invent a requirement the workbench does not make.
#[test]
fn says_nothing_about_scope_for_a_diff_scan() {
    for kind in [
        NormalizedTargetKind::Refs,
        NormalizedTargetKind::WorkingTree,
    ] {
        let target = NormalizedTarget {
            kind: Some(kind),
            base: Some("main".to_owned()),
            head: Some("HEAD".to_owned()),
            ..NormalizedTarget::default()
        };

        let (_temp, root) = plugin_root();
        let prompt =
            scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

        assert!(
            !prompt.contains("scan.scope.includePaths"),
            "{kind:?}: {prompt}"
        );
    }
}

/// Which target kinds the workbench accepts depends on a snapshot it took at
/// registration, compared against the working tree now. That cannot be worked
/// out here without reimplementing the plugin's digest logic, so the agent is
/// told to ask the workbench instead of guessing — it guessed `git_worktree`,
/// `directory_snapshot` and `git_revision` across runs of one unchanged scan.
#[test]
fn tells_the_agent_to_read_the_target_contract() {
    let target = NormalizedTarget {
        kind: Some(NormalizedTargetKind::Repository),
        ..NormalizedTarget::default()
    };
    let (_temp, root) = plugin_root();

    let prompt = scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

    assert!(prompt.contains("get-scan"), "{prompt}");
    assert!(prompt.contains("contract.target.allowedKinds"), "{prompt}");
    assert!(prompt.contains("requiredSnapshotDigest"), "{prompt}");
}

/// Each kind takes exactly one coordinate field, and sending both is what the
/// workbench refused on the very first working scan.
#[test]
fn says_a_target_carries_one_coordinate_field() {
    let target = NormalizedTarget {
        kind: Some(NormalizedTargetKind::Repository),
        ..NormalizedTarget::default()
    };
    let (_temp, root) = plugin_root();

    let prompt = scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

    assert!(prompt.contains("Do not send both"), "{prompt}");
    assert!(prompt.contains("revision for git_revision"), "{prompt}");
}

/// A diff scan gets no scope instruction but still needs the contract, because
/// its kind is decided the same way.
#[test]
fn still_reads_the_contract_for_a_diff_scan() {
    let target = NormalizedTarget {
        kind: Some(NormalizedTargetKind::Refs),
        base: Some("main".to_owned()),
        head: Some("HEAD".to_owned()),
        ..NormalizedTarget::default()
    };
    let (_temp, root) = plugin_root();

    let prompt = scan_prompt(&root, &target, ScanMode::Standard, false, false).expect("a prompt");

    assert!(!prompt.contains("scan.scope.includePaths"), "{prompt}");
    assert!(prompt.contains("contract.target.allowedKinds"), "{prompt}");
}
