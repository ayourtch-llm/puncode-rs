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
