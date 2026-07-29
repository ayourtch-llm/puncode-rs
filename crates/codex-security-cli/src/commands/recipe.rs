//! Rebuilding a scan from the recipe a previous run saved.
//!
//! Ported from `scanArgumentsFromRecipe` in `src/cli.ts`.
//!
//! A recipe is data that outlived the run that wrote it: the workbench may have
//! been written by a different version, or edited, so every field is checked
//! rather than trusted. A rerun that silently scanned something other than what
//! the original scan looked at would be worse than one that refused.

use serde_json::Value;

use crate::cli::{Mode, ScanArgs, Severity};

/// Severities a saved recipe may name.
const REPORTABLE_SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Rebuilds the arguments a saved scan ran with.
pub fn scan_arguments(recipe: Option<&Value>, parent_scan_id: &str) -> Result<ScanArgs, String> {
    let recipe = recipe
        .and_then(Value::as_object)
        .ok_or_else(|| "This scan does not have a saved launch recipe.".to_owned())?;

    let repository = recipe
        .get("repository")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "The saved scan recipe does not contain a repository.".to_owned())?;

    let target = recipe
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| "The saved scan recipe contains no target.".to_owned())?;

    let paths = string_list(target.get("paths"))
        .ok_or_else(|| "The saved scan recipe contains invalid paths.".to_owned())?;
    let knowledge_base = match recipe.get("knowledgeBasePaths") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => string_list(Some(value)).ok_or_else(|| {
            "The saved scan recipe contains invalid knowledge base paths.".to_owned()
        })?,
    };

    let kind = target
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| matches!(*kind, "repository" | "paths" | "refs" | "working_tree"));
    let kind =
        kind.ok_or_else(|| "The saved scan recipe contains an invalid target.".to_owned())?;

    let mode = match recipe.get("mode").and_then(Value::as_str) {
        Some("standard") => Mode::Standard,
        Some("deep") => Mode::Deep,
        _ => return Err("The saved scan recipe contains an invalid mode.".to_owned()),
    };

    let saved_overrides = recipe
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "The saved scan recipe contains invalid configuration.".to_owned())?;

    // Older recipes spell the base ref differently; both are accepted, and a
    // ref comparison without one is refused.
    let reference = target.get("baseRef").or_else(|| target.get("base"));
    let reference = match reference {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => return Err("The saved scan recipe has an invalid Git base.".to_owned()),
    };
    if kind == "refs" && reference.as_deref().is_none_or(str::is_empty) {
        return Err("The saved scan recipe has an invalid Git base.".to_owned());
    }

    let head = match target.get("headRef") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(_) => return Err("The saved scan recipe has an invalid Git head.".to_owned()),
    };

    let fail_on_severity = match recipe.get("failOnSeverity") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if REPORTABLE_SEVERITIES.contains(&value.as_str()) => {
            Some(match value.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            })
        }
        Some(_) => {
            return Err("The saved scan recipe contains an invalid severity policy.".to_owned());
        }
    };

    let max_cost = match recipe.get("maxCostUsd") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let limit = value
                .as_f64()
                .filter(|limit| limit.is_finite() && *limit > 0.0)
                .ok_or_else(|| {
                    "The saved scan recipe contains an invalid cost limit.".to_owned()
                })?;
            Some(limit)
        }
    };

    Ok(ScanArgs {
        // A saved recipe carries any endpoint choice inside its Codex
        // overrides, so these stay at their defaults rather than being
        // reconstructed from a flag that was never typed.
        base_url: None,
        endpoint_compat: Vec::new(),
        wire_api: crate::cli::WireApi::default(),
        api_key_env: "OPENAI_API_KEY".to_owned(),
        repository: Some(repository.into()),
        paths,
        knowledge_base,
        diff: (kind == "refs").then(|| reference.clone().unwrap_or_default()),
        working_tree: kind == "working_tree",
        // A ref comparison with no head recorded compared against `HEAD`.
        head: (kind == "refs").then(|| head.clone().unwrap_or_else(|| "HEAD".to_owned())),
        base: (kind == "working_tree").then_some(reference).flatten(),
        mode,
        model: None,
        output_dir: None,
        archive_existing: false,
        plugin_path: None,
        python: None,
        codex: Vec::new(),
        fail_on_severity,
        max_cost,
        dry_run: false,
        output: crate::cli::OutputOptions::default(),
        // Recorded so the rerun is linked to what it repeats, and refused if
        // the installed plugin is no longer the one that produced it.
        parent_scan_id: Some(parent_scan_id.to_owned()),
        expected_plugin_version: recipe
            .get("pluginVersion")
            .and_then(Value::as_str)
            .map(str::to_owned),
        // The rerun runs under the settings the original scan used; a rerun
        // with a different model is not repeating that scan.
        saved_overrides: Some(saved_overrides),
    })
}

/// A list of non-empty strings, or `None` if it is anything else.
fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A recipe a completed repository scan would have saved.
    fn recipe() -> Value {
        json!({
            "repository": "/repos/payments",
            "target": { "kind": "repository", "paths": [] },
            "mode": "standard",
            "config": { "model": "gpt-5.6-sol" },
            "pluginVersion": "0.1.14",
        })
    }

    /// The recipe with one field replaced.
    fn with(field: &str, value: Value) -> Value {
        let mut recipe = recipe();
        recipe[field] = value;
        recipe
    }

    /// The recipe with one target field replaced.
    fn with_target(field: &str, value: Value) -> Value {
        let mut recipe = recipe();
        recipe["target"][field] = value;
        recipe
    }

    fn rebuild(recipe: &Value) -> Result<ScanArgs, String> {
        scan_arguments(Some(recipe), "scan_1")
    }

    #[test]
    fn rebuilds_a_repository_scan() {
        let arguments = rebuild(&recipe()).expect("valid");

        assert_eq!(
            arguments.repository.as_deref(),
            Some(std::path::Path::new("/repos/payments"))
        );
        assert_eq!(arguments.mode, Mode::Standard);
        assert!(arguments.paths.is_empty());
        assert!(!arguments.working_tree);
        assert_eq!(arguments.diff, None);
    }

    // A rerun is linked to what it repeats, and refuses a plugin that would
    // not reproduce it.
    #[test]
    fn records_what_it_repeats() {
        let arguments = rebuild(&recipe()).expect("valid");

        assert_eq!(arguments.parent_scan_id.as_deref(), Some("scan_1"));
        assert_eq!(arguments.expected_plugin_version.as_deref(), Some("0.1.14"));
    }

    #[test]
    fn rebuilds_a_scoped_scan() {
        let recipe = with_target("kind", json!("paths"));
        let recipe = {
            let mut recipe = recipe;
            recipe["target"]["paths"] = json!(["src", "lib"]);
            recipe
        };

        let arguments = rebuild(&recipe).expect("valid");

        assert_eq!(arguments.paths, ["src", "lib"]);
    }

    #[test]
    fn rebuilds_a_ref_comparison() {
        let mut recipe = with_target("kind", json!("refs"));
        recipe["target"]["baseRef"] = json!("main");
        recipe["target"]["headRef"] = json!("feature");

        let arguments = rebuild(&recipe).expect("valid");

        assert_eq!(arguments.diff.as_deref(), Some("main"));
        assert_eq!(arguments.head.as_deref(), Some("feature"));
    }

    // A ref comparison with no head recorded compared against `HEAD`.
    #[test]
    fn defaults_a_missing_head_to_head() {
        let mut recipe = with_target("kind", json!("refs"));
        recipe["target"]["baseRef"] = json!("main");

        let arguments = rebuild(&recipe).expect("valid");

        assert_eq!(arguments.head.as_deref(), Some("HEAD"));
    }

    // Older recipes spell the base differently.
    #[test]
    fn accepts_either_spelling_of_the_base() {
        let mut recipe = with_target("kind", json!("refs"));
        recipe["target"]["base"] = json!("main");

        assert_eq!(
            rebuild(&recipe).expect("valid").diff.as_deref(),
            Some("main")
        );
    }

    #[test]
    fn rebuilds_a_working_tree_scan() {
        let mut recipe = with_target("kind", json!("working_tree"));
        recipe["target"]["baseRef"] = json!("main");

        let arguments = rebuild(&recipe).expect("valid");

        assert!(arguments.working_tree);
        assert_eq!(arguments.base.as_deref(), Some("main"));
        assert_eq!(arguments.diff, None);
    }

    #[test]
    fn carries_the_severity_policy_and_cost_limit() {
        let mut recipe = recipe();
        recipe["failOnSeverity"] = json!("high");
        recipe["maxCostUsd"] = json!(5.0);

        let arguments = rebuild(&recipe).expect("valid");

        assert_eq!(arguments.fail_on_severity, Some(Severity::High));
        assert_eq!(arguments.max_cost, Some(5.0));
    }

    // A recipe that outlived its writer may be missing or malformed, and a
    // rerun that silently scanned something else would be worse than one that
    // refused.
    #[test]
    fn refuses_a_missing_recipe() {
        for recipe in [None, Some(&Value::Null), Some(&json!("not an object"))] {
            assert_eq!(
                scan_arguments(recipe, "scan_1").expect_err("refused"),
                "This scan does not have a saved launch recipe."
            );
        }
    }

    #[test]
    fn refuses_a_recipe_with_no_repository() {
        for value in [json!(null), json!(""), json!(42)] {
            assert_eq!(
                rebuild(&with("repository", value.clone())).expect_err("refused"),
                "The saved scan recipe does not contain a repository.",
                "for {value}"
            );
        }
    }

    #[test]
    fn refuses_a_recipe_with_no_target() {
        assert_eq!(
            rebuild(&with("target", json!(null))).expect_err("refused"),
            "The saved scan recipe contains no target."
        );
    }

    #[test]
    fn refuses_an_unknown_target_kind() {
        for kind in [json!("everything"), json!(null), json!(7)] {
            assert_eq!(
                rebuild(&with_target("kind", kind.clone())).expect_err("refused"),
                "The saved scan recipe contains an invalid target.",
                "for {kind}"
            );
        }
    }

    #[test]
    fn refuses_invalid_paths() {
        for paths in [json!("src"), json!([""]), json!([1])] {
            assert_eq!(
                rebuild(&with_target("paths", paths.clone())).expect_err("refused"),
                "The saved scan recipe contains invalid paths.",
                "for {paths}"
            );
        }
    }

    #[test]
    fn refuses_invalid_knowledge_base_paths() {
        assert_eq!(
            rebuild(&with("knowledgeBasePaths", json!([""]))).expect_err("refused"),
            "The saved scan recipe contains invalid knowledge base paths."
        );
    }

    #[test]
    fn refuses_an_unknown_mode() {
        assert_eq!(
            rebuild(&with("mode", json!("thorough"))).expect_err("refused"),
            "The saved scan recipe contains an invalid mode."
        );
    }

    #[test]
    fn refuses_missing_configuration() {
        assert_eq!(
            rebuild(&with("config", json!(null))).expect_err("refused"),
            "The saved scan recipe contains invalid configuration."
        );
    }

    // A ref comparison needs something to compare against.
    #[test]
    fn refuses_a_ref_comparison_with_no_base() {
        let recipe = with_target("kind", json!("refs"));

        assert_eq!(
            rebuild(&recipe).expect_err("refused"),
            "The saved scan recipe has an invalid Git base."
        );
    }

    #[test]
    fn refuses_an_invalid_git_head() {
        let mut recipe = with_target("kind", json!("refs"));
        recipe["target"]["baseRef"] = json!("main");
        recipe["target"]["headRef"] = json!("");

        assert_eq!(
            rebuild(&recipe).expect_err("refused"),
            "The saved scan recipe has an invalid Git head."
        );
    }

    #[test]
    fn refuses_an_unknown_severity_policy() {
        assert_eq!(
            rebuild(&with("failOnSeverity", json!("catastrophic"))).expect_err("refused"),
            "The saved scan recipe contains an invalid severity policy."
        );
    }

    #[test]
    fn refuses_a_cost_limit_that_is_not_a_positive_amount() {
        for limit in [json!(0), json!(-1), json!("5")] {
            assert_eq!(
                rebuild(&with("maxCostUsd", limit.clone())).expect_err("refused"),
                "The saved scan recipe contains an invalid cost limit.",
                "for {limit}"
            );
        }
    }

    // The rerun runs under the settings the original scan used.
    #[test]
    fn carries_the_saved_configuration() {
        let arguments = rebuild(&recipe()).expect("valid");

        let saved = arguments.saved_overrides.expect("a saved configuration");
        assert_eq!(saved["model"], json!("gpt-5.6-sol"));
    }

    // A rerun repeats a scan; it does not archive or dry-run unless asked
    // again, and it never inherits an output directory.
    #[test]
    fn does_not_inherit_one_off_choices() {
        let arguments = rebuild(&recipe()).expect("valid");

        assert!(!arguments.archive_existing);
        assert!(!arguments.dry_run);
        assert_eq!(arguments.output_dir, None);
    }
}
