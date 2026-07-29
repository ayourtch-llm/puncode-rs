//! Running a scan, and reporting what one would do.
//!
//! Ported from `runScan` in `src/cli.ts`.
//!
//! Only the dry run is wired so far. It is the half that answers without
//! spending anything: what would be scanned, where results would land, which
//! model and credentials would be used. Everything it reports is decided
//! locally, so it is also the fastest way to find out that a request is wrong.

use std::path::{Path, PathBuf};

use codex_security::ProtectedScanPathKind;
use codex_security::api::require_output_outside_repository;
use codex_security::api::{
    ApiKeySource, CodexSecurity, ScanAuthentication, ScanCancellation, ScanObserver, ScanOptions,
    ScanPreflight,
};
use codex_security::config::CodexSecurityConfig;
use codex_security::endpoint_shim::{Adaptations, EndpointShim, ShimOptions};
use codex_security::models::Completeness;
use codex_security::result::ScanResult;
use codex_security::targets::{DiffTarget, ScanMode, ScanTarget};
use serde_json::{Value, json};

use crate::cli::{Format, Mode, ScanArgs};

/// Reports what a scan would do, without running it.
pub fn dry_run(arguments: &ScanArgs, current_directory: &Path) -> Result<String, String> {
    let repository = arguments
        .repository
        .clone()
        .unwrap_or_else(|| current_directory.to_path_buf());
    let client = CodexSecurity::new(config(arguments, None)?);
    let preflight = client
        .preflight(&repository.to_string_lossy(), &options(arguments)?)
        .map_err(|error| error.to_string())?;

    // Closed explicitly so a failure to clean up is reported rather than
    // swallowed by the drop that would otherwise do it.
    client.close().map_err(|error| error.to_string())?;

    Ok(match arguments.output.resolved() {
        Format::Text => render_text(&preflight),
        Format::Json => serde_json::to_string_pretty(&report(&preflight, arguments))
            .map_err(|error| error.to_string())?,
        Format::Jsonl => serde_json::to_string(&report(&preflight, arguments))
            .map_err(|error| error.to_string())?,
    })
}

/// The forwarder to run in front of the endpoint, if one is needed at all.
///
/// Needed when a request has to be reshaped, and also when the traffic is being
/// recorded — the forwarder is the only place that sees it.
fn endpoint_adapter(
    arguments: &ScanArgs,
    repository: &Path,
) -> Result<Option<EndpointShim>, String> {
    let Some(base_url) = &arguments.base_url else {
        return Ok(None);
    };
    let adaptations = Adaptations {
        merge_system: arguments
            .endpoint_compat
            .contains(&crate::cli::EndpointCompat::MergeSystem),
    };
    if !adaptations.any() && arguments.capture_traffic.is_none() {
        return Ok(None);
    }

    let capture = match &arguments.capture_traffic {
        Some(path) => {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .map_err(|error| error.to_string())?
                    .join(path)
            };
            // The capture carries source excerpts and the findings drawn from
            // them; writing it into the tree under review would mix it into the
            // very thing being scanned. Scan output is refused here for the same
            // reason.
            require_output_outside_repository(
                repository,
                path.parent().unwrap_or(&path),
                ProtectedScanPathKind::Output,
            )
            .map_err(|error| error.to_string())?;
            eprintln!(
                "codex-security: Recording endpoint traffic to {}. It will contain prompts, \
                 model output, and source from the repository.",
                path.display()
            );
            Some(path)
        }
        None => None,
    };

    EndpointShim::start(
        base_url,
        &ShimOptions {
            adaptations,
            capture,
        },
    )
    .map(Some)
    .map_err(|error| error.to_string())
}

/// The configuration a scan runs under.
///
/// `--model` and `--codex model=…` say the same thing, so naming both is a
/// contradiction the override parser refuses rather than silently resolving.
fn config(arguments: &ScanArgs, endpoint: Option<&str>) -> Result<CodexSecurityConfig, String> {
    let mut overrides =
        crate::overrides::parse_codex_overrides(&arguments.codex, arguments.model.as_deref())?;

    // A ceiling that cannot be enforced is worse than none, because it is
    // believed to be protecting someone.
    codex_security::model_endpoint::validate_cost_limit_for_endpoint(
        arguments.max_cost,
        arguments.base_url.as_deref(),
    )
    .map_err(|error| error.to_string())?;

    // An endpoint and a hand-written provider override say the same thing, so
    // naming both is a contradiction rather than a preference.
    if let Some(base_url) = endpoint.or(arguments.base_url.as_deref()) {
        for key in ["model_provider", "model_providers"] {
            if overrides.contains_key(key) {
                return Err(format!(
                    "--base-url and --codex {key}=… both choose a model provider; use one."
                ));
            }
        }
        let endpoint = codex_security::model_endpoint::model_endpoint_overrides(
            &codex_security::model_endpoint::ModelEndpoint {
                base_url: base_url.to_owned(),
                wire_api: arguments.wire_api.into(),
                api_key_env: arguments.api_key_env.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        overrides.extend(endpoint);
    }

    // A rerun starts from what the original scan ran under; anything asked for
    // on the command line still wins, so a rerun can be nudged.
    if let Some(saved) = &arguments.saved_overrides {
        for (key, value) in saved {
            overrides
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    Ok(CodexSecurityConfig {
        plugin_path: arguments.plugin_path.clone(),
        python_path: arguments.python.as_ref().map(PathBuf::from),
        codex_overrides: (!overrides.is_empty()).then_some(overrides),
    })
}

/// The scan the arguments describe.
fn options(arguments: &ScanArgs) -> Result<ScanOptions, String> {
    let mut options = ScanOptions::new()
        .with_mode(match arguments.mode {
            Mode::Standard => ScanMode::Standard,
            Mode::Deep => ScanMode::Deep,
        })
        .with_knowledge_base_paths(arguments.knowledge_base.clone())
        .with_archive_existing(arguments.archive_existing);

    if let Some(target) = target(arguments)? {
        options = options.with_target(target);
    }
    if let Some(output_dir) = &arguments.output_dir {
        options = options.with_output_dir(output_dir.clone());
    }
    if let Some(max_cost) = arguments.max_cost {
        options = options.with_max_cost_usd(max_cost);
    }
    if let Some(severity) = arguments.fail_on_severity {
        options = options.with_failure_severity(format!("{severity:?}").to_lowercase());
    }
    if let Some(parent) = &arguments.parent_scan_id {
        options = options.with_parent_scan_id(parent.clone());
    }
    if let Some(version) = &arguments.expected_plugin_version {
        options = options.with_expected_plugin_version(version.clone());
    }
    Ok(options)
}

/// What the scan is pointed at.
///
/// The arguments have already been checked for naming more than one, so at most
/// one of these applies.
fn target(arguments: &ScanArgs) -> Result<Option<ScanTarget>, String> {
    if !arguments.paths.is_empty() {
        return Ok(Some(ScanTarget::Paths(arguments.paths.clone())));
    }
    if let Some(base) = &arguments.diff {
        let diff = DiffTarget::refs(base.clone(), arguments.head.clone())
            .map_err(|error| error.to_string())?;
        return Ok(Some(ScanTarget::Diff(diff)));
    }
    if arguments.working_tree {
        let diff =
            DiffTarget::working_tree(arguments.base.clone()).map_err(|error| error.to_string())?;
        return Ok(Some(ScanTarget::Diff(diff)));
    }
    Ok(None)
}

/// The preflight as a machine-readable record.
///
/// `dryRun` leads, as upstream does, so a caller reading the output can tell at
/// a glance that nothing was actually scanned.
fn report(preflight: &ScanPreflight, arguments: &ScanArgs) -> Value {
    let mut record = json!({
        "dryRun": true,
        "repository": preflight.repository.to_string_lossy(),
        "target": {
            "kind": preflight.target.kind.map(|kind| kind.as_str()),
            "paths": preflight.target.paths,
        },
        "mode": preflight.mode.as_str(),
        "outputDir": preflight
            .output_dir
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        "authentication": authentication(preflight.authentication),
        "model": preflight.model,
        "reasoningEffort": preflight.reasoning_effort,
    });

    // Where the model will actually run. Without this, someone pointing the
    // scan at a local server has no way to confirm it took effect short of
    // running a real scan.
    if let Some(base_url) = &arguments.base_url {
        record["modelEndpoint"] = json!({
            "baseUrl": base_url,
            "wireApi": codex_security::model_endpoint::WireApi::from(arguments.wire_api).as_str(),
            "apiKeyEnv": arguments.api_key_env,
        });
    }

    // Absent rather than null, so the shape says what applies.
    if !preflight.knowledge_base_paths.is_empty() {
        record["knowledgeBasePaths"] = json!(preflight.knowledge_base_paths);
    }
    if let Some(archive_dir) = &preflight.archive_dir {
        record["archiveDir"] = json!(archive_dir.to_string_lossy());
    }
    if let Some(max_cost) = preflight.max_cost_usd {
        record["maxCostUsd"] = json!(max_cost);
    }
    record
}

/// How the scan would sign in.
fn authentication(authentication: ScanAuthentication) -> Value {
    match authentication {
        ScanAuthentication::ApiKey { source, verified } => json!({
            "method": "api_key",
            "source": match source {
                ApiKeySource::OpenAiApiKey => "OPENAI_API_KEY",
                ApiKeySource::CodexApiKey => "CODEX_API_KEY",
            },
            "verified": verified,
        }),
        ScanAuthentication::StoredCredentials { verified } => json!({
            "method": "stored_credentials",
            "verified": verified,
        }),
    }
}

/// The same report, for a person.
fn render_text(preflight: &ScanPreflight) -> String {
    let mut lines = vec![
        "Dry run: nothing was scanned.".to_owned(),
        String::new(),
        format!("  repository       {}", preflight.repository.display()),
        format!(
            "  target           {}",
            preflight
                .target
                .kind
                .map_or("repository", |kind| kind.as_str())
        ),
    ];
    if !preflight.target.paths.is_empty() {
        lines.push(format!(
            "  paths            {}",
            preflight.target.paths.join(", ")
        ));
    }
    lines.push(format!("  mode             {}", preflight.mode.as_str()));
    lines.push(format!(
        "  output           {}",
        preflight.output_dir.as_ref().map_or_else(
            || "a temporary directory".to_owned(),
            |path| path.display().to_string()
        )
    ));
    if let Some(archive_dir) = &preflight.archive_dir {
        lines.push(format!("  archive to       {}", archive_dir.display()));
    }
    if !preflight.knowledge_base_paths.is_empty() {
        lines.push(format!(
            "  knowledge base   {}",
            preflight.knowledge_base_paths.join(", ")
        ));
    }
    lines.push(format!("  model            {}", preflight.model));
    lines.push(format!("  reasoning effort {}", preflight.reasoning_effort));
    lines.push(format!(
        "  authentication   {}",
        match preflight.authentication {
            ScanAuthentication::ApiKey { source, .. } => format!(
                "API key from {}",
                match source {
                    ApiKeySource::OpenAiApiKey => "OPENAI_API_KEY",
                    ApiKeySource::CodexApiKey => "CODEX_API_KEY",
                }
            ),
            ScanAuthentication::StoredCredentials { .. } => "stored Codex credentials".to_owned(),
        }
    ));
    if let Some(max_cost) = preflight.max_cost_usd {
        lines.push(format!("  cost limit       {max_cost} USD"));
    }
    lines.join("\n")
}

/// What a finished scan means for the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// The report to print.
    pub report: String,
    /// Lines about the scan itself, which belong on standard error so they do
    /// not contaminate a redirected report.
    pub summary: Vec<String>,
    /// Why a scan with incomplete coverage cannot be judged, when that applies.
    pub coverage_warning: Option<String>,
    pub exit_code: u8,
}

/// Severities in the order the failure policy ranks them.
const REPORTABLE_SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Severities a summary counts, worst first.
const DISPLAY_SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "informational"];

/// Runs a scan and reports what it found.
pub fn run(
    arguments: &ScanArgs,
    current_directory: &Path,
    observer: &mut dyn ScanObserver,
    cancellation: &ScanCancellation,
) -> Result<ScanOutcome, String> {
    let repository = arguments
        .repository
        .clone()
        .unwrap_or_else(|| current_directory.to_path_buf());
    // Requests are adapted by a forwarder on this machine; the scan is pointed
    // at it instead of the endpoint. It is held for the whole scan and shuts
    // down when this returns.
    let adapter = endpoint_adapter(arguments, current_directory)?;
    let client = CodexSecurity::new(config(
        arguments,
        adapter.as_ref().map(EndpointShim::base_url).as_deref(),
    )?);

    let outcome = client.run(
        &repository.to_string_lossy(),
        &options(arguments)?,
        observer,
        cancellation,
    );
    // Closed whatever happened, so the isolated runtime never outlives the
    // command that made it.
    let closed = client.close();

    let result = outcome.map_err(|error| error.to_string())?;
    closed.map_err(|error| error.to_string())?;

    let report = match arguments.output.resolved() {
        Format::Text | Format::Json => serde_json::to_string_pretty(&result),
        Format::Jsonl => serde_json::to_string(&result),
    }
    .map_err(|error| error.to_string())?;

    Ok(ScanOutcome {
        exit_code: exit_code(arguments, &result),
        summary: summary(&result),
        coverage_warning: coverage_warning(arguments, &result),
        report,
    })
}

/// What the scan means for the process's exit status.
///
/// Three outcomes have to stay distinguishable, because a CI job acts on each
/// differently: nothing to report, something at or above the failure severity,
/// and a scan whose coverage was too incomplete to judge either way.
fn exit_code(arguments: &ScanArgs, result: &ScanResult) -> u8 {
    if result.coverage.completeness != Completeness::Complete {
        return crate::exit::ERROR;
    }
    let Some(threshold) = arguments.fail_on_severity else {
        return crate::exit::SUCCESS;
    };
    let threshold = format!("{threshold:?}").to_lowercase();
    let blocking: Vec<&str> = REPORTABLE_SEVERITIES
        .iter()
        .take_while(|severity| **severity != threshold)
        .chain(std::iter::once(&threshold.as_str()))
        .copied()
        .collect();

    let found = result
        .findings
        .findings
        .iter()
        .any(|finding| blocking.contains(&finding.severity.level.as_str()));
    if found {
        crate::exit::FINDINGS
    } else {
        crate::exit::SUCCESS
    }
}

/// The lines describing what the scan did.
fn summary(result: &ScanResult) -> Vec<String> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for finding in &result.findings.findings {
        *counts.entry(finding.severity.level.as_str()).or_default() += 1;
    }
    let breakdown: Vec<String> = DISPLAY_SEVERITIES
        .iter()
        .filter_map(|severity| {
            counts
                .get(severity)
                .map(|count| format!("{count} {severity}"))
        })
        .collect();

    let mut lines = vec![format!(
        "Findings: {}{}. Coverage: {}.",
        result.findings.findings.len(),
        if breakdown.is_empty() {
            String::new()
        } else {
            format!(" ({})", breakdown.join(", "))
        },
        result.coverage.completeness.as_str()
    )];

    if let Some(cost) = &result.cost {
        lines.push(format!(
            "Estimated cost: {} USD.",
            codex_security::cost::format_usd(cost.estimated_usd)
        ));
    }
    lines.push(format!("Results: {}", result.scan_dir.display()));
    // What to do next depends on whether the export already exists.
    lines.push(match &result.sarif_path {
        Some(_) => format!(
            "Next: review {}",
            result.scan_dir.join("report.md").display()
        ),
        None => format!(
            "Next: codex-security export {} --export-format sarif",
            result.scan_dir.display()
        ),
    });
    lines
}

/// Says why a scan whose coverage was incomplete cannot be judged.
fn coverage_warning(arguments: &ScanArgs, result: &ScanResult) -> Option<String> {
    if result.coverage.completeness == Completeness::Complete {
        return None;
    }
    Some(match arguments.fail_on_severity {
        None => format!(
            "Scan coverage is {}; results may be incomplete.",
            result.coverage.completeness.as_str()
        ),
        Some(_) => format!(
            "Cannot evaluate the failure policy: coverage is {}.",
            result.coverage.completeness.as_str()
        ),
    })
}
