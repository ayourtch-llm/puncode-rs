//! Finding out what will break, before a scan spends ten minutes discovering it.
//!
//! Every check here exists because something went wrong once and took a long
//! time to explain. A scan against a local model can run for ten minutes and
//! end in "completed without required artifacts" when the real answer —
//! bubblewrap cannot start on this host — was available in a second.
//!
//! Two rules shape all of it.
//!
//! **Run the check; never infer it from configuration.** That a sandbox mode is
//! set says nothing about whether a namespace can be created here. Only trying
//! it answers that, and the difference between the two is exactly the bug this
//! command exists to catch.
//!
//! **Keep going after a failure.** Someone with three problems should learn all
//! three from one run, not one per run.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use puncode_security::diagnosis::{Cause, recognise};
use puncode_security::provenance::Endpoint;
use puncode_security::runtime::{
    PluginPythonOptions, bundled_plugin_root, resolve_codex_command, resolve_plugin_python,
};
use puncode_security::targets::ProcessEnvironment;

/// How a check came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Working, with what was found.
    Ok(String),
    /// Broken in a way that stops a scan.
    Broken { detail: String, remedy: String },
    /// Not checked, and why not.
    ///
    /// Distinct from working: reporting an unchecked thing as fine is how a
    /// green report comes to mean nothing.
    Skipped(String),
    /// Worth knowing, and not a reason to stop.
    ///
    /// Kept apart from `Broken` deliberately. A note that blocks a scan is a
    /// false alarm, and the first thing anyone does with a command that raises
    /// false alarms is stop running it.
    Note(String),
}

impl Health {
    #[must_use]
    pub fn blocks_a_scan(&self) -> bool {
        matches!(self, Self::Broken { .. })
    }
}

/// One thing that was looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub health: Health,
}

/// What to check, and where.
pub struct Examination {
    pub environment: ProcessEnvironment,
    pub working_directory: PathBuf,
    /// The endpoint to exercise, when one was given.
    pub base_url: Option<Endpoint>,
    /// The model to ask for, when one was given.
    pub model: Option<String>,
}

/// Looks at everything, in the order things tend to fail.
#[must_use]
pub fn examine(examination: &Examination) -> Vec<Check> {
    let mut checks = vec![
        Check {
            name: "codex",
            health: check_codex(examination),
        },
        Check {
            name: "plugin",
            health: check_plugin(),
        },
        Check {
            name: "python",
            health: check_python(examination),
        },
        Check {
            name: "sandbox",
            health: check_sandbox(),
        },
    ];

    match &examination.base_url {
        Some(base_url) => {
            checks.push(Check {
                name: "endpoint",
                health: check_endpoint(base_url),
            });
            checks.push(Check {
                name: "model",
                health: check_model_listed(base_url, examination.model.as_deref()),
            });
            checks.push(Check {
                name: "system messages",
                health: check_system_messages(base_url, examination.model.as_deref()),
            });
        }
        None => {
            for name in ["endpoint", "model", "system messages"] {
                checks.push(Check {
                    name,
                    health: Health::Skipped("no --base-url given".to_owned()),
                });
            }
        }
    }

    checks
}

fn check_codex(examination: &Examination) -> Health {
    let resolved = resolve_codex_command(&examination.environment, &examination.working_directory);
    let Ok(command) = resolved else {
        return Health::Broken {
            detail: "the codex binary was not found".to_owned(),
            remedy: "Install the Codex CLI and make sure it is on PATH.".to_owned(),
        };
    };

    match Command::new(&command.command).arg("--version").output() {
        Ok(output) if output.status.success() => {
            Health::Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        }
        Ok(output) => Health::Broken {
            detail: format!("codex --version exited {}", output.status),
            remedy: "Check the Codex CLI installation.".to_owned(),
        },
        Err(error) => Health::Broken {
            detail: format!("codex could not be run: {error}"),
            remedy: "Check the Codex CLI installation.".to_owned(),
        },
    }
}

fn check_plugin() -> Health {
    match bundled_plugin_root() {
        Ok(root) => Health::Ok(format!("unpacked at {}", root.display())),
        Err(error) => Health::Broken {
            detail: error.to_string(),
            remedy: "The plugin ships with this binary; a failure here usually means the \
                     unpack directory is not writable."
                .to_owned(),
        },
    }
}

fn check_python(examination: &Examination) -> Health {
    let options = PluginPythonOptions {
        configured_path: None,
        environment: examination.environment.clone(),
        protected_root: examination.working_directory.clone(),
        home_directory: None,
        managed_runtime_roots: None,
    };
    match resolve_plugin_python(&options) {
        Ok(path) => Health::Ok(path.display().to_string()),
        Err(error) => Health::Broken {
            detail: error.to_string(),
            remedy: "Install a Python interpreter the plugin can use, or pass --python.".to_owned(),
        },
    }
}

/// Actually starts the sandbox rather than asking whether it is configured.
///
/// Codex ships its own bubblewrap. Running the real binary is the only thing
/// that answers whether a namespace can be created on this host — and on an
/// unprivileged container with an idmapped root filesystem, it cannot.
fn check_sandbox() -> Health {
    let Some(bwrap) = find_bundled_bwrap() else {
        return Health::Skipped(
            "no bundled bwrap found; the installed codex may sandbox differently".to_owned(),
        );
    };

    match Command::new(&bwrap)
        .args(["--unshare-user", "--bind", "/", "/", "true"])
        .output()
    {
        Ok(output) if output.status.success() => Health::Ok("bubblewrap starts".to_owned()),
        Ok(output) => {
            let complaint = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            // The remedy comes from the shared diagnosis so the wording is not
            // maintained in two places.
            let remedy = recognise(&complaint).map_or_else(
                || "Run scans on a host where bubblewrap works.".to_owned(),
                |cause| cause.explanation().to_owned(),
            );
            Health::Broken {
                detail: if complaint.is_empty() {
                    format!("bubblewrap exited {}", output.status)
                } else {
                    complaint
                },
                remedy,
            }
        }
        Err(error) => Health::Broken {
            detail: format!("bubblewrap could not be run: {error}"),
            remedy: "Run scans on a host where bubblewrap works.".to_owned(),
        },
    }
}

/// A transport failure described without quoting the address it was given.
///
/// A transport error's own text can include the URL, credentials and all.
fn error_kind(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Io(inner) => inner.kind().to_string(),
        ureq::Error::Timeout(_) => "timed out".to_owned(),
        ureq::Error::HostNotFound => "host not found".to_owned(),
        _ => "could not connect".to_owned(),
    }
}

/// The bwrap that ships with the installed codex, if it can be found.
fn find_bundled_bwrap() -> Option<PathBuf> {
    let home = std::env::home_dir()?;
    let releases = home.join(".codex/packages/standalone/releases");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(releases)
        .ok()?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path().join("codex-resources/bwrap"))
        .filter(|path| path.is_file())
        .collect();
    candidates.sort();
    candidates.pop()
}

/// Whether anything answers at the endpoint.
///
/// The address is reported with any credentials removed. This output is meant
/// to be shared — it is what someone pastes into a bug report when asking why a
/// scan will not run — and a URL can carry a username and password.
fn check_endpoint(base_url: &Endpoint) -> Health {
    let target = format!("{}/models", base_url.for_request().trim_end_matches('/'));
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .new_agent();

    match agent.get(&target).call() {
        Ok(response) if response.status().is_success() => {
            Health::Ok(format!("answers at {base_url}"))
        }
        Ok(response) => Health::Broken {
            detail: format!("{base_url} answered {}", response.status()),
            remedy: Cause::EndpointUnreachable.explanation().to_owned(),
        },
        // The error text is not interpolated: a transport error can quote the
        // URL it was given, credentials and all.
        Err(error) => Health::Broken {
            detail: format!("{base_url} did not answer ({})", error_kind(&error)),
            remedy: Cause::EndpointUnreachable.explanation().to_owned(),
        },
    }
}

/// Whether the endpoint accepts more than one system message.
///
/// This is the check worth having. Codex sends `instructions` plus several
/// `developer` items, and a server whose template permits one system message
/// refuses the request with a message about ordering — which is not the problem
/// and sends the reader somewhere useless.
/// Whether the endpoint lists the model that was asked for.
///
/// A note, never a failure, and the difference was measured rather than
/// assumed: this endpoint serves whatever it loaded and ignores the `model`
/// field entirely, so a name it does not list still works. Somewhere that
/// routes by name it would not, and a typo would cost a whole scan to
/// discover. Both facts fit in one line.
fn check_model_listed(base_url: &Endpoint, model: Option<&str>) -> Health {
    let Some(model) = model else {
        return Health::Skipped("no --model given, so there is nothing to look for".to_owned());
    };

    let target = format!("{}/models", base_url.for_request().trim_end_matches('/'));
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .new_agent();

    let listed = match agent.get(&target).call() {
        Ok(mut response) if response.status().is_success() => {
            let body = response.body_mut().read_to_string().unwrap_or_default();
            models_in(&body)
        }
        // The endpoint check above already reports an unreachable endpoint;
        // saying it twice helps nobody.
        _ => return Health::Skipped("the endpoint did not list its models".to_owned()),
    };

    if listed.iter().any(|listed| listed == model) {
        return Health::Ok(format!("{model} is served"));
    }
    Health::Note(format!(
        "the endpoint lists {} model(s) and none is {model}. Some servers ignore the name and serve \
         whatever they loaded, so this may be fine — but a mistyped name looks exactly like this \
         and costs a whole scan to find out.",
        listed.len()
    ))
}

/// The model identifiers in an OpenAI-compatible `/models` response.
fn models_in(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|document| document.get("data")?.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry.get("id")?.as_str().map(str::to_owned))
        .collect()
}

fn check_system_messages(base_url: &Endpoint, model: Option<&str>) -> Health {
    let Some(model) = model else {
        return Health::Skipped("no --model given, so nothing could be asked".to_owned());
    };

    let target = format!(
        "{}/chat/completions",
        base_url.for_request().trim_end_matches('/')
    );
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(90)))
        .http_status_as_error(false)
        .build()
        .new_agent();

    let body = serde_json::json!({
        "model": model,
        "messages": [
            { "role": "system", "content": "one" },
            { "role": "system", "content": "two" },
            { "role": "user", "content": "hi" },
        ],
        "max_tokens": 1,
    });

    match agent.post(&target).send_json(&body) {
        Ok(response) if response.status().is_success() => {
            Health::Ok("several system messages accepted".to_owned())
        }
        Ok(mut response) => {
            let complaint = response.body_mut().read_to_string().unwrap_or_default();
            let cause = recognise(&complaint);
            Health::Broken {
                detail: "the endpoint refused two system messages".to_owned(),
                remedy: cause.map_or_else(
                    || "Retry the scan with --endpoint-compat merge-system.".to_owned(),
                    |cause| cause.explanation().to_owned(),
                ),
            }
        }
        Err(error) => Health::Skipped(format!("could not ask: {error}")),
    }
}

/// The findings, for a person.
#[must_use]
pub fn render(checks: &[Check]) -> String {
    let mut lines = Vec::new();
    for check in checks {
        match &check.health {
            Health::Ok(detail) => lines.push(format!("  ok       {:<16} {detail}", check.name)),
            Health::Skipped(why) => {
                lines.push(format!("  skipped  {:<16} {why}", check.name));
            }
            Health::Broken { detail, remedy } => {
                lines.push(format!("  BROKEN   {:<16} {detail}", check.name));
                lines.push(format!("           {:<16} {remedy}", ""));
            }
            Health::Note(detail) => {
                lines.push(format!("  note     {:<16} {detail}", check.name));
            }
        }
    }

    let broken = checks.iter().filter(|c| c.health.blocks_a_scan()).count();
    let skipped = checks
        .iter()
        .filter(|c| matches!(c.health, Health::Skipped(_)))
        .count();
    lines.push(String::new());
    if broken == 0 {
        lines.push(format!(
            "nothing checked here would stop a scan{}",
            if skipped > 0 {
                format!(", though {skipped} could not be checked")
            } else {
                String::new()
            }
        ));
    } else {
        lines.push(format!("{broken} thing(s) would stop a scan"));
    }
    lines.join("\n")
}

/// The findings, for another program.
#[must_use]
pub fn render_json(checks: &[Check]) -> String {
    let entries: Vec<serde_json::Value> = checks
        .iter()
        .map(|check| match &check.health {
            Health::Ok(detail) => serde_json::json!({
                "check": check.name, "status": "ok", "detail": detail }),
            Health::Skipped(why) => serde_json::json!({
                "check": check.name, "status": "skipped", "detail": why }),
            Health::Note(detail) => serde_json::json!({
                "check": check.name,
                "status": "note",
                "detail": detail,
                // Said in the payload too: a job reading this must not treat a
                // note as a reason to stop.
                "blocksAScan": false,
            }),
            Health::Broken { detail, remedy } => serde_json::json!({
                "check": check.name, "status": "broken",
                "detail": detail, "remedy": remedy }),
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "blocking": checks.iter().filter(|c| c.health.blocks_a_scan()).count(),
        "checks": entries,
    }))
    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(name: &'static str) -> Check {
        Check {
            name,
            health: Health::Ok("fine".to_owned()),
        }
    }

    fn broken(name: &'static str) -> Check {
        Check {
            name,
            health: Health::Broken {
                detail: "it does not work".to_owned(),
                remedy: "do the thing".to_owned(),
            },
        }
    }

    #[test]
    fn only_a_broken_check_stops_a_scan() {
        assert!(!Health::Ok("x".to_owned()).blocks_a_scan());
        assert!(!Health::Skipped("x".to_owned()).blocks_a_scan());
        assert!(
            Health::Broken {
                detail: String::new(),
                remedy: String::new()
            }
            .blocks_a_scan()
        );
    }

    /// A remedy that is not printed is a diagnosis nobody can act on.
    #[test]
    fn a_broken_check_prints_what_to_do_about_it() {
        let rendered = render(&[broken("sandbox")]);

        assert!(rendered.contains("it does not work"), "{rendered}");
        assert!(rendered.contains("do the thing"), "{rendered}");
        assert!(
            rendered.contains("1 thing(s) would stop a scan"),
            "{rendered}"
        );
    }

    /// Every problem from one run, not one problem per run.
    #[test]
    fn reports_every_broken_check_not_just_the_first() {
        let rendered = render(&[broken("codex"), broken("sandbox"), ok("python")]);

        assert!(
            rendered.contains("2 thing(s) would stop a scan"),
            "{rendered}"
        );
    }

    /// Reporting an unchecked thing as fine is how a green report stops meaning
    /// anything.
    #[test]
    fn an_unchecked_thing_is_not_reported_as_working() {
        let checks = vec![
            ok("codex"),
            Check {
                name: "endpoint",
                health: Health::Skipped("no --base-url given".to_owned()),
            },
        ];

        let rendered = render(&checks);

        assert!(rendered.contains("skipped"), "{rendered}");
        assert!(rendered.contains("1 could not be checked"), "{rendered}");
        assert!(!rendered.contains("ok       endpoint"), "{rendered}");
    }

    #[test]
    fn says_so_plainly_when_everything_works() {
        let rendered = render(&[ok("codex"), ok("sandbox")]);

        assert!(
            rendered.contains("nothing checked here would stop a scan"),
            "{rendered}"
        );
        assert!(!rendered.contains("could not be checked"), "{rendered}");
    }

    #[test]
    fn structured_output_carries_the_remedy() {
        let rendered = render_json(&[broken("sandbox"), ok("codex")]);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");

        assert_eq!(parsed["blocking"], 1);
        assert_eq!(parsed["checks"][0]["status"], "broken");
        assert_eq!(parsed["checks"][0]["remedy"], "do the thing");
    }

    /// Without an endpoint the endpoint checks are skipped, never invented.
    #[test]
    fn skips_the_endpoint_checks_when_there_is_no_endpoint() {
        let checks = examine(&Examination {
            environment: ProcessEnvironment::new(),
            working_directory: std::env::current_dir().expect("a directory"),
            base_url: None,
            model: None,
        });

        let endpoint = checks
            .iter()
            .find(|check| check.name == "endpoint")
            .expect("an endpoint check");
        assert!(matches!(endpoint.health, Health::Skipped(_)));
    }

    /// The sandbox is checked by running it. On this host it is known broken,
    /// and a report of "ok" would mean the check is not really running.
    #[test]
    fn checks_the_sandbox_by_running_it() {
        let health = check_sandbox();

        match health {
            Health::Ok(_) | Health::Broken { .. } => {}
            Health::Skipped(why) => {
                assert!(why.contains("bwrap"), "an unexpected skip: {why}");
            }
            // The sandbox either works or it does not; there is nothing here
            // that is merely worth knowing.
            Health::Note(detail) => panic!("the sandbox check must decide: {detail}"),
        }
    }
}

#[cfg(test)]
mod model_listing_tests {
    use super::*;

    #[test]
    fn reads_model_ids_from_an_openai_style_listing() {
        let body = serde_json::json!({
            "object": "list",
            "data": [{ "id": "a-model", "object": "model" }, { "id": "b-model" }],
        })
        .to_string();

        assert_eq!(models_in(&body), vec!["a-model", "b-model"]);
    }

    /// The real body this endpoint returns, so the parser is not written
    /// against a shape somebody imagined.
    #[test]
    fn reads_the_shape_this_endpoint_actually_returns() {
        let body = serde_json::json!({
            "object": "list",
            "data": [{
                "id": "/home/ayourtch/models/deepreinforce-ai_Ornith-1.0-35B-IQ4_XS.gguf",
                "object": "model",
                "created": 0,
                "owned_by": "llamacpp",
            }],
        })
        .to_string();

        assert_eq!(models_in(&body).len(), 1);
        assert!(models_in(&body)[0].ends_with(".gguf"));
    }

    #[test]
    fn a_listing_it_cannot_read_yields_nothing_rather_than_panicking() {
        for body in [
            "",
            "not json",
            "{}",
            r#"{"data":"nope"}"#,
            r#"{"data":[{}]}"#,
        ] {
            assert!(models_in(body).is_empty(), "{body}");
        }
    }

    /// A note must never stop a scan. The one thing that would make this check
    /// worse than useless is a false alarm on an endpoint that ignores the
    /// model name — which is exactly what the endpoint here does.
    #[test]
    fn a_note_does_not_block_a_scan() {
        let note = Health::Note("the endpoint lists 1 model(s) and none is x".to_owned());

        assert!(!note.blocks_a_scan());
        let rendered = render(&[Check {
            name: "model",
            health: note,
        }]);
        assert!(rendered.contains("note     model"), "{rendered}");
        assert!(
            rendered.contains("nothing checked here would stop a scan"),
            "{rendered}"
        );
    }

    /// And a machine reading this must not treat it as a reason to stop either.
    #[test]
    fn the_structured_form_says_a_note_does_not_block() {
        let structured = render_json(&[Check {
            name: "model",
            health: Health::Note("something worth knowing".to_owned()),
        }]);

        assert!(structured.contains("\"status\": \"note\""), "{structured}");
        assert!(
            structured.contains("\"blocksAScan\": false"),
            "{structured}"
        );
    }

    /// Nothing is claimed when nothing was asked for.
    #[test]
    fn says_it_was_skipped_when_no_model_was_given() {
        let health = check_model_listed(&Endpoint::new("http://127.0.0.1:1/v1"), None);

        assert!(matches!(health, Health::Skipped(_)), "{health:?}");
    }

    /// An endpoint that cannot be reached is already reported by the endpoint
    /// check; saying it twice helps nobody.
    #[test]
    fn does_not_repeat_an_unreachable_endpoint() {
        let health =
            check_model_listed(&Endpoint::new("http://127.0.0.1:1/v1"), Some("some-model"));

        assert!(matches!(health, Health::Skipped(_)), "{health:?}");
    }
}
