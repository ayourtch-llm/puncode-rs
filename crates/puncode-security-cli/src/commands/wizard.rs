//! Choosing repositories to scan, interactively.
//!
//! Ported from `runBulkScanWizard` in `src/bulk-scan-discovery.ts`.
//!
//! The wizard only ever writes one thing — the inventory — and it asks before
//! doing so. Everything up to that point can be abandoned without leaving
//! anything behind, which matters because the next step spends money on every
//! repository it lists.

use std::path::{Path, PathBuf};

use puncode_security::bulk_scan_discovery::{
    ACTIVITY_WINDOW_DAYS, DiscoveredRepository, RepositorySource, create_wizard_output,
    discover_repositories, validate_wizard_output, write_inventory,
};

/// Asks the person questions.
///
/// Behind a trait so the wizard's flow — what it asks, in what order, and what
/// it does with the answers — can be checked without a terminal.
pub trait Prompt {
    /// Whether there is someone to ask.
    fn is_interactive(&self) -> bool;

    /// Says something that is not a question.
    fn write(&self, value: &str);

    /// Asks for one of `choices`, returning the value chosen.
    fn select(&self, question: &str, choices: &[(String, String)]) -> Result<String, String>;

    /// Asks for a line of text.
    fn input(&self, question: &str, default: &str) -> Result<String, String>;

    /// Asks a yes-or-no question.
    fn confirm(&self, question: &str) -> Result<bool, String>;
}

/// What the wizard settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardResult {
    pub input_path: PathBuf,
    pub output_dir: PathBuf,
    pub github_host: String,
}

/// Runs the wizard, returning what to scan — or nothing, if it was abandoned.
pub fn run(
    source: &dyn RepositorySource,
    prompt: &dyn Prompt,
    host: &str,
    current_directory: &Path,
    now: i64,
) -> Result<Option<WizardResult>, String> {
    if !prompt.is_interactive() {
        return Err(
            "Interactive repository selection requires a terminal. Provide a CSV with \
             'puncode-security bulk-scan repositories.csv --output-dir ./security-scans'."
                .to_owned(),
        );
    }

    let owner = select_owner(source, prompt)?;
    prompt.write("\nFinding active repositories...\n");
    let cutoff = now - ACTIVITY_WINDOW_DAYS * 86_400_000;
    let discovered =
        discover_repositories(source, host, &owner, cutoff).map_err(|error| error.to_string())?;
    if discovered.is_empty() {
        prompt.write("\nNo repositories matched your selection.\n");
        return Ok(None);
    }
    prompt.write(&format!("\nFound {} repositories.\n", discovered.len()));

    let selected = select_repositories(&discovered, prompt)?;
    let output_dir = current_directory
        .join(prompt.input("Where should scan results be saved?", "./security-scans")?);
    let output_dir = crate::commands::wizard::absolute(current_directory, &output_dir);
    let input_path = output_dir.join("repositories.csv");

    // Checked before asking to start: finding out afterwards that the
    // directory already holds a scan would waste the person's decision.
    validate_wizard_output(&output_dir).map_err(|error| error.to_string())?;
    prompt.write(&format!(
        "\nReady to scan {} repositories?\nResults: {}\nRepository list: {}\n",
        selected.len(),
        output_dir.display(),
        input_path.display()
    ));
    if !prompt.confirm("Start scanning?")? {
        prompt.write("\nScan canceled.\n");
        return Ok(None);
    }

    // The first and only thing written.
    create_wizard_output(&output_dir).map_err(|error| error.to_string())?;
    write_inventory(&input_path, &selected).map_err(|error| error.to_string())?;

    Ok(Some(WizardResult {
        input_path,
        output_dir,
        github_host: host.to_owned(),
    }))
}

/// Which account to scan.
///
/// Only asked when there is genuinely a choice.
fn select_owner(source: &dyn RepositorySource, prompt: &dyn Prompt) -> Result<String, String> {
    let organizations = source.organizations().map_err(|error| error.to_string())?;
    if organizations.len() > 1 {
        let choices: Vec<(String, String)> = organizations
            .iter()
            .map(|owner| (owner.clone(), owner.clone()))
            .collect();
        return prompt.select("Which account or organization should we scan?", &choices);
    }
    // No organizations means a personal account, which is still something to
    // scan.
    let owner = match organizations.into_iter().next() {
        Some(owner) => owner,
        None => source
            .signed_in_account()
            .map_err(|error| error.to_string())?,
    };
    prompt.write(&format!("\nFinding repositories in {owner}.\n"));
    Ok(owner)
}

/// Which repositories to scan.
///
/// Asked repeatedly so several can be picked; choosing the first entry stops.
/// Picking none means all of them, which is what the first entry says.
fn select_repositories(
    repositories: &[DiscoveredRepository],
    prompt: &dyn Prompt,
) -> Result<Vec<DiscoveredRepository>, String> {
    let mut selected: Vec<String> = Vec::new();

    while selected.len() < repositories.len() {
        let mut choices = vec![(
            if selected.is_empty() {
                format!("All {} repositories", repositories.len())
            } else {
                format!("Done ({} selected)", selected.len())
            },
            String::new(),
        )];
        choices.extend(
            repositories
                .iter()
                .filter(|repository| !selected.contains(&repository.full_name))
                .map(|repository| (repository.full_name.clone(), repository.full_name.clone())),
        );

        let choice = prompt.select("Select repositories to scan (type to filter)", &choices)?;
        if choice.is_empty() {
            break;
        }
        selected.push(choice);
    }

    if selected.is_empty() {
        return Ok(repositories.to_vec());
    }
    Ok(repositories
        .iter()
        .filter(|repository| selected.contains(&repository.full_name))
        .cloned()
        .collect())
}

/// `path` against `base`, unless it is already absolute.
fn absolute(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Asks the person through the terminal.
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn is_interactive(&self) -> bool {
        use std::io::IsTerminal;
        // Both ends: a question needs somewhere to appear and someone to
        // answer it.
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    fn write(&self, value: &str) {
        use std::io::Write;
        // Prompts and progress go to standard error, leaving standard output
        // for the report the wizard's caller produces.
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "{value}");
        let _ = stderr.flush();
    }

    fn select(&self, question: &str, choices: &[(String, String)]) -> Result<String, String> {
        let labels: Vec<&str> = choices.iter().map(|(label, _)| label.as_str()).collect();
        let chosen = dialoguer::FuzzySelect::new()
            .with_prompt(question)
            .items(&labels)
            .default(0)
            .interact()
            .map_err(|error| format!("Selection canceled: {error}"))?;
        Ok(choices[chosen].1.clone())
    }

    fn input(&self, question: &str, default: &str) -> Result<String, String> {
        dialoguer::Input::new()
            .with_prompt(question)
            .default(default.to_owned())
            .interact_text()
            .map_err(|error| format!("Input canceled: {error}"))
    }

    fn confirm(&self, question: &str) -> Result<bool, String> {
        dialoguer::Confirm::new()
            .with_prompt(question)
            .default(false)
            .interact()
            .map_err(|error| format!("Confirmation canceled: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use puncode_security::bulk_scan_discovery::{RepositoryNode, RepositoryPage};
    use std::cell::RefCell;

    /// A source with one page of repositories.
    struct FakeSource {
        organizations: Vec<String>,
        nodes: Vec<RepositoryNode>,
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
            Ok(if cursor.is_some() {
                RepositoryPage::default()
            } else {
                RepositoryPage {
                    nodes: self.nodes.clone(),
                    end_cursor: None,
                }
            })
        }
    }

    fn node(name: &str) -> RepositoryNode {
        RepositoryNode {
            name_with_owner: name.to_owned(),
            pushed_at: "2026-07-20T00:00:00Z".to_owned(),
            default_branch_oid: Some("a".repeat(40)),
        }
    }

    /// A prompt that answers from a script and records what it was asked.
    struct ScriptedPrompt {
        selections: RefCell<Vec<String>>,
        input: String,
        confirm: bool,
        interactive: bool,
        asked: RefCell<Vec<String>>,
        said: RefCell<Vec<String>>,
    }

    impl ScriptedPrompt {
        fn new(selections: &[&str], confirm: bool) -> Self {
            Self {
                selections: RefCell::new(
                    selections.iter().map(|value| (*value).to_owned()).collect(),
                ),
                input: "./security-scans".to_owned(),
                confirm,
                interactive: true,
                asked: RefCell::new(Vec::new()),
                said: RefCell::new(Vec::new()),
            }
        }
    }

    impl Prompt for ScriptedPrompt {
        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn write(&self, value: &str) {
            self.said.borrow_mut().push(value.to_owned());
        }

        fn select(&self, question: &str, choices: &[(String, String)]) -> Result<String, String> {
            self.asked.borrow_mut().push(question.to_owned());
            let mut selections = self.selections.borrow_mut();
            if selections.is_empty() {
                // Nothing scripted: take the first entry, which stops.
                return Ok(choices[0].1.clone());
            }
            Ok(selections.remove(0))
        }

        fn input(&self, question: &str, _default: &str) -> Result<String, String> {
            self.asked.borrow_mut().push(question.to_owned());
            Ok(self.input.clone())
        }

        fn confirm(&self, question: &str) -> Result<bool, String> {
            self.asked.borrow_mut().push(question.to_owned());
            Ok(self.confirm)
        }
    }

    /// A time well after the fixtures' push dates.
    fn now() -> i64 {
        // 2026-08-01, so the fixtures are inside the activity window.
        1_785_542_400_000
    }

    fn source(organizations: &[&str], repositories: &[&str]) -> FakeSource {
        FakeSource {
            organizations: organizations.iter().map(|o| (*o).to_owned()).collect(),
            nodes: repositories.iter().map(|name| node(name)).collect(),
        }
    }

    #[test]
    fn writes_an_inventory_of_everything_it_found() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&[], true);

        let result = run(
            &source(&["acme"], &["acme/payments", "acme/ledger"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs")
        .expect("an inventory");

        let inventory = std::fs::read_to_string(&result.input_path).expect("read");
        assert!(inventory.contains("acme--payments"), "{inventory}");
        assert!(inventory.contains("acme--ledger"), "{inventory}");
    }

    // Picking specific repositories scans only those.
    #[test]
    fn writes_only_what_was_chosen() {
        let root = tempfile::TempDir::new().expect("root");
        // Choose one, then stop.
        let prompt = ScriptedPrompt::new(&["acme/payments", ""], true);

        let result = run(
            &source(&["acme"], &["acme/payments", "acme/ledger"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs")
        .expect("an inventory");

        let inventory = std::fs::read_to_string(&result.input_path).expect("read");
        assert!(inventory.contains("acme--payments"), "{inventory}");
        assert!(!inventory.contains("acme--ledger"), "{inventory}");
    }

    // The next step spends money on every repository listed, so nothing is
    // written until the person says to start.
    #[test]
    fn writes_nothing_when_it_is_abandoned() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&[], false);

        let result = run(
            &source(&["acme"], &["acme/payments"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs");

        assert_eq!(result, None);
        assert!(
            !root.path().join("security-scans").exists(),
            "nothing should have been created"
        );
    }

    #[test]
    fn reports_when_nothing_matched() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&[], true);

        let result = run(
            &source(&["acme"], &[]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs");

        assert_eq!(result, None);
        assert!(
            prompt
                .said
                .borrow()
                .iter()
                .any(|said| said.contains("No repositories matched")),
            "{:?}",
            prompt.said.borrow()
        );
    }

    // Only asked when there is genuinely a choice.
    #[test]
    fn does_not_ask_which_account_when_there_is_one() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&[], true);

        run(
            &source(&["acme"], &["acme/payments"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs");

        assert!(
            !prompt
                .asked
                .borrow()
                .iter()
                .any(|question| question.contains("account or organization")),
            "{:?}",
            prompt.asked.borrow()
        );
    }

    #[test]
    fn asks_which_account_when_there_are_several() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&["acme", ""], true);

        run(
            &source(&["acme", "zeta"], &["acme/payments"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs");

        assert!(
            prompt
                .asked
                .borrow()
                .iter()
                .any(|question| question.contains("account or organization")),
            "{:?}",
            prompt.asked.borrow()
        );
    }

    // Finding out afterwards that the directory already holds a scan would
    // waste the person's decision.
    #[test]
    fn refuses_an_output_directory_that_already_holds_a_scan() {
        let root = tempfile::TempDir::new().expect("root");
        let output = root.path().join("security-scans");
        std::fs::create_dir_all(&output).expect("create");
        std::fs::write(output.join("repositories.csv"), "").expect("write");
        let prompt = ScriptedPrompt::new(&[], true);

        let error = run(
            &source(&["acme"], &["acme/payments"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect_err("refused");

        assert!(
            error.contains("already contains a repository list"),
            "{error}"
        );
        // Asked before starting, so the confirmation never came up.
        assert!(
            !prompt
                .asked
                .borrow()
                .iter()
                .any(|question| question.contains("Start scanning")),
            "{:?}",
            prompt.asked.borrow()
        );
    }

    // There is nobody to answer, so asking would hang.
    #[test]
    fn refuses_to_run_without_a_terminal() {
        let root = tempfile::TempDir::new().expect("root");
        let mut prompt = ScriptedPrompt::new(&[], true);
        prompt.interactive = false;

        let error = run(
            &source(&["acme"], &["acme/payments"]),
            &prompt,
            "github.com",
            root.path(),
            now(),
        )
        .expect_err("refused");

        assert!(error.contains("requires a terminal"), "{error}");
        assert!(error.contains("bulk-scan repositories.csv"), "{error}");
    }

    #[test]
    fn builds_urls_for_the_host_it_was_given() {
        let root = tempfile::TempDir::new().expect("root");
        let prompt = ScriptedPrompt::new(&[], true);

        let result = run(
            &source(&["acme"], &["acme/payments"]),
            &prompt,
            "github.example.com",
            root.path(),
            now(),
        )
        .expect("the wizard runs")
        .expect("an inventory");

        let inventory = std::fs::read_to_string(&result.input_path).expect("read");
        assert!(
            inventory.contains("https://github.example.com/acme/payments.git"),
            "{inventory}"
        );
        assert_eq!(result.github_host, "github.example.com");
    }
}
