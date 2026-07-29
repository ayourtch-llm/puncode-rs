//! Making flaws on purpose, to find out what a scanner does not see.
//!
//! Not a port: upstream has no notion of this.
//!
//! Every measurement in this project so far answers one question — how good is
//! the scanner at flaws somebody thought to plant? A corpus can only ever
//! contain what its author imagined, and a score against it says nothing about
//! anybody else's code.
//!
//! Mutation testing turns that around. Start from code that is safe, break one
//! protection in a known way, and ask whether the scanner notices. The ground
//! truth is true by construction: the difference between the two files *is* the
//! flaw, and its location is exactly where the edit was made.
//!
//! **How far that reaches, honestly.** The idea works on any codebase. What is
//! implemented here does not: each operator matches *literal lines*, taken from
//! `inventory-service`, and will fire on other code only where it happens to
//! contain those lines verbatim. So this demonstrates the technique and
//! measures this corpus; it does not yet measure anybody else's repository, and
//! an earlier version of this comment said it did. Generalising means matching
//! idioms rather than text, which means parsing rather than comparing strings —
//! a different piece of work, and one where soundness is the whole difficulty.
//!
//! It also aims squarely at the one blind spot measurement here has found. The
//! model follows a taint it can see and does not see an absence: `/admin/export`
//! missing the `require_admin()` its siblings call went unnoticed. Deleting a
//! guard is the easiest mutation there is to generate, and the hardest class for
//! the scanner — so this can produce, mechanically, exactly the flaws it is
//! worst at.
//!
//! **What this cannot do, and says so.** An operator recognises a safe idiom and
//! replaces it with an unsafe one. Whether the result is genuinely exploitable
//! depends on whether anything untrusted reaches it, which reading one function
//! cannot settle. So a generated mutant is a **candidate** until somebody
//! confirms it, and [`Mutant::confirmed_by`] carries how — for the operators
//! shipped here, by running an attack against the mutant and the same attack
//! against the original.
//!
//! A mutant nobody has confirmed still measures something worth knowing: a
//! protection was removed and the scanner said nothing. It just must not be
//! reported as a missed vulnerability, because it might not be one.

/// A safe idiom, and the unsafe one it becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// Short name, used as the mutant's id.
    pub id: &'static str,
    /// The weakness the mutation introduces.
    pub cwe: &'static str,
    pub severity: &'static str,
    /// What the mutation does, for whoever reads the ground truth.
    pub summary: &'static str,
    /// The exact text to find. Whole lines, matched with their indentation
    /// stripped so the operator works at any nesting.
    pub before: &'static [&'static str],
    /// What replaces it, at the same indentation.
    pub after: &'static [&'static str],
    /// How the shipped example was shown to be a real flaw.
    ///
    /// `None` when nothing has confirmed it, which is the honest default for an
    /// operator applied to code nobody has checked.
    pub confirmed_by: Option<&'static str>,
}

/// One flaw introduced into one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutant {
    pub operator: &'static str,
    pub cwe: &'static str,
    pub severity: &'static str,
    pub summary: &'static str,
    /// Path of the file that was changed, as given.
    pub file: String,
    /// Inclusive first and last line of the replacement, one-based.
    pub lines: (u32, u32),
    /// The whole file, mutated.
    pub source: String,
    /// How this was shown to be a real flaw, when anything has.
    pub confirmed_by: Option<&'static str>,
}

impl Mutant {
    /// Whether anything has established that this is genuinely exploitable.
    #[must_use]
    pub fn confirmed(&self) -> bool {
        self.confirmed_by.is_some()
    }
}

/// The operators that ship.
///
/// Deliberately few. Each one replaces an idiom whose safety is the whole
/// reason it is written that way — a bound parameter, an allowlist, an argument
/// list — with the form that idiom exists to avoid. An operator that needed a
/// judgement about the surrounding code would produce mutants nobody could
/// trust, and the point of this is ground truth nobody has to trust.
pub const OPERATORS: &[Operator] = &[
    Operator {
        id: "bind-to-concat",
        cwe: "CWE-89",
        severity: "high",
        summary: "a bound query parameter replaced by string concatenation",
        before: &["\"SELECT sku, name, quantity FROM items WHERE sku = ?\", (sku,)"],
        after: &["\"SELECT sku, name, quantity FROM items WHERE sku = '\" + sku + \"'\""],
        confirmed_by: Some(
            "An injection payload through find_item returned a row it must not have; the same \
             payload against the original returned nothing.",
        ),
    },
    Operator {
        id: "drop-validator",
        cwe: "CWE-22",
        severity: "high",
        summary: "an allowlist check removed from a path built out of an argument",
        before: &[
            "if not SKU_PATTERN.fullmatch(sku):",
            "raise ValueError(\"not a stock keeping unit\")",
        ],
        after: &[],
        confirmed_by: Some(
            "export_path(\"../../etc/passwd\") returned a path outside EXPORT_ROOT; the original \
             refused it.",
        ),
    },
    Operator {
        id: "list-to-shell",
        cwe: "CWE-78",
        severity: "critical",
        summary: "an argument list replaced by a shell command string",
        before: &["subprocess.run([\"gzip\", \"--force\", path], check=True)"],
        after: &["subprocess.run(f\"gzip --force {path}\", shell=True, check=True)"],
        confirmed_by: Some(
            "A path of \"x; touch /tmp/pwned\" ran the second command; the original passed it to \
             gzip as a filename.",
        ),
    },
];

/// Every mutant one file admits.
///
/// One mutant per operator per match, each carrying the whole file so a caller
/// can write it wherever it likes without re-deriving anything.
#[must_use]
pub fn mutate(file: &str, source: &str) -> Vec<Mutant> {
    let lines: Vec<&str> = source.lines().collect();
    let mut mutants = Vec::new();

    for operator in OPERATORS {
        for start in 0..lines.len() {
            if !matches_at(&lines, start, operator.before) {
                continue;
            }
            let indent = indent_of(lines[start]);
            let mut rewritten: Vec<String> = lines[..start]
                .iter()
                .map(|line| (*line).to_owned())
                .collect();
            for replacement in operator.after {
                rewritten.push(format!("{indent}{replacement}"));
            }
            let first = u32::try_from(start + 1).unwrap_or(u32::MAX);
            // A deletion has no line of its own, so it is recorded at the line
            // the removed code began on — which is where a reader looking for
            // what changed will go.
            let last = first + u32::try_from(operator.after.len().max(1)).unwrap_or(1) - 1;
            rewritten.extend(
                lines[start + operator.before.len()..]
                    .iter()
                    .map(|line| (*line).to_owned()),
            );

            let mut body = rewritten.join("\n");
            if source.ends_with('\n') {
                body.push('\n');
            }
            mutants.push(Mutant {
                operator: operator.id,
                cwe: operator.cwe,
                severity: operator.severity,
                summary: operator.summary,
                file: file.to_owned(),
                lines: (first, last),
                source: body,
                confirmed_by: operator.confirmed_by,
            });
        }
    }

    mutants
}

/// Whether the operator's lines sit at `start`, ignoring indentation.
fn matches_at(lines: &[&str], start: usize, before: &[&str]) -> bool {
    if before.is_empty() || start + before.len() > lines.len() {
        return false;
    }
    before
        .iter()
        .enumerate()
        .all(|(offset, wanted)| lines[start + offset].trim() == *wanted)
}

fn indent_of(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_fixture() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/inventory-service/src/inventory.py"),
        )
        .expect("the control fixture")
    }

    /// Against the fixture the scanner has called clean in every run.
    #[test]
    fn every_operator_finds_its_idiom_in_the_control_fixture() {
        let mutants = mutate("src/inventory.py", &control_fixture());

        let found: Vec<&str> = mutants.iter().map(|mutant| mutant.operator).collect();
        for operator in OPERATORS {
            assert!(
                found.contains(&operator.id),
                "{} found nothing in a file written to contain exactly that idiom",
                operator.id
            );
        }
    }

    /// The mutation has to change the file, and change only what it says.
    #[test]
    fn a_mutant_differs_from_the_original_at_the_line_it_reports() {
        let original = control_fixture();

        for mutant in mutate("src/inventory.py", &original) {
            assert_ne!(
                mutant.source, original,
                "{} changed nothing",
                mutant.operator
            );
            let (before, after): (Vec<&str>, Vec<&str>) =
                (original.lines().collect(), mutant.source.lines().collect());
            let first_difference = before
                .iter()
                .zip(&after)
                .position(|(a, b)| a != b)
                .or(Some(before.len().min(after.len())))
                .expect("a difference");
            let reported = usize::try_from(mutant.lines.0).expect("fits") - 1;
            assert_eq!(
                first_difference,
                reported,
                "{} reports line {} and first differs at {}",
                mutant.operator,
                mutant.lines.0,
                first_difference + 1
            );
        }
    }

    /// A deletion removes lines; a replacement keeps the count.
    #[test]
    fn dropping_a_validator_removes_the_guard() {
        let original = control_fixture();
        let mutant = mutate("src/inventory.py", &original)
            .into_iter()
            .find(|mutant| mutant.operator == "drop-validator")
            .expect("the operator");

        assert_eq!(
            mutant.source.lines().count(),
            original.lines().count() - 2,
            "the guard is two lines"
        );
        assert!(!mutant.source.contains("SKU_PATTERN.fullmatch"));
        // And the thing it was guarding is still there, or the mutant is not a
        // flaw, it is a deletion.
        assert!(mutant.source.contains("os.path.join(EXPORT_ROOT"));
    }

    #[test]
    fn binding_becomes_concatenation() {
        let mutant = mutate("src/inventory.py", &control_fixture())
            .into_iter()
            .find(|mutant| mutant.operator == "bind-to-concat")
            .expect("the operator");

        assert!(mutant.source.contains("WHERE sku = '\" + sku + \"'"));
        assert!(!mutant.source.contains("WHERE sku = ?\", (sku,)"));
    }

    #[test]
    fn an_argument_list_becomes_a_shell_string() {
        let mutant = mutate("src/inventory.py", &control_fixture())
            .into_iter()
            .find(|mutant| mutant.operator == "list-to-shell")
            .expect("the operator");

        assert!(mutant.source.contains("shell=True"));
        assert!(!mutant.source.contains("[\"gzip\", \"--force\", path]"));
    }

    /// Indentation is preserved, or the mutant does not parse.
    #[test]
    fn the_replacement_keeps_the_indentation_it_replaced() {
        let source =
            "def f(path):\n        subprocess.run([\"gzip\", \"--force\", path], check=True)\n";

        let mutant = mutate("a.py", source).into_iter().next().expect("a mutant");

        assert!(
            mutant.source.contains("\n        subprocess.run(f\"gzip"),
            "{}",
            mutant.source
        );
    }

    /// Code with none of the idioms yields nothing, rather than a mutation
    /// somewhere arbitrary.
    #[test]
    fn code_without_the_idioms_yields_no_mutants() {
        assert!(mutate("a.py", "def f():\n    return 1\n").is_empty());
    }

    /// Every shipped operator has been shown to introduce a real flaw. An
    /// operator nobody has confirmed may still be worth running, but it must
    /// not arrive claiming to be a vulnerability.
    #[test]
    fn every_shipped_operator_records_how_it_was_confirmed() {
        for operator in OPERATORS {
            let confirmation = operator
                .confirmed_by
                .unwrap_or_else(|| panic!("{} has no confirmation", operator.id));
            assert!(
                confirmation.contains("original"),
                "{}: a confirmation has to say what the unmutated code did too — {confirmation}",
                operator.id
            );
        }
    }

    #[test]
    fn a_mutant_carries_its_confirmation() {
        for mutant in mutate("src/inventory.py", &control_fixture()) {
            assert!(mutant.confirmed(), "{}", mutant.operator);
        }
    }

    /// A file with no trailing newline does not gain one, and one with keeps it.
    #[test]
    fn the_trailing_newline_is_left_as_it_was() {
        let with = "subprocess.run([\"gzip\", \"--force\", path], check=True)\n";
        let without = "subprocess.run([\"gzip\", \"--force\", path], check=True)";

        assert!(mutate("a.py", with)[0].source.ends_with('\n'));
        assert!(!mutate("a.py", without)[0].source.ends_with('\n'));
    }
}

impl Mutant {
    /// The mutant, stated as a planted flaw.
    ///
    /// Ground truth for a mutant is not a judgement anybody has to make: the
    /// edit is the flaw and its line is where the edit was. This is the join to
    /// [`crate::benchmark`], so a run over mutants scores the same way a run
    /// over the fixture corpus does — same matcher, same class handling, same
    /// range when the scan names a different weakness.
    ///
    /// An unconfirmed mutant carries its uncertainty into the corpus through
    /// [`crate::benchmark::PlantedFlaw::found_not_planted`] and `why`, so a
    /// score built on it cannot quietly read as a score over confirmed flaws.
    #[must_use]
    pub fn as_planted_flaw(&self) -> crate::benchmark::PlantedFlaw {
        crate::benchmark::PlantedFlaw {
            id: self.operator.to_owned(),
            file: self.file.clone(),
            lines: self.lines,
            cwe: Some(self.cwe.to_owned()),
            severity: Some(self.severity.to_owned()),
            summary: Some(self.summary.to_owned()),
            also: Vec::new(),
            found_not_planted: false,
            why: Some(match self.confirmed_by {
                Some(confirmation) => format!(
                    "Introduced by mutation, and confirmed to be a real flaw: {confirmation}"
                ),
                None => "Introduced by mutation. NOT CONFIRMED: an operator swaps a safe idiom \
                         for an unsafe one, and whether untrusted input reaches it is not \
                         something this can settle. A scan that misses it has missed a removed \
                         protection, which is worth knowing, and not necessarily a vulnerability."
                    .to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod ground_truth_tests {
    use super::*;

    fn control_fixture() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/inventory-service/src/inventory.py"),
        )
        .expect("the control fixture")
    }

    /// The flaw a mutant states must be the edit it made, with no judgement in
    /// between.
    #[test]
    fn a_mutant_states_itself_as_the_flaw_it_introduced() {
        for mutant in mutate("src/inventory.py", &control_fixture()) {
            let flaw = mutant.as_planted_flaw();

            assert_eq!(flaw.id, mutant.operator);
            assert_eq!(flaw.file, mutant.file);
            assert_eq!(flaw.lines, mutant.lines);
            assert_eq!(flaw.cwe.as_deref(), Some(mutant.cwe));
        }
    }

    /// A confirmed mutant carries the attack that confirmed it, so a reader of
    /// the corpus can see why it was believed.
    #[test]
    fn a_confirmed_mutant_carries_its_attack() {
        let flaw = mutate("src/inventory.py", &control_fixture())[0].as_planted_flaw();

        let why = flaw.why.expect("a reason");
        assert!(why.contains("confirmed to be a real flaw"), "{why}");
        assert!(why.contains("original"), "{why}");
    }

    /// And an unconfirmed one says so loudly, because a corpus that quietly
    /// mixes the two produces a number nobody can read.
    #[test]
    fn an_unconfirmed_mutant_says_it_is_unconfirmed() {
        let mut mutant = mutate("src/inventory.py", &control_fixture())[0].clone();
        mutant.confirmed_by = None;

        let why = mutant.as_planted_flaw().why.expect("a reason");

        assert!(why.contains("NOT CONFIRMED"), "{why}");
        assert!(why.contains("not necessarily a vulnerability"), "{why}");
    }

    /// The flaw round-trips through the corpus format the benchmark reads.
    #[test]
    fn the_flaw_survives_the_corpus_format() {
        let flaw = mutate("src/inventory.py", &control_fixture())[0].as_planted_flaw();

        let corpus = serde_json::json!({
            "fixtures": [{
                "name": "mutant",
                "path": "mutants/bind-to-concat",
                "flaws": [flaw],
            }]
        })
        .to_string();

        let parsed = crate::benchmark::GroundTruth::parse(&corpus).expect("parses");
        assert_eq!(parsed.fixtures[0].flaws[0], flaw);
    }
}
