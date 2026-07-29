//! Checking that a fixture does not tell a scan what is wrong with it.
//!
//! Not a port: upstream has no corpus.
//!
//! A scan reads its whole target. If a fixture says what is planted in it, the
//! run measures reading rather than detection, and the number it produces looks
//! exactly like a real one. That has happened twice here. The first time it was
//! a README inside the fixture directory, caught by a person. The second time
//! it was comments in the source — `/* Use after free: ... */` — and docstrings
//! in the control fixture explaining why each decoy was safe. That one survived
//! for days and every number taken in that period was wrong.
//!
//! Both times the corpus was inspected by reading it, and both times reading it
//! is what failed. So this checks it instead, before the score is printed.
//!
//! **This errs toward flagging, which is the opposite of the choice made in
//! [`crate::manifest_form`], and deliberately so.** That check speaks about
//! somebody's real scan, where crying wolf gets it switched off. This one
//! speaks about a test corpus that only its author reads: a false flag costs
//! one glance, and a miss costs every number the corpus ever produces.

use std::path::Path;

/// Text in a fixture that names what the fixture is hiding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    pub fixture: String,
    /// Path relative to the fixture.
    pub file: String,
    /// One-based.
    pub line: u32,
    /// The phrase that matched.
    pub phrase: String,
    /// The line it was found in, trimmed.
    pub text: String,
}

/// Phrases that name a weakness class, or admit the corpus is a corpus.
///
/// Lower case; matched case-insensitively against whole lines. Chosen to be
/// things that appear in writing *about* code rather than in code that was
/// written to work — a comment explaining what a routine is for does not need
/// any of them.
const TELLS: &[&str] = &[
    "sql injection",
    "command injection",
    "code injection",
    "shell injection",
    "path traversal",
    "directory traversal",
    "buffer overflow",
    "stack overflow",
    "heap overflow",
    "use after free",
    "use-after-free",
    "off by one",
    "off-by-one",
    "double free",
    "memory safety",
    "memory-safety",
    "ssrf",
    "server-side request forgery",
    "request forgery",
    "timing attack",
    "timing-unsafe",
    "timing side channel",
    "constant-time",
    "constant time",
    "cross-site",
    "deserialization",
    "race condition",
    "toctou",
    "vulnerab",
    "exploit",
    "attacker",
    "malicious",
    "unsanitiz",
    "unvalidat",
    "insecure",
    "usually unsafe",
    "often unsafe",
    "is unsafe",
    "safe because",
    "is safe",
    "are safe",
    "deliberate",
    "planted",
    "on purpose",
    "for testing a scanner",
    "this is a test",
    "weak hash",
    "weak password",
    "hardcoded credential",
    "hard-coded credential",
];

/// Reads a fixture's files and reports anything that gives the answers away.
///
/// `root` is the fixture directory itself. Files that cannot be read as text
/// are skipped rather than guessed at — a compiled artifact has no comments to
/// leak, and one should not be in a fixture at all.
#[must_use]
pub fn audit_fixture(name: &str, root: &Path) -> Vec<Leak> {
    let mut leaks = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Its own history is not part of the target a scan reads.
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            leaks.extend(leaks_in(name, &relative, &text));
        }
    }

    leaks.sort_by(|a, b| (&a.file, a.line, &a.phrase).cmp(&(&b.file, b.line, &b.phrase)));
    leaks
}

/// Every tell in one file's text.
fn leaks_in(fixture: &str, file: &str, text: &str) -> Vec<Leak> {
    let mut leaks = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let lowered = line.to_ascii_lowercase();
        // Every tell on the line, not only the first. This is read while
        // fixing a fixture, and the second phrase on a line is the second
        // thing that has to go.
        let phrases = TELLS
            .iter()
            .filter(|tell| lowered.contains(**tell))
            .map(|tell| (*tell).to_owned())
            .chain(cwe_in(&lowered));
        for phrase in phrases {
            leaks.push(Leak {
                fixture: fixture.to_owned(),
                file: file.to_owned(),
                line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                phrase,
                text: line.trim().to_owned(),
            });
        }
    }
    leaks
}

/// A CWE identifier anywhere in the line.
///
/// The most direct giveaway there is: a fixture citing the identifier of the
/// thing planted in it has handed over the classification as well as the
/// location.
fn cwe_in(lowered: &str) -> Option<String> {
    let start = lowered.find("cwe-")?;
    let digits: String = lowered[start + 4..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then(|| format!("cwe-{digits}"))
}

/// How a leak reads for a person.
#[must_use]
pub fn describe(leak: &Leak) -> String {
    format!(
        "{}/{}:{} says \"{}\" — {}",
        leak.fixture,
        leak.file,
        leak.line,
        leak.phrase,
        leak.text.chars().take(72).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, name: &str, body: &str) {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("creates");
        std::fs::write(path, body).expect("writes");
    }

    #[test]
    fn finds_a_comment_that_names_the_flaw() {
        let directory = tempfile::tempdir().expect("a directory");
        write(
            directory.path(),
            "src/store.c",
            "/* Use after free: the record is released but left in the table. */\nvoid f(void) {}\n",
        );

        let leaks = audit_fixture("kv-store", directory.path());

        assert_eq!(leaks.len(), 1, "{leaks:?}");
        assert_eq!(leaks[0].phrase, "use after free");
        assert_eq!(leaks[0].line, 1);
        assert!(describe(&leaks[0]).contains("src/store.c:1"), "{leaks:?}");
    }

    /// The control fixture's failure mode, which is the mirror image: a decoy
    /// that comes with a note saying it is safe tests nothing at all.
    #[test]
    fn finds_a_docstring_that_says_a_decoy_is_safe() {
        let directory = tempfile::tempdir().expect("a directory");
        write(
            directory.path(),
            "src/inventory.py",
            "\"\"\"Several routines here resemble things that are often unsafe.\n\nEach is safe.\n\"\"\"\n",
        );

        let leaks = audit_fixture("inventory-service", directory.path());

        assert!(leaks.len() >= 2, "{leaks:?}");
        assert!(leaks.iter().any(|leak| leak.phrase == "often unsafe"));
        assert!(leaks.iter().any(|leak| leak.phrase == "is safe"));
    }

    #[test]
    fn finds_a_cited_cwe() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.js", "// See CWE-89 for background.\n");

        let leaks = audit_fixture("f", directory.path());

        assert_eq!(leaks[0].phrase, "cwe-89");
    }

    /// Comments that describe what a routine is for are what a fixture should
    /// read like, and must not be flagged.
    #[test]
    fn leaves_ordinary_comments_alone() {
        let directory = tempfile::tempdir().expect("a directory");
        write(
            directory.path(),
            "src/server.js",
            "// A small file server and link previewer.\n\
             // Serves a file from the public directory.\n\
             // Fetches a URL and returns its first kilobyte, for link previews.\n\
             // Compares a submitted token against the configured one.\n",
        );

        assert_eq!(audit_fixture("link-service", directory.path()), Vec::new());
    }

    #[test]
    fn does_not_read_the_fixtures_own_history() {
        let directory = tempfile::tempdir().expect("a directory");
        write(
            directory.path(),
            ".git/COMMIT_EDITMSG",
            "plant a use after free\n",
        );
        write(directory.path(), "a.c", "int main(void) { return 0; }\n");

        assert_eq!(audit_fixture("f", directory.path()), Vec::new());
    }

    #[test]
    fn skips_something_that_is_not_text() {
        let directory = tempfile::tempdir().expect("a directory");
        std::fs::write(directory.path().join("a.bin"), [0xff, 0xfe, 0x00, 0x01]).expect("writes");

        assert_eq!(audit_fixture("f", directory.path()), Vec::new());
    }

    #[test]
    fn an_empty_fixture_leaks_nothing() {
        let directory = tempfile::tempdir().expect("a directory");

        assert_eq!(audit_fixture("f", directory.path()), Vec::new());
    }
}

#[cfg(test)]
mod shipped_corpus_tests {
    use super::*;

    fn corpus_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The check that earns this module its place: the corpus that ships,
    /// audited on every test run rather than by somebody remembering to look.
    ///
    /// It has been wrong twice. It will be wrong again the next time a fixture
    /// gains a flaw and a helpful comment along with it.
    #[test]
    fn the_shipped_fixtures_do_not_give_their_answers_away() {
        let text = std::fs::read_to_string(corpus_root().join("benchmark/ground-truth.json"))
            .expect("the shipped corpus");
        let corpus = crate::benchmark::GroundTruth::parse(&text).expect("parses");

        let mut leaks = Vec::new();
        for fixture in &corpus.fixtures {
            let root = corpus_root().join(&fixture.path);
            assert!(root.is_dir(), "no fixture at {}", root.display());
            leaks.extend(audit_fixture(&fixture.name, &root));
        }

        assert!(
            leaks.is_empty(),
            "the corpus gives its answers away:\n{}",
            leaks.iter().map(describe).collect::<Vec<_>>().join("\n")
        );
    }

    /// And proof the audit is not vacuous. The comments below are the real ones
    /// that were in `kv-store` and `inventory-service` until 2026-07-29; a check
    /// that passed over them would be worth nothing.
    #[test]
    fn the_audit_catches_what_was_actually_in_the_corpus() {
        let directory = tempfile::tempdir().expect("a directory");
        std::fs::write(
            directory.path().join("store.c"),
            "/* A key/value store with deliberate memory-safety bugs, for testing a scanner. */\n\
             /* Stack buffer overflow: the label is copied without checking its length. */\n\
             /* Use after free: the record is released but left in the table, so a later\n\
             \x20* lookup reads memory that has been returned to the allocator. */\n\
             /* Off-by-one: the loop admits index MAX_RECORDS, one past the last slot. */\n\
             /* Reads freed memory. */\n",
        )
        .expect("writes");

        let leaks = audit_fixture("kv-store", directory.path());

        for expected in [
            "deliberate",
            "memory-safety",
            "buffer overflow",
            "use after free",
            "off-by-one",
        ] {
            assert!(
                leaks.iter().any(|leak| leak.phrase == expected),
                "missed {expected} in {leaks:?}"
            );
        }
    }
}
