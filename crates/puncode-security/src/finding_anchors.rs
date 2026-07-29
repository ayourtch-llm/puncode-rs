//! Checking that a finding points at code that exists.
//!
//! Not a port: upstream validates that a location is a safe repository-relative
//! path, and stops there.
//!
//! Everything else that checks a scan here checks it against itself. The seal
//! says the documents are the ones that were sealed; the fingerprints say a
//! finding was not renamed or moved between scans. All of it would hold for a
//! finding that cites `src/auth.py:184` in a repository where `src/auth.py` has
//! ninety lines, or does not exist at all.
//!
//! That is the cheapest possible hallucination to detect and nothing was
//! detecting it. A reader working down a report opens the file and finds
//! nothing there, and has to decide for themselves whether the tool is worth
//! their morning.
//!
//! Two questions only, and both have exact answers:
//!
//! - does the file the finding names exist in the target?
//! - is the line it names inside that file?
//!
//! Neither says a finding is *right*. A location that resolves can still
//! describe code that is perfectly safe, and this makes no claim about that —
//! see `verify`, which says the same thing about consistency. What it rules out
//! is a finding about code that is not there.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Why a finding's location could not be confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unanchored {
    /// The named file is not in the target.
    NoSuchFile { finding: String, file: String },
    /// The named line is past the end of the file.
    PastEndOfFile {
        finding: String,
        file: String,
        line: u32,
        lines: u32,
    },
    /// The path leaves the target, or is otherwise not usable.
    ///
    /// Contract validation refuses these before a scan is accepted, so seeing
    /// one here means the documents were not validated — worth saying rather
    /// than quietly resolving it against whatever is at the other end.
    UnsafePath { finding: String, file: String },
}

impl Unanchored {
    /// The finding this is about.
    #[must_use]
    pub fn finding(&self) -> &str {
        match self {
            Self::NoSuchFile { finding, .. }
            | Self::PastEndOfFile { finding, .. }
            | Self::UnsafePath { finding, .. } => finding,
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NoSuchFile { finding, file } => {
                format!("{finding}: no such file in the target — {file}")
            }
            Self::PastEndOfFile {
                finding,
                file,
                line,
                lines,
            } => format!("{finding}: {file} has {lines} line(s), and the finding cites {line}"),
            Self::UnsafePath { finding, file } => {
                format!("{finding}: the path leaves the target — {file}")
            }
        }
    }
}

/// What checking a scan's findings against the code found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorCheck {
    /// Locations that resolved.
    pub resolved: usize,
    /// Locations that did not, with why.
    pub unanchored: Vec<Unanchored>,
    /// Findings that cite nowhere at all.
    ///
    /// Not an error — a finding may be about a repository rather than a line —
    /// but a report of them is a report nobody can check.
    pub without_locations: Vec<String>,
}

impl AnchorCheck {
    #[must_use]
    pub fn holds(&self) -> bool {
        self.unanchored.is_empty()
    }

    /// One line for a summary, when there is anything to say.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        if self.unanchored.is_empty() {
            return None;
        }
        let findings: std::collections::BTreeSet<&str> =
            self.unanchored.iter().map(Unanchored::finding).collect();
        Some(format!(
            "{} finding(s) point at code that is not there. A location that does not resolve is \
             not a judgement call — the file or the line is absent from the target.",
            findings.len()
        ))
    }
}

/// One place a finding says something is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cited {
    /// Whatever identifies the finding to a reader.
    pub finding: String,
    pub file: String,
    pub line: u32,
}

/// Checks every cited location against the target.
///
/// Files are read once each however many findings cite them, because a report
/// over a large repository can cite the same file hundreds of times and this
/// runs at the end of a scan that already took minutes.
#[must_use]
pub fn check(cited: &[Cited], empty_findings: &[String], target: &Path) -> AnchorCheck {
    let mut check = AnchorCheck {
        without_locations: empty_findings.to_vec(),
        ..AnchorCheck::default()
    };
    let mut lengths: BTreeMap<String, Option<u32>> = BTreeMap::new();

    for location in cited {
        let Some(relative) = contained_path(&location.file) else {
            check.unanchored.push(Unanchored::UnsafePath {
                finding: location.finding.clone(),
                file: location.file.clone(),
            });
            continue;
        };
        let lines = *lengths
            .entry(location.file.clone())
            .or_insert_with(|| line_count(&target.join(&relative)));
        let Some(lines) = lines else {
            check.unanchored.push(Unanchored::NoSuchFile {
                finding: location.finding.clone(),
                file: location.file.clone(),
            });
            continue;
        };
        // Line 0 is not a line. An empty file has none, so nothing can resolve
        // in it and citing it is the same error as citing past the end.
        if location.line == 0 || location.line > lines {
            check.unanchored.push(Unanchored::PastEndOfFile {
                finding: location.finding.clone(),
                file: location.file.clone(),
                line: location.line,
                lines,
            });
            continue;
        }
        check.resolved += 1;
    }

    check
}

/// A relative path that stays inside the target, or nothing.
///
/// Rejected rather than normalised: `..` in a finding's path is a document that
/// never passed contract validation, and quietly resolving it would read a file
/// the scan was never pointed at.
fn contained_path(path: &str) -> Option<PathBuf> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return None;
    }
    let mut cleaned = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => cleaned.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!cleaned.as_os_str().is_empty()).then_some(cleaned)
}

/// How many lines a file has, or nothing when it is not a readable file.
///
/// A file whose last line has no terminator still has that line, which is how
/// an editor counts and therefore how whoever opens the file will count.
fn line_count(path: &Path) -> Option<u32> {
    // Not followed: a link inside the target could point anywhere, and a
    // finding resolving against something outside it is not resolved.
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let text = std::fs::read(path).ok()?;
    if text.is_empty() {
        return Some(0);
    }
    let newlines = text.iter().filter(|byte| **byte == b'\n').count();
    let trailing = usize::from(text.last() != Some(&b'\n'));
    u32::try_from(newlines + trailing).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, name: &str, body: &str) {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("creates");
        std::fs::write(path, body).expect("writes");
    }

    fn cited(finding: &str, file: &str, line: u32) -> Cited {
        Cited {
            finding: finding.to_owned(),
            file: file.to_owned(),
            line,
        }
    }

    #[test]
    fn a_location_inside_the_file_resolves() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "src/a.py", "one\ntwo\nthree\n");

        let check = check(&[cited("F-1", "src/a.py", 2)], &[], directory.path());

        assert!(check.holds());
        assert_eq!(check.resolved, 1);
        assert_eq!(check.summary(), None);
    }

    /// The case this exists for.
    #[test]
    fn a_finding_about_a_file_that_is_not_there_is_named() {
        let directory = tempfile::tempdir().expect("a directory");

        let check = check(&[cited("F-1", "src/auth.py", 184)], &[], directory.path());

        assert!(!check.holds());
        assert_eq!(
            check.unanchored,
            vec![Unanchored::NoSuchFile {
                finding: "F-1".to_owned(),
                file: "src/auth.py".to_owned(),
            }]
        );
        let summary = check.summary().expect("a summary");
        assert!(summary.contains("1 finding(s)"), "{summary}");
        assert!(summary.contains("not a judgement call"), "{summary}");
    }

    #[test]
    fn a_line_past_the_end_is_named_with_the_real_length() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.py", "one\ntwo\n");

        let check = check(&[cited("F-1", "a.py", 90)], &[], directory.path());

        assert_eq!(
            check.unanchored[0],
            Unanchored::PastEndOfFile {
                finding: "F-1".to_owned(),
                file: "a.py".to_owned(),
                line: 90,
                lines: 2,
            }
        );
        assert!(
            check.unanchored[0].describe().contains("has 2 line(s)"),
            "{:?}",
            check.unanchored[0]
        );
    }

    /// The last line counts even without a terminator, because that is how the
    /// person opening the file will count it.
    #[test]
    fn the_last_line_counts_without_a_trailing_newline() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.py", "one\ntwo");

        let check = check(&[cited("F-1", "a.py", 2)], &[], directory.path());

        assert!(check.holds(), "{check:?}");
    }

    #[test]
    fn nothing_resolves_in_an_empty_file() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.py", "");

        let check = check(&[cited("F-1", "a.py", 1)], &[], directory.path());

        assert!(!check.holds());
    }

    /// Line zero is not a line, and must not pass by being "within" the file.
    #[test]
    fn line_zero_does_not_resolve() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.py", "one\n");

        let check = check(&[cited("F-1", "a.py", 0)], &[], directory.path());

        assert!(!check.holds());
    }

    /// A path leaving the target is refused rather than resolved against
    /// whatever happens to be at the other end.
    #[test]
    fn a_path_out_of_the_target_is_refused() {
        let outside = tempfile::tempdir().expect("a directory");
        write(outside.path(), "secret.txt", "line\n");
        let directory = tempfile::tempdir().expect("a directory");

        for path in ["../secret.txt", "/etc/passwd", "a/../../secret.txt"] {
            let check = check(&[cited("F-1", path, 1)], &[], directory.path());
            assert_eq!(
                check.unanchored,
                vec![Unanchored::UnsafePath {
                    finding: "F-1".to_owned(),
                    file: path.to_owned(),
                }],
                "{path}"
            );
        }
    }

    /// A symlink inside the target is not a file the scan was pointed at.
    #[test]
    #[cfg(unix)]
    fn a_link_inside_the_target_does_not_resolve() {
        let outside = tempfile::tempdir().expect("a directory");
        write(outside.path(), "secret.txt", "line\n");
        let directory = tempfile::tempdir().expect("a directory");
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            directory.path().join("link.py"),
        )
        .expect("links");

        let check = check(&[cited("F-1", "link.py", 1)], &[], directory.path());

        assert!(matches!(check.unanchored[0], Unanchored::NoSuchFile { .. }));
    }

    /// A finding citing nowhere is recorded but is not a failure.
    #[test]
    fn a_finding_without_a_location_is_recorded_and_not_a_failure() {
        let directory = tempfile::tempdir().expect("a directory");

        let check = check(&[], &["F-9".to_owned()], directory.path());

        assert!(check.holds());
        assert_eq!(check.without_locations, vec!["F-9"]);
    }

    /// Many citations of one file must not read it many times.
    #[test]
    fn reads_each_file_once() {
        let directory = tempfile::tempdir().expect("a directory");
        write(directory.path(), "a.py", "one\ntwo\nthree\n");
        let many: Vec<Cited> = (1..=3)
            .flat_map(|line| (0..50).map(move |n| cited(&format!("F-{n}"), "a.py", line)))
            .collect();

        let check = check(&many, &[], directory.path());

        assert_eq!(check.resolved, 150);
        assert!(check.holds());
    }

    #[test]
    fn one_finding_is_counted_once_however_many_locations_it_gets_wrong() {
        let directory = tempfile::tempdir().expect("a directory");

        let check = check(
            &[
                cited("F-1", "gone.py", 1),
                cited("F-1", "also-gone.py", 2),
                cited("F-2", "gone.py", 3),
            ],
            &[],
            directory.path(),
        );

        assert_eq!(check.unanchored.len(), 3);
        assert!(check.summary().expect("a summary").contains("2 finding(s)"));
    }
}

/// Every location a findings document cites, and the findings citing none.
///
/// Lives here rather than at the call sites so the scan path and any later
/// reader pull the same locations out of the same document. `endLine` is
/// checked as well as `startLine`: a finding whose range runs off the end of
/// the file is as wrong as one that starts past it, and only one of the two
/// would have been noticed.
#[must_use]
pub fn cited_locations(findings: &crate::models::FindingsDocument) -> (Vec<Cited>, Vec<String>) {
    let mut cited = Vec::new();
    let mut without = Vec::new();

    for finding in &findings.findings {
        if finding.locations.is_empty() {
            without.push(finding.title.clone());
            continue;
        }
        for location in &finding.locations {
            for line in std::iter::once(location.start_line).chain(location.end_line) {
                cited.push(Cited {
                    finding: finding.title.clone(),
                    file: location.path.clone(),
                    line: u32::try_from(line).unwrap_or(u32::MAX),
                });
            }
        }
    }

    (cited, without)
}

#[cfg(test)]
mod document_tests {
    use super::*;

    /// A real findings document from a real run. Written from a guess at the
    /// schema first, which did not parse — the shape has required fields that
    /// were not obvious, and a test built on the guess would have been testing
    /// the guess.
    fn real_findings() -> crate::models::FindingsDocument {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/findings-link-service.json"),
        )
        .expect("the captured findings");
        serde_json::from_str(&text).expect("the findings parse")
    }

    /// A range running off the end is as wrong as a start past the end, and
    /// checking only the start would have missed it.
    #[test]
    fn takes_both_ends_of_every_range() {
        let findings = real_findings();
        let expected: usize = findings
            .findings
            .iter()
            .flat_map(|finding| &finding.locations)
            .map(|location| 1 + usize::from(location.end_line.is_some()))
            .sum();

        let (cited, without) = cited_locations(&findings);

        assert!(expected > findings.findings.len(), "no ranges to check");
        assert_eq!(cited.len(), expected);
        assert!(without.is_empty());
        // Every citation carries the title, so a reader can find the finding
        // a broken location belongs to.
        assert!(cited.iter().all(|one| !one.finding.is_empty()));
    }

    /// And the real document resolves against the code it was made from.
    #[test]
    fn a_real_document_resolves_against_its_own_target() {
        let directory = tempfile::tempdir().expect("a directory");
        let source = directory.path().join("src");
        std::fs::create_dir_all(&source).expect("creates");
        std::fs::write(
            source.join("server.js"),
            std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/link-service/src/server.js"),
            )
            .expect("the fixture"),
        )
        .expect("writes");

        let (cited, without) = cited_locations(&real_findings());
        let outcome = check(&cited, &without, directory.path());

        assert!(outcome.holds(), "{:?}", outcome.unanchored);
        assert_eq!(outcome.resolved, cited.len());
    }

    #[test]
    fn a_finding_citing_nowhere_is_listed_by_title() {
        let mut findings = real_findings();
        let title = findings.findings[0].title.clone();
        findings.findings[0].locations.clear();

        let (_, without) = cited_locations(&findings);

        assert_eq!(without, vec![title]);
    }
}
