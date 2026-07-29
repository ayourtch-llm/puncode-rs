//! Whether a scan's documents were written by the plugin's own writer.
//!
//! Not a port: upstream checks the seal, and the seal cannot check itself.
//!
//! The manifest records a digest for every artifact a scan produced, and
//! `contract::seal` verifies each of them against what is on disk. That makes
//! the findings and the coverage document tamper-evident. It leaves one thing
//! unchecked, and it is the one everything else hangs from: **the manifest is
//! not an artifact of itself**, so nothing in the contract says the manifest is
//! the file that was sealed. A scan whose manifest had been replaced verified
//! as fully consistent, because replacing it leaves every artifact digest it
//! records untouched.
//!
//! What this checks is narrow and provable. The plugin writes every contract
//! document through one function, and that function is specific in two
//! unrelated ways:
//!
//! - `json.dumps(payload, indent=2, sort_keys=True) + "\n"` — sorted keys
//!   throughout, and a trailing newline.
//! - `os.open(..., O_CREAT | O_EXCL, 0o600)` — mode 600, never the umask.
//!
//! A document missing either was written by something else. Across 25 real scan
//! manifests on the machine this was developed on, the two signals agreed on
//! every single one, which is what a genuine common cause looks like: they have
//! no implementation in common.
//!
//! **What it does not say.** The first version of this claimed a document in
//! this state meant the workbench had refused to publish the scan. That was
//! wrong, and checking it against real runs is what showed it: of eleven scans
//! flagged, three had published perfectly well. So this reports the fact and
//! not a verdict, and deliberately does not fail verification. Someone reading
//! a scan directory should know its documents were not produced by the tool's
//! own writer — with the sandbox off the agent can write them itself — and then
//! decide what that is worth.
//!
//! Reconstructing the canonical bytes and comparing was the obvious approach
//! and is the wrong one: Python escapes non-ASCII by default and Rust does not,
//! so a manifest naming a path with an accent in it would be called a forgery.
//! The checks here read structure, and cannot be fooled by encoding.

use std::path::Path;

use serde_json::Value;

/// The mode the plugin's writer creates contract documents with.
const WRITER_MODE: u32 = 0o600;

/// What reading a contract document said about who wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestForm {
    /// Consistent with the plugin's writer having produced it.
    ///
    /// Not a guarantee of authenticity: someone reproducing the writer's output
    /// exactly would land here. It says nothing was found that a different
    /// writer would have left behind.
    FromTheWriter,
    /// Written by something other than the plugin's writer.
    NotFromTheWriter {
        /// What gave it away, in the order found.
        how: Vec<String>,
        /// Whether the content itself still parses as JSON.
        ///
        /// Almost always true, and worth saying: it means only the file's form
        /// is unusual and the findings are readable. It is also the reason not
        /// to "fix" it — see [`ManifestForm::advice`].
        content_parses: bool,
    },
    /// Not JSON at all.
    Unreadable { why: String },
}

impl ManifestForm {
    /// Whether this document looks like the writer's own output.
    #[must_use]
    pub fn from_the_writer(&self) -> bool {
        matches!(self, Self::FromTheWriter)
    }

    /// What someone holding this directory should do about it.
    #[must_use]
    pub fn advice(&self) -> Option<&'static str> {
        match self {
            Self::FromTheWriter => None,
            // Deliberately not offering to rewrite it into canonical form.
            // That is resealing a document somebody else changed, which is
            // precisely what a seal exists to prevent, and nothing here can
            // tell an accident from an edit.
            Self::NotFromTheWriter { .. } => Some(
                "This is a reason to read the documents, not a verdict on them. Do not rewrite \
                 one into canonical form to make this go away: resealing by hand is the one thing \
                 a seal exists to prevent.",
            ),
            Self::Unreadable { .. } => {
                Some("Nothing can be concluded from this directory. Rerun the scan.")
            }
        }
    }
}

/// Reads a contract document from disk and says whether the writer produced it.
///
/// Prefer this to [`inspect_manifest`]: the permission check is an entirely
/// independent signal, and two signals that share no implementation are much
/// harder to trip by accident than either alone.
#[must_use]
pub fn inspect_manifest_file(path: &Path) -> ManifestForm {
    let Ok(text) = std::fs::read_to_string(path) else {
        return ManifestForm::Unreadable {
            why: "the file could not be read".to_owned(),
        };
    };

    let mut form = inspect_manifest(&text);
    let Some(mode) = file_mode(path) else {
        return form;
    };
    if mode == WRITER_MODE {
        return form;
    }
    let note = format!("the file is mode {mode:o}, and the writer creates {WRITER_MODE:o}");
    match &mut form {
        ManifestForm::NotFromTheWriter { how, .. } => how.push(note),
        ManifestForm::FromTheWriter => {
            form = ManifestForm::NotFromTheWriter {
                how: vec![note],
                content_parses: true,
            };
        }
        ManifestForm::Unreadable { .. } => {}
    }
    form
}

/// The permission bits of a file, where the platform has them.
#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    Some(std::fs::metadata(path).ok()?.permissions().mode() & 0o777)
}

/// Nothing to compare against where permissions do not work this way.
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// The same, from the text alone.
///
/// Structure only. Use [`inspect_manifest_file`] when there is a file to stat.
#[must_use]
pub fn inspect_manifest(text: &str) -> ManifestForm {
    let document: Value = match serde_json::from_str(text) {
        Ok(document) => document,
        Err(error) => {
            return ManifestForm::Unreadable {
                why: format!("not JSON: {error}"),
            };
        }
    };

    let mut how = Vec::new();

    // The writer serialises with sort_keys=True. Insertion order surviving
    // anywhere means something else produced this file. Checked against the
    // parsed structure rather than the bytes, so nothing about indentation,
    // spacing or escaping can produce a false accusation.
    if let Some(path) = first_unsorted_object(&document, "") {
        how.push(format!("keys are not in sorted order at {path}"));
    }

    // And appends a newline, which json.dumps does not add on its own.
    if !text.ends_with('\n') {
        how.push("the file does not end with a newline".to_owned());
    }

    if how.is_empty() {
        ManifestForm::FromTheWriter
    } else {
        ManifestForm::NotFromTheWriter {
            how,
            content_parses: true,
        }
    }
}

/// The path to the first object whose keys are out of order, if any.
///
/// Returns a location rather than a yes or no, because whoever reads this will
/// want to look at the file themselves.
fn first_unsorted_object(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            if keys.windows(2).any(|pair| pair[0] > pair[1]) {
                return Some(if path.is_empty() {
                    "the top level".to_owned()
                } else {
                    path.to_owned()
                });
            }
            map.iter().find_map(|(key, child)| {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                first_unsorted_object(child, &child_path)
            })
        }
        Value::Array(items) => items.iter().enumerate().find_map(|(index, child)| {
            let child_path = if path.is_empty() {
                format!("[{index}]")
            } else {
                format!("{path}[{index}]")
            };
            first_unsorted_object(child, &child_path)
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name)
    }

    fn read(name: &str) -> String {
        std::fs::read_to_string(data(name)).expect("the captured document")
    }

    /// The document that started this: the real manifest from the run that
    /// found every flaw in `c-memory` and was then refused by the workbench.
    #[test]
    fn recognises_a_manifest_the_writer_did_not_produce() {
        let form = inspect_manifest(&read("manifest-rewritten.json"));

        let ManifestForm::NotFromTheWriter {
            how,
            content_parses,
        } = &form
        else {
            panic!("expected a foreign writer, got {form:?}");
        };
        assert!(content_parses);
        assert!(
            how.iter().any(|reason| reason.contains("sorted order")),
            "{how:?}"
        );
        assert!(!form.from_the_writer());
    }

    /// And a real one from the same run must not be accused.
    #[test]
    fn accepts_a_manifest_the_writer_produced() {
        assert_eq!(
            inspect_manifest(&read("manifest-sealed.json")),
            ManifestForm::FromTheWriter
        );
    }

    /// The claim this deliberately stops short of making. Three scans with a
    /// document in this state published perfectly well, so nothing here may
    /// read as a verdict on the results.
    #[test]
    fn does_not_claim_the_scan_was_refused() {
        let form = inspect_manifest(&read("manifest-rewritten.json"));

        let advice = form.advice().expect("advice");
        assert!(advice.contains("not a verdict"), "{advice}");
        assert!(advice.contains("Do not rewrite"), "{advice}");
    }

    #[test]
    fn names_where_the_order_broke() {
        let ManifestForm::NotFromTheWriter { how, .. } =
            inspect_manifest("{\n  \"a\": { \"z\": 1, \"b\": 2 }\n}\n")
        else {
            panic!("expected a foreign writer");
        };

        assert!(how[0].contains("at a"), "{how:?}");
    }

    #[test]
    fn finds_disorder_inside_an_array() {
        let ManifestForm::NotFromTheWriter { how, .. } =
            inspect_manifest("{\n  \"a\": [ { \"z\": 1, \"b\": 2 } ]\n}\n")
        else {
            panic!("expected a foreign writer");
        };

        assert!(how[0].contains("a[0]"), "{how:?}");
    }

    #[test]
    fn a_missing_trailing_newline_is_noticed() {
        let ManifestForm::NotFromTheWriter { how, .. } = inspect_manifest("{\n  \"a\": 1\n}")
        else {
            panic!("expected a foreign writer");
        };

        assert_eq!(how, vec!["the file does not end with a newline".to_owned()]);
    }

    /// Non-ASCII text is the reason this compares structure and not bytes.
    /// Python would have written `\\u00e9` where Rust writes the character, and
    /// a byte comparison would call an honest manifest a forgery.
    #[test]
    fn does_not_accuse_a_manifest_carrying_non_ascii_text() {
        for body in [
            "{\n  \"path\": \"src/caf\\u00e9.py\"\n}\n",
            "{\n  \"path\": \"src/café.py\"\n}\n",
        ] {
            assert_eq!(
                inspect_manifest(body),
                ManifestForm::FromTheWriter,
                "{body}"
            );
        }
    }

    /// Nor one carrying numbers the two languages render differently.
    #[test]
    fn does_not_accuse_a_manifest_carrying_awkward_numbers() {
        for body in [
            "{\n  \"a\": 1e30\n}\n",
            "{\n  \"a\": 1.0\n}\n",
            "{\n  \"a\": -0.0\n}\n",
        ] {
            assert_eq!(
                inspect_manifest(body),
                ManifestForm::FromTheWriter,
                "{body}"
            );
        }
    }

    /// Indentation is not checked, on purpose: it is weaker evidence than key
    /// order and this would rather miss a foreign writer than accuse an honest
    /// file.
    #[test]
    fn does_not_accuse_a_manifest_over_whitespace_alone() {
        assert_eq!(
            inspect_manifest("{\"a\":1,\"b\":2}\n"),
            ManifestForm::FromTheWriter
        );
    }

    #[test]
    fn an_empty_object_is_in_order() {
        assert_eq!(inspect_manifest("{}\n"), ManifestForm::FromTheWriter);
    }

    #[test]
    fn something_that_is_not_json_is_reported_as_unreadable() {
        let form = inspect_manifest("not json");

        assert!(matches!(form, ManifestForm::Unreadable { .. }), "{form:?}");
        assert!(!form.from_the_writer());
        assert!(form.advice().expect("advice").contains("Rerun"));
    }
}

#[cfg(all(test, unix))]
mod file_tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn written(body: &str, mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("scan-manifest.json");
        std::fs::write(&path, body).expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        (directory, path)
    }

    /// The second signal, and the one that makes the first believable: it
    /// shares no implementation with key ordering, so the two agreeing is
    /// evidence and not a coincidence.
    #[test]
    fn a_document_the_writer_did_not_create_has_the_wrong_mode() {
        let (_directory, path) = written("{\n  \"a\": 1\n}\n", 0o664);

        let form = inspect_manifest_file(&path);

        let ManifestForm::NotFromTheWriter { how, .. } = &form else {
            panic!("expected a foreign writer, got {form:?}");
        };
        assert_eq!(how, &["the file is mode 664, and the writer creates 600"]);
    }

    #[test]
    fn a_document_with_the_writers_mode_and_form_is_accepted() {
        let (_directory, path) = written("{\n  \"a\": 1\n}\n", 0o600);

        assert_eq!(inspect_manifest_file(&path), ManifestForm::FromTheWriter);
    }

    /// Both signals are reported when both fire, because a reader deciding how
    /// much to believe this wants to know it is not resting on one check.
    #[test]
    fn both_signals_are_reported_together() {
        let (_directory, path) = written("{\n  \"z\": 1,\n  \"a\": 2\n}", 0o644);

        let ManifestForm::NotFromTheWriter { how, .. } = inspect_manifest_file(&path) else {
            panic!("expected a foreign writer");
        };

        assert_eq!(how.len(), 3, "{how:?}");
        assert!(
            how.iter().any(|reason| reason.contains("sorted")),
            "{how:?}"
        );
        assert!(
            how.iter().any(|reason| reason.contains("newline")),
            "{how:?}"
        );
        assert!(
            how.iter().any(|reason| reason.contains("mode 644")),
            "{how:?}"
        );
    }

    #[test]
    fn a_file_that_is_not_there_is_unreadable() {
        let form = inspect_manifest_file(std::path::Path::new("/does/not/exist"));

        assert!(matches!(form, ManifestForm::Unreadable { .. }), "{form:?}");
    }
}
