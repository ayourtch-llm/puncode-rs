//! Behavior tests for knowledge-base preparation.
//!
//! Ported from `tests-ts/knowledge-base.test.ts`, including its hand-built PDF
//! and DOCX fixtures, so the extraction is checked against the same documents
//! the TypeScript implementation is.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use codex_security::api::ScanCancellation;
use codex_security::knowledge_base::{
    PreparedKnowledgeBase, prepare_knowledge_base, prepare_knowledge_base_in,
};
use tempfile::TempDir;

/// Prepares a knowledge base from paths that are already known good.
fn prepare(paths: &[&Path]) -> PreparedKnowledgeBase {
    let paths: Vec<String> = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    prepare_knowledge_base(&paths, &ScanCancellation::new()).expect("prepares a knowledge base")
}

/// The failure a knowledge base reports for `paths`.
fn refuse(paths: &[&Path]) -> String {
    let paths: Vec<String> = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    prepare_knowledge_base(&paths, &ScanCancellation::new())
        .expect_err("the knowledge base is refused")
        .to_string()
}

/// Every extracted document's text, sorted.
fn extracted(base: &PreparedKnowledgeBase) -> Vec<String> {
    let mut documents: Vec<String> = fs::read_dir(&base.path)
        .expect("read extracted documents")
        .map(|entry| fs::read_to_string(entry.expect("entry").path()).expect("read"))
        .collect();
    documents.sort();
    documents
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write");
}

/// The upstream DOCX fixture: a zip holding one WordprocessingML part.
fn docx(text: &str) -> Vec<u8> {
    let mut buffer = Vec::new();
    {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
        archive
            .start_file::<_, ()>(
                "word/document.xml",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("start part");
        let xml = format!(
            "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/\
             wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p>\
             </w:body></w:document>"
        );
        archive.write_all(xml.as_bytes()).expect("write part");
        archive.finish().expect("finish archive");
    }
    buffer
}

/// A zip that is not a DOCX at all.
fn zip_with(name: &str, contents: &str) -> Vec<u8> {
    let mut buffer = Vec::new();
    {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
        archive
            .start_file::<_, ()>(name, zip::write::SimpleFileOptions::default())
            .expect("start file");
        archive.write_all(contents.as_bytes()).expect("write");
        archive.finish().expect("finish archive");
    }
    buffer
}

/// The upstream PDF fixture: one uncompressed page showing `text`.
fn pdf(text: &str) -> Vec<u8> {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)");
    let stream = format!("BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R \
         >> >> /Contents 5 0 R >>"
            .to_owned(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
        format!(
            "<< /Length {} >>\nstream\n{stream}\nendstream",
            stream.len()
        ),
    ];

    let mut output = String::from("%PDF-1.4\n");
    let mut offsets = vec![0_usize];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(output.len());
        output.push_str(&format!("{} 0 obj\n{object}\nendobj\n", index + 1));
    }
    let xref = output.len();
    output.push_str(&format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len()));
    for offset in &offsets[1..] {
        output.push_str(&format!("{offset:010} 00000 n \n"));
    }
    output.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        offsets.len()
    ));
    output.into_bytes()
}

/// A temporary directory, canonicalized so paths compare equal to the resolved
/// sources a knowledge base reports.
fn temporary() -> (TempDir, PathBuf) {
    let directory = TempDir::new().expect("temporary directory");
    let path = fs::canonicalize(directory.path()).expect("canonicalize");
    (directory, path)
}

/// Removes an extracted knowledge base once a test is done with it.
struct Cleanup(PreparedKnowledgeBase);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.cleanup();
    }
}

#[test]
fn prepares_nested_documents_and_retains_the_requested_roots() {
    let (_directory, root) = temporary();
    let scope = root.join("scope.md");
    write(&scope, "Ignore local debug endpoints.");
    write(
        &root.join("architecture/threats/deployment.MARKDOWN"),
        "Public API gateway.",
    );
    write(
        &root.join("architecture/threats/notes.txt"),
        "Prioritize SSRF.",
    );
    write(&root.join("ignored.json"), "{}");

    let base = Cleanup(prepare(&[&root, &scope, &scope]));

    // The same root twice is one source, and one document.
    assert_eq!(base.0.sources, vec![root.clone(), scope.clone()]);
    assert_eq!(
        extracted(&base.0),
        [
            "Ignore local debug endpoints.",
            "Prioritize SSRF.",
            "Public API gateway.",
        ]
    );
    // The extracted text lives outside the material it came from.
    assert!(!base.0.path.starts_with(&root));
}

// The scan reads the extracted text; nobody else needs to.
#[test]
fn keeps_the_extracted_text_private() {
    let (_directory, root) = temporary();
    write(&root.join("scope.md"), "Ignore local debug endpoints.");

    let base = Cleanup(prepare(&[&root]));

    for entry in fs::read_dir(&base.0.path).expect("read") {
        let path = entry.expect("entry").path();
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{} is not private", path.display());
    }
}

#[test]
fn extracts_text_from_pdf_and_docx_documents() {
    let (_directory, root) = temporary();
    fs::write(
        root.join("architecture.pdf"),
        pdf("Payment service boundary"),
    )
    .expect("write pdf");
    fs::write(root.join("threat-model.docx"), docx("SSRF &amp; IDOR")).expect("write docx");

    let base = Cleanup(prepare(&[&root]));

    let documents = extracted(&base.0);
    assert!(
        documents
            .iter()
            .any(|text| text.contains("Payment service boundary")),
        "the PDF text is missing: {documents:?}"
    );
    // The paragraph ends a line, and the entity is resolved.
    assert!(
        documents.iter().any(|text| text == "SSRF & IDOR\n"),
        "the DOCX text is missing: {documents:?}"
    );
}

#[test]
fn cleans_up_without_touching_the_original_documents() {
    let (_directory, root) = temporary();
    let source = root.join("scope.md");
    write(&source, "Initial scope");
    let first = prepare(&[&root]);

    first.cleanup().expect("cleans up");

    assert!(!first.path.exists());
    assert_eq!(
        fs::read_to_string(&source).expect("the original survives"),
        "Initial scope"
    );
}

// The sources are the roots, not the documents, so a later run picks up
// whatever the directory holds by then.
#[test]
fn rediscovers_directory_contents_on_a_later_run() {
    let (_directory, root) = temporary();
    let source = root.join("scope.md");
    write(&source, "Initial scope");
    let first = prepare(&[&root]);
    first.cleanup().expect("cleans up");

    write(&source, "Updated scope");
    write(&root.join("priorities.txt"), "New attack priorities");
    let sources: Vec<&Path> = first.sources.iter().map(PathBuf::as_path).collect();
    let second = Cleanup(prepare(&sources));

    assert_eq!(
        extracted(&second.0),
        ["New attack priorities", "Updated scope"]
    );
}

#[test]
fn refuses_a_blank_path() {
    let error = prepare_knowledge_base(&[""], &ScanCancellation::new())
        .expect_err("a blank path is refused")
        .to_string();

    assert!(error.contains("cannot be empty"), "unexpected: {error}");
}

#[test]
fn refuses_a_missing_path() {
    let (_directory, root) = temporary();

    let error = refuse(&[&root.join("missing.md")]);

    assert!(
        error.contains("is not a file or directory"),
        "unexpected: {error}"
    );
}

// A file named directly must be one the scan can actually read.
#[test]
fn refuses_an_unsupported_document() {
    let (_directory, root) = temporary();
    let unsupported = root.join("scope.doc");
    write(&unsupported, "legacy document");

    let error = refuse(&[&unsupported]);

    assert!(
        error.contains("Unsupported knowledge base document"),
        "unexpected: {error}"
    );
}

// A directory that contributes nothing is a mistake worth reporting, not an
// empty knowledge base to scan with.
#[test]
fn refuses_a_directory_with_nothing_supported_in_it() {
    let (_directory, root) = temporary();
    write(&root.join("scope.doc"), "legacy document");

    let error = refuse(&[&root]);

    assert!(
        error.contains("contains no supported documents"),
        "unexpected: {error}"
    );
}

#[test]
fn refuses_text_that_is_not_valid_utf8() {
    let (_directory, root) = temporary();
    let invalid = root.join("invalid.md");
    fs::write(&invalid, [0xc3, 0x28]).expect("write");

    let error = refuse(&[&invalid]);

    assert!(error.contains("not valid UTF-8"), "unexpected: {error}");
}

#[test]
fn refuses_a_malformed_pdf() {
    let (_directory, root) = temporary();
    let invalid = root.join("invalid.pdf");
    write(&invalid, "not a PDF");

    let error = refuse(&[&invalid]);

    assert!(
        error.contains("Cannot extract text from knowledge base PDF"),
        "unexpected: {error}"
    );
}

// A zip with no WordprocessingML part is not a DOCX.
#[test]
fn refuses_an_archive_that_is_not_a_docx() {
    let (_directory, root) = temporary();
    let invalid = root.join("invalid.docx");
    fs::write(&invalid, zip_with("README.md", "not DOCX")).expect("write");

    let error = refuse(&[&invalid]);

    assert!(
        error.contains("Cannot extract text from knowledge base DOCX"),
        "unexpected: {error}"
    );
}

#[test]
fn refuses_a_docx_whose_document_part_is_malformed() {
    let (_directory, root) = temporary();
    let invalid = root.join("invalid-xml.docx");
    fs::write(&invalid, zip_with("word/document.xml", "not XML")).expect("write");

    let error = refuse(&[&invalid]);

    assert!(
        error.contains("Cannot extract text from knowledge base DOCX"),
        "unexpected: {error}"
    );
}

// A link inside an offered directory is skipped, so the document it points at
// is not extracted twice.
#[test]
fn skips_symbolic_links_found_inside_a_directory() {
    let (_directory, root) = temporary();
    let source = root.join("scope.md");
    write(&source, "External APIs");
    std::os::unix::fs::symlink(&source, root.join("linked.md")).expect("symlink");

    let base = Cleanup(prepare(&[&root]));

    assert_eq!(extracted(&base.0), ["External APIs"]);
}

// A link named directly is how a supplied path reaches a file the caller did
// not mean to share, so it is refused rather than followed.
#[test]
fn refuses_a_symbolic_link_named_directly() {
    let (_directory, root) = temporary();
    let source = root.join("scope.md");
    write(&source, "External APIs");
    let linked = root.join("linked.md");
    std::os::unix::fs::symlink(&source, &linked).expect("symlink");

    let error = refuse(&[&linked]);

    assert!(
        error.contains("cannot be symbolic links"),
        "unexpected: {error}"
    );
}

#[test]
fn refuses_an_unreadable_document() {
    let (_directory, root) = temporary();
    let source = root.join("scope.md");
    write(&source, "External APIs");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o000)).expect("chmod");

    let error = refuse(&[&source]);
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("restore");

    assert!(error.contains("not readable"), "unexpected: {error}");
}

// Nothing is left behind when one document in a set fails: a half-extracted
// knowledge base would give the scan less than the caller asked for.
#[test]
fn leaves_nothing_behind_when_extraction_fails() {
    let (_directory, root) = temporary();
    let (_bases, base_root) = temporary();
    write(&root.join("good.md"), "Fine");
    fs::write(root.join("bad.md"), [0xc3, 0x28]).expect("write");

    prepare_knowledge_base_in(
        &base_root,
        &[root.display().to_string()],
        &ScanCancellation::new(),
    )
    .expect_err("the invalid document is refused");

    let leftovers: Vec<_> = fs::read_dir(&base_root)
        .expect("read")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed preparation left its directory behind: {leftovers:?}"
    );
}

#[test]
fn stops_when_the_scan_is_cancelled() {
    let (_directory, root) = temporary();
    write(&root.join("scope.md"), "External APIs");
    let cancellation = ScanCancellation::new();
    cancellation.cancel();

    let error = prepare_knowledge_base(&[root.display().to_string()], &cancellation)
        .expect_err("cancelled")
        .to_string();

    assert!(error.contains("interrupted"), "unexpected: {error}");
}

/// Extracts one DOCX whose `word/document.xml` is exactly `xml`.
///
/// The expectations below were taken from the TypeScript implementation, which
/// builds this text with two regular expressions and `String.fromCodePoint`;
/// this port walks the markup by hand, so every case is pinned.
fn docx_body(xml: &str) -> std::result::Result<String, String> {
    let (_directory, root) = temporary();
    let path = root.join("body.docx");
    fs::write(&path, zip_with("word/document.xml", xml)).expect("write");
    let paths = [path.display().to_string()];
    match prepare_knowledge_base_in(&root, &paths, &ScanCancellation::new()) {
        Ok(base) => {
            let text = extracted(&base).first().cloned().unwrap_or_default();
            base.cleanup().expect("cleans up");
            Ok(text)
        }
        Err(error) => Err(error.to_string()),
    }
}

const NAMESPACED: &str = r#"<w:document xmlns:w="x">"#;

#[test]
fn extracts_docx_bodies_the_way_the_typescript_does() {
    let cases: [(&str, &str); 13] = [
        // A paragraph ends a line.
        (
            &format!(
                "{NAMESPACED}<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>"
            ),
            "Hello\n",
        ),
        (
            &format!("{NAMESPACED}<w:p><w:t>One</w:t></w:p><w:p><w:t>Two</w:t></w:p></w:document>"),
            "One\nTwo\n",
        ),
        // A tab is a tab, with or without attributes.
        (
            &format!("{NAMESPACED}<w:p><w:t>A</w:t><w:tab/><w:t>B</w:t></w:p></w:document>"),
            "A\tB\n",
        ),
        (
            &format!(
                "{NAMESPACED}<w:p><w:t>A</w:t><w:tab val=\"x\"/><w:t>B</w:t></w:p></w:document>"
            ),
            "A\tB\n",
        ),
        (
            &format!("{NAMESPACED}<w:p><w:t>&amp;&lt;&gt;&quot;&apos;</w:t></w:p></w:document>"),
            "&<>\"'\n",
        ),
        // Decimal, lowercase and uppercase hexadecimal.
        (
            &format!("{NAMESPACED}<w:p><w:t>&#65;&#x42;&#X43;</w:t></w:p></w:document>"),
            "ABC\n",
        ),
        // Entity names are matched without regard to case.
        (
            &format!("{NAMESPACED}<w:p><w:t>&AMP;&Lt;</w:t></w:p></w:document>"),
            "&<\n",
        ),
        // Anything else stays exactly as written.
        (
            &format!("{NAMESPACED}<w:p><w:t>a&nbsp;b&foo;</w:t></w:p></w:document>"),
            "a&nbsp;b&foo;\n",
        ),
        (
            &format!("{NAMESPACED}<w:p><w:t>a & b</w:t></w:p></w:document>"),
            "a & b\n",
        ),
        // The namespace prefix is optional, and the closing tag may be spaced.
        ("<document><p><t>Bare</t></p></document>", "Bare\n"),
        (
            &format!("{NAMESPACED}<w:p><w:t>Spaced</w:t></w:p></w:document >"),
            "Spaced\n",
        ),
        // A word starting with "document" is text, not the document element.
        (
            &format!("{NAMESPACED}<w:p><w:t>documentation</w:t></w:p></w:document>"),
            "documentation\n",
        ),
        // Beyond the basic plane, and a code point of zero.
        (
            &format!("{NAMESPACED}<w:p><w:t>&#x1F600;</w:t></w:p></w:document>"),
            "\u{1f600}\n",
        ),
    ];

    for (xml, expected) in cases {
        assert_eq!(docx_body(xml).as_deref(), Ok(expected), "extracting {xml}");
    }
}

// A code point of zero is kept, matching String.fromCodePoint(0).
#[test]
fn keeps_a_zero_code_point() {
    let xml = format!("{NAMESPACED}<w:p><w:t>&#0;x</w:t></w:p></w:document>");

    assert_eq!(docx_body(&xml).as_deref(), Ok("\u{0}x\n"));
}

// A lone surrogate is not a character; upstream stores what encoding one as
// UTF-8 produces, which is the replacement character.
#[test]
fn replaces_a_lone_surrogate() {
    let xml = format!("{NAMESPACED}<w:p><w:t>&#xD83D;</w:t></w:p></w:document>");

    assert_eq!(docx_body(&xml).as_deref(), Ok("\u{fffd}\n"));
}

// Upstream's String.fromCodePoint throws on this, failing the whole document.
#[test]
fn refuses_a_code_point_beyond_unicode() {
    let xml = format!("{NAMESPACED}<w:p><w:t>&#x110000;</w:t></w:p></w:document>");

    let error = docx_body(&xml).expect_err("out of range");

    assert!(
        error.contains("Cannot extract text from knowledge base DOCX"),
        "unexpected: {error}"
    );
}

#[test]
fn refuses_a_body_with_no_document_element() {
    let error = docx_body("<w:body><w:p><w:t>Nope</w:t></w:p></w:body>").expect_err("malformed");

    assert!(
        error.contains("Cannot extract text from knowledge base DOCX"),
        "unexpected: {error}"
    );
}

// An element merely starting with "document" is not the document element.
#[test]
fn refuses_a_differently_named_root_element() {
    let error =
        docx_body("<w:documentx><w:p><w:t>X</w:t></w:p></w:documentx>").expect_err("malformed");

    assert!(
        error.contains("Cannot extract text from knowledge base DOCX"),
        "unexpected: {error}"
    );
}

#[test]
fn refuses_a_docx_with_no_text_in_it() {
    let xml = format!("{NAMESPACED}<w:body></w:body></w:document>");

    let error = docx_body(&xml).expect_err("no text");

    assert!(
        error.contains("contains no extractable text"),
        "unexpected: {error}"
    );
}
