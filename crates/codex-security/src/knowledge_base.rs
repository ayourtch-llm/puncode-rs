//! Turning caller-supplied documents into plain text a scan can read.
//!
//! Ported from `src/knowledge-base.ts`.
//!
//! Every document is converted to UTF-8 text in a private temporary directory,
//! and only that directory is exposed to the scan. The originals are never
//! handed over: the agent reads text, not PDFs, so a malformed or hostile
//! document cannot reach it.
//!
//! Selection is deliberately strict. Symbolic links are refused rather than
//! followed, since a link is how a caller-supplied path reaches a file the
//! caller did not mean to share, and unreadable or unsupported files are an
//! error rather than a silent skip — a knowledge base missing the one document
//! that mattered would quietly weaken the scan.
//!
//! Upstream throws plain `Error`s here rather than its own class hierarchy;
//! this port raises the base [`Error::codex_security`] for all of them.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::api::ScanCancellation;
use crate::contract::files::open_no_follow;
use crate::error::{Error, Result};
use crate::targets::lexical_absolute;

/// The document kinds a knowledge base accepts.
const SUPPORTED_EXTENSIONS: [&str; 5] = ["md", "markdown", "txt", "pdf", "docx"];

/// The largest `word/document.xml` a DOCX may expand to.
const MAX_DOCX_TEXT_BYTES: u64 = 25 * 1024 * 1024;

/// Extracted knowledge-base text, and where it came from.
#[derive(Debug, Clone)]
pub struct PreparedKnowledgeBase {
    /// The private directory holding the extracted text.
    pub path: PathBuf,
    /// The requested roots, resolved — recorded on the scan recipe.
    pub sources: Vec<PathBuf>,
}

impl PreparedKnowledgeBase {
    /// Removes the extracted text.
    ///
    /// The documents exist only for the duration of one scan, so leaving them
    /// behind would leave the caller's material in a temporary directory.
    pub fn cleanup(&self) -> Result<()> {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::codex_security(format!(
                "Unable to remove the knowledge base at {}",
                self.path.display()
            ))
            .with_source(error)),
        }
    }
}

/// Extracts every requested document into one private directory.
///
/// The directory is created under the system temporary directory, as upstream
/// does; [`prepare_knowledge_base_in`] puts it somewhere specific instead.
pub fn prepare_knowledge_base(
    paths: &[impl AsRef<str>],
    cancellation: &ScanCancellation,
) -> Result<PreparedKnowledgeBase> {
    prepare_knowledge_base_in(&std::env::temp_dir(), paths, cancellation)
}

/// Extracts every requested document into a private directory under `root`.
pub fn prepare_knowledge_base_in(
    root: &Path,
    paths: &[impl AsRef<str>],
    cancellation: &ScanCancellation,
) -> Result<PreparedKnowledgeBase> {
    let (sources, documents) = select(paths, cancellation)?;

    let directory = tempfile::Builder::new()
        .prefix("codex-security-knowledge-")
        .tempdir_in(root)
        .map_err(|error| {
            Error::codex_security(format!(
                "Unable to create a knowledge base directory under {}",
                root.display()
            ))
            .with_source(error)
        })?
        .keep();

    // Anything that fails leaves nothing behind: a half-extracted knowledge
    // base would silently give the scan less than the caller asked for.
    match extract_all(&documents, &directory, cancellation) {
        Ok(()) => Ok(PreparedKnowledgeBase {
            path: directory,
            sources,
        }),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&directory);
            Err(error)
        }
    }
}

/// Resolves the requested paths into the roots and the documents beneath them.
fn select(
    paths: &[impl AsRef<str>],
    cancellation: &ScanCancellation,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut sources: Vec<PathBuf> = Vec::new();
    let mut documents: Vec<PathBuf> = Vec::new();

    for requested in paths {
        stop_if_cancelled(cancellation)?;
        let requested = requested.as_ref();
        if requested.trim().is_empty() {
            return Err(Error::codex_security(
                "Knowledge base paths cannot be empty.",
            ));
        }
        let path = lexical_absolute(Path::new(requested));
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            Error::codex_security(format!(
                "Knowledge base path is not a file or directory: {}",
                path.display()
            ))
            .with_source(error)
        })?;
        // A link is how a supplied path reaches a file the caller did not mean
        // to share, so it is refused rather than followed.
        if metadata.is_symlink() {
            return Err(Error::codex_security(format!(
                "Knowledge base paths cannot be symbolic links: {}",
                path.display()
            )));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(Error::codex_security(format!(
                "Knowledge base path is not a file or directory: {}",
                path.display()
            )));
        }

        let source = std::fs::canonicalize(&path).map_err(|error| {
            Error::codex_security(format!(
                "Knowledge base path is not a file or directory: {}",
                path.display()
            ))
            .with_source(error)
        })?;
        let selected = if metadata.is_dir() {
            discover(&source)?
        } else {
            vec![source.clone()]
        };
        if selected.is_empty() {
            return Err(Error::codex_security(format!(
                "Knowledge base directory contains no supported documents: {}",
                path.display()
            )));
        }
        for document in selected {
            // A directory walk has already filtered by extension; this catches
            // a file named directly.
            if !is_supported(&document) {
                return Err(Error::codex_security(format!(
                    "Unsupported knowledge base document: {}",
                    document.display()
                )));
            }
            if !documents.contains(&document) {
                documents.push(document);
            }
        }
        if !sources.contains(&source) {
            sources.push(source);
        }
    }

    Ok((sources, documents))
}

/// Extracts each document into `directory` as numbered plain text.
fn extract_all(
    documents: &[PathBuf],
    directory: &Path,
    cancellation: &ScanCancellation,
) -> Result<()> {
    for (index, document) in documents.iter().enumerate() {
        stop_if_cancelled(cancellation)?;
        let text = extract(document)?;
        let name = format!(
            "{index}-{}.txt",
            document.file_name().unwrap_or_default().to_string_lossy()
        );
        write_private(&directory.join(name), &text)?;
    }
    Ok(())
}

/// Reads one document and returns its text.
fn extract(document: &Path) -> Result<String> {
    require_readable(document)?;
    let bytes = read_no_follow(document)?;
    let extension = extension_of(document);
    let text = match extension.as_str() {
        "pdf" => extract_pdf(document, &bytes)?,
        "docx" => extract_docx(document, &bytes)?,
        _ => decode_text(document, &bytes)?,
    };
    // A PDF or DOCX that yields nothing is a document the scan cannot use, and
    // silently contributing an empty file would hide that.
    if matches!(extension.as_str(), "pdf" | "docx") && text.trim().is_empty() {
        return Err(Error::codex_security(format!(
            "Knowledge base document contains no extractable text: {}",
            document.display()
        )));
    }
    Ok(text)
}

/// Refuses a document with no read permission bits at all.
fn require_readable(document: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(document).map_err(|error| {
            Error::codex_security(format!(
                "Knowledge base document is not readable: {}",
                document.display()
            ))
            .with_source(error)
        })?;
        if metadata.mode() & 0o444 == 0 {
            return Err(Error::codex_security(format!(
                "Knowledge base document is not readable: {}",
                document.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = document;
    Ok(())
}

/// Reads a document without following a link that appeared since selection.
fn read_no_follow(document: &Path) -> Result<Vec<u8>> {
    let mut file = open_no_follow(document).map_err(|error| {
        Error::codex_security(format!(
            "Unable to read knowledge base document: {}",
            document.display()
        ))
        .with_source(error)
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        Error::codex_security(format!(
            "Unable to read knowledge base document: {}",
            document.display()
        ))
        .with_source(error)
    })?;
    Ok(bytes)
}

/// Writes extracted text readable only by its owner.
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        Error::codex_security(format!(
            "Unable to write knowledge base text to {}",
            path.display()
        ))
        .with_source(error)
    })?;
    file.write_all(text.as_bytes()).map_err(|error| {
        Error::codex_security(format!(
            "Unable to write knowledge base text to {}",
            path.display()
        ))
        .with_source(error)
    })
}

/// Every supported document beneath `directory`, recursively.
///
/// Symbolic links are skipped rather than refused: a link inside a directory
/// the caller offered wholesale is far more likely to be incidental than
/// deliberate, and refusing would make an ordinary directory unusable.
fn discover(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut documents = Vec::new();
    // Sorted so the extracted files are numbered the same way on every
    // platform; readdir order is not guaranteed.
    let mut entries: BTreeSet<PathBuf> = BTreeSet::new();
    let listing = std::fs::read_dir(directory).map_err(|error| {
        Error::codex_security(format!(
            "Unable to read knowledge base directory: {}",
            directory.display()
        ))
        .with_source(error)
    })?;
    for entry in listing {
        let entry = entry.map_err(|error| {
            Error::codex_security(format!(
                "Unable to read knowledge base directory: {}",
                directory.display()
            ))
            .with_source(error)
        })?;
        entries.insert(entry.path());
    }

    for path in entries {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            documents.extend(discover(&path)?);
        } else if metadata.is_file() && is_supported(&path) {
            documents.push(path);
        }
    }
    Ok(documents)
}

/// A path's extension, lowercased, without the dot.
fn extension_of(path: &Path) -> String {
    path.extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase()
}

fn is_supported(path: &Path) -> bool {
    SUPPORTED_EXTENSIONS.contains(&extension_of(path).as_str())
}

/// Decodes bytes as strict UTF-8.
fn decode_text(path: &Path, bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|error| {
        Error::codex_security(format!(
            "Knowledge base document is not valid UTF-8: {}",
            path.display()
        ))
        .with_source(error)
    })
}

/// Extracts a PDF's text.
///
/// The extractor panics on some malformed input rather than returning an error,
/// so a panic is caught and reported as an unreadable document: a hostile PDF
/// in a knowledge base must fail the scan, not abort the process.
fn extract_pdf(path: &Path, bytes: &[u8]) -> Result<String> {
    let extracted = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes));
    match extracted {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(error)) => Err(Error::codex_security(format!(
            "Cannot extract text from knowledge base PDF: {}",
            path.display()
        ))
        .with_source(error)),
        Err(_) => Err(Error::codex_security(format!(
            "Cannot extract text from knowledge base PDF: {}",
            path.display()
        ))),
    }
}

/// Extracts a DOCX's text from its main document part.
fn extract_docx(path: &Path, bytes: &[u8]) -> Result<String> {
    docx_text(bytes).map_err(|detail| {
        Error::codex_security(format!(
            "Cannot extract text from knowledge base DOCX: {}: {detail}",
            path.display()
        ))
    })
}

/// The DOCX body text, or why it could not be read.
fn docx_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|error| format!("unreadable archive: {error}"))?;
    let mut part = archive
        .by_name("word/document.xml")
        .map_err(|_| "Missing word/document.xml.".to_owned())?;
    // Checked before reading: the declared size is what a zip bomb inflates.
    if part.size() > MAX_DOCX_TEXT_BYTES {
        return Err("DOCX document text exceeds 25 MB.".to_owned());
    }
    let mut xml = String::new();
    part.read_to_string(&mut xml)
        .map_err(|_| "word/document.xml is not valid UTF-8.".to_owned())?;

    if !is_word_document(&xml) {
        return Err("Malformed word/document.xml.".to_owned());
    }
    decode_xml(&strip_markup(&xml))
}

/// Whether the XML really is a WordprocessingML document.
///
/// Written by hand rather than as one expression: matching an opening and a
/// closing `document` tag needs a scan, and the `[\s\S]*` an equivalent regular
/// expression would use backtracks badly on a large body.
fn is_word_document(xml: &str) -> bool {
    let Some(open) = find_tag(xml, "document", false) else {
        return false;
    };
    find_tag(&xml[open..], "document", true).is_some()
}

/// The byte just past a `<name ...>` or `</name >` tag, allowing a namespace.
fn find_tag(xml: &str, name: &str, closing: bool) -> Option<usize> {
    let mut rest = xml;
    let mut base = 0;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let after = if closing {
            match after.strip_prefix('/') {
                Some(after) => after,
                None => {
                    base += start + 1;
                    rest = &rest[start + 1..];
                    continue;
                }
            }
        } else if after.starts_with('/') {
            base += start + 1;
            rest = &rest[start + 1..];
            continue;
        } else {
            after
        };
        // An optional `w:`-style namespace prefix.
        let local = match after.split_once(':') {
            Some((prefix, local)) if is_name_chars(prefix) => local,
            _ => after,
        };
        if let Some(tail) = local.strip_prefix(name) {
            let boundary = tail.chars().next();
            let ends_element = if closing {
                matches!(boundary, Some(character) if character.is_whitespace() || character == '>')
            } else {
                matches!(boundary, Some(character) if !is_name_char(character))
            };
            if ends_element && let Some(end) = tail.find('>') {
                return Some(base + start + 1 + (after.len() - local.len()) + name.len() + end + 1);
            }
        }
        base += start + 1;
        rest = &rest[start + 1..];
    }
    None
}

fn is_name_chars(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_name_char)
}

fn is_name_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || character == '-' || character == '.'
}

/// Replaces paragraph and tab markup with their text, then drops every tag.
fn strip_markup(xml: &str) -> String {
    let mut text = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        text.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('>') else {
            // An unterminated tag ends the document; there is no text after it.
            return text;
        };
        let tag = &rest[start + 1..start + end];
        text.push_str(replacement_for(tag));
        rest = &rest[start + end + 1..];
    }
    text.push_str(rest);
    text
}

/// What a tag contributes to the text, if anything.
fn replacement_for(tag: &str) -> &'static str {
    let name = tag.trim();
    let (name, closing) = match name.strip_prefix('/') {
        Some(name) => (name, true),
        None => (name, false),
    };
    let local = match name.split_once(':') {
        Some((prefix, local)) if is_name_chars(prefix) => local,
        _ => name,
    };
    let local = local
        .split(|character: char| character.is_whitespace() || character == '/')
        .next()
        .unwrap_or_default();
    match (local, closing) {
        // A paragraph ends a line, and a tab is a tab.
        ("p", true) => "\n",
        ("tab", false) => "\t",
        _ => "",
    }
}

/// Resolves the XML entities WordprocessingML uses.
fn decode_xml(value: &str) -> std::result::Result<String, String> {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        decoded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let resolved = match after.find(';') {
            Some(end) => resolve_entity(&after[..end])?.map(|resolved| (resolved, end)),
            None => None,
        };
        match resolved {
            Some((resolved, end)) => {
                decoded.push_str(&resolved);
                rest = &after[end + 1..];
            }
            // Not an entity this document uses; the ampersand stands alone.
            None => {
                decoded.push('&');
                rest = after;
            }
        }
    }
    decoded.push_str(rest);
    Ok(decoded)
}

/// The character an unpaired surrogate becomes once encoded as UTF-8.
const REPLACEMENT: char = '\u{fffd}';

/// The text an entity body stands for.
///
/// `Ok(None)` means the text was not an entity at all and stays as written.
/// An out-of-range code point is an error, because upstream's
/// `String.fromCodePoint` throws on one and fails the whole document.
fn resolve_entity(entity: &str) -> std::result::Result<Option<String>, String> {
    if let Some(number) = entity.strip_prefix('#') {
        let (digits, radix) = match number.strip_prefix(['x', 'X']) {
            Some(hexadecimal) => (hexadecimal, 16),
            None => (number, 10),
        };
        if digits.is_empty() || !digits.chars().all(|digit| digit.is_digit(radix)) {
            return Ok(None);
        }
        let code = u32::from_str_radix(digits, radix)
            .map_err(|_| format!("Code point out of range: {entity}."))?;
        if code > 0x0010_ffff {
            return Err(format!("Code point out of range: {entity}."));
        }
        // A lone surrogate is not a character; writing one as UTF-8 yields the
        // replacement character, which is what upstream ends up storing.
        return Ok(Some(String::from(
            char::from_u32(code).unwrap_or(REPLACEMENT),
        )));
    }
    let named = match entity.to_lowercase().as_str() {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        _ => return Ok(None),
    };
    Ok(Some(named.to_owned()))
}

fn stop_if_cancelled(cancellation: &ScanCancellation) -> Result<()> {
    if !cancellation.is_cancelled() {
        return Ok(());
    }
    if let Some(reason) = cancellation.take_reason() {
        return Err(reason);
    }
    Err(Error::codex_security(
        "Knowledge base preparation was interrupted.",
    ))
}
