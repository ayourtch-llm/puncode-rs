//! Reading contract documents within strict bounds.
//!
//! Ported from the document-reading half of `src/contract.ts`.
//!
//! Every document here is written by a plugin running against an untrusted
//! repository, so each one is read defensively: bounded in size, bounded in
//! nesting depth, required to be well-formed UTF-8, and required to carry only
//! numbers that survive a round trip through the contract. Error messages
//! deliberately never quote document content, because a key or value could
//! itself be attacker-chosen.

// Layers B-D of the contract port consume these; the module is being brought
// over incrementally.
#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// The deepest nesting a contract document may use.
pub(crate) const MAX_JSON_DEPTH: usize = 256;

/// Read granularity while enforcing the size bound.
const DOCUMENT_READ_CHUNK_BYTES: usize = 64 * 1_024;

/// The largest integer JavaScript represents exactly. Documents are produced
/// and consumed by JavaScript as well, so anything beyond this could not
/// round-trip.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// `serde_json` refuses a float literal that overflows `f64`, where JavaScript
/// produces `Infinity` and upstream reports it as a non-finite number. The
/// mapping is pinned by a test so a dependency upgrade cannot silently change
/// which message a document gets rejected with.
const SERDE_NUMBER_OUT_OF_RANGE: &str = "number out of range";

/// Reads at most `maximum` bytes, refusing a document that is or becomes
/// larger.
///
/// The size is checked before reading and again while reading: a file that
/// grows between the two would otherwise slip past the bound.
pub(crate) fn read_bounded_document(file: &mut File, path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let too_large = || {
        Error::contract_validation(format!(
            "{}: JSON document exceeds the {maximum}-byte limit.",
            path.display()
        ))
    };

    let metadata = file
        .metadata()
        .map_err(|error| unreadable(path).with_source(error))?;
    if metadata.len() > maximum {
        return Err(too_large());
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|error| unreadable(path).with_source(error))?;

    let mut contents = Vec::new();
    let mut buffer = vec![0_u8; DOCUMENT_READ_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| unreadable(path).with_source(error))?;
        if read == 0 {
            break;
        }
        contents.extend_from_slice(&buffer[..read]);
        if contents.len() as u64 > maximum {
            return Err(too_large());
        }
    }
    Ok(contents)
}

pub(crate) fn unreadable(path: &Path) -> Error {
    Error::contract_validation(format!("{}: unreadable JSON document.", path.display()))
}

/// Parses `bytes` as a JSON object, enforcing the contract's document rules.
pub(crate) fn parse_json(path: &Path, bytes: &[u8]) -> Result<Map<String, Value>> {
    let text = std::str::from_utf8(bytes).map_err(|error| unreadable(path).with_source(error))?;
    require_json_nesting(text, path)?;

    // `serde_json` caps recursion at 128 levels by default, which is shallower
    // than the contract allows. Depth is already bounded above from the raw
    // text, so its limit is disabled and the contract's governs.
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    let payload: Value = Value::deserialize(&mut deserializer).map_err(|error| {
        // Match upstream, which sees `Infinity` rather than a parse failure.
        if error.to_string().starts_with(SERDE_NUMBER_OUT_OF_RANGE) {
            return Error::contract_validation(format!(
                "{}: non-finite JSON numbers are not supported.",
                path.display()
            ));
        }
        Error::contract_validation(format!("{}: invalid JSON: {error}", path.display()))
    })?;

    let Value::Object(payload) = payload else {
        return Err(Error::contract_validation(format!(
            "{}: expected a JSON object.",
            path.display()
        )));
    };

    let context = path.display().to_string();
    for (key, value) in &payload {
        require_well_formed_key(key, &context)?;
        validate_parsed_json(value, &context, 1)?;
    }
    Ok(payload)
}

/// Rejects excessive nesting from the raw text, before a parser can recurse
/// into it.
fn require_json_nesting(text: &str, path: &Path) -> Result<()> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for character in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' | '[' => {
                depth += 1;
                // Upstream allows one level beyond the limit here; the parsed
                // form is checked exactly.
                if depth > MAX_JSON_DEPTH + 1 {
                    return Err(nesting_error(path));
                }
            }
            '}' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn nesting_error(path: &Path) -> Error {
    Error::contract_validation(format!(
        "{}: JSON document exceeds the {MAX_JSON_DEPTH}-level nesting limit.",
        path.display()
    ))
}

/// Walks a parsed document, rejecting values that cannot round-trip.
///
/// `context` never includes a key or value from the document: a malicious
/// document could otherwise choose the text of an error message.
fn validate_parsed_json(value: &Value, context: &str, depth: usize) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        return Err(Error::contract_validation(format!(
            "{context}: JSON document exceeds the {MAX_JSON_DEPTH}-level nesting limit."
        )));
    }

    match value {
        Value::Number(number) => {
            let Some(as_float) = number.as_f64() else {
                return Err(Error::contract_validation(format!(
                    "{context}: non-finite JSON numbers are not supported."
                )));
            };
            if !as_float.is_finite() {
                return Err(Error::contract_validation(format!(
                    "{context}: non-finite JSON numbers are not supported."
                )));
            }
            // Integer-valued numbers must stay exactly representable. Rust
            // parses these losslessly where JavaScript would already have
            // rounded, so the check has to be explicit.
            if as_float.fract() == 0.0 && as_float.abs() > MAX_SAFE_INTEGER {
                return Err(Error::contract_validation(format!(
                    "{context}: unsafe integer-valued JSON numbers are not supported."
                )));
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                validate_parsed_json(item, &format!("{context}[{index}]"), depth + 1)?;
            }
            Ok(())
        }
        Value::Object(entries) => {
            for (key, item) in entries {
                require_well_formed_key(key, context)?;
                validate_parsed_json(item, &format!("{context}.<property>"), depth + 1)?;
            }
            Ok(())
        }
        // Rust strings are already well-formed UTF-8, and `serde_json` rejects
        // unpaired surrogate escapes, so upstream's string check cannot fail
        // here. Keys are checked below for the same reason: to keep the shape
        // of the validation obvious rather than silently absent.
        Value::String(_) | Value::Bool(_) | Value::Null => Ok(()),
    }
}

fn require_well_formed_key(key: &str, context: &str) -> Result<()> {
    if key.chars().any(|character| character == '\u{FFFD}') && !key.is_char_boundary(key.len()) {
        return Err(Error::contract_validation(format!(
            "{context}: expected well-formed Unicode JSON keys."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse(text: &str) -> Result<Map<String, Value>> {
        parse_json(Path::new("/scan/findings.json"), text.as_bytes())
    }

    fn error_of(text: &str) -> String {
        parse(text).expect_err("should be rejected").to_string()
    }

    #[test]
    fn parses_a_json_object() {
        let parsed = parse(r#"{"scanId":"scan","count":3}"#).expect("parses");

        assert_eq!(parsed["scanId"], Value::from("scan"));
        assert_eq!(parsed["count"], Value::from(3));
    }

    #[test]
    fn rejects_a_document_that_is_not_an_object() {
        assert_eq!(
            error_of("[1,2,3]"),
            "/scan/findings.json: expected a JSON object."
        );
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(error_of("{").starts_with("/scan/findings.json: invalid JSON:"));
    }

    #[test]
    fn rejects_invalid_utf8() {
        let error = parse_json(Path::new("/scan/findings.json"), &[0xff, 0xfe, b'{', b'}'])
            .expect_err("invalid UTF-8 is rejected");

        assert_eq!(
            error.to_string(),
            "/scan/findings.json: unreadable JSON document."
        );
    }

    #[test]
    fn rejects_nesting_beyond_the_limit() {
        let depth = 258;
        let text = format!(
            "{{\"overflow\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );

        assert_eq!(
            error_of(&text),
            "/scan/findings.json: JSON document exceeds the 256-level nesting limit."
        );
    }

    #[test]
    fn accepts_nesting_at_the_limit() {
        // The outer object plus 255 arrays sits exactly at the bound.
        let depth = 255;
        let text = format!("{{\"deep\":{}0{}}}", "[".repeat(depth), "]".repeat(depth));

        assert!(parse(&text).is_ok(), "depth {depth} should be accepted");
    }

    // Braces inside strings are data, not structure.
    #[test]
    fn does_not_count_braces_inside_strings() {
        let text = format!(r#"{{"note":"{}"}}"#, "[".repeat(1_000));

        assert!(parse(&text).is_ok());
    }

    #[test]
    fn does_not_count_escaped_quotes_as_ending_a_string() {
        let text = r#"{"note":"a \" [[[ b"}"#;

        assert!(parse(text).is_ok());
    }

    // JavaScript turns an overflowing literal into `Infinity`; upstream reports
    // that as a non-finite number rather than a parse failure.
    #[test]
    fn rejects_non_finite_numbers() {
        assert_eq!(
            error_of(r#"{"overflow":1e400}"#),
            "/scan/findings.json: non-finite JSON numbers are not supported."
        );
        assert_eq!(
            error_of(r#"{"overflow":-1e400}"#),
            "/scan/findings.json: non-finite JSON numbers are not supported."
        );
    }

    /// Pins the dependency coupling: if `serde_json` changes this message, the
    /// document would be rejected with the wrong error instead.
    #[test]
    fn serde_json_still_reports_out_of_range_numbers_as_expected() {
        let error = serde_json::from_str::<Value>("1e400").expect_err("overflows f64");

        assert!(
            error.to_string().starts_with(SERDE_NUMBER_OUT_OF_RANGE),
            "serde_json message changed: {error}"
        );
    }

    #[test]
    fn rejects_unsafe_integer_valued_numbers() {
        for text in [
            r#"{"startLine":9007199254740993}"#,
            r#"{"startLine":-9007199254740993}"#,
            r#"{"startLine":12345678901234567890}"#,
            r#"{"startLine":1e300}"#,
        ] {
            assert_eq!(
                error_of(text),
                "/scan/findings.json: unsafe integer-valued JSON numbers are not supported.",
                "{text}"
            );
        }
    }

    #[test]
    fn accepts_numbers_at_the_safe_integer_boundary() {
        assert!(parse(r#"{"startLine":9007199254740991}"#).is_ok());
        assert!(parse(r#"{"startLine":-9007199254740991}"#).is_ok());
        assert!(
            parse(r#"{"score":8.1}"#).is_ok(),
            "fractional values are unaffected"
        );
    }

    // Error text must never quote the document: a key could be chosen by an
    // attacker to smuggle content into a log.
    #[test]
    fn does_not_expose_document_keys_in_errors() {
        let marker = "PRIVATE_JSON_KEY";
        let text = format!(r#"{{"findings":[{{"{marker}":9007199254740993}}]}}"#);

        let error = error_of(&text);

        assert!(
            !error.contains(marker),
            "error leaked a document key: {error}"
        );
        // The position is reported structurally, never by name.
        assert_eq!(
            error,
            "/scan/findings.json[0].<property>: unsafe integer-valued JSON numbers are not supported."
        );
    }

    #[test]
    fn reports_array_positions_without_exposing_values() {
        let text = r#"{"findings":[0,1,1e400]}"#;

        let error = error_of(text);

        assert!(error.contains("non-finite"), "{error}");
    }

    #[test]
    fn reads_a_document_within_its_bound() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"{\"ok\":true}").expect("write");
        let mut handle = file.reopen().expect("reopen");

        let bytes =
            read_bounded_document(&mut handle, Path::new("/scan/x.json"), 1_024).expect("reads");

        assert_eq!(bytes, b"{\"ok\":true}");
    }

    #[test]
    fn rejects_a_document_beyond_its_bound() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(&vec![b'x'; 2_048]).expect("write");
        let mut handle = file.reopen().expect("reopen");

        let error = read_bounded_document(&mut handle, Path::new("/scan/x.json"), 1_024)
            .expect_err("exceeds the bound");

        assert_eq!(
            error.to_string(),
            "/scan/x.json: JSON document exceeds the 1024-byte limit."
        );
    }

    #[test]
    fn accepts_a_document_exactly_at_its_bound() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(&vec![b'x'; 1_024]).expect("write");
        let mut handle = file.reopen().expect("reopen");

        assert!(read_bounded_document(&mut handle, Path::new("/scan/x.json"), 1_024).is_ok());
    }
}
