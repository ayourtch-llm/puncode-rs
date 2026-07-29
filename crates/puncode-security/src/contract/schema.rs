//! Bounding what a contract schema is allowed to ask for.
//!
//! Ported from the schema-guard half of `src/contract.ts`.
//!
//! The schemas are read from a plugin directory, so they are treated as input
//! rather than as trusted code. An unbounded schema can be made to cost far
//! more to validate than it costs to write — through deep applicator nesting,
//! enormous collections, or a pattern that backtracks exponentially. This
//! module refuses such a schema before it ever reaches the validator, and it
//! refuses keywords whose evaluation the contract does not need at all.

#![allow(dead_code)]

use serde_json::Value;

use crate::error::{Error, Result};

/// Total values the schema tree may contain.
const MAX_SCHEMA_NODES: usize = 8_192;
/// Entries any single object or array in the schema may hold.
const MAX_SCHEMA_COLLECTION_ENTRIES: usize = 4_096;
/// Subschema references the schema may apply, in total.
const MAX_SCHEMA_APPLICATOR_EDGES: usize = 128;

/// Keywords the contract never uses. `$ref` and friends are refused outright,
/// which is also why no reference resolution is needed anywhere here.
const UNSUPPORTED_KEYWORDS: [&str; 10] = [
    "$async",
    "$ref",
    "$dynamicRef",
    "$recursiveRef",
    "prefixItems",
    "patternProperties",
    "propertyNames",
    "dependentSchemas",
    "dependencies",
    "uniqueItems",
];

/// The exact patterns the contract schemas are allowed to use. An allowlist,
/// rather than an analysis, because deciding whether an arbitrary regex
/// backtracks badly is not something to attempt at load time.
const SAFE_SCHEMA_PATTERNS: [&str; 10] = [
    r"^(?![^:/?#]+://[^/?#]*@)[^?#]+$",
    r"^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$",
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*\\).+$",
    r"^[a-f0-9]{64}$",
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?!.*\\)artifacts/.+$",
    r"^csf_[a-f0-9]{24}$",
    r"^occ_[a-f0-9]{24}$",
    r"^[a-z0-9][a-z0-9._/-]*$",
    r"^codex-security/v1:sha256:[a-f0-9]{64}$",
    r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$",
];

/// Property names that may appear verbatim in a validation error. Everything
/// else is replaced, because an instance path can otherwise carry
/// attacker-chosen text into a message.
pub(crate) const SAFE_SCHEMA_ERROR_PROPERTIES: [&str; 9] = [
    "scan",
    "target",
    "remote",
    "completedAt",
    "sealedAt",
    "artifacts",
    "findings",
    "coverage",
    "scope",
];

/// Keywords whose value is data rather than a subschema.
const DATA_KEYWORDS: [&str; 5] = ["const", "enum", "default", "examples", "dependentRequired"];

/// Keywords holding a map of named subschemas.
const SUBSCHEMA_MAPS: [&str; 3] = ["properties", "$defs", "definitions"];

/// Keywords holding a list of subschemas.
const SUBSCHEMA_LISTS: [&str; 3] = ["allOf", "anyOf", "oneOf"];

/// Keywords holding a single subschema.
const SUBSCHEMA_SINGLES: [&str; 9] = [
    "if",
    "then",
    "else",
    "not",
    "items",
    "contains",
    "additionalProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
];

/// Refuses a schema that is too large, too branching, or uses a keyword or
/// pattern outside the contract.
pub(crate) fn require_schema_complexity(schema: &Value, schema_name: &str) -> Result<()> {
    // Walked as a stack, matching upstream, so that when several limits are
    // exceeded the same one is reported.
    let mut pending: Vec<(&Value, bool)> = vec![(schema, true)];
    let mut nodes = 0_usize;
    let mut applicator_edges = 0_usize;

    while let Some((value, is_schema)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_SCHEMA_NODES {
            return Err(Error::contract_validation(format!(
                "{schema_name}: JSON Schema exceeds the {MAX_SCHEMA_NODES}-node complexity limit."
            )));
        }

        match value {
            Value::Array(items) => {
                if items.len() > MAX_SCHEMA_COLLECTION_ENTRIES {
                    return Err(collection_limit(schema_name));
                }
                for item in items {
                    pending.push((item, is_schema));
                }
            }
            Value::Object(entries) => {
                if entries.len() > MAX_SCHEMA_COLLECTION_ENTRIES {
                    return Err(collection_limit(schema_name));
                }
                for (keyword, child) in entries {
                    // Outside a schema position every key is just data.
                    if !is_schema {
                        pending.push((child, false));
                        continue;
                    }
                    if UNSUPPORTED_KEYWORDS.contains(&keyword.as_str()) {
                        return Err(Error::contract_validation(format!(
                            "{schema_name}: unsupported JSON Schema keyword."
                        )));
                    }

                    applicator_edges += applicator_edges_for(keyword, child);
                    if applicator_edges > MAX_SCHEMA_APPLICATOR_EDGES {
                        return Err(Error::contract_validation(format!(
                            "{schema_name}: JSON Schema exceeds the \
                             {MAX_SCHEMA_APPLICATOR_EDGES}-edge applicator limit."
                        )));
                    }

                    if keyword == "pattern"
                        && let Some(pattern) = child.as_str()
                        && !SAFE_SCHEMA_PATTERNS.contains(&pattern)
                    {
                        return Err(Error::contract_validation(format!(
                            "{schema_name}: unsupported JSON Schema pattern."
                        )));
                    }

                    if SUBSCHEMA_MAPS.contains(&keyword.as_str())
                        && let Some(subschemas) = child.as_object()
                    {
                        if subschemas.len() > MAX_SCHEMA_COLLECTION_ENTRIES {
                            return Err(collection_limit(schema_name));
                        }
                        for subschema in subschemas.values() {
                            pending.push((subschema, true));
                        }
                        continue;
                    }

                    pending.push((child, !DATA_KEYWORDS.contains(&keyword.as_str())));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// How many subschemas `keyword` brings into play.
fn applicator_edges_for(keyword: &str, child: &Value) -> usize {
    if SUBSCHEMA_LISTS.contains(&keyword)
        && let Value::Array(items) = child
    {
        return items.len();
    }
    if SUBSCHEMA_SINGLES.contains(&keyword) && matches!(child, Value::Bool(_) | Value::Object(_)) {
        return 1;
    }
    if SUBSCHEMA_MAPS.contains(&keyword)
        && let Value::Object(entries) = child
    {
        return entries.len();
    }
    0
}

fn collection_limit(schema_name: &str) -> Error {
    Error::contract_validation(format!(
        "{schema_name}: JSON Schema exceeds the {MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit."
    ))
}

/// Compiles `schema` into a validator that also enforces the contract's
/// calendar-accurate `date-time` format.
pub(crate) fn compile_validator(
    schema: &Value,
    schema_name: &str,
) -> Result<jsonschema::Validator> {
    jsonschema::options()
        .with_format("date-time", |value: &str| {
            super::datetime::valid_rfc3339_date_time(value)
        })
        .should_validate_formats(true)
        .build(schema)
        .map_err(|_| Error::contract_validation(format!("{schema_name}: invalid JSON Schema.")))
}

/// Validates `payload`, reporting the first violation.
///
/// Upstream runs Ajv with `allErrors: false`, so exactly one error is ever
/// reported; `validate` gives the same single-error behavior here. Which
/// violation surfaces first when a document breaks several rules is up to the
/// validator, so only the shape of the message is guaranteed to match.
pub(crate) fn validate_document(
    validator: &jsonschema::Validator,
    filename: &str,
    payload: &Value,
) -> Result<()> {
    match validator.validate(payload) {
        Ok(()) => Ok(()),
        Err(error) => Err(schema_error(filename, &error)),
    }
}

/// Builds a validation failure message that cannot be steered by the document.
///
/// The instance path locates the fault, but every property name in it is
/// replaced unless it is an array index or one of the known contract fields:
/// a document could otherwise choose the text through a crafted key.
fn schema_error(filename: &str, error: &jsonschema::ValidationError<'_>) -> Error {
    let pointer = error.instance_path.to_string();
    let segments: Vec<&str> = pointer.split('/').filter(|part| !part.is_empty()).collect();

    let location = if segments.is_empty() {
        "<root>".to_owned()
    } else {
        segments
            .iter()
            .take(super::document::MAX_JSON_DEPTH)
            .map(|segment| {
                if is_array_index(segment) || SAFE_SCHEMA_ERROR_PROPERTIES.contains(segment) {
                    (*segment).to_owned()
                } else {
                    "<property>".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    };

    let keyword = keyword_of(error);
    let detail = if keyword == "format" {
        "; date-time"
    } else {
        ""
    };
    Error::contract_validation(format!(
        "{filename}:{location}: schema validation failed ({keyword}{detail}; 1 error)."
    ))
}

/// A non-negative index without leading zeros, as upstream's
/// `^(?:0|[1-9]\d{0,9})$` accepts.
fn is_array_index(segment: &str) -> bool {
    match segment.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] if first.is_ascii_digit() && *first != b'0' && rest.len() <= 9 => {
            rest.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

/// The schema keyword a violation came from, named as JSON Schema names it.
fn keyword_of(error: &jsonschema::ValidationError<'_>) -> String {
    let debug = format!("{:?}", error.kind);
    let name = debug
        .split(['{', '('])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    // `ValidationErrorKind` variants carry the keyword names in PascalCase.
    let mut characters = name.chars();
    match characters.next() {
        Some(first) => first.to_ascii_lowercase().to_string() + characters.as_str(),
        None => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MANIFEST_SCHEMA: &str =
        include_str!("../../tests/fixtures/schemas/scan-manifest.schema.json");
    const FINDINGS_SCHEMA: &str = include_str!("../../tests/fixtures/schemas/findings.schema.json");
    const COVERAGE_SCHEMA: &str = include_str!("../../tests/fixtures/schemas/coverage.schema.json");

    fn check(schema: Value) -> Result<()> {
        require_schema_complexity(&schema, "test.schema.json")
    }

    fn error_of(schema: Value) -> String {
        check(schema).expect_err("should be refused").to_string()
    }

    /// The shipped schemas must pass their own guard, or no scan can load.
    #[test]
    fn accepts_the_bundled_plugin_schemas() {
        for (name, source) in [
            ("scan-manifest.schema.json", MANIFEST_SCHEMA),
            ("findings.schema.json", FINDINGS_SCHEMA),
            ("coverage.schema.json", COVERAGE_SCHEMA),
        ] {
            let schema: Value = serde_json::from_str(source).expect("fixture parses");

            require_schema_complexity(&schema, name)
                .unwrap_or_else(|error| panic!("{name} should be accepted: {error}"));
        }
    }

    #[test]
    fn rejects_unsupported_keywords() {
        for keyword in UNSUPPORTED_KEYWORDS {
            let schema = json!({ "type": "object", keyword: true });

            assert_eq!(
                error_of(schema),
                "test.schema.json: unsupported JSON Schema keyword.",
                "{keyword} should be refused"
            );
        }
    }

    #[test]
    fn rejects_an_unsupported_keyword_nested_in_a_subschema() {
        let schema = json!({
            "type": "object",
            "properties": { "a": { "type": "object", "patternProperties": {} } }
        });

        assert_eq!(
            error_of(schema),
            "test.schema.json: unsupported JSON Schema keyword."
        );
    }

    // A keyword name appearing inside `const` or `enum` is data, not a schema,
    // so it must not be mistaken for an unsupported keyword.
    #[test]
    fn treats_const_and_enum_values_as_data() {
        assert!(check(json!({ "const": { "$ref": "http://example.com" } })).is_ok());
        assert!(check(json!({ "enum": [{ "patternProperties": {} }] })).is_ok());
        assert!(check(json!({ "default": { "uniqueItems": true } })).is_ok());
        assert!(check(json!({ "examples": [{ "$dynamicRef": "#x" }] })).is_ok());
        assert!(check(json!({ "dependentRequired": { "a": ["b"] } })).is_ok());
    }

    // A property literally named "$ref" is still a property name, not a keyword.
    #[test]
    fn treats_property_names_as_names_not_keywords() {
        let schema = json!({
            "type": "object",
            "properties": { "$ref": { "type": "string" } }
        });

        assert!(check(schema).is_ok());
    }

    #[test]
    fn rejects_patterns_outside_the_allowlist() {
        let schema = json!({ "type": "string", "pattern": "^(a+)+$" });

        assert_eq!(
            error_of(schema),
            "test.schema.json: unsupported JSON Schema pattern."
        );
    }

    #[test]
    fn accepts_allowlisted_patterns() {
        for pattern in SAFE_SCHEMA_PATTERNS {
            assert!(
                check(json!({ "type": "string", "pattern": pattern })).is_ok(),
                "{pattern} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_a_schema_beyond_the_node_limit() {
        // Spread across several collections so the per-collection limit is not
        // the one that trips, and held under `const` so no applicator edge is
        // counted either.
        let chunk = |size: usize| -> Value { (0..size).map(|index| json!(index)).collect() };
        let schema = json!({
            "const": { "a": chunk(4_000), "b": chunk(4_000), "c": chunk(1_000) }
        });

        assert_eq!(
            error_of(schema),
            format!(
                "test.schema.json: JSON Schema exceeds the {MAX_SCHEMA_NODES}-node complexity limit."
            )
        );
    }

    #[test]
    fn rejects_an_oversized_collection() {
        let items: Vec<Value> = (0..MAX_SCHEMA_COLLECTION_ENTRIES + 1)
            .map(|index| json!(index))
            .collect();

        assert_eq!(
            error_of(json!({ "enum": items })),
            format!(
                "test.schema.json: JSON Schema exceeds the \
                 {MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit."
            )
        );
    }

    #[test]
    fn rejects_too_many_applicator_edges() {
        let branches: Vec<Value> = (0..MAX_SCHEMA_APPLICATOR_EDGES + 1)
            .map(|_| json!({ "type": "string" }))
            .collect();

        assert_eq!(
            error_of(json!({ "anyOf": branches })),
            format!(
                "test.schema.json: JSON Schema exceeds the \
                 {MAX_SCHEMA_APPLICATOR_EDGES}-edge applicator limit."
            )
        );
    }

    #[test]
    fn counts_edges_across_keyword_shapes() {
        // A map of subschemas contributes one edge per entry.
        let properties: serde_json::Map<String, Value> = (0..MAX_SCHEMA_APPLICATOR_EDGES + 1)
            .map(|index| (format!("p{index}"), json!({ "type": "string" })))
            .collect();
        assert!(error_of(json!({ "properties": properties })).contains("edge applicator limit"));

        // A single subschema contributes exactly one.
        assert!(check(json!({ "not": { "type": "string" } })).is_ok());
        assert!(check(json!({ "additionalProperties": false })).is_ok());
    }

    #[test]
    fn accepts_a_schema_at_the_edge_limit() {
        let branches: Vec<Value> = (0..MAX_SCHEMA_APPLICATOR_EDGES)
            .map(|_| json!({ "type": "string" }))
            .collect();

        assert!(check(json!({ "anyOf": branches })).is_ok());
    }

    #[test]
    fn accepts_a_trivial_schema() {
        assert!(check(json!({})).is_ok());
        assert!(check(json!({ "type": "object", "required": ["a"] })).is_ok());
    }
    // --- validation and error redaction ---

    fn manifest_validator() -> jsonschema::Validator {
        let schema: Value = serde_json::from_str(MANIFEST_SCHEMA).expect("fixture parses");
        compile_validator(&schema, "scan-manifest.schema.json").expect("compiles")
    }

    #[test]
    fn validates_the_bundled_example_documents() {
        for (schema_source, document_source, name) in [
            (
                MANIFEST_SCHEMA,
                include_str!("../../tests/fixtures/completed-scan/scan-manifest.json"),
                "scan-manifest.json",
            ),
            (
                FINDINGS_SCHEMA,
                include_str!("../../tests/fixtures/completed-scan/findings.json"),
                "findings.json",
            ),
            (
                COVERAGE_SCHEMA,
                include_str!("../../tests/fixtures/completed-scan/coverage.json"),
                "coverage.json",
            ),
        ] {
            let schema: Value = serde_json::from_str(schema_source).expect("schema parses");
            let document: Value = serde_json::from_str(document_source).expect("document parses");
            let validator = compile_validator(&schema, name).expect("compiles");

            validate_document(&validator, name, &document)
                .unwrap_or_else(|error| panic!("{name} should validate: {error}"));
        }
    }

    #[test]
    fn reports_a_missing_required_field() {
        let validator = manifest_validator();

        let error = validate_document(&validator, "scan-manifest.json", &json!({}))
            .expect_err("an empty document is invalid");

        assert_eq!(
            error.to_string(),
            "scan-manifest.json:<root>: schema validation failed (required; 1 error)."
        );
    }

    // The custom format is what rejects a calendar-invalid timestamp; the
    // schema alone only says "string".
    #[test]
    fn rejects_a_calendar_invalid_timestamp_through_the_custom_format() {
        let mut document: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/completed-scan/scan-manifest.json"
        ))
        .expect("parses");
        document["scan"]["completedAt"] = json!("2026-02-30T00:00:00Z");
        let validator = manifest_validator();

        let error = validate_document(&validator, "scan-manifest.json", &document)
            .expect_err("February 30th is not a date");

        assert_eq!(
            error.to_string(),
            "scan-manifest.json:scan.completedAt: schema validation failed (format; date-time; 1 error)."
        );
    }

    // Known contract fields stay readable; anything else is replaced so a
    // crafted key cannot choose the message text.
    #[test]
    fn redacts_property_names_outside_the_allowlist() {
        let schema = json!({
            "type": "object",
            "properties": {
                "scan": { "type": "object", "properties": {
                    "PRIVATE_KEY_NAME": { "type": "integer" }
                }}
            }
        });
        let validator = compile_validator(&schema, "test.schema.json").expect("compiles");
        let document = json!({ "scan": { "PRIVATE_KEY_NAME": "not an integer" } });

        let error =
            validate_document(&validator, "scan-manifest.json", &document).expect_err("wrong type");

        assert!(!error.to_string().contains("PRIVATE_KEY_NAME"), "{error}");
        assert_eq!(
            error.to_string(),
            "scan-manifest.json:scan.<property>: schema validation failed (type; 1 error)."
        );
    }

    #[test]
    fn keeps_array_indexes_in_the_location() {
        let schema = json!({
            "type": "object",
            "properties": { "artifacts": { "type": "array", "items": { "type": "string" } } }
        });
        let validator = compile_validator(&schema, "test.schema.json").expect("compiles");

        let error = validate_document(
            &validator,
            "scan-manifest.json",
            &json!({ "artifacts": ["a", 2] }),
        )
        .expect_err("wrong item type");

        assert_eq!(
            error.to_string(),
            "scan-manifest.json:artifacts.1: schema validation failed (type; 1 error)."
        );
    }

    #[test]
    fn recognizes_array_indexes_exactly() {
        assert!(is_array_index("0"));
        assert!(is_array_index("7"));
        assert!(is_array_index("1234567890"));
        assert!(!is_array_index("00"));
        assert!(!is_array_index("01"));
        assert!(!is_array_index("12345678901"), "more than ten digits");
        assert!(!is_array_index(""));
        assert!(!is_array_index("1a"));
        assert!(!is_array_index("-1"));
    }

    /// Pins the dependency coupling: the keyword name is derived from the
    /// error kind, so a crate upgrade that renames a variant must fail loudly.
    #[test]
    fn derives_keyword_names_from_the_validator() {
        // Each constraint sits on its own property: a value that breaks two
        // at once leaves which one surfaces first up to the validator.
        let schema = json!({
            "type": "object",
            "properties": {
                "a": { "enum": ["x"] },
                "c": { "type": "integer" }
            },
            "required": ["b"]
        });
        let validator = compile_validator(&schema, "test.schema.json").expect("compiles");

        let required = validate_document(&validator, "d.json", &json!({})).expect_err("missing b");
        assert!(required.to_string().contains("(required;"), "{required}");

        let wrong_type = validate_document(&validator, "d.json", &json!({ "b": 1, "c": "no" }))
            .expect_err("wrong type");
        assert!(wrong_type.to_string().contains("(type;"), "{wrong_type}");

        let not_in_enum = validate_document(&validator, "d.json", &json!({ "a": "y", "b": 1 }))
            .expect_err("not in enum");
        assert!(not_in_enum.to_string().contains("(enum;"), "{not_in_enum}");
    }

    #[test]
    fn refuses_a_schema_that_cannot_compile() {
        let error = compile_validator(&json!({ "type": 5 }), "broken.schema.json")
            .expect_err("invalid schema");

        assert_eq!(
            error.to_string(),
            "broken.schema.json: invalid JSON Schema."
        );
    }
}
