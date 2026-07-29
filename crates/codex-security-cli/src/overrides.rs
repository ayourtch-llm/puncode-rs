//! Parsing `--codex KEY=VALUE` overrides.
//!
//! Ported from `parseCodexOverrides` in `src/cli.ts`.
//!
//! These become configuration the isolated Codex runs under, so the key is
//! treated as structure rather than text: it is split into a path, every
//! segment is checked, and a segment that would reach an object's machinery
//! rather than its data is refused outright. The limits exist because the
//! values end up on a command line and in a configuration file, and neither
//! should be unbounded.

use serde_json::{Map, Value};

/// The longest key an override may use.
const MAX_KEY_BYTES: usize = 1_024;

/// The longest value an override may carry.
const MAX_VALUE_BYTES: usize = 64 * 1_024;

/// How deeply an override may nest.
const MAX_DEPTH: usize = 64;

/// Segments that name an object's machinery rather than its data.
const RESERVED_SEGMENTS: [&str; 3] = ["__proto__", "prototype", "constructor"];

/// Turns `KEY=VALUE` overrides into the configuration they describe.
///
/// `model`, when given, is applied first and then guarded: an explicit
/// `--model` alongside `--codex model=…` is a contradiction, not a preference.
pub fn parse_codex_overrides(
    values: &[String],
    model: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let mut result = Map::new();
    if let Some(model) = model {
        result.insert("model".to_owned(), Value::String(model.to_owned()));
    }

    for value in values {
        let (key, literal) = value
            .split_once('=')
            .filter(|(key, literal)| !key.is_empty() && !literal.is_empty())
            .ok_or_else(|| "--codex expects KEY=VALUE".to_owned())?;
        if key.len() > MAX_KEY_BYTES || literal.len() > MAX_VALUE_BYTES {
            return Err("--codex key or value exceeds the limit".to_owned());
        }

        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() > MAX_DEPTH
            || parts
                .iter()
                .any(|part| part.is_empty() || RESERVED_SEGMENTS.contains(part))
        {
            return Err("Invalid --codex key".to_owned());
        }

        // The value is TOML, as it would be written in the configuration file,
        // so `1` is a number and `"1"` is a string.
        let parsed = parse_toml_value(literal)?;

        let mut cursor = &mut result;
        for part in &parts[..parts.len() - 1] {
            let entry = cursor
                .entry((*part).to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            cursor = entry
                .as_object_mut()
                .ok_or_else(|| "Conflicting --codex key".to_owned())?;
        }

        let last = parts[parts.len() - 1];
        if cursor.contains_key(last) {
            return Err(if model.is_some() && key == "model" {
                "--model conflicts with --codex model".to_owned()
            } else {
                "Duplicate --codex key".to_owned()
            });
        }
        cursor.insert(last.to_owned(), parsed);
    }
    Ok(result)
}

/// Reads one TOML value, as the configuration file would.
fn parse_toml_value(literal: &str) -> Result<Value, String> {
    let document: toml::Value = toml::from_str(&format!("value = {literal}"))
        .map_err(|_| "Invalid --codex TOML value".to_owned())?;
    let value = document
        .get("value")
        .ok_or_else(|| "Invalid --codex TOML value".to_owned())?;
    serde_json::to_value(value).map_err(|_| "Invalid --codex TOML value".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(values: &[&str]) -> Result<Map<String, Value>, String> {
        let values: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        parse_codex_overrides(&values, None)
    }

    #[test]
    fn reads_a_simple_override() {
        let parsed = parse(&["model=\"gpt-5.6-sol\""]).expect("valid");

        assert_eq!(parsed["model"], json!("gpt-5.6-sol"));
    }

    // The value is TOML, as it would be written in the configuration file, so
    // a bare number is a number and a quoted one is a string.
    #[test]
    fn reads_values_as_the_configuration_would() {
        let parsed = parse(&["a=1", "b=\"1\"", "c=true", "d=[1, 2]"]).expect("valid");

        assert_eq!(parsed["a"], json!(1));
        assert_eq!(parsed["b"], json!("1"));
        assert_eq!(parsed["c"], json!(true));
        assert_eq!(parsed["d"], json!([1, 2]));
    }

    #[test]
    fn nests_a_dotted_key() {
        let parsed = parse(&["features.plugins=false"]).expect("valid");

        assert_eq!(parsed["features"]["plugins"], json!(false));
    }

    #[test]
    fn merges_two_keys_under_one_table() {
        let parsed = parse(&["features.a=1", "features.b=2"]).expect("valid");

        assert_eq!(parsed["features"]["a"], json!(1));
        assert_eq!(parsed["features"]["b"], json!(2));
    }

    #[test]
    fn refuses_a_value_that_is_not_key_and_value() {
        for value in ["model", "=value", "model=", ""] {
            assert_eq!(
                parse(&[value]).expect_err("refused"),
                "--codex expects KEY=VALUE",
                "for {value:?}"
            );
        }
    }

    // A segment naming an object's machinery rather than its data is refused
    // outright, whatever it would have been used for.
    #[test]
    fn refuses_a_key_reaching_object_machinery() {
        for key in [
            "__proto__=1",
            "a.__proto__=1",
            "prototype=1",
            "a.constructor.b=1",
        ] {
            assert_eq!(
                parse(&[key]).expect_err("refused"),
                "Invalid --codex key",
                "for {key}"
            );
        }
    }

    #[test]
    fn refuses_an_empty_key_segment() {
        for key in ["a..b=1", ".a=1", "a.=1"] {
            assert_eq!(
                parse(&[key]).expect_err("refused"),
                "Invalid --codex key",
                "for {key}"
            );
        }
    }

    // These end up on a command line and in a configuration file; neither
    // should be unbounded.
    #[test]
    fn refuses_an_oversized_key_or_value() {
        let long_key = format!("{}=1", "a".repeat(MAX_KEY_BYTES + 1));
        let long_value = format!("a=\"{}\"", "b".repeat(MAX_VALUE_BYTES + 1));

        assert_eq!(
            parse(&[&long_key]).expect_err("refused"),
            "--codex key or value exceeds the limit"
        );
        assert_eq!(
            parse(&[&long_value]).expect_err("refused"),
            "--codex key or value exceeds the limit"
        );
    }

    #[test]
    fn refuses_a_key_nested_beyond_the_limit() {
        let deep = format!("{}=1", vec!["a"; MAX_DEPTH + 1].join("."));

        assert_eq!(parse(&[&deep]).expect_err("refused"), "Invalid --codex key");
    }

    #[test]
    fn refuses_a_value_that_is_not_toml() {
        assert_eq!(
            parse(&["a=not valid toml here"]).expect_err("refused"),
            "Invalid --codex TOML value"
        );
    }

    // Saying the same thing twice is a mistake, not a preference.
    #[test]
    fn refuses_a_duplicate_key() {
        assert_eq!(
            parse(&["a=1", "a=2"]).expect_err("refused"),
            "Duplicate --codex key"
        );
    }

    // A scalar cannot also be a table.
    #[test]
    fn refuses_a_key_that_conflicts_with_a_value() {
        assert_eq!(
            parse(&["a=1", "a.b=2"]).expect_err("refused"),
            "Conflicting --codex key"
        );
    }

    // An explicit --model alongside --codex model is a contradiction, and the
    // message says which two things disagree.
    #[test]
    fn refuses_a_model_given_two_ways() {
        let values = vec!["model=\"other\"".to_owned()];

        assert_eq!(
            parse_codex_overrides(&values, Some("chosen")).expect_err("refused"),
            "--model conflicts with --codex model"
        );
    }

    #[test]
    fn applies_a_model_given_once() {
        let parsed =
            parse_codex_overrides(&["effort=\"high\"".to_owned()], Some("chosen")).expect("valid");

        assert_eq!(parsed["model"], json!("chosen"));
        assert_eq!(parsed["effort"], json!("high"));
    }
}
