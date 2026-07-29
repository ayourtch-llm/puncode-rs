//! Checks a scan's findings against the code they cite.
//!
//! Kept as an example so the claim "every finding in every run here resolved"
//! stays checkable rather than quoted.
//!
//!     cargo run -p puncode-security --example check_anchors -- <scan-dir> <target-dir>

use puncode_security::finding_anchors::{Cited, check};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(scan_dir), Some(target)) = (args.next(), args.next()) else {
        eprintln!("usage: check_anchors <scan-dir> <target-dir>");
        std::process::exit(2);
    };
    let body = std::fs::read_to_string(std::path::Path::new(&scan_dir).join("findings.json"))
        .expect("findings.json");
    let document: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let mut cited = Vec::new();
    let mut empty = Vec::new();
    for finding in document
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = finding
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(untitled)")
            .to_owned();
        let locations = finding
            .get("locations")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        if locations.is_empty() {
            empty.push(name);
            continue;
        }
        for location in locations {
            let Some(file) = location.get("path").and_then(serde_json::Value::as_str) else {
                continue;
            };
            for key in ["startLine", "endLine"] {
                if let Some(line) = location.get(key).and_then(serde_json::Value::as_u64) {
                    cited.push(Cited {
                        finding: name.clone(),
                        file: file.to_owned(),
                        line: u32::try_from(line).unwrap_or(u32::MAX),
                    });
                }
            }
        }
    }

    let outcome = check(&cited, &empty, std::path::Path::new(&target));
    for problem in &outcome.unanchored {
        println!("  {}", problem.describe());
    }
    println!(
        "-- {} location(s) resolved, {} did not, {} finding(s) cite nowhere",
        outcome.resolved,
        outcome.unanchored.len(),
        outcome.without_locations.len()
    );
}
