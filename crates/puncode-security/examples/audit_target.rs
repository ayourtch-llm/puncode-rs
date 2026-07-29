//! Reads a directory for passages addressed to an automated reader.
//!
//! Kept as an example rather than a subcommand: this is how the false-positive
//! rate was measured against real repositories, and it should stay runnable so
//! the next person can measure it again rather than take the number on trust.
//!
//!     cargo run -p puncode-security --example audit_target -- <dir>

fn main() {
    let Some(root) = std::env::args().nth(1) else {
        eprintln!("usage: audit_target <dir>");
        std::process::exit(2);
    };
    let audit = puncode_security::target_audit::audit_target(std::path::Path::new(&root));
    for passage in &audit.passages {
        println!(
            "{}:{} [{}] {}",
            passage.file, passage.line, passage.phrase, passage.text
        );
    }
    println!(
        "-- {} passage(s), truncated={}, large files skipped={}",
        audit.passages.len(),
        audit.truncated,
        audit.skipped_large_files
    );
}
