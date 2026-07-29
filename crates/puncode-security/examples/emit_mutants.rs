//! Writes every mutant of a file, one directory each.
//!
//! Kept as an example so the ground truth stays reproducible: the claim that a
//! mutant is genuinely exploitable was established by generating these and
//! attacking them, and anyone can do it again.
//!
//!     cargo run -p puncode-security --example emit_mutants -- <file> <out-dir>

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(file), Some(out)) = (args.next(), args.next()) else {
        eprintln!("usage: emit_mutants <file> <out-dir>");
        std::process::exit(2);
    };
    let source = std::fs::read_to_string(&file).expect("the file");
    let relative = std::path::Path::new(&file)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.clone());

    for mutant in puncode_security::mutation::mutate(&relative, &source) {
        let directory = std::path::Path::new(&out).join(mutant.operator);
        std::fs::create_dir_all(&directory).expect("creates");
        std::fs::write(directory.join(&relative), &mutant.source).expect("writes");
        println!(
            "{} {}:{}-{} {} {}",
            mutant.operator,
            mutant.file,
            mutant.lines.0,
            mutant.lines.1,
            mutant.cwe,
            if mutant.confirmed() {
                "confirmed"
            } else {
                "UNCONFIRMED"
            }
        );
    }
}
