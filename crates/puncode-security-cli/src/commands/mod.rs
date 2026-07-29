//! One module per command.
//!
//! Each command turns parsed arguments into the text to print, and leaves the
//! printing and the exit code to `main`. That keeps the commands testable
//! without a process and keeps process I/O in one place.

pub mod bench;
pub mod bulk_scan;
pub mod export;
pub mod github;
pub mod history;
pub mod info;
pub mod install_hook;
pub mod login;
pub mod logout;
pub mod match_all;
pub mod mcp;
pub mod progress;
pub mod recipe;
pub mod scan;
pub mod skill;
pub mod wizard;
