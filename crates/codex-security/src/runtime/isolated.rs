//! The private Codex home a scan runs against.
//!
//! Ported from `createIsolatedHome`, `importAmbientAuth`, `cleanupSdkDirectory`
//! and `resolveCodexCommand` in `src/runtime.ts`.
//!
//! A scan does not run against the user's own Codex home. It gets a private
//! one, so plugin registration, session logs, and configuration written during
//! the scan cannot disturb the user's setup — and so a scan cannot read more of
//! it than it needs. Credentials are the exception: they are copied in
//! deliberately, one file, with owner-only permissions.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, expand_home};
use crate::trusted_executable::resolve_trusted_executable;

use super::output::{LocationCheck, validate_prepared_output_dir};

/// The `codex` executable, and any arguments that must precede its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexCommand {
    pub command: PathBuf,
    pub prefix_args: Vec<String>,
}

/// Creates a private Codex home for one scan.
pub fn create_isolated_home(
    temporary_root: &Path,
    validate_location: Option<LocationCheck<'_>>,
) -> Result<PathBuf> {
    let created = tempfile::Builder::new()
        .prefix("openai-codex-security-home-")
        .tempdir_in(temporary_root)
        .map_err(|error| {
            Error::plugin_bootstrap(format!(
                "Unable to create an isolated Codex home under {}",
                temporary_root.display()
            ))
            .with_source(error)
        })?
        .keep();

    set_private_dir(&created)?;
    match validate_prepared_output_dir(&created, validate_location) {
        Ok(canonical) => Ok(canonical),
        Err(error) => {
            let _ = std::fs::remove_dir(&created);
            Err(error)
        }
    }
}

/// Copies the user's Codex credentials into the isolated home, if there are any.
///
/// Returns whether credentials were imported. A missing file is an ordinary
/// outcome — the scan simply has no ambient credentials to use — but a file
/// that exists and cannot be copied is an error, because proceeding would look
/// like an authentication failure later.
pub fn import_ambient_auth(
    ambient_home: &str,
    isolated_home: &Path,
    environment: &ProcessEnvironment,
) -> Result<bool> {
    let source = expand_home(ambient_home, environment).join("auth.json");

    let metadata = match std::fs::metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(Error::plugin_bootstrap(format!(
                "Unable to inspect ambient Codex authentication: {}",
                source.display()
            ))
            .with_source(error));
        }
    };
    if !metadata.is_file() {
        return Ok(false);
    }

    create_private_dir(isolated_home)?;
    let destination = isolated_home.join("auth.json");
    let temporary = isolated_home.join(format!(
        ".auth-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));

    let copied = copy_private_file(&source, &temporary)
        .and_then(|()| {
            std::fs::rename(&temporary, &destination).map_err(|error| {
                Error::plugin_bootstrap("Unable to copy ambient Codex authentication.")
                    .with_source(error)
            })
        })
        .and_then(|()| set_private_file(&destination));

    if copied.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    copied.map(|()| true)
}

/// Removes a directory the SDK created.
pub fn cleanup_sdk_directory(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(
            Error::plugin_bootstrap(format!("Unable to remove {}", path.display()))
                .with_source(error),
        ),
    }
}

/// Finds the `codex` executable.
///
/// Upstream resolves a binary vendored inside the `@openai/codex` npm package.
/// This port has no npm package to look inside, so `codex` is resolved from
/// `PATH` — through the trusted executable search, so a `codex` committed to the
/// repository under scan is never selected.
pub fn resolve_codex_command(
    environment: &ProcessEnvironment,
    protected_root: &Path,
) -> Result<CodexCommand> {
    let resolved =
        resolve_trusted_executable("codex", environment, protected_root).ok_or_else(|| {
            Error::plugin_bootstrap(
                "The codex executable was not found on a trusted PATH. Install Codex, or put \
                 it on PATH outside the repository being scanned.",
            )
        })?;
    Ok(CodexCommand {
        command: resolved.executable,
        prefix_args: Vec::new(),
    })
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::plugin_bootstrap(format!("Unable to create {}", path.display())).with_source(error)
    })
}

fn set_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                Error::plugin_bootstrap(format!("Unable to secure {}", path.display()))
                    .with_source(error)
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                Error::plugin_bootstrap("Unable to copy ambient Codex authentication.")
                    .with_source(error)
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Copies `source` to a file that must not already exist, owner-readable only.
fn copy_private_file(source: &Path, destination: &Path) -> Result<()> {
    let failed = || Error::plugin_bootstrap("Unable to copy ambient Codex authentication.");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut input = std::fs::File::open(source).map_err(|error| failed().with_source(error))?;
    let mut output = options
        .open(destination)
        .map_err(|error| failed().with_source(error))?;
    std::io::copy(&mut input, &mut output).map_err(|error| failed().with_source(error))?;
    set_private_file(destination)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn environment() -> ProcessEnvironment {
        ProcessEnvironment::new()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn creates_a_private_isolated_home() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");

        let home = create_isolated_home(&base, None).expect("created");

        assert!(home.is_dir());
        assert!(
            home.file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with("openai-codex-security-home-")
        );
        assert_eq!(mode_of(&home), 0o700, "the isolated home must be private");
    }

    #[test]
    fn removes_an_isolated_home_the_location_check_refuses() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let refuse = |_: &Path| -> Result<()> { Err(Error::output_directory("refused")) };

        let error = create_isolated_home(&base, Some(&refuse)).expect_err("refused");

        assert_eq!(error.to_string(), "refused");
        let leftovers = std::fs::read_dir(&base).expect("read").count();
        assert_eq!(leftovers, 0, "the rejected home is removed");
    }

    #[test]
    fn imports_ambient_credentials() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let ambient = base.join("ambient");
        std::fs::create_dir(&ambient).expect("create ambient home");
        std::fs::write(ambient.join("auth.json"), b"{\"token\":\"secret\"}\n").expect("write");
        let isolated = base.join("isolated");

        let imported = import_ambient_auth(&ambient.to_string_lossy(), &isolated, &environment())
            .expect("imports");

        assert!(imported);
        let copied = isolated.join("auth.json");
        assert_eq!(
            std::fs::read_to_string(&copied).expect("read"),
            "{\"token\":\"secret\"}\n"
        );
        // Credentials must not be readable by anyone else.
        assert_eq!(mode_of(&copied), 0o600);
        assert_eq!(mode_of(&isolated), 0o700);
    }

    // No ambient credentials is an ordinary outcome, not a failure.
    #[test]
    fn reports_no_credentials_when_there_are_none() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let ambient = base.join("ambient");
        std::fs::create_dir(&ambient).expect("create ambient home");
        let isolated = base.join("isolated");

        let imported = import_ambient_auth(&ambient.to_string_lossy(), &isolated, &environment())
            .expect("no credentials is fine");

        assert!(!imported);
        assert!(
            !isolated.exists(),
            "nothing is created when there is nothing to copy"
        );
    }

    #[test]
    fn ignores_a_credentials_path_that_is_not_a_file() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let ambient = base.join("ambient");
        std::fs::create_dir_all(ambient.join("auth.json")).expect("create a directory instead");
        let isolated = base.join("isolated");

        let imported = import_ambient_auth(&ambient.to_string_lossy(), &isolated, &environment())
            .expect("a directory is not credentials");

        assert!(!imported);
    }

    #[test]
    fn expands_a_home_relative_ambient_home() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".codex")).expect("create");
        std::fs::write(home.join(".codex").join("auth.json"), b"{}\n").expect("write");
        let environment =
            ProcessEnvironment::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
        let isolated = base.join("isolated");

        let imported = import_ambient_auth("~/.codex", &isolated, &environment).expect("imports");

        assert!(imported);
        assert!(isolated.join("auth.json").is_file());
    }

    #[test]
    fn removes_a_directory_and_tolerates_a_missing_one() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let directory = base.join("sdk");
        std::fs::create_dir_all(directory.join("nested")).expect("create");
        std::fs::write(directory.join("nested").join("file.txt"), b"x").expect("write");

        cleanup_sdk_directory(&directory).expect("removes");
        assert!(!directory.exists());

        cleanup_sdk_directory(&base.join("absent")).expect("a missing directory is fine");
    }

    #[test]
    fn resolves_the_codex_executable_from_path() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let bin = base.join("bin");
        std::fs::create_dir(&bin).expect("create bin");
        let codex = bin.join("codex");
        std::fs::write(&codex, "#!/bin/sh\ntrue\n").expect("write");
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let repository = base.join("repository");
        std::fs::create_dir(&repository).expect("create repository");
        let environment =
            ProcessEnvironment::from([("PATH".to_owned(), bin.to_string_lossy().into_owned())]);

        let resolved = resolve_codex_command(&environment, &repository).expect("resolves");

        assert_eq!(
            resolved.command,
            std::fs::canonicalize(&codex).expect("canonical")
        );
        assert!(resolved.prefix_args.is_empty());
    }

    // A codex committed to the repository under scan must never be run.
    #[test]
    fn refuses_a_codex_inside_the_repository() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let repository = base.join("repository");
        let hostile = repository.join("bin");
        std::fs::create_dir_all(&hostile).expect("create");
        let codex = hostile.join("codex");
        std::fs::write(&codex, "#!/bin/sh\ntrue\n").expect("write");
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let environment =
            ProcessEnvironment::from([("PATH".to_owned(), hostile.to_string_lossy().into_owned())]);

        let error = resolve_codex_command(&environment, &repository)
            .expect_err("a repository codex is refused");

        assert!(
            error.to_string().contains("not found on a trusted PATH"),
            "{error}"
        );
        assert!(error.is_plugin_bootstrap());
    }
}
