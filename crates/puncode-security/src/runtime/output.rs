//! Deciding whether a directory may receive scan output.
//!
//! Ported from the output-directory half of `src/runtime.ts`.
//!
//! Scan output contains source excerpts, reproduction steps, and vulnerability
//! detail, so where it lands matters as much as what it says. A directory is
//! only acceptable if it is a real directory the current user owns, no other
//! user can read, and whose path cannot be used to mislead the model reading it
//! back.

#![allow(dead_code)]

use std::fs::Metadata;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::targets::{ProcessEnvironment, expand_home, lexical_absolute};

/// Characters that would let a path forge line structure or terminal control
/// in text the model reads back: C0 and C1 control ranges, plus the Unicode
/// line and paragraph separators.
fn is_model_unsafe(character: char) -> bool {
    matches!(character, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}')
}

/// Refuses a path that could distort the text a model later reads.
pub(crate) fn require_model_safe_output_dir(path: &str) -> Result<()> {
    if path.chars().any(is_model_unsafe) {
        return Err(Error::output_directory(
            "Scan output directory must not contain control or line-separator characters.",
        ));
    }
    Ok(())
}

/// Refuses a directory other users can reach, or that the current user does not
/// own.
pub(crate) fn require_private_output_directory(
    metadata: &Metadata,
    path: &Path,
    effective_uid: Option<u32>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(Error::output_directory(format!(
                "Scan output directory must not be accessible to other users (chmod 700): {}",
                path.display()
            )));
        }
        if let Some(effective_uid) = effective_uid
            && metadata.uid() != effective_uid
        {
            return Err(Error::output_directory(format!(
                "Scan output directory must be owned by the current user: {}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, path, effective_uid);
    }
    Ok(())
}

/// The current effective user, where the platform has one.
pub(crate) fn effective_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(rustix::process::geteuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Resolves where scan output would go, without creating anything.
///
/// Returns `None` when no directory was requested, meaning a temporary one
/// should be made instead. When the directory does not exist yet, the nearest
/// existing ancestor is resolved so the answer is still canonical.
///
/// This answers "would this be accepted?" without the side effects of
/// [`prepare_output_dir`], so a caller can check a destination before
/// committing to it.
pub fn validate_output_dir(
    output_directory: Option<&str>,
    archive_existing: bool,
    environment: &ProcessEnvironment,
) -> Result<Option<PathBuf>> {
    let Some(output_directory) = output_directory else {
        return Ok(None);
    };
    require_model_safe_output_dir(output_directory)?;
    let path = lexical_absolute(&expand_home(output_directory, environment));

    let uninspectable = || {
        Error::output_directory(format!(
            "Unable to inspect scan output directory: {output_directory}"
        ))
    };

    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.is_symlink() {
                return Err(Error::output_directory(format!(
                    "Scan output is not a directory: {}",
                    path.display()
                )));
            }
            if !archive_existing {
                let mut entries = std::fs::read_dir(&path).map_err(|_| uninspectable())?;
                if entries.next().is_some() {
                    return Err(Error::output_directory(format!(
                        "Scan output directory is not empty: {}. To keep the existing results \
                         and start a new scan, add --archive-existing.",
                        path.display()
                    )));
                }
            }
            require_private_output_directory(&metadata, &path, effective_uid())?;
            let canonical = std::fs::canonicalize(&path).map_err(|_| uninspectable())?;
            require_model_safe_output_dir(&canonical.to_string_lossy())?;
            Ok(Some(canonical))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Resolve through the nearest existing ancestor so the answer is
            // canonical even though the directory is not there yet.
            let mut parent = path.parent().map(Path::to_path_buf);
            while let Some(current) = parent {
                if let Ok(metadata) = std::fs::metadata(&current)
                    && metadata.is_dir()
                {
                    let canonical_parent =
                        std::fs::canonicalize(&current).map_err(|_| uninspectable())?;
                    let relative = path.strip_prefix(&current).map_err(|_| uninspectable())?;
                    let canonical = canonical_parent.join(relative);
                    require_model_safe_output_dir(&canonical.to_string_lossy())?;
                    return Ok(Some(canonical));
                }
                let next = current.parent().map(Path::to_path_buf);
                if next.as_deref() == Some(current.as_path()) {
                    break;
                }
                parent = next;
            }
            Err(Error::output_directory(format!(
                "Unable to create scan output directory: {}",
                path.display()
            )))
        }
        Err(_) => Err(uninspectable()),
    }
}

/// A caller's check that output is landing somewhere acceptable, such as
/// outside the repository being scanned.
pub type LocationCheck<'a> = &'a dyn Fn(&Path) -> Result<()>;

/// Confirms a directory that has just been prepared is still fit to write into.
pub(crate) fn validate_prepared_output_dir(
    path: &Path,
    validate_location: Option<LocationCheck<'_>>,
) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::output_directory(format!(
            "Scan output is not a directory: {}",
            path.display()
        ))
        .with_source(error)
    })?;
    if !metadata.is_dir() || metadata.is_symlink() {
        return Err(Error::output_directory(format!(
            "Scan output is not a directory: {}",
            path.display()
        )));
    }

    let canonical = std::fs::canonicalize(path).map_err(|error| {
        Error::output_directory(format!(
            "Unable to inspect scan output directory: {}",
            path.display()
        ))
        .with_source(error)
    })?;
    require_model_safe_output_dir(&canonical.to_string_lossy())?;
    if let Some(validate_location) = validate_location {
        validate_location(&canonical)?;
    }

    let mut entries = std::fs::read_dir(&canonical).map_err(|error| {
        Error::output_directory(format!(
            "Unable to inspect scan output directory: {}",
            path.display()
        ))
        .with_source(error)
    })?;
    if entries.next().is_some() {
        return Err(Error::output_directory(format!(
            "Scan output directory must be empty: {}",
            path.display()
        )));
    }
    require_private_output_directory(&metadata, path, effective_uid())?;
    Ok(canonical)
}

/// A caller notified when existing output is moved aside.
pub(crate) type ArchiveNotice<'a> = &'a dyn Fn(&Path);

/// What to prepare, and what must be true of where it lands.
pub struct PrepareOutputOptions<'a> {
    /// The directory the caller asked for; `None` makes a temporary one.
    pub output_directory: Option<&'a str>,
    /// Used to name a temporary directory recognizably.
    pub repository_name: &'a str,
    pub temporary_root: PathBuf,
    pub validate_location: Option<LocationCheck<'a>>,
    /// Move existing output aside rather than refusing to overwrite it.
    pub archive_existing: bool,
    pub on_output_archived: Option<ArchiveNotice<'a>>,
    pub environment: &'a ProcessEnvironment,
}

impl<'a> PrepareOutputOptions<'a> {
    #[must_use]
    pub fn new(repository_name: &'a str, environment: &'a ProcessEnvironment) -> Self {
        Self {
            output_directory: None,
            repository_name,
            temporary_root: std::env::temp_dir(),
            validate_location: None,
            archive_existing: false,
            on_output_archived: None,
            environment,
        }
    }
}

/// Creates the directory a scan will write into, and returns its canonical path.
///
/// The directory is always created private to the current user. Upstream reads
/// the process umask and only adjusts the mode when it would matter; POSIX has
/// no race-free way to read a umask (it must be set to be read), so the mode is
/// set unconditionally here instead. The resulting permissions are the same.
pub fn prepare_output_dir(options: &PrepareOutputOptions<'_>) -> Result<PathBuf> {
    if options.output_directory.is_none() {
        require_model_safe_output_dir(&options.temporary_root.to_string_lossy())?;
        let canonical = std::fs::canonicalize(&options.temporary_root).map_err(|error| {
            Error::output_directory(format!(
                "Unable to inspect scan output directory: {}",
                options.temporary_root.display()
            ))
            .with_source(error)
        })?;
        require_model_safe_output_dir(&canonical.to_string_lossy())?;
    }

    let path = validate_output_dir(
        options.output_directory,
        options.archive_existing,
        options.environment,
    )?;

    if let Some(validate_location) = options.validate_location {
        let subject = match &path {
            Some(path) => path.clone(),
            None => std::fs::canonicalize(&options.temporary_root)
                .unwrap_or_else(|_| options.temporary_root.clone()),
        };
        validate_location(&subject)?;
    }

    let Some(path) = path else {
        let created = tempfile::Builder::new()
            .prefix(&format!(
                "puncode-security-{}-",
                safe_prefix(options.repository_name)
            ))
            .tempdir_in(&options.temporary_root)
            .map_err(|error| {
                Error::output_directory("Unable to create scan output directory.")
                    .with_source(error)
            })?
            .keep();
        set_private(&created)?;
        return match validate_prepared_output_dir(&created, options.validate_location) {
            Ok(canonical) => Ok(canonical),
            Err(error) => {
                let _ = std::fs::remove_dir(&created);
                Err(error)
            }
        };
    };

    let mut created_root: Option<PathBuf> = None;
    let outcome = (|| -> Result<PathBuf> {
        let mut existing = std::fs::symlink_metadata(&path).ok();
        if existing.is_some()
            && options.archive_existing
            && let Some(archive_dir) = plan_output_archive(&path)?
        {
            std::fs::rename(&path, &archive_dir).map_err(|error| {
                Error::output_directory(format!(
                    "Unable to archive existing scan output: {}",
                    path.display()
                ))
                .with_source(error)
            })?;
            if let Some(notify) = options.on_output_archived {
                notify(&archive_dir);
            }
            existing = None;
        }
        if existing.is_none() {
            created_root = Some(shallowest_missing_ancestor(&path));
            std::fs::create_dir_all(&path).map_err(|error| {
                Error::output_directory(format!(
                    "Unable to create scan output directory: {}",
                    path.display()
                ))
                .with_source(error)
            })?;
            set_private(&path)?;
        }
        validate_prepared_output_dir(&path, options.validate_location)
    })();

    if outcome.is_err()
        && let Some(root) = created_root
    {
        remove_empty_directories(&path, &root);
    }
    outcome
}

/// Where existing output would be moved to, or `None` if there is nothing to
/// move.
pub(crate) fn plan_output_archive(output_directory: &Path) -> Result<Option<PathBuf>> {
    match std::fs::read_dir(output_directory) {
        Ok(mut entries) => {
            if entries.next().is_none() {
                return Ok(None);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::output_directory(format!(
                "Unable to inspect scan output directory: {}",
                output_directory.display()
            ))
            .with_source(error));
        }
    }

    let mut name = output_directory.as_os_str().to_os_string();
    name.push(format!(".previous-{}-{}", utc_stamp(), unique_suffix()));
    Ok(Some(PathBuf::from(name)))
}

/// A recognizable, filesystem-safe form of a repository name.
pub(crate) fn safe_prefix(value: &str) -> String {
    // `basename` yields an empty string for a bare separator, which falls
    // through to the default below; taking the whole value instead would
    // produce a name made entirely of replacement characters.
    let base = Path::new(value)
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let cleaned: String = base
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "repository".to_owned()
    } else {
        cleaned
    }
}

fn set_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                Error::output_directory(format!(
                    "Unable to secure scan output directory: {}",
                    path.display()
                ))
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

/// The highest ancestor that does not exist yet, so only directories this call
/// created are removed on failure.
fn shallowest_missing_ancestor(path: &Path) -> PathBuf {
    let mut shallowest = path.to_path_buf();
    let mut current = path;
    while let Some(parent) = current.parent() {
        if parent.exists() {
            break;
        }
        shallowest = parent.to_path_buf();
        current = parent;
    }
    shallowest
}

/// Removes `path` and its now-empty ancestors, up to and including `root`.
fn remove_empty_directories(path: &Path, root: &Path) {
    let mut current = path.to_path_buf();
    loop {
        if std::fs::remove_dir(&current).is_err() {
            return;
        }
        if current == root {
            return;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return,
        }
    }
}

/// `YYYYMMDDTHHMMSS` in UTC, matching the shape upstream derives from an ISO
/// timestamp.
fn utc_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let time_of_day = seconds % 86_400;
    let (year, month, day) = crate::contract::datetime::civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
}

/// A short suffix distinguishing archives made in the same second.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let digest =
        crate::contract::files::sha256_text(&format!("{nanos}-{}-{sequence}", std::process::id()));
    digest[..8].to_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn environment() -> ProcessEnvironment {
        ProcessEnvironment::new()
    }

    fn private_dir(parent: &Path, name: &str) -> PathBuf {
        let path = parent.join(name);
        std::fs::create_dir_all(&path).expect("create directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        path
    }

    #[test]
    fn returns_nothing_when_no_directory_is_requested() {
        assert_eq!(
            validate_output_dir(None, false, &environment()).expect("ok"),
            None
        );
    }

    #[test]
    fn accepts_an_empty_private_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");

        let resolved = validate_output_dir(Some(&output.to_string_lossy()), false, &environment())
            .expect("accepted");

        assert_eq!(resolved, Some(output));
    }

    // Scan output carries vulnerability detail; a world-readable directory
    // would publish it.
    #[test]
    fn refuses_a_directory_other_users_can_read() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let error = validate_output_dir(Some(&output.to_string_lossy()), false, &environment())
            .expect_err("a readable directory is refused");

        assert!(
            error
                .to_string()
                .contains("must not be accessible to other users (chmod 700)"),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_non_empty_directory_without_archiving() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        std::fs::write(output.join("existing.txt"), b"prior results\n").expect("write");

        let error = validate_output_dir(Some(&output.to_string_lossy()), false, &environment())
            .expect_err("a non-empty directory is refused");

        assert!(error.to_string().contains("is not empty"), "{error}");
        assert!(error.to_string().contains("--archive-existing"), "{error}");
    }

    #[test]
    fn accepts_a_non_empty_directory_when_archiving() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        std::fs::write(output.join("existing.txt"), b"prior results\n").expect("write");

        assert!(validate_output_dir(Some(&output.to_string_lossy()), true, &environment()).is_ok());
    }

    #[test]
    fn refuses_a_file_or_symlink_where_a_directory_is_expected() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let file = base.join("results");
        std::fs::write(&file, b"not a directory\n").expect("write");

        let error = validate_output_dir(Some(&file.to_string_lossy()), false, &environment())
            .expect_err("a file is refused");
        assert!(
            error.to_string().contains("Scan output is not a directory"),
            "{error}"
        );

        let target = private_dir(&base, "actual");
        let link = base.join("linked");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error = validate_output_dir(Some(&link.to_string_lossy()), false, &environment())
            .expect_err("a symlink is refused");
        assert!(
            error.to_string().contains("Scan output is not a directory"),
            "{error}"
        );
    }

    // A directory that does not exist yet still resolves, through its nearest
    // existing ancestor, so the answer is canonical.
    #[test]
    fn resolves_a_directory_that_does_not_exist_yet() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let requested = base.join("a").join("b").join("results");

        let resolved =
            validate_output_dir(Some(&requested.to_string_lossy()), false, &environment())
                .expect("accepted");

        assert_eq!(resolved, Some(requested));
    }

    #[test]
    fn resolves_a_pending_directory_through_a_symlinked_ancestor() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let actual = private_dir(&base, "actual");
        let linked = base.join("linked");
        std::os::unix::fs::symlink(&actual, &linked).expect("symlink");

        let resolved = validate_output_dir(
            Some(&linked.join("results").to_string_lossy()),
            false,
            &environment(),
        )
        .expect("accepted");

        assert_eq!(
            resolved,
            Some(actual.join("results")),
            "resolved through the link"
        );
    }

    #[test]
    fn refuses_control_characters_in_the_path() {
        for path in [
            "/tmp/out\u{1}put",
            "/tmp/out\u{2028}put",
            "/tmp/out\u{7f}put",
            "/tmp/o\u{9f}ut",
        ] {
            let error = validate_output_dir(Some(path), false, &environment())
                .expect_err("control characters are refused");
            assert_eq!(
                error.to_string(),
                "Scan output directory must not contain control or line-separator characters."
            );
        }
        assert!(require_model_safe_output_dir("/tmp/ordinary-path").is_ok());
    }

    #[test]
    fn expands_a_home_relative_output_directory() {
        let root = TempDir::new().expect("temp dir");
        let home = std::fs::canonicalize(root.path()).expect("canonical");
        private_dir(&home, "results");
        let environment =
            ProcessEnvironment::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);

        let resolved =
            validate_output_dir(Some("~/results"), false, &environment).expect("accepted");

        assert_eq!(resolved, Some(home.join("results")));
    }

    #[test]
    fn validates_a_prepared_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");

        let canonical = validate_prepared_output_dir(&output, None).expect("prepared");

        assert_eq!(canonical, output);
    }

    #[test]
    fn refuses_a_prepared_directory_that_is_not_empty() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        std::fs::write(output.join("stray.txt"), b"x").expect("write");

        let error = validate_prepared_output_dir(&output, None)
            .expect_err("a non-empty prepared directory is refused");

        assert!(error.to_string().contains("must be empty"), "{error}");
    }

    // The location hook is how a caller keeps output out of the repository
    // being scanned.
    #[test]
    fn applies_the_location_check_to_a_prepared_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        let refuse = |path: &Path| -> Result<()> {
            Err(Error::output_inside_protected_root(
                path,
                "/protected",
                crate::error::ProtectedScanPathKind::Output,
            ))
        };

        let error = validate_prepared_output_dir(&output, Some(&refuse))
            .expect_err("the location check is applied");

        assert!(error.is_output_inside_protected_root(), "{error}");
    }

    // A file ancestor yields ENOTDIR rather than ENOENT, so this is reported
    // as an inspection failure rather than a creation failure.
    #[test]
    fn reports_an_unusable_path() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let file = base.join("file");
        std::fs::write(&file, b"x").expect("write");

        // A file cannot be an ancestor directory of the requested output.
        let error = validate_output_dir(
            Some(&file.join("results").to_string_lossy()),
            false,
            &environment(),
        )
        .expect_err("a file ancestor is refused");

        assert!(
            error
                .to_string()
                .contains("Unable to inspect scan output directory"),
            "{error}"
        );
    }

    // --- preparation ---

    fn prepare_options<'a>(
        environment: &'a ProcessEnvironment,
        temporary_root: &Path,
    ) -> PrepareOutputOptions<'a> {
        let mut options = PrepareOutputOptions::new("example/repo", environment);
        options.temporary_root = temporary_root.to_path_buf();
        options
    }

    #[test]
    fn creates_a_private_temporary_directory_when_none_is_requested() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let environment = environment();

        let created = prepare_output_dir(&prepare_options(&environment, &base)).expect("prepared");

        assert!(created.is_dir());
        assert!(created.starts_with(&base));
        let name = created
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("puncode-security-repo-"), "{name}");
        let mode = std::fs::metadata(&created)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "temporary output must be private");
    }

    #[test]
    fn creates_a_requested_directory_with_private_permissions() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let environment = environment();
        let requested = base.join("nested").join("results");
        let mut options = prepare_options(&environment, &base);
        let requested_text = requested.to_string_lossy().into_owned();
        options.output_directory = Some(&requested_text);

        let created = prepare_output_dir(&options).expect("prepared");

        assert_eq!(created, requested);
        let mode = std::fs::metadata(&created)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    // A failed preparation must not leave the directories it created behind.
    #[test]
    fn removes_directories_it_created_when_preparation_fails() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let environment = environment();
        let requested = base.join("a").join("b").join("results");
        let requested_text = requested.to_string_lossy().into_owned();
        let refuse = |_: &Path| -> Result<()> { Err(Error::output_directory("refused")) };
        let mut options = prepare_options(&environment, &base);
        options.output_directory = Some(&requested_text);
        options.validate_location = Some(&refuse);

        let error = prepare_output_dir(&options).expect_err("the location check refuses");

        assert_eq!(error.to_string(), "refused");
        assert!(!base.join("a").exists(), "created directories are removed");
    }

    #[test]
    fn archives_existing_output_when_asked() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let environment = environment();
        let output = private_dir(&base, "results");
        std::fs::write(output.join("prior.txt"), b"prior results\n").expect("write");
        let output_text = output.to_string_lossy().into_owned();

        let archived = std::cell::RefCell::new(Vec::new());
        let notice = |path: &Path| archived.borrow_mut().push(path.to_path_buf());
        let mut options = prepare_options(&environment, &base);
        options.output_directory = Some(&output_text);
        options.archive_existing = true;
        options.on_output_archived = Some(&notice);

        let prepared = prepare_output_dir(&options).expect("prepared");

        assert_eq!(prepared, output);
        assert!(
            std::fs::read_dir(&prepared).expect("read").next().is_none(),
            "fresh directory"
        );
        let archived = archived.into_inner();
        assert_eq!(archived.len(), 1, "the caller is told where output went");
        assert!(
            archived[0].join("prior.txt").is_file(),
            "prior results are kept"
        );
        let name = archived[0]
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("results.previous-"), "{name}");
    }

    #[test]
    fn does_not_archive_an_empty_directory() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");

        assert_eq!(plan_output_archive(&output).expect("planned"), None);
        assert_eq!(
            plan_output_archive(&base.join("absent")).expect("planned"),
            None
        );
    }

    #[test]
    fn plans_a_distinct_archive_name_each_time() {
        let root = TempDir::new().expect("temp dir");
        let base = std::fs::canonicalize(root.path()).expect("canonical");
        let output = private_dir(&base, "results");
        std::fs::write(output.join("prior.txt"), b"x").expect("write");

        let first = plan_output_archive(&output)
            .expect("planned")
            .expect("some");
        let second = plan_output_archive(&output)
            .expect("planned")
            .expect("some");

        assert_ne!(
            first, second,
            "archives made in the same second must not collide"
        );
    }

    #[test]
    fn names_temporary_directories_after_the_repository() {
        assert_eq!(safe_prefix("/src/example/repo"), "repo");
        assert_eq!(safe_prefix("my repo!"), "my-repo-");
        assert_eq!(safe_prefix("ok.name_1-2"), "ok.name_1-2");
        assert_eq!(safe_prefix(""), "repository");
        assert_eq!(safe_prefix("/"), "repository");
    }

    #[test]
    fn stamps_archives_with_a_sortable_utc_time() {
        let stamp = utc_stamp();

        assert_eq!(stamp.len(), 15, "{stamp}");
        assert_eq!(&stamp[8..9], "T", "{stamp}");
        assert!(
            stamp.chars().filter(char::is_ascii_digit).count() == 14,
            "{stamp}"
        );
        assert!(stamp.starts_with("20"), "{stamp}");
    }
}
