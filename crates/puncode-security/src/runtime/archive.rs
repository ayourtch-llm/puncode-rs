//! Refusing a plugin archive before anything is extracted from it.
//!
//! Ported from `rejectBackslashZipNames` in `src/runtime.ts`.
//!
//! The archive's central directory is parsed here by hand rather than through
//! the extraction library. Two reasons:
//!
//! * A member name containing a backslash means different things on different
//!   platforms, and a library may normalize it before anyone can object —
//!   `a\..\..\evil` is one path component on Unix and three on Windows. Reading
//!   the raw bytes is the only way to refuse it consistently.
//! * The entry count and central directory size are bounded before any
//!   allocation, so a crafted archive cannot turn a header into large work.

#![allow(dead_code)]

use std::path::Path;

use crate::error::{Error, Result};

/// Members a plugin archive may declare.
const MAX_ZIP_ENTRIES: u16 = 4_096;

/// How large the central directory itself may be.
const MAX_ZIP_CENTRAL_DIRECTORY: u32 = 16 * 1024 * 1024;

/// The end-of-central-directory record, and the largest tail it can live in:
/// 22 fixed bytes plus a comment of up to `u16::MAX`.
const EOCD_SIZE: usize = 22;
const MAX_EOCD_SEARCH: usize = 65_557;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_HEADER_SIZE: usize = 46;

/// Rejects an archive whose central directory is malformed, oversized, or names
/// a member with a backslash in it.
pub(crate) fn reject_backslash_zip_names(archive_path: &Path) -> Result<()> {
    let invalid =
        || Error::plugin_bootstrap(format!("Invalid plugin ZIP: {}", archive_path.display()));

    let bytes = std::fs::read(archive_path).map_err(|error| invalid().with_source(error))?;
    if bytes.len() < EOCD_SIZE {
        return Err(invalid());
    }

    let tail_size = bytes.len().min(MAX_EOCD_SEARCH);
    let tail = &bytes[bytes.len() - tail_size..];

    // The record is found from the end, and only accepted where the declared
    // comment length exactly reaches the end of the file.
    let mut end = None;
    for candidate in (0..=tail.len() - EOCD_SIZE).rev() {
        if read_u32(tail, candidate) == Some(EOCD_SIGNATURE)
            && read_u16(tail, candidate + 20)
                .is_some_and(|comment| candidate + EOCD_SIZE + usize::from(comment) == tail.len())
        {
            end = Some(candidate);
            break;
        }
    }
    let Some(end) = end else {
        return Err(invalid());
    };

    let (Some(entries), Some(central_size), Some(central_offset)) = (
        read_u16(tail, end + 10),
        read_u32(tail, end + 12),
        read_u32(tail, end + 16),
    ) else {
        return Err(invalid());
    };

    // These sentinels mean the real values live in a ZIP64 record, which this
    // archive format is not expected to use.
    if entries == 0xffff || central_size == 0xffff_ffff || central_offset == 0xffff_ffff {
        return Err(invalid());
    }
    if entries > MAX_ZIP_ENTRIES {
        return Err(Error::plugin_bootstrap(format!(
            "Plugin ZIP contains too many entries: {entries}."
        )));
    }
    if central_size > MAX_ZIP_CENTRAL_DIRECTORY {
        return Err(Error::plugin_bootstrap(
            "Plugin ZIP central directory exceeds the safety limit.",
        ));
    }

    let end_offset = bytes.len() - tail_size + end;
    let central_start = usize::try_from(central_offset).map_err(|_| invalid())?;
    let central_length = usize::try_from(central_size).map_err(|_| invalid())?;
    if central_start
        .checked_add(central_length)
        .is_none_or(|finish| finish > end_offset)
    {
        return Err(invalid());
    }
    let central = &bytes[central_start..central_start + central_length];

    let mut offset = 0_usize;
    for _ in 0..entries {
        if offset + CENTRAL_HEADER_SIZE > central.len()
            || read_u32(central, offset) != Some(CENTRAL_HEADER_SIGNATURE)
        {
            return Err(invalid());
        }
        let (Some(name_length), Some(extra_length), Some(comment_length)) = (
            read_u16(central, offset + 28),
            read_u16(central, offset + 30),
            read_u16(central, offset + 32),
        ) else {
            return Err(invalid());
        };

        let name_start = offset + CENTRAL_HEADER_SIZE;
        let Some(name_end) = name_start.checked_add(usize::from(name_length)) else {
            return Err(invalid());
        };
        if name_end > central.len() {
            return Err(invalid());
        }
        if central[name_start..name_end].contains(&b'\\') {
            return Err(Error::plugin_bootstrap(
                "Plugin ZIP contains a backslash-qualified path.",
            ));
        }

        offset = name_end + usize::from(extra_length) + usize::from(comment_length);
    }
    // The walk must land exactly on the end, or the directory disagrees with
    // its own declared size.
    if offset != central.len() {
        return Err(invalid());
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    /// Writes an archive containing `names`, returning its path.
    fn archive(root: &Path, names: &[&str]) -> std::path::PathBuf {
        let path = root.join("plugin.zip");
        let file = std::fs::File::create(&path).expect("create archive");
        let mut writer = zip::ZipWriter::new(file);
        for name in names {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .expect("start entry");
            writer.write_all(b"contents\n").expect("write entry");
        }
        writer.finish().expect("finish archive");
        path
    }

    fn error_of(path: &Path) -> String {
        reject_backslash_zip_names(path)
            .expect_err("should be refused")
            .to_string()
    }

    #[test]
    fn accepts_an_ordinary_archive() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(
            root.path(),
            &[".codex-plugin/plugin.json", "schemas/a.json"],
        );

        reject_backslash_zip_names(&path).expect("an ordinary archive is accepted");
    }

    #[test]
    fn accepts_an_archive_with_a_comment() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().join("plugin.zip");
        let file = std::fs::File::create(&path).expect("create");
        let mut writer = zip::ZipWriter::new(file);
        writer.set_comment("a trailing comment");
        writer
            .start_file("a.txt", SimpleFileOptions::default())
            .expect("start entry");
        writer.write_all(b"x").expect("write");
        writer.finish().expect("finish");

        reject_backslash_zip_names(&path).expect("a comment does not hide the record");
    }

    // The reason this parser exists: a backslash name is one component on Unix
    // and several on Windows, so it must be refused before extraction.
    #[test]
    fn rejects_a_backslash_qualified_name() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["ok.txt", r"a\..\..\evil.txt"]);

        assert_eq!(
            error_of(&path),
            "Plugin ZIP contains a backslash-qualified path."
        );
    }

    #[test]
    fn rejects_a_backslash_in_any_position() {
        let root = TempDir::new().expect("temp dir");
        for name in [r"\absolute.txt", r"dir\file.txt", r"trailing\"] {
            let path = archive(root.path(), &[name]);
            assert_eq!(
                error_of(&path),
                "Plugin ZIP contains a backslash-qualified path.",
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_a_file_that_is_not_an_archive() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().join("plugin.zip");
        std::fs::write(&path, b"not a zip file at all, but long enough to look at").expect("write");

        assert!(error_of(&path).starts_with("Invalid plugin ZIP:"));
    }

    #[test]
    fn rejects_a_file_too_short_to_hold_a_record() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().join("plugin.zip");
        std::fs::write(&path, b"tiny").expect("write");

        assert!(error_of(&path).starts_with("Invalid plugin ZIP:"));
    }

    #[test]
    fn rejects_a_missing_archive() {
        let root = TempDir::new().expect("temp dir");

        assert!(error_of(&root.path().join("absent.zip")).starts_with("Invalid plugin ZIP:"));
    }

    /// Rewrites a little-endian value inside the archive's tail.
    fn patch_u16(bytes: &mut [u8], eocd: usize, field: usize, value: u16) {
        bytes[eocd + field..eocd + field + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn eocd_offset(bytes: &[u8]) -> usize {
        (0..=bytes.len() - EOCD_SIZE)
            .rev()
            .find(|candidate| read_u32(bytes, *candidate) == Some(EOCD_SIGNATURE))
            .expect("archive has an end record")
    }

    // A header claiming more entries than the limit is refused without reading
    // them.
    #[test]
    fn rejects_a_declared_entry_count_beyond_the_limit() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["a.txt"]);
        let mut bytes = std::fs::read(&path).expect("read");
        let eocd = eocd_offset(&bytes);
        patch_u16(&mut bytes, eocd, 10, MAX_ZIP_ENTRIES + 1);
        std::fs::write(&path, &bytes).expect("write");

        assert_eq!(
            error_of(&path),
            format!(
                "Plugin ZIP contains too many entries: {}.",
                MAX_ZIP_ENTRIES + 1
            )
        );
    }

    #[test]
    fn rejects_a_zip64_archive() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["a.txt"]);
        let mut bytes = std::fs::read(&path).expect("read");
        let eocd = eocd_offset(&bytes);
        patch_u16(&mut bytes, eocd, 10, 0xffff);
        std::fs::write(&path, &bytes).expect("write");

        assert!(error_of(&path).starts_with("Invalid plugin ZIP:"));
    }

    #[test]
    fn rejects_an_oversized_central_directory() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["a.txt"]);
        let mut bytes = std::fs::read(&path).expect("read");
        let eocd = eocd_offset(&bytes);
        bytes[eocd + 12..eocd + 16].copy_from_slice(&(MAX_ZIP_CENTRAL_DIRECTORY + 1).to_le_bytes());
        std::fs::write(&path, &bytes).expect("write");

        assert_eq!(
            error_of(&path),
            "Plugin ZIP central directory exceeds the safety limit."
        );
    }

    // A directory pointing past its own record would otherwise read whatever
    // happens to follow.
    #[test]
    fn rejects_central_directory_bounds_outside_the_record() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["a.txt"]);
        let mut bytes = std::fs::read(&path).expect("read");
        let eocd = eocd_offset(&bytes);
        let inflated = u32::try_from(bytes.len()).expect("size fits");
        bytes[eocd + 12..eocd + 16].copy_from_slice(&inflated.to_le_bytes());
        std::fs::write(&path, &bytes).expect("write");

        assert!(error_of(&path).starts_with("Invalid plugin ZIP:"));
    }

    #[test]
    fn rejects_a_directory_that_disagrees_with_its_declared_entry_count() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &["a.txt", "b.txt"]);
        let mut bytes = std::fs::read(&path).expect("read");
        let eocd = eocd_offset(&bytes);
        // One fewer entry than the directory actually holds.
        patch_u16(&mut bytes, eocd, 10, 1);
        std::fs::write(&path, &bytes).expect("write");

        assert!(error_of(&path).starts_with("Invalid plugin ZIP:"));
    }

    #[test]
    fn accepts_an_empty_archive() {
        let root = TempDir::new().expect("temp dir");
        let path = archive(root.path(), &[]);

        reject_backslash_zip_names(&path).expect("an empty archive has a valid record");
    }
}
