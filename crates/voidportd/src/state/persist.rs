//! The temporary file is written in the same directory, so the rename is an
//! atomic replace on one filesystem, and the directory is synced after the
//! rename, so the rename survives a crash.
//!
//! The rename is the commit point. A failure after it means the write happened
//! and may not survive a crash, so it is reported as
//! [`PersistError::Committed`]. A caller that treated it like a failure before
//! the commit point would serve a document the file no longer contains.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::containing_directory;
use super::document::StateDocument;

pub const STATE_FILE_MODE: u32 = 0o600;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// # Errors
///
/// Returns a [`PersistError`] if the document cannot be rendered or any step
/// of the write fails. [`PersistError::NotCommitted`] leaves the state file
/// unchanged; [`PersistError::Committed`] means the rename succeeded and only the
/// directory flush failed.
pub fn persist(document: &StateDocument, path: &Path) -> Result<(), PersistError> {
    let text = document.to_toml().map_err(PersistError::Serialize)?;
    let directory = containing_directory(path).to_path_buf();
    let mode = existing_mode(path)?;
    let temporary = directory.join(temporary_name(path));

    match write_and_rename(&temporary, path, &directory, text.as_bytes(), mode) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Past the commit point the temporary is the state file now.
            if matches!(error, PersistError::NotCommitted { .. }) {
                let _ = fs::remove_file(&temporary);
            }
            Err(error)
        }
    }
}

/// A file that exists but cannot be read or parsed is left alone, so a typo'd
/// path can never shadow a real configuration. The probe is
/// [`fs::symlink_metadata`], because a dangling symbolic link is something on
/// the path.
///
/// Call this while holding the instance lock of the state file: two daemons
/// racing here would each create a file, and one would serve a document the
/// other replaced.
///
/// # Errors
///
/// Returns a [`PersistError`] if the path cannot be examined or the document
/// cannot be written. A missing parent directory is not created.
pub fn create_if_missing(path: &Path) -> Result<bool, PersistError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            persist(&StateDocument::default(), path)?;
            Ok(true)
        }
        Err(source) => Err(PersistError::not_committed(path, source)),
    }
}

/// The caller removes the temporary file on failure. The record sidecars are
/// written with the same sequence, so the directory flush exists once.
///
/// # Errors
///
/// Returns a [`PersistError`] naming the step that failed and which side of the
/// commit point it was on.
pub(crate) fn write_and_rename(
    temporary: &Path,
    path: &Path,
    directory: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), PersistError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(temporary)
        .map_err(|source| PersistError::not_committed(temporary, source))?;
    file.write_all(bytes)
        .map_err(|source| PersistError::not_committed(temporary, source))?;
    // The umask filters the mode `open` was given, so state it again.
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| PersistError::not_committed(temporary, source))?;
    file.sync_all()
        .map_err(|source| PersistError::not_committed(temporary, source))?;
    drop(file);

    fs::rename(temporary, path).map_err(|source| PersistError::not_committed(path, source))?;

    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PersistError::Committed {
            path: directory.to_path_buf(),
            source,
        })
}

fn existing_mode(path: &Path) -> Result<u32, PersistError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.permissions().mode() & 0o7777),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(STATE_FILE_MODE),
        Err(source) => Err(PersistError::not_committed(path, source)),
    }
}

fn temporary_name(path: &Path) -> String {
    let name = path.file_name().map_or_else(
        || "state.toml".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(".{name}.{}.{sequence}.tmp", std::process::id())
}

/// Call this only while holding the instance lock of the state file, because
/// it could otherwise unlink a live persist from another process.
///
/// # Errors
///
/// Returns a [`PersistError::NotCommitted`] if the containing directory cannot
/// be read or a matching orphan cannot be removed.
pub fn sweep_orphans(path: &Path) -> Result<(), PersistError> {
    let directory = containing_directory(path);
    let name = path.file_name().map_or_else(
        || "state.toml".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let prefix = format!(".{name}.");
    for entry in
        fs::read_dir(directory).map_err(|source| PersistError::not_committed(directory, source))?
    {
        let entry = entry.map_err(|source| PersistError::not_committed(directory, source))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.starts_with(&prefix) && file_name.ends_with(".tmp") {
            fs::remove_file(entry.path())
                .map_err(|source| PersistError::not_committed(&entry.path(), source))?;
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistError {
    #[error("cannot render the state document")]
    Serialize(#[source] toml::ser::Error),
    #[error("cannot write state to {path}")]
    NotCommitted {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The rename succeeded but the directory could not be flushed. The state
    /// file already contains the new document; only its survival of a crash is
    /// unconfirmed.
    #[error("state written, but {path} could not be flushed: a crash may lose the change")]
    Committed {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl PersistError {
    fn not_committed(path: &Path, source: io::Error) -> Self {
        Self::NotCommitted {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure() -> io::Error {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }

    #[test]
    fn the_error_variant_states_which_side_of_the_commit_point_failed() {
        assert!(matches!(
            PersistError::not_committed(Path::new("/srv/state.toml"), failure()),
            PersistError::NotCommitted { .. }
        ));
        assert!(matches!(
            PersistError::Committed {
                path: PathBuf::from("/srv"),
                source: failure(),
            },
            PersistError::Committed { .. }
        ));
    }

    #[test]
    fn an_unflushed_directory_says_the_change_already_happened() {
        let error = PersistError::Committed {
            path: PathBuf::from("/srv"),
            source: failure(),
        };
        assert_eq!(
            error.to_string(),
            "state written, but /srv could not be flushed: a crash may lose the change"
        );
    }

    #[test]
    fn a_temporary_name_is_hidden_and_beside_the_state_file() {
        let name = temporary_name(Path::new("/srv/state.toml"));
        assert!(name.starts_with(".state.toml."), "{name}");
        assert!(name.ends_with(".tmp"), "{name}");
        assert_ne!(name, temporary_name(Path::new("/srv/state.toml")));
    }

    #[test]
    fn a_cleanly_missing_state_file_is_created_as_the_empty_document() {
        let scratch = voidport_test_host::Scratch::new("create-missing");
        let path = scratch.join("state.toml");
        assert!(create_if_missing(&path).expect("creatable"), "created");
        assert_eq!(
            fs::read_to_string(&path).expect("readable"),
            StateDocument::default()
                .to_toml()
                .expect("the empty document renders")
        );
        assert_eq!(
            fs::metadata(&path).expect("readable").permissions().mode() & 0o7777,
            STATE_FILE_MODE,
            "the file describes what is exposed, so it is owner-only"
        );
        assert_eq!(
            super::super::load_document(&path).expect("the created file loads"),
            StateDocument::default()
        );

        fs::write(&path, "[[namespaces]]\nname = \"kept\"\n").expect("writable");
        assert!(!create_if_missing(&path).expect("nothing to do"));
        assert_eq!(
            fs::read_to_string(&path).expect("readable"),
            "[[namespaces]]\nname = \"kept\"\n"
        );
    }

    #[test]
    fn only_a_cleanly_missing_file_is_created() {
        let scratch = voidport_test_host::Scratch::new("create-refuses");

        let malformed = scratch.join("malformed.toml");
        fs::write(&malformed, "this is not toml").expect("writable");
        assert!(!create_if_missing(&malformed).expect("nothing to do"));
        assert_eq!(
            fs::read_to_string(&malformed).expect("readable"),
            "this is not toml"
        );

        let dangling = scratch.join("dangling.toml");
        std::os::unix::fs::symlink(scratch.join("nowhere.toml"), &dangling).expect("linkable");
        assert!(!create_if_missing(&dangling).expect("nothing to do"));
        assert!(
            fs::symlink_metadata(&dangling)
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        assert!(!scratch.join("nowhere.toml").exists());

        let error = create_if_missing(&scratch.join("absent/state.toml"))
            .expect_err("the directory is not there");
        assert!(
            matches!(error, PersistError::NotCommitted { .. }),
            "{error}"
        );
        assert!(!scratch.join("absent").exists());
    }

    #[test]
    fn only_enoent_uses_the_first_create_mode() {
        let directory = std::env::temp_dir().join(format!(
            "voidport-existing-mode-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        voidport_test_host::create_directory(&directory);
        assert_eq!(
            existing_mode(&directory.join("absent.toml")).expect("missing"),
            STATE_FILE_MODE
        );
        let regular = directory.join("regular");
        fs::write(&regular, b"").expect("a regular file");
        let error =
            existing_mode(&regular.join("child")).expect_err("the parent is not a directory");
        assert!(matches!(error, PersistError::NotCommitted { .. }));
        fs::remove_file(regular).expect("cleanup file");
        fs::remove_dir(directory).expect("cleanup directory");
    }
}
