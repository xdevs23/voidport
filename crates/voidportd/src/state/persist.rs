//! Atomic, durable persistence of the state document.
//!
//! The server owns the state file, so a mutation is only real once the file
//! says so. That is why the sequence is fixed and complete:
//!
//! 1. render the source document (never a derived form);
//! 2. create a temporary file **in the same directory**, so the rename that
//!    follows is a same-filesystem, atomic replace;
//! 3. give it the state file's permissions — preserved on replace, `0600` on
//!    first create — set explicitly, because the mode passed to `open` is
//!    filtered by the process umask;
//! 4. write and `fsync` the file, so the bytes are on the medium before
//!    anything points at them;
//! 5. rename over the state file;
//! 6. `fsync` the directory, so the rename itself survives a crash.
//!
//! Skipping step 6 is the classic almost-atomic bug: the new file's contents
//! are durable but the directory entry that names it is not, and a crash can
//! leave the old file in place — the caller would have published a mutation
//! the disk never took.
//!
//! Step 5 is the commit point, and step 6 is the only step that can fail after
//! it. Once the rename has returned, the state file *is* the new document for
//! every reader, so a failure there is not "the write did not happen" — it is
//! "the write happened and may not survive a crash". The two are different
//! facts for the caller and are reported as different failures
//! ([`PersistError::Committed`]): a caller that treated a post-commit
//! failure like a pre-commit one would keep serving a document the file no
//! longer holds, which is exactly the memory/disk divergence this sequence
//! exists to prevent.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::containing_directory;
use super::document::StateDocument;

/// The mode a state file is created with: owner-only, because it describes
/// exactly which parts of the host filesystem are exposed.
pub const STATE_FILE_MODE: u32 = 0o600;

/// Distinguishes concurrent temporary files within one process.
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Writes the document to the state file atomically and durably.
///
/// # Errors
///
/// Returns a [`PersistError`] if the document cannot be rendered or any step
/// of the write fails. [`PersistError::NotCommitted`] leaves the state file
/// untouched; [`PersistError::Committed`] means the rename landed and only the
/// directory flush failed.
pub fn persist(document: &StateDocument, path: &Path) -> Result<(), PersistError> {
    let text = document.to_toml().map_err(PersistError::Serialize)?;
    let directory = containing_directory(path).to_path_buf();
    let mode = existing_mode(path)?;
    let temporary = directory.join(temporary_name(path));

    match write_and_rename(&temporary, path, &directory, text.as_bytes(), mode) {
        Ok(()) => Ok(()),
        Err(error) => {
            // A failed attempt must not leave debris that can collide with a
            // later create-new. Past the commit point there is nothing to
            // remove: the temporary is the state file now.
            if matches!(error, PersistError::NotCommitted { .. }) {
                let _ = fs::remove_file(&temporary);
            }
            Err(error)
        }
    }
}

/// Creates the state file as the empty document if — and only if — nothing is
/// there at all. Returns whether it was created.
///
/// A cleanly missing file is a server with nothing configured, which is a state
/// the schema already defines, so writing it costs the operator nothing and
/// saves them a first file that says `[server]` and nothing else. Anything else
/// on the path is left exactly as it is: a file that exists but cannot be read
/// or parsed stays a startup error, so a typo'd path can never silently shadow
/// a real configuration. That is also why the probe is
/// [`fs::symlink_metadata`] — a dangling symbolic link *is* something on the
/// path, and replacing it with a fresh empty document would be doing precisely
/// what this refuses to do.
///
/// The write goes through [`persist`], so the file appears atomically with mode
/// [`STATE_FILE_MODE`] and never in a half-written form.
///
/// Call this while holding the state file's instance lock: two daemons racing
/// here would each create a file and one of them would then serve a document
/// the other replaced.
///
/// # Errors
///
/// Returns a [`PersistError`] if the path cannot be examined or the document
/// cannot be written. A missing parent directory surfaces here instead of
/// being created — a mistyped directory is not an instruction to build one.
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

/// Steps 2 through 6, with the temporary file's cleanup left to the caller.
fn write_and_rename(
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

    // The commit point: from here on the state file holds the new document.
    fs::rename(temporary, path).map_err(|source| PersistError::not_committed(path, source))?;

    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PersistError::Committed {
            path: directory.to_path_buf(),
            source,
        })
}

/// The mode to write with: the state file's own, or [`STATE_FILE_MODE`] if it
/// does not exist yet.
fn existing_mode(path: &Path) -> Result<u32, PersistError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.permissions().mode() & 0o7777),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(STATE_FILE_MODE),
        Err(source) => Err(PersistError::not_committed(path, source)),
    }
}

/// A temporary name beside the state file, unique per process and call.
fn temporary_name(path: &Path) -> String {
    let name = path.file_name().map_or_else(
        || "state.toml".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(".{name}.{}.{sequence}.tmp", std::process::id())
}

/// Removes temporary files left by an interrupted persist of `path`.
///
/// Call this only while holding the state file's instance lock: otherwise it
/// could unlink a live persist from another process.
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

/// Why a state document could not be persisted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistError {
    /// The document could not be rendered as TOML.
    #[error("cannot render the state document")]
    Serialize(#[source] toml::ser::Error),
    /// A filesystem step before the commit point failed, so the state file is
    /// untouched.
    #[error("cannot write state to {path}")]
    NotCommitted {
        /// The path the failing step touched.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The rename succeeded but the directory could not be flushed. The state
    /// file **already holds the new document**; only its survival of a crash
    /// is unconfirmed.
    #[error("state written, but {path} could not be flushed: a crash may lose the change")]
    Committed {
        /// The directory whose flush failed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

impl PersistError {
    /// Wraps a pre-rename filesystem failure with the path it happened on.
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
        // The message must not read like a failed write: the caller publishes
        // this change, and the operator has to know that it took effect.
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
        let scratch = crate::testing::Scratch::new("create-missing");
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

        // Idempotent, and never a rewrite: a second call reports that it did
        // nothing and leaves whatever the file now holds.
        fs::write(&path, "[[namespaces]]\nname = \"kept\"\n").expect("writable");
        assert!(!create_if_missing(&path).expect("nothing to do"));
        assert_eq!(
            fs::read_to_string(&path).expect("readable"),
            "[[namespaces]]\nname = \"kept\"\n"
        );
    }

    #[test]
    fn only_a_cleanly_missing_file_is_created() {
        let scratch = crate::testing::Scratch::new("create-refuses");

        // A file that exists but is not a state document is left untouched, so
        // the loader can refuse it: creation must never shadow a real file.
        let malformed = scratch.join("malformed.toml");
        fs::write(&malformed, "this is not toml").expect("writable");
        assert!(!create_if_missing(&malformed).expect("nothing to do"));
        assert_eq!(
            fs::read_to_string(&malformed).expect("readable"),
            "this is not toml"
        );

        // A dangling symbolic link is something on the path, not an absence.
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

        // A missing parent directory is a failure, not an instruction to build
        // a tree the operator did not ask for.
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
        crate::testing::create_directory(&directory);
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
