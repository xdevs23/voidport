//! In memory the table is keyed by node identity, so one inode is one record and
//! every name of a hard link presents and strips it. On disk the sidecar is
//! keyed by a revalidating locator, see [`super::sidecar`].
//!
//! A session captures its store at handshake, so a namespace deleted under a
//! mount does not take the store from a session still serving.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use voidport_control::NamespaceName;

use super::bits::PrivilegedBits;
use super::sidecar::{HostLocator, RecordHome, SidecarDocument};
use crate::data::node::Move;
use crate::host::attr::NodeIdentity;
use crate::state::PersistError;
use crate::state::persist::{STATE_FILE_MODE, write_and_rename};

/// A crash loses at most this much recorded truth, and a burst of chmods or the
/// repeated strip marks of a chunked write coalesce into one rename-over.
pub const SIDECAR_CADENCE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub bits: PrivilegedBits,
    pub locator: HostLocator,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records(BTreeMap<NodeIdentity, Record>);

impl Records {
    #[must_use]
    pub fn of(records: BTreeMap<NodeIdentity, Record>) -> Self {
        Self(records)
    }

    #[must_use]
    pub fn bits(&self, identity: &NodeIdentity) -> PrivilegedBits {
        self.0
            .get(identity)
            .map_or(PrivilegedBits::NONE, |record| record.bits)
    }

    #[must_use]
    pub fn get(&self, identity: &NodeIdentity) -> Option<&Record> {
        self.0.get(identity)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeIdentity, &Record)> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug)]
pub struct RecordStore {
    name: NamespaceName,
    published: RwLock<Arc<Records>>,
    sidecar: Arc<Sidecar>,
    flusher: Mutex<Option<JoinHandle<()>>>,
    retired: AtomicBool,
}

/// A store has a file and a thread, so it has no value equality. Two registry
/// snapshots are equal where they share the very instance.
impl PartialEq for RecordStore {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for RecordStore {}

impl RecordStore {
    /// The only place a sidecar is read: server startup for a name of the state
    /// file, and the namespace-create that introduces one. Never at namespace
    /// build, so no two tables race one sidecar.
    /// # Errors
    ///
    /// [`RecordError::Io`] if the sidecar cannot be read and
    /// [`RecordError::Parse`] if it is not a record document, which the server
    /// cannot serve.
    pub fn open(name: &NamespaceName, home: &RecordHome) -> Result<Arc<Self>, RecordError> {
        let path = home.sidecar(name);
        let records = load(&path)?;
        let store = Arc::new(Self {
            name: name.clone(),
            published: RwLock::new(Arc::new(records)),
            sidecar: Arc::new(Sidecar {
                path,
                temporaries: Temporaries {
                    home: home.clone(),
                    name: name.clone(),
                    sequence: AtomicU64::new(0),
                },
                owed: Mutex::new(Owed::default()),
                wake: Condvar::new(),
            }),
            flusher: Mutex::new(None),
            retired: AtomicBool::new(false),
        });
        let sidecar = Arc::clone(&store.sidecar);
        let flusher = std::thread::Builder::new()
            .name(format!("voidport-records-{}", name.as_str()))
            .spawn(move || sidecar.serve())
            .map_err(|source| RecordError::Io {
                path: store.sidecar.path.clone(),
                source,
            })?;
        *store.flusher() = Some(flusher);
        Ok(store)
    }

    #[must_use]
    pub fn name(&self) -> &NamespaceName {
        &self.name
    }

    #[must_use]
    pub fn sidecar(&self) -> &Path {
        &self.sidecar.path
    }

    /// Taken once per operation beside the namespace snapshot, so a listing
    /// walks hundreds of entries against one table without synchronizing.
    #[must_use]
    pub fn records(&self) -> Arc<Records> {
        Arc::clone(
            &self
                .published
                .read()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    #[must_use]
    pub fn bits(&self, identity: &NodeIdentity) -> PrivilegedBits {
        self.records().bits(identity)
    }

    /// An assignment, never a merge: the mode that a chmod or a create delivered
    /// has passed the permission and setgid-clearing logic of the guest kernel,
    /// so its privileged bits are the new value of the record, and a plain chmod
    /// clears as local semantics demand. A store that would not change writes
    /// nothing.
    pub fn assign(&self, identity: NodeIdentity, locator: HostLocator, bits: PrivilegedBits) {
        if self.is_retired() {
            return;
        }
        let mut published = self
            .published
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let held = published.get(&identity);
        let wanted = (!bits.is_empty()).then_some(Record { bits, locator });
        if held == wanted.as_ref() {
            return;
        }
        let mut table = published.0.clone();
        match wanted {
            Some(record) => table.insert(identity, record),
            None => table.remove(&identity),
        };
        let fresh = Arc::new(Records(table));
        *published = Arc::clone(&fresh);
        drop(published);
        self.sidecar.owe(fresh);
    }

    /// The record of the entry follows it by identity, through every name of a
    /// hard link, and the records beneath a moved directory follow by prefix
    /// rewrite. All moves apply in one pass, so an exchange applies at most one of
    /// them to any record.
    pub fn relocate(&self, moves: &[Move]) {
        if self.is_retired() || moves.is_empty() {
            return;
        }
        let mut published = self
            .published
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut table: Option<BTreeMap<NodeIdentity, Record>> = None;
        for (identity, record) in published.iter() {
            let Some(locator) = relocated(moves, identity, &record.locator) else {
                continue;
            };
            table.get_or_insert_with(|| published.0.clone()).insert(
                *identity,
                Record {
                    bits: record.bits,
                    locator,
                },
            );
        }
        let Some(table) = table else {
            return;
        };
        let fresh = Arc::new(Records(table));
        *published = Arc::clone(&fresh);
        drop(published);
        self.sidecar.owe(fresh);
    }

    /// The daemon calls this for every store after both planes stop and before
    /// the instance lock drops.
    /// # Errors
    ///
    /// Returns why the sidecar could not be written; the store still serves its
    /// records either way.
    pub fn flush(&self) -> Result<(), RecordError> {
        self.sidecar.flush()
    }

    /// Stops all further writes and removes the sidecar. A re-created name starts
    /// a fresh, empty store.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.stop();
        self.sidecar.discard();
        if let Err(source) = std::fs::remove_file(&self.sidecar.path)
            && source.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                namespace = self.name.as_str(),
                sidecar = %self.sidecar.path.display(),
                %source,
                "the record sidecar of a removed namespace could not be deleted"
            );
        }
    }

    /// Whether the namespace this store belongs to is gone.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    fn stop(&self) {
        self.sidecar.stop();
        if let Some(flusher) = self.flusher().take() {
            let _ = flusher.join();
        }
    }

    fn flusher(&self) -> MutexGuard<'_, Option<JoinHandle<()>>> {
        self.flusher
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// A retired store writes nothing, so the sidecar of a removed namespace
/// is not written back.
impl Drop for RecordStore {
    fn drop(&mut self) {
        if let Err(source) = self.sidecar.flush() {
            tracing::warn!(
                namespace = self.name.as_str(),
                %source,
                "the record sidecar could not be written as the store was released"
            );
        }
        self.stop();
    }
}

/// The record *is* the entry that moved, whatever name reached it, or its
/// locator sits underneath a directory that moved.
fn relocated(
    moves: &[Move],
    identity: &NodeIdentity,
    locator: &HostLocator,
) -> Option<HostLocator> {
    let fresh = moves.iter().find_map(|moved| {
        if identity.names(moved.entry()) {
            return Some(HostLocator::of(moved.to()));
        }
        locator.rebased(
            &HostLocator::of(moved.from()?),
            &HostLocator::of(moved.to()),
        )
    })?;
    (fresh != *locator).then_some(fresh)
}

fn load(path: &Path) -> Result<Records, RecordError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Records::default()),
        Err(source) => {
            return Err(RecordError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let document: SidecarDocument = toml::from_str(&text).map_err(|source| RecordError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    Ok(document.revalidate())
}

#[derive(Debug)]
struct Sidecar {
    path: PathBuf,
    temporaries: Temporaries,
    owed: Mutex<Owed>,
    wake: Condvar,
}

#[derive(Debug, Default)]
struct Owed {
    table: Option<Arc<Records>>,
    due: Option<Instant>,
    stopped: bool,
}

#[derive(Debug)]
struct Temporaries {
    home: RecordHome,
    name: NamespaceName,
    sequence: AtomicU64,
}

impl Temporaries {
    fn next(&self) -> PathBuf {
        self.home
            .temporary(&self.name, self.sequence.fetch_add(1, Ordering::Relaxed))
    }
}

impl Sidecar {
    /// Sleeps until a pending write is due, writes it, and repeats until the
    /// store stops.
    fn serve(&self) {
        let mut owed = self.lock();
        loop {
            if owed.stopped {
                return;
            }
            let Some(table) = owed.table.clone() else {
                owed = self
                    .wake
                    .wait(owed)
                    .unwrap_or_else(|poison| poison.into_inner());
                continue;
            };
            let due = owed.due.unwrap_or_else(Instant::now);
            let now = Instant::now();
            if now < due {
                owed = self
                    .wake
                    .wait_timeout(owed, due - now)
                    .unwrap_or_else(|poison| poison.into_inner())
                    .0;
                continue;
            }
            owed.table = None;
            owed.due = None;
            drop(owed);
            self.persist(&table);
            owed = self.lock();
        }
    }

    /// The window is not extended by later marks, so it bounds how long recorded
    /// truth can be newer than the file.
    fn owe(&self, table: Arc<Records>) {
        let mut owed = self.lock();
        if owed.stopped {
            return;
        }
        if owed.table.is_none() {
            owed.due = Some(Instant::now() + SIDECAR_CADENCE);
        }
        owed.table = Some(table);
        drop(owed);
        self.wake.notify_all();
    }

    fn flush(&self) -> Result<(), RecordError> {
        let table = {
            let mut owed = self.lock();
            owed.due = None;
            owed.table.take()
        };
        match table {
            Some(table) => self.write(&table),
            None => Ok(()),
        }
    }

    fn discard(&self) {
        let mut owed = self.lock();
        owed.table = None;
        owed.due = None;
    }

    fn stop(&self) {
        let mut owed = self.lock();
        owed.stopped = true;
        drop(owed);
        self.wake.notify_all();
    }

    fn persist(&self, table: &Records) {
        if let Err(source) = self.write(table) {
            tracing::warn!(
                sidecar = %self.path.display(),
                %source,
                "the record sidecar could not be written"
            );
        }
    }

    fn write(&self, table: &Records) -> Result<(), RecordError> {
        let document = SidecarDocument::of(table);
        let text = toml::to_string(&document).map_err(RecordError::Serialize)?;
        let directory = crate::state::containing_directory(&self.path);
        let temporary = self.temporaries.next();
        let result = write_and_rename(
            &temporary,
            &self.path,
            directory,
            text.as_bytes(),
            STATE_FILE_MODE,
        );
        if matches!(result, Err(PersistError::NotCommitted { .. })) {
            let _ = std::fs::remove_file(&temporary);
        }
        Ok(result?)
    }

    fn lock(&self) -> MutexGuard<'_, Owed> {
        self.owed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Why the records of a namespace could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    #[error("cannot read the record sidecar {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid record sidecar {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("cannot render the recorded metadata")]
    Serialize(#[source] toml::ser::Error),
    #[error(transparent)]
    Persist(#[from] PersistError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::attr::HostAttr;
    use voidport_test_host::Scratch;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn identity(path: &Path) -> NodeIdentity {
        HostAttr::of_host_path(path)
            .expect("stattable")
            .node_identity()
    }

    fn locator(path: &Path) -> HostLocator {
        HostLocator::of(&crate::rules::HostBacking::graft_root(
            crate::rules::HostTarget::new(path.to_string_lossy().into_owned()),
        ))
    }

    fn records_birth(path: &Path) -> bool {
        identity(path).birth.is_some()
    }

    #[test]
    fn an_assignment_is_a_new_value_and_an_empty_one_deletes() {
        let scratch = Scratch::new("records-assign");
        let file = scratch.file("tool", b"x");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
        let held = identity(&file);

        assert_eq!(store.bits(&held), PrivilegedBits::NONE);
        store.assign(held, locator(&file), PrivilegedBits::of(0o6755));
        assert_eq!(store.bits(&held), PrivilegedBits::of(0o6000));
        store.assign(held, locator(&file), PrivilegedBits::of(0o2755));
        assert_eq!(store.bits(&held), PrivilegedBits::new(false, true));
        store.assign(held, locator(&file), PrivilegedBits::of(0o0644));
        assert_eq!(store.bits(&held), PrivilegedBits::NONE);
        assert!(store.records().is_empty());
    }

    #[test]
    fn a_write_that_changes_nothing_does_not_swap_the_table() {
        let scratch = Scratch::new("records-noop");
        let file = scratch.file("tool", b"x");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
        let held = identity(&file);

        store.assign(held, locator(&file), PrivilegedBits::of(0o4755));
        let published = store.records();
        store.assign(held, locator(&file), PrivilegedBits::of(0o4755));
        assert!(Arc::ptr_eq(&published, &store.records()));
        store.assign(
            identity(&scratch.file("other", b"y")),
            locator(&file),
            PrivilegedBits::NONE,
        );
        assert!(Arc::ptr_eq(&published, &store.records()));
    }

    #[test]
    fn the_sidecar_is_written_debounced_and_flushed_on_demand() {
        let scratch = Scratch::new("records-flush");
        let file = scratch.file("tool", b"x");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
        let sidecar = store.sidecar().to_path_buf();

        store.assign(identity(&file), locator(&file), PrivilegedBits::of(0o4755));
        assert!(
            !sidecar.exists(),
            "the write is owed, not taken: {}",
            sidecar.display()
        );
        store.flush().expect("the sidecar writes");
        let text = std::fs::read_to_string(&sidecar).expect("readable");
        assert!(text.contains("setuid = true"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("readable")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0,
            "a finished persist leaves no temporary behind"
        );
    }

    #[test]
    fn a_flushed_store_reopens_with_the_rows_that_still_name_their_file() {
        let scratch = Scratch::new("records-reopen");
        let file = scratch.file("tool", b"x");
        if !records_birth(&file) {
            return;
        }
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let held = identity(&file);
        {
            let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
            store.assign(held, locator(&file), PrivilegedBits::of(0o6755));
            store.flush().expect("the sidecar writes");
        }
        let reopened = RecordStore::open(&name("project"), &home).expect("the sidecar loads");
        assert_eq!(reopened.bits(&held), PrivilegedBits::of(0o6000));

        let other = RecordStore::open(&name("other"), &home).expect("a fresh store");
        assert!(other.records().is_empty());
    }

    #[test]
    fn retiring_deletes_the_sidecar_and_takes_no_further_writes() {
        let scratch = Scratch::new("records-retire");
        let file = scratch.file("tool", b"x");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
        let held = identity(&file);
        store.assign(held, locator(&file), PrivilegedBits::of(0o4755));
        store.flush().expect("the sidecar writes");
        assert!(store.sidecar().exists());

        store.retire();
        assert!(store.is_retired());
        assert!(!store.sidecar().exists(), "removal deletes the sidecar");
        store.assign(held, locator(&file), PrivilegedBits::of(0o6755));
        assert_eq!(
            store.bits(&held),
            PrivilegedBits::of(0o4000),
            "a retired store takes no further writes"
        );
        let fresh = RecordStore::open(&name("project"), &home).expect("a fresh store");
        assert!(fresh.records().is_empty());
    }

    #[test]
    fn a_sidecar_that_does_not_parse_refuses_the_store() {
        let scratch = Scratch::new("records-refuse");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        std::fs::write(home.sidecar(&name("project")), "this is not toml").expect("writable");
        let error = RecordStore::open(&name("project"), &home).expect_err("not a record document");
        assert!(matches!(error, RecordError::Parse { .. }), "{error}");
    }

    #[test]
    fn a_rename_through_the_server_moves_the_locator_with_the_entry() {
        use crate::rules::{HostTarget, Name};

        let scratch = Scratch::new("records-relocate");
        let directory = std::path::PathBuf::from(scratch.directory("tree"));
        let file = scratch.file("tree/tool", b"x");
        let home = RecordHome::for_state_file(&scratch.join("state.toml"));
        let store = RecordStore::open(&name("project"), &home).expect("a fresh store");
        let held = identity(&file);
        let graft = crate::rules::HostBacking::graft_root(HostTarget::new(
            scratch.path().to_string_lossy().into_owned(),
        ));
        let old = graft
            .child(&Name::new("tree").expect("valid"))
            .child(&Name::new("tool").expect("valid"));
        store.assign(held, HostLocator::of(&old), PrivilegedBits::of(0o4755));

        let renamed = graft.child(&Name::new("renamed").expect("valid"));
        store.relocate(&[Move::renamed(
            held.host_identity(),
            old.clone(),
            renamed.clone(),
        )]);
        assert_eq!(
            store.records().get(&held).expect("recorded").locator,
            HostLocator::of(&renamed)
        );

        store.assign(held, HostLocator::of(&old), PrivilegedBits::of(0o4755));
        let moved = graft.child(&Name::new("moved").expect("valid"));
        store.relocate(&[Move::renamed(
            identity(&directory).host_identity(),
            graft.child(&Name::new("tree").expect("valid")),
            moved.clone(),
        )]);
        assert_eq!(
            store.records().get(&held).expect("recorded").locator,
            HostLocator::of(&moved.child(&Name::new("tool").expect("valid")))
        );
    }
}
